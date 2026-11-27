//! Contract checks for custom [`Store`] implementations.
//!
//! Requires the `testing` feature. Call [`check`] from your adapter's own
//! `#[test]` suite on an isolated namespace or directory.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::account::AccountId;
use crate::entropy::OsEntropy;
use crate::error::{Error, ErrorKind};

use super::{EntryName, Store};

/// Patience passed to locks that are expected to succeed without contention.
const UNCONTENDED_PATIENCE: Duration = Duration::from_secs(5);

/// Patience passed to verify that a contended lock waits before returning
/// [`ErrorKind::StoreBusy`].
const CONTENDED_PATIENCE: Duration = Duration::from_millis(40);
const CONTENTION_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Distinctive marker written during the `Debug` check so a store that prints
/// its entries is caught at once.
const SECRET_MARKER: &[u8] = b"siwc-conformance-secret-do-not-print";

/// Verifies that `store` satisfies the [`Store`] contract:
///
/// - missing entries read as `Ok(None)` and removing a missing entry succeeds;
/// - binary bytes (`0x00`, `0xff`, `\n`), empty slices (`b""`) and multi-kilobyte
///   values round-trip intact, and replacing a long value with a short one
///   leaves no trailing bytes behind;
/// - distinct entries stay isolated when written and removed;
/// - `Debug` output of `store` never prints stored bytes, neither as text nor
///   as the decimal list a derived `Debug` prints for `Vec<u8>` nor as hex;
/// - [`Store::lock`] excludes concurrent takers across threads, fails at once
///   with [`ErrorKind::StoreBusy`] on `Duration::ZERO`, waits up to `patience`
///   before failing with [`ErrorKind::StoreBusy`], allows independent entries
///   to be locked side by side, and releases the lock when [`Lock`](super::Lock)
///   is dropped.
///
/// The check tries to remove every temporary `conformance-*` entry it
/// created before returning; a failed removal is ignored. Store
/// implementations may retain lock metadata, so use a disposable directory
/// for file-based adapters. The check releases its held lock if a contended
/// request exceeds its budget. Run it in a supervised subprocess if an
/// adapter may hang independently of contention.
///
/// ```
/// use siwc::store::MemoryStore;
///
/// siwc::store::conformance::check(&MemoryStore::new())?;
/// # Ok::<(), siwc::Error>(())
/// ```
///
/// # Errors
///
/// Generating the disposable entry names can return [`ErrorKind::Randomness`].
/// Returns whatever [`Error`] `store` itself fails with, or an
/// [`ErrorKind::StoreCorrupt`] error naming the violated contract rule.
pub fn check<S: Store + ?Sized>(store: &S) -> Result<(), Error> {
    let run = AccountId::generate(&OsEntropy)?;
    let missing = EntryName::new(&format!("conformance-{run}-missing"))?;
    let alpha = EntryName::new(&format!("conformance-{run}-a"))?;
    let beta = EntryName::new(&format!("conformance-{run}-b"))?;

    for entry in [&missing, &alpha, &beta] {
        if store.read(entry)?.is_some() {
            return Err(violated(
                "reading a fresh conformance entry did not return None",
            ));
        }
    }

    let _cleanup = Cleanup {
        store,
        entries: [&missing, &alpha, &beta],
    };

    store.remove(&missing)?;

    // Binary, empty, large and shrinking writes.
    let binary = [0u8, 1, 2, 0xfe, 0xff, b'\n', 0, b'"', b'\\'];
    store.write(&alpha, &binary)?;
    expect_bytes(store, &alpha, &binary, "binary bytes did not round-trip")?;

    store.write(&alpha, b"")?;
    expect_bytes(
        store,
        &alpha,
        b"",
        "an empty entry read back as missing or non-empty",
    )?;

    let large = vec![0xa5_u8; 3072];
    store.write(&alpha, &large)?;
    expect_bytes(
        store,
        &alpha,
        &large,
        "a multi-kilobyte entry did not round-trip",
    )?;

    store.write(&alpha, SECRET_MARKER)?;
    expect_bytes(
        store,
        &alpha,
        SECRET_MARKER,
        "replacing a longer entry did not replace it as a whole",
    )?;
    if shows_marker(&format!("{store:?}")) {
        return Err(violated("Debug output of the store exposed a stored value"));
    }

    // Entry isolation.
    store.write(&beta, b"other-entry")?;
    expect_bytes(
        store,
        &alpha,
        SECRET_MARKER,
        "writing another entry altered the first",
    )?;
    store.remove(&alpha)?;
    if store.read(&alpha)?.is_some() {
        return Err(violated("a removed entry could still be read"));
    }
    expect_bytes(
        store,
        &beta,
        b"other-entry",
        "removing one entry altered another",
    )?;

    check_locks(store, &alpha, &beta)
}

fn check_locks<S: Store + ?Sized>(
    store: &S,
    alpha: &EntryName,
    beta: &EntryName,
) -> Result<(), Error> {
    let held_alpha = store.lock(alpha, UNCONTENDED_PATIENCE)?;
    // Locking another entry at the same time must succeed.
    let held_beta = store.lock(beta, Duration::ZERO)?;
    drop(held_beta);

    // Check cross-thread exclusion for both zero and bounded patience.
    thread::scope(|scope| -> Result<(), Error> {
        let (done_tx, done_rx) = mpsc::channel();
        scope.spawn(move || {
            let zero_err = store.lock(alpha, Duration::ZERO).err();
            let started = Instant::now();
            let waited = store.lock(alpha, CONTENDED_PATIENCE);
            let elapsed = started.elapsed();
            let _sent = done_tx.send((zero_err, waited.err(), elapsed));
        });
        let outcome = done_rx.recv_timeout(CONTENTION_CHECK_TIMEOUT);
        drop(held_alpha);
        let (zero_err, waited_err, elapsed) = outcome.map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => {
                violated("locking a held entry did not honor its patience")
            }
            mpsc::RecvTimeoutError::Disconnected => {
                violated("lock conformance helper thread failed")
            }
        })?;
        if zero_err.as_ref().map(Error::kind) != Some(ErrorKind::StoreBusy) {
            return Err(violated(
                "locking a held entry with zero patience did not fail with StoreBusy",
            ));
        }
        if waited_err.as_ref().map(Error::kind) != Some(ErrorKind::StoreBusy) {
            return Err(violated(
                "locking a held entry past patience did not fail with StoreBusy",
            ));
        }
        // Allow small timer granularity slack while catching non-waiting implementations.
        if elapsed < CONTENDED_PATIENCE / 2 {
            return Err(violated(
                "locking a held entry returned before waiting for its patience",
            ));
        }
        Ok(())
    })?;

    let reacquired = store.lock(alpha, UNCONTENDED_PATIENCE)?;
    drop(reacquired);
    Ok(())
}

fn expect_bytes<S: Store + ?Sized>(
    store: &S,
    entry: &EntryName,
    expected: &[u8],
    reason: &'static str,
) -> Result<(), Error> {
    match store.read(entry)? {
        Some(stored) if stored.expose() == expected => Ok(()),
        _ => Err(violated(reason)),
    }
}

/// Whether `debug` shows [`SECRET_MARKER`] as text, as the decimal list a
/// derived `Debug` prints for bytes, or as hex digits in either case.
fn shows_marker(debug: &str) -> bool {
    let decimal = format!("{SECRET_MARKER:?}");
    let decimal = decimal.trim_start_matches('[').trim_end_matches(']');
    let mut hex = String::with_capacity(2 * SECRET_MARKER.len());
    for &byte in SECRET_MARKER {
        crate::hex::push(&mut hex, byte);
    }
    let lowered = debug.to_ascii_lowercase();
    lowered.contains("siwc-conformance-secret-do-not-print")
        || debug.contains(decimal)
        || lowered.contains(&hex)
}

fn violated(reason: &'static str) -> Error {
    Error::corrupt_entry(reason)
}

struct Cleanup<'a, S: Store + ?Sized> {
    store: &'a S,
    entries: [&'a EntryName; 3],
}

impl<S: Store + ?Sized> Drop for Cleanup<'_, S> {
    fn drop(&mut self) {
        for entry in self.entries {
            let _removed = self.store.remove(entry);
        }
    }
}
