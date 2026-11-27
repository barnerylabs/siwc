//! Recovery after the keychain lost the sealing key.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::Error;
use crate::store::KEY_LEN;
use crate::store::sealed::inventory;

use super::Keychain;
use super::deadline::ResetDeadline;
use super::material::{Backend, Lookup, find_key};

impl Keychain {
    /// Discards sealed entries that no readable active or retired key opens.
    /// Returns `true` if it removed at least one entry. Use it to recover from
    /// a lost key, such as
    /// [`ErrorKind::SealingKeyMissing`](crate::ErrorKind::SealingKeyMissing),
    /// only after the user agrees to losing those entries. If the installation
    /// record is lost, the app must register and sign in again. The discarded
    /// provider sessions are not revoked.
    ///
    /// It holds the key and reset locks, so crossing writes resolve the new
    /// generation after the reset finishes. A key in a locked Secret Service
    /// collection, or in a macOS keychain of the search list other than the
    /// default one, fails the reset with
    /// [`ErrorKind::Store`](crate::ErrorKind::Store) and removes nothing. A
    /// macOS keychain outside the search list that is not the default one
    /// is not looked at, so a key there reads as missing: confirm the key
    /// was lost before approving deletion. The generation advances before the
    /// first lookup, so live stores reload
    /// their keys on next use. Inventory, active and retired lookups, and
    /// planning deletion share 30 seconds once the locks are held. If the
    /// budget expires before deletion begins, nothing is removed. Once
    /// deletion begins, it finishes even if a filesystem call runs long.
    ///
    /// ```no_run
    /// # fn after_user_agreed(keychain: &siwc::store::Keychain) -> Result<(), siwc::Error> {
    /// if keychain.start_over()? {
    ///     println!("Unreadable sign-in entries were removed.");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::StoreBusy`](crate::ErrorKind::StoreBusy) when another
    ///   process holds the key lock for longer than 60 seconds.
    /// - [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) when
    ///   the directory contains sealed entries and the recorded service
    ///   differs from the configured one and is missing from
    ///   [`with_retired`](Self::with_retired).
    /// - Inventory forwards privacy and envelope errors, including
    ///   [`ErrorKind::StoreUnsupported`](crate::ErrorKind::StoreUnsupported).
    /// - [`ErrorKind::Store`](crate::ErrorKind::Store) when the keychain or
    ///   directory cannot be read, an entry cannot be removed, or the
    ///   reset metadata cannot be saved. Waiting three minutes for the
    ///   reset lock or expiring the shared reset budget also gives `Store`;
    ///   an expired budget names [`ErrorCause::TimedOut`](crate::ErrorCause::TimedOut)
    ///   even when recording the aborted reset fails, and calling it again
    ///   finishes the reset.
    ///   On a filesystem error during deletion,
    ///   entries already removed stay removed; call it again.
    pub fn start_over(&self) -> Result<bool, Error> {
        self.start_over_using(&self.platform_tool())
    }

    fn start_over_using(&self, backend: &impl Backend) -> Result<bool, Error> {
        let _locked = self.key_lock(None)?;
        let _reset_lock = self.lock_against_reset()?;
        let elapsed = |started: &Instant| self.reset_elapsed(started);
        let deadline = ResetDeadline::new(&elapsed);
        let mut reset = self.begin_reset()?;
        let result: Result<bool, Error> = (|| {
            let entries = || inventory::entries_checking(&self.files, || deadline.check());
            if entries()?.next().transpose()?.is_none() {
                deadline.check()?;
                self.record_reset_keys(&reset, std::iter::empty())?;
                self.record_cleared_reset(reset.started)?;
                reset.completed = reset.started;
                self.record_reset(&reset)?;
                return Ok(false);
            }
            let recorded = self.recorded_service()?;
            self.require_configured_service(recorded.as_ref(), || Ok(true))?;
            let lookup = Lookup {
                stop: None,
                reset: Some(&deadline),
            };
            let mut active = Zeroizing::new([0; KEY_LEN]);
            let have_active = find_key(backend, &self.service, lookup, &mut active)?;
            let retired = self.read_retired(backend, lookup)?;
            let keys = || {
                have_active
                    .then_some(&*active)
                    .into_iter()
                    .chain(retired.iter().map(|key| &**key))
            };

            let mut discard = Vec::new();
            let mut kept = false;
            for item in entries()? {
                let (entry, stored) = item?;
                if inventory::opens_with_any(&entry, &stored, keys())? {
                    kept = true;
                } else {
                    discard.push(entry);
                }
            }
            deadline.check()?;
            self.record_reset_keys(&reset, keys())?;
            if !discard.is_empty() {
                deadline.check()?;
            }
            // All keychain work and the removal plan finished within the budget.
            // Once deletion starts, finish it even if a filesystem call runs long.
            let mut removed = false;
            for entry in discard {
                removed |= self.files.remove_entry(&entry)?;
            }
            // A write already in flight can still publish under the old key
            // after this scan. Only a completed clear authorizes recovery of
            // those writes, and only until a subsequent key is activated.
            if !have_active && !kept {
                self.record_cleared_reset(reset.started)?;
            }
            reset.completed = reset.started;
            self.record_reset(&reset)?;
            Ok(removed)
        })();
        match result {
            Err(error) if error.keychain_timeout == Some(crate::error::KeychainTimeout::Reset) => {
                if !reset.prior_unsettled {
                    reset.aborted = reset.started;
                    // The expiry decides what the caller does next, so a
                    // failed record does not replace it. Unrecorded, the
                    // reset stays unfinished, as after a crash mid-reset,
                    // and crossing writes take the per-entry path.
                    let _unrecorded = self.record_reset(&reset);
                }
                Err(error)
            }
            other => other,
        }
    }

    fn reset_elapsed(&self, started: &Instant) -> Duration {
        #[cfg(all(test, target_os = "linux", feature = "testing"))]
        if let Some(elapsed) = self
            .timing
            .as_ref()
            .and_then(|timing| timing.elapsed.as_ref())
        {
            return Duration::from_secs(elapsed.load(std::sync::atomic::Ordering::Acquire));
        }
        started.elapsed()
    }
}
