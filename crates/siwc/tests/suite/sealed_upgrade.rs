//! `Sealed::seal_existing`: a directory that plain `PrivateFiles` filled
//! keeps its accounts when the app starts sealing it.
//!
//! Each test works in a directory of its own under `CARGO_TARGET_TMPDIR`
//! and removes it when it ends.

use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use siwc::store::{
    EntryName, KEY_LEN, KeyGeneration, PrivateFiles, RetiredKeys, Sealed, SealingKey, Store,
};
use siwc::{AppName, Client, Error, ErrorKind};

use crate::support::provider::User;
use crate::support::random::Seeded;
use crate::support::rig::Rig;

const PATIENCE: Duration = Duration::from_secs(5);

/// A synthetic plain value in the shape of the client's entries.
const PLAIN: &[u8] = b"{\"v\":1,\"synthetic\":\"refresh-token-7d2f\"}";

/// A key of one repeated byte that counts how often it was fetched.
#[derive(Clone, Default)]
struct Key {
    fetched: Arc<AtomicUsize>,
}

impl SealingKey for Key {
    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(KeyGeneration::new(0, None))
    }

    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        self.fetched.fetch_add(1, Ordering::SeqCst);
        key.fill(0x42);
        Ok(())
    }

    fn fill_retired(&self, _keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        Ok(())
    }
}

/// A directory of its own for one test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Self {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("sealed-upgrade-{test}-{}", process::id()));
        let _ = fs::remove_dir_all(&path);
        Self(path)
    }

    fn files(&self) -> PrivateFiles {
        PrivateFiles::open(&self.0).unwrap()
    }

    fn raw(&self, name: &str) -> Vec<u8> {
        fs::read(self.0.join(name)).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn name(text: &str) -> EntryName {
    EntryName::new(text).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn an_installation_kept_in_plain_files_keeps_its_account_and_token_once_sealed() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let token = rig.token(alex.id());
    let scratch = Scratch::new("client");
    let plain = scratch.files();
    let account = format!("account-{}", alex.id());
    for entry in ["installation", account.as_str()] {
        plain
            .write(&name(entry), &rig.store.bytes(entry).unwrap())
            .unwrap();
    }

    let sealed = Sealed::new(scratch.files(), Key::default());
    sealed.seal_existing(PATIENCE).unwrap();

    for entry in ["installation", account.as_str()] {
        let raw = scratch.raw(entry);
        assert_eq!(raw[0], 1, "{entry} is not sealed");
        assert!(!contains(&raw, alex.id().to_string().as_bytes()), "{entry}");
    }
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        sealed,
        Arc::clone(&rig.transport),
    )
    .clock(rig.clock.clone())
    .entropy(Seeded::new(9_000_000))
    .build();
    let accounts = client.accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id(), alex.id());
    assert_eq!(client.access_token(alex.id()).unwrap().expose(), token);
}

#[test]
fn a_store_that_is_already_sealed_is_left_as_it_is_without_fetching_the_key() {
    let scratch = Scratch::new("already-sealed");
    let key = Key::default();
    Sealed::new(scratch.files(), key.clone())
        .write(&name("installation"), PLAIN)
        .unwrap();
    let before = scratch.raw("installation");

    let key = Key::default();
    Sealed::new(scratch.files(), key.clone())
        .seal_existing(PATIENCE)
        .unwrap();

    assert_eq!(scratch.raw("installation"), before);
    assert_eq!(key.fetched.load(Ordering::SeqCst), 0);
}

#[test]
fn lock_files_and_temporary_files_are_no_entries_and_stay_unchanged() {
    let scratch = Scratch::new("not-entries");
    let files = scratch.files();
    drop(files.lock(&name("installation"), PATIENCE).unwrap());
    let leftover = scratch.0.join("installation.1-0.new");
    fs::write(&leftover, PLAIN).unwrap();

    Sealed::new(scratch.files(), Key::default())
        .seal_existing(PATIENCE)
        .unwrap();

    assert_eq!(fs::read(&leftover).unwrap(), PLAIN);
    assert!(scratch.raw("installation.lock").is_empty());
}

#[test]
fn a_plain_entry_whose_lock_another_holder_keeps_stays_plain_and_the_call_is_busy() {
    let scratch = Scratch::new("busy");
    let plain = scratch.files();
    plain.write(&name("installation"), PLAIN).unwrap();
    let _held = plain.lock(&name("installation"), PATIENCE).unwrap();

    let sealed = Sealed::new(scratch.files(), Key::default());
    let error = sealed.seal_existing(Duration::from_millis(60)).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::StoreBusy);
    assert_eq!(scratch.raw("installation"), PLAIN);
}

#[test]
fn seal_existing_refuses_corrupt_or_unknown_version_entries_without_overwriting_them() {
    let scratch = Scratch::new("corrupt-existing");
    let plain = scratch.files();
    for bad in [
        &b""[..],
        &b"\x00damaged-header"[..],
        &b"\x03future-envelope"[..],
        &b"not-json"[..],
        &[3; 28],
        &[3; 29],
        &[0x1f; 29],
        &[0x20; 29],
        &[0x09; 29],
        &[0x0a; 29],
        &[0x0d; 29],
    ] {
        plain.write(&name("installation"), bad).unwrap();
        let error = Sealed::new(scratch.files(), Key::default())
            .seal_existing(PATIENCE)
            .unwrap_err();
        assert_eq!(
            error.kind(),
            if bad == [3; 29] || bad == [0x1f; 29] {
                ErrorKind::StoreUnsupported
            } else {
                ErrorKind::StoreCorrupt
            }
        );
        assert_eq!(scratch.raw("installation"), bad);
    }
}

#[test]
fn resealing_rotates_retired_and_plain_entries_to_the_active_key_and_refuses_corrupt_ones() {
    #[derive(Clone)]
    struct Rotated {
        active: u8,
        retired: Option<u8>,
        retired_fetches: Arc<AtomicUsize>,
    }

    impl SealingKey for Rotated {
        fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
            Ok(KeyGeneration::new(0, None))
        }

        fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
            key.fill(self.active);
            Ok(())
        }

        fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
            self.retired_fetches.fetch_add(1, Ordering::SeqCst);
            if let Some(old) = self.retired {
                keys.add(|slot| {
                    slot.fill(old);
                    Ok(())
                })?;
            }
            Ok(())
        }
    }

    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let token = rig.token(alex.id());
    let scratch = Scratch::new("rotate");
    let account = format!("account-{}", alex.id());

    // Start with `installation` sealed under old key 0x11 and the account entry still plain.
    let v1 = Sealed::new(
        scratch.files(),
        Rotated {
            active: 0x11,
            retired: None,
            retired_fetches: Arc::default(),
        },
    );
    v1.write(
        &name("installation"),
        &rig.store.bytes("installation").unwrap(),
    )
    .unwrap();
    scratch
        .files()
        .write(&name(&account), &rig.store.bytes(&account).unwrap())
        .unwrap();

    // Rotate to 0x22 with 0x11 retired, reseal, and then drop 0x11 completely.
    let retired_fetches = Arc::new(AtomicUsize::new(0));
    let v2 = Sealed::new(
        scratch.files(),
        Rotated {
            active: 0x22,
            retired: Some(0x11),
            retired_fetches: Arc::clone(&retired_fetches),
        },
    );
    v2.reseal(PATIENCE).unwrap();
    assert_eq!(retired_fetches.load(Ordering::SeqCst), 1);

    // Calling reseal again when everything is on 0x22 leaves files untouched and skips retired keys.
    let install_after = scratch.raw("installation");
    let fresh_fetches = Arc::new(AtomicUsize::new(0));
    let v2_again = Sealed::new(
        scratch.files(),
        Rotated {
            active: 0x22,
            retired: Some(0x11),
            retired_fetches: Arc::clone(&fresh_fetches),
        },
    );
    v2_again.reseal(PATIENCE).unwrap();
    assert_eq!(fresh_fetches.load(Ordering::SeqCst), 0);
    assert_eq!(scratch.raw("installation"), install_after);

    // Without the retired key, the client still reads the account and its token.
    let active_only = Sealed::new(
        scratch.files(),
        Rotated {
            active: 0x22,
            retired: None,
            retired_fetches: Arc::default(),
        },
    );
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        active_only,
        Arc::clone(&rig.transport),
    )
    .clock(rig.clock.clone())
    .entropy(Seeded::new(9_100_000))
    .build();
    assert_eq!(client.access_token(alex.id()).unwrap().expose(), token);

    // Version 3 is reserved. Other damage is corrupt. Both errors preserve the bytes.
    let valid_sealed = scratch.raw(&account);
    let mut bad_tag = valid_sealed.clone();
    let last = bad_tag.len() - 1;
    bad_tag[last] ^= 0xff;
    let mut bad_v3 = valid_sealed.clone();
    bad_v3[0] = 3;
    let mut bad_v0 = valid_sealed;
    bad_v0[0] = 0;

    for damaged in [
        bad_tag.as_slice(),
        bad_v3.as_slice(),
        bad_v0.as_slice(),
        b"",
    ] {
        fs::write(scratch.0.join(&account), damaged).unwrap();
        assert_eq!(
            v2.reseal(PATIENCE).unwrap_err().kind(),
            if damaged == bad_v3 {
                ErrorKind::StoreUnsupported
            } else {
                ErrorKind::StoreCorrupt
            }
        );
        assert_eq!(scratch.raw(&account), damaged);
    }
}

#[test]
fn inventory_refuses_only_names_that_alias_store_entries() {
    let scratch = Scratch::new("case-alias");
    let files = scratch.files();
    files.write(&name("installation"), PLAIN).unwrap();
    fs::rename(
        scratch.0.join("installation"),
        scratch.0.join("Installation"),
    )
    .unwrap();
    let sealed = Sealed::new(files.clone(), Key::default());
    if scratch.0.join("installation").exists() {
        assert_eq!(
            sealed.seal_existing(PATIENCE).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    } else {
        sealed.seal_existing(PATIENCE).unwrap();
        files.write(&name("installation"), PLAIN).unwrap();
        sealed.seal_existing(PATIENCE).unwrap();
        assert_eq!(scratch.raw("installation")[0], 1);
    }
    assert_eq!(scratch.raw("Installation"), PLAIN);
}

#[test]
fn sign_out_discards_damaged_sealed_credentials_but_preserves_future_envelopes() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let scratch = Scratch::new("damaged-credentials");
    let files = scratch.files();
    let account = name(&format!("account-{}", alex.id()));
    let store = Sealed::new(files.clone(), Key::default());
    store
        .write(
            &name("installation"),
            &rig.store.bytes("installation").unwrap(),
        )
        .unwrap();
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        store,
        Arc::clone(&rig.transport),
    )
    .build();

    files.write(&account, &[3; 29]).unwrap();
    assert_eq!(
        client.sign_out(alex.id()).unwrap_err().kind(),
        ErrorKind::StoreUnsupported
    );
    assert_eq!(
        client.forget(alex.id()).unwrap_err().kind(),
        ErrorKind::StoreUnsupported
    );
    assert_eq!(files.read(&account).unwrap().unwrap().expose(), &[3; 29]);
    files.write(&account, b"truncated credentials").unwrap();
    assert!(!client.sign_out(alex.id()).unwrap().revocation_confirmed());
    assert!(files.read(&account).unwrap().is_none());
    assert_eq!(rig.journal.count("send revoke"), 0);
}

#[cfg(unix)]
#[test]
fn a_distinct_mixed_case_file_needs_no_read_access() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new("distinct-file");
    let files = scratch.files();
    let path = scratch.0.join("Preferences");
    fs::write(&path, b"{}").unwrap();
    if scratch.0.join("preferences").exists() {
        return;
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    Sealed::new(files, Key::default())
        .seal_existing(PATIENCE)
        .unwrap();
}
