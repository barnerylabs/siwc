//! A synthetic `secret-tool` with per-service keys and a locked keychain.

#[path = "keychain_fixture/activation.rs"]
mod activation;
#[path = "keychain_fixture/locked.rs"]
mod locked;
#[path = "keychain_fixture/recovery.rs"]
mod recovery;
#[path = "keychain_fixture/renewal.rs"]
mod renewal;
#[path = "keychain_fixture/replacement.rs"]
mod replacement;
#[path = "keychain_fixture/reset_history.rs"]
mod reset_history;
#[path = "keychain_fixture/reset_renewal.rs"]
mod reset_renewal;
#[path = "keychain_fixture/wrappers.rs"]
mod wrappers;

use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use siwc::ErrorKind;
use siwc::store::{Keychain, PrivateFiles, Sealed, Store};

use super::{Scratch, name};

const HELPER_DIR: &str = "SIWC_TEST_MISSING_KEYCHAIN_ITEM";
const SERVICE: &str = "com.example.siwc-missing-key";
const ROTATED: &str = "com.example.siwc-missing-key.v2";
const MARKER: &str = ".sealing-key.service";
const VALUE: &[u8] = br#"{"account":"synthetic"}"#;

fn with_fake_tool(test: &str, run: impl FnOnce(&Path)) {
    if let Some(dir) = env::var_os(HELPER_DIR) {
        run(Path::new(&dir));
        return;
    }
    let scratch = Scratch::new(&test.replace("::", "-"));
    fs::create_dir(scratch.path()).unwrap();
    // Linked rather than written, so no forked test can hold it open for
    // writing when it starts (ETXTBSY).
    symlink(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/suite/store/keychain_fixture/secret-tool.sh"
        ),
        scratch.join("secret-tool"),
    )
    .unwrap();
    let output = Command::new(env::current_exe().unwrap())
        .arg("--exact")
        .arg(format!("store::keychain_fixture::{test}"))
        .arg("--nocapture")
        .env(HELPER_DIR, scratch.path())
        .env("PATH", scratch.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_missing_lookup_leaves_the_key_of_sealed_entries_alone() {
    with_fake_tool(
        "a_missing_lookup_leaves_the_key_of_sealed_entries_alone",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            files.write(&entry, VALUE).unwrap();
            let open = || Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap());

            // A missing item with only plain entries still permits migration.
            open().seal_existing(Duration::ZERO).unwrap();
            let item = fs::read(dir.join(SERVICE)).unwrap();
            let sealed = files.read(&entry).unwrap().unwrap();
            fs::write(dir.join(format!("{SERVICE}.missing")), []).unwrap();

            let cold = open();
            let error = cold.read(&entry).unwrap_err();
            assert_eq!(
                fs::read_to_string(dir.join("writes")).unwrap(),
                format!("{SERVICE}\n")
            );
            assert_eq!(error.kind(), ErrorKind::SealingKeyMissing);
            assert_eq!(fs::read(dir.join(SERVICE)).unwrap(), item);
            assert_eq!(
                files.read(&entry).unwrap().unwrap().expose(),
                sealed.expose()
            );

            fs::remove_file(dir.join(format!("{SERVICE}.missing"))).unwrap();
            assert_eq!(cold.read(&entry).unwrap().unwrap().expose(), VALUE);
        },
    );
}

#[test]
fn rotating_to_a_new_service_reseals_entries_under_the_new_key() {
    with_fake_tool(
        "rotating_to_a_new_service_reseals_entries_under_the_new_key",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            let original = Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap());
            original.write(&entry, VALUE).unwrap();
            let old_key = fs::read(dir.join(SERVICE)).unwrap();
            assert!(!dir.join(ROTATED).exists());

            let rotating = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(SERVICE)
                .unwrap();
            Sealed::new(files.clone(), rotating)
                .reseal(Duration::ZERO)
                .unwrap();

            let only_active = Keychain::new(ROTATED, &files).unwrap();
            let reopened = Sealed::new(files, only_active);
            assert_eq!(reopened.read(&entry).unwrap().unwrap().expose(), VALUE);
            assert_eq!(fs::read(dir.join(SERVICE)).unwrap(), old_key);
            assert_ne!(fs::read(dir.join(ROTATED)).unwrap(), old_key);
            assert_eq!(
                fs::read_to_string(dir.join("writes")).unwrap(),
                format!("{SERVICE}\n{ROTATED}\n")
            );
        },
    );
}

#[test]
fn rotation_cannot_create_a_key_without_reading_a_retired_key() {
    with_fake_tool(
        "rotation_cannot_create_a_key_without_reading_a_retired_key",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            let original = Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap());
            original.write(&entry, VALUE).unwrap();
            let sealed = files.read(&entry).unwrap().unwrap();
            let old_key = fs::read(dir.join(SERVICE)).unwrap();
            fs::write(dir.join(format!("{SERVICE}.missing")), []).unwrap();

            let rotating = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(SERVICE)
                .unwrap();
            let store = Sealed::new(files.clone(), rotating);
            assert_eq!(
                store.reseal(Duration::ZERO).unwrap_err().kind(),
                ErrorKind::SealingKeyMissing
            );
            assert_eq!(
                store.write(&entry, b"replacement").unwrap_err().kind(),
                ErrorKind::SealingKeyMissing
            );
            assert!(!dir.join(ROTATED).exists());
            assert_eq!(
                fs::read_to_string(dir.join("writes")).unwrap(),
                format!("{SERVICE}\n")
            );
            assert_eq!(fs::read(dir.join(SERVICE)).unwrap(), old_key);
            assert_eq!(
                files.read(&entry).unwrap().unwrap().expose(),
                sealed.expose()
            );
        },
    );
}

#[test]
fn starting_over_after_a_lost_key_discards_sealed_entries_and_makes_a_new_key() {
    with_fake_tool(
        "starting_over_after_a_lost_key_discards_sealed_entries_and_makes_a_new_key",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            let keychain = Keychain::new(SERVICE, &files).unwrap();
            Sealed::new(files.clone(), keychain.clone())
                .write(&entry, VALUE)
                .unwrap();
            let old_key = fs::read(dir.join(SERVICE)).unwrap();
            // The keychain was reset: the item is gone for good.
            fs::remove_file(dir.join(SERVICE)).unwrap();

            let cold = Sealed::new(files.clone(), keychain.clone());
            assert_eq!(
                cold.read(&entry).unwrap_err().kind(),
                ErrorKind::SealingKeyMissing
            );
            assert!(keychain.start_over().unwrap());

            assert!(files.read(&entry).unwrap().is_none());
            let fresh = Sealed::new(files.clone(), keychain);
            assert!(fresh.read(&entry).unwrap().is_none());
            fresh.write(&entry, b"signed in again").unwrap();
            assert_eq!(
                fresh.read(&entry).unwrap().unwrap().expose(),
                b"signed in again"
            );
            assert_ne!(fs::read(dir.join(SERVICE)).unwrap(), old_key);
        },
    );
}

#[test]
fn starting_over_keeps_everything_when_the_key_can_be_read_again() {
    with_fake_tool(
        "starting_over_keeps_everything_when_the_key_can_be_read_again",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            let keychain = Keychain::new(SERVICE, &files).unwrap();
            Sealed::new(files.clone(), keychain.clone())
                .write(&entry, VALUE)
                .unwrap();
            let sealed = files.read(&entry).unwrap().unwrap();
            let old_key = fs::read(dir.join(SERVICE)).unwrap();
            fs::write(dir.join(format!("{SERVICE}.missing")), []).unwrap();

            let cold = Sealed::new(files.clone(), keychain.clone());
            assert_eq!(
                cold.read(&entry).unwrap_err().kind(),
                ErrorKind::SealingKeyMissing
            );
            // The item is readable again before the user confirms the reset.
            fs::remove_file(dir.join(format!("{SERVICE}.missing"))).unwrap();
            assert!(!keychain.start_over().unwrap());

            assert_eq!(
                files.read(&entry).unwrap().unwrap().expose(),
                sealed.expose()
            );
            assert_eq!(fs::read(dir.join(SERVICE)).unwrap(), old_key);
            assert_eq!(cold.read(&entry).unwrap().unwrap().expose(), VALUE);
        },
    );
}

#[test]
fn starting_over_during_a_rotation_keeps_entries_a_retired_key_opens() {
    with_fake_tool(
        "starting_over_during_a_rotation_keeps_entries_a_retired_key_opens",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap())
                .write(&entry, VALUE)
                .unwrap();
            let sealed = files.read(&entry).unwrap().unwrap();

            let rotating = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(SERVICE)
                .unwrap();
            assert!(!rotating.start_over().unwrap());

            assert_eq!(
                files.read(&entry).unwrap().unwrap().expose(),
                sealed.expose()
            );
            let store = Sealed::new(files.clone(), rotating);
            assert_eq!(store.read(&entry).unwrap().unwrap().expose(), VALUE);
        },
    );
}
