//! Moving a signed-in account to another installation as a sealed bundle.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use siwc::store::{EntryName, MemoryStore, Store};
use siwc::{AccountId, AccountState, AppName, Client, ErrorKind};

use crate::support::NOW;
use crate::support::browser::{Browser, PATIENCE};
use crate::support::clock::TestClock;
use crate::support::provider::User;
use crate::support::random::Seeded;
use crate::support::rig::Rig;

const PASSPHRASE: &[u8] = b"synthetic-transfer-passphrase";

struct Destination(PathBuf);

impl Destination {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let number = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("siwc-export-{}-{number}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn bundle(&self) -> PathBuf {
        self.0.join("account.bundle")
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn export(client: &Client, id: &AccountId) -> Vec<u8> {
    let destination = Destination::new();
    let path = destination.bundle();
    client.export_account_to(id, PASSPHRASE, &path).unwrap();
    fs::read(path).unwrap()
}

#[test]
fn export_publishes_a_complete_private_bundle() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let destination = Destination::new();
    let path = destination.bundle();

    rig.client
        .export_account_to(account.id(), PASSPHRASE, &path)
        .unwrap();

    let bytes = fs::read(&path).unwrap();
    assert!(bytes.starts_with(b"SIWCBUN1"), "the bundle must be on disk");
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_dir(&destination.0).unwrap().count(), 1);
    assert!(rig.credentials_of(account.id()).is_none());
}

#[test]
fn an_existing_export_destination_is_never_replaced() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let before = rig.store.snapshot();
    let destination = Destination::new();
    let path = destination.bundle();
    fs::write(&path, b"previous bundle").unwrap();

    let error = rig
        .client
        .export_account_to(account.id(), PASSPHRASE, &path)
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(rig.store.snapshot(), before);
    assert_eq!(fs::read(path).unwrap(), b"previous bundle");
    assert_eq!(fs::read_dir(&destination.0).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn a_dangling_destination_link_is_never_replaced() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let before = rig.store.snapshot();
    let destination = Destination::new();
    let link = destination.0.join("bundle-link");
    let missing = destination.0.join("missing-target");
    symlink(&missing, &link).unwrap();

    let error = rig
        .client
        .export_account_to(account.id(), PASSPHRASE, &link)
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(rig.store.snapshot(), before);
    assert_eq!(fs::read_link(link).unwrap(), missing);
    assert!(!missing.exists());
    assert_eq!(fs::read_dir(&destination.0).unwrap().count(), 1);
}

#[test]
fn two_exports_to_the_same_path_move_only_one_session() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sam = rig.add(&User::sam());
    let destination = Destination::new();
    let path = destination.bundle();
    let ready = Barrier::new(2);
    let export = |id| {
        ready.wait();
        rig.client.export_account_to(id, PASSPHRASE, &path)
    };
    let accounts = [alex.id(), sam.id()];
    let results = thread::scope(|scope| {
        accounts
            .map(|id| scope.spawn(move || export(id)))
            .map(|job| job.join().unwrap())
    });

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    for (id, result) in accounts.into_iter().zip(results) {
        if let Err(error) = result {
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
            assert_eq!(
                rig.client.account(id).unwrap().state(),
                AccountState::SignedIn
            );
            assert!(rig.credentials_of(id).is_some());
        } else {
            assert_eq!(
                rig.client.account(id).unwrap().state(),
                AccountState::SignedOut
            );
            assert!(rig.credentials_of(id).is_none());
        }
    }
    assert_eq!(fs::read_dir(&destination.0).unwrap().count(), 1);
    assert!(fs::read(&path).unwrap().starts_with(b"SIWCBUN1"));
}

#[test]
fn an_export_publishes_the_bundle_before_removing_credentials() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let before = rig.store.snapshot();
    let destination = Destination::new();
    let path = destination.bundle();
    rig.store.fail_removes();

    let error = rig
        .client
        .export_account_to(account.id(), PASSPHRASE, &path)
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Store);
    assert!(fs::read(&path).unwrap().starts_with(b"SIWCBUN1"));
    assert_eq!(rig.store.snapshot(), before);
}

#[test]
fn exporting_moves_the_session_without_revoking_and_the_target_keeps_its_own_host_id() {
    let laptop = Rig::new();
    let alex = laptop.add(&User::alex());
    laptop.client.set_label(alex.id(), Some("Work")).unwrap();
    let laptop_host_before: serde_json::Value =
        serde_json::from_slice(&laptop.store.bytes("installation").unwrap()).unwrap();

    // Build a second installation sharing the same fake provider, with a different seed so its
    // generated HostId is distinct.
    let remote_store = Arc::new(MemoryStore::new());
    let remote_clock = TestClock::new(NOW);
    let remote = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        Arc::clone(&remote_store),
        Arc::clone(&laptop.transport),
    )
    .clock(remote_clock.clone())
    .entropy(Seeded::new(42_424))
    .build();

    laptop.journal.clear();
    let bundle = export(&laptop.client, alex.id());
    assert!(
        !String::from_utf8_lossy(&bundle).contains("refresh-"),
        "bundle ciphertext exposes no plain token"
    );
    assert!(
        laptop.journal.about("send").is_empty(),
        "exporting does not call /oauth/revoke"
    );
    assert_eq!(
        laptop.client.account(alex.id()).unwrap().state(),
        AccountState::SignedOut
    );
    assert_eq!(
        laptop.client.access_token(alex.id()).unwrap_err().kind(),
        ErrorKind::SignInRequired
    );

    let imported = remote.import_account(&bundle, PASSPHRASE).unwrap();
    assert_eq!(imported.state(), AccountState::SignedIn);
    assert_eq!(imported.label(), Some("Work"));
    assert_eq!(imported.identity().email(), Some("alex@example.com"));
    assert!(imported.plan_use());

    let remote_install: serde_json::Value = serde_json::from_slice(
        remote_store
            .read(&EntryName::new("installation").unwrap())
            .unwrap()
            .unwrap()
            .expose(),
    )
    .unwrap();
    assert_ne!(
        remote_install["host_id"], laptop_host_before["host_id"],
        "each host keeps its own HostId"
    );

    // Advance past token expiry on the remote machine: the rotated refresh token works there!
    remote_clock.set(NOW + 3600);
    laptop.at(3600);
    let renewed = remote.access_token(imported.id()).unwrap();
    assert!(!renewed.expose().is_empty());

    let repeated = remote.import_account(&bundle, PASSPHRASE).unwrap();
    assert_eq!(repeated.id(), imported.id());
    assert_eq!(
        remote.access_token(imported.id()).unwrap().expose(),
        renewed.expose()
    );

    // Re-signing in on the laptop and re-exporting updates the existing account on the remote VM
    // in place instead of duplicating its client_id.
    let installation_entry = EntryName::new("installation").unwrap();
    let before_update = remote_store.read(&installation_entry).unwrap().unwrap();
    let sign_in = laptop.client.sign_in_again(alex.id()).unwrap();
    let browser = Browser::new(sign_in.start_link());
    let provider = Arc::clone(&laptop.provider);
    let tab = thread::spawn(move || {
        let mut updated = User::alex();
        updated.name = Some("Alex Updated");
        browser.approve(&provider, &updated)
    });
    sign_in.finish(PATIENCE).unwrap();
    assert_eq!(tab.join().unwrap().status, 200);

    let refreshed_bundle = export(&laptop.client, alex.id());
    let updated = remote
        .import_account(&refreshed_bundle, PASSPHRASE)
        .unwrap();
    assert_eq!(updated.id(), imported.id());
    assert_eq!(updated.identity().name(), Some("Alex Updated"));
    assert_eq!(remote.accounts().unwrap().len(), 1);

    // An interrupted import can leave the credentials written but the old
    // installation record intact. Retrying must finish the metadata update.
    remote_store
        .write(&installation_entry, before_update.expose())
        .unwrap();
    let repaired = remote
        .import_account(&refreshed_bundle, PASSPHRASE)
        .unwrap();
    assert_eq!(repaired.identity().name(), Some("Alex Updated"));

    remote.set_label(repaired.id(), None).unwrap();
    let repeated = remote
        .import_account(&refreshed_bundle, PASSPHRASE)
        .unwrap();
    assert_eq!(repeated.label(), None);
}

#[test]
fn an_export_output_failure_leaves_the_source_session_in_place() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let before = rig.store.snapshot();
    let destination = Destination::new();
    let path = destination.0.join("missing-parent").join("account.bundle");

    let error = rig
        .client
        .export_account_to(account.id(), PASSPHRASE, &path)
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Store);
    assert_eq!(rig.store.snapshot(), before);
    assert_eq!(fs::read_dir(&destination.0).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn a_directory_sync_failure_keeps_the_source_session_in_place() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let before = rig.store.snapshot();
    let destination = Destination::new();
    let path = destination.bundle();
    // Search and write permission allow publication, but syncing the
    // directory uses a read handle. Skip if this process can bypass the mode.
    fs::set_permissions(&destination.0, fs::Permissions::from_mode(0o300)).unwrap();
    let result = fs::File::open(&destination.0).is_err().then(|| {
        rig.client
            .export_account_to(account.id(), PASSPHRASE, &path)
    });
    fs::set_permissions(&destination.0, fs::Permissions::from_mode(0o700)).unwrap();
    let Some(result) = result else { return };

    let error = result.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Store);
    assert_eq!(
        error.to_string(),
        "the new file's directory could not be synced"
    );
    assert!(!path.exists(), "an output failure must remove the new file");
    assert_eq!(rig.store.snapshot(), before);
}

#[test]
fn an_in_flight_sign_in_again_cannot_undo_an_export_that_crossed_it() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());

    let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
    let browser = Browser::new(sign_in.start_link());
    let _bundle = export(&rig.client, alex.id());

    let provider = Arc::clone(&rig.provider);
    let tab = thread::spawn(move || browser.approve(&provider, &User::alex()));
    let error = sign_in.finish(PATIENCE).unwrap_err();
    let _ = tab.join().unwrap();
    assert_eq!(error.kind(), ErrorKind::SignInRequired);
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedOut
    );
}

#[test]
fn wrong_passphrases_damaged_bundles_and_unexportable_accounts_fail_cleanly() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let destination = Destination::new();
    let path = destination.bundle();

    // Passphrases shorter than 8 bytes or longer than 1024 bytes are InvalidInput and leave the
    // account signed in.
    for bad_pass in [&b""[..], b"short77", &[b'x'; 1025]] {
        assert_eq!(
            rig.client
                .export_account_to(alex.id(), bad_pass, &path)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
    }
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedIn
    );

    let bundle = export(&rig.client, alex.id());
    // Exporting an already signed-out account fails with SignInRequired.
    assert_eq!(
        rig.client
            .export_account_to(alex.id(), PASSPHRASE, &path)
            .unwrap_err()
            .kind(),
        ErrorKind::SignInRequired
    );
    assert!(!path.exists());

    let target = Rig::new();
    // Wrong passphrase -> BundleRejected, nothing stored.
    let wrong = target
        .client
        .import_account(&bundle, b"wrong-passphrase-123")
        .unwrap_err();
    assert_eq!(wrong.kind(), ErrorKind::BundleRejected);
    assert!(!format!("{wrong} {wrong:?}").contains("wrong-passphrase"));
    assert!(target.client.accounts().unwrap().is_empty());

    // Tampered ciphertext, truncated bundle, wrong magic, and >96 KiB input -> BundleRejected.
    let mut flipped = bundle.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    let mut oversized = bundle.clone();
    oversized.resize(Client::MAX_BUNDLE_LEN + 1, 0);
    for damaged in [
        flipped.as_slice(),
        &bundle[..20],
        b"NOTMAGIC01234567890123456789012345678901234567890123456789",
        oversized.as_slice(),
    ] {
        assert_eq!(
            target
                .client
                .import_account(damaged, PASSPHRASE)
                .unwrap_err()
                .kind(),
            ErrorKind::BundleRejected
        );
    }
    assert!(target.client.accounts().unwrap().is_empty());
}

#[test]
fn failed_installation_updates_keep_imported_credentials_for_retry() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let token_before = rig.token(alex.id());

    // Fail writing `installation` during export: credentials must be restored.
    rig.store.fail_one_write_after(0);
    let destination = Destination::new();
    let path = destination.bundle();
    assert_eq!(
        rig.client
            .export_account_to(alex.id(), PASSPHRASE, &path)
            .unwrap_err()
            .kind(),
        ErrorKind::Store
    );
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedIn
    );
    assert_eq!(
        rig.client.access_token(alex.id()).unwrap().expose(),
        token_before
    );
    assert!(fs::read(&path).unwrap().starts_with(b"SIWCBUN1"));
    rig.journal.assert_lock_rules();

    // Export succeeds once the store is healthy, leaving `alex` SignedOut.
    let bundle = export(&rig.client, alex.id());
    let creds_entry = format!("account-{}", alex.id());
    assert!(rig.store.bytes(&creds_entry).is_none());

    // Fail writing `installation` (the 2nd write, right after `write_credentials`)
    // when re-importing into that SignedOut account: credentials remain for retry.
    rig.store.fail_one_write_after(1);
    assert_eq!(
        rig.client
            .import_account(&bundle, PASSPHRASE)
            .unwrap_err()
            .kind(),
        ErrorKind::Store
    );
    assert!(rig.store.bytes(&creds_entry).is_some());
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedOut
    );
    assert_eq!(
        rig.client
            .import_account(&bundle, PASSPHRASE)
            .unwrap()
            .state(),
        AccountState::SignedIn
    );
}

#[test]
fn export_preserves_published_sign_out_even_when_confirmation_fails() {
    for unreadable in [false, true] {
        let rig = Rig::new();
        let account = rig.add(&User::alex());
        let id = account.id();
        *rig.store.fail_after_publish.lock().unwrap() = Some(unreadable);
        let destination = Destination::new();
        assert_eq!(
            rig.client
                .export_account_to(id, PASSPHRASE, destination.bundle())
                .unwrap_err()
                .kind(),
            ErrorKind::Store
        );
        assert!(rig.store.bytes(&format!("account-{id}")).is_none());
        assert_eq!(
            rig.client.account(id).unwrap().state(),
            AccountState::SignedOut
        );
        assert!(!rig.client.sign_out(id).unwrap().revocation_confirmed());
        assert_eq!(rig.journal.count("send revoke"), 0);
        rig.journal.assert_lock_rules();
    }
}

#[test]
fn exhausted_sign_out_generation_cannot_move_or_revoke_the_session() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let mut record: serde_json::Value =
        serde_json::from_slice(&rig.store.bytes("installation").unwrap()).unwrap();
    record["accounts"][0]["sign_outs"] = u64::MAX.into();
    rig.store.put("installation", record.to_string().as_bytes());
    let before = rig.store.snapshot();
    let destination = Destination::new();
    let path = destination.bundle();
    assert_eq!(
        rig.client
            .export_account_to(account.id(), PASSPHRASE, &path)
            .unwrap_err()
            .kind(),
        ErrorKind::StoreCorrupt
    );
    assert!(!path.exists());
    assert_eq!(
        rig.client.sign_out(account.id()).unwrap_err().kind(),
        ErrorKind::StoreCorrupt
    );
    assert_eq!(rig.store.snapshot(), before);
    assert_eq!(rig.journal.count("send revoke"), 0);
}

#[test]
fn transfer_size_is_decided_by_the_complete_bundle() {
    for (length, fits) in [(10_000, true), (16_384, false)] {
        let rig = Rig::new();
        let account = rig.add(&User::alex());
        let id = account.id();
        let entry = format!("account-{id}");
        let mut credentials: serde_json::Value =
            serde_json::from_slice(&rig.store.bytes(&entry).unwrap()).unwrap();
        credentials["refresh_token"] = "\u{0001}".repeat(length).into();
        rig.store.put(&entry, credentials.to_string().as_bytes());
        let before = rig.store.snapshot();
        let destination = Destination::new();
        let path = destination.bundle();
        let result = rig.client.export_account_to(id, PASSPHRASE, &path);
        if fits {
            result.unwrap();
            Rig::new()
                .client
                .import_account(&fs::read(path).unwrap(), PASSPHRASE)
                .unwrap();
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Store);
            assert!(error.to_string().contains("bundle size"));
            assert_eq!(rig.store.snapshot(), before);
            assert!(!path.exists());
        }
    }
}

#[test]
fn refresh_and_import_filter_diagnostics_that_repeat_credentials() {
    use crate::support::recording::Failure;
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let token = rig.token(account.id());
    rig.transport
        .fail("refresh", 1, Failure::Diagnostic(token.clone()));
    rig.at(3600);
    let error = rig.client.access_token(account.id()).unwrap_err();
    assert!(error.request_id().is_none());
    assert!(!format!("{error:?} {error}").contains(&token));
    let bundle = export(&rig.client, account.id());
    let target = Rig::new();
    target
        .transport
        .fail("keys", 1, Failure::Diagnostic(token.clone()));
    let error = target
        .client
        .import_account(&bundle, PASSPHRASE)
        .unwrap_err();
    assert!(error.request_id().is_none());
    assert!(!format!("{error:?} {error}").contains(&token));
}

#[test]
fn import_reports_a_repeated_random_account_id_without_changing_the_store() {
    let source = Rig::new();
    let one = source.add(&User::alex());
    let two = source.add(&User::alex());
    let target = Rig::new();
    let importer = || target.builder("Synthetic").entropy(Seeded::new(42)).build();
    importer()
        .import_account(&export(&source.client, one.id()), PASSPHRASE)
        .unwrap();
    let before = target.store.snapshot();
    let error = importer()
        .import_account(&export(&source.client, two.id()), PASSPHRASE)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Randomness);
    assert_eq!(target.store.snapshot(), before);
}

#[test]
fn export_reports_the_installation_error_when_credential_restore_also_fails() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    rig.store
        .fail_writes_with("installation", siwc::Error::store_busy());
    rig.store.fail_writes_to("account-");
    let destination = Destination::new();
    let error = rig
        .client
        .export_account_to(account.id(), PASSPHRASE, destination.bundle())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::StoreBusy);
    assert_eq!(
        rig.journal
            .count(&format!("failed write account-{}", account.id())),
        1
    );
}
