//! Renewal across explicit recovery from a lost key.

use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use siwc::testing::FakeProvider;
use siwc::{AppName, Client};

use super::super::set_mode;
use super::renewal::{AfterRefresh, sign_in};
use super::*;

fn renew_across_reset(label: &str, reset: impl FnOnce(&Path, &Path, &Keychain) + Send + 'static) {
    with_fake_tool(label, |dir| {
        let files = PrivateFiles::open(dir.join("store")).unwrap();
        let original = Keychain::new(SERVICE, &files).unwrap();
        let rotating = Keychain::new(ROTATED, &files)
            .unwrap()
            .with_retired(SERVICE)
            .unwrap();
        let provider = FakeProvider::new();
        let app = AppName::new("Offline Test App").unwrap();
        let old = Client::new(
            app.clone(),
            Sealed::new(files.clone(), original),
            provider.clone(),
        );
        let id = sign_in(&old, &provider);

        let active = dir.join(ROTATED);
        let active_during_refresh = active.clone();
        let store_during_refresh = dir.join("store");
        let resetting = rotating.clone();
        let transport = AfterRefresh {
            provider: provider.clone(),
            once: Mutex::new(Some(move || {
                reset(&active_during_refresh, &store_during_refresh, &resetting)
            })),
        };
        let new = Client::new(
            app.clone(),
            Sealed::new(files.clone(), rotating.clone()),
            transport,
        );
        let first = new.access_token(&id).unwrap();
        let lost = fs::read(&active).unwrap();
        let successor = new.access_token_after_rejection(&id, &first).unwrap();

        let cold = Client::new(app, Sealed::new(files, rotating), provider);
        let current = cold.access_token(&id);
        let renewed = cold.access_token_after_rejection(&id, &successor);
        assert_eq!(current.unwrap().expose(), successor.expose());
        assert_ne!(renewed.unwrap().expose(), successor.expose());
        assert_ne!(fs::read(active).unwrap(), lost);
    });
}

fn retains_every_entry(key: &Keychain) {
    // All entries still open under the retired key.
    assert!(!key.start_over().unwrap());
}

#[test]
fn a_reset_that_found_the_active_key_missing_never_reuses_it() {
    renew_across_reset(
        "reset_renewal::a_reset_that_found_the_active_key_missing_never_reuses_it",
        |active, _, key| {
            fs::remove_file(active).unwrap();
            retains_every_entry(key);
        },
    );
}

#[test]
fn a_reset_that_found_a_different_active_key_never_reuses_the_lost_one() {
    renew_across_reset(
        "reset_renewal::a_reset_that_found_a_different_active_key_never_reuses_the_lost_one",
        |active, _, key| {
            replace_active(active);
            retains_every_entry(key);
        },
    );
}

#[test]
fn a_later_reset_cannot_reauthorise_a_key_an_earlier_reset_cleared() {
    renew_across_reset(
        "reset_renewal::a_later_reset_cannot_reauthorise_a_key_an_earlier_reset_cleared",
        |active, _, key| {
            let previous = fs::read(active).unwrap();
            fs::remove_file(active).unwrap();
            retains_every_entry(key);
            fs::write(active, previous).unwrap();
            retains_every_entry(key);
            replace_active(active);
        },
    );
}

fn replace_active(path: &Path) {
    fs::write(path, format!("{}\n", "c1".repeat(32))).unwrap();
}

fn crash_before_readable_keys(store_dir: &Path) {
    let generation_path = store_dir.join(".sealing-key.generation");
    let current = u64::from_le_bytes(fs::read(&generation_path).unwrap().try_into().unwrap());
    let next = current + 1;
    let mut history = Vec::new();
    history.extend_from_slice(&next.to_le_bytes());
    history.extend_from_slice(&0_u64.to_le_bytes());
    history.extend_from_slice(&0_u64.to_le_bytes());
    let history_path = store_dir.join(".sealing-key.resets");
    fs::write(&history_path, history).unwrap();
    fs::set_permissions(history_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&generation_path, next.to_le_bytes()).unwrap();
    fs::set_permissions(&generation_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!store_dir.join(".sealing-key.reset-keys").exists());
}

#[test]
fn a_missing_readable_key_record_keeps_a_retained_cached_entry() {
    with_fake_tool(
        "reset_renewal::a_missing_readable_key_record_keeps_a_retained_cached_entry",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let provider = FakeProvider::new();
            let app = AppName::new("Offline Test App").unwrap();
            let source = Keychain::new(SERVICE, &files).unwrap();
            let store_dir = dir.join("store");
            let missing = dir.join(format!("{SERVICE}.missing"));
            let missing_during_refresh = missing.clone();
            let transport = AfterRefresh {
                provider: provider.clone(),
                once: Mutex::new(Some(move || {
                    crash_before_readable_keys(&store_dir);
                    fs::write(missing_during_refresh, []).unwrap();
                })),
            };
            let warm = Client::new(
                app.clone(),
                Sealed::new(files.clone(), source.clone()),
                transport,
            );
            let id = sign_in(&warm, &provider);
            let first = warm.access_token(&id).unwrap();
            let successor = warm.access_token_after_rejection(&id, &first).unwrap();
            fs::remove_file(missing).unwrap();
            let cold = Client::new(app, Sealed::new(files, source), provider);
            assert_eq!(cold.access_token(&id).unwrap().expose(), successor.expose());
            assert!(cold.access_token_after_rejection(&id, &successor).is_ok());
        },
    );
}

#[test]
fn unrecorded_reset_with_locked_keychain_keeps_spent_successor() {
    with_fake_tool(
        "reset_renewal::unrecorded_reset_with_locked_keychain_keeps_spent_successor",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let provider = FakeProvider::new();
            let app = AppName::new("Offline Test App").unwrap();
            let original = Client::new(
                app.clone(),
                Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap()),
                provider.clone(),
            );
            let id = sign_in(&original, &provider);
            let source = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(SERVICE)
                .unwrap();
            let store_dir = dir.join("store");
            let locked = dir.join("locked");
            let lock_during_refresh = locked.clone();
            let transport = AfterRefresh {
                provider: provider.clone(),
                once: Mutex::new(Some(move || {
                    crash_before_readable_keys(&store_dir);
                    fs::write(lock_during_refresh, []).unwrap();
                })),
            };
            let warm = Client::new(
                app.clone(),
                Sealed::new(files.clone(), source.clone()),
                transport,
            );
            let first = warm.access_token(&id).unwrap();
            assert!(dir.join(ROTATED).exists());
            let successor = warm.access_token_after_rejection(&id, &first).unwrap();
            fs::remove_file(locked).unwrap();
            let cold = Client::new(app, Sealed::new(files, source), provider);
            assert_eq!(cold.access_token(&id).unwrap().expose(), successor.expose());
            assert!(cold.access_token_after_rejection(&id, &successor).is_ok());
        },
    );
}

#[test]
fn a_cached_key_uses_its_validated_reset_lock_after_the_path_becomes_nonprivate() {
    with_fake_tool(
        "reset_renewal::a_cached_key_uses_its_validated_reset_lock_after_the_path_becomes_nonprivate",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let provider = FakeProvider::new();
            let app = AppName::new("Offline Test App").unwrap();
            let original = Keychain::new(SERVICE, &files).unwrap();
            let rotating = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(SERVICE)
                .unwrap();
            let activate = Sealed::new(files.clone(), rotating.clone());
            let lock_path = dir.join("store/.sealing-key.reset.lock");
            let hook = move || {
                assert!(activate.read(&name("installation")).unwrap().is_some());
                fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
            };
            let transport = AfterRefresh {
                provider: provider.clone(),
                once: Mutex::new(Some(hook)),
            };
            let warm = Client::new(app.clone(), Sealed::new(files.clone(), original), transport);
            let id = sign_in(&warm, &provider);
            let first = warm.access_token(&id).unwrap();
            let successor = warm.access_token_after_rejection(&id, &first).unwrap();
            fs::set_permissions(
                dir.join("store/.sealing-key.reset.lock"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let cold = Client::new(app, Sealed::new(files, rotating), provider);
            assert_eq!(cold.access_token(&id).unwrap().expose(), successor.expose());
            assert!(cold.access_token_after_rejection(&id, &successor).is_ok());
        },
    );
}

fn reject_planted_lock(label: &str, plant: impl FnOnce(&Path)) {
    with_fake_tool(label, |dir| {
        let store_dir = dir.join("store");
        let files = PrivateFiles::open(&store_dir).unwrap();
        let source = Keychain::new(SERVICE, &files).unwrap();
        let provider = FakeProvider::new();
        let app = AppName::new("Offline Test App").unwrap();
        let old = Client::new(
            app.clone(),
            Sealed::new(files.clone(), source.clone()),
            provider.clone(),
        );
        let id = sign_in(&old, &provider);
        let first = old.access_token(&id).unwrap();
        let path = store_dir.join(".sealing-key.reset.lock");
        let _ = fs::remove_file(&path);
        plant(&path);

        let sent = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&sent);
        let transport = AfterRefresh {
            provider: provider.clone(),
            once: Mutex::new(Some(move || {
                counted.fetch_add(1, Ordering::Relaxed);
            })),
        };
        let cold = Client::new(app, Sealed::new(files, source), transport);
        let result = cold.access_token_after_rejection(&id, &first);
        assert_eq!(
            sent.load(Ordering::Relaxed),
            0,
            "the refresh token was spent"
        );
        assert_eq!(result.unwrap_err().kind(), ErrorKind::StoreNotPrivate);
        fs::remove_file(path).unwrap();
        let renewed = cold.access_token_after_rejection(&id, &first).unwrap();
        assert_ne!(renewed.expose(), first.expose());
    });
}

#[test]
fn a_shared_reset_lock_file_is_refused_before_sending_a_refresh() {
    reject_planted_lock(
        "reset_renewal::a_shared_reset_lock_file_is_refused_before_sending_a_refresh",
        |path| {
            fs::write(path, []).unwrap();
            set_mode(path, 0o644);
        },
    );
}

#[test]
fn a_link_at_the_reset_lock_path_is_refused_before_sending_a_refresh() {
    reject_planted_lock(
        "reset_renewal::a_link_at_the_reset_lock_path_is_refused_before_sending_a_refresh",
        |path| {
            let target = path.with_file_name(".private-target");
            fs::write(&target, []).unwrap();
            set_mode(&target, 0o600);
            symlink(target, path).unwrap();
        },
    );
}

#[test]
fn a_warm_successor_never_opens_the_reset_lock_for_the_same_generation() {
    with_fake_tool(
        "reset_renewal::a_warm_successor_never_opens_the_reset_lock_for_the_same_generation",
        |dir| {
            let store_dir = dir.join("store");
            let files = PrivateFiles::open(&store_dir).unwrap();
            let source = Keychain::new(SERVICE, &files).unwrap();
            let provider = FakeProvider::new();
            let app = AppName::new("Offline Test App").unwrap();
            let warm = Client::new(
                app.clone(),
                Sealed::new(files.clone(), source),
                provider.clone(),
            );
            let id = sign_in(&warm, &provider);
            let first = warm.access_token(&id).unwrap();
            let reset_lock = store_dir.join(".sealing-key.reset.lock");
            fs::write(&reset_lock, []).unwrap();
            set_mode(&reset_lock, 0o644);
            let successor = warm.access_token_after_rejection(&id, &first);
            set_mode(&reset_lock, 0o600);
            let successor = successor.unwrap();

            let rotating = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(SERVICE)
                .unwrap();
            let cold = Client::new(app, Sealed::new(files, rotating), provider);
            assert_eq!(cold.access_token(&id).unwrap().expose(), successor.expose());
            assert_ne!(
                cold.access_token_after_rejection(&id, &successor)
                    .unwrap()
                    .expose(),
                successor.expose()
            );
        },
    );
}
