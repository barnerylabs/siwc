//! A newer incomplete reset cannot inherit an older key inventory.

use std::sync::Mutex;

use siwc::testing::FakeProvider;
use siwc::{AppName, Client};

use super::renewal::{AfterRefresh, sign_in};
use super::*;

fn complete_then_interrupt(files: &PrivateFiles, directory: &Path) {
    let source = Keychain::new(ROTATED, files)
        .unwrap()
        .with_retired(SERVICE)
        .unwrap();
    assert!(!source.start_over().unwrap());
    let reset_path = directory.join("store/.sealing-key.resets");
    let first = fs::read(&reset_path).unwrap();
    let completed = u64::from_le_bytes(first[16..24].try_into().unwrap());
    fs::remove_file(directory.join(ROTATED)).unwrap();
    assert!(!source.start_over().unwrap());
    let mut interrupted = fs::read(&reset_path).unwrap();
    assert!(u64::from_le_bytes(interrupted[..8].try_into().unwrap()) > completed);
    interrupted[16..24].copy_from_slice(&completed.to_le_bytes());
    fs::write(reset_path, interrupted).unwrap();
}

#[test]
fn older_completed_inventory_cannot_authorise_a_key_missing_in_later_uncompleted_reset() {
    with_fake_tool(
        "reset_history::older_completed_inventory_cannot_authorise_a_key_missing_in_later_uncompleted_reset",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let old = Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap());
            old.write(&name("seed"), VALUE).unwrap();
            old.write(&name("account-1"), VALUE).unwrap();
            let source = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(SERVICE)
                .unwrap();
            let warm = Sealed::new(files.clone(), source.clone());
            assert_eq!(
                warm.read(&name("account-1")).unwrap().unwrap().expose(),
                VALUE
            );
            complete_then_interrupt(&files, dir);
            warm.write(&name("account-1"), b"synthetic successor")
                .unwrap();
            let cold = Sealed::new(files, source);
            assert_eq!(
                cold.read(&name("account-1")).unwrap().unwrap().expose(),
                b"synthetic successor"
            );
        },
    );
}

#[test]
fn spent_refresh_successor_is_readable_after_two_reset_inventories() {
    with_fake_tool(
        "reset_history::spent_refresh_successor_is_readable_after_two_reset_inventories",
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
            let during = files.clone();
            let directory = dir.to_path_buf();
            let transport = AfterRefresh {
                provider: provider.clone(),
                once: Mutex::new(Some(move || complete_then_interrupt(&during, &directory))),
            };
            let current = Client::new(
                app.clone(),
                Sealed::new(files.clone(), source.clone()),
                transport,
            );
            let first = current.access_token(&id).unwrap();
            let successor = current.access_token_after_rejection(&id, &first).unwrap();
            let cold = Client::new(app, Sealed::new(files, source), provider);
            assert_eq!(cold.access_token(&id).unwrap().expose(), successor.expose());
            assert!(cold.access_token_after_rejection(&id, &successor).is_ok());
        },
    );
}
