//! Store changes after the provider has spent a refresh token.

use std::fmt;
use std::sync::{Arc, Mutex};

use siwc::protocol::{HttpRequest, HttpResponse};
use siwc::testing::{FakeProvider, FakeUser};
use siwc::{AccountId, AccountState, AppName, Client, Error, Transport};

use super::*;

pub(super) struct AfterRefresh<F> {
    pub(super) provider: FakeProvider,
    pub(super) once: Mutex<Option<F>>,
}

impl<F> fmt::Debug for AfterRefresh<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AfterRefresh")
    }
}

impl<F: FnOnce() + Send> Transport for AfterRefresh<F> {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        let response = self.provider.send(request)?;
        if request.body().starts_with(b"grant_type=refresh_token")
            && let Some(hook) = self.once.lock().unwrap().take()
        {
            hook();
        }
        Ok(response)
    }
}

pub(super) fn sign_in(client: &Client, provider: &FakeProvider) -> AccountId {
    let mut sign_in = client.add_account_manually().unwrap();
    let redirect = provider
        .approve_manual(&sign_in, FakeUser::new("sample@example.invalid"))
        .unwrap();
    sign_in.finish(&redirect).unwrap().account().id().clone()
}

#[test]
fn a_held_key_lock_cannot_strand_a_renewed_session() {
    with_fake_tool(
        "renewal::a_held_key_lock_cannot_strand_a_renewed_session",
        |dir| {
            let store_dir = dir.join("store");
            let files = PrivateFiles::open(&store_dir).unwrap();
            let source = Keychain::new(SERVICE, &files).unwrap();
            let provider = FakeProvider::new();
            let app = AppName::new("Offline Test App").unwrap();
            // Warm the store and create the lock before opening the second handle.
            let store = Sealed::new(files.clone(), source.clone());
            store.write(&name("example"), VALUE).unwrap();
            let lock = Arc::new(
                fs::File::options()
                    .read(true)
                    .write(true)
                    .open(store_dir.join(".sealing-key.lock"))
                    .unwrap(),
            );
            let held_on_refresh = Arc::clone(&lock);
            let transport = AfterRefresh {
                provider: provider.clone(),
                once: Mutex::new(Some(move || held_on_refresh.try_lock().unwrap())),
            };
            let client = Client::new(app.clone(), store, transport);
            let id = sign_in(&client, &provider);
            let first = client.access_token(&id).unwrap();

            // The lock stays held until renewal returns, even if it takes its
            // full patience and fails. There is no timing window for success.
            let renewed = client.access_token_after_rejection(&id, &first);
            let second =
                renewed.expect("the rotated successor must be stored while the key lock is held");
            let held = fs::File::open(store_dir.join(".sealing-key.lock")).unwrap();
            assert!(matches!(held.try_lock(), Err(fs::TryLockError::WouldBlock)));
            assert_ne!(second.expose(), first.expose());
            assert_eq!(client.access_token(&id).unwrap().expose(), second.expose());
            lock.unlock().unwrap();

            let cold = Client::new(app, Sealed::new(files, source), provider);
            assert_eq!(cold.access_token(&id).unwrap().expose(), second.expose());
            let third = cold.access_token_after_rejection(&id, &second).unwrap();
            assert_ne!(third.expose(), second.expose());
        },
    );
}

#[test]
fn an_old_service_stores_the_renewed_session_after_rotation() {
    with_fake_tool(
        "renewal::an_old_service_stores_the_renewed_session_after_rotation",
        |dir| {
            let store_dir = dir.join("store");
            let files = PrivateFiles::open(&store_dir).unwrap();
            let original = Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap());
            let source = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(SERVICE)
                .unwrap();
            let rotated = Arc::new(Sealed::new(files.clone(), source));
            let activating = Arc::clone(&rotated);
            let marker = store_dir.join(MARKER);
            let activation_marker = marker.clone();
            let provider = FakeProvider::new();
            let transport = AfterRefresh {
                provider: provider.clone(),
                once: Mutex::new(Some(move || {
                    assert!(activating.read(&name("installation")).unwrap().is_some());
                    assert_eq!(fs::read_to_string(activation_marker).unwrap(), ROTATED);
                })),
            };
            let app = AppName::new("Offline Test App").unwrap();
            let old = Client::new(app.clone(), original, transport);
            let id = sign_in(&old, &provider);
            let first = old.access_token(&id).unwrap();

            let successor = old
                .access_token_after_rejection(&id, &first)
                .expect("the previous release must be able to store its successor");
            assert_ne!(successor.expose(), first.expose());
            assert_eq!(fs::read_to_string(marker).unwrap(), ROTATED);

            let new = Client::new(app, rotated, provider);
            assert_eq!(new.access_token(&id).unwrap().expose(), successor.expose());
            let renewed = new.access_token_after_rejection(&id, &successor).unwrap();
            assert_ne!(renewed.expose(), successor.expose());
        },
    );
}

#[test]
fn a_temporarily_unavailable_old_key_does_not_strand_a_successor() {
    with_fake_tool(
        "renewal::a_temporarily_unavailable_old_key_does_not_strand_a_successor",
        |dir| {
            for failure in ["missing", "fail-readback"] {
                let store_dir = dir.join(failure);
                let files = PrivateFiles::open(&store_dir).unwrap();
                let original = Keychain::new(SERVICE, &files).unwrap();
                let rotated = Keychain::new(ROTATED, &files)
                    .unwrap()
                    .with_retired(SERVICE)
                    .unwrap();
                let provider = FakeProvider::new();
                let app = AppName::new("Offline Test App").unwrap();
                let failure_flag = dir.join(format!("{SERVICE}.{failure}"));
                let activating = Sealed::new(files.clone(), rotated.clone());
                let hide_old_key = failure_flag.clone();
                let transport = AfterRefresh {
                    provider: provider.clone(),
                    once: Mutex::new(Some(move || {
                        assert!(activating.read(&name("installation")).unwrap().is_some());
                        fs::write(hide_old_key, []).unwrap();
                    })),
                };
                let old = Client::new(app.clone(), Sealed::new(files.clone(), original), transport);
                let id = sign_in(&old, &provider);
                let first = old.access_token(&id).unwrap();
                let successor = old.access_token_after_rejection(&id, &first);
                fs::remove_file(failure_flag).unwrap();
                assert_eq!(fs::read_to_string(store_dir.join(MARKER)).unwrap(), ROTATED);
                let successor = successor.expect("rotation must preserve the refresh successor");

                let new = Client::new(app, Sealed::new(files, rotated), provider);
                assert_eq!(new.access_token(&id).unwrap().expose(), successor.expose());
                let renewed = new.access_token_after_rejection(&id, &successor).unwrap();
                assert_ne!(renewed.expose(), successor.expose());

                // Let the next iteration exercise an actual creation as well.
                fs::remove_file(dir.join(ROTATED)).unwrap();
            }
        },
    );
}

#[test]
fn an_old_release_cannot_sign_out_an_account_sealed_by_the_new_service() {
    with_fake_tool(
        "renewal::an_old_release_cannot_sign_out_an_account_sealed_by_the_new_service",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let original = Keychain::new(SERVICE, &files).unwrap();
            let rotated = Keychain::new(ROTATED, &files)
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
            let first = old.access_token(&id).unwrap();
            let new = Client::new(app, Sealed::new(files, rotated), provider);
            let renewed = new.access_token_after_rejection(&id, &first).unwrap();

            let read_error = old.access_token(&id).unwrap_err();
            let signed_out = old.sign_out(&id);
            let state = new.account(&id).unwrap().state();
            assert_eq!(
                read_error.kind(),
                ErrorKind::InvalidInput,
                "new release state: {state:?}"
            );
            assert_eq!(
                read_error.to_string(),
                "another keychain service sealed the store and this release cannot read it"
            );
            assert_eq!(signed_out.unwrap_err().kind(), ErrorKind::InvalidInput);
            assert_eq!(state, AccountState::SignedIn);
            assert_eq!(new.access_token(&id).unwrap().expose(), renewed.expose());
        },
    );
}
