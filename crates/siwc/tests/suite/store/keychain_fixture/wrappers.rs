//! Public Store and SealingKey adapters around the keychain store.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use siwc::protocol::{HttpRequest, HttpResponse};
use siwc::store::{EntryName, KEY_LEN, KeyGeneration, Lock, RetiredKeys, SealingKey, Stored};
use siwc::testing::FakeProvider;
use siwc::{AccountState, AppName, Client, Error, Transport};

use super::renewal::{AfterRefresh, sign_in};
use super::*;

#[derive(Debug)]
struct ForwardStore<S>(S);

impl<S: Store> Store for ForwardStore<S> {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        self.0.read(entry)
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        self.0.write(entry, value)
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        self.0.remove(entry)
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        self.0.lock(entry, patience)
    }
}

struct ForwardKey(Keychain);

impl SealingKey for ForwardKey {
    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        self.0.fill(key)
    }

    fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        self.0.fill_retired(keys)
    }

    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        self.0.lock_generation()
    }

    fn refill_after_write(
        &self,
        key: &mut [u8; KEY_LEN],
        generation: u64,
        previous: &[u8; KEY_LEN],
    ) -> Result<(), Error> {
        self.0.refill_after_write(key, generation, previous)
    }
}

struct NumberOnlyKey(Keychain);

impl SealingKey for NumberOnlyKey {
    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        self.0.fill(key)
    }

    fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        self.0.fill_retired(keys)
    }

    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(KeyGeneration::new(self.0.lock_generation()?.number(), None))
    }

    fn refill_after_write(
        &self,
        key: &mut [u8; KEY_LEN],
        generation: u64,
        previous: &[u8; KEY_LEN],
    ) -> Result<(), Error> {
        self.0.refill_after_write(key, generation, previous)
    }
}

struct SwitchingKey {
    inner: Keychain,
    erase: Arc<AtomicBool>,
}

impl SealingKey for SwitchingKey {
    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        self.inner.fill(key)
    }

    fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        self.inner.fill_retired(keys)
    }

    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        let generation = self.inner.lock_generation()?;
        if self.erase.load(Ordering::SeqCst) {
            Ok(KeyGeneration::new(generation.number(), None))
        } else {
            Ok(generation)
        }
    }
}

struct OffThreadKey {
    inner: Keychain,
    rebuild: bool,
}

impl SealingKey for OffThreadKey {
    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        std::thread::scope(|scope| scope.spawn(|| self.inner.fill(key)).join().unwrap())
    }

    fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| self.inner.fill_retired(keys))
                .join()
                .unwrap()
        })
    }

    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        let generation = self.inner.lock_generation()?;
        if self.rebuild {
            Ok(KeyGeneration::new(generation.number(), None))
        } else {
            Ok(generation)
        }
    }
}

#[derive(Debug)]
struct CountRefresh {
    provider: FakeProvider,
    sent: Arc<AtomicUsize>,
}

impl Transport for CountRefresh {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        if request.body().starts_with(b"grant_type=refresh_token") {
            self.sent.fetch_add(1, Ordering::SeqCst);
        }
        self.provider.send(request)
    }
}

struct GuardedKey {
    inner: Keychain,
    guard: Mutex<()>,
}

impl SealingKey for GuardedKey {
    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        self.inner.fill(key)
    }

    fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        self.inner.fill_retired(keys)
    }

    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(self
            .inner
            .lock_generation()?
            .with_guard(Lock::new(self.guard.lock().unwrap())))
    }

    fn refill_after_write(
        &self,
        key: &mut [u8; KEY_LEN],
        generation: u64,
        previous: &[u8; KEY_LEN],
    ) -> Result<(), Error> {
        self.inner.refill_after_write(key, generation, previous)
    }
}

#[derive(Debug)]
struct EncodingStore<S>(S);

impl<S: Store> Store for EncodingStore<S> {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        self.0
            .read(entry)?
            .map(|stored| {
                stored
                    .expose()
                    .strip_prefix(b"encoded:")
                    .map(|value| Stored::new(value.to_vec()))
                    .ok_or_else(Error::store_failed)
            })
            .transpose()
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        let encoded = Stored::new([b"encoded:", value].concat());
        self.0.write(entry, encoded.expose())
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        self.0.remove(entry)
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        self.0.lock(entry, patience)
    }
}

fn renew_across_change<S: Store + 'static>(
    label: &str,
    reset: bool,
    wrap: impl Fn(PrivateFiles, Keychain) -> S,
) {
    with_fake_tool(label, |dir| {
        let store_dir = dir.join("store");
        let files = PrivateFiles::open(&store_dir).unwrap();
        let original = Keychain::new(SERVICE, &files).unwrap();
        let rotating = Keychain::new(ROTATED, &files)
            .unwrap()
            .with_retired(SERVICE)
            .unwrap();
        let activate = Sealed::new(files.clone(), rotating.clone());
        let reset_key = rotating.clone();
        let unavailable = dir.join(format!("{SERVICE}.missing"));
        let hide_key = unavailable.clone();
        let provider = FakeProvider::new();
        let transport = AfterRefresh {
            provider: provider.clone(),
            once: Mutex::new(Some(move || {
                assert!(activate.read(&name("installation")).unwrap().is_some());
                if reset {
                    assert!(!reset_key.start_over().unwrap());
                }
                fs::write(hide_key, []).unwrap();
            })),
        };
        let app = AppName::new("Offline Test App").unwrap();
        let old = Client::new(app.clone(), wrap(files.clone(), original), transport);
        let id = sign_in(&old, &provider);
        let first = old.access_token(&id).unwrap();
        let successor = old.access_token_after_rejection(&id, &first);
        fs::remove_file(unavailable).unwrap();
        assert_eq!(fs::read_to_string(store_dir.join(MARKER)).unwrap(), ROTATED);
        let successor = successor.expect("the wrapper must be able to store the successor");
        assert_ne!(successor.expose(), first.expose());

        let later = Client::new(app, wrap(files, rotating), provider);
        let matches_successor = |token: siwc::AccessToken| token.expose() == successor.expose();
        let old_read = old
            .access_token(&id)
            .map(matches_successor)
            .map_err(|e| e.kind());
        let new_read = later
            .access_token(&id)
            .map(matches_successor)
            .map_err(|e| e.kind());
        let renewed = later.access_token_after_rejection(&id, &successor);
        assert_eq!(
            old_read,
            Ok(true),
            "the original wrapper must read the successor"
        );
        assert_eq!(
            new_read,
            Ok(true),
            "the new release must read the successor"
        );
        assert_ne!(renewed.unwrap().expose(), successor.expose());
    });
}

#[test]
fn a_forwarding_store_keeps_the_successor_after_rotation() {
    renew_across_change(
        "wrappers::a_forwarding_store_keeps_the_successor_after_rotation",
        false,
        |files, key| ForwardStore(Sealed::new(files, key)),
    );
}

#[test]
fn a_forwarding_key_keeps_the_successor_after_rotation() {
    renew_across_change(
        "wrappers::a_forwarding_key_keeps_the_successor_after_rotation",
        false,
        |files, key| Sealed::new(files, ForwardKey(key)),
    );
}

#[test]
fn a_number_only_key_adapter_fails_before_spending_a_refresh_token() {
    with_fake_tool(
        "wrappers::a_number_only_key_adapter_fails_before_spending_a_refresh_token",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let provider = FakeProvider::new();
            let app = AppName::new("Offline Test App").unwrap();
            let direct = Client::new(
                app.clone(),
                Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap()),
                provider.clone(),
            );
            let id = sign_in(&direct, &provider);
            let first = direct.access_token(&id).unwrap();
            let adapted = Client::new(
                app,
                Sealed::new(
                    files,
                    NumberOnlyKey(
                        Keychain::new(SERVICE, &PrivateFiles::open(dir.join("store")).unwrap())
                            .unwrap(),
                    ),
                ),
                provider,
            );
            let error = adapted
                .access_token_after_rejection(&id, &first)
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
            assert!(error.to_string().contains("adapter"));
            assert!(direct.access_token_after_rejection(&id, &first).is_ok());
        },
    );
}

#[test]
fn a_number_only_old_release_cannot_destroy_a_new_service_account() {
    with_fake_tool(
        "wrappers::a_number_only_old_release_cannot_destroy_a_new_service_account",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let provider = FakeProvider::new();
            let app = AppName::new("Offline Test App").unwrap();
            let old = Client::new(
                app.clone(),
                Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap()),
                provider.clone(),
            );
            let id = sign_in(&old, &provider);
            let first = old.access_token(&id).unwrap();
            let new = Client::new(
                app.clone(),
                Sealed::new(
                    files.clone(),
                    Keychain::new(ROTATED, &files)
                        .unwrap()
                        .with_retired(SERVICE)
                        .unwrap(),
                ),
                provider.clone(),
            );
            let successor = new.access_token_after_rejection(&id, &first).unwrap();
            let broken_old = Client::new(
                app,
                Sealed::new(
                    files,
                    NumberOnlyKey(
                        Keychain::new(SERVICE, &PrivateFiles::open(dir.join("store")).unwrap())
                            .unwrap(),
                    ),
                ),
                provider,
            );
            assert_eq!(
                broken_old.sign_out(&id).unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
            assert_eq!(new.access_token(&id).unwrap().expose(), successor.expose());
        },
    );
}

#[test]
fn warm_adapter_cannot_erase_provenance_before_refresh() {
    with_fake_tool(
        "wrappers::warm_adapter_cannot_erase_provenance_before_refresh",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let provider = FakeProvider::new();
            let sent = Arc::new(AtomicUsize::new(0));
            let erase = Arc::new(AtomicBool::new(false));
            let client = Client::new(
                AppName::new("Offline Test App").unwrap(),
                Sealed::new(
                    files.clone(),
                    SwitchingKey {
                        inner: Keychain::new(SERVICE, &files).unwrap(),
                        erase: Arc::clone(&erase),
                    },
                ),
                CountRefresh {
                    provider: provider.clone(),
                    sent: Arc::clone(&sent),
                },
            );
            let id = sign_in(&client, &provider);
            let first = client.access_token(&id).unwrap();
            erase.store(true, Ordering::SeqCst);
            let error = client
                .access_token_after_rejection(&id, &first)
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
            assert_eq!(sent.load(Ordering::SeqCst), 0);
            let intact = Client::new(
                AppName::new("Offline Test App").unwrap(),
                Sealed::new(
                    files,
                    Keychain::new(SERVICE, &PrivateFiles::open(dir.join("store")).unwrap())
                        .unwrap(),
                ),
                provider,
            );
            assert!(intact.access_token_after_rejection(&id, &first).is_ok());
        },
    );
}

#[test]
fn off_thread_intact_adapter_opens_coordinated_entries() {
    with_fake_tool(
        "wrappers::off_thread_intact_adapter_opens_coordinated_entries",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            let store = Sealed::new(
                files.clone(),
                OffThreadKey {
                    inner: Keychain::new(SERVICE, &files).unwrap(),
                    rebuild: false,
                },
            );
            store.write(&entry, VALUE).unwrap();
            assert_eq!(store.read(&entry).unwrap().unwrap().expose(), VALUE);
            assert_eq!(files.read(&entry).unwrap().unwrap().expose()[0], 2);
        },
    );
}

#[test]
fn coordinated_envelope_version_is_authenticated() {
    with_fake_tool(
        "wrappers::coordinated_envelope_version_is_authenticated",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            let source = Keychain::new(SERVICE, &files).unwrap();
            let store = Sealed::new(files.clone(), source);
            store.write(&entry, VALUE).unwrap();
            let mut raw = files.read(&entry).unwrap().unwrap().expose().to_vec();
            assert_eq!(raw[0], 2);
            raw[0] = 1;
            files.write(&entry, &raw).unwrap();
            assert_eq!(
                store.read(&entry).unwrap_err().kind(),
                ErrorKind::StoreCorrupt
            );
        },
    );
}

#[test]
fn off_thread_rebuilt_adapter_fails_before_refresh() {
    with_fake_tool(
        "wrappers::off_thread_rebuilt_adapter_fails_before_refresh",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let provider = FakeProvider::new();
            let direct = Client::new(
                AppName::new("Offline Test App").unwrap(),
                Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap()),
                provider.clone(),
            );
            let id = sign_in(&direct, &provider);
            let first = direct.access_token(&id).unwrap();
            let sent = Arc::new(AtomicUsize::new(0));
            let adapted = Client::new(
                AppName::new("Offline Test App").unwrap(),
                Sealed::new(
                    files,
                    OffThreadKey {
                        inner: Keychain::new(
                            SERVICE,
                            &PrivateFiles::open(dir.join("store")).unwrap(),
                        )
                        .unwrap(),
                        rebuild: true,
                    },
                ),
                CountRefresh {
                    provider: provider.clone(),
                    sent: Arc::clone(&sent),
                },
            );
            assert_eq!(
                adapted
                    .access_token_after_rejection(&id, &first)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidInput
            );
            assert_eq!(sent.load(Ordering::SeqCst), 0);
            assert!(direct.access_token_after_rejection(&id, &first).is_ok());
        },
    );
}

#[test]
fn off_thread_rebuilt_old_release_cannot_sign_out_new_account() {
    with_fake_tool(
        "wrappers::off_thread_rebuilt_old_release_cannot_sign_out_new_account",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let provider = FakeProvider::new();
            let app = AppName::new("Offline Test App").unwrap();
            let old = Client::new(
                app.clone(),
                Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap()),
                provider.clone(),
            );
            let id = sign_in(&old, &provider);
            let first = old.access_token(&id).unwrap();
            let newer = Client::new(
                app.clone(),
                Sealed::new(
                    files.clone(),
                    Keychain::new(ROTATED, &files)
                        .unwrap()
                        .with_retired(SERVICE)
                        .unwrap(),
                ),
                provider.clone(),
            );
            let successor = newer.access_token_after_rejection(&id, &first).unwrap();
            let broken = Client::new(
                app,
                Sealed::new(
                    files.clone(),
                    OffThreadKey {
                        inner: Keychain::new(SERVICE, &files).unwrap(),
                        rebuild: true,
                    },
                ),
                provider,
            );
            assert_eq!(
                broken.sign_out(&id).unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
            assert_eq!(newer.account(&id).unwrap().state(), AccountState::SignedIn);
            assert_eq!(
                newer.access_token(&id).unwrap().expose(),
                successor.expose()
            );
        },
    );
}

#[test]
fn an_adapter_can_add_a_guard_and_read_retired_entries() {
    renew_across_change(
        "wrappers::an_adapter_can_add_a_guard_and_read_retired_entries",
        false,
        |files, key| {
            Sealed::new(
                files,
                GuardedKey {
                    inner: key,
                    guard: Mutex::new(()),
                },
            )
        },
    );
}

#[test]
fn an_arc_store_and_key_keep_the_successor_after_rotation() {
    renew_across_change(
        "wrappers::an_arc_store_and_key_keep_the_successor_after_rotation",
        false,
        |files, key| Arc::new(Sealed::new(files, Arc::new(key))),
    );
}

#[test]
fn a_store_encodes_the_successor_after_rotation() {
    renew_across_change(
        "wrappers::a_store_encodes_the_successor_after_rotation",
        false,
        |files, key| EncodingStore(Sealed::new(files, key)),
    );
}

#[test]
fn a_store_encodes_the_successor_after_a_reset_that_keeps_the_account() {
    renew_across_change(
        "wrappers::a_store_encodes_the_successor_after_a_reset_that_keeps_the_account",
        true,
        |files, key| EncodingStore(Sealed::new(files, key)),
    );
}

#[test]
fn a_forwarding_key_cannot_sign_out_an_account_sealed_by_the_new_service() {
    with_fake_tool(
        "wrappers::a_forwarding_key_cannot_sign_out_an_account_sealed_by_the_new_service",
        |dir| {
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
                EncodingStore(ForwardStore(Sealed::new(
                    files.clone(),
                    ForwardKey(original),
                ))),
                provider.clone(),
            );
            let id = sign_in(&old, &provider);
            let first = old.access_token(&id).unwrap();
            let later = Client::new(
                app,
                EncodingStore(ForwardStore(Sealed::new(files, ForwardKey(rotating)))),
                provider,
            );
            let successor = later.access_token_after_rejection(&id, &first).unwrap();
            let read_error = old.access_token(&id).unwrap_err();
            let signed_out = old.sign_out(&id);
            assert_eq!(later.account(&id).unwrap().state(), AccountState::SignedIn);
            assert_eq!(read_error.kind(), ErrorKind::InvalidInput);
            assert_eq!(signed_out.unwrap_err().kind(), ErrorKind::InvalidInput);
            assert_eq!(
                later.access_token(&id).unwrap().expose(),
                successor.expose()
            );
        },
    );
}
