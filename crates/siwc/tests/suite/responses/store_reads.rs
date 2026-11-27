//! Cancelling store access during a plan request, while another reader
//! holds the sealing-key cache or a nested call uses a different store.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use siwc::store::{EntryName, KEY_LEN, KeyGeneration, Lock, MemoryStore, Sealed, SealingKey};
use siwc::store::{Store, Stored};
use siwc::testing::{FakeProvider, FakeUser};
use siwc::{AppName, Canceller, Client, Error, ErrorKind};

use super::{request, sign_in};

const GUARD: Duration = Duration::from_secs(3);
const INSTALLATION: &str = "installation";

struct Fixed(u8);

impl SealingKey for Fixed {
    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(KeyGeneration::new(0, None))
    }

    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        key.fill(self.0);
        Ok(())
    }

    fn fill_retired(&self, _keys: &mut siwc::store::RetiredKeys<'_>) -> Result<(), Error> {
        Ok(())
    }
}

struct PausedReload {
    reload: AtomicBool,
    entered: mpsc::Sender<()>,
    released: Mutex<mpsc::Receiver<()>>,
}

impl SealingKey for PausedReload {
    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        if self.reload.load(Ordering::SeqCst) {
            self.entered.send(()).unwrap();
            self.released.lock().unwrap().recv().unwrap();
        }
        Fixed(1).fill(key)
    }

    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(KeyGeneration::new(
            u64::from(self.reload.load(Ordering::SeqCst)),
            None,
        ))
    }

    fn fill_retired(&self, _keys: &mut siwc::store::RetiredKeys<'_>) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum At {
    Read,
    LockedRead,
    Write,
}

type Hook = Box<dyn FnOnce() + Send>;

struct Watched<S> {
    inner: S,
    installation_hook: Mutex<Option<(At, Hook)>>,
}

impl<S> Watched<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            installation_hook: Mutex::new(None),
        }
    }

    fn watch(&self, when: At, hook: impl FnOnce() + Send + 'static) {
        *self.installation_hook.lock().unwrap() = Some((when, Box::new(hook)));
    }

    fn reached(&self, entry: &EntryName, at: At) {
        if entry.as_str() == INSTALLATION {
            let hook = {
                let mut slot = self.installation_hook.lock().unwrap();
                if slot.as_ref().is_some_and(|(when, _)| *when == at) {
                    slot.take()
                } else {
                    None
                }
            };
            if let Some((_, run)) = hook {
                run();
            }
        }
    }
}

impl<S: fmt::Debug> fmt::Debug for Watched<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Watched")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: Store> Store for Watched<S> {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        self.reached(entry, At::Read);
        self.inner.read(entry)
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        self.reached(entry, At::Write);
        self.inner.write(entry, value)
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        self.inner.remove(entry)
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        let lock = self.inner.lock(entry, patience)?;
        if entry.as_str() == INSTALLATION
            && let Some((when, _)) = &mut *self.installation_hook.lock().unwrap()
            && *when == At::LockedRead
        {
            *when = At::Read;
        }
        Ok(lock)
    }

    fn shared_across_processes(&self) -> bool {
        self.inner.shared_across_processes()
    }
}

fn cancel_grant_repair(at: At) {
    let raw = Arc::new(MemoryStore::new());
    let old = EntryName::new("reader-entry").unwrap();
    let previous = b"synthetic sealed value";
    Sealed::new(Arc::clone(&raw), Fixed(1))
        .write(&old, previous)
        .unwrap();
    let (entered, cache_held) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let source = Arc::new(PausedReload {
        reload: AtomicBool::new(false),
        entered,
        released: Mutex::new(released),
    });
    let sealed = Arc::new(Sealed::new(Arc::clone(&raw), Arc::clone(&source)));
    let store = Arc::new(Watched::new(Arc::clone(&sealed)));
    let provider = FakeProvider::new();
    let client = Client::new(
        AppName::new("Paste Perfect").unwrap(),
        Arc::clone(&store),
        provider.clone(),
    );
    let id = sign_in(&client, &provider, FakeUser::new("sample@example.invalid"));
    let installation = EntryName::new(INSTALLATION).unwrap();
    let account = EntryName::new(&format!("account-{id}")).unwrap();
    // A previous renewal stored credentials granting plan use without
    // updating the installation. This call must repair that stale grant.
    let record = sealed.read(&installation).unwrap().unwrap();
    let mut stale: serde_json::Value = serde_json::from_slice(record.expose()).unwrap();
    assert_eq!(stale["accounts"][0]["plan_use"], true);
    stale["accounts"][0]["plan_use"] = false.into();
    sealed
        .write(&installation, &serde_json::to_vec(&stale).unwrap())
        .unwrap();

    let (start, started) = mpsc::channel();
    let (repairing, repair_reached) = mpsc::channel();
    store.watch(at, move || {
        start.send(()).unwrap();
        cache_held.recv_timeout(GUARD).unwrap();
        repairing.send(()).unwrap();
    });
    let other = thread::spawn(move || {
        started.recv_timeout(GUARD).unwrap();
        source.reload.store(true, Ordering::SeqCst);
        sealed.read(&old).unwrap().unwrap()
    });
    let stop = Canceller::new();
    let (done, result) = mpsc::channel();
    let worker = thread::spawn({
        let (client, id, stop) = (client.clone(), id.clone(), stop.clone());
        move || {
            let opened = client.stream_response_cancellable(&id, &request(), &stop);
            done.send(opened.map(drop).map_err(|error| error.kind()))
                .unwrap();
        }
    });
    repair_reached.recv_timeout(GUARD).unwrap();
    let locks = [&account, &installation];
    let held_during_repair = locks.map(|entry| {
        raw.lock(entry, Duration::ZERO)
            .map(drop)
            .map_err(|error| error.kind())
    });
    stop.cancel();
    let cancelled_while_blocked = result.recv_timeout(GUARD);
    let available_before_release = locks.map(|entry| raw.lock(entry, Duration::ZERO).map(drop));
    let other_still_waiting = !other.is_finished();
    release.send(()).unwrap();
    assert_eq!(other.join().unwrap().expose(), previous);
    worker.join().unwrap();

    assert_eq!(held_during_repair, [Err(ErrorKind::StoreBusy); 2]);
    assert!(
        other_still_waiting,
        "the cancelled repair must leave the other key reader alone"
    );
    assert_eq!(
        cancelled_while_blocked,
        Ok(Err(ErrorKind::Cancelled)),
        "the repair still waited for the other key reader"
    );
    for available in available_before_release {
        available.expect("the cancelled repair kept one of its locks");
    }
    assert!(!client.account(&id).unwrap().plan_use());
    assert!(provider.plan_requests().is_empty());
}

#[test]
fn cancelling_the_plan_grant_repair_read_releases_both_locks() {
    cancel_grant_repair(At::LockedRead);
}

#[test]
fn cancelling_the_plan_grant_repair_write_releases_both_locks() {
    cancel_grant_repair(At::Write);
}

#[test]
fn a_cancelled_store_read_does_not_cancel_another_clients_accounts_call() {
    let app = AppName::new("Paste Perfect").unwrap();
    let provider = FakeProvider::new();
    let other = Client::new(
        app.clone(),
        Sealed::new(MemoryStore::new(), Fixed(1)),
        provider.clone(),
    );
    let other_id = sign_in(&other, &provider, FakeUser::new("other@example.invalid"));
    let store = Arc::new(Watched::new(MemoryStore::new()));
    let client = Client::new(app, Arc::clone(&store), provider.clone());
    let id = sign_in(&client, &provider, FakeUser::new("sample@example.invalid"));
    let stop = Canceller::new();
    let cancel = stop.clone();
    let (nested, result) = mpsc::channel();
    store.watch(At::Read, move || {
        cancel.cancel();
        nested
            .send(other.accounts().map_err(|error| error.kind()))
            .unwrap();
    });
    let error = client
        .stream_response_cancellable(&id, &request(), &stop)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    let accounts = result
        .try_recv()
        .unwrap()
        .expect("the plan request's cancellation leaked into another client");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id(), &other_id);
    assert!(provider.plan_requests().is_empty());
}
