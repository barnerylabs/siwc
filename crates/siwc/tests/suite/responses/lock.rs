//! Cancelling a request that is about to renew its token: the wait for the
//! account's lock ends, and no renewal is sent for a request nobody wants
//! any more. One that was sent is seen through.

use std::cell::Cell;
use std::future::ready;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use siwc::plan::Refusal;
use siwc::protocol::{HttpRequest, HttpResponse};
use siwc::store::{EntryName, Lock, MemoryStore, Store, Stored};
use siwc::testing::{FakeClock, FakeProvider, FakeResponse, FakeUser};
use siwc::{AccountId, AppName, Canceller, Client, Error, ErrorKind, Transport, UnixTime};

use crate::support::executor::block_on;
use crate::support::random::Seeded;

use super::{INVALID_USER, request, sign_in};

/// When the store below cancels a request.
#[derive(Debug)]
enum Cancel {
    Never,
    InstallationBusy(Canceller),
    /// In the second try for an account's lock: the request is waiting.
    WhileWaiting(Canceller),
    /// As soon as an account's lock is taken: the last moment before the
    /// renewal is sent.
    OnceLocked(Canceller),
    /// In every try for an account's lock, which then finds it taken.
    AndBusy(Canceller),
}

/// A store in memory that cancels a request at a chosen point of taking an
/// account's lock.
#[derive(Debug)]
struct Watched {
    inner: MemoryStore,
    cancel: Mutex<Cancel>,
    tries: Mutex<usize>,
    /// The patience of every try for an account's lock.
    waits: Mutex<Vec<Duration>>,
    /// Whether removing an account's credentials fails.
    keeps_credentials: AtomicBool,
}

impl Store for Watched {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        self.inner.read(entry)
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        self.inner.write(entry, value)
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        if self.keeps_credentials.load(Ordering::SeqCst) && entry.as_str().starts_with("account-") {
            return Err(Error::store_failed());
        }
        self.inner.remove(entry)
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        if entry.as_str() == "installation"
            && let Cancel::InstallationBusy(stop) = &*self.cancel.lock().unwrap()
        {
            self.waits.lock().unwrap().push(patience);
            stop.cancel();
            return Err(Error::store_busy());
        }
        if !entry.as_str().starts_with("account-") {
            return self.inner.lock(entry, patience);
        }
        let tries = {
            let mut tries = self.tries.lock().unwrap();
            *tries += 1;
            *tries
        };
        self.waits.lock().unwrap().push(patience);
        if let Cancel::AndBusy(canceller) = &*self.cancel.lock().unwrap() {
            canceller.cancel();
            return Err(Error::store_busy());
        }
        if let Cancel::WhileWaiting(canceller) = &*self.cancel.lock().unwrap()
            && tries == 2
        {
            canceller.cancel();
        }
        let lock = self.inner.lock(entry, patience)?;
        if let Cancel::OnceLocked(canceller) = &*self.cancel.lock().unwrap() {
            canceller.cancel();
        }
        Ok(lock)
    }

    fn shared_across_processes(&self) -> bool {
        false
    }
}

/// The fake provider, cancelling a request once its renewal was sent.
#[derive(Debug)]
struct CancelOnRenewal {
    provider: FakeProvider,
    armed: AtomicBool,
    canceller: Canceller,
}

impl Transport for CancelOnRenewal {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        let answer = self.provider.send(request);
        if self.armed.load(Ordering::SeqCst) && request.url().ends_with("/oauth/token") {
            self.canceller.cancel();
        }
        answer
    }
}

struct Rig {
    clock: FakeClock,
    provider: FakeProvider,
    store: Arc<Watched>,
    client: Client,
    id: AccountId,
}

impl Rig {
    fn new() -> Self {
        // Waited out in full only by a client that ignores the canceller.
        Self::patient_for(Duration::from_secs(2))
    }

    fn patient_for(patience: Duration) -> Self {
        let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
        let provider = FakeProvider::with_clock(&clock);
        let store = Arc::new(Watched {
            inner: MemoryStore::new(),
            cancel: Mutex::new(Cancel::Never),
            tries: Mutex::new(0),
            waits: Mutex::new(Vec::new()),
            keeps_credentials: AtomicBool::new(false),
        });
        let client = Client::builder(
            AppName::new("Paste Perfect").unwrap(),
            Arc::clone(&store),
            provider.transport(),
        )
        .clock(clock.clone())
        .entropy(Seeded::new(11))
        .lock_patience(patience)
        .build();
        let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
        Self {
            clock,
            provider,
            store,
            client,
            id,
        }
    }

    fn token(&self) -> String {
        self.client
            .access_token(&self.id)
            .unwrap()
            .expose()
            .to_owned()
    }

    /// Sets when the next request is cancelled, and returns its canceller.
    fn cancel(&self, when: fn(Canceller) -> Cancel) -> Canceller {
        let canceller = Canceller::new();
        *self.store.cancel.lock().unwrap() = when(canceller.clone());
        *self.store.tries.lock().unwrap() = 0;
        self.store.waits.lock().unwrap().clear();
        canceller
    }

    /// One request the API refuses with a `401`, sent the way with this
    /// number: through the stream, `call` or `call_async`. Returns the
    /// kind of the error and how often the request was sent.
    fn refused(&self, way: usize, canceller: &Canceller) -> (ErrorKind, usize) {
        let sent = Cell::new(0);
        let refusal = || {
            sent.set(sent.get() + 1);
            let body = FakeProvider::refusal_body(INVALID_USER, None);
            Err(Refusal::from_response(401, &body).unwrap())
        };
        let before = self.provider.plan_requests().len();
        let result: Result<(), Error> = match way {
            0 => {
                self.provider
                    .push_response(FakeResponse::refusal(401, INVALID_USER));
                self.client
                    .stream_response_cancellable(&self.id, &request(), canceller)
                    .map(drop)
            }
            1 => self
                .client
                .call_cancellable(&self.id, canceller, |_| Ok(refusal())),
            _ => block_on(
                self.client
                    .call_async_cancellable(&self.id, canceller, |_| ready(Ok(refusal()))),
            ),
        };
        let streamed = self.provider.plan_requests().len() - before;
        (result.unwrap_err().kind(), sent.get() + streamed)
    }
}

#[test]
fn a_cancellation_ends_the_wait_for_the_accounts_lock_and_nothing_is_renewed() {
    let rig = Rig::new();
    let token = rig.token();
    // Somebody else is busy with the account for as long as this takes.
    let entry = EntryName::new(&format!("account-{}", rig.id)).unwrap();
    let held = rig.store.inner.lock(&entry, Duration::ZERO).unwrap();

    for way in 0..3 {
        let canceller = rig.cancel(Cancel::WhileWaiting);
        assert_eq!(
            rig.refused(way, &canceller),
            (ErrorKind::Cancelled, 1),
            "way {way}"
        );
        // It gave up in the second try, well before its patience ended.
        assert_eq!(*rig.store.tries.lock().unwrap(), 2, "way {way}");
    }
    drop(held);
    // The account still has the token it had: nothing was rotated.
    assert_eq!(rig.token(), token);
}

#[test]
fn a_cancellation_seen_under_the_lock_keeps_the_renewal_from_being_sent() {
    let rig = Rig::new();
    let token = rig.token();
    for way in 0..3 {
        let canceller = rig.cancel(Cancel::OnceLocked);
        assert_eq!(
            rig.refused(way, &canceller),
            (ErrorKind::Cancelled, 1),
            "way {way}"
        );
        assert_eq!(*rig.store.tries.lock().unwrap(), 1, "way {way}");
        assert_eq!(rig.token(), token, "way {way}");
    }

    // Without a cancellation the same refusal renews the token.
    *rig.store.cancel.lock().unwrap() = Cancel::Never;
    rig.provider
        .push_response(FakeResponse::refusal(401, INVALID_USER));
    rig.provider.push_response(FakeResponse::text(&["Here."]));
    let stream = rig.client.stream_response(&rig.id, &request()).unwrap();
    assert_eq!(stream.into_text().unwrap(), "Here.");
    assert_ne!(rig.token(), token);
}

#[test]
fn a_renewal_that_was_sent_is_stored_although_its_request_was_cancelled() {
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let canceller = Canceller::new();
    let transport = Arc::new(CancelOnRenewal {
        provider: provider.clone(),
        armed: AtomicBool::new(false),
        canceller: canceller.clone(),
    });
    let client = super::Desk::client_over(Arc::clone(&transport), &clock);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    let token = client.access_token(&id).unwrap().expose().to_owned();
    transport.armed.store(true, Ordering::SeqCst);

    provider.push_response(FakeResponse::refusal(401, INVALID_USER));
    provider.push_response(FakeResponse::text(&["never shown"]));
    let error = client
        .stream_response_cancellable(&id, &request(), &canceller)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    // The request is not sent again, but the successor of the spent
    // refresh token is in the store and works.
    assert_eq!(provider.plan_requests().len(), 1);
    transport.armed.store(false, Ordering::SeqCst);
    assert_ne!(client.access_token(&id).unwrap().expose(), token);
    let stream = client.stream_response(&id, &request()).unwrap();
    assert_eq!(stream.into_text().unwrap(), "never shown");
}

#[test]
fn a_cancellation_during_the_last_try_for_the_lock_is_the_cancellation_and_not_a_busy_store() {
    // So little patience that the first try is the last one.
    let rig = Rig::patient_for(Duration::from_millis(25));
    let token = rig.token();
    for way in 0..3 {
        let canceller = rig.cancel(Cancel::AndBusy);
        assert_eq!(
            rig.refused(way, &canceller),
            (ErrorKind::Cancelled, 1),
            "way {way}"
        );
        assert_eq!(*rig.store.tries.lock().unwrap(), 1, "way {way}");
    }
    // A store that is busy without a cancellation is still that.
    let rig = Rig::patient_for(Duration::from_millis(25));
    let entry = EntryName::new(&format!("account-{}", rig.id)).unwrap();
    let held = rig.store.inner.lock(&entry, Duration::ZERO).unwrap();
    for way in 0..3 {
        let canceller = rig.cancel(|_| Cancel::Never);
        assert_eq!(
            rig.refused(way, &canceller),
            (ErrorKind::StoreBusy, 1),
            "way {way}"
        );
    }
    drop(held);
    assert_eq!(rig.token(), token);
}

#[test]
fn the_cleanup_of_an_ended_session_waits_for_the_lock_no_longer_than_a_cancellation_allows() {
    let rig = Rig::new();
    // The session ends, and the tokens it leaves cannot be removed: every
    // later request tries that removal again, under the account's lock.
    rig.store.keeps_credentials.store(true, Ordering::SeqCst);
    rig.provider.revoke_refresh_tokens();
    rig.clock.advance(Duration::from_secs(3600));
    let error = rig.client.access_token(&rig.id).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::SignInRequired);

    for way in 0..3 {
        let canceller = rig.cancel(Cancel::AndBusy);
        assert_eq!(
            rig.refused(way, &canceller),
            (ErrorKind::Cancelled, 0),
            "way {way}"
        );
        let waits = rig.store.waits.lock().unwrap().clone();
        assert_eq!(waits.len(), 1, "way {way}");
        assert!(
            waits[0] <= Duration::from_millis(50),
            "way {way}: {waits:?}"
        );
    }

    // Without a cancellation the account says what it needs, and the
    // removal goes through once the store allows it.
    let canceller = rig.cancel(|_| Cancel::Never);
    assert_eq!(rig.refused(0, &canceller).0, ErrorKind::SignInRequired);
    rig.store.keeps_credentials.store(false, Ordering::SeqCst);
    assert_eq!(rig.refused(1, &canceller).0, ErrorKind::SignInRequired);
    let entry = EntryName::new(&format!("account-{}", rig.id)).unwrap();
    assert!(rig.store.inner.read(&entry).unwrap().is_none());
}

fn cancel_at_installation(rig: &Rig, id: &AccountId) {
    for asynchronous in [false, true] {
        let stop = rig.cancel(Cancel::InstallationBusy);
        let request = request();
        let error = if asynchronous {
            block_on(
                rig.client
                    .stream_response_async_cancellable(id, &request, &stop),
            )
            .unwrap_err()
        } else {
            rig.client
                .stream_response_cancellable(id, &request, &stop)
                .unwrap_err()
        };
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        // The last try is for the installation; cancellation there wins
        // even though the store reported a busy lock.
        let waits = rig.store.waits.lock().unwrap();
        assert!(
            waits.last().unwrap() <= &Duration::from_millis(50),
            "{waits:?}"
        );
        assert!(rig.provider.plan_requests().is_empty());
    }
    *rig.store.cancel.lock().unwrap() = Cancel::Never;
}

#[test]
fn cancelling_at_the_installation_lock_leaves_a_plan_grant_for_the_next_call_to_repair() {
    let rig = Rig::new();
    // Credentials were stored, but the installation still has the old grant.
    let entry = EntryName::new("installation").unwrap();
    let record = rig.store.read(&entry).unwrap().unwrap();
    let mut data: serde_json::Value = serde_json::from_slice(record.expose()).unwrap();
    data["accounts"][0]["plan_use"] = false.into();
    rig.store
        .write(&entry, &serde_json::to_vec(&data).unwrap())
        .unwrap();
    assert!(!rig.client.account(&rig.id).unwrap().plan_use());

    cancel_at_installation(&rig, &rig.id);
    assert!(!rig.client.account(&rig.id).unwrap().plan_use());
    rig.client.access_token(&rig.id).unwrap();
    assert!(rig.client.account(&rig.id).unwrap().plan_use());
}

#[test]
fn cancelling_at_the_installation_lock_leaves_an_expired_session_for_the_next_call_to_end() {
    let rig = Rig::new();
    let id = sign_in(
        &rig.client,
        &rig.provider,
        FakeUser::new("guest@example.invalid").without_refresh_token(),
    );
    rig.clock.advance(Duration::from_secs(7200));
    cancel_at_installation(&rig, &id);
    assert_eq!(
        rig.client.account(&id).unwrap().state(),
        siwc::AccountState::SignedIn
    );
    assert_eq!(
        rig.client.access_token(&id).unwrap_err().kind(),
        ErrorKind::SignInRequired
    );
}
