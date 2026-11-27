//! A `Client` on a recording store and transport, with a settable clock,
//! seeded entropy and a browser thread for its sign-ins.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use siwc::{Account, AccountId, AppName, Client, Completed, Error, SignIn};

use super::NOW;
use super::browser::{Browser, PATIENCE, Response};
use super::clock::TestClock;
use super::provider::{FakeProvider, User};
use super::random::Seeded;
use super::recording::{Journal, RecordingStore, RecordingTransport};

/// One installation: a store, a provider, a clock and a client on them.
pub struct Rig {
    pub provider: Arc<FakeProvider>,
    pub transport: Arc<RecordingTransport>,
    pub store: Arc<RecordingStore>,
    pub clock: TestClock,
    pub journal: Journal,
    pub client: Client,
    seeds: AtomicU64,
}

impl Rig {
    pub fn new() -> Self {
        let journal = Journal::default();
        let provider = Arc::new(FakeProvider::new(NOW));
        let transport = Arc::new(RecordingTransport::new(
            Arc::clone(&provider),
            journal.clone(),
        ));
        let store = Arc::new(RecordingStore::new(journal.clone()));
        let clock = TestClock::new(NOW);
        let seeds = AtomicU64::new(1);
        let client = builder(&store, &transport, &clock, &seeds, "Paste Perfect").build();
        Self {
            provider,
            transport,
            store,
            clock,
            journal,
            client,
            seeds,
        }
    }

    /// A second client on the same store, transport and clock: it stands
    /// in for another process of the same app.
    pub fn another_client(&self) -> Client {
        self.client_named("Paste Perfect")
    }

    /// Another client on the same store, under another app name.
    pub fn client_named(&self, app: &str) -> Client {
        self.builder(app).build()
    }

    pub fn builder(&self, app: &str) -> siwc::ClientBuilder {
        builder(&self.store, &self.transport, &self.clock, &self.seeds, app)
    }

    /// Moves the provider's and the client's clocks to `NOW + offset`.
    pub fn at(&self, offset: u64) {
        self.provider.set_now(NOW + offset);
        self.clock.set(NOW + offset);
    }

    /// Runs the browser side on a thread while `finish` waits here.
    pub fn browse(
        &self,
        sign_in: SignIn,
        browser: impl FnOnce(&Browser, &FakeProvider) -> Response + Send + 'static,
    ) -> (Result<Completed, Error>, Response) {
        let side = Browser::new(sign_in.start_link());
        let provider = Arc::clone(&self.provider);
        let tab = thread::spawn(move || browser(&side, &provider));
        let result = sign_in.finish(PATIENCE);
        (result, tab.join().unwrap())
    }

    /// The browser side approves as `user`.
    pub fn approve(&self, sign_in: SignIn, user: &User) -> (Result<Completed, Error>, Response) {
        let user = user.clone();
        self.browse(sign_in, move |browser, provider| {
            browser.approve(provider, &user)
        })
    }

    /// Adds an account that `user` signs in to; returns it.
    pub fn add(&self, user: &User) -> Account {
        let (result, page) = self.approve(self.client.add_account().unwrap(), user);
        assert_eq!(page.status, 200);
        result.unwrap().into_account()
    }

    /// The credentials entry of an account.
    pub fn credentials_of(&self, id: &AccountId) -> Option<Vec<u8>> {
        self.store.bytes(&format!("account-{id}"))
    }

    /// The access token the client hands out for `id`, as text.
    pub fn token(&self, id: &AccountId) -> String {
        self.client.access_token(id).unwrap().expose().to_owned()
    }
}

fn builder(
    store: &Arc<RecordingStore>,
    transport: &Arc<RecordingTransport>,
    clock: &TestClock,
    seeds: &AtomicU64,
    app: &str,
) -> siwc::ClientBuilder {
    // Seeds far apart, so two clients never draw the same bytes.
    let seed = seeds.fetch_add(1, Ordering::Relaxed) * 1_000_000;
    Client::builder(
        AppName::new(app).unwrap(),
        Arc::clone(store),
        Arc::clone(transport),
    )
    .clock(clock.clone())
    .entropy(Seeded::new(seed))
}
