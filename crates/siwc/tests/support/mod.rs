//! Shared fixtures: the fake provider, synthetic keys and a ready-made app.

pub mod browser;
pub mod clock;
pub mod executor;
pub mod keys;
pub mod provider;
pub mod random;
pub mod recording;
pub mod rig;
pub mod wire;

use siwc::protocol::{Accepted, Attempt, Callback, Exchange, Jwks, Registration, SignedIn};
use siwc::{AppName, HostId, UnixTime};

use provider::{FakeProvider, User};
use random::Seeded;

/// A fixed "now" for every test: no test reads the clock.
pub const NOW: u64 = 1_795_000_000;

pub const PORT: u16 = 53_124;

/// An app, its installation and a provider to sign in with.
pub struct World {
    pub provider: FakeProvider,
    pub app: AppName,
    pub host: HostId,
    pub entropy: Seeded,
}

impl World {
    pub fn new() -> Self {
        let entropy = Seeded::new(7);
        Self {
            provider: FakeProvider::new(NOW),
            app: AppName::new("Paste Perfect").unwrap(),
            host: HostId::generate_with_entropy(&entropy).unwrap(),
            entropy,
        }
    }

    pub fn now(&self) -> UnixTime {
        UnixTime::from_secs(NOW)
    }

    pub fn attempt(&self, registration: Registration<'_>) -> Attempt {
        Attempt::start_with_entropy(registration, Some(&self.host), PORT, &self.entropy).unwrap()
    }

    pub fn keys(&self) -> Jwks {
        Jwks::from_response(&self.provider.send(&Jwks::request())).unwrap()
    }

    /// A first registration up to the accepted callback.
    pub fn authorized(&self, user: &User) -> Exchange {
        let attempt = self.attempt(Registration::New(&self.app));
        let query = self.provider.authorize(attempt.authorization_url(), user);
        saved(answered(attempt.accept(&query)).unwrap())
    }

    /// A complete first sign-in.
    pub fn sign_in(&self, user: &User) -> SignedIn {
        self.finish(self.authorized(user)).unwrap()
    }

    /// Code exchange and verification.
    pub fn finish(&self, exchange: Exchange) -> Result<SignedIn, siwc::Error> {
        let response = self.provider.send(&exchange.request());
        exchange
            .response(response, self.now())?
            .verify(&self.keys(), self.now())
    }
}

/// The outcome of a request that is the attempt's callback.
pub fn answered(callback: Callback) -> Result<Accepted, siwc::Error> {
    match callback {
        Callback::Final(result) => result,
        Callback::Unrelated(_) => panic!("the request does not carry the attempt's state"),
    }
}

/// The exchange of an accepted callback, as if the client ID were stored.
pub fn saved(accepted: Accepted) -> Exchange {
    match accepted {
        Accepted::NewRegistration(registration) => registration.saved(),
        Accepted::Returning(exchange) => exchange,
        other => panic!("an unknown kind of accepted callback: {other:?}"),
    }
}
