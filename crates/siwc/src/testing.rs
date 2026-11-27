//! Test doubles for application test suites: an in-memory provider, synthetic
//! users and a controllable clock.
//!
//! Requires the `testing` feature; enable it under `[dev-dependencies]` only:
//!
//! ```toml
//! [dev-dependencies]
//! siwc = { version = "0.1", features = ["testing"] }
//! ```
//!
//! [`FakeProvider`] is an in-memory stand-in for the provider: it implements
//! [`Transport`], answers the OAuth, JWKS, model-list and `/v1/responses`
//! requests, and signs ID tokens with a synthetic RSA key. It also plays the
//! browser side of [`SignIn`] and [`ManualSignIn`]. With it an app tests its
//! account UI, its own [`Store`](crate::store::Store), token renewal,
//! streamed answers ([`FakeResponse`]) and plan refusals without a network
//! or a real account. A browser sign-in still uses a socket on `127.0.0.1`.
//!
//! ```
//! use std::time::Duration;
//!
//! use siwc::store::MemoryStore;
//! use siwc::testing::{FakeClock, FakeProvider, FakeUser};
//! use siwc::{AppName, Client, UnixTime};
//!
//! let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
//! let provider = FakeProvider::with_clock(&clock);
//! let client = Client::builder(
//!     AppName::new("Paste Perfect")?,
//!     MemoryStore::new(),
//!     provider.transport(),
//! )
//! .clock(clock.clone())
//! .build();
//!
//! let sign_in = client.add_account()?;
//! provider.approve(&sign_in, FakeUser::new("owner@example.invalid"));
//! let account = sign_in.finish(Duration::from_secs(5))?.into_account();
//!
//! clock.advance(Duration::from_secs(3600));
//! let renewed = client.access_token(account.id())?;
//! # drop(renewed);
//! # Ok::<(), siwc::Error>(())
//! ```

mod browser;
mod clock;
mod key;
mod oauth;
mod plan;
mod provider;
mod responses;
mod user;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use crate::cancel::Canceller;
use crate::client::{ManualSignIn, SignIn};
use crate::error::Error;
use crate::protocol::{HttpRequest, HttpResponse, StreamingResponse};
use crate::time::{Clock, SystemClock};
use crate::transport::Transport;

use browser::{Outcome, drive_loopback};
use provider::ProviderCore;

pub use clock::FakeClock;
pub use responses::FakeResponse;
pub use user::FakeUser;

static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

/// An in-memory stand-in for the provider's authorization, token, revocation,
/// JWKS and model-discovery endpoints and its `/v1/responses` route. Use
/// [`push_response`](Self::push_response) to script the route with
/// [`FakeResponse`] and [`plan_requests`](Self::plan_requests) to inspect
/// the requests it received.
///
/// Clones share the same state and registered accounts. Pass `provider.transport()`
/// (or `provider.clone()`) to [`Client::new`](crate::Client::new) or
/// [`Client::builder`](crate::Client::builder).
#[derive(Clone)]
pub struct FakeProvider {
    core: Arc<ProviderCore>,
}

impl FakeProvider {
    /// Creates a fake provider reading the current time from [`SystemClock`].
    ///
    /// When testing expiry with [`FakeClock`], prefer
    /// [`with_clock`](Self::with_clock) so advancing the clock moves both the
    /// client and the provider together.
    #[must_use]
    pub fn new() -> Self {
        Self::from_clock(Box::new(SystemClock))
    }

    /// Creates a fake provider that shares `clock` with the client under test.
    #[must_use]
    pub fn with_clock(clock: &FakeClock) -> Self {
        Self::from_clock(Box::new(clock.clone()))
    }

    fn from_clock(clock: Box<dyn Clock>) -> Self {
        let instance = NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed);
        Self {
            core: Arc::new(ProviderCore::new(instance, clock)),
        }
    }

    /// A [`Transport`] clone connected to this provider.
    #[must_use]
    pub fn transport(&self) -> Self {
        self.clone()
    }

    /// Approves `sign_in` as `user` through the loopback listener on a
    /// background helper thread, so [`SignIn::finish`] can be called on the
    /// next line without deadlocking single-threaded tests.
    pub fn approve(&self, sign_in: &SignIn, user: FakeUser) {
        drive_loopback(
            Arc::clone(&self.core),
            sign_in.start_link(),
            Outcome::Approve(user),
        );
    }

    /// Declines `sign_in` in the browser (`access_denied`).
    pub fn decline(&self, sign_in: &SignIn) {
        self.fail_authorization(sign_in, "access_denied");
    }

    /// Ends `sign_in` in the browser with the OAuth error `code` (such as
    /// `"temporarily_unavailable"`).
    pub fn fail_authorization(&self, sign_in: &SignIn, code: &str) {
        drive_loopback(
            Arc::clone(&self.core),
            sign_in.start_link(),
            Outcome::Error(code.to_owned()),
        );
    }

    /// Approves `sign_in` as `user` and returns the redirect address to pass to
    /// [`ManualSignIn::finish`].
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) if the
    /// authorization link is unreadable.
    pub fn approve_manual(&self, sign_in: &ManualSignIn, user: FakeUser) -> Result<String, Error> {
        let (redirect_uri, query) = self.core.authorize(sign_in.authorization_link(), user)?;
        Ok(format!("{redirect_uri}?{query}"))
    }

    /// Declines `sign_in` (`access_denied`) and returns the redirect address to
    /// pass to [`ManualSignIn::finish`].
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) if the
    /// authorization link is unreadable.
    pub fn decline_manual(&self, sign_in: &ManualSignIn) -> Result<String, Error> {
        self.fail_manual(sign_in, "access_denied")
    }

    /// Fails `sign_in` with the OAuth `error_code` and returns the redirect
    /// address to pass to [`ManualSignIn::finish`].
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) if the
    /// authorization link is unreadable.
    pub fn fail_manual(&self, sign_in: &ManualSignIn, error_code: &str) -> Result<String, Error> {
        let (redirect_uri, query) = self
            .core
            .fail_authorization(sign_in.authorization_link(), error_code)?;
        Ok(format!("{redirect_uri}?{query}"))
    }

    /// Invalidates all currently active refresh tokens, so the next token
    /// renewal fails with [`ErrorKind::SignInRequired`](crate::ErrorKind::SignInRequired).
    pub fn revoke_refresh_tokens(&self) {
        self.core.revoke_refresh_tokens();
    }

    /// Marks every issued client registration as revoked by the user, so the
    /// next refresh or re-sign-in fails with
    /// [`ErrorKind::ClientRejected`](crate::ErrorKind::ClientRejected). An
    /// access token that has not expired is still returned without a
    /// request.
    pub fn reject_registrations(&self) {
        self.core.reject_registrations();
    }

    /// Fails the next [`Transport::send`] request with HTTP `status` and an
    /// optional OAuth `error_code` (`status == 0` simulates a network drop
    /// returning [`Error::transport_unavailable`]).
    pub fn fail_next_request(&self, status: u16, error_code: Option<&str>) {
        let body = match error_code {
            Some(code) => json!({ "error": code }).to_string().into_bytes(),
            None => Vec::new(),
        };
        self.core.fail_next_request(status, body);
    }

    /// Refuses the next `/v1/models` call with `status` and the structured API
    /// error `code` (such as `"subscription_sharing_usage_limit_exceeded"`).
    pub fn refuse_next_models(&self, status: u16, code: &str) {
        self.core
            .refuse_next_models(status, Self::refusal_body(code, None));
    }

    /// Queues `response` as the answer to a plan request
    /// (`POST /v1/responses`). Queued answers go out in order, one per
    /// request, so an eligible HTTP refusal followed by a stream scripts
    /// a retry. With an empty queue a plan request gets a short complete
    /// answer.
    ///
    /// A request whose token the provider would not accept never reaches
    /// the queue: an unknown or expired token is answered `401`, one without
    /// plan use `403`, and a body without `"store": false` and
    /// `"stream": true` is answered `400`.
    ///
    /// ```
    /// use siwc::plan::ResponseRequest;
    /// use siwc::store::MemoryStore;
    /// use siwc::testing::{FakeProvider, FakeResponse, FakeUser};
    /// use siwc::{AppName, Client};
    ///
    /// let provider = FakeProvider::new();
    /// let client = Client::new(
    ///     AppName::new("Paste Perfect")?,
    ///     MemoryStore::new(),
    ///     provider.transport(),
    /// );
    /// let mut sign_in = client.add_account_manually()?;
    /// let redirect = provider.approve_manual(&sign_in, FakeUser::new("owner@example.invalid"))?;
    /// let account = sign_in.finish(&redirect)?.into_account();
    ///
    /// // Busy once, then an answer in two pieces.
    /// provider.push_response(FakeResponse::refusal(503, "subscription_sharing_usage_unavailable").retry_after(0));
    /// provider.push_response(FakeResponse::text(&["Hel", "lo"]));
    ///
    /// let request = ResponseRequest::text("example-large", "Say hello.")?;
    /// let answer = client.stream_response(account.id(), &request)?.into_text()?;
    /// assert_eq!(answer, "Hello");
    /// assert_eq!(provider.plan_requests().len(), 2);
    /// # Ok::<(), siwc::Error>(())
    /// ```
    pub fn push_response(&self, response: FakeResponse) {
        self.core.push_response(response);
    }

    /// The JSON bodies of the plan requests received so far, oldest first,
    /// including those that were refused: what the app under test asked
    /// the model, and how often.
    #[must_use]
    pub fn plan_requests(&self) -> Vec<String> {
        self.core.plan_requests()
    }

    /// Replaces the `(id, display_name)` pairs returned by `/v1/models`.
    pub fn set_models(&self, models: &[(&str, &str)]) {
        self.core.set_models(models);
    }

    /// Builds a structured JSON refusal body (`{"error":{"code":...,"param":...}}`)
    /// for testing [`Refusal::from_response`](crate::plan::Refusal::from_response)
    /// and [`Client::call`](crate::Client::call) adapters.
    #[must_use]
    pub fn refusal_body(code: &str, param: Option<&str>) -> Vec<u8> {
        json!({
            "error": {
                "code": code,
                "param": param,
                "message": "synthetic test refusal",
            }
        })
        .to_string()
        .into_bytes()
    }

    /// Builds an SSE `response.failed` frame (`event: response.failed\ndata: {...}\n\n`)
    /// for testing [`Refusal::from_event`](crate::plan::Refusal::from_event)
    /// in streaming Responses adapters.
    #[must_use]
    pub fn failure_event(code: &str, param: Option<&str>) -> Vec<u8> {
        let payload = json!({
            "type": "response.failed",
            "response": {
                "id": "resp_fake",
                "status": "failed",
                "error": {
                    "code": code,
                    "param": param,
                    "message": "synthetic test stream failure",
                }
            }
        });
        format!("event: response.failed\ndata: {payload}\n\n").into_bytes()
    }
}

impl Default for FakeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for FakeProvider {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.core.handle(request)
    }

    /// Answers a plan request with its scripted [`FakeResponse`], read
    /// piece by piece; a read fails once `canceller` is triggered.
    fn send_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<StreamingResponse, Error> {
        self.core.handle_streaming(request, canceller)
    }
}

impl fmt::Debug for FakeProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeProvider").finish_non_exhaustive()
    }
}
