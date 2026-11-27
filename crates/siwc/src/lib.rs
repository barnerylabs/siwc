//! Client for Sign in with ChatGPT in desktop apps and command-line tools
//! that run on the user's own machine.
//!
//! A user signs in through the system browser; the app receives tokens and
//! uses the user's ChatGPT plan through the OpenAI API. `siwc` is an
//! independent implementation of the publicly documented flow and is not
//! affiliated with or endorsed by OpenAI. These docs call OpenAI's
//! authorization server and API "the provider".
//!
//! ```toml
//! [dependencies]
//! siwc = { version = "0.1", features = ["https", "keychain"] }
//! ```
//!
//! ```no_run
//! # #[cfg(all(feature = "https", feature = "keychain"))]
//! # fn example() -> Result<(), siwc::Error> {
//! use std::time::Duration;
//!
//! use siwc::store::Keychain;
//! use siwc::{AppName, Client, Https};
//!
//! // Encrypted files in the user's app-data folder; their key is in the
//! // OS keychain.
//! let store = Keychain::open_sealed("com.example.paste-perfect", "paste-perfect")?;
//! let client = Client::new(AppName::new("Paste Perfect")?, store, Https::new()?);
//!
//! // Add an account: the user signs in through the browser.
//! let sign_in = client.add_account()?;
//! if sign_in.open_browser().is_err() {
//!     println!("To sign in, open {}", sign_in.start_link());
//! }
//! let account = sign_in.finish(Duration::from_secs(300))?.into_account();
//!
//! // Later, including after a restart: every call names its account.
//! for account in client.accounts()? {
//!     let token = client.access_token(account.id())?;
//!     // `client.stream_response(account.id(), &request)` sends a plan
//!     // request with this token and streams the answer; see the `plan` module.
//!     # drop(token);
//! }
//! let signed_out = client.sign_out(account.id())?;
//! # drop(signed_out);
//! # Ok(())
//! # }
//! ```
//!
//! [`Client::new`] takes any [`store::Store`] and any [`Transport`]. Without
//! the two features above, pass [`store::PrivateFiles`] or
//! [`store::MemoryStore`] as the store, and as the transport `Ureq` (feature
//! `ureq`) or your own implementation of [`Transport`] over the HTTP client
//! the app already has.
//!
//! From here, [`plan`] walks through sending requests on the user's plan and
//! [`ErrorKind`] says what to do about each error.
//! [`examples/quickstart.rs`](https://github.com/barnerylabs/siwc/blob/v0.1.0/crates/siwc/examples/quickstart.rs)
//! is a complete program that signs in and streams an answer. The
//! [README](https://github.com/barnerylabs/siwc/blob/v0.1.0/README.md)
//! compares the transports and stores and has recipes for async executors,
//! an HTTP client of your own, headless servers, offline tests and corporate
//! proxies.
//!
//! # Choosing how to store accounts
//!
//! A desktop app calls `store::Keychain::open_sealed(service, app_dir)`
//! (feature `keychain`). It wraps [`store::PrivateFiles::open_app_dir`] in
//! [`store::Sealed`] and seals in place the plain `installation` and
//! `account-*` entries it finds; [`store::Sealed::reseal`] rotates to a new
//! key without losing accounts.
//! [`examples/keychain.rs`](https://github.com/barnerylabs/siwc/blob/v0.1.0/crates/siwc/examples/keychain.rs)
//! and
//! [`examples/desktop.rs`](https://github.com/barnerylabs/siwc/blob/v0.1.0/crates/siwc/examples/desktop.rs)
//! show it.
//!
//! A command-line tool on a server, in a container or in an SSH session
//! builds its [`Client`] over [`store::PrivateFiles::open_app_dir`], or over
//! an explicit path with [`store::PrivateFiles::open`]. To sign in without a
//! local browser, it forwards a fixed port set with
//! [`ClientBuilder::callback_port`], calls [`Client::add_account_manually`]
//! when no port can be forwarded, or takes over a session signed in
//! elsewhere as a passphrase-sealed bundle
//! ([`examples/sign_in.rs`](https://github.com/barnerylabs/siwc/blob/v0.1.0/crates/siwc/examples/sign_in.rs)).
//!
//! A test, or a session that ends with the process, passes
//! [`store::MemoryStore`], which writes nothing to disk.
//!
//! # Feature flags
//!
//! No feature is on by default.
//!
//! - `https`: `Https` and `https::HttpsBuilder`, a blocking TLS 1.3
//!   transport for the crate's requests to the provider's two hosts,
//!   streamed plan requests included. It takes extra PEM root CAs and an
//!   `http://` or `https://` forward `CONNECT` proxy.
//! - `ureq`: `Ureq` and `ureq::UreqBuilder`, a second blocking transport
//!   for the same requests, built on ureq 3.5, with the same options for
//!   roots and proxies. `ureq::Ureq` documents where its TLS, logging,
//!   timeouts and cancellation differ.
//! - `keychain`: `store::Keychain`, which keeps the 32-byte sealing key of
//!   [`store::Sealed`] in the macOS default keychain, the Linux Secret
//!   Service or the Windows Credential Manager.
//! - `testing`: `testing::{FakeProvider, FakeClock, FakeUser, FakeResponse}`
//!   and `store::conformance::check` for an app's own test suite, and the
//!   `Entropy` trait for fixed randomness in tests. It adds no dependency.
//!
//! # The app appears under its own name
//!
//! The first sign-in registers the app with the provider under an
//! [`AppName`]. That name is what the user reads on the consent screen and
//! later finds in their ChatGPT settings, so it is a required argument with
//! no default, and names that belong to the provider or to this library are
//! refused.
//!
//! # What is here
//!
//! [`Client`] is what most apps use. It holds up to 32 accounts side by side,
//! each with its own registration, credentials entry and lock:
//!
//! - [`Client::add_account`] and [`Client::sign_in_again`] run a browser
//!   sign-in through the loopback listener; their `*_manually` counterparts
//!   serve remote shells.
//! - [`Client::export_account_to`] writes a passphrase-sealed account bundle
//!   to a new path and syncs the file (and on Unix, the directory) before
//!   deleting local tokens. [`Client::import_account`] verifies the bundle's
//!   identity with the provider's signing keys before storing it.
//! - [`Client::access_token`] and [`Client::access_token_async`] renew tokens
//!   under the account's lock, across threads and processes.
//! - [`Client::stream_response`] and [`Client::stream_response_async`] send
//!   a request to the Responses API on the user's plan through the
//!   [`Transport`] and hand out the answer as it is written
//!   ([`ResponseStream`], [`AsyncResponseStream`]).
//! - [`Client::call`] and [`Client::call_async`] wrap a plan request the app
//!   sends with its own HTTP client: they renew a rejected token once
//!   and retry temporary API errors a bounded number of times; their
//!   `*_cancellable` counterparts stop early when a [`Canceller`] fires.
//! - [`Client::selected_account`] and [`Client::select_account`] store which
//!   account the app's UI has selected. Every token and API call still names
//!   its [`AccountId`] and never falls back from one account to another.
//!
//! The layers below it are public for apps that drive the steps
//! themselves:
//!
//! - [`protocol`] holds the whole flow as pure data without I/O: PKCE, `state`
//!   and `nonce`, callback and pasted-redirect validation, code exchange,
//!   RS256 ID token verification, refresh with rotation (`earliest_refresh_at`
//!   honoured) and revocation.
//! - [`loopback`] serves `127.0.0.1` for one sign-in. It redirects a local
//!   start link to the provider and answers the tab with a CSP-locked page
//!   whose texts and look the app sets with [`loopback::Texts`] and
//!   [`loopback::Style`].
//! - [`plan`] lists the models an account may use ([`plan::Models`]), checks
//!   the body of a plan request ([`plan::ResponseRequest`]), decodes
//!   streamed `/v1/responses` SSE chunks ([`plan::SseDecoder`],
//!   [`plan::ResponseEvent`], [`plan::StreamEvent`]), classifies HTTP and
//!   streaming API refusals ([`plan::Refusal::from_response`],
//!   [`plan::Refusal::from_event`]), and exports [`plan::RESPONSES_URL`],
//!   [`plan::MODELS_URL`], [`plan::MANAGE_USAGE_URL`] and [`plan::wording`].
//! - [`store`] defines [`store::Store`] with cross-process locks, and the
//!   stores [`store::MemoryStore`], [`store::PrivateFiles`] and
//!   [`store::Sealed`].
//! - [`Transport`] and [`Clock`] are the network and time seams.
//!   [`background::run`] turns any blocking call into a `Future` that needs
//!   no particular runtime, and [`ClientBuilder::spawner`] puts the work of
//!   the `*_async` methods on a runtime's own pool for blocking calls.
//!
//! Secrets are their own types. They print as `[redacted]`, are wiped when
//! dropped and implement neither `Display` nor serialisation. Through
//! [`Client`] the only one an app reads is the [`AccessToken`]; the
//! low-level [`protocol::Credentials::to_stored`] form exposes the refresh
//! and ID tokens too and is as sensitive as the store.
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod account;
mod app;
pub mod background;
mod cancel;
mod client;
mod entropy;
mod error;
mod hex;
mod host;
#[cfg(feature = "https")]
#[cfg_attr(docsrs, doc(cfg(feature = "https")))]
pub mod https;
pub mod loopback;
#[cfg(test)]
mod open_trait_tests;
pub mod plan;
pub mod protocol;
mod secret;
pub mod store;
#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;
mod time;
mod transport;
#[cfg(feature = "ureq")]
#[cfg_attr(docsrs, doc(cfg(feature = "ureq")))]
pub mod ureq;

pub use account::{Account, AccountId, AccountState};
pub use app::AppName;
pub use cancel::Canceller;
pub use client::{
    AsyncResponseStream, Change, Changes, Client, ClientBuilder, Completed, Diagnosis,
    ManualSignIn, ResponseStream, SignIn, SignOut,
};
#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub use entropy::Entropy;
pub use entropy::OsEntropy;
pub use error::{Error, ErrorCause, ErrorKind};
pub use host::HostId;
#[cfg(feature = "https")]
#[cfg_attr(docsrs, doc(cfg(feature = "https")))]
pub use https::{Https, HttpsBuilder};
pub use secret::AccessToken;
pub use time::{Clock, SystemClock, UnixTime};
pub use transport::Transport;
#[cfg(feature = "ureq")]
#[cfg_attr(docsrs, doc(cfg(feature = "ureq")))]
pub use ureq::{Ureq, UreqBuilder};

// The program in the README is compiled as a doc test. Cargo names the file
// in `CARGO_PKG_README`, so the path holds in the repository and the package.
#[cfg(all(doctest, feature = "https", feature = "keychain", feature = "testing"))]
#[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/", env!("CARGO_PKG_README")))]
struct Readme;

/// Exercises account-bundle envelope and payload parsing for cargo-fuzz harnesses.
#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_account_bundle(data: &[u8]) {
    client::fuzz_bundle(data);
}

/// Exercises stored installation and credentials readers (including
/// `earliest_refresh_at` parsing) for cargo-fuzz harnesses.
#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_stored_records(data: &[u8]) {
    client::fuzz_installation(data);
    if let Ok(credentials) = protocol::Credentials::from_stored(data) {
        let _ = credentials.earliest_refresh_time();
    }
    if let Ok(text) = std::str::from_utf8(data) {
        protocol::fuzz_timestamp(text);
    }
}

#[cfg(test)]
mod send_sync_tests {
    use std::future::Future;
    use std::time::Duration;

    use super::*;

    fn thread_safe<T: Send + Sync + Unpin>() {}
    fn assert_send<T: Send>() {}
    fn shared<T: Send + Sync + Unpin + std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
    fn ref_unwind_safe<T: std::panic::RefUnwindSafe>() {}
    fn movable<T: Unpin>() {}
    fn unwind_safe<T: Unpin + std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
    fn shared_iterator<
        T: Iterator + Send + Sync + Unpin + std::panic::UnwindSafe + std::panic::RefUnwindSafe,
    >(
        _: T,
    ) {
    }

    fn assert_send_future<F: Future + Send>(_: F) {}

    #[derive(Debug)]
    struct DummyKey;

    impl store::SealingKey for DummyKey {
        fn lock_generation(&self) -> Result<store::KeyGeneration<'_>, Error> {
            Ok(store::KeyGeneration::new(0, None))
        }

        fn fill(&self, key: &mut [u8; store::KEY_LEN]) -> Result<(), Error> {
            key.fill(7);
            Ok(())
        }

        fn fill_retired(&self, _keys: &mut store::RetiredKeys<'_>) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn public_handles_and_futures_are_send_and_sync() {
        shared::<(
            Account,
            AccountId,
            AccountState,
            AccessToken,
            AppName,
            Change,
            Completed,
            Diagnosis,
            Error,
            ErrorCause,
            ErrorKind,
            HostId,
            SignOut,
        )>();
        shared::<(
            AsyncResponseStream,
            ResponseStream,
            Canceller,
            SystemClock,
            UnixTime,
            OsEntropy,
        )>();
        shared::<(
            plan::Model,
            plan::Models,
            plan::Reason,
            plan::Refusal,
            plan::ResponseRequest,
            plan::ResponseEvent,
            plan::SseDecoder,
            plan::StreamEvent,
        )>();
        shared::<(
            protocol::Accepted,
            protocol::Attempt,
            protocol::Callback,
            protocol::NewRegistration,
            protocol::Registration<'_>,
            protocol::Returning<'_>,
        )>();
        shared::<(
            protocol::Credentials,
            protocol::Exchange,
            protocol::SignedIn,
            protocol::Unverified,
            protocol::IssuedClientId,
            protocol::Identity,
            protocol::Jwks,
        )>();
        shared::<(
            protocol::HttpRequest,
            protocol::HttpResponse,
            protocol::Method,
            protocol::Scopes,
            protocol::ScopeIter<'_>,
        )>();
        shared::<(
            loopback::Answer,
            loopback::Page,
            loopback::Text,
            loopback::Texts,
            loopback::Reply,
            loopback::LogoFormat,
            loopback::Style,
            loopback::Listener,
            loopback::Waiting,
            loopback::Received,
        )>();
        shared::<(
            store::Stored,
            store::EntryName,
            store::MemoryStore,
            store::PrivateFiles,
            store::Sealed<store::MemoryStore, DummyKey>,
        )>();
        shared_iterator(protocol::Scopes::default().iter());
        shared_iterator(protocol::Jwks::request().headers());

        thread_safe::<(Client, ClientBuilder, Changes, SignIn, ManualSignIn)>();
        shared::<background::Background<std::cell::Cell<u8>>>();
        unwind_safe::<background::Background<std::rc::Rc<()>>>();
        movable::<(
            store::Lock<'_>,
            store::KeyGeneration<'_>,
            protocol::StreamingResponse,
            background::Job,
        )>();
        assert_send::<(protocol::StreamingResponse, background::Job)>();
        thread_safe::<store::RetiredKeys<'_>>();
        ref_unwind_safe::<store::RetiredKeys<'_>>();
        #[cfg(feature = "ureq")]
        {
            thread_safe::<Ureq>();
            shared::<UreqBuilder>();
        }
        #[cfg(feature = "https")]
        {
            thread_safe::<Https>();
            shared::<HttpsBuilder>();
        }
        #[cfg(feature = "keychain")]
        shared::<store::Keychain>();
        #[cfg(feature = "testing")]
        {
            thread_safe::<testing::FakeProvider>();
            shared::<(testing::FakeClock, testing::FakeUser, testing::FakeResponse)>();
        }

        // Compile-time check that every async method produces a `Send` future
        // suitable for multi-threaded executors (`tokio::spawn` and equivalents).
        fn check_send_futures(
            client: &Client,
            id: &AccountId,
            token: &AccessToken,
            cancel: &Canceller,
            sign_in: SignIn,
            request: &plan::ResponseRequest,
            mut stream: AsyncResponseStream,
        ) {
            assert_send_future(background::run(|| 1_u8));
            assert_send_future(client.access_token_async(id));
            assert_send_future(client.access_token_after_rejection_async(id, token));
            assert_send_future(client.models_async(id));
            assert_send_future(client.sign_out_async(id));
            assert_send_future(client.forget_async(id));
            assert_send_future(client.call_async(id, |_tok| async move {
                Ok::<Result<(), plan::Refusal>, Error>(Ok(()))
            }));
            assert_send_future(
                client.call_async_cancellable(id, cancel, |_tok| async move {
                    Ok::<Result<(), plan::Refusal>, Error>(Ok(()))
                }),
            );
            assert_send_future(sign_in.finish_async(Duration::from_secs(1)));
            assert_send_future(client.stream_response_async(id, request));
            assert_send_future(client.stream_response_async_cancellable(id, request, cancel));
            assert_send_future(stream.next());
            assert_send_future(stream.into_text());
        }
        let _ = check_send_futures;
    }
}
