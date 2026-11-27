//! `Client::stream_response`: a plan request sent by the crate and read as a
//! stream of events, against the scripted `/v1/responses` route of
//! `siwc::testing::FakeProvider`.

//!
//! This file holds what the tests share; the rules are in the modules
//! below, one topic each.

use siwc::plan::{ResponseEvent, ResponseRequest};
use siwc::store::MemoryStore;
use siwc::testing::{FakeClock, FakeProvider, FakeUser};
use siwc::{AccountId, AppName, Client, ClientBuilder, Error, Transport, UnixTime};

use crate::support::executor::block_on;
use crate::support::random::Seeded;

#[path = "responses/answers.rs"]
mod answers;
#[path = "responses/async_end.rs"]
mod async_end;
#[path = "responses/async_state.rs"]
mod async_state;
#[path = "responses/async_stream.rs"]
mod async_stream;
#[path = "responses/cancel.rs"]
mod cancel;
#[path = "responses/decoding.rs"]
mod decoding;
#[path = "responses/diagnosis.rs"]
mod diagnosis;
#[path = "responses/echo.rs"]
mod echo;
#[path = "responses/ending.rs"]
mod ending;
#[path = "responses/events.rs"]
mod events;
#[path = "responses/fake.rs"]
mod fake;
#[cfg(all(feature = "keychain", target_os = "linux"))]
#[path = "responses/key_lock.rs"]
mod key_lock;
#[path = "responses/lock.rs"]
mod lock;
#[path = "responses/processes.rs"]
mod processes;
#[path = "responses/reads.rs"]
mod reads;
#[path = "responses/renewal.rs"]
mod renewal;
#[path = "responses/resend.rs"]
mod resend;
#[path = "responses/retry.rs"]
mod retry;
#[path = "responses/spawner.rs"]
mod spawner;
#[path = "responses/status_rule.rs"]
mod status_rule;
#[path = "responses/store_reads.rs"]
mod store_reads;
#[path = "responses/tail.rs"]
mod tail;
#[path = "responses/transport.rs"]
mod transport;

const BUSY: &str = "subscription_sharing_usage_unavailable";
const LIMIT: &str = "subscription_sharing_usage_limit_exceeded";
const INVALID_USER: &str = "subscription_sharing_invalid_user";

/// A signed-in account on a fake provider, with a clock that records the
/// waits between attempts instead of waiting.
pub struct Desk {
    pub provider: FakeProvider,
    pub clock: FakeClock,
    pub client: Client,
    pub id: AccountId,
}

impl Desk {
    pub fn new() -> Self {
        Self::with_user(FakeUser::new("owner@example.invalid"))
    }

    fn with_user(user: FakeUser) -> Self {
        let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
        let provider = FakeProvider::with_clock(&clock);
        let client = Self::client_over(provider.transport(), &clock);
        let id = sign_in(&client, &provider, user);
        Self {
            provider,
            clock,
            client,
            id,
        }
    }

    /// A desk whose client never sends a plan request again after a `5xx`.
    pub fn sending_once_after_server_errors() -> Self {
        let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
        let provider = FakeProvider::with_clock(&clock);
        let client = Self::builder_over(provider.transport(), &clock)
            .resend_after_server_error(false)
            .build();
        let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
        Self {
            provider,
            clock,
            client,
            id,
        }
    }

    /// A client on a store of its own that sends through `transport`.
    pub fn client_over(transport: impl Transport + 'static, clock: &FakeClock) -> Client {
        Self::builder_over(transport, clock).build()
    }

    fn builder_over(transport: impl Transport + 'static, clock: &FakeClock) -> ClientBuilder {
        Client::builder(
            AppName::new("Paste Perfect").unwrap(),
            MemoryStore::new(),
            transport,
        )
        .clock(clock.clone())
        .entropy(Seeded::new(11))
    }

    fn token(&self) -> String {
        let token = self.client.access_token(&self.id).unwrap();
        token.expose().to_owned()
    }

    /// Every item of the stream for one request, or the error of opening it.
    fn items(&self) -> Result<Vec<Result<ResponseEvent, Error>>, Error> {
        Ok(self.client.stream_response(&self.id, &request())?.collect())
    }
}

/// Signs `user` in without a browser and returns the new account's ID.
pub fn sign_in(client: &Client, provider: &FakeProvider, user: FakeUser) -> AccountId {
    let mut sign_in = client.add_account_manually().unwrap();
    let redirect = provider.approve_manual(&sign_in, user).unwrap();
    sign_in.finish(&redirect).unwrap().account().id().clone()
}

pub fn request() -> ResponseRequest {
    ResponseRequest::text("example-large", "Why is the sky blue?").unwrap()
}

/// Every item of the async stream for one request, or the error of
/// opening it.
fn items_async(
    client: &Client,
    id: &AccountId,
) -> Result<Vec<Result<ResponseEvent, Error>>, Error> {
    block_on(async {
        let mut stream = client.stream_response_async(id, &request()).await?;
        let mut items = Vec::new();
        while let Some(item) = stream.next().await {
            items.push(item);
        }
        Ok(items)
    })
}

/// What each item is: an event's type, or the kind of the error.
fn kinds(items: &[Result<ResponseEvent, Error>]) -> Vec<String> {
    items
        .iter()
        .map(|item| match item {
            Ok(event) => event.event_type().unwrap_or("?").to_owned(),
            Err(error) => format!("{:?}", error.kind()),
        })
        .collect()
}

fn text(items: &[Result<ResponseEvent, Error>]) -> String {
    items
        .iter()
        .filter_map(|item| item.as_ref().ok()?.text_delta())
        .collect()
}

fn last_error(items: &[Result<ResponseEvent, Error>]) -> &Error {
    items.last().unwrap().as_ref().unwrap_err()
}
