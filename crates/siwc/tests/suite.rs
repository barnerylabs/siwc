//! Integration tests for `siwc`, run against an in-memory fake provider.
//!
//! Everything here goes through the public API. No test sleeps or touches
//! the network; the loopback tests use sockets on `127.0.0.1` only. One
//! store test and one responses test wait out a lock's patience of 60 ms. The
//! cross-process lock tests start this program again as the holder or reader.
#![expect(
    unreachable_pub,
    reason = "the support modules are private to this test program"
)]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed assumption in a test or in the fake provider fails the test"
)]

mod support;

#[path = "suite/accounts.rs"]
mod accounts;
#[path = "suite/authorization.rs"]
mod authorization;
#[path = "suite/background.rs"]
mod background;
#[path = "suite/callback.rs"]
mod callback;
#[path = "suite/client_accounts.rs"]
mod client_accounts;
#[path = "suite/client_changes.rs"]
mod client_changes;
#[path = "suite/client_diagnosis.rs"]
mod client_diagnosis;
#[path = "suite/client_manual_sign_in.rs"]
mod client_manual_sign_in;
#[path = "suite/client_models.rs"]
mod client_models;
#[path = "suite/client_sign_in.rs"]
mod client_sign_in;
#[path = "suite/client_sign_in_async.rs"]
mod client_sign_in_async;
#[path = "suite/client_store.rs"]
mod client_store;
#[path = "suite/client_tokens.rs"]
mod client_tokens;
#[path = "suite/client_transfer.rs"]
mod client_transfer;
#[path = "suite/exchange.rs"]
mod exchange;
#[path = "suite/id_token.rs"]
mod id_token;
#[path = "suite/loopback.rs"]
mod loopback;
#[path = "suite/mangled.rs"]
mod mangled;
#[path = "suite/pasted.rs"]
mod pasted;
#[path = "suite/plan.rs"]
mod plan;
#[path = "suite/plan_endings.rs"]
mod plan_endings;
#[path = "suite/plan_events.rs"]
mod plan_events;
#[path = "suite/plan_examples.rs"]
mod plan_examples;
#[path = "suite/refresh.rs"]
mod refresh;
#[cfg(feature = "testing")]
#[path = "suite/responses.rs"]
mod responses;
#[path = "suite/revocation.rs"]
mod revocation;
#[path = "suite/sealed.rs"]
mod sealed;
#[path = "suite/sealed_upgrade.rs"]
mod sealed_upgrade;
#[path = "suite/secrets.rs"]
mod secrets;
#[path = "suite/store.rs"]
mod store;
#[cfg(feature = "testing")]
#[path = "suite/testing.rs"]
mod testing;
#[path = "suite/transport.rs"]
mod transport;
