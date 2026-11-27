//! `ClientBuilder::spawner`: where the async calls run their work.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use siwc::background::Job;
use siwc::store::MemoryStore;
use siwc::testing::{FakeClock, FakeProvider, FakeResponse, FakeUser};
use siwc::{AccountId, AppName, Client, ErrorKind, UnixTime};

use crate::support::executor::block_on;
use crate::support::random::Seeded;

use super::{items_async, kinds, sign_in};

/// A signed-in account on a client whose async work goes to `spawner`.
fn desk(spawner: impl Fn(Job) + Send + Sync + 'static) -> (FakeProvider, Client, AccountId) {
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        MemoryStore::new(),
        provider.transport(),
    )
    .clock(clock)
    .entropy(Seeded::new(11))
    .spawner(spawner)
    .build();
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    (provider, client, id)
}

#[test]
fn async_calls_and_streams_run_where_the_spawner_puts_them() {
    let jobs = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&jobs);
    let (provider, client, id) = desk(move |job| {
        counted.fetch_add(1, Ordering::Relaxed);
        thread::spawn(job);
    });

    block_on(client.access_token_async(&id)).unwrap();
    assert_eq!(jobs.load(Ordering::Relaxed), 1);

    provider.push_response(FakeResponse::text(&["Here."]));
    let items = items_async(&client, &id).unwrap();
    assert_eq!(
        kinds(&items).last().map(String::as_str),
        Some("response.completed")
    );
    assert_eq!(jobs.load(Ordering::Relaxed), 2);
}

#[test]
fn a_stream_whose_job_the_spawner_drops_ends_before_anything_is_sent() {
    let (provider, client, id) = desk(drop);
    provider.push_response(FakeResponse::text(&["never sent"]));
    let error = items_async(&client, &id).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert!(provider.plan_requests().is_empty());
}
