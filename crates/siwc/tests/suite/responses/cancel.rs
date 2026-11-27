//! Cancelling a plan request: before it is sent, between two attempts and
//! while the stream waits for the next event.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use siwc::store::MemoryStore;
use siwc::testing::{FakeProvider, FakeResponse, FakeUser};
use siwc::{AppName, Canceller, Client, Clock, ErrorKind, UnixTime};

use crate::support::executor::block_on;

use super::{BUSY, Desk, request, sign_in};

#[test]
fn a_cancelled_request_is_not_sent() {
    let desk = Desk::new();
    let canceller = Canceller::new();
    canceller.cancel();
    let error = desk
        .client
        .stream_response_cancellable(&desk.id, &request(), &canceller)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(desk.provider.plan_requests().is_empty());
}

/// A clock whose wait between two attempts is when the user gives up.
#[derive(Debug)]
struct StopWhileWaiting(Canceller);

impl Clock for StopWhileWaiting {
    fn now(&self) -> UnixTime {
        UnixTime::now()
    }

    fn sleep(&self, _wait: Duration) {
        self.0.cancel();
    }
}

#[test]
fn cancelling_in_the_wait_between_two_attempts_sends_no_second_request() {
    let provider = FakeProvider::new();
    let canceller = Canceller::new();
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        MemoryStore::new(),
        provider.transport(),
    )
    .clock(StopWhileWaiting(canceller.clone()))
    .build();
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    provider.push_response(FakeResponse::refusal(503, BUSY).retry_after(30));

    let error = client
        .stream_response_cancellable(&id, &request(), &canceller)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(provider.plan_requests().len(), 1);
}

#[test]
fn cancelling_mid_stream_ends_a_read_that_waits_for_the_next_event() {
    let desk = Desk::new();
    desk.provider
        .push_response(FakeResponse::stream().created().delta("Thinking").hangs());
    let canceller = Canceller::new();
    let stream = desk
        .client
        .stream_response_cancellable(&desk.id, &request(), &canceller)
        .unwrap();

    let (seen, items) = mpsc::channel();
    let reader = thread::spawn(move || {
        for item in stream {
            seen.send(item).unwrap();
        }
    });
    let patience = Duration::from_secs(30);
    let mut shown = String::new();
    while shown.is_empty() {
        let event = items.recv_timeout(patience).unwrap().unwrap();
        shown.push_str(event.text_delta().unwrap_or_default());
    }
    assert_eq!(shown, "Thinking");
    // The reader now waits on a connection that sends nothing more.
    canceller.cancel();
    let error = items.recv_timeout(patience).unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(items.recv_timeout(patience).is_err(), "the stream ended");
    reader.join().unwrap();
    assert_eq!(desk.provider.plan_requests().len(), 1);
}

#[test]
fn events_already_read_are_not_handed_out_after_a_cancellation() {
    // The whole answer arrives in the first read; the app cancels after
    // the first words.
    let desk = Desk::new();
    let script = || FakeResponse::text(&["One", "Two", "Three"]);
    desk.provider.push_response(script());
    let canceller = Canceller::new();
    let mut stream = desk
        .client
        .stream_response_cancellable(&desk.id, &request(), &canceller)
        .unwrap();
    let mut shown = String::new();
    while shown.is_empty() {
        let event = stream.next().unwrap().unwrap();
        shown.push_str(event.text_delta().unwrap_or_default());
    }
    assert_eq!(shown, "One");
    canceller.cancel();
    let error = stream.next().unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(stream.next().is_none());

    // The same for events that wait in the async stream's queue.
    desk.provider.push_response(script());
    let canceller = Canceller::new();
    block_on(async {
        let mut stream = desk
            .client
            .stream_response_async_cancellable(&desk.id, &request(), &canceller)
            .await
            .unwrap();
        let mut shown = String::new();
        while shown.is_empty() {
            let event = stream.next().await.unwrap().unwrap();
            shown.push_str(event.text_delta().unwrap_or_default());
        }
        canceller.cancel();
        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert!(stream.next().await.is_none());
    });

    // A failure that waits behind the cancellation renews nothing.
    let token = desk.token();
    desk.provider
        .push_response(FakeResponse::stream().created().failed(super::INVALID_USER));
    let canceller = Canceller::new();
    let mut stream = desk
        .client
        .stream_response_cancellable(&desk.id, &request(), &canceller)
        .unwrap();
    canceller.cancel();
    let error = stream.next().unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(desk.token(), token);
    assert_eq!(desk.provider.plan_requests().len(), 3);
}

#[test]
fn a_completed_sign_ins_canceller_stops_both_streams() {
    let desk = Desk::new();
    let sign_in = desk.client.add_account().unwrap();
    let stop = sign_in.canceller();
    desk.provider
        .approve(&sign_in, FakeUser::new("guest@example.invalid"));
    let account = sign_in
        .finish(Duration::from_secs(10))
        .unwrap()
        .into_account();
    let request = request();
    for _ in 0..2 {
        desk.provider
            .push_response(FakeResponse::text(&["one", "two"]));
    }
    let mut sync = desk
        .client
        .stream_response_cancellable(account.id(), &request, &stop)
        .unwrap();
    let mut awaited = block_on(desk.client.stream_response_async_cancellable(
        account.id(),
        &request,
        &stop,
    ))
    .unwrap();
    while sync.next().unwrap().unwrap().text_delta().is_none() {}
    while block_on(awaited.next())
        .unwrap()
        .unwrap()
        .text_delta()
        .is_none()
    {}

    stop.cancel();
    assert_eq!(
        sync.next().unwrap().unwrap_err().kind(),
        ErrorKind::Cancelled
    );
    assert_eq!(
        block_on(awaited.next()).unwrap().unwrap_err().kind(),
        ErrorKind::Cancelled
    );
}
