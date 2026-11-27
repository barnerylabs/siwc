//! What an async stream that nobody polls holds on to: the thread that
//! reads the answer ends with the answer, and a cancellation empties the
//! queue whether or not that thread is still there.

use std::cell::RefCell;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use siwc::protocol::{HttpRequest, HttpResponse, StreamingResponse};
use siwc::testing::{FakeClock, FakeProvider, FakeResponse, FakeUser};
use siwc::{AccountId, Canceller, Client, Error, ErrorKind, Transport, UnixTime};

use crate::support::executor::block_on;

use super::{Desk, request, sign_in};

/// Longer than anything here takes; reached only when a test fails.
const PATIENCE: Duration = Duration::from_secs(3);

/// Says so when the thread it was left with ends.
struct Report(Sender<()>);

impl Drop for Report {
    fn drop(&mut self) {
        // The test may have ended already.
        let _ = self.0.send(());
    }
}

thread_local! {
    static AT_THE_END: RefCell<Option<Report>> = const { RefCell::new(None) };
}

pub(super) fn report_thread_end(ended: &Sender<()>) {
    AT_THE_END.with_borrow_mut(|slot| {
        slot.get_or_insert_with(|| Report(ended.clone()));
    });
}

/// Sends through `inner` and reports the end of every thread that sent a
/// streamed request: for an async stream, the thread that reads it.
#[derive(Debug)]
pub(super) struct ThreadEnds<T> {
    inner: T,
    ended: Sender<()>,
}

impl<T> ThreadEnds<T> {
    pub(super) fn watch(inner: T) -> (Self, Receiver<()>) {
        let (ended, ends) = mpsc::channel();
        (Self { inner, ended }, ends)
    }
}

impl<T: Transport> Transport for ThreadEnds<T> {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.inner.send(request)
    }

    fn send_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<StreamingResponse, Error> {
        report_thread_end(&self.ended);
        self.inner.send_streaming(request, canceller)
    }
}

fn desk() -> (FakeProvider, Client, AccountId, Receiver<()>) {
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let (transport, ends) = ThreadEnds::watch(provider.transport());
    let client = Desk::client_over(transport, &clock);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    (provider, client, id, ends)
}

/// An answer of `events` events that ends with `response.completed`.
fn completed_with(events: usize) -> FakeResponse {
    FakeResponse::text(&vec!["x"; events - 3])
}

/// An answer of `items` items whose last one is an error: the connection
/// breaks behind the events.
fn broken_with(items: usize) -> FakeResponse {
    (1..items)
        .fold(FakeResponse::stream(), |script, _| script.delta("x"))
        .interrupted()
}

#[test]
fn the_reading_thread_ends_with_the_answer_even_when_its_last_item_fills_the_queue() {
    let (provider, client, id, ends) = desk();
    // 32 items fill the queue; one fewer leaves room behind the last.
    for items in [31, 32] {
        for answer in [completed_with(items), broken_with(items)] {
            provider.push_response(answer);
            let stream = block_on(client.stream_response_async(&id, &request())).unwrap();
            // Nobody polls. The thread has read the whole answer and has
            // nothing left to wait for.
            ends.recv_timeout(PATIENCE)
                .unwrap_or_else(|_| panic!("{items} items: the thread still waits; {stream:?}"));
            let waiting = format!("waiting_events: {items},");
            assert!(format!("{stream:?}").contains(&waiting), "{stream:?}");
            drop(stream);
        }
    }
}

#[test]
fn a_cancellation_empties_the_queue_of_a_stream_whose_thread_has_ended() {
    let (provider, client, id, ends) = desk();
    for items in [4, 31, 32] {
        provider.push_response(completed_with(items));
        let canceller = Canceller::new();
        let mut stream =
            block_on(client.stream_response_async_cancellable(&id, &request(), &canceller))
                .unwrap();
        ends.recv_timeout(PATIENCE).unwrap();
        let waiting = format!("waiting_events: {items},");
        assert!(format!("{stream:?}").contains(&waiting), "{stream:?}");

        // Neither polled nor dropped: the cancellation alone lets go of
        // the answer that waited, before anybody asks.
        canceller.cancel();
        assert!(
            format!("{stream:?}").contains("waiting_events: 0,"),
            "{items} items: {stream:?}"
        );
        block_on(async {
            let error = stream.next().await.unwrap().unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Cancelled);
            assert!(stream.next().await.is_none());
        });
    }
}
