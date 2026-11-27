//! Cancellation with a transport that leaves it to the client: its reader
//! never looks at the canceller, so the client does, around every read.

use std::io::{self, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use siwc::protocol::StreamingResponse;
use siwc::testing::FakeProvider;
use siwc::{Canceller, ErrorCause, ErrorKind};

use crate::support::executor::block_on;

use super::answers::{Wired, completed, delta, opening};
use super::{BUSY, kinds, request};

/// What one read of a body does.
#[derive(Clone)]
enum Step {
    /// Hands out these bytes, as many as fit.
    Bytes(Vec<u8>),
    /// Fails the way a signal makes a read fail.
    Interrupted,
    /// Fails with this kind and a message that must not travel.
    Fails(io::ErrorKind),
    Oversized,
    /// Reports the clean end of the body.
    End,
}

/// A body that follows its script read by read and cancels the request
/// from inside the read with the number `cancel_in`.
struct Stubborn {
    steps: Vec<Step>,
    reads: Arc<AtomicUsize>,
    cancel_in: usize,
    canceller: Canceller,
}

impl Read for Stubborn {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let number = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        if number == self.cancel_in {
            self.canceller.cancel();
        }
        let step = self.steps.get(number - 1).cloned().unwrap_or(Step::End);
        match step {
            Step::Bytes(bytes) => {
                assert!(bytes.len() <= buffer.len());
                buffer[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            Step::Interrupted => Err(io::ErrorKind::Interrupted.into()),
            Step::Fails(kind) => Err(io::Error::new(kind, "synthetic-secret in a reader message")),
            Step::Oversized => Ok(buffer.len() + 1),
            Step::End => Ok(0),
        }
    }
}

/// Queues an answer with `status` whose body follows `steps`, and returns
/// the canceller of the request and the count of reads.
fn queue(
    wired: &Wired,
    status: u16,
    steps: Vec<Step>,
    cancel_in: usize,
) -> (Canceller, Arc<AtomicUsize>) {
    let canceller = Canceller::new();
    let reads = Arc::new(AtomicUsize::new(0));
    let body = Stubborn {
        steps,
        reads: Arc::clone(&reads),
        cancel_in,
        canceller: canceller.clone(),
    };
    wired.answer(move |_| StreamingResponse::new(status, body));
    (canceller, reads)
}

/// A body one byte per read.
fn byte_by_byte(body: &[u8]) -> Vec<Step> {
    body.iter().map(|byte| Step::Bytes(vec![*byte])).collect()
}

#[test]
fn a_refusal_body_is_not_read_on_after_a_cancellation() {
    let refusal = FakeProvider::refusal_body(BUSY, None);
    let interrupted_first = [vec![Step::Interrupted], byte_by_byte(&refusal)].concat();
    for (steps, cancel_in) in [
        // Cancelled inside the first read of many, and inside a later one.
        (byte_by_byte(&refusal), 1),
        (byte_by_byte(&refusal), 5),
        // Inside a read that was interrupted, which is otherwise repeated.
        (interrupted_first.clone(), 1),
        // Inside the read that reports the end: the refusal arrived whole
        // and would be waited out and sent again.
        (byte_by_byte(&refusal), refusal.len() + 1),
    ] {
        let (wired, client, id, clock) = Wired::desk();
        let (canceller, reads) = queue(&wired, 503, steps, cancel_in);
        let error = client
            .stream_response_cancellable(&id, &request(), &canceller)
            .unwrap_err();
        assert_eq!(
            error.kind(),
            ErrorKind::Cancelled,
            "cancelled in {cancel_in}"
        );
        assert_eq!(reads.load(Ordering::SeqCst), cancel_in);
        assert_eq!(wired.sent(), 1);
        assert!(clock.sleeps().is_empty());
    }

    // Not cancelled, an interrupted read is repeated and the refusal read.
    let (wired, client, id, _clock) = Wired::desk();
    let (canceller, reads) = queue(&wired, 403, interrupted_first, 0);
    let error = client
        .stream_response_cancellable(&id, &request(), &canceller)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotPermitted);
    assert_eq!(error.provider_code(), Some(BUSY));
    assert_eq!(reads.load(Ordering::SeqCst), refusal.len() + 2);
}

#[test]
fn an_answer_is_not_read_on_after_a_cancellation() {
    let answer = [opening(), delta("All of it"), completed()].concat();
    let whole = vec![Step::Bytes(answer.clone())];
    for (steps, cancel_in, expected) in [
        // Inside an interrupted read, before any event.
        (
            [vec![Step::Interrupted], whole.clone()].concat(),
            1,
            vec!["Cancelled"],
        ),
        // Inside the read that reports the end: every event arrived, but
        // a cancelled request has no complete answer.
        (
            whole.clone(),
            2,
            vec![
                "response.created",
                "response.in_progress",
                "response.output_text.delta",
                "Cancelled",
            ],
        ),
        // Inside an interrupted read behind the last event.
        (
            [whole.clone(), vec![Step::Interrupted]].concat(),
            2,
            vec![
                "response.created",
                "response.in_progress",
                "response.output_text.delta",
                "Cancelled",
            ],
        ),
    ] {
        let (wired, client, id, _clock) = Wired::desk();
        let (canceller, reads) = queue(&wired, 200, steps.clone(), cancel_in);
        let stream = client
            .stream_response_cancellable(&id, &request(), &canceller)
            .unwrap();
        let items: Vec<_> = stream.collect();
        assert_eq!(kinds(&items), expected, "cancelled in {cancel_in}");
        assert_eq!(reads.load(Ordering::SeqCst), cancel_in);

        let (canceller, reads) = queue(&wired, 200, steps, cancel_in);
        let items = block_on(async {
            let mut stream = client
                .stream_response_async_cancellable(&id, &request(), &canceller)
                .await
                .unwrap();
            let mut items = Vec::new();
            while let Some(item) = stream.next().await {
                items.push(item);
            }
            items
        });
        assert_eq!(kinds(&items).last().unwrap(), "Cancelled");
        assert!(reads.load(Ordering::SeqCst) <= cancel_in);
        assert_eq!(wired.sent(), 2);
    }
}

#[test]
fn a_head_that_arrives_for_a_cancelled_request_is_not_accepted() {
    for status in [200, 503, 401] {
        let (wired, client, id, clock) = Wired::desk();
        let canceller = Canceller::new();
        let body = wired.body([opening(), delta("All of it"), completed()].concat());
        wired.answer({
            let canceller = canceller.clone();
            move |_| {
                // The user gave up while the request was on its way.
                canceller.cancel();
                StreamingResponse::new(status, body)
            }
        });
        let error = client
            .stream_response_cancellable(&id, &request(), &canceller)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Cancelled, "{status}");
        assert_eq!(wired.served(), 0, "{status}");
        assert_eq!(wired.sent(), 1, "{status}");
        assert!(clock.sleeps().is_empty(), "{status}");
    }
}

#[test]
fn invalid_reader_progress_ends_accepted_and_refused_bodies() {
    for status in [200, 403] {
        for (steps, expected_reads) in [
            (vec![Step::Interrupted; 64], 32),
            (vec![Step::Oversized], 1),
        ] {
            let (wired, client, id, _) = Wired::desk();
            let (_, reads) = queue(&wired, status, steps, 0);
            let error = client
                .stream_response(&id, &request())
                .and_then(|stream| stream.into_text())
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Temporary);
            assert_eq!(
                reads.load(Ordering::SeqCst),
                expected_reads,
                "status {status}"
            );
            assert_eq!(wired.sent(), 1);
        }
    }
}

#[test]
fn a_failed_body_read_names_only_the_kind_of_the_readers_error() {
    for status in [200, 403] {
        for (kind, cause) in [
            (io::ErrorKind::TimedOut, ErrorCause::TimedOut),
            (io::ErrorKind::ConnectionReset, ErrorCause::ConnectionClosed),
            (
                io::ErrorKind::PermissionDenied,
                ErrorCause::Io(io::ErrorKind::PermissionDenied),
            ),
        ] {
            let (wired, client, id, _) = Wired::desk();
            queue(&wired, status, vec![Step::Fails(kind)], 0);
            let error = client
                .stream_response(&id, &request())
                .and_then(|stream| stream.into_text())
                .unwrap_err();
            assert_eq!(error.cause(), Some(cause), "status {status}");
            let source = std::error::Error::source(&error).map(ToString::to_string);
            let shown = format!("{error} {error:?} {source:?}");
            assert!(!shown.contains("synthetic-secret"), "{shown}");
        }
    }
}

#[test]
fn an_invalid_stream_status_is_rejected_before_reading_the_body() {
    for status in [99, 600] {
        let (wired, client, id, clock) = Wired::desk();
        let (_, reads) = queue(&wired, status, vec![Step::Oversized], 0);
        let error = client.stream_response(&id, &request()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
        assert_eq!(error.http_status(), None);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(wired.sent(), 1);
        assert!(clock.sleeps().is_empty());
    }
}
