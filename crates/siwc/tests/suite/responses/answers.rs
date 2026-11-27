//! A transport whose answers to plan requests the test writes itself, head
//! and bytes, for what the fake provider does not script: a header the
//! provider would not send, a body of a counted length, the token echoed
//! back.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use siwc::protocol::{HttpRequest, HttpResponse, StreamingResponse};
use siwc::testing::{FakeClock, FakeProvider, FakeUser};
use siwc::{AccountId, Canceller, Client, Error, Transport, UnixTime};

use super::{Desk, sign_in};

/// Makes one answer from the bearer token of the request it answers.
type Make = Box<dyn FnOnce(&str) -> StreamingResponse + Send>;

/// Answers plan requests from the test's queue and sends everything else
/// to the fake provider.
pub struct Wired {
    provider: FakeProvider,
    answers: Mutex<VecDeque<Make>>,
    sent: AtomicUsize,
    served: Arc<AtomicU64>,
}

impl std::fmt::Debug for Wired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wired").finish_non_exhaustive()
    }
}

impl Wired {
    /// A signed-in account whose plan requests go to the returned transport.
    pub fn desk() -> (Arc<Self>, Client, AccountId, FakeClock) {
        let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
        let provider = FakeProvider::with_clock(&clock);
        let wired = Arc::new(Self {
            provider: provider.clone(),
            answers: Mutex::new(VecDeque::new()),
            sent: AtomicUsize::new(0),
            served: Arc::new(AtomicU64::new(0)),
        });
        let client = Desk::client_over(Arc::clone(&wired), &clock);
        let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
        (wired, client, id, clock)
    }

    /// Queues the answer to the next plan request.
    pub fn answer(&self, make: impl FnOnce(&str) -> StreamingResponse + Send + 'static) {
        self.answers.lock().unwrap().push_back(Box::new(make));
    }

    /// A body of `bytes` that ends cleanly and counts what is read of it.
    pub fn body(&self, bytes: impl Into<Vec<u8>>) -> Counted {
        Counted {
            bytes: bytes.into(),
            at: 0,
            served: Arc::clone(&self.served),
        }
    }

    /// How many plan requests were sent.
    pub fn sent(&self) -> usize {
        self.sent.load(Ordering::SeqCst)
    }

    /// How many body bytes were read, over all answers.
    pub fn served(&self) -> u64 {
        self.served.load(Ordering::SeqCst)
    }
}

impl Transport for Wired {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.provider.send(request)
    }

    fn send_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<StreamingResponse, Error> {
        if request.url() != siwc::plan::RESPONSES_URL {
            return self.provider.send_streaming(request, canceller);
        }
        self.sent.fetch_add(1, Ordering::SeqCst);
        let token = request
            .headers()
            .find(|(name, _)| *name == "authorization")
            .and_then(|(_, value)| value.strip_prefix("Bearer "))
            .unwrap();
        let make = self.answers.lock().unwrap().pop_front();
        Ok(make.expect("an answer was queued")(token))
    }
}

/// The bytes of a body, and a count of how many were read.
pub struct Counted {
    bytes: Vec<u8>,
    at: usize,
    served: Arc<AtomicU64>,
}

impl Counted {
    /// Replaces the bytes, for a body that depends on the request.
    pub fn fill(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }
}

impl Read for Counted {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let rest = &self.bytes[self.at..];
        let count = rest.len().min(buffer.len());
        buffer[..count].copy_from_slice(&rest[..count]);
        self.at += count;
        self.served.fetch_add(count as u64, Ordering::SeqCst);
        Ok(count)
    }
}

/// One event frame with this JSON.
pub fn frame(json: &str) -> Vec<u8> {
    format!("data: {json}\n\n").into_bytes()
}

/// The two events an answer opens with.
pub fn opening() -> Vec<u8> {
    [
        frame(r#"{"type":"response.created"}"#),
        frame(r#"{"type":"response.in_progress"}"#),
    ]
    .concat()
}

pub fn delta(text: &str) -> Vec<u8> {
    frame(&format!(
        r#"{{"type":"response.output_text.delta","delta":"{text}"}}"#
    ))
}

pub fn completed() -> Vec<u8> {
    frame(r#"{"type":"response.completed"}"#)
}
