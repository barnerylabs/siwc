//! The stream over transports of the app's own: one that only buffers, and
//! one whose answer never ends.

use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use siwc::protocol::{HttpRequest, HttpResponse, StreamingResponse};
use siwc::testing::{FakeClock, FakeProvider, FakeResponse, FakeUser};
use siwc::{Canceller, Error, ErrorKind, Transport, UnixTime};

use super::{BUSY, Desk, request, sign_in};

/// A transport written before `send_streaming` existed: it only buffers.
#[derive(Debug)]
struct BufferedOnly(FakeProvider);

impl Transport for BufferedOnly {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.0.send(request)
    }
}

#[test]
fn the_buffered_stream_honours_cancellation_before_the_first_write() {
    #[derive(Debug)]
    struct CancelDuringSetup(FakeProvider, Canceller);

    impl Transport for CancelDuringSetup {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
            if request.url() == siwc::plan::RESPONSES_URL {
                self.1.cancel();
            }
            self.0.send(request)
        }

        fn send_cancellable(
            &self,
            request: &HttpRequest,
            stop: &Canceller,
        ) -> Result<HttpResponse, Error> {
            self.1.cancel();
            self.0.send_cancellable(request, stop)
        }
    }

    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let stop = Canceller::new();
    let client = Desk::client_over(CancelDuringSetup(provider.clone(), stop.clone()), &clock);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    let error = client
        .stream_response_cancellable(&id, &request(), &stop)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(provider.plan_requests().len(), 0);
}

#[test]
fn a_transport_without_streaming_answers_through_its_buffered_send() {
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let client = Desk::client_over(BufferedOnly(provider.clone()), &clock);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));

    provider.push_response(FakeResponse::refusal(503, BUSY));
    provider.push_response(FakeResponse::text(&["All ", "at once."]));
    let stream = client.stream_response(&id, &request()).unwrap();
    assert!(stream.request_id().is_some());
    assert_eq!(stream.into_text().unwrap(), "All at once.");
    assert_eq!(provider.plan_requests().len(), 2);

    // The wait the API asks for arrives through the buffered answer too.
    provider.push_response(FakeResponse::refusal(503, BUSY).retry_after(7));
    provider.push_response(FakeResponse::text(&["Later."]));
    let stream = client.stream_response(&id, &request()).unwrap();
    assert_eq!(stream.into_text().unwrap(), "Later.");
    assert_eq!(clock.sleeps().last(), Some(&Duration::from_secs(7)));
    let sent = provider.plan_requests().len();
    let waits = clock.sleeps().len();
    provider.push_response(FakeResponse::refusal(503, BUSY).retry_after(31));
    let error = client.stream_response(&id, &request()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert_eq!(provider.plan_requests().len(), sent + 1);
    assert_eq!(clock.sleeps().len(), waits);

    // A body that breaks never arrives whole: no answer, and no retry.
    provider.push_response(FakeResponse::stream().created().delta("Half").interrupted());
    let error = client.stream_response(&id, &request()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert_eq!(provider.plan_requests().len(), sent + 2);
}

/// One `response.output_text.delta` frame of the endless answer below.
const DELTA: &[u8] =
    b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"0123456789\"}\n\n";

/// An answer that never ends, and how many of its bytes were read so far.
struct EndlessAnswer {
    at: usize,
    served: Arc<AtomicU64>,
    /// Whether a read fills its whole buffer, with as many frames as fit,
    /// or brings the rest of one frame.
    whole_reads: bool,
}

impl Read for EndlessAnswer {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut filled = 0;
        while filled < buffer.len() {
            let rest = &DELTA[self.at..];
            let count = rest.len().min(buffer.len() - filled);
            buffer[filled..filled + count].copy_from_slice(&rest[..count]);
            self.at = (self.at + count) % DELTA.len();
            filled += count;
            if !self.whole_reads {
                break;
            }
        }
        self.served.fetch_add(filled as u64, Ordering::SeqCst);
        Ok(filled)
    }
}

/// Sends plan requests to an endless answer and everything else to the
/// fake provider.
#[derive(Debug)]
pub struct Endless {
    pub provider: FakeProvider,
    pub served: Arc<AtomicU64>,
    /// Whether one read brings as many events as fit into it.
    pub whole_reads: bool,
}

impl Transport for Endless {
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
        let answer = EndlessAnswer {
            at: 0,
            served: Arc::clone(&self.served),
            whole_reads: self.whole_reads,
        };
        Ok(StreamingResponse::new(200, answer))
    }
}

/// The length of one frame of the endless answer.
pub fn endless_frame_len() -> u64 {
    DELTA.len() as u64
}

#[test]
fn an_answer_of_any_length_is_read_one_piece_ahead_of_the_events_handed_out() {
    // A transport that brings one frame with each read, and one that
    // fills every read with as many frames as fit.
    for whole_reads in [false, true] {
        let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
        let provider = FakeProvider::with_clock(&clock);
        let served = Arc::new(AtomicU64::new(0));
        let transport = Endless {
            provider: provider.clone(),
            served: Arc::clone(&served),
            whole_reads,
        };
        let client = Desk::client_over(transport, &clock);
        let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));

        // 300 000 events, about 20 MiB of answer.
        let mut stream = client.stream_response(&id, &request()).unwrap();
        let frame = endless_frame_len();
        let mut reads_ahead = 0;
        for handed_out in 1..=300_000_u64 {
            let before = served.load(Ordering::SeqCst);
            let event = stream.next().unwrap().unwrap();
            assert_eq!(event.text_delta(), Some("0123456789"));
            // The stream holds what one read of 8 KiB brought and nothing
            // more, so it cannot grow with the answer.
            let now = served.load(Ordering::SeqCst);
            let ahead = now - handed_out * frame;
            assert!(ahead <= 8 * 1024, "{ahead} bytes ahead at {handed_out}");
            // And it reads again only when it has no event left to hand
            // out: what was read before this one was less than its end.
            if now > before {
                assert!(before < handed_out * frame, "read early at {handed_out}");
            }
            if ahead >= frame {
                reads_ahead += 1;
            }
        }
        // With whole reads, events do wait in the stream: about 122 of
        // these frames fit into one read.
        assert_eq!(reads_ahead > 0, whole_reads);
    }
}

/// One plan request as the transport saw it.
#[derive(Debug)]
struct Sent {
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Notes where each request goes and which headers it carries.
#[derive(Debug)]
struct Wire {
    provider: FakeProvider,
    seen: Mutex<Vec<Sent>>,
}

impl Transport for Wire {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.provider.send(request)
    }

    fn send_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<StreamingResponse, Error> {
        let headers = request
            .headers()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect();
        self.seen.lock().unwrap().push(Sent {
            url: request.url().to_owned(),
            headers,
            body: request.body().to_vec(),
        });
        self.provider.send_streaming(request, canceller)
    }
}

#[test]
fn every_attempt_goes_to_the_one_address_with_the_token_in_its_header_only() {
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let wire = Arc::new(Wire {
        provider: provider.clone(),
        seen: Mutex::new(Vec::new()),
    });
    let client = Desk::client_over(Arc::clone(&wire), &clock);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    let first = client.access_token(&id).unwrap().expose().to_owned();

    // Busy, then a refused token, then the answer: three attempts.
    provider.push_response(FakeResponse::refusal(503, BUSY));
    provider.push_response(FakeResponse::refusal(
        401,
        "subscription_sharing_invalid_user",
    ));
    provider.push_response(FakeResponse::text(&["Hello"]));
    let stream = client.stream_response(&id, &request()).unwrap();
    assert_eq!(stream.into_text().unwrap(), "Hello");
    let renewed = client.access_token(&id).unwrap().expose().to_owned();
    assert_ne!(renewed, first);

    let seen = wire.seen.lock().unwrap();
    let tokens = [&first, &first, &renewed];
    assert_eq!(seen.len(), tokens.len());
    for (Sent { url, headers, body }, token) in seen.iter().zip(tokens) {
        assert_eq!(url, siwc::plan::RESPONSES_URL);
        assert_eq!(url, "https://api.openai.com/v1/responses");
        let expected = [
            ("accept", "text/event-stream".to_owned()),
            ("content-type", "application/json".to_owned()),
            ("authorization", format!("Bearer {token}")),
        ];
        let headers: Vec<_> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.clone()))
            .collect();
        assert_eq!(headers, expected);
        let body = String::from_utf8(body.clone()).unwrap();
        assert!(!body.contains(token.as_str()));
        assert!(body.contains(r#""store":false"#));
        assert!(body.contains(r#""stream":true"#));
    }
}
