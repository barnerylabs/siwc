//! `Client::stream_response_async`: the same answers for async code, read
//! on a thread of the stream's own, and what dropping a stream ends.

use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use siwc::protocol::{HttpRequest, HttpResponse, StreamingResponse};
use siwc::store::MemoryStore;
use siwc::testing::{FakeClock, FakeProvider, FakeResponse, FakeUser};
use siwc::{AppName, Canceller, Client, Clock, Error, ErrorKind, Transport, UnixTime};

use crate::support::executor::{block_on, waker};

use super::async_end::ThreadEnds;
use super::transport::{Endless, endless_frame_len};
use super::{BUSY, Desk, LIMIT, request, sign_in};

/// Longer than anything here takes; reached only when a test fails.
const PATIENCE: Duration = Duration::from_secs(30);

#[test]
fn the_async_stream_hands_out_the_same_events_and_ends_after_completed() {
    let desk = Desk::new();
    desk.provider
        .push_response(FakeResponse::text(&["The sky ", "is blue."]));
    block_on(async {
        let mut stream = desk
            .client
            .stream_response_async(&desk.id, &request())
            .await
            .unwrap();
        assert!(stream.request_id().unwrap().starts_with("req_fake_"));
        let mut kinds = Vec::new();
        let mut text = String::new();
        while let Some(event) = stream.next().await {
            let event = event.unwrap();
            kinds.push(event.event_type().unwrap().to_owned());
            text.push_str(event.text_delta().unwrap_or_default());
        }
        assert_eq!(
            kinds,
            [
                "response.created",
                "response.in_progress",
                "response.output_text.delta",
                "response.output_text.delta",
                "response.completed",
            ]
        );
        assert_eq!(text, "The sky is blue.");
        // The stream stays ended.
        assert!(stream.next().await.is_none());
    });

    desk.provider.push_response(FakeResponse::text(&["Again."]));
    let whole = block_on(async {
        let stream = desk
            .client
            .stream_response_async(&desk.id, &request())
            .await?;
        stream.into_text().await
    });
    assert_eq!(whole.unwrap(), "Again.");
}

#[test]
fn the_async_stream_follows_the_rules_of_the_blocking_one() {
    let desk = Desk::new();
    // Busy once before the answer: sent again after a wait.
    desk.provider
        .push_response(FakeResponse::refusal(503, BUSY));
    desk.provider.push_response(
        FakeResponse::stream()
            .created()
            .delta("Once upon")
            .failed(LIMIT),
    );
    block_on(async {
        let mut stream = desk
            .client
            .stream_response_async(&desk.id, &request())
            .await
            .unwrap();
        let mut text = String::new();
        let error = loop {
            match stream.next().await.unwrap() {
                Ok(event) => text.push_str(event.text_delta().unwrap_or_default()),
                Err(error) => break error,
            }
        };
        assert_eq!(text, "Once upon");
        // The error is the last item.
        assert_eq!(error.kind(), ErrorKind::UsageLimit);
        assert!(error.request_id().is_some());
        assert!(stream.next().await.is_none());
    });
    assert_eq!(desk.provider.plan_requests().len(), 2);
    assert_eq!(desk.clock.sleeps().len(), 1);

    // A refusal of the request itself is the error of the call.
    desk.provider
        .push_response(FakeResponse::refusal(429, LIMIT));
    let refused = block_on(desk.client.stream_response_async(&desk.id, &request()));
    assert_eq!(refused.unwrap_err().kind(), ErrorKind::UsageLimit);
}

#[test]
fn a_canceller_ends_an_async_stream_that_waits_for_the_next_event() {
    let desk = Desk::new();
    desk.provider
        .push_response(FakeResponse::stream().created().delta("Thinking").hangs());
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

    // Triggered beforehand, nothing is sent.
    let sent = desk.provider.plan_requests().len();
    let refused = block_on(desk.client.stream_response_async_cancellable(
        &desk.id,
        &request(),
        &canceller,
    ));
    assert_eq!(refused.unwrap_err().kind(), ErrorKind::Cancelled);
    assert_eq!(desk.provider.plan_requests().len(), sent);
}

/// The body of an answer that reports when it is dropped: the moment the
/// thread that read it has let go of the connection.
struct Watched<R> {
    body: R,
    dropped: Sender<()>,
}

impl<R: Read> Read for Watched<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.body.read(buffer)
    }
}

impl<R> Drop for Watched<R> {
    fn drop(&mut self) {
        // The test may have ended already.
        let _ = self.dropped.send(());
    }
}

/// Hands every streamed body to the test's watch.
#[derive(Debug)]
struct Watching<T> {
    inner: T,
    dropped: Mutex<Sender<()>>,
}

impl<T: Transport> Transport for Watching<T> {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.inner.send(request)
    }

    fn send_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<StreamingResponse, Error> {
        let answer = self.inner.send_streaming(request, canceller)?;
        let status = answer.status();
        let request_id = answer.request_id().map(str::to_owned);
        let body = Watched {
            body: Whole(answer),
            dropped: self.dropped.lock().unwrap().clone(),
        };
        Ok(StreamingResponse::new(status, body).with_request_id(request_id.as_deref()))
    }
}

/// Reads the body of the answer it owns.
struct Whole(StreamingResponse);

impl Read for Whole {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.body_mut().read(buffer)
    }
}

#[test]
fn cancellation_after_the_async_opening_wake_keeps_the_accepted_request_id() {
    use std::future::Future;
    use std::pin::pin;

    #[derive(Debug)]
    struct GatedHead(FakeProvider, Mutex<mpsc::Receiver<()>>);

    impl Transport for GatedHead {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
            self.0.send(request)
        }

        fn send_streaming(
            &self,
            request: &HttpRequest,
            stop: &Canceller,
        ) -> Result<StreamingResponse, Error> {
            self.1.lock().unwrap().recv_timeout(PATIENCE).unwrap();
            self.0.send_streaming(request, stop)
        }
    }

    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let (release, gate) = mpsc::channel();
    let (dropped, drops) = mpsc::channel();
    let client = Desk::client_over(
        Watching {
            inner: GatedHead(provider.clone(), Mutex::new(gate)),
            dropped: Mutex::new(dropped),
        },
        &clock,
    );
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    provider.push_response(FakeResponse::stream().hangs());

    let stop = Canceller::new();
    let request = request();
    let mut opening = pin!(client.stream_response_async_cancellable(&id, &request, &stop));
    let (waker, wakes) = waker();
    let mut context = Context::from_waker(&waker);
    assert!(opening.as_mut().poll(&mut context).is_pending());
    release.send(()).unwrap();
    // The silent body has nothing to report. This wake publishes the head.
    wakes.recv_timeout(PATIENCE).unwrap();
    stop.cancel();
    let Poll::Ready(Ok(mut stream)) = opening.poll(&mut context) else {
        panic!("the already accepted head must resolve to a stream");
    };
    assert!(stream.request_id().unwrap().starts_with("req_fake_"));
    assert_eq!(
        block_on(stream.next()).unwrap().unwrap_err().kind(),
        ErrorKind::Cancelled
    );
    assert!(block_on(stream.next()).is_none());
    drops.recv_timeout(PATIENCE).unwrap();
    assert_eq!(provider.plan_requests().len(), 1);
}

#[test]
fn dropping_the_async_stream_cancels_the_request_and_ends_its_thread() {
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let (dropped, drops) = mpsc::channel();
    let transport = Watching {
        inner: provider.clone(),
        dropped: Mutex::new(dropped),
    };
    let (transport, ends) = ThreadEnds::watch(transport);
    let client = Desk::client_over(transport, &clock);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));

    // The connection stays open and silent after the first words.
    provider.push_response(FakeResponse::stream().created().delta("Thinking").hangs());
    {
        let mut stream = block_on(client.stream_response_async(&id, &request())).unwrap();
        let (waker, wakes) = waker();
        let mut context = Context::from_waker(&waker);
        let mut first = String::new();
        while first.is_empty() {
            match stream.poll_next(&mut context) {
                Poll::Ready(event) => {
                    first.push_str(event.unwrap().unwrap().text_delta().unwrap_or_default());
                }
                Poll::Pending => wakes.recv_timeout(PATIENCE).unwrap(),
            }
        }
        // The reading thread now waits on the connection.
        assert!(stream.poll_next(&mut context).is_pending());
        assert!(drops.try_recv().is_err(), "the answer is still being read");
    }
    drops.recv_timeout(PATIENCE).unwrap();
    ends.recv_timeout(Duration::from_secs(3))
        .expect("reader thread must exit");
}

#[test]
fn a_slow_async_reader_slows_the_download_instead_of_filling_memory() {
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let served = Arc::new(AtomicU64::new(0));
    let (dropped, drops) = mpsc::channel();
    let transport = Watching {
        inner: Endless {
            provider: provider.clone(),
            served: Arc::clone(&served),
            whole_reads: false,
        },
        dropped: Mutex::new(dropped),
    };
    let client = Desk::client_over(transport, &clock);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));

    // Each read brings just one frame. The worker makes room before
    // reading it, so queued frames and the one in flight fit in 32 slots.
    let frame = endless_frame_len();
    let ahead_at_most = 32 * frame;
    block_on(async {
        let mut stream = client.stream_response_async(&id, &request()).await.unwrap();
        for handed_out in 1..=2_000_u64 {
            let event = stream.next().await.unwrap().unwrap();
            assert_eq!(event.text_delta(), Some("0123456789"));
            // A reader that takes its time: the thread that downloads gets
            // every chance to run ahead, and does not.
            for _ in 0..50 {
                thread::yield_now();
                let ahead = served.load(Ordering::SeqCst) - handed_out * frame;
                assert!(
                    ahead <= ahead_at_most,
                    "{ahead} bytes ahead at {handed_out}"
                );
            }
        }
        // Dropped mid-answer: the endless download stops.
    });
    drops.recv_timeout(PATIENCE).unwrap();
}

#[test]
fn cancelling_a_paused_stream_drops_its_reader_without_another_read() {
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let (dropped, drops) = mpsc::channel();
    let transport = Watching {
        inner: provider.clone(),
        dropped: Mutex::new(dropped),
    };
    let client = Desk::client_over(transport, &clock);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    for after_output in [false, true] {
        provider.push_response(FakeResponse::stream().delta("One").delta("Two").completed());
        let stop = Canceller::new();
        let mut stream = client
            .stream_response_cancellable(&id, &request(), &stop)
            .unwrap();
        if after_output {
            assert_eq!(stream.next().unwrap().unwrap().text_delta(), Some("One"));
        }
        assert!(drops.try_recv().is_err());
        stop.cancel();
        drops
            .try_recv()
            .expect("cancel must drop the idle reader before it returns");
        assert_eq!(
            stream.next().unwrap().unwrap_err().kind(),
            ErrorKind::Cancelled
        );
        assert!(stream.next().is_none());
    }
}

#[test]
fn dropping_the_blocking_stream_lets_go_of_the_connection() {
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let (dropped, drops) = mpsc::channel();
    let transport = Watching {
        inner: provider.clone(),
        dropped: Mutex::new(dropped),
    };
    let client = Desk::client_over(transport, &clock);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));

    // Dropped in the middle of an answer.
    provider.push_response(FakeResponse::text(&["One", "Two", "Three"]));
    let mut stream = client.stream_response(&id, &request()).unwrap();
    stream.next().unwrap().unwrap();
    assert!(drops.try_recv().is_err(), "the answer is still open");
    drop(stream);
    drops.try_recv().unwrap();

    // A stream that ended lets go at once, before it is dropped.
    provider.push_response(FakeResponse::stream().created().delta("Half").interrupted());
    let mut stream = client.stream_response(&id, &request()).unwrap();
    assert!(stream.by_ref().last().unwrap().is_err());
    drops.try_recv().unwrap();
    drop(stream);
}

#[test]
fn cancelling_ends_the_reader_of_a_full_queue_that_nobody_polls() {
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let (dropped, drops) = mpsc::channel();
    let transport = Watching {
        inner: Endless {
            provider: provider.clone(),
            served: Arc::new(AtomicU64::new(0)),
            whole_reads: false,
        },
        dropped: Mutex::new(dropped),
    };
    let (transport, ends) = ThreadEnds::watch(transport);
    let client = Desk::client_over(transport, &clock);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    let canceller = Canceller::new();
    let mut stream =
        block_on(client.stream_response_async_cancellable(&id, &request(), &canceller)).unwrap();

    // Nobody reads: the queue fills to its 32 events and the thread that
    // reads the answer waits for room.
    let begun = Instant::now();
    while !format!("{stream:?}").contains("waiting_events: 32") {
        assert!(begun.elapsed() < PATIENCE, "{stream:?}");
        thread::yield_now();
    }
    assert!(drops.try_recv().is_err(), "the answer is still open");

    // The stream is neither polled nor dropped; the cancellation alone
    // ends the thread, which lets go of the connection.
    canceller.cancel();
    drops.recv_timeout(PATIENCE).unwrap();
    ends.recv_timeout(Duration::from_secs(3))
        .expect("reader thread must exit");

    // What waited in the queue is gone with it, before anybody asks.
    assert!(
        format!("{stream:?}").contains("waiting_events: 0"),
        "{stream:?}"
    );
    block_on(async {
        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert!(stream.next().await.is_none());
    });
}

#[test]
fn dropping_the_opening_future_during_a_custom_clock_sleep_prevents_a_resend() {
    use std::future::Future;
    use std::task::Waker;

    #[derive(Debug)]
    struct GatedClock {
        sleeping: mpsc::Sender<Duration>,
        release: Mutex<mpsc::Receiver<()>>,
        ended: mpsc::Sender<()>,
    }
    impl Clock for GatedClock {
        fn now(&self) -> UnixTime {
            UnixTime::now()
        }

        fn sleep(&self, wait: Duration) {
            self.sleeping.send(wait).unwrap();
            self.release.lock().unwrap().recv().unwrap();
        }
    }
    impl Drop for GatedClock {
        fn drop(&mut self) {
            let _ = self.ended.send(());
        }
    }

    let provider = FakeProvider::new();
    let (sleeping, waits) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let (ended, finished) = mpsc::channel();
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        MemoryStore::new(),
        provider.transport(),
    )
    .clock(GatedClock {
        sleeping,
        release: Mutex::new(gate),
        ended,
    })
    .build();
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    provider.push_response(FakeResponse::refusal(503, BUSY).retry_after(30));
    provider.push_response(FakeResponse::text(&["never shown"]));

    let request = request();
    let mut opening = Box::pin(client.stream_response_async(&id, &request));
    assert!(
        opening
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let guard = Duration::from_secs(3);
    assert_eq!(waits.recv_timeout(guard).unwrap(), Duration::from_secs(30));
    drop(opening);
    drop(client);
    // Only the worker still owns the clock. A custom sleep can only
    // observe the default cancellation check when it gives control back.
    assert!(matches!(
        finished.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    release.send(()).unwrap();
    finished.recv_timeout(guard).unwrap();
    assert_eq!(provider.plan_requests().len(), 1);
}
