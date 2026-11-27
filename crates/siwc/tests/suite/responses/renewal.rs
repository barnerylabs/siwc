//! Cancellation at the token endpoint, before the first plan request or on a retry.

use std::time::Duration;

use siwc::protocol::{HttpRequest, HttpResponse};
use siwc::testing::{FakeClock, FakeProvider, FakeResponse, FakeUser};
use siwc::{Canceller, Error, ErrorKind, Transport, UnixTime};

use super::{Desk, INVALID_USER, block_on, request, sign_in};

#[derive(Debug)]
struct FailedRenewal {
    provider: FakeProvider,
    stop: Canceller,
}

impl Transport for FailedRenewal {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        if request.body().starts_with(b"grant_type=refresh_token&") {
            self.provider
                .fail_next_request(503, Some("temporarily_unavailable"));
            let answer = self.provider.send(request);
            self.stop.cancel();
            answer
        } else {
            self.provider.send(request)
        }
    }
}

#[test]
fn cancellation_outweighs_a_failed_renewal_on_both_streams() {
    let mut outcomes = Vec::new();
    for asynchronous in [false, true] {
        for refusal in [None, Some(FakeResponse::refusal(401, INVALID_USER))] {
            let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
            let provider = FakeProvider::with_clock(&clock);
            let stop = Canceller::new();
            let transport = FailedRenewal {
                provider: provider.clone(),
                stop: stop.clone(),
            };
            let client = Desk::client_over(transport, &clock);
            let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
            let expected_posts = usize::from(refusal.is_some());
            if let Some(refusal) = refusal {
                provider.push_response(refusal);
            } else {
                clock.advance(Duration::from_secs(3600));
            }
            let request = request();
            let result = if asynchronous {
                block_on(async {
                    client
                        .stream_response_async_cancellable(&id, &request, &stop)
                        .await?
                        .into_text()
                        .await
                })
            } else {
                client
                    .stream_response_cancellable(&id, &request, &stop)
                    .and_then(siwc::ResponseStream::into_text)
            };
            assert!(stop.is_cancelled());
            assert_eq!(provider.plan_requests().len(), expected_posts);
            outcomes.push(result.unwrap_err().kind());
        }
    }
    assert_eq!(outcomes, [ErrorKind::Cancelled; 4]);
}

#[test]
fn an_async_renewal_finishes_before_opening_reports_cancellation() {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::{Mutex, mpsc};
    use std::task::{Context, Waker};

    #[derive(Debug)]
    struct PausedRenewal {
        provider: FakeProvider,
        rotated: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl Transport for PausedRenewal {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
            let answer = self.provider.send(request);
            if request.body().starts_with(b"grant_type=refresh_token&") {
                self.rotated.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(3))
                    .unwrap();
            }
            answer
        }
    }

    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let (rotated, sent) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let transport = PausedRenewal {
        provider: provider.clone(),
        rotated,
        release: Mutex::new(gate),
    };
    let client = Desk::client_over(transport, &clock);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    let original = client.access_token(&id).unwrap();
    let stop = Canceller::new();
    provider.push_response(FakeResponse::refusal(401, INVALID_USER));
    let request = request();
    let mut opening = pin!(client.stream_response_async_cancellable(&id, &request, &stop));
    let mut context = Context::from_waker(Waker::noop());
    assert!(opening.as_mut().poll(&mut context).is_pending());
    sent.recv_timeout(Duration::from_secs(3)).unwrap();
    stop.cancel();
    let pending = opening.as_mut().poll(&mut context).is_pending();
    release.send(()).unwrap();
    assert!(
        pending,
        "the provider rotated but the successor has not reached the store"
    );
    assert_eq!(block_on(opening).unwrap_err().kind(), ErrorKind::Cancelled);
    assert_ne!(
        client.access_token(&id).unwrap().expose(),
        original.expose()
    );
    assert_eq!(provider.plan_requests().len(), 1);
}
