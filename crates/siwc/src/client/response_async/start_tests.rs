//! What happens when the thread that reads an answer cannot be started.

use std::cell::Cell;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use crate::app::AppName;
use crate::cancel::Canceller;
use crate::client::Client;
use crate::error::{Error, ErrorKind};
use crate::plan::ResponseRequest;
use crate::store::MemoryStore;
use crate::testing::{FakeClock, FakeProvider, FakeUser};
use crate::time::UnixTime;

type StartFailure = fn(&Canceller);

thread_local! {
    pub(super) static FAIL_START: Cell<Option<StartFailure>> = const { Cell::new(None) };
}

/// The opening error after one poll, and whether the thread start was attempted.
fn open(
    stop: Option<&Canceller>,
    on_start: StartFailure,
) -> Result<(Option<ErrorKind>, bool), Error> {
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let app = AppName::new("Paste Perfect")?;
    let client = Client::builder(app, MemoryStore::new(), provider.transport())
        .clock(clock)
        .build();
    let mut sign_in = client.add_account_manually()?;
    let user = FakeUser::new("owner@example.invalid");
    let redirect = provider.approve_manual(&sign_in, user)?;
    let id = sign_in.finish(&redirect)?.account().id().clone();
    let request = ResponseRequest::text("example-large", "Why is the sky blue?")?;

    FAIL_START.set(Some(on_start));
    let mut opening = pin!(async {
        match stop {
            Some(stop) => {
                client
                    .stream_response_async_cancellable(&id, &request, stop)
                    .await
            }
            None => client.stream_response_async(&id, &request).await,
        }
    });
    let opened = opening
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()));
    let attempted = FAIL_START.take().is_none();

    assert!(provider.plan_requests().is_empty());
    let kind = match opened {
        Poll::Ready(Err(error)) => Some(error.kind()),
        _ => None,
    };
    Ok((kind, attempted))
}

#[test]
fn a_thread_that_cannot_be_started_is_an_error_and_nothing_is_sent() {
    assert_eq!(
        open(None, |_| {}).unwrap(),
        (Some(ErrorKind::Temporary), true)
    );
}

#[test]
fn a_pre_cancelled_async_stream_starts_no_thread() {
    let stop = Canceller::new();
    stop.cancel();
    assert_eq!(
        open(Some(&stop), |_| {}).unwrap(),
        (Some(ErrorKind::Cancelled), false)
    );
}

#[test]
fn cancellation_during_thread_start_outweighs_a_start_failure() {
    assert_eq!(
        open(None, Canceller::cancel).unwrap(),
        (Some(ErrorKind::Cancelled), true)
    );
}
