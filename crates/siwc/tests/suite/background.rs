//! The blocking calls as futures, driven by the support executor and by
//! hand-made wakers in place of an async runtime.

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::pin;
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::time::Duration;

use siwc::background;

use crate::support::executor::{block_on, waker};

/// Longer than any work in these tests takes; only a failure waits it out.
const PATIENCE: Duration = Duration::from_secs(30);

#[test]
fn the_task_that_polled_last_is_woken_once_the_work_has_ended() {
    let (go, gate) = mpsc::channel::<()>();
    let mut future = pin!(background::run(move || {
        gate.recv().unwrap();
        7
    }));
    let (first, first_wakes) = waker();
    let (second, second_wakes) = waker();

    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&first))
            .is_pending()
    );
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&second))
            .is_pending()
    );
    go.send(()).unwrap();

    second_wakes.recv_timeout(PATIENCE).unwrap();
    assert!(
        first_wakes.try_recv().is_err(),
        "only the last waker is woken"
    );
    let ready = future.as_mut().poll(&mut Context::from_waker(&second));
    assert_eq!(ready, Poll::Ready(7));
}

#[test]
fn a_panic_in_the_work_is_raised_again_where_the_future_is_awaited() {
    let future = background::run(|| -> u8 { panic::panic_any("the work broke") });
    let payload = panic::catch_unwind(AssertUnwindSafe(|| block_on(future))).unwrap_err();
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"the work broke"));
}

#[test]
fn dropping_the_future_lets_the_work_run_to_its_end() {
    let (go, gate) = mpsc::channel::<()>();
    let (done, finished) = mpsc::channel();
    let future = background::run(move || {
        gate.recv().unwrap();
        done.send("ended").unwrap();
    });
    drop(future);
    go.send(()).unwrap();
    assert_eq!(finished.recv_timeout(PATIENCE), Ok("ended"));
}

#[test]
fn debug_shows_whether_the_result_is_there_but_never_the_result() {
    let (go, gate) = mpsc::channel::<()>();
    let mut future = pin!(background::run(move || {
        gate.recv().unwrap();
        "secret value"
    }));
    let (waker, wakes) = waker();
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert!(format!("{future:?}").contains("ready: false"));

    go.send(()).unwrap();
    wakes.recv_timeout(PATIENCE).unwrap();
    let shown = format!("{future:?}");
    assert!(shown.contains("ready: true"), "{shown}");
    assert!(!shown.contains("secret"), "{shown}");
}

#[test]
fn call_async_renews_rejected_tokens_retries_temporary_refusals_and_cancels_cleanly() {
    use crate::support::provider::User;
    use crate::support::rig::Rig;
    use siwc::plan::Refusal;
    use siwc::{Canceller, Error, ErrorKind};

    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let id = alex.id().clone();
    let client = rig.client.clone();

    let models = block_on(client.models_async(&id)).unwrap();
    assert_eq!(models.len(), 3);

    let first_token = block_on(client.access_token_async(&id)).unwrap();
    let mut seen_tokens = Vec::new();
    let answer = block_on(client.call_async(&id, |token| {
        let recorded = token.expose().to_owned();
        let attempt_num = seen_tokens.len();
        seen_tokens.push(recorded);
        async move {
            Ok::<_, Error>(match attempt_num {
                0 => Err(Refusal::from_response(401, b"").unwrap()),
                1 => Err(Refusal::from_response(503, b"").unwrap()),
                _ => Ok("streamed-ok"),
            })
        }
    }))
    .unwrap();
    assert_eq!(answer, "streamed-ok");
    assert_eq!(seen_tokens.len(), 3);
    assert_eq!(seen_tokens[0], first_token.expose());
    assert_ne!(seen_tokens[1], first_token.expose());
    assert_eq!(seen_tokens[2], seen_tokens[1]);

    let canceller = Canceller::new();
    canceller.cancel();
    let cancelled: Result<&str, Error> = block_on(client.call_async_cancellable(
        &id,
        &canceller,
        |_token| async move { Ok(Ok("unused")) },
    ));
    assert_eq!(cancelled.unwrap_err().kind(), ErrorKind::Cancelled);

    // Retry-After exceeding 30s ends immediately with Temporary instead of sleeping.
    let too_long: Result<&str, Error> = block_on(client.call_async(&id, |_token| async move {
        Ok(Err(Refusal::from_response(503, b"")
            .unwrap()
            .with_retry_after(Some("120"))))
    }));
    assert_eq!(too_long.unwrap_err().kind(), ErrorKind::Temporary);

    // `access_token_after_rejection_async`, `finish_async`, `sign_out_async`,
    // and `forget_async` complete without blocking the caller's executor.
    let current = block_on(client.access_token_async(&id)).unwrap();
    let rotated = block_on(client.access_token_after_rejection_async(&id, &current)).unwrap();
    assert_ne!(rotated.expose(), current.expose());

    let sign_in = client.add_account().unwrap();
    let side = crate::support::browser::Browser::new(sign_in.start_link());
    let provider = std::sync::Arc::clone(&rig.provider);
    let tab = std::thread::spawn(move || side.approve(&provider, &User::sam()));
    let sam = block_on(sign_in.finish_async(PATIENCE))
        .unwrap()
        .into_account();
    assert_eq!(tab.join().unwrap().status, 200);
    let signed_out = block_on(client.sign_out_async(sam.id())).unwrap();
    assert!(signed_out.revocation_confirmed());
    let forgotten = block_on(client.forget_async(sam.id())).unwrap();
    assert!(!forgotten.revocation_confirmed());
    assert_eq!(
        client.account(sam.id()).unwrap_err().kind(),
        ErrorKind::UnknownAccount
    );

    // Dropping a `call_async` future during a `Retry-After` sleep wakes its
    // internal canceller immediately instead of parking a thread for 30s.
    let (entered_sleep, sleeping) = mpsc::channel::<()>();
    let (woke_up, woken) = mpsc::channel::<bool>();
    #[derive(Debug)]
    struct SignallingClock {
        entered: mpsc::Sender<()>,
        woke: mpsc::Sender<bool>,
    }
    impl siwc::Clock for SignallingClock {
        fn now(&self) -> siwc::UnixTime {
            siwc::UnixTime::from_secs(1_700_000_000)
        }
        fn sleep_cancellable(&self, wait: Duration, canceller: &Canceller) -> bool {
            let _ = self.entered.send(());
            let finished = siwc::SystemClock.sleep_cancellable(wait, canceller);
            let _ = self.woke.send(finished);
            finished
        }
    }
    let timed_client = siwc::Client::builder(
        siwc::AppName::new("Paste Perfect").unwrap(),
        rig.store.clone(),
        rig.transport.clone(),
    )
    .clock(SignallingClock {
        entered: entered_sleep,
        woke: woke_up,
    })
    .build();
    {
        let fut = Box::pin(timed_client.call_async(&id, |_tok| async move {
            Ok::<Result<(), Refusal>, Error>(Err(Refusal::from_response(503, b"")
                .unwrap()
                .with_retry_after(Some("25"))))
        }));
        poll_until_sleeping(fut, &sleeping);
    }
    // `fut` is dropped here; `CancelOnDrop` wakes `SystemClock` in milliseconds.
    assert_eq!(woken.recv_timeout(Duration::from_secs(2)), Ok(false));

    // Dropping a `call_async_cancellable` future also wakes the background
    // sleep immediately via its child canceller without marking the caller's
    // parent `Canceller` as cancelled.
    let parent_canceller = Canceller::new();
    {
        let fut = Box::pin(timed_client.call_async_cancellable(
            &id,
            &parent_canceller,
            |_tok| async move {
                Ok::<Result<(), Refusal>, Error>(Err(Refusal::from_response(503, b"")
                    .unwrap()
                    .with_retry_after(Some("25"))))
            },
        ));
        poll_until_sleeping(fut, &sleeping);
    }
    assert_eq!(woken.recv_timeout(Duration::from_secs(2)), Ok(false));
    assert!(!parent_canceller.is_cancelled());
}

/// Polls `fut` until its retry sleep has begun, then returns, dropping it.
///
/// The sleep runs on a background thread that wakes the task only once it
/// ends, so the start of the sleep and a wake are watched together: waiting
/// for a wake alone would sit out the whole `Retry-After` when the sleep
/// starts just after the last check, as on a slow runner.
fn poll_until_sleeping<F: Future>(mut fut: std::pin::Pin<Box<F>>, sleeping: &mpsc::Receiver<()>) {
    let (step_waker, wakes) = waker();
    let deadline = std::time::Instant::now() + PATIENCE;
    loop {
        assert!(
            fut.as_mut()
                .poll(&mut Context::from_waker(&step_waker))
                .is_pending()
        );
        loop {
            if sleeping.try_recv().is_ok() {
                return;
            }
            if wakes.recv_timeout(Duration::from_millis(10)).is_ok() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the call never reached its retry sleep"
            );
        }
    }
}

#[test]
fn call_async_never_sends_a_token_whose_credentials_do_not_grant_plan_use() {
    use crate::support::provider::User;
    use crate::support::rig::Rig;
    use siwc::{Error, ErrorKind};

    let rig = Rig::new();
    let off = rig.add(&User::sam().without_plan_use());
    let mut sent = 0;
    let result: Result<(), Error> = block_on(rig.client.call_async(off.id(), |_token| {
        sent += 1;
        async move { Ok(Ok(())) }
    }));
    assert_eq!(result.unwrap_err().kind(), ErrorKind::PlanUseNotGranted);
    assert_eq!(sent, 0);
}
