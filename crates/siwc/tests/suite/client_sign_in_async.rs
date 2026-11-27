//! Cancellation when the executor drops a running browser sign-in.

use std::future::Future;
use std::sync::mpsc;
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use siwc::ErrorKind;

use crate::support::browser::{Browser, PATIENCE};
use crate::support::executor::waker;
use crate::support::provider::User;
use crate::support::rig::Rig;

#[test]
fn dropping_finish_async_cancels_the_browser_wait_and_releases_the_client() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    let stop = sign_in.canceller();
    let mut finish = Box::pin(sign_in.finish_async(PATIENCE));
    let mut context = Context::from_waker(Waker::noop());
    assert!(finish.as_mut().poll(&mut context).is_pending());
    drop(finish);

    let cancelled_by_drop = stop.is_cancelled();
    // Release the thread even when the assertion below is red.
    stop.cancel();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match rig.client.add_account() {
            Ok(restarted) => {
                drop(restarted);
                break;
            }
            Err(error) => assert_eq!(error.kind(), ErrorKind::SignInInProgress),
        }
        assert!(
            Instant::now() < deadline,
            "the cancelled listener still holds the client"
        );
        thread::yield_now();
    }
    assert!(rig.client.accounts().unwrap().is_empty());
    assert!(cancelled_by_drop);
}

#[test]
fn dropping_finish_async_after_the_worker_completed_does_not_cancel() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    let browser = Browser::new(sign_in.start_link());
    let stop = sign_in.canceller();
    let mut finish = Box::pin(sign_in.finish_async(PATIENCE));
    let (waker, wakes) = waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(finish.as_mut().poll(&mut context), Poll::Pending));

    assert_eq!(browser.approve(&rig.provider, &User::alex()).status, 200);
    wakes.recv_timeout(PATIENCE).unwrap();
    drop(finish);

    assert!(!stop.is_cancelled());
    assert_eq!(rig.client.accounts().unwrap().len(), 1);
}

#[test]
fn dropping_finish_async_during_exchange_prevents_storing_the_account() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    let browser = Browser::new(sign_in.start_link());
    let (reached, at_exchange) = mpsc::channel();
    let (release, can_finish) = mpsc::channel();
    rig.provider.alter_next_response(move |_| {
        reached.send(()).unwrap();
        can_finish.recv_timeout(PATIENCE).unwrap();
    });
    let mut finish = Box::pin(sign_in.finish_async(PATIENCE));
    let mut context = Context::from_waker(Waker::noop());
    assert!(finish.as_mut().poll(&mut context).is_pending());
    let provider = rig.provider.clone();
    let tab = thread::spawn(move || browser.approve(&provider, &User::alex()));

    at_exchange.recv_timeout(PATIENCE).unwrap();
    drop(finish);
    release.send(()).unwrap();
    assert_eq!(tab.join().unwrap().heading(), "Sign-in did not complete");
    assert!(rig.client.accounts().unwrap().is_empty());
    assert_eq!(rig.journal.count("send revoke"), 1);
}
