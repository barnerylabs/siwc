//! The crate's blocking calls as futures, for apps with an async runtime.
//!
//! Every method of a [`Client`](crate::Client) without `_async` blocks its
//! thread: it reads the store, may renew a token over the network or waits
//! for another process's lock. [`SignIn::finish`](crate::SignIn::finish)
//! waits for the browser for as long as its timeout allows. On an async
//! runtime such a call would hold one of the few executor threads.
//!
//! [`run`] moves the call to a thread of its own and returns a future of
//! its result. It needs no particular runtime: the future wakes the task
//! that awaits it once the result is there, which works with Tokio,
//! async-std, smol or any other executor.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use siwc::background;
//!
//! # async fn example(client: siwc::Client) -> Result<(), siwc::Error> {
//! let sign_in = client.add_account()?;
//! // Keep a canceller: dropping the future does not stop the wait.
//! let canceller = sign_in.canceller();
//! # drop(canceller);
//! let completed = background::run(move || sign_in.finish(Duration::from_secs(300))).await?;
//!
//! let id = completed.account().id().clone();
//! let token = background::run(move || client.access_token(&id)).await?;
//! # drop(token);
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::mem;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread;

/// Blocking work for another thread, as the spawner of
/// [`ClientBuilder::spawner`](crate::ClientBuilder::spawner) receives it.
pub type Job = Box<dyn FnOnce() + Send + 'static>;

/// What puts a [`Job`] on a thread that may block.
pub(crate) type Spawner = dyn Fn(Job) + Send + Sync;

/// Runs `work` on a thread of its own and returns a future of its result.
///
/// The work starts at once, whether or not the future is awaited. Dropping
/// the future does not stop it: the work runs to its end and its result is
/// dropped. To end a waiting sign-in early, keep its
/// [`Canceller`](crate::Canceller) and cancel it.
///
/// A panic in `work` is raised again in the task that awaits the future.
///
/// # Panics
///
/// When the operating system cannot start another thread, as
/// [`std::thread::spawn`] does.
#[expect(
    clippy::expect_used,
    reason = "the standalone infallible API documents a panic on thread creation failure"
)]
pub fn run<T, F>(work: F) -> Background<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    try_run_with(spawn, work).expect("the operating system starts another thread")
}

/// Like [`run`], with the thread `spawner` chooses.
pub(crate) fn run_on<T, F>(spawner: &Spawner, work: F) -> Background<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (job, future) = prepare(work);
    spawner(job);
    future
}

pub(crate) fn try_run_with<T: Send + 'static>(
    start: impl FnOnce(Job) -> std::io::Result<()>,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<Background<T>, crate::Error> {
    let (job, future) = prepare(work);
    start(job).map_err(|_| {
        crate::Error::new(
            crate::ErrorKind::Temporary,
            "no thread could be started for the operation",
        )
    })?;
    Ok(future)
}

fn prepare<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> (Job, Background<T>) {
    let shared = Arc::new(Mutex::new(Slot::Waiting(None)));
    let report = Report(Arc::clone(&shared));
    let job = Box::new(move || report.done(panic::catch_unwind(AssertUnwindSafe(work))));
    (job, Background { shared })
}

pub(crate) fn spawn(job: Job) -> std::io::Result<()> {
    thread::Builder::new()
        .name("siwc-background".to_owned())
        .spawn(job)
        .map(drop)
}

/// The work's side of the slot. A job that a spawner drops without
/// running it reports that as a panic, so the future never waits forever.
struct Report<T>(Arc<Mutex<Slot<T>>>);

impl<T> Report<T> {
    fn done(&self, result: thread::Result<T>) {
        let waiting = mem::replace(&mut *lock(&self.0), Slot::Done(result));
        if let Slot::Waiting(Some(waker)) = waiting {
            waker.wake();
        }
    }
}

impl<T> Drop for Report<T> {
    fn drop(&mut self) {
        let unreported = matches!(*lock(&self.0), Slot::Waiting(_));
        if unreported {
            self.done(Err(Box::new(
                "the spawner dropped the work without running it",
            )));
        }
    }
}

/// The result of [`run`], once its work has ended.
///
/// `Debug` shows only whether the result is there, never the result.
#[must_use = "the work runs anyway; await the future to get its result"]
pub struct Background<T> {
    shared: Arc<Mutex<Slot<T>>>,
}

/// Where the work and the future meet.
enum Slot<T> {
    /// The work runs; the waker of the task that last polled, if any.
    Waiting(Option<Waker>),
    /// The work has ended, with its value or its panic.
    Done(thread::Result<T>),
    /// The future has handed out the result.
    Taken,
}

/// A poisoned lock can only come from a panic in this module's few lines
/// that hold it, which leave the slot whole.
fn lock<T>(shared: &Mutex<Slot<T>>) -> std::sync::MutexGuard<'_, Slot<T>> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<T> Future for Background<T> {
    type Output = T;

    #[expect(
        clippy::panic,
        reason = "polling a future after it was ready is a bug of the caller, which std futures meet with a panic as well"
    )]
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<T> {
        let mut slot = lock(&self.shared);
        match mem::replace(&mut *slot, Slot::Taken) {
            Slot::Waiting(known) => {
                let waker = match known {
                    Some(known) if known.will_wake(context.waker()) => known,
                    _ => context.waker().clone(),
                };
                *slot = Slot::Waiting(Some(waker));
                Poll::Pending
            }
            Slot::Done(Ok(value)) => Poll::Ready(value),
            Slot::Done(Err(payload)) => {
                drop(slot);
                panic::resume_unwind(payload)
            }
            Slot::Taken => panic!("a Background future was polled after it was ready"),
        }
    }
}

impl<T> std::fmt::Debug for Background<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ready = matches!(*lock(&self.shared), Slot::Done(_));
        f.debug_struct("Background")
            .field("ready", &ready)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::pin::pin;

    use super::*;

    #[test]
    fn worker_creation_failure_returns_before_work_starts() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let started = Arc::new(AtomicBool::new(false));
        let observed = started.clone();
        let failed = try_run_with(
            |_| Err(std::io::ErrorKind::WouldBlock.into()),
            move || started.store(true, Ordering::Release),
        );
        assert_eq!(failed.unwrap_err().kind(), crate::ErrorKind::Temporary);
        assert!(!observed.load(Ordering::Acquire));
    }

    #[test]
    fn work_a_spawner_drops_is_a_panic_for_the_awaiting_task_and_never_pending() {
        let dropped = run_on(&|job| drop(job), || 1_u8);
        let mut dropped = pin!(dropped);
        let mut context = Context::from_waker(Waker::noop());
        let polled = panic::catch_unwind(AssertUnwindSafe(|| dropped.as_mut().poll(&mut context)));
        let payload = polled.unwrap_err();
        assert_eq!(
            payload.downcast_ref::<&str>().copied(),
            Some("the spawner dropped the work without running it")
        );
    }

    #[test]
    fn work_a_spawner_runs_at_once_is_ready_at_the_first_poll() {
        let ran = run_on(&|job| job(), || 7_u8);
        let mut ran = pin!(ran);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(ran.as_mut().poll(&mut context), Poll::Ready(7));
    }
}
