//! The smallest executor: polls one future on the calling thread and waits
//! for its waker between polls, as any async runtime would.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

/// Longer than any work in the tests takes; only a future that is never
/// woken waits it out.
const PATIENCE: Duration = Duration::from_secs(30);

/// A waker that reports each wake on a channel.
struct Notify(Sender<()>);

impl Wake for Notify {
    fn wake(self: Arc<Self>) {
        // The receiver may be gone once the test has what it needs.
        let _ = self.0.send(());
    }
}

/// A waker and the channel its wakes arrive on.
pub fn waker() -> (Waker, Receiver<()>) {
    let (sender, wakes) = mpsc::channel();
    (Waker::from(Arc::new(Notify(sender))), wakes)
}

/// Polls `future` to its end, waiting for a wake whenever it is pending.
/// A future that is not woken within 30 seconds fails the test.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let (waker, wakes) = waker();
    let mut context = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
        wakes
            .recv_timeout(PATIENCE)
            .expect("a pending future is woken");
    }
}
