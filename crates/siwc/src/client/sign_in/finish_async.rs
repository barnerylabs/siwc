//! Cancellation when the executor drops a running browser sign-in.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::cancel::Canceller;
use crate::error::Error;

use super::{Completed, SignIn};

impl SignIn {
    /// Async counterpart of [`finish`](Self::finish), waiting for the browser
    /// and completing the sign-in on a background thread.
    ///
    /// Dropping the running future requests cancellation. The worker frees
    /// the client for another sign-in when it finishes. The same commit
    /// points as in [`finish`](Self::finish) apply, so a final store update
    /// already in progress can complete. Once the worker has finished,
    /// dropping the future leaves its [`canceller`](Self::canceller) alone.
    ///
    /// # Errors
    ///
    /// As [`finish`](Self::finish). A worker that cannot start returns
    /// [`Temporary`](crate::ErrorKind::Temporary). This consumes the sign-in;
    /// start a new one to try again.
    pub async fn finish_async(self, timeout: Duration) -> Result<Completed, Error> {
        let finished = Arc::new(AtomicBool::new(false));
        let _cancel = CancelOnDrop {
            stop: self.canceller(),
            finished: finished.clone(),
        };
        let client = self.client.clone();
        client
            .background(move || {
                let result = self.finish(timeout);
                // Disarm before publishing the result, even if the caller never
                // polls again to receive it.
                finished.store(true, Ordering::Release);
                result
            })?
            .await
    }
}

struct CancelOnDrop {
    stop: Canceller,
    finished: Arc<AtomicBool>,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.finished.load(Ordering::Acquire) {
            self.stop.cancel();
        }
    }
}
