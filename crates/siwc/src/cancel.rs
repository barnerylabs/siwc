//! Cooperative cancellation across threads for browser waits and retry sleeps.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

/// Stops a [`Waiting::wait`](crate::loopback::Waiting::wait), a
/// [`SignIn`](crate::SignIn) or a
/// [`Client::call_cancellable`](crate::Client::call_cancellable) /
/// [`Client::call_async_cancellable`](crate::Client::call_async_cancellable)
/// retry wait from another thread.
///
/// Clones share the same state: calling [`cancel`](Self::cancel) on any clone
/// cancels all of them and wakes any thread waiting in
/// [`Client::call_cancellable`](crate::Client::call_cancellable) or
/// [`Client::call_async_cancellable`](crate::Client::call_async_cancellable)
/// at once, as far as the client's [`Clock`](crate::Clock) supports it.
///
/// ```
/// let canceller = siwc::Canceller::new();
/// let stop = canceller.clone();
/// stop.cancel();
/// assert!(canceller.is_cancelled());
/// ```
#[derive(Clone)]
pub struct Canceller {
    inner: Arc<Inner>,
}

struct Inner {
    cancelled: AtomicBool,
    wake_lock: Mutex<Vec<Weak<Inner>>>,
    wake: Condvar,
    /// Who is told of a cancellation, besides the children.
    told: Mutex<Vec<Weak<dyn OnCancel>>>,
}

/// Something that holds what a cancelled operation must let go of at
/// once, whether or not a thread of that operation is still there to
/// notice.
///
/// Kept crate-private on purpose: a public cancellation hook for
/// transports would be a narrow API of its own.
pub(crate) trait OnCancel: Send + Sync {
    /// Runs once, on the thread that cancels or, for a canceller that was
    /// triggered before, on the one that registers.
    fn cancelled(&self);
}

impl Canceller {
    /// A fresh canceller that has not been triggered.
    #[must_use]
    pub fn new() -> Self {
        Self::unshared()
    }

    /// Fresh canceller.
    pub(crate) fn unshared() -> Self {
        Self {
            inner: Arc::new(Inner {
                cancelled: AtomicBool::new(false),
                wake_lock: Mutex::new(Vec::new()),
                wake: Condvar::new(),
                told: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Has `listener` told when this canceller is triggered, or now if it
    /// was already. Only a weak reference is kept.
    pub(crate) fn tell(&self, listener: Weak<dyn OnCancel>) {
        let mut told = self
            .inner
            .told
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // `cancel` takes the list under this lock after it set the state:
        // a listener is either in the list it takes or sees the state here.
        if self.is_cancelled() {
            drop(told);
            if let Some(listener) = listener.upgrade() {
                listener.cancelled();
            }
        } else {
            told.retain(|known| known.strong_count() > 0);
            told.push(listener);
        }
    }

    /// Creates a child canceller that cancels automatically when `self` is
    /// cancelled, while cancelling the child leaves `self` untouched.
    pub(crate) fn child(&self) -> Self {
        let child = Self::unshared();
        let mut guard = self
            .inner
            .wake_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        guard.retain(|weak| weak.strong_count() > 0);
        if self.is_cancelled() {
            drop(guard);
            child.cancel();
        } else {
            guard.push(Arc::downgrade(&child.inner));
        }
        child
    }

    /// Cancels the operation.
    ///
    /// Ends a loopback wait with
    /// [`ErrorKind::Cancelled`](crate::ErrorKind::Cancelled) within a few
    /// milliseconds (or at once before it begins), wakes an active retry wait
    /// in [`Client::call_cancellable`](crate::Client::call_cancellable)
    /// immediately with [`SystemClock`](crate::SystemClock) (another
    /// [`Clock`](crate::Clock) notices it after its `sleep`), and stops a
    /// [`SignIn::finish`](crate::SignIn::finish) unless its final store
    /// commit has already begun.
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            // Acquire and drop `wake_lock` before notifying so a thread checking
            // `is_cancelled()` under `wake_lock` never misses the wakeup.
            let children = {
                let mut guard = self
                    .inner
                    .wake_lock
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                std::mem::take(&mut *guard)
            };
            self.inner.wake.notify_all();
            for weak in children {
                if let Some(inner) = weak.upgrade() {
                    Self { inner }.cancel();
                }
            }
            let told = {
                let mut guard = self
                    .inner
                    .told
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                std::mem::take(&mut *guard)
            };
            // Outside the lock: a listener takes locks of its own.
            for listener in told.iter().filter_map(Weak::upgrade) {
                listener.cancelled();
            }
        }
    }

    /// Whether [`cancel`](Self::cancel) was called on this handle or a clone.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Waits up to `duration`, returning `false` as soon as [`cancel`](Self::cancel)
    /// is triggered and `true` if the full duration elapsed without cancellation.
    pub(crate) fn wait(&self, duration: Duration) -> bool {
        if self.is_cancelled() {
            return false;
        }
        if duration.is_zero() {
            return !self.is_cancelled();
        }
        let deadline = Instant::now().checked_add(duration);
        let mut guard = self
            .inner
            .wake_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        loop {
            if self.is_cancelled() {
                return false;
            }
            match deadline {
                Some(deadline) => {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        return true;
                    };
                    if remaining.is_zero() {
                        return true;
                    }
                    let (next_guard, timeout) = self
                        .inner
                        .wake
                        .wait_timeout(guard, remaining)
                        .unwrap_or_else(PoisonError::into_inner);
                    guard = next_guard;
                    if timeout.timed_out() {
                        return !self.is_cancelled();
                    }
                }
                None => {
                    guard = self
                        .inner
                        .wake
                        .wait(guard)
                        .unwrap_or_else(PoisonError::into_inner);
                }
            }
        }
    }
}

impl Default for Canceller {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Canceller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Canceller").finish_non_exhaustive()
    }
}
