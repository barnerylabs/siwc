//! Time as the protocol sees it: whole seconds since the Unix epoch.

use std::fmt;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cancel::Canceller;

/// A point in time in seconds since the Unix epoch.
///
/// Every function that depends on time takes one, so expiry rules can be
/// tested without waiting.
///
/// ```
/// let later = siwc::UnixTime::from_secs(1_800_000_000);
/// assert_eq!(later.as_secs(), 1_800_000_000);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(u64);

impl UnixTime {
    /// A time from seconds since the Unix epoch.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// The current time of the system clock.
    ///
    /// A clock set before 1970 reads as the epoch. No sign-in completes
    /// then, because every ID token looks issued in the future; stored
    /// access tokens look fresh, and the API decides whether they still are.
    #[must_use]
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs()),
        )
    }

    /// Seconds since the Unix epoch.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    pub(crate) const fn plus(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs))
    }
}

/// Where the crate reads the time.
///
/// The parts of the crate that act on their own, such as renewing a token
/// that is about to expire, ask a clock. Apps use [`SystemClock`]; tests
/// pass one they can set.
///
/// **Compatibility:** a release that is not a breaking one adds no required
/// method or supertrait and keeps the trait usable as `dyn Clock`; a new
/// method, such as a monotonic reading, comes with a default.
///
/// ```
/// use siwc::{Clock, SystemClock, UnixTime};
///
/// #[derive(Debug)]
/// struct Frozen(UnixTime);
///
/// impl Clock for Frozen {
///     fn now(&self) -> UnixTime {
///         self.0
///     }
/// }
///
/// let frozen = Frozen(UnixTime::from_secs(1_800_000_000));
/// assert_eq!(frozen.now().as_secs(), 1_800_000_000);
/// assert!(SystemClock.now() > UnixTime::from_secs(0));
/// ```
pub trait Clock: Send + Sync + fmt::Debug {
    /// The current time.
    fn now(&self) -> UnixTime;

    /// Waits `wait` before the crate tries something again, such as
    /// between two attempts of [`Client::call`](crate::Client::call).
    ///
    /// The default sleeps the current thread. A test clock moves its time
    /// on instead, so a test never waits.
    fn sleep(&self, wait: Duration) {
        thread::sleep(wait);
    }

    /// Waits up to `wait`, stopping early when `canceller` is triggered.
    /// Returns `true` when the whole wait elapsed and `false` when cancelled.
    ///
    /// The default checks `canceller` before and after [`sleep`](Self::sleep);
    /// [`SystemClock`] wakes at once when [`Canceller::cancel`] is called.
    fn sleep_cancellable(&self, wait: Duration, canceller: &Canceller) -> bool {
        if canceller.is_cancelled() {
            return false;
        }
        self.sleep(wait);
        !canceller.is_cancelled()
    }
}

impl<T: Clock + ?Sized> Clock for Arc<T> {
    fn now(&self) -> UnixTime {
        (**self).now()
    }

    fn sleep(&self, wait: Duration) {
        (**self).sleep(wait);
    }

    fn sleep_cancellable(&self, wait: Duration, canceller: &Canceller) -> bool {
        (**self).sleep_cancellable(wait, canceller)
    }
}

impl<T: Clock + ?Sized> Clock for Box<T> {
    fn now(&self) -> UnixTime {
        (**self).now()
    }

    fn sleep(&self, wait: Duration) {
        (**self).sleep(wait);
    }

    fn sleep_cancellable(&self, wait: Duration, canceller: &Canceller) -> bool {
        (**self).sleep_cancellable(wait, canceller)
    }
}

/// A stateless handle to the system clock, as [`UnixTime::now`] reads it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixTime {
        UnixTime::now()
    }

    fn sleep_cancellable(&self, wait: Duration, canceller: &Canceller) -> bool {
        canceller.wait(wait)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixedClock(UnixTime);

    impl Clock for FixedClock {
        fn now(&self) -> UnixTime {
            self.0
        }

        fn sleep(&self, _wait: Duration) {}
    }

    #[test]
    fn box_arc_and_system_clock_delegate_time_and_cancellable_sleeps() {
        let base = UnixTime::from_secs(100);
        assert_eq!(base.plus(25).as_secs(), 125);

        let boxed: Box<dyn Clock> = Box::new(FixedClock(base));
        let shared: Arc<dyn Clock> = Arc::new(FixedClock(base));
        assert_eq!(boxed.now(), base);
        assert_eq!(shared.now(), base);

        boxed.sleep(Duration::ZERO);
        shared.sleep(Duration::ZERO);

        let open = Canceller::new();
        assert!(boxed.sleep_cancellable(Duration::ZERO, &open));
        assert!(shared.sleep_cancellable(Duration::ZERO, &open));
        assert!(SystemClock.sleep_cancellable(Duration::ZERO, &open));
        assert!(SystemClock.now().as_secs() > 0);

        open.cancel();
        assert!(!boxed.sleep_cancellable(Duration::from_secs(1), &open));
        assert!(!shared.sleep_cancellable(Duration::from_secs(1), &open));
        assert!(!SystemClock.sleep_cancellable(Duration::from_secs(1), &open));
    }
}
