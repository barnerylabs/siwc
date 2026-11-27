//! Deterministic [`Clock`] for application tests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::time::{Clock, UnixTime};

/// A [`Clock`] controlled by a test: clones share the same current time and
/// recorded retry waits.
///
/// Calling [`Clock::sleep`] (such as during [`Client::call`](crate::Client::call)
/// backoff) advances the clock without blocking the thread and appends the
/// requested duration to [`sleeps`](Self::sleeps).
///
/// ```
/// use std::time::Duration;
///
/// use siwc::testing::FakeClock;
/// use siwc::{Clock, UnixTime};
///
/// let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
/// clock.advance(Duration::from_secs(60));
/// assert_eq!(clock.now(), UnixTime::from_secs(1_800_000_060));
/// ```
#[derive(Debug, Clone)]
pub struct FakeClock {
    now: Arc<AtomicU64>,
    sleeps: Arc<Mutex<Vec<Duration>>>,
}

impl FakeClock {
    /// Starts at `now`.
    #[must_use]
    pub fn new(now: UnixTime) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now.as_secs())),
            sleeps: Arc::default(),
        }
    }

    /// Sets the clock to `now`.
    pub fn set(&self, now: UnixTime) {
        self.now.store(now.as_secs(), Ordering::SeqCst);
    }

    /// Moves the clock forward by `duration` (rounded up to whole seconds when
    /// sub-second nanos are non-zero).
    pub fn advance(&self, duration: Duration) {
        let secs = duration
            .as_secs()
            .saturating_add(u64::from(duration.subsec_nanos() > 0));
        let mut current = self.now.load(Ordering::SeqCst);
        while let Err(actual) = self.now.compare_exchange_weak(
            current,
            current.saturating_add(secs),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            current = actual;
        }
    }

    /// Every wait passed to [`Clock::sleep`] so far, oldest first.
    #[must_use]
    pub fn sleeps(&self) -> Vec<Duration> {
        self.sleeps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> UnixTime {
        UnixTime::from_secs(self.now.load(Ordering::SeqCst))
    }

    fn sleep(&self, wait: Duration) {
        self.sleeps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(wait);
        self.advance(wait);
    }
}
