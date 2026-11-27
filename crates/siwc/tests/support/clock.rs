//! A clock the test sets.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use siwc::{Clock, UnixTime};

/// Shows the time it was last set to; clones share it. Asked to wait, it
/// notes the wait and moves its time on by it, in whole seconds.
#[derive(Debug, Clone)]
pub struct TestClock {
    now: Arc<AtomicU64>,
    waits: Arc<Mutex<Vec<Duration>>>,
}

impl TestClock {
    pub fn new(now: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now)),
            waits: Arc::default(),
        }
    }

    pub fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }

    /// The waits asked for so far, oldest first.
    pub fn waits(&self) -> Vec<Duration> {
        self.waits.lock().unwrap().clone()
    }
}

impl Clock for TestClock {
    fn now(&self) -> UnixTime {
        UnixTime::from_secs(self.now.load(Ordering::SeqCst))
    }

    fn sleep(&self, wait: Duration) {
        self.waits.lock().unwrap().push(wait);
        let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
        self.now.fetch_add(secs, Ordering::SeqCst);
    }
}
