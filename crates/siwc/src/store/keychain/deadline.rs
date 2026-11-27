//! One budget for preparing and starting a reset under the key lock.

use std::time::{Duration, Instant};

use crate::error::{Error, KeychainTimeout};

// A reset's inventory and all lookups together get half the ordinary
// key-lock patience. A successor still waits if filesystem work runs long.
const RESET_BUDGET: Duration = Duration::from_secs(30);

pub(super) struct ResetDeadline<'a> {
    started: Instant,
    elapsed: &'a dyn Fn(&Instant) -> Duration,
}

impl<'a> ResetDeadline<'a> {
    pub(super) fn new(elapsed: &'a dyn Fn(&Instant) -> Duration) -> Self {
        Self {
            started: Instant::now(),
            elapsed,
        }
    }

    pub(super) fn remaining(&self) -> Result<Duration, Error> {
        let left = RESET_BUDGET.saturating_sub((self.elapsed)(&self.started));
        if left.is_zero() {
            return Err(KeychainTimeout::Reset.into());
        }
        Ok(left)
    }

    pub(super) fn check(&self) -> Result<(), Error> {
        self.remaining().map(|_| ())
    }
}
