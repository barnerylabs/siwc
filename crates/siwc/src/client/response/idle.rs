//! Between calls to next, cancellation owns the right to discard the reader.

use std::sync::{Arc, Mutex, PoisonError};

use crate::cancel::{Canceller, OnCancel};

use super::Reading;

pub(super) struct Idle(Mutex<Option<Reading>>);

impl Idle {
    pub(super) fn new(reading: Reading, stop: &Canceller) -> Arc<Self> {
        let idle = Arc::new(Self(Mutex::new(Some(reading))));
        let listener = Arc::downgrade(&idle);
        stop.tell(listener);
        idle
    }

    /// Move the state out before reading or dropping it. Either can call
    /// back into the canceller through a transport supplied by the app.
    pub(super) fn take(&self) -> Option<Reading> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }

    pub(super) fn park(&self, reading: Reading, stop: &Canceller) {
        let previous = {
            let mut idle = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if stop.is_cancelled() {
                // The listener may already have run during a read. The guard
                // leaves scope before the reader's destructor can run.
                return;
            }
            idle.replace(reading)
        };
        debug_assert!(previous.is_none(), "only the iterator returns a reader");
    }
}

impl OnCancel for Idle {
    fn cancelled(&self) {
        drop(self.take());
    }
}
