//! Stops ureq's internal read loop when body bytes make no decoded progress.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, DefaultConnector, NextTimeout, Transport,
};

use crate::cancel::Canceller;
use crate::error::ErrorCause;

const MAX_RAW_PER_READ: usize = 64 * 1024;

pub(super) struct StreamGuard {
    stop: Option<Canceller>,
    active: AtomicBool,
    raw: AtomicUsize,
    refusal_until: OnceLock<Instant>,
}

impl fmt::Debug for StreamGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamGuard")
    }
}

impl StreamGuard {
    pub(super) fn new(stop: Option<Canceller>) -> Self {
        Self {
            stop,
            active: AtomicBool::new(false),
            raw: AtomicUsize::new(0),
            refusal_until: OnceLock::new(),
        }
    }

    pub(super) fn start(&self) {
        self.active.store(true, Ordering::Release);
    }

    pub(super) fn refusal_deadline(&self, timeout: Duration) {
        if let Some(until) = Instant::now().checked_add(timeout) {
            let _ = self.refusal_until.set(until);
        }
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.stop.as_ref().is_some_and(Canceller::is_cancelled)
    }

    pub(super) fn begin_read(&self) -> Result<(), ureq::Error> {
        self.raw.store(0, Ordering::Release);
        self.check()
    }

    pub(super) fn check(&self) -> Result<(), ureq::Error> {
        if !self.active.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.is_cancelled() {
            // Not `Interrupted`: the standard library's read helpers retry
            // that kind and would spin on a cancelled stream.
            return Err(io_error(io::ErrorKind::ConnectionAborted));
        }
        if self
            .refusal_until
            .get()
            .is_some_and(|until| Instant::now() >= *until)
        {
            return Err(io_error(io::ErrorKind::TimedOut));
        }
        if self.raw.load(Ordering::Acquire) > MAX_RAW_PER_READ {
            // The cause `Https` names for trailers beyond its budget.
            return Err(ureq::Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                ErrorCause::ResponseTooLarge,
            )));
        }
        Ok(())
    }

    fn read_raw(&self, bytes: usize) -> Result<(), ureq::Error> {
        self.raw.fetch_add(bytes, Ordering::AcqRel);
        self.check()
    }
}

fn io_error(kind: io::ErrorKind) -> ureq::Error {
    ureq::Error::Io(io::Error::new(kind, "stream read stopped"))
}

#[derive(Debug)]
pub(super) struct GuardConnector {
    inner: DefaultConnector,
    guard: Arc<StreamGuard>,
}

impl GuardConnector {
    pub(super) fn new(guard: Arc<StreamGuard>) -> Self {
        Self {
            inner: DefaultConnector::new(),
            guard,
        }
    }
}

impl Connector<()> for GuardConnector {
    type Out = GuardedTransport;

    fn connect(
        &self,
        details: &ConnectionDetails<'_>,
        chained: Option<()>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        Ok(self
            .inner
            .connect(details, chained)?
            .map(|inner| GuardedTransport {
                inner,
                guard: Arc::clone(&self.guard),
            }))
    }
}

#[derive(Debug)]
pub(super) struct GuardedTransport {
    inner: Box<dyn Transport>,
    guard: Arc<StreamGuard>,
}

impl Transport for GuardedTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.inner.buffers()
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.inner.transmit_output(amount, timeout)
    }

    fn maybe_await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.guard.check()?;
        if self.inner.buffers().can_use_input() {
            return Ok(true);
        }
        self.await_input(timeout)
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.guard.check()?;
        let before = self.inner.buffers().input().len();
        let result = self.inner.await_input(timeout)?;
        let after = self.inner.buffers().input().len();
        self.guard.read_raw(after.saturating_sub(before))?;
        Ok(result)
    }

    fn is_open(&mut self) -> bool {
        self.inner.is_open()
    }

    fn is_tls(&self) -> bool {
        self.inner.is_tls()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoded_read_budget_counts_raw_bytes_and_reports_its_cause() {
        let guard = StreamGuard::new(None);
        guard.start();
        guard.read_raw(MAX_RAW_PER_READ).unwrap();
        assert!(
            matches!(guard.read_raw(1), Err(ureq::Error::Io(e)) if e.kind() == io::ErrorKind::InvalidData
                && e.get_ref().and_then(|inner| inner.downcast_ref::<ErrorCause>())
                    == Some(&ErrorCause::ResponseTooLarge))
        );
        guard.begin_read().unwrap();
        assert!(guard.read_raw(1).is_ok());
    }
}
