//! The moment by which a whole exchange has to be over, and how long one
//! wait on the way may last.

use std::io;
use std::time::{Duration, Instant};

use crate::cancel::Canceller;

/// The end of an exchange; every connect, read and write gets what is left.
#[derive(Debug, Clone, Copy)]
pub(super) struct Deadline(Instant);

impl Deadline {
    /// `total` from now; `None` if that moment cannot be represented.
    pub(super) fn after(total: Duration) -> Option<Self> {
        Instant::now().checked_add(total).map(Self)
    }

    /// The time left, or a `TimedOut` error once there is none.
    pub(super) fn remaining(self) -> io::Result<Duration> {
        let left = self.0.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(left)
        }
    }
}

/// How long a cancelled wait can go unnoticed: a read, a write or a wait
/// for the resolver wakes this often to look at its canceller.
pub(super) const CANCEL_POLL: Duration = Duration::from_millis(50);

/// Fails once `canceller` is triggered.
pub(super) fn stop_if_cancelled(canceller: Option<&Canceller>) -> io::Result<()> {
    match canceller {
        Some(canceller) if canceller.is_cancelled() => Err(io::ErrorKind::ConnectionAborted.into()),
        _ => Ok(()),
    }
}

/// How long one wait may last: what is left until `deadline`, cut into
/// pieces of [`CANCEL_POLL`] when there is a canceller to look at.
///
/// # Errors
///
/// When the deadline has passed or `canceller` is triggered.
pub(super) fn wait_left(deadline: Deadline, canceller: Option<&Canceller>) -> io::Result<Duration> {
    stop_if_cancelled(canceller)?;
    // Winsock truncates socket timeouts to whole milliseconds (and treats
    // 0 ms as infinite), so a wait is at least 1 ms and its caller loops
    // until the monotonic `Deadline` itself has elapsed.
    let left = deadline.remaining()?.max(Duration::from_millis(1));
    Ok(match canceller {
        Some(_) => left.min(CANCEL_POLL),
        None => left,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deadline_in_the_past_has_no_time_left() {
        let deadline = Deadline::after(Duration::ZERO).unwrap();
        let error = deadline.remaining().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn a_wait_with_a_canceller_is_a_slice_and_a_cancelled_one_is_over() {
        let deadline = Deadline::after(Duration::from_secs(60)).unwrap();
        // Without a canceller the whole rest is one wait.
        assert!(wait_left(deadline, None).unwrap() > Duration::from_secs(59));
        // With one, the wait is cut so that it is looked at in time.
        let canceller = Canceller::new();
        assert_eq!(wait_left(deadline, Some(&canceller)).unwrap(), CANCEL_POLL);
        let soon = Deadline::after(Duration::from_millis(20)).unwrap();
        assert!(wait_left(soon, Some(&canceller)).unwrap() <= Duration::from_millis(20));
        canceller.cancel();
        let error = wait_left(deadline, Some(&canceller)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        // A deadline that passed ends the wait whoever asks.
        let over = Deadline::after(Duration::ZERO).unwrap();
        let error = wait_left(over, Some(&Canceller::new())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn a_future_deadline_hands_out_at_most_its_total() {
        let total = Duration::from_secs(60);
        let left = Deadline::after(total).unwrap().remaining().unwrap();
        assert!(left <= total && !left.is_zero());
    }
}
