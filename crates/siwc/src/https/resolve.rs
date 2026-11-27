//! Looking up a host with the system resolver: a bounded number of
//! lookups at once, each wait ended by the exchange's deadline or its
//! canceller.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Condvar, Mutex, PoisonError, mpsc};
use std::thread;

use crate::cancel::Canceller;

use super::deadline::{Deadline, wait_left};

/// Most system-resolver lookups allowed in flight at once on one [`Https`].
const MAX_IN_FLIGHT: usize = 4;

/// Limits concurrent system DNS lookups, including lookups that outlive
/// their exchange. Each exchange waits only until its own deadline.
#[derive(Clone, Default)]
pub(super) struct Resolver {
    slots: Arc<ResolverSlots>,
}

#[derive(Default)]
struct ResolverSlots {
    in_flight: Mutex<usize>,
    available: Condvar,
}

impl Resolver {
    /// The addresses of `(host, port)` from the system resolver, in its order,
    /// bounded by `deadline`. A triggered `canceller` ends the wait; the
    /// lookup itself runs on, on its own thread, and its result is dropped.
    pub(super) fn resolve(
        &self,
        host: &str,
        port: u16,
        deadline: Deadline,
        canceller: Option<&Canceller>,
    ) -> io::Result<Vec<SocketAddr>> {
        let host = host.to_owned();
        self.resolve_with(deadline, canceller, move || lookup(&host, port))
    }

    fn resolve_with(
        &self,
        deadline: Deadline,
        canceller: Option<&Canceller>,
        lookup: impl FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
    ) -> io::Result<Vec<SocketAddr>> {
        let slot = ResolverSlot::acquire(&self.slots, deadline, canceller)?;
        let (done, result) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("siwc-dns".to_owned())
            .spawn(move || {
                let _slot = slot;
                let _sent = done.send(deadline.remaining().and_then(|_| lookup()));
            })?;
        loop {
            match result.recv_timeout(wait_left(deadline, canceller)?) {
                Ok(resolved) => {
                    deadline.remaining()?;
                    return resolved;
                }
                // Looks at the canceller and the deadline again.
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::ErrorKind::TimedOut.into());
                }
            }
        }
    }
}

/// The system resolver's addresses of `(host, port)`. Its error kind says
/// nothing stable about why a name has no address (an unknown name is
/// `Uncategorized` on Linux), so a failed lookup is `NotFound`, as an empty
/// one is when the connect finds no address to try.
fn lookup(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    match (host, port).to_socket_addrs() {
        Ok(addresses) => Ok(addresses.collect()),
        Err(_) => Err(io::ErrorKind::NotFound.into()),
    }
}

/// Releases one in-flight DNS lookup slot when the helper thread finishes.
struct ResolverSlot(Arc<ResolverSlots>);

impl ResolverSlot {
    fn acquire(
        slots: &Arc<ResolverSlots>,
        deadline: Deadline,
        canceller: Option<&Canceller>,
    ) -> io::Result<Self> {
        let mut active = slots
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        loop {
            let remaining = wait_left(deadline, canceller)?;
            if *active < MAX_IN_FLIGHT {
                *active += 1;
                return Ok(Self(Arc::clone(slots)));
            }
            (active, _) = slots
                .available
                .wait_timeout(active, remaining)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

impl Drop for ResolverSlot {
    fn drop(&mut self) {
        *self
            .0
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner) -= 1;
        // A woken caller might have expired before taking the available slot.
        self.0.available.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::{Duration, Instant};

    use super::super::connect::PORT;
    use super::*;

    const LOCAL: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT));
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    struct PendingLookup {
        started: mpsc::Receiver<()>,
        release: mpsc::Sender<()>,
        result: mpsc::Receiver<io::Result<Vec<SocketAddr>>>,
    }

    fn pending_lookup(resolver: &Resolver, total: Duration) -> PendingLookup {
        cancellable_lookup(resolver, total, None)
    }

    fn cancellable_lookup(
        resolver: &Resolver,
        total: Duration,
        canceller: Option<Canceller>,
    ) -> PendingLookup {
        let resolver = resolver.clone();
        let deadline = Deadline::after(total).unwrap();
        let (started, entered) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (done, result) = mpsc::channel();
        thread::spawn(move || {
            let resolved = resolver.resolve_with(deadline, canceller.as_ref(), move || {
                let _ = started.send(());
                let _ = released.recv();
                Ok(vec![LOCAL])
            });
            let _ = done.send(resolved);
        });
        PendingLookup {
            started: entered,
            release,
            result,
        }
    }

    fn occupy_workers(resolver: &Resolver, total: Duration) -> [PendingLookup; MAX_IN_FLIGHT] {
        let workers = std::array::from_fn(|_| pending_lookup(resolver, total));
        for worker in &workers {
            worker.started.recv_timeout(TEST_TIMEOUT).unwrap();
        }
        workers
    }

    #[test]
    fn a_failed_lookup_is_not_found() {
        // A name the system resolver refuses without asking the network.
        let deadline = Deadline::after(TEST_TIMEOUT).unwrap();
        let error = Resolver::default()
            .resolve("no\0such-host.invalid", PORT, deadline, None)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            crate::transport::cause::of_io(&error),
            crate::error::ErrorCause::Io(io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn a_stalled_lookup_ends_at_the_deadline() {
        let resolver = Resolver::default();
        let total = Duration::from_millis(100);
        let started = Instant::now();
        // The helper thread may start after the deadline and skip the
        // lookup; either way the caller gets `TimedOut`, and a lookup that
        // did start stays blocked until `lookup` is dropped.
        let lookup = pending_lookup(&resolver, total);
        let error = lookup
            .result
            .recv_timeout(TEST_TIMEOUT)
            .unwrap()
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= total);
    }

    #[test]
    fn stalled_lookups_cannot_grow_without_bound_and_release_their_slots() {
        let resolver = Resolver::default();
        let workers = occupy_workers(&resolver, TEST_TIMEOUT);

        let stalled = pending_lookup(&resolver, Duration::from_millis(30));
        let error = stalled
            .result
            .recv_timeout(Duration::from_millis(300))
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            stalled.started.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        );

        workers[0].release.send(()).unwrap();
        let resolved = resolver
            .resolve_with(Deadline::after(TEST_TIMEOUT).unwrap(), None, || {
                Ok(vec![LOCAL])
            })
            .unwrap();
        assert_eq!(resolved, [LOCAL]);
    }

    #[test]
    fn a_fifth_lookup_waits_for_an_available_worker() {
        let resolver = Resolver::default();
        let workers = occupy_workers(&resolver, TEST_TIMEOUT);
        let fifth = pending_lookup(&resolver, TEST_TIMEOUT);
        assert!(matches!(
            fifth.result.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert_eq!(fifth.started.try_recv(), Err(mpsc::TryRecvError::Empty));

        workers[0].release.send(()).unwrap();
        fifth.started.recv_timeout(TEST_TIMEOUT).unwrap();
        fifth.release.send(()).unwrap();
        let resolved = fifth.result.recv_timeout(TEST_TIMEOUT).unwrap().unwrap();
        assert_eq!(resolved, [LOCAL]);
    }

    #[test]
    fn waiting_for_a_worker_uses_the_lookup_deadline() {
        let resolver = Resolver::default();
        let workers = occupy_workers(&resolver, TEST_TIMEOUT);
        let total = Duration::from_secs(1);
        let begun = Instant::now();
        let fifth = pending_lookup(&resolver, total);

        // Hold all slots for half the deadline, then free one. The lookup
        // may start in it or, on a slow host, time out before it does;
        // either way it must end at the first deadline, not a fresh one
        // counted from the free slot (about 1.5 s).
        assert_eq!(
            fifth.started.recv_timeout(total / 2),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        workers[0].release.send(()).unwrap();
        let error = fifth
            .result
            .recv_timeout(TEST_TIMEOUT)
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let elapsed = begun.elapsed();
        assert!(
            elapsed >= total && elapsed < total + total * 2 / 5,
            "{elapsed:?}"
        );
    }

    #[test]
    fn a_canceller_ends_the_wait_for_a_lookup_and_for_a_worker() {
        // A lookup that never answers: only the canceller ends the wait.
        let resolver = Resolver::default();
        let canceller = Canceller::new();
        let lookup = cancellable_lookup(&resolver, TEST_TIMEOUT, Some(canceller.clone()));
        lookup.started.recv_timeout(TEST_TIMEOUT).unwrap();
        let begun = Instant::now();
        canceller.cancel();
        let error = lookup
            .result
            .recv_timeout(TEST_TIMEOUT)
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(begun.elapsed() < TEST_TIMEOUT / 2, "{:?}", begun.elapsed());

        // All workers busy: the wait for a free one ends the same way, and
        // the lookup never starts.
        let resolver = Resolver::default();
        let _workers = occupy_workers(&resolver, TEST_TIMEOUT);
        let canceller = Canceller::new();
        let fifth = cancellable_lookup(&resolver, TEST_TIMEOUT, Some(canceller.clone()));
        assert!(matches!(
            fifth.result.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        canceller.cancel();
        let error = fifth
            .result
            .recv_timeout(TEST_TIMEOUT / 2)
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            fifth.started.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        );
    }
}
