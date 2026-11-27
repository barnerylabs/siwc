//! Cancellation during synchronous store access. Neither the public Store
//! nor SealingKey trait takes a canceller. Each client store call sets its
//! own scope on the calling thread, including on an async stream's worker.

use std::cell::RefCell;
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::Duration;

use crate::cancel::Canceller;
use crate::error::{Error, ErrorKind};

thread_local! {
    static READING: RefCell<Option<Canceller>> = const { RefCell::new(None) };
}

/// Scope the canceller to a store call, restoring an enclosing caller's
/// canceller even if a custom store unwinds.
pub(crate) fn with_canceller<T>(stop: Option<&Canceller>, read: impl FnOnce() -> T) -> T {
    struct Restore(Option<Canceller>);
    impl Drop for Restore {
        fn drop(&mut self) {
            READING.set(self.0.take());
        }
    }

    let _restore = Restore(READING.replace(stop.cloned()));
    read()
}

pub(super) fn canceller() -> Option<Canceller> {
    READING.with_borrow(Clone::clone)
}

pub(super) fn cancelled() -> Error {
    Error::new(ErrorKind::Cancelled, "the store key wait was cancelled")
}

/// Another reader may be fetching the key while it holds this mutex.
pub(super) fn lock_keys<T>(keys: &Mutex<T>) -> Result<MutexGuard<'_, T>, Error> {
    let Some(stop) = canceller() else {
        return Ok(keys.lock().unwrap_or_else(PoisonError::into_inner));
    };
    loop {
        let locked = keys.try_lock();
        if stop.is_cancelled() {
            return Err(cancelled());
        }
        match locked {
            Ok(keys) => return Ok(keys),
            Err(TryLockError::Poisoned(error)) => return Ok(error.into_inner()),
            Err(TryLockError::WouldBlock) => {
                stop.wait(Duration::from_millis(50));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::thread;

    use super::*;

    #[test]
    fn a_nested_store_read_restores_its_callers_canceller_on_unwind() {
        let outer = Canceller::new();
        with_canceller(Some(&outer), || {
            let inner = std::panic::catch_unwind(|| {
                with_canceller(None, || {
                    assert!(canceller().is_none());
                    std::panic::resume_unwind(Box::new("custom store panicked"));
                });
            });
            assert_eq!(
                inner.unwrap_err().downcast_ref::<&str>(),
                Some(&"custom store panicked")
            );
            canceller().expect("outer canceller").cancel();
        });
        assert!(outer.is_cancelled());
        assert!(canceller().is_none());
    }

    #[test]
    fn a_cancelled_store_read_leaves_another_threads_key_fetch_running() {
        let keys = Arc::new(Mutex::new(()));
        let held = keys.lock().unwrap();
        let stop = Canceller::new();
        let (entered, waiting) = mpsc::channel();
        let (done, finished) = mpsc::channel();
        let reader = thread::spawn({
            let keys = Arc::clone(&keys);
            let stop = stop.clone();
            move || {
                with_canceller(Some(&stop), || {
                    entered.send(()).unwrap();
                    done.send(lock_keys(&keys).map(drop)).unwrap();
                })
            }
        });
        let guard = Duration::from_secs(3);
        waiting.recv_timeout(guard).unwrap();
        stop.cancel();
        let result = finished.recv_timeout(guard);
        drop(held);
        reader.join().unwrap();
        assert_eq!(result.unwrap().unwrap_err().kind(), ErrorKind::Cancelled);
    }
}
