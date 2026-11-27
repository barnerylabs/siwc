//! Bounded lock waits for writes that cross a key generation.

use std::fs::{File, TryLockError};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use crate::cancel::Canceller;
use crate::error::{Error, ErrorKind};
use crate::store::{Lock, reading};

use super::{KEY_LOCK_FILE, Keychain, RESET_LOCK_FILE};

// Leave time beyond the reset's 30-second planning budget for removals.
const WRITE_LOCK_WAIT: Duration = Duration::from_secs(180);

impl Keychain {
    pub(in crate::store) fn validated_reset_lock(&self) -> Result<ValidatedResetLock, Error> {
        Ok(ValidatedResetLock {
            file: self.files.checked_lock_handle(RESET_LOCK_FILE)?,
            local: Mutex::new(()),
        })
    }
    pub(super) fn lock_against_reset(&self) -> Result<Lock<'_>, Error> {
        self.files
            .lock_file(RESET_LOCK_FILE, WRITE_LOCK_WAIT, None)
            .map_err(write_lock_error)
    }

    pub(in crate::store) fn write_deadline(&self) -> WriteDeadline<'_> {
        WriteDeadline {
            keychain: self,
            started: Instant::now(),
            stop: reading::canceller(),
        }
    }
}

pub(in crate::store) struct WriteDeadline<'a> {
    keychain: &'a Keychain,
    started: Instant,
    stop: Option<Canceller>,
}

pub(in crate::store) struct ValidatedResetLock {
    file: File,
    local: Mutex<()>,
}

struct HeldValidatedLock<'a> {
    file: &'a File,
    _local: MutexGuard<'a, ()>,
}

impl Drop for HeldValidatedLock<'_> {
    fn drop(&mut self) {
        let _unlocked = self.file.unlock();
    }
}

impl<'a> WriteDeadline<'a> {
    pub(in crate::store) fn lock_reset_cached<'b>(
        &self,
        validated: &'b ValidatedResetLock,
    ) -> Result<Lock<'b>, Error> {
        loop {
            if self.stop.as_ref().is_some_and(Canceller::is_cancelled) {
                return Err(reading::cancelled());
            }
            let local = match validated.local.try_lock() {
                Ok(local) => Some(local),
                Err(std::sync::TryLockError::Poisoned(error)) => Some(error.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            };
            if let Some(local) = local {
                match validated.file.try_lock() {
                    Ok(()) => {
                        return Ok(Lock::new(HeldValidatedLock {
                            file: &validated.file,
                            _local: local,
                        }));
                    }
                    Err(TryLockError::WouldBlock) => {}
                    Err(TryLockError::Error(_)) => {
                        return Err(Error::store_failed());
                    }
                }
            }
            let elapsed = self.elapsed();
            if elapsed >= WRITE_LOCK_WAIT {
                return Err(write_lock_error(Error::store_busy()));
            }
            let delay = Duration::from_millis(20).min(WRITE_LOCK_WAIT.saturating_sub(elapsed));
            if let Some(stop) = self.stop.as_ref() {
                stop.wait(delay);
            } else {
                thread::sleep(delay);
            }
        }
    }

    /// Resets take the key lock first. When we hold the reset lock, the key
    /// lock can only be tried once, never waited for.
    pub(in crate::store) fn try_key_lock(&self) -> Result<Option<Lock<'a>>, Error> {
        match self
            .keychain
            .files
            .lock_file(KEY_LOCK_FILE, Duration::ZERO, self.stop.as_ref())
        {
            Ok(lock) => Ok(Some(lock)),
            Err(error) if error.kind() == ErrorKind::StoreBusy => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(in crate::store) fn lock_key(&self) -> Result<Lock<'a>, Error> {
        self.lock(KEY_LOCK_FILE)
    }

    fn lock(&self, name: &str) -> Result<Lock<'a>, Error> {
        self.keychain
            .files
            .lock_file_timed(name, WRITE_LOCK_WAIT, self.stop.as_ref(), || self.elapsed())
            .map_err(write_lock_error)
    }

    fn elapsed(&self) -> Duration {
        #[cfg(all(test, target_os = "linux", feature = "testing"))]
        if let Some(timing) = &self.keychain.timing {
            if let Some(signal) = &timing.contended {
                let _ = signal.try_send(());
            }
            if let Some(elapsed) = &timing.write_elapsed {
                return Duration::from_secs(elapsed.load(std::sync::atomic::Ordering::Acquire));
            }
        }
        self.started.elapsed()
    }
}

fn write_lock_error(error: Error) -> Error {
    if error.kind() == ErrorKind::StoreBusy {
        crate::error::KeychainTimeout::WriteLock.into()
    } else {
        error
    }
}
