//! A store that lives only as long as the process.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::secret::SecretBytes;

use super::{EntryName, Lock, Store, Stored};

/// Keeps everything in memory; nothing survives the process. For
/// session-only sign-ins and tests.
///
/// Locks exclude other threads of the same process only, which is all a
/// value that lives in one process needs.
///
/// ```
/// use siwc::store::{EntryName, MemoryStore, Store};
///
/// let store = MemoryStore::new();
/// let entry = EntryName::new("account-1")?;
/// store.write(&entry, b"first")?;
/// store.write(&entry, b"second")?;
/// assert_eq!(store.read(&entry)?.unwrap().expose(), b"second");
/// store.remove(&entry)?;
/// assert!(store.read(&entry)?.is_none());
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Default)]
pub struct MemoryStore {
    state: Mutex<State>,
    /// Signalled whenever a lock is released.
    released: Condvar,
}

#[derive(Default)]
struct State {
    /// `SecretBytes` wipes a value when it is replaced, removed or dropped
    /// with the store. No test can observe the wiping.
    values: HashMap<EntryName, SecretBytes>,
    locked: HashSet<EntryName>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The state; a panic in another thread while it held the mutex leaves
    /// nothing half-done, so a poisoned mutex is used as it is.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Store for MemoryStore {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        Ok(self
            .state()
            .values
            .get(entry)
            .map(|value| Stored::new(value.expose().to_vec())))
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        self.state()
            .values
            .insert(entry.clone(), SecretBytes::new(value.to_vec()));
        Ok(())
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        self.state().values.remove(entry);
        Ok(())
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        let deadline = Instant::now().checked_add(patience);
        let mut state = self.state();
        while state.locked.contains(entry) {
            let remaining = match deadline {
                Some(deadline) => deadline.saturating_duration_since(Instant::now()),
                None => patience,
            };
            if remaining.is_zero() {
                return Err(Error::store_busy());
            }
            state = match self.released.wait_timeout(state, remaining) {
                Ok((state, _)) => state,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        state.locked.insert(entry.clone());
        drop(state);
        Ok(Lock::new(Held {
            store: self,
            entry: entry.clone(),
        }))
    }

    /// Memory belongs to one process only.
    fn shared_across_processes(&self) -> bool {
        false
    }
}

impl fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryStore { .. }")
    }
}

/// An entry's lock in a [`MemoryStore`]; released on drop.
struct Held<'a> {
    store: &'a MemoryStore,
    entry: EntryName,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.store.state().locked.remove(&self.entry);
        self.store.released.notify_all();
    }
}
