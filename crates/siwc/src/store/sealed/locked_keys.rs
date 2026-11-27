//! Keys seen while an entry lock is held, independent of other entries' reads.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::store::{EntryName, Lock};

use super::cache::Keys;

#[derive(Default)]
pub(super) struct LockedKeys(Mutex<HashMap<EntryName, Option<Arc<Keys>>>>);

impl LockedKeys {
    pub(super) fn track<'a>(&'a self, entry: &EntryName, lock: Lock<'a>) -> Lock<'a> {
        self.held().insert(entry.clone(), None);
        Lock::new(TrackedEntry {
            keys: self,
            entry: entry.clone(),
            _lock: lock,
        })
    }

    pub(super) fn remember(&self, entry: &EntryName, keys: &Arc<Keys>) {
        if let Some(last) = self.held().get_mut(entry)
            && last
                .as_ref()
                .is_none_or(|last| last.generation <= keys.generation)
        {
            *last = Some(Arc::clone(keys));
        }
    }

    pub(super) fn last(&self, entry: &EntryName) -> Option<Arc<Keys>> {
        self.held().get(entry).cloned().flatten()
    }

    fn held(&self) -> MutexGuard<'_, HashMap<EntryName, Option<Arc<Keys>>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct TrackedEntry<'a> {
    keys: &'a LockedKeys,
    entry: EntryName,
    _lock: Lock<'a>,
}

impl Drop for TrackedEntry<'_> {
    fn drop(&mut self) {
        // Remove the key before releasing this entry to the next taker.
        self.keys.held().remove(&self.entry);
    }
}
