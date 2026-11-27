//! Choosing the sealing key when a publication crosses a generation change.

use std::sync::Arc;

use crate::error::{Error, ErrorKind};
use crate::store::keychain::ResetSince;
use crate::store::{EntryName, Keychain, Store};

use super::cache::Keys;
use super::{KeyGeneration, Sealed, SealingKey, inventory};

impl<S: Store, K: SealingKey> Sealed<S, K> {
    pub(super) fn write_with_keychain<'s>(
        &'s self,
        entry: &EntryName,
        value: &[u8],
        keychain: &Keychain,
        mut generation: KeyGeneration<'s>,
    ) -> Result<(), Error> {
        let cached = self.keys.last()?;
        let previous = match self.locked_keys.last(entry).or(cached) {
            Some(keys) => keys,
            None => {
                let (keys, loaded) = self.keys.lock_current(&self.source, generation, None)?;
                generation = loaded;
                keys
            }
        };
        if !previous.keychain_coordinated {
            return Err(super::key_source::lost_coordination());
        }

        if previous.generation == generation.number() {
            self.publish(entry, value, &previous.current, true)?;
            if keychain.generation()? == previous.generation {
                self.locked_keys.remember(entry, &previous);
                return Ok(());
            }
        }
        self.write_across_generation(entry, value, keychain, &previous)
    }

    fn write_across_generation(
        &self,
        entry: &EntryName,
        value: &[u8],
        keychain: &Keychain,
        previous: &Arc<Keys>,
    ) -> Result<(), Error> {
        let deadline = keychain.write_deadline();
        let validated = previous
            .reset_lock
            .as_ref()
            .ok_or_else(Error::store_failed)?;
        let reset_lock = deadline.lock_reset_cached(validated)?;
        match keychain.reset_since(previous.generation)? {
            ResetSince::None => {
                let immediate = deadline.try_key_lock()?;
                drop(reset_lock);
                let key_lock = match immediate {
                    Some(lock) => lock,
                    None => match deadline.lock_key() {
                        Ok(lock) => lock,
                        Err(error)
                            if error.keychain_timeout
                                == Some(crate::error::KeychainTimeout::WriteLock) =>
                        {
                            let _reset_lock = deadline.lock_reset_cached(validated)?;
                            if matches!(
                                keychain.reset_since(previous.generation)?,
                                ResetSince::None
                            ) {
                                return self.publish_with(entry, value, previous);
                            }
                            return Err(error);
                        }
                        Err(error) => return Err(error),
                    },
                };
                return self.write_with_key_lock(entry, value, keychain, previous, &key_lock);
            }
            ResetSince::Checked(reset) => {
                if self.reset_kept_entry(entry, previous, &reset)? {
                    return self.publish_with(entry, value, previous);
                }
            }
            ResetSince::Unrecorded { prior, provisional } => {
                if self.unrecorded_keeps_entry(
                    entry,
                    previous,
                    prior.as_ref(),
                    provisional.as_ref(),
                )? {
                    return self.publish_with(entry, value, previous);
                }
            }
        }

        // A reset cleared the cached key or the entry. Drop the reset lock
        // before waiting for the key lock, which excludes subsequent resets.
        drop(reset_lock);
        let _key_lock = deadline.lock_key()?;
        let loaded = Keys::load(
            |key| keychain.reload_key_locked(key, previous.generation, &previous.current),
            true,
            previous.reset_lock.clone(),
        )?;
        self.publish_loaded(entry, value, &loaded)
    }

    fn write_with_key_lock(
        &self,
        entry: &EntryName,
        value: &[u8],
        keychain: &Keychain,
        previous: &Arc<Keys>,
        _key_lock: &crate::store::Lock<'_>,
    ) -> Result<(), Error> {
        match keychain.reset_since(previous.generation)? {
            ResetSince::None => match Keys::load(
                |key| keychain.read_existing_key_locked(key),
                true,
                previous.reset_lock.clone(),
            ) {
                Ok(loaded) => self.publish_loaded(entry, value, &loaded),
                Err(error) if error.kind() == ErrorKind::Cancelled => Err(error),
                Err(_) => self.publish_with(entry, value, previous),
            },
            ResetSince::Checked(reset) if self.reset_kept_entry(entry, previous, &reset)? => {
                self.publish_with(entry, value, previous)
            }
            ResetSince::Unrecorded { prior, provisional }
                if self.unrecorded_keeps_entry(
                    entry,
                    previous,
                    prior.as_ref(),
                    provisional.as_ref(),
                )? =>
            {
                self.publish_with(entry, value, previous)
            }
            _ => {
                let loaded = Keys::load(
                    |key| keychain.reload_key_locked(key, previous.generation, &previous.current),
                    true,
                    previous.reset_lock.clone(),
                )?;
                self.publish_loaded(entry, value, &loaded)
            }
        }
    }

    fn unrecorded_keeps_entry(
        &self,
        entry: &EntryName,
        previous: &Keys,
        prior: Option<&crate::store::keychain::ResetKeys>,
        provisional: Option<&crate::store::keychain::ResetKeys>,
    ) -> Result<bool, Error> {
        if [prior, provisional]
            .into_iter()
            .flatten()
            .any(|reset| !reset.kept(&previous.current, previous.generation))
        {
            return Ok(false);
        }
        let Some(stored) = self.store.read(entry)? else {
            return Ok(false);
        };
        inventory::opens_with_any(
            entry,
            &stored,
            previous.known_keys().filter(|key| {
                [prior, provisional]
                    .into_iter()
                    .flatten()
                    .all(|reset| reset.kept(key, previous.generation))
            }),
        )
    }

    fn reset_kept_entry(
        &self,
        entry: &EntryName,
        previous: &Keys,
        reset: &crate::store::keychain::ResetKeys,
    ) -> Result<bool, Error> {
        if !reset.kept(&previous.current, previous.generation) {
            return Ok(false);
        }
        let Some(stored) = self.store.read(entry)? else {
            return Ok(false);
        };
        inventory::opens_with_any(
            entry,
            &stored,
            previous
                .known_keys()
                .filter(|key| reset.kept(key, previous.generation)),
        )
    }

    fn publish_loaded(
        &self,
        entry: &EntryName,
        value: &[u8],
        keys: &Arc<Keys>,
    ) -> Result<(), Error> {
        self.publish_with(entry, value, keys)?;
        self.keys.remember(keys);
        Ok(())
    }

    fn publish_with(&self, entry: &EntryName, value: &[u8], keys: &Arc<Keys>) -> Result<(), Error> {
        self.publish(entry, value, &keys.current, true)?;
        self.locked_keys.remember(entry, keys);
        Ok(())
    }
}
