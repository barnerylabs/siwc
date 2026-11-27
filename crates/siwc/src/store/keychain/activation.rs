//! Filling the active and retired keys under the directory's key lock.

use std::iter;

use zeroize::{Zeroize, Zeroizing};

use crate::cancel::Canceller;
use crate::entropy::OsEntropy;
use crate::error::{Error, ErrorKind};
use crate::store::sealed::inventory;
use crate::store::{KEY_LEN, KeyGeneration, RetiredKeys, SealingKey, reading};

use super::material::{Backend, Lookup, fill_from, fill_retired_from, find_key};
use super::state::ClearedReset;
use super::{Keychain, RESET_LOCK_FILE, ServiceName};

pub(super) struct PreviousWrite<'a> {
    pub(super) generation: u64,
    pub(super) key: &'a [u8; KEY_LEN],
}

impl Keychain {
    pub(super) fn read_retired(
        &self,
        backend: &impl Backend,
        lookup: Lookup<'_>,
    ) -> Result<Vec<Zeroizing<[u8; KEY_LEN]>>, Error> {
        let mut keys = Vec::new();
        fill_retired_from(
            backend,
            &self.retired,
            lookup,
            &mut RetiredKeys::new(&mut keys),
        )?;
        Ok(keys)
    }

    fn require_rotation_or_empty(
        &self,
        backend: &impl Backend,
        stop: Option<&Canceller>,
        previous_key: Option<&[u8; KEY_LEN]>,
    ) -> Result<(), Error> {
        let mut sealed = inventory::entries(&self.files)?;
        let Some(first) = sealed.next().transpose()? else {
            return Ok(());
        };
        let retired = self.read_retired(backend, Lookup::cancellable(stop))?;
        let mut cleared = previous_key.is_some();
        let mut rotating = false;
        for item in iter::once(Ok(first)).chain(sealed) {
            let (entry, stored) = item?;
            if !rotating {
                rotating =
                    inventory::opens_with_any(&entry, &stored, retired.iter().map(|key| &**key))?;
            }
            if cleared {
                cleared = inventory::opens_with_any(&entry, &stored, previous_key)?;
            }
        }
        if rotating || cleared {
            return Ok(());
        }
        Err(Error::new(
            ErrorKind::SealingKeyMissing,
            "the keychain has no sealing key for the sealed entries",
        ))
    }

    pub(super) fn fill_using(
        &self,
        backend: &impl Backend,
        key: &mut [u8; KEY_LEN],
    ) -> Result<(), Error> {
        self.fill_or_replay(backend, key, None)
    }

    fn fill_or_replay(
        &self,
        backend: &impl Backend,
        key: &mut [u8; KEY_LEN],
        previous: Option<PreviousWrite<'_>>,
    ) -> Result<(), Error> {
        let stop = reading::canceller();
        let stop = stop.as_ref();
        let _locked = self.key_lock(stop)?;
        self.fill_locked(backend, stop, key, previous)
    }

    pub(super) fn fill_locked(
        &self,
        backend: &impl Backend,
        stop: Option<&Canceller>,
        key: &mut [u8; KEY_LEN],
        previous: Option<PreviousWrite<'_>>,
    ) -> Result<(), Error> {
        self.files.check_lock_file(RESET_LOCK_FILE)?;
        let recorded = self.recorded_service()?;
        let cleared = self.cleared_reset()?;
        let created = fill_from(backend, &self.service, &OsEntropy, stop, key, || {
            self.require_configured_service(recorded.as_ref(), || self.has_sealed_entries())?;
            let previous_key = previous
                .filter(|previous| {
                    cleared.as_ref().is_some_and(|reset| {
                        reset.same_service && previous.generation < reset.generation
                    })
                })
                .map(|previous| previous.key);
            self.require_rotation_or_empty(backend, stop, previous_key)?;
            // Invalidate caches before creation: the helper can commit
            // the new key and then fail before we can read it back.
            self.bump_generation()?;
            Ok(())
        })?;
        self.publish_activation(recorded.as_ref(), created, cleared.as_ref(), key)
            .inspect_err(|_| key.zeroize())
    }

    /// Reads an existing item with the key lock held, without activating or
    /// creating a service. A write can fall back if this lookup fails.
    pub(in crate::store) fn read_existing_key_locked(
        &self,
        key: &mut [u8; KEY_LEN],
    ) -> Result<u64, Error> {
        let stop = reading::canceller();
        let read = find_key(
            &self.platform_tool(),
            &self.service,
            Lookup::cancellable(stop.as_ref()),
            key,
        )?;
        if !read {
            return Err(Error::new(
                ErrorKind::SealingKeyMissing,
                "the keychain item is missing",
            ));
        }
        self.generation()
    }

    /// Reloads after a reset with the key lock already held. Only this path
    /// can use the cleared-reset record to recover a crossing write.
    pub(in crate::store) fn reload_key_locked(
        &self,
        key: &mut [u8; KEY_LEN],
        previous_generation: u64,
        previous_key: &[u8; KEY_LEN],
    ) -> Result<u64, Error> {
        let stop = reading::canceller();
        self.fill_locked(
            &self.platform_tool(),
            stop.as_ref(),
            key,
            Some(PreviousWrite {
                generation: previous_generation,
                key: previous_key,
            }),
        )?;
        self.generation()
    }

    fn publish_activation(
        &self,
        recorded: Option<&ServiceName>,
        created: bool,
        cleared: Option<&ClearedReset>,
        key: &[u8; KEY_LEN],
    ) -> Result<(), Error> {
        let record_service = match recorded {
            Some(previous) if *previous == self.service => false,
            _ if created => true,
            // Keep an unlisted service's marker while sealed entries exist.
            Some(previous) => self.retired.contains(previous) || !self.has_sealed_entries()?,
            None => self.empty_or_opened_by(key)?,
        };
        let changes_service = recorded.is_some() && record_service;
        let ends_reset = cleared.is_some_and(|reset| reset.same_service);
        if !created && (changes_service || ends_reset) {
            self.bump_generation()?;
        }
        if record_service {
            self.record_service()?;
        }
        Ok(())
    }

    fn has_sealed_entries(&self) -> Result<bool, Error> {
        Ok(inventory::entries(&self.files)?
            .next()
            .transpose()?
            .is_some())
    }

    fn empty_or_opened_by(&self, key: &[u8; KEY_LEN]) -> Result<bool, Error> {
        let mut sealed = inventory::entries(&self.files)?;
        let Some(first) = sealed.next().transpose()? else {
            return Ok(true);
        };
        for item in iter::once(Ok(first)).chain(sealed) {
            let (entry, stored) = item?;
            if inventory::opens_with_any(&entry, &stored, [key])? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl SealingKey for Keychain {
    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        self.fill_using(&self.platform_tool(), key)
    }

    fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        if self.retired.is_empty() {
            return Ok(());
        }
        let stop = reading::canceller();
        let _locked = self.key_lock(stop.as_ref())?;
        fill_retired_from(
            &self.platform_tool(),
            &self.retired,
            Lookup::cancellable(stop.as_ref()),
            keys,
        )
    }

    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(KeyGeneration::coordinated(self.generation()?, self))
    }

    fn refill_after_write(
        &self,
        key: &mut [u8; KEY_LEN],
        previous_generation: u64,
        previous_key: &[u8; KEY_LEN],
    ) -> Result<(), Error> {
        self.fill_or_replay(
            &self.platform_tool(),
            key,
            Some(PreviousWrite {
                generation: previous_generation,
                key: previous_key,
            }),
        )
    }
}
