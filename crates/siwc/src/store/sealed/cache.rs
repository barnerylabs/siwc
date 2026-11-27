//! Cached sealing keys and the generation they were fetched under.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind};
#[cfg(feature = "keychain")]
use crate::store::keychain::ValidatedResetLock;
use crate::store::{EntryName, reading};

use super::{
    KEY_LEN, KeyGeneration, MAX_RETIRED_KEYS, RetiredKeys, SealingKey, envelope,
    require_nonzero_key,
};

pub(super) const KEY_ATTEMPTS: usize = 3;

pub(super) fn generation_keeps_changing() -> Error {
    Error::new(
        ErrorKind::Store,
        "the sealing key generation keeps changing",
    )
}

#[derive(Default)]
pub(super) struct Cache {
    // Keep the last validated key while a lookup in a newer generation
    // is pending or fails. Only the loading mutex is held across a fetch.
    last: Mutex<Option<Arc<Keys>>>,
    loading: Mutex<()>,
}

impl Cache {
    pub(super) fn last(&self) -> Result<Option<Arc<Keys>>, Error> {
        Ok(reading::lock_keys(&self.last)?.clone())
    }

    pub(super) fn remember(&self, keys: &Arc<Keys>) {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last
            .as_ref()
            .is_none_or(|last| last.generation <= keys.generation)
        {
            *last = Some(Arc::clone(keys));
        }
    }

    pub(super) fn lock_current<'s>(
        &self,
        source: &'s impl SealingKey,
        mut generation: KeyGeneration<'s>,
        previous_write: Option<&Keys>,
    ) -> Result<(Arc<Keys>, KeyGeneration<'s>), Error> {
        if let Some(keys) = self.current(&generation)? {
            return Ok((keys, generation));
        }
        drop(generation);
        let _loading = reading::lock_keys(&self.loading)?;
        generation = source.lock_generation()?;
        for _ in 0..KEY_ATTEMPTS {
            let number = generation.number();
            let coordinated = generation.is_keychain_coordinated();
            #[cfg(feature = "keychain")]
            let expected = generation.keychain;
            #[cfg(feature = "keychain")]
            let reset_lock = expected
                .map(|keychain| keychain.validated_reset_lock().map(Arc::new))
                .transpose()?;
            if let Some(keys) = self.current(&generation)? {
                return Ok((keys, generation));
            }
            drop(generation);
            let keys = Keys::load(
                |key| {
                    if let Some(previous) = previous_write {
                        source.refill_after_write(key, previous.generation, &previous.current)?;
                    } else {
                        source.fill(key)?;
                    }
                    Ok(number)
                },
                coordinated,
                #[cfg(feature = "keychain")]
                reset_lock,
            )?;
            // Fill can itself advance the generation.
            generation = source.lock_generation()?;
            if generation.number() == number {
                if generation.is_keychain_coordinated() != coordinated {
                    return Err(super::key_source::lost_coordination());
                }
                self.remember(&keys);
                return Ok((keys, generation));
            }
        }
        Err(generation_keeps_changing())
    }

    fn current(&self, generation: &KeyGeneration<'_>) -> Result<Option<Arc<Keys>>, Error> {
        let keys = self
            .last()?
            .filter(|keys| keys.generation == generation.number());
        if keys
            .as_ref()
            .is_some_and(|keys| keys.keychain_coordinated != generation.is_keychain_coordinated())
        {
            return Err(super::key_source::lost_coordination());
        }
        Ok(keys)
    }
}

pub(super) struct Keys {
    pub(super) generation: u64,
    pub(super) keychain_coordinated: bool,
    pub(super) current: Zeroizing<[u8; KEY_LEN]>,
    retired: OnceLock<Vec<Zeroizing<[u8; KEY_LEN]>>>,
    retired_loading: Mutex<()>,
    #[cfg(feature = "keychain")]
    pub(super) reset_lock: Option<Arc<ValidatedResetLock>>,
}

impl Keys {
    pub(super) fn load(
        fill: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<u64, Error>,
        keychain_coordinated: bool,
        #[cfg(feature = "keychain")] reset_lock: Option<Arc<ValidatedResetLock>>,
    ) -> Result<Arc<Self>, Error> {
        let mut keys = Arc::new(Self {
            generation: 0,
            keychain_coordinated,
            current: Zeroizing::new([0; KEY_LEN]),
            retired: OnceLock::new(),
            retired_loading: Mutex::new(()),
            #[cfg(feature = "keychain")]
            reset_lock,
        });
        let fresh = Arc::get_mut(&mut keys).ok_or_else(Error::store_failed)?;
        fresh.generation = fill(&mut fresh.current)?;
        require_nonzero_key(&fresh.current)?;
        Ok(keys)
    }

    #[cfg(feature = "keychain")]
    pub(super) fn known_keys(&self) -> impl Iterator<Item = &[u8; KEY_LEN]> {
        std::iter::once(&*self.current)
            .chain(self.retired.get().into_iter().flatten().map(|key| &**key))
    }

    /// Tries the retired keys. None means their generation changed, so
    /// the caller must try again with the current generation.
    pub(super) fn open_retired(
        &self,
        source: &impl SealingKey,
        entry: &EntryName,
        sealed: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let _loading = reading::lock_keys(&self.retired_loading)?;
        let mut generation = source.lock_generation()?;
        if self.keychain_coordinated != generation.is_keychain_coordinated() {
            return Err(super::key_source::lost_coordination());
        }
        if self.generation != generation.number() {
            return Ok(None);
        }
        let retired = if let Some(keys) = self.retired.get() {
            keys
        } else {
            drop(generation);
            let mut keys = Vec::with_capacity(MAX_RETIRED_KEYS);
            source.fill_retired(&mut RetiredKeys::new(&mut keys))?;
            generation = source.lock_generation()?;
            if self.keychain_coordinated != generation.is_keychain_coordinated() {
                return Err(super::key_source::lost_coordination());
            }
            if self.generation != generation.number() {
                return Ok(None);
            }
            self.retired.get_or_init(|| keys)
        };
        for candidate in retired {
            match envelope::open_checked(candidate, entry, sealed) {
                Ok(value) => return Ok(Some(value)),
                Err(envelope::OpenFailure::WrongKey) => {}
                Err(failure) => return Err(failure.into_error()),
            }
        }
        Err(envelope::OpenFailure::WrongKey.into_error())
    }
}
