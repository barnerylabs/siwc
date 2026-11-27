//! A store that encrypts every value before another store keeps it.

mod cache;
pub(super) mod envelope;
#[cfg(feature = "keychain")]
pub(super) mod inventory;
mod key_source;
#[cfg(feature = "keychain")]
mod locked_keys;
mod retired;
mod upgrade;
#[cfg(feature = "keychain")]
mod write_keychain;

use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::entropy::{Entropy, OsEntropy};
use crate::error::{Error, ErrorKind};

use super::{EntryName, Lock, Store, Stored};

use cache::{Cache, KEY_ATTEMPTS, generation_keeps_changing};
pub use envelope::KEY_LEN;
pub use key_source::{KeyGeneration, SealingKey};
pub use retired::{MAX_RETIRED_KEYS, RetiredKeys};

/// A [`Store`] that encrypts every value with a key the app supplies and
/// hands only the result to another store, such as [`PrivateFiles`].
///
/// A value is sealed with ChaCha20-Poly1305 under a fresh random nonce, and
/// the entry's name is bound to it: a value that was changed, copied to
/// another entry or sealed under neither the active nor a retired key does
/// not open, and a read fails with
/// [`ErrorKind::StoreCorrupt`](crate::ErrorKind::StoreCorrupt). With the
/// built-in keychain, an unreadable entry and an unconfigured recorded
/// service give [`ErrorKind::InvalidInput`] instead. The inner store's
/// locks, removal and [`shared_across_processes`](Store::shared_across_processes)
/// are used as they are.
/// The authenticated version byte is `1` for a custom key source and `2`
/// for a keychain-coordinated source. Reading a version-2 entry through an
/// adapter that lost its [`KeyGeneration`] coordination gives
/// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) before opening
/// the value, including when its key is already cached. An adapter that
/// drops coordination from its first use writes version-1 entries instead
/// and violates the [`SealingKey`] contract without triggering this check.
/// A value of at least 29 bytes (header and tag) whose first byte is an
/// ASCII control byte from `0x03` to `0x1F` other than the JSON whitespace
/// `0x09`, `0x0A` and `0x0D` is reserved for a later format: it gives
/// [`ErrorKind::StoreUnsupported`](crate::ErrorKind::StoreUnsupported) and
/// is never opened or resealed.
///
/// The key is fetched from the [`SealingKey`] when a value is first written
/// or read, not when the store is built. It is kept in a wiped buffer.
/// A change of generation makes reads reload. With the built-in keychain,
/// a write can still use the last key if no approved reset cleared it.
/// With the built-in keychain, an entry lock retains the key set from the
/// successful read until that lock is released, even if other entries cause
/// a reload.
///
/// Wiping is best effort: the cipher works on a copy of the key that
/// `ring` does not wipe.
///
/// A value it did not seal does not open either, including one that plain
/// [`PrivateFiles`] wrote before the app wrapped it; an app that starts
/// sealing such a directory calls [`seal_existing`](Self::seal_existing)
/// once when it builds the store.
///
/// Sealing shows that a value was sealed under this key for this entry, not
/// that it is the latest one or that the app wrote it. Someone who can write
/// the inner store can put back an older sealed value of the same entry,
/// and it opens. A plain value they write there is refused only until the
/// next [`seal_existing`](Self::seal_existing), which seals it like any
/// other; `Keychain::open_sealed` runs that on every open. Such a writer
/// controls the user's files and is outside the threat model in
/// [`SECURITY.md`](https://github.com/barnerylabs/siwc/blob/v0.1.0/SECURITY.md).
///
/// ```
/// use siwc::store::{EntryName, KEY_LEN, KeyGeneration, MemoryStore, Sealed, SealingKey, Store};
///
/// struct Fixed;
///
/// impl SealingKey for Fixed {
///     fn lock_generation(&self) -> Result<KeyGeneration<'_>, siwc::Error> {
///         Ok(KeyGeneration::new(0, None))
///     }
///
///     fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), siwc::Error> {
///         key.fill(0x42);
///         Ok(())
///     }
///
///     fn fill_retired(&self, _keys: &mut siwc::store::RetiredKeys<'_>) -> Result<(), siwc::Error> {
///         Ok(())
///     }
/// }
///
/// let store = Sealed::new(MemoryStore::new(), Fixed);
/// let entry = EntryName::new("account-1")?;
/// store.write(&entry, b"synthetic credentials")?;
/// assert_eq!(store.read(&entry)?.unwrap().expose(), b"synthetic credentials");
/// # Ok::<(), siwc::Error>(())
/// ```
///
/// [`PrivateFiles`]: super::PrivateFiles
pub struct Sealed<S, K> {
    store: S,
    source: K,
    keys: Cache,
    #[cfg(feature = "keychain")]
    locked_keys: locked_keys::LockedKeys,
}

/// Which key opened a sealed entry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OpenedWith {
    Current,
    Retired,
}

impl<S: Store, K: SealingKey> Sealed<S, K> {
    /// Seals what goes into `store` with the key from `source`. Nothing is
    /// fetched yet.
    #[must_use]
    pub fn new(store: S, source: K) -> Self {
        Self {
            store,
            source,
            keys: Cache::default(),
            #[cfg(feature = "keychain")]
            locked_keys: locked_keys::LockedKeys::default(),
        }
    }

    /// Opens `sealed` for `entry` under the active key or, on an authentication
    /// failure, under any retired key from [`SealingKey::fill_retired`].
    pub(super) fn open_sealed(
        &self,
        entry: &EntryName,
        sealed: &[u8],
    ) -> Result<(Zeroizing<Vec<u8>>, OpenedWith), Error> {
        envelope::check_version(sealed)?;
        let coordinated =
            envelope::requires_keychain(sealed).map_err(|error| error.into_error())?;
        for _ in 0..KEY_ATTEMPTS {
            let generation = self.source.lock_generation()?;
            if coordinated && !generation.is_keychain_coordinated() {
                return Err(key_source::lost_coordination());
            }
            let (keys, mut generation) = self.keys.lock_current(&self.source, generation, None)?;
            let opened = match envelope::open_checked(&keys.current, entry, sealed) {
                Ok(value) => (value, OpenedWith::Current),
                Err(envelope::OpenFailure::WrongKey) => {
                    drop(generation.guard.take());
                    let Some(value) = keys
                        .open_retired(&self.source, entry, sealed)
                        .map_err(|error| generation.open_error(error))?
                    else {
                        continue;
                    };
                    (value, OpenedWith::Retired)
                }
                Err(failure) => return Err(generation.open_error(failure.into_error())),
            };
            #[cfg(feature = "keychain")]
            if generation.keychain.is_some() {
                self.locked_keys.remember(entry, &keys);
            }
            return Ok(opened);
        }
        Err(generation_keeps_changing())
    }

    fn publish(
        &self,
        entry: &EntryName,
        value: &[u8],
        key: &[u8; KEY_LEN],
        coordinated: bool,
    ) -> Result<(), Error> {
        let mut nonce = [0; envelope::NONCE_BYTES];
        OsEntropy.fill(&mut nonce)?;
        self.store.write(
            entry,
            &envelope::seal(key, entry, nonce, value, coordinated)?,
        )
    }
}

pub(super) fn require_nonzero_key(key: &[u8; KEY_LEN]) -> Result<(), Error> {
    if *key == [0; KEY_LEN] {
        return Err(Error::new(
            ErrorKind::Store,
            "an all-zero sealing key is not allowed",
        ));
    }
    Ok(())
}

impl<S: Store, K: SealingKey> Store for Sealed<S, K> {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        let Some(sealed) = self.store.read(entry)? else {
            return Ok(None);
        };
        let (mut value, _) = self.open_sealed(entry, sealed.expose())?;
        Ok(Some(Stored::new(std::mem::take(&mut *value))))
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        let mut generation = self.source.lock_generation()?;
        #[cfg(feature = "keychain")]
        if let Some(keychain) = generation.keychain {
            return self.write_with_keychain(entry, value, keychain, generation);
        }
        let mut previous = None;
        for _ in 0..KEY_ATTEMPTS {
            let (used, observed) =
                self.keys
                    .lock_current(&self.source, generation, previous.as_deref())?;
            self.publish(entry, value, &used.current, used.keychain_coordinated)?;
            if observed.guard.is_some() {
                return Ok(());
            }
            generation = self.source.lock_generation()?;
            if generation.number() == used.generation {
                return Ok(());
            }
            previous = Some(used);
        }
        Err(generation_keeps_changing())
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        self.store.remove(entry)
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        let lock = self.store.lock(entry, patience)?;
        #[cfg(feature = "keychain")]
        let lock = self.locked_keys.track(entry, lock);
        Ok(lock)
    }

    fn shared_across_processes(&self) -> bool {
        self.store.shared_across_processes()
    }
}

impl<S, K> fmt::Debug for Sealed<S, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealed").finish_non_exhaustive()
    }
}
