//! Sealing what a store kept in plain text before it was wrapped.

use std::time::Duration;

use crate::error::Error;
use crate::store::{EntryName, PrivateFiles, Store};

use super::{OpenedWith, Sealed, SealingKey, envelope};

impl<K: SealingKey> Sealed<PrivateFiles, K> {
    /// Seals plaintext `installation` and `account-*` entries left by an app
    /// that used plain [`PrivateFiles`]. Other files may share the directory;
    /// plaintext under all other names is left alone. Call it once when the store is built,
    /// before a [`Client`](crate::Client) reads it.
    ///
    /// Each plain entry is read again and replaced under its own lock,
    /// which waits up to `patience`, so a refresh in another process that
    /// holds the lock is never overwritten with an older value. Only one
    /// lock is held at a time. An entry already in the sealed format is
    /// left as it is without being opened, so when nothing is plain the key
    /// is not fetched. Plain entries must be valid JSON objects (the shape
    /// [`Client`](crate::Client) writes); reserved future envelopes return
    /// [`StoreUnsupported`](crate::ErrorKind::StoreUnsupported). Other non-JSON bytes
    /// without a supported header fail with
    /// [`ErrorKind::StoreCorrupt`](crate::ErrorKind::StoreCorrupt) instead of
    /// being double-sealed.
    ///
    /// Until the call returns, another process that reads the store through
    /// `Sealed` gets [`ErrorKind::StoreCorrupt`](crate::ErrorKind::StoreCorrupt)
    /// for an entry not sealed yet, and changes nothing; an older version of
    /// the app that reads the store plain gets the same afterwards.
    /// Stop all plain-store writers before migrating. This pass only handles
    /// named entries. Backups and temporary files from interrupted plain
    /// writes may still hold plaintext and require separate cleanup.
    ///
    /// ```no_run
    /// use std::time::Duration;
    ///
    /// use siwc::store::{KEY_LEN, KeyGeneration, PrivateFiles, RetiredKeys, Sealed, SealingKey};
    ///
    /// # struct FromKeychain;
    /// # impl SealingKey for FromKeychain {
    /// #     fn lock_generation(&self) -> Result<KeyGeneration<'_>, siwc::Error> { Ok(KeyGeneration::new(0, None)) }
    /// #     fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), siwc::Error> { key.fill(0x42); Ok(()) }
    /// #     fn fill_retired(&self, _keys: &mut RetiredKeys<'_>) -> Result<(), siwc::Error> { Ok(()) }
    /// # }
    /// let files = PrivateFiles::open("/home/alex/.local/share/paste-perfect/sign-in")?;
    /// let store = Sealed::new(files, FromKeychain);
    /// store.seal_existing(Duration::from_secs(10))?;
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// An unsupported envelope version returns [`StoreUnsupported`](crate::ErrorKind::StoreUnsupported).
    ///
    /// [`ErrorKind::StoreCorrupt`](crate::ErrorKind::StoreCorrupt) when an
    /// plain entry is not a valid JSON object, plus whatever the store or
    /// key source reports. Entries sealed before the error stay sealed, and a
    /// later call carries on with the rest.
    pub fn seal_existing(&self, patience: Duration) -> Result<(), Error> {
        for entry in self.store.entries()? {
            if !self.needs_sealing(&entry)? {
                continue;
            }
            let _lock = self.store.lock(&entry, patience)?;
            // Read again under the lock: another process may have sealed
            // or removed it meanwhile.
            let Some(stored) = self.store.read(&entry)? else {
                continue;
            };
            let raw = stored.expose();
            envelope::check_version(raw)?;
            if envelope::is_sealed(raw) || !entry.is_client_entry() {
                continue;
            }
            if !is_plain_json_object(raw) {
                return Err(Error::new(
                    crate::error::ErrorKind::StoreCorrupt,
                    "an entry in the store is corrupt",
                ));
            }
            self.write(&entry, raw)?;
        }
        Ok(())
    }

    /// Re-encrypts each plain client JSON entry and every entry sealed under a
    /// [retired key](SealingKey::fill_retired) with the active key, one entry
    /// lock at a time (waiting up to `patience` per lock).
    ///
    /// Entries already sealed under the active key are verified and left on
    /// disk untouched, and when every entry opens under the active key the
    /// retired keys are not fetched. Plain unsealed entries must be valid JSON
    /// objects (as written by [`Client`](crate::Client)). A reserved future envelope
    /// returns [`StoreUnsupported`](crate::ErrorKind::StoreUnsupported). A damaged entry, non-JSON
    /// plain bytes, or an entry sealed under an unknown key stops the pass with
    /// [`ErrorKind::StoreCorrupt`](crate::ErrorKind::StoreCorrupt) and leaves
    /// that entry untouched. With the built-in keychain an unreadable
    /// entry and an unconfigured service marker give
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) instead.
    /// Stop processes using the former active key
    /// before rotating, since they cannot read new entries and could write
    /// an old-key entry after this pass. After a successful pass, named
    /// entries no longer depend on the retired keys.
    ///
    /// ```no_run
    /// use std::time::Duration;
    ///
    /// use siwc::store::{KEY_LEN, KeyGeneration, PrivateFiles, RetiredKeys, Sealed, SealingKey};
    ///
    /// # struct RotatedKeychain;
    /// # impl SealingKey for RotatedKeychain {
    /// #     fn lock_generation(&self) -> Result<KeyGeneration<'_>, siwc::Error> { Ok(KeyGeneration::new(0, None)) }
    /// #     fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), siwc::Error> { key.fill(2); Ok(()) }
    /// #     fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), siwc::Error> {
    /// #         keys.add(|key| { key.fill(1); Ok(()) })
    /// #     }
    /// # }
    /// let files = PrivateFiles::open("/home/alex/.local/share/paste-perfect/sign-in")?;
    /// let store = Sealed::new(files, RotatedKeychain);
    /// store.reseal(Duration::from_secs(10))?;
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// An unsupported envelope version returns [`StoreUnsupported`](crate::ErrorKind::StoreUnsupported).
    ///
    /// [`ErrorKind::StoreCorrupt`](crate::ErrorKind::StoreCorrupt) when a
    /// sealed entry cannot be opened with either the active or a retired key,
    /// or [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) if the
    /// recorded keychain service is unconfigured. Store and key source
    /// errors keep their own kind.
    pub fn reseal(&self, patience: Duration) -> Result<(), Error> {
        for entry in self.store.entries()? {
            let _lock = self.store.lock(&entry, patience)?;
            let Some(stored) = self.store.read(&entry)? else {
                continue;
            };
            let raw = stored.expose();
            envelope::check_version(raw)?;
            if !envelope::is_sealed(raw) {
                if !entry.is_client_entry() {
                    continue;
                }
                if is_plain_json_object(raw) {
                    self.write(&entry, raw)?;
                    continue;
                }
            }
            let (plaintext, opened_with) = self.open_sealed(&entry, raw)?;
            if opened_with == OpenedWith::Retired {
                self.write(&entry, &plaintext)?;
            }
        }
        Ok(())
    }

    fn needs_sealing(&self, entry: &EntryName) -> Result<bool, Error> {
        Ok(self
            .store
            .read(entry)?
            .is_some_and(|stored| !envelope::is_sealed(stored.expose())))
    }
}

/// Checks that `bytes` is a JSON object (the shape of unsealed `Client`
/// entries), wiping any parsed strings on drop so damaged or future-version
/// ciphertexts are never mistaken for plain entries by [`Sealed::reseal`].
fn is_plain_json_object(bytes: &[u8]) -> bool {
    crate::protocol::json::object(bytes)
        .map(crate::protocol::json::Document)
        .is_some()
}
