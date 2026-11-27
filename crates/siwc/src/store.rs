//! Where an app keeps what has to survive a restart.
//!
//! A [`Store`] holds named byte values, such as an installation record and
//! one credentials entry per account, and gives each entry an exclusive
//! [`Lock`] that works across threads and, for a store shared between
//! processes, across processes, so a token refresh can be serialised. A
//! store knows nothing about what it holds: every value is treated as
//! private, comes back as a [`Stored`] that is wiped when dropped, and never
//! appears in `Debug` output or an error.
//!
//! Two stores come with the crate: [`MemoryStore`] for sign-ins that end
//! with the process, and [`PrivateFiles`] for machines without a keychain.
//! [`Sealed`] encrypts what another store keeps with a key from a
//! [`SealingKey`], usually held in the system keychain. With the `keychain`
//! feature, `Keychain` is that key for macOS, Linux and Windows; an app can
//! also implement [`SealingKey`] over a keychain of its choice, or [`Store`]
//! over the keychain itself.

#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod conformance;
mod files;
#[cfg(feature = "keychain")]
mod keychain;
mod memory;
mod name;
pub(crate) mod reading;
mod sealed;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::error::Error;
use crate::secret::SecretBytes;

pub use files::PrivateFiles;
pub(crate) use files::write_new_file;
#[cfg(feature = "keychain")]
#[cfg_attr(docsrs, doc(cfg(feature = "keychain")))]
pub use keychain::Keychain;
pub use memory::MemoryStore;
pub use name::EntryName;
pub use sealed::{KEY_LEN, KeyGeneration, MAX_RETIRED_KEYS, RetiredKeys, Sealed, SealingKey};

/// Where an app keeps what has to survive a restart. Everything a store
/// holds is private.
///
/// Reading, writing and removing do not take an entry's lock; a caller that
/// needs read, change and write to happen as one step takes the lock first.
///
/// # Implementing `Store`
///
/// - **Diagnostics:** redact entry contents and personal paths from your
///   adapter's own `Debug` output.
/// - **Errors:** All operations may return [`Error::store_not_private`] for
///   unsafe permissions, including removal of a missing file. Report damaged
///   content with [`Error::store_corrupt`]. Sealed stores also forward key
///   source errors and can report randomness failure when writing.
/// - **Names and sizes:** [`Client`](crate::Client) uses `installation` and
///   one `account-<id>` entry per account (validated [`EntryName`]s of 1 to
///   64 lowercase ASCII letters, digits and inner hyphens). A credentials
///   entry is typically a few kilobytes, and [`PrivateFiles`] caps entries at
///   256 KiB (262,144 bytes; under `Sealed` that is the sealed value, which
///   leaves 262,115 bytes of plaintext). A credentials entry can exceed the
///   item limit of some backends, such as the 2,560 bytes of a Windows
///   Credential Manager credential, so do not keep entries in such a backend
///   directly; prefer `Sealed<PrivateFiles, _>` with only the 32-byte
///   [`SealingKey`] in the keychain
///   ([`examples/keychain.rs`](https://github.com/barnerylabs/siwc/blob/v0.1.0/crates/siwc/examples/keychain.rs)).
/// - **Whole-entry writes:** [`write`](Self::write) must make the new value
///   visible as a whole or leave the previous value untouched, never a
///   truncated or half-written entry.
/// - **Cross-process locks:** when [`shared_across_processes`](Self::shared_across_processes)
///   is `true`, [`lock`](Self::lock) must exclude both threads in this
///   process and other processes sharing the store. A keychain adapter whose
///   backend offers no lock can delegate `lock` to a [`PrivateFiles`]
///   directory. Return [`Error::store_busy`] when `patience` expires while
///   another holder keeps the lock, and [`Error::store_failed`] for other
///   storage failures.
/// - **Plan request cancellation:** The built-in sealed-store key waits
///   observe cancellation when they run on the plan request's thread (the
///   worker for an async request). If an adapter forwards a cold read to
///   another thread, the request waits for it to return before reporting
///   cancellation. A call into another client uses its own store scope.
/// - **Compatibility:** a release that is not a breaking one adds no
///   required method or supertrait and keeps the trait usable as
///   `dyn Store`. A new capability, such as another kind of lock, comes as
///   a method with a default, and [`lock`](Self::lock) and [`Lock::new`]
///   keep their signatures.
///
/// ```
/// use std::time::Duration;
///
/// use siwc::store::{EntryName, MemoryStore, Store};
///
/// let store = MemoryStore::new();
/// let entry = EntryName::new("account-1")?;
///
/// let lock = store.lock(&entry, Duration::from_secs(5))?;
/// assert!(store.read(&entry)?.is_none());
/// store.write(&entry, b"synthetic value")?;
/// drop(lock);
///
/// assert_eq!(store.read(&entry)?.unwrap().expose(), b"synthetic value");
/// # Ok::<(), siwc::Error>(())
/// ```
pub trait Store: Send + Sync + fmt::Debug {
    /// Reads an entry; `Ok(None)` when the entry does not exist.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Store`](crate::ErrorKind::Store) when the entry cannot be
    /// read; a store may refuse with a more specific category, such as
    /// [`ErrorKind::StoreNotPrivate`](crate::ErrorKind::StoreNotPrivate).
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error>;

    /// Replaces the entry as a whole: a reader sees the old or the new
    /// value, never a part. A returned error may leave the new whole value
    /// visible if a check after publication failed. Callers must re-read
    /// before deciding whether to undo or revoke a newly stored session.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Store`](crate::ErrorKind::Store) when the value cannot be
    /// written or a check after publication fails. The previous or the new
    /// whole value may then be in place. File privacy checks can return
    /// `StoreNotPrivate`; sealed writes also forward key-source errors and
    /// can return `Randomness` when drawing the nonce.
    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error>;

    /// Removes an entry. Removing an entry that does not exist succeeds.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Store`](crate::ErrorKind::Store) when removal fails. File stores check
    /// directory privacy even for an absent entry and can return `StoreNotPrivate`.
    fn remove(&self, entry: &EntryName) -> Result<(), Error>;

    /// Takes the entry's exclusive lock across threads and, for a store
    /// shared between processes, across processes, waiting at most
    /// `patience`. `Duration::ZERO` tries once.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::StoreBusy`](crate::ErrorKind::StoreBusy) when someone
    /// else still holds the lock after `patience`;
    /// [`ErrorKind::Store`](crate::ErrorKind::Store) when the lock cannot be
    /// taken at all. An unsafe directory or lock can return `StoreNotPrivate`.
    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error>;

    /// Whether other processes see what this store holds, as they do for
    /// files or a keychain. Reported by [`Client::diagnose`](crate::Client::diagnose).
    /// `conformance::check` tests locking across threads only; test
    /// cross-process exclusion in the adapter's own suite.
    /// The default is `true`; [`MemoryStore`] says `false`.
    fn shared_across_processes(&self) -> bool {
        true
    }
}

/// A store behind an `Arc` is a store, so two clients can share one.
impl<T: Store + ?Sized> Store for Arc<T> {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        (**self).read(entry)
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        (**self).write(entry, value)
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        (**self).remove(entry)
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        (**self).lock(entry, patience)
    }

    fn shared_across_processes(&self) -> bool {
        (**self).shared_across_processes()
    }
}

/// A boxed store is a store, so an app can select its backend at runtime.
impl<T: Store + ?Sized> Store for Box<T> {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        (**self).read(entry)
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        (**self).write(entry, value)
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        (**self).remove(entry)
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        (**self).lock(entry, patience)
    }

    fn shared_across_processes(&self) -> bool {
        (**self).shared_across_processes()
    }
}

/// A value read from a store. Wiped when dropped; `Debug` prints only its
/// length.
///
/// ```
/// let stored = siwc::store::Stored::new(b"synthetic".to_vec());
/// assert_eq!(stored.expose(), b"synthetic");
/// assert!(!format!("{stored:?}").contains("synthetic"));
/// ```
pub struct Stored(SecretBytes);

impl Stored {
    /// Wraps the bytes a store read. A custom [`Store`] builds its result
    /// with this.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(SecretBytes::new(bytes))
    }

    /// The stored bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

impl fmt::Debug for Stored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Stored([redacted; {} bytes])", self.0.expose().len())
    }
}

/// Anything that releases a lock when it is dropped.
trait Guard {}

impl<T> Guard for T {}

/// A held lock. Dropping it releases the lock. A backend can return a
/// thread-bound guard, so keep the lock on the thread that acquired it.
///
/// ```
/// use std::time::Duration;
///
/// use siwc::store::{EntryName, MemoryStore, Store};
///
/// let store = MemoryStore::new();
/// let entry = EntryName::new("installation")?;
/// let lock = store.lock(&entry, Duration::ZERO)?;
/// assert!(store.lock(&entry, Duration::ZERO).is_err());
/// drop(lock);
/// assert!(store.lock(&entry, Duration::ZERO).is_ok());
/// # Ok::<(), siwc::Error>(())
/// ```
#[must_use = "dropping the lock releases it at once"]
pub struct Lock<'a> {
    _held: Box<dyn Guard + 'a>,
}

impl<'a> Lock<'a> {
    /// Wraps whatever releases the lock on drop, such as a mutex guard or a
    /// locked file. A custom [`Store`] builds its result with this.
    pub fn new<T: 'a>(guard: T) -> Self {
        Self {
            _held: Box::new(guard),
        }
    }
}

impl fmt::Debug for Lock<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lock")
    }
}
