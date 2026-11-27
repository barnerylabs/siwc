//! The source of a sealed store's active and retired keys.

use std::fmt;

use crate::error::{Error, ErrorKind};
#[cfg(feature = "keychain")]
use crate::store::Keychain;
use crate::store::Lock;

use super::{KEY_LEN, RetiredKeys};

/// Where a [`Sealed`](super::Sealed) store gets its key, such as an item in the system
/// keychain. The app implements it.
///
/// The built-in keychain waits observe plan request cancellation when they
/// run on the plan request's thread (the worker for an async request). If
/// an implementation forwards a cold key read to another thread, the
/// request waits for that read to return before reporting cancellation.
/// The client never interrupts `fill` or `fill_retired` itself; only the
/// waits for the key cache and the built-in keychain's lock observe it.
/// Forwarding adapters delegate the methods below, including the entire
/// result of [`lock_generation`](Self::lock_generation). A coordinated
/// keychain adapter must leave key bytes unchanged: crossing writes read
/// the keychain directly under its lock and do not call the adapter's
/// `fill` or `refill_after_write` methods. An adapter may run `fill` and
/// `fill_retired` on another thread while forwarding the generation intact.
/// A keychain-coordinated entry records that requirement in its authenticated
/// header. An adapter that drops coordination cannot read it, even with a
/// cached key, and gets [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput).
/// This detects lost coordination only for entries written with it. An
/// adapter that rebuilds the generation from its number from the first
/// sign-in writes uncoordinated entries and cannot be detected this way;
/// that adapter violates this trait's forwarding contract.
///
/// **Compatibility:** a release that is not a breaking one adds no required
/// method or supertrait and keeps the trait usable as `dyn SealingKey`.
/// It also adds no method whose default would quietly decide which keys
/// open an entry, as an empty `fill_retired` would. Extra coordination
/// travels inside [`KeyGeneration`], and a capability a key source has to
/// provide comes as a separate opt-in interface.
///
/// ```
/// use siwc::store::{KEY_LEN, KeyGeneration, SealingKey};
///
/// /// A fixed key, for this example only: a real key comes from the
/// /// keychain and is random.
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
/// ```
pub trait SealingKey: Send + Sync {
    /// Writes the 32-byte key into `key`, a buffer the store wipes when it
    /// is dropped. A key of all zero bytes, including an unfilled buffer,
    /// makes the store return [`ErrorKind::Store`](crate::ErrorKind::Store).
    ///
    /// The store calls this on ordinary key loads when it first needs the
    /// key, after a failed fetch, or when the cached key is stale. A write
    /// crossing a built-in keychain generation reads that keychain directly
    /// under its lock instead. This call may ask the user to unlock the
    /// keychain.
    ///
    /// # Errors
    ///
    /// Whatever the key's source reports; the store returns it to its
    /// caller unchanged. [`Error::store_failed`] fits a keychain that
    /// cannot be read.
    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error>;

    /// Writes any retired 32-byte keys into `keys`, in the order they should
    /// be tried when a stored entry does not open under [`fill`](Self::fill).
    ///
    /// Ordinary writes seal under [`fill`](Self::fill). [`Sealed`](super::Sealed)
    /// calls this at most once per generation, only after an entry in the
    /// sealed format failed to open under the active key (or during
    /// [`Sealed::reseal`](super::Sealed::reseal)).
    /// A failed call is retried on the next read that needs retired keys.
    /// Implementations with no retired keys return `Ok(())` explicitly.
    /// Call [`Sealed::reseal`](super::Sealed::reseal) to rewrite retired entries under the active
    /// key so the retired key can later be removed.
    ///
    /// # Errors
    ///
    /// Whatever the key source reports; returned to the caller unchanged.
    /// [`RetiredKeys::add`] refuses a key of all zero bytes.
    fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error>;

    /// Reports the generation of the keys this source fills, and optionally
    /// returns a lock that prevents it from changing while held.
    ///
    /// A fixed source returns `KeyGeneration::new(0, None)`, so its keys
    /// stay cached. A source with reset support advances the generation
    /// before discarding or replacing keys and never reuses a generation.
    /// `Sealed` checks before using cached keys. It holds a supplied lock
    /// through the inner store's write. Without one it checks again after
    /// the write and resolves any generation change before it returns.
    /// It drops any guard before fetching keys and checks the generation
    /// again before using the results. Repeated changes fail with
    /// [`ErrorKind::Store`](crate::ErrorKind::Store).
    ///
    /// An adapter that wraps another `SealingKey` must forward this method's
    /// entire result. The built-in keychain attaches reset coordination and
    /// service information to it, in addition to the generation number.
    /// Every read of a keychain-coordinated entry checks for this information
    /// before decryption, including on a cache hit. Rebuilding the result
    /// from its number from first use writes entries without this marker and
    /// breaks the forwarding contract without a detectable error.
    ///
    /// # Errors
    ///
    /// If the generation could not be read or its lock could not be taken,
    /// the error is returned without using the cached keys.
    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error>;

    /// Refills the active key when a write finished under an earlier
    /// generation for a source without built-in keychain coordination. The
    /// default calls [`fill`](Self::fill). A coordinated crossing write uses
    /// the keychain directly and does not call an adapter's override.
    ///
    /// `previous_key` is the key that sealed the write. A source can use it
    /// to recognize ciphertext published across an explicitly approved
    /// reset. The store still checks the generation before using the result.
    ///
    /// # Errors
    ///
    /// Whatever the source reports, as with [`fill`](Self::fill).
    fn refill_after_write(
        &self,
        key: &mut [u8; KEY_LEN],
        _previous_generation: u64,
        _previous_key: &[u8; KEY_LEN],
    ) -> Result<(), Error> {
        self.fill(key)
    }
}

/// The generation of a [`SealingKey`], with its optional lock.
/// Forward this value intact when adapting a key source. The coordinated
/// envelope header requires its keychain information on every read, whether
/// the key is cached or loaded cold. An adapter that strips the information
/// from first use writes entries without that marker and violates the
/// forwarding contract without being detected.
///
/// ```
/// use siwc::store::KeyGeneration;
///
/// let fixed = KeyGeneration::new(0, None);
/// assert_eq!(fixed.number(), 0);
/// ```
#[must_use]
pub struct KeyGeneration<'a> {
    number: u64,
    pub(super) guard: Option<Lock<'a>>,
    #[cfg(feature = "keychain")]
    pub(super) keychain: Option<&'a Keychain>,
}

impl<'a> KeyGeneration<'a> {
    /// Describes a custom source's generation. If supplied, `guard` must
    /// prevent the generation from changing until it is dropped. An adapter
    /// around another source must forward its generation intact; use
    /// [`with_guard`](Self::with_guard) to add a guard without discarding
    /// keychain coordination. Rebuilding a keychain generation from its
    /// number makes reads of entries written with coordination fail with
    /// `InvalidInput`, including cache hits. If the adapter does this from
    /// its first use, no coordinated entry exists to expose the error.
    pub const fn new(number: u64, guard: Option<Lock<'a>>) -> Self {
        Self {
            number,
            guard,
            #[cfg(feature = "keychain")]
            keychain: None,
        }
    }

    /// The source's generation number.
    #[must_use]
    pub const fn number(&self) -> u64 {
        self.number
    }

    pub(super) fn is_keychain_coordinated(&self) -> bool {
        #[cfg(feature = "keychain")]
        {
            self.keychain.is_some()
        }
        #[cfg(not(feature = "keychain"))]
        {
            false
        }
    }

    /// Adds a lock to a forwarded generation without losing the source's
    /// keychain coordination. The lock must prevent this generation from
    /// changing until it is dropped.
    pub fn with_guard(mut self, guard: Lock<'a>) -> Self {
        self.guard = Some(match self.guard.take() {
            Some(previous) => Lock::new((previous, guard)),
            None => guard,
        });
        self
    }

    #[cfg(feature = "keychain")]
    pub(in crate::store) fn coordinated(number: u64, keychain: &'a Keychain) -> Self {
        Self {
            number,
            guard: None,
            keychain: Some(keychain),
        }
    }

    pub(super) fn open_error(&self, error: Error) -> Error {
        #[cfg(feature = "keychain")]
        if error.kind() == crate::ErrorKind::StoreCorrupt
            && let Some(keychain) = self.keychain
            && let Err(service_error) = keychain.require_readable_service()
        {
            return service_error;
        }
        error
    }
}

pub(super) fn lost_coordination() -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        "the sealing key adapter lost keychain generation coordination",
    )
}

impl fmt::Debug for KeyGeneration<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyGeneration")
            .field("number", &self.number)
            .finish_non_exhaustive()
    }
}

impl<T: SealingKey + ?Sized> SealingKey for std::sync::Arc<T> {
    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        (**self).fill(key)
    }

    fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        (**self).fill_retired(keys)
    }

    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        (**self).lock_generation()
    }

    fn refill_after_write(
        &self,
        key: &mut [u8; KEY_LEN],
        previous_generation: u64,
        previous_key: &[u8; KEY_LEN],
    ) -> Result<(), Error> {
        (**self).refill_after_write(key, previous_generation, previous_key)
    }
}

impl<T: SealingKey + ?Sized> SealingKey for Box<T> {
    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        (**self).fill(key)
    }

    fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        (**self).fill_retired(keys)
    }

    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        (**self).lock_generation()
    }

    fn refill_after_write(
        &self,
        key: &mut [u8; KEY_LEN],
        previous_generation: u64,
        previous_key: &[u8; KEY_LEN],
    ) -> Result<(), Error> {
        (**self).refill_after_write(key, previous_generation, previous_key)
    }
}
