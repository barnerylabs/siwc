//! Collecting retired sealing keys into wiped buffers owned by the crate.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind};

use super::{KEY_LEN, require_nonzero_key};

/// Most retired keys one [`SealingKey`](super::SealingKey) may supply.
pub const MAX_RETIRED_KEYS: usize = 8;

/// Receives retired 32-byte keys inside [`SealingKey::fill_retired`](super::SealingKey::fill_retired).
///
/// Each key is written directly into a buffer that [`Sealed`](super::Sealed)
/// owns and wipes.
///
/// ```
/// use siwc::store::{KEY_LEN, KeyGeneration, RetiredKeys, SealingKey};
///
/// struct Rotated;
///
/// impl SealingKey for Rotated {
///     fn lock_generation(&self) -> Result<KeyGeneration<'_>, siwc::Error> {
///         Ok(KeyGeneration::new(0, None))
///     }
///
///     fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), siwc::Error> {
///         key.fill(0x22);
///         Ok(())
///     }
///
///     fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), siwc::Error> {
///         keys.add(|key| {
///             key.fill(0x11);
///             Ok(())
///         })
///     }
/// }
/// ```
pub struct RetiredKeys<'a> {
    keys: &'a mut Vec<Zeroizing<[u8; KEY_LEN]>>,
}

impl<'a> RetiredKeys<'a> {
    pub(crate) fn new(keys: &'a mut Vec<Zeroizing<[u8; KEY_LEN]>>) -> Self {
        Self { keys }
    }

    /// Allocates one wiped 32-byte buffer and passes it to `fill` to populate.
    ///
    /// At most [`MAX_RETIRED_KEYS`] keys may be added.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when more than [`MAX_RETIRED_KEYS`] keys are
    /// added, [`ErrorKind::Store`] when the key is all zero bytes, or whatever
    /// `fill` returns. The buffer is wiped and discarded on error.
    pub fn add(
        &mut self,
        fill: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.keys.len() >= MAX_RETIRED_KEYS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "too many retired sealing keys",
            ));
        }
        if self.keys.capacity() < MAX_RETIRED_KEYS {
            self.keys.reserve(MAX_RETIRED_KEYS - self.keys.len());
        }
        let index = self.keys.len();
        self.keys.push(Zeroizing::new([0; KEY_LEN]));
        let key = &mut self.keys[index];
        if let Err(error) = fill(key).and_then(|()| require_nonzero_key(key)) {
            self.keys.truncate(index);
            return Err(error);
        }
        Ok(())
    }
}

impl fmt::Debug for RetiredKeys<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetiredKeys")
            .field("len", &self.keys.len())
            .finish()
    }
}
