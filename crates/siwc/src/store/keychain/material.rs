//! Reading and creating key material through a platform backend.

use zeroize::{Zeroize, Zeroizing};

use crate::cancel::Canceller;
use crate::entropy::Entropy;
use crate::error::{Error, ErrorKind};
use crate::store::sealed::require_nonzero_key;
use crate::store::{KEY_LEN, RetiredKeys, reading};

use super::{ServiceName, deadline::ResetDeadline, key_text};

/// Waiting policy for a read-only keychain lookup.
#[derive(Clone, Copy, Default)]
pub(super) struct Lookup<'a> {
    pub(super) stop: Option<&'a Canceller>,
    pub(super) reset: Option<&'a ResetDeadline<'a>>,
}

impl<'a> Lookup<'a> {
    pub(super) fn cancellable(stop: Option<&'a Canceller>) -> Self {
        Self { stop, reset: None }
    }

    fn read(
        self,
        backend: &impl Backend,
        service: &ServiceName,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        if self.stop.is_some_and(Canceller::is_cancelled) {
            return Err(reading::cancelled());
        }
        if let Some(deadline) = self.reset {
            deadline.check()?;
        }
        let result = backend.find(service, self);
        if let Some(deadline) = self.reset {
            // The native Windows lookup is synchronous and cannot be interrupted.
            deadline.check()?;
        }
        result
    }
}

/// One keychain, as the platform's tool reaches it.
pub(super) trait Backend {
    /// The text stored for `service`; `None` only when the backend has
    /// established that there is no item. An item it cannot read, for
    /// example in a locked keychain, is an error, never `None`.
    fn find(
        &self,
        service: &ServiceName,
        lookup: Lookup<'_>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error>;

    /// Stores `text` for `service`, where there is no item yet.
    fn add(&self, service: &ServiceName, text: &[u8]) -> Result<(), Error>;
}

/// Reads the key for `service` from `backend`, or creates one from
/// `entropy`, stores it and reads it back. Returns whether it created a key.
pub(super) fn fill_from(
    backend: &impl Backend,
    service: &ServiceName,
    entropy: &impl Entropy,
    stop: Option<&Canceller>,
    key: &mut [u8; KEY_LEN],
    before_create: impl FnOnce() -> Result<(), Error>,
) -> Result<bool, Error> {
    if find_key(backend, service, Lookup::cancellable(stop), key)? {
        return Ok(false);
    }
    before_create()?;
    entropy.fill(key).inspect_err(|_| key.zeroize())?;
    require_nonzero_key(key)?;
    let text = key_text::encode(key);
    if stop.is_some_and(Canceller::is_cancelled) {
        key.zeroize();
        return Err(reading::cancelled());
    }
    // Once creation begins, read back the stored key even if the plan
    // request was cancelled in the meantime.
    backend.add(service, &text).inspect_err(|_| key.zeroize())?;
    match backend.find(service, Lookup::default()) {
        Ok(Some(stored)) if stored.trim_ascii() == text.as_slice() => Ok(true),
        Ok(_) => {
            key.zeroize();
            Err(Error::new(
                ErrorKind::Store,
                "the keychain did not keep the new sealing key",
            ))
        }
        Err(err) => {
            key.zeroize();
            Err(err)
        }
    }
}

/// Reads a single existing key without creating one.
pub(super) fn find_key(
    backend: &impl Backend,
    service: &ServiceName,
    lookup: Lookup<'_>,
    key: &mut [u8; KEY_LEN],
) -> Result<bool, Error> {
    let Some(text) = lookup.read(backend, service)? else {
        return Ok(false);
    };
    decode_key(&text, key)?;
    Ok(true)
}

fn decode_key(text: &[u8], key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
    if key_text::decode(text, key) {
        require_nonzero_key(key)
    } else {
        Err(Error::new(
            ErrorKind::Store,
            "the keychain item holds no sealing key",
        ))
    }
}

/// Reads any existing retired keys from `backend` without creating missing
/// items.
pub(super) fn fill_retired_from(
    backend: &impl Backend,
    retired: &[ServiceName],
    lookup: Lookup<'_>,
    keys: &mut RetiredKeys<'_>,
) -> Result<(), Error> {
    for service in retired {
        let Some(text) = lookup.read(backend, service)? else {
            continue;
        };
        keys.add(|slot| decode_key(&text, slot))?;
    }
    Ok(())
}
