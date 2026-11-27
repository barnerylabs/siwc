//! A sealed value has a version byte, nonce, and ChaCha20-Poly1305 value.
//! Version 1 uses a custom source; version 2 requires keychain coordination.
//! The version and entry name are authenticated as associated data.

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::store::EntryName;

/// The length of a [`SealingKey`](super::SealingKey) in bytes.
pub const KEY_LEN: usize = 32;

/// The length of the random nonce that precedes each value.
pub(super) const NONCE_BYTES: usize = NONCE_LEN;

/// The authenticated header identifies whether the key needs keychain
/// generation coordination. Both formats are written by this release.
const FIXED_KEY: u8 = 1;
const KEYCHAIN_KEY: u8 = 2;

/// The version byte and the nonce.
const HEADER_LEN: usize = 1 + NONCE_LEN;

/// The Poly1305 tag after the encrypted value.
const TAG_LEN: usize = 16;

pub(in crate::store) const MIN_ENVELOPE_LEN: usize = HEADER_LEN + TAG_LEN;

/// Whether `stored` is in this format's version, without opening it. A
/// value written before the store was sealed, such as the client's JSON,
/// starts with another byte.
pub(in crate::store) fn is_sealed(stored: &[u8]) -> bool {
    matches!(stored.first(), Some(&FIXED_KEY) | Some(&KEYCHAIN_KEY))
}

/// Future versions use ASCII control bytes outside JSON whitespace and
/// have room for at least a version, nonce and authentication tag.
pub(in crate::store) fn is_reserved(stored: &[u8]) -> bool {
    stored.len() >= MIN_ENVELOPE_LEN && matches!(stored.first(), Some(3..=8 | 11..=12 | 14..=31))
}

pub(super) fn check_version(stored: &[u8]) -> Result<(), Error> {
    if is_reserved(stored) {
        return Err(Error::unsupported_format());
    }
    Ok(())
}

pub(super) fn requires_keychain(stored: &[u8]) -> Result<bool, OpenFailure> {
    if stored.len() < HEADER_LEN + TAG_LEN {
        return Err(OpenFailure::UnknownFormat);
    }
    match stored.first() {
        Some(&FIXED_KEY) => Ok(false),
        Some(&KEYCHAIN_KEY) => Ok(true),
        _ => Err(OpenFailure::UnknownFormat),
    }
}

/// Encrypts `value` for `entry` under `key` with a nonce the caller drew
/// at random. The result is written into one buffer of its final size.
pub(super) fn seal(
    key: &[u8; KEY_LEN],
    entry: &EntryName,
    nonce: [u8; NONCE_LEN],
    value: &[u8],
    keychain_coordinated: bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let version = if keychain_coordinated {
        KEYCHAIN_KEY
    } else {
        FIXED_KEY
    };
    let mut sealed = Zeroizing::new(Vec::with_capacity(HEADER_LEN + value.len() + TAG_LEN));
    sealed.push(version);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(value);
    let tag = cipher(key)?
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            associated_data(version, entry),
            &mut sealed[HEADER_LEN..],
        )
        // Only a value of more than 256 GiB cannot be sealed.
        .map_err(|_| Error::store_failed())?;
    sealed.extend_from_slice(tag.as_ref());
    Ok(sealed)
}

/// Why a sealed value did not open.
pub(super) enum OpenFailure {
    /// Too short or another envelope version; no key can open it.
    UnknownFormat,
    /// Valid envelope header, but authentication failed under this key or entry.
    WrongKey,
    /// Cipher construction failed.
    CipherFailed,
}

impl OpenFailure {
    pub(super) fn into_error(self) -> Error {
        match self {
            Self::UnknownFormat => Error::corrupt_entry(
                "the stored value is not sealed in a format this version reads",
            ),
            Self::WrongKey => Error::corrupt_entry(
                "the stored value does not open with the sealing key for its entry",
            ),
            Self::CipherFailed => Error::store_failed(),
        }
    }
}

/// Decrypts what [`seal`] wrote for `entry` under `key`. A value that is
/// too short, has another version, was changed, belongs to another entry
/// or was sealed under another key does not open.
pub(super) fn open_checked(
    key: &[u8; KEY_LEN],
    entry: &EntryName,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpenFailure> {
    let (&version, rest) = sealed.split_first().ok_or(OpenFailure::UnknownFormat)?;
    let (nonce, body) = rest
        .split_at_checked(NONCE_LEN)
        .ok_or(OpenFailure::UnknownFormat)?;
    if !matches!(version, FIXED_KEY | KEYCHAIN_KEY) || body.len() < TAG_LEN {
        return Err(OpenFailure::UnknownFormat);
    }
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| OpenFailure::UnknownFormat)?;
    let mut value = Zeroizing::new(body.to_vec());
    let len = cipher(key)
        .map_err(|_| OpenFailure::CipherFailed)?
        .open_in_place(nonce, associated_data(version, entry), &mut value)
        .map_err(|_| OpenFailure::WrongKey)?
        .len();
    value.truncate(len);
    Ok(value)
}

/// The cipher under `key`. The copy of the key inside it is not wiped.
fn cipher(key: &[u8; KEY_LEN]) -> Result<LessSafeKey, Error> {
    UnboundKey::new(&CHACHA20_POLY1305, key)
        .map(LessSafeKey::new)
        .map_err(|_| Error::store_failed())
}

/// The version byte followed by the entry's name.
fn associated_data(version: u8, entry: &EntryName) -> Aad<Vec<u8>> {
    let name = entry.as_str().as_bytes();
    let mut data = Vec::with_capacity(1 + name.len());
    data.push(version);
    data.extend_from_slice(name);
    Aad::from(data)
}
