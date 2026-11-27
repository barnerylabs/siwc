//! Passphrase-sealed single-account bundle for moving a session to another host.

use std::fmt;
use std::num::NonZeroU32;

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA512};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::entropy::Entropy;
use crate::error::{Error, ErrorKind};
use crate::protocol::{Credentials, Identity, IssuedClientId, base64url, json};

use super::records::{AccountRecord, app_name, is_label};

#[cfg(all(test, feature = "testing"))]
mod tests;

/// Magic header and format version (`1`).
const MAGIC: &[u8; 8] = b"SIWCBUN1";

/// Random PBKDF2 salt length in bytes.
const SALT_LEN: usize = 16;

/// Poly1305 tag length in bytes.
const TAG_LEN: usize = 16;

/// Fixed header length before ciphertext (`MAGIC` + salt + AEAD nonce).
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;

/// OWASP-recommended iteration count for PBKDF2-HMAC-SHA512; fixed in code so
/// an untrusted bundle cannot choose an expensive work factor.
const PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(210_000).expect("non-zero iteration count");

/// Shortest passphrase accepted when sealing or opening a bundle.
const MIN_PASSPHRASE_LEN: usize = 8;

/// Longest passphrase accepted when sealing or opening a bundle.
const MAX_PASSPHRASE_LEN: usize = 1024;

/// Largest sealed bundle accepted on export or import (96 KiB).
pub(super) const MAX_BUNDLE_LEN: usize = 96 * 1024;

/// Budget shared by all serialized payload members.
const PAYLOAD_LIMIT: usize = MAX_BUNDLE_LEN - HEADER_LEN - TAG_LEN;

const PAYLOAD_VERSION: u64 = 1;
const PAYLOAD_MEMBERS: [&str; 7] = [
    "v",
    "client_id",
    "registered_as",
    "label",
    "identity",
    "welcomed",
    "credentials",
];

/// One signed-in account sealed under a caller-supplied passphrase, as
/// [`Client::export_account_to`](crate::Client::export_account_to) writes it
/// to its file. Dropping the bundle wipes its buffer, and `Debug` prints
/// only its byte length.
///
/// The passphrase is stretched with PBKDF2-HMAC-SHA512 (210,000 iterations,
/// random salt) and the bundle is sealed with ChaCha20-Poly1305.
#[must_use]
pub(crate) struct AccountBundle(Zeroizing<Vec<u8>>);

impl AccountBundle {
    /// The encrypted bundle bytes, as export writes them to its file.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for AccountBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountBundle([redacted; {} bytes])", self.0.len())
    }
}

/// Contents of an opened bundle before storing on the target machine.
pub(super) struct UnpackedAccount {
    pub(super) client_id: IssuedClientId,
    pub(super) registered_as: String,
    pub(super) label: Option<String>,
    pub(super) welcomed: bool,
    pub(super) credentials: Credentials,
}

/// Validates passphrase length (`8..=1024` bytes).
pub(super) fn check_passphrase(passphrase: &[u8]) -> Result<(), Error> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the bundle passphrase must be at least 8 bytes",
        ));
    }
    if passphrase.len() > MAX_PASSPHRASE_LEN {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the bundle passphrase is longer than 1024 bytes",
        ));
    }
    Ok(())
}

/// Validates outer bundle size and magic before running PBKDF2.
fn check_bundle_envelope(bundle: &[u8]) -> Result<(), Error> {
    if bundle.len() < HEADER_LEN + TAG_LEN
        || bundle.len() > MAX_BUNDLE_LEN
        || !bundle.starts_with(MAGIC)
    {
        return Err(bundle_rejected());
    }
    Ok(())
}

fn bundle_rejected() -> Error {
    Error::new(
        ErrorKind::BundleRejected,
        "the account bundle could not be opened; check the passphrase and the file",
    )
}

/// Encodes and encrypts `account` under `passphrase` using a fresh random salt
/// and nonce from `entropy`.
pub(super) fn seal(
    account: &AccountRecord,
    credentials: &Credentials,
    passphrase: &[u8],
    entropy: &dyn Entropy,
) -> Result<AccountBundle, Error> {
    check_passphrase(passphrase)?;
    let mut salt = [0u8; SALT_LEN];
    entropy.fill(&mut salt)?;
    let mut nonce = [0u8; NONCE_LEN];
    entropy.fill(&mut nonce)?;

    let plaintext = encode_payload(account, credentials)?;
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::derive(
        PBKDF2_HMAC_SHA512,
        PBKDF2_ITERATIONS,
        &salt,
        passphrase,
        &mut *key,
    );

    let mut out = Zeroizing::new(Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&plaintext);

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &*key).map_err(|_| Error::store_failed())?;
    let tag = LessSafeKey::new(unbound)
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            associated_data(&salt),
            &mut out[HEADER_LEN..],
        )
        .map_err(|_| Error::store_failed())?;
    out.extend_from_slice(tag.as_ref());
    Ok(AccountBundle(out))
}

/// Verifies and decrypts `bundle` under `passphrase` and validates its inner
/// account record and credentials.
pub(super) fn open(bundle: &[u8], passphrase: &[u8]) -> Result<UnpackedAccount, Error> {
    check_passphrase(passphrase)?;
    check_bundle_envelope(bundle)?;
    let salt = bundle
        .get(MAGIC.len()..MAGIC.len() + SALT_LEN)
        .ok_or_else(bundle_rejected)?;
    let nonce_bytes = bundle
        .get(MAGIC.len() + SALT_LEN..HEADER_LEN)
        .ok_or_else(bundle_rejected)?;
    let body = bundle.get(HEADER_LEN..).ok_or_else(bundle_rejected)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| bundle_rejected())?;

    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::derive(
        PBKDF2_HMAC_SHA512,
        PBKDF2_ITERATIONS,
        salt,
        passphrase,
        &mut *key,
    );

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &*key).map_err(|_| bundle_rejected())?;
    let mut buffer = Zeroizing::new(body.to_vec());
    let plain_len = LessSafeKey::new(unbound)
        .open_in_place(nonce, associated_data(salt), &mut buffer)
        .map_err(|_| bundle_rejected())?
        .len();
    buffer.truncate(plain_len);
    decode_payload(&buffer).ok_or_else(bundle_rejected)
}

fn associated_data(salt: &[u8]) -> Aad<[u8; MAGIC.len() + SALT_LEN]> {
    let mut aad = [0u8; MAGIC.len() + SALT_LEN];
    aad[..MAGIC.len()].copy_from_slice(MAGIC);
    aad[MAGIC.len()..].copy_from_slice(salt);
    Aad::from(aad)
}

fn encode_payload(
    account: &AccountRecord,
    credentials: &Credentials,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let stored = credentials.to_stored();
    let mut encoded_creds = Zeroizing::new(base64url::encode(stored.expose()));
    let mut object = Map::new();
    object.insert("v".to_owned(), PAYLOAD_VERSION.into());
    object.insert("client_id".to_owned(), account.client_id.as_str().into());
    object.insert(
        "registered_as".to_owned(),
        account.registered_as.as_str().into(),
    );
    object.insert(
        "label".to_owned(),
        account.label.as_deref().map_or(Value::Null, Value::from),
    );
    object.insert("identity".to_owned(), account.identity.to_record());
    object.insert("welcomed".to_owned(), account.welcomed.into());
    object.insert(
        "credentials".to_owned(),
        Value::String(std::mem::take(&mut *encoded_creds)),
    );
    // Keep `object` inside `document` so `Drop` wipes every string in place.
    let document = json::Document(object);
    let limit = PAYLOAD_LIMIT;
    let mut bytes = Zeroizing::new(vec![0; limit]);
    let mut remaining = bytes.as_mut_slice();
    serde_json::to_writer(&mut remaining, &document.0).map_err(|_| {
        Error::new(
            ErrorKind::Store,
            "the stored session exceeds the bundle size limit",
        )
    })?;
    let written = limit - remaining.len();
    bytes.truncate(written);
    Ok(bytes)
}

fn decode_payload(bytes: &[u8]) -> Option<UnpackedAccount> {
    if bytes.len() > MAX_BUNDLE_LEN {
        return None;
    }
    let mut document = json::Document(json::object(bytes)?);
    let object = &mut document.0;
    if !json::exact(object, &PAYLOAD_MEMBERS) || object.get("v")?.as_u64()? != PAYLOAD_VERSION {
        return None;
    }
    let client_id = IssuedClientId::parse(object.get("client_id")?.as_str()?).ok()?;
    let registered_as = app_name(object.get("registered_as")?)?;
    let label = match object.get("label")? {
        Value::Null => None,
        Value::String(text) if is_label(text) => Some(text.clone()),
        _ => return None,
    };
    // Keep checking the legacy member for format and subject consistency.
    // Only the separately verified ID token supplies the imported identity.
    let identity = Identity::from_record(object.get("identity")?)?;
    let welcomed = object.get("welcomed")?.as_bool()?;
    let creds_b64 = Zeroizing::new(json::take_text(object, "credentials", PAYLOAD_LIMIT).ok()??);
    let creds_bytes = Zeroizing::new(base64url::decode(&creds_b64)?);
    let credentials = Credentials::from_stored(&creds_bytes).ok()?;
    if *credentials.client_id() != client_id || credentials.subject() != identity.subject() {
        return None;
    }
    Some(UnpackedAccount {
        client_id,
        registered_as,
        label,
        welcomed,
        credentials,
    })
}

/// Exercises bundle envelope checks and inner payload parsing for cargo-fuzz harnesses.
#[cfg(fuzzing)]
pub(crate) fn fuzz_bundle(data: &[u8]) {
    let _envelope = check_bundle_envelope(data);
    let _payload = decode_payload(data);
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn passphrase_endpoints_and_outer_size_are_checked_before_derivation() {
        for len in [8, 1024] {
            assert!(check_passphrase(&vec![0; len]).is_ok());
        }
        let mut envelope = MAGIC.to_vec();
        envelope.resize(MAX_BUNDLE_LEN, 0);
        assert!(check_bundle_envelope(&envelope).is_ok());
        envelope.push(0);
        assert_eq!(
            check_bundle_envelope(&envelope).unwrap_err().kind(),
            ErrorKind::BundleRejected
        );
    }
}
