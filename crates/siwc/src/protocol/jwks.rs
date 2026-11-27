//! The provider's published signing keys.

use std::fmt;

use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde_json::Value;

use crate::error::{Error, ErrorKind};

use super::http::{HttpRequest, HttpResponse};
use super::{JWKS_URL, base64url, json, provider_error};

/// Most signing keys kept from one key set.
const MAX_KEYS: usize = 32;

/// The provider's signing keys, fetched over HTTPS from its fixed JWKS URL.
///
/// Fetch a fresh set for every sign-in: the request is one small `GET`, and
/// a fresh set holds a key the provider has just rotated in. Only the first
/// 32 supported signing keys of a set are kept.
///
/// ```no_run
/// # fn send(_: siwc::protocol::HttpRequest) -> siwc::protocol::HttpResponse { todo!() }
/// use siwc::protocol::Jwks;
///
/// let keys = Jwks::from_response(&send(Jwks::request()))?;
/// # Ok::<(), siwc::Error>(())
/// ```
pub struct Jwks {
    keys: Vec<Key>,
}

struct Key {
    id: Option<String>,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

impl Jwks {
    /// The request that fetches the key set.
    #[must_use]
    pub fn request() -> HttpRequest {
        HttpRequest::get(JWKS_URL)
    }

    /// Reads the key set from the provider's answer.
    ///
    /// Keys that are not RSA signing keys for RS256 are skipped.
    /// During a sign-in, use
    /// [`Unverified::keys_from_response`](super::Unverified::keys_from_response)
    /// to keep any echoes of the new tokens out of errors.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Temporary`] for a server error, a rate limit (`429`) or a
    /// request timeout (`408`), otherwise
    /// [`ErrorKind::InvalidResponse`] when the answer is not a key set.
    pub fn from_response(response: &HttpResponse) -> Result<Self, Error> {
        if response.status() != 200 {
            let kind = if provider_error::is_temporary(response.status()) {
                ErrorKind::Temporary
            } else {
                ErrorKind::InvalidResponse
            };
            return Err(
                Error::new(kind, "the provider did not return its signing keys")
                    .with_response(response),
            );
        }
        let invalid = || {
            Error::new(
                ErrorKind::InvalidResponse,
                "the signing key set is malformed",
            )
        };
        let object = json::object(response.body()).ok_or_else(invalid)?;
        let Some(Value::Array(entries)) = object.get("keys") else {
            return Err(invalid());
        };
        let keys = entries
            .iter()
            .filter_map(rsa_signing_key)
            .take(MAX_KEYS)
            .collect();
        Ok(Self { keys })
    }

    /// Verifies an RS256 signature with any published RSA key named
    /// `key_id`.
    ///
    /// A token without a key ID is only accepted while the set holds a single
    /// key; guessing among several would let any of them sign.
    pub(crate) fn verify(
        &self,
        key_id: Option<&str>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError> {
        let candidates: &[Key] = match key_id {
            Some(_) => &self.keys,
            None if self.keys.len() == 1 => &self.keys,
            None => &[],
        };
        let mut matched = false;
        for key in candidates {
            if key_id.is_some_and(|id| key.id.as_deref() != Some(id)) {
                continue;
            }
            matched = true;
            let public_key = RsaPublicKeyComponents {
                n: &key.modulus,
                e: &key.exponent,
            };
            if public_key
                .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok()
            {
                return Ok(());
            }
        }
        if matched {
            Err(SignatureError::Invalid)
        } else {
            Err(SignatureError::UnknownKey)
        }
    }
}

impl fmt::Debug for Jwks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jwks")
            .field("key_count", &self.keys.len())
            .finish()
    }
}

pub(crate) enum SignatureError {
    /// The set holds no key for the token.
    UnknownKey,
    /// The key does not confirm the signature.
    Invalid,
}

fn rsa_signing_key(entry: &Value) -> Option<Key> {
    let entry = entry.as_object()?;
    let is = |name, expected| {
        entry
            .get(name)
            .is_none_or(|value| value.is_null() || value.as_str() == Some(expected))
    };
    let allows_verify = entry.get("key_ops").is_none_or(|ops| {
        ops.is_null()
            || ops
                .as_array()
                .is_some_and(|list| list.iter().any(|op| op.as_str() == Some("verify")))
    });
    if json::string(entry, "kty") != Some("RSA")
        || !is("use", "sig")
        || !is("alg", "RS256")
        || !allows_verify
    {
        return None;
    }
    Some(Key {
        id: json::string(entry, "kid").map(str::to_owned),
        modulus: unsigned(json::string(entry, "n")?)?,
        exponent: unsigned(json::string(entry, "e")?)?,
    })
}

/// A big-endian unsigned integer without leading zero bytes.
fn unsigned(encoded: &str) -> Option<Vec<u8>> {
    let bytes = base64url::decode(encoded)?;
    let leading_zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
    let digits = bytes
        .get(leading_zeros..)
        .filter(|digits| !digits.is_empty())?;
    Some(digits.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rsa_signing_key_enforces_key_ops_when_present() {
        let valid_without_ops = json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "k1",
            "n": "AQAB",
            "e": "AQAB",
        });
        assert!(rsa_signing_key(&valid_without_ops).is_some());

        let with_verify = json!({
            "kty": "RSA",
            "key_ops": ["verify"],
            "n": "AQAB",
            "e": "AQAB",
        });
        assert!(rsa_signing_key(&with_verify).is_some());

        let sign_only = json!({
            "kty": "RSA",
            "key_ops": ["sign"],
            "n": "AQAB",
            "e": "AQAB",
        });
        assert!(rsa_signing_key(&sign_only).is_none());

        let non_array_ops = json!({
            "kty": "RSA",
            "key_ops": "verify",
            "n": "AQAB",
            "e": "AQAB",
        });
        assert!(rsa_signing_key(&non_array_ops).is_none());
    }
}
