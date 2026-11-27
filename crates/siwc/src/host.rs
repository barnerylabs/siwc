//! The stable identifier of an app installation (`ext_agent_host_id`).

use std::fmt;
use std::str::FromStr;

use crate::entropy::{Entropy, OsEntropy};
use crate::error::{Error, ErrorKind};
use crate::hex;

const UUID_PREFIX: &str = "urn:uuid:";
const THUMBPRINT_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:";
const DID_KEY_PREFIX: &str = "did:key:z";
const MAX_LEN: usize = 256;

/// The stable, opaque identifier of one installation of the app.
///
/// [`Client`](crate::Client) generates and stores a `HostId` automatically in
/// its installation record and sends it as `ext_agent_host_id`, unless
/// [`ClientBuilder::send_host_id`](crate::ClientBuilder::send_host_id) turns
/// that off.
/// Callers driving [`protocol::Attempt::start`](crate::protocol::Attempt::start)
/// directly generate one once, store it apart from credentials, and pass
/// `Option<&HostId>` as needed. Only the forms the provider documents can be
/// built: a random UUID, a JWK thumbprint or a `did:key`. An e-mail address or
/// user ID does not parse.
///
/// ```
/// let host = siwc::HostId::generate(&siwc::OsEntropy)?;
/// assert!(host.as_str().starts_with("urn:uuid:"));
///
/// // Later runs read the stored text back.
/// assert_eq!(siwc::HostId::parse(host.as_str())?, host);
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostId(String);

impl HostId {
    /// A new random identifier in the form `urn:uuid:<uuid-v4>`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Randomness`] when `entropy` fails.
    pub fn generate(entropy: &OsEntropy) -> Result<Self, Error> {
        Self::generate_inner(entropy)
    }

    /// Generates a host identifier with a test entropy source.
    ///
    /// ```
    /// # fn example(source: &dyn siwc::Entropy) -> Result<(), siwc::Error> {
    /// let host = siwc::HostId::generate_with_entropy(source)?;
    /// assert!(host.as_str().starts_with("urn:uuid:"));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The same errors as [`Self::generate`].
    #[cfg(feature = "testing")]
    #[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
    pub fn generate_with_entropy(entropy: &dyn Entropy) -> Result<Self, Error> {
        Self::generate_inner(entropy)
    }

    pub(crate) fn generate_inner(entropy: &dyn Entropy) -> Result<Self, Error> {
        let mut bytes = [0u8; 16];
        entropy.fill(&mut bytes)?;
        // RFC 9562: version 4 in the high nibble of byte 6, variant 10 in the
        // two high bits of byte 8.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let mut text = String::with_capacity(UUID_PREFIX.len() + 36);
        text.push_str(UUID_PREFIX);
        for (index, byte) in bytes.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                text.push('-');
            }
            hex::push(&mut text, *byte);
        }
        Ok(Self(text))
    }

    /// Reads back a stored identifier.
    ///
    /// Accepts `urn:uuid:<uuid-v4>`, an RFC 9278 JWK thumbprint URI and a
    /// `did:key`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] for any other text.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let known = text.len() <= MAX_LEN
            && (text.strip_prefix(UUID_PREFIX).is_some_and(is_uuid_v4)
                || text
                    .strip_prefix(THUMBPRINT_PREFIX)
                    .is_some_and(is_thumbprint)
                || text.strip_prefix(DID_KEY_PREFIX).is_some_and(is_base58));
        if known {
            Ok(Self(text.to_owned()))
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "the host ID is not a UUID, JWK thumbprint or did:key URI",
            ))
        }
    }

    /// The identifier as text, for storing.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for HostId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for HostId {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Lowercase hyphenated UUID with version 4 and the RFC variant.
fn is_uuid_v4(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, &byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            14 => byte == b'4',
            19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// `<hash-name>:<base64url-digest>`, as in `sha-256:NzbLs…`.
fn is_thumbprint(text: &str) -> bool {
    text.split_once(':').is_some_and(|(hash, digest)| {
        !hash.is_empty()
            && hash
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !digest.is_empty()
            && digest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

fn is_base58(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_always_accepts_os_entropy() {
        let _: fn(&crate::OsEntropy) -> Result<HostId, Error> = HostId::generate;
    }

    #[cfg(feature = "testing")]
    struct Fixed(u8);

    #[cfg(feature = "testing")]
    impl Entropy for Fixed {
        fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
            bytes.fill(self.0);
            Ok(())
        }
    }

    #[test]
    #[cfg(feature = "testing")]
    fn generated_ids_carry_version_and_variant() {
        assert_eq!(
            HostId::generate_with_entropy(&Fixed(0xff))
                .unwrap()
                .as_str(),
            "urn:uuid:ffffffff-ffff-4fff-bfff-ffffffffffff"
        );
        assert_eq!(
            HostId::generate_with_entropy(&Fixed(0x00))
                .unwrap()
                .as_str(),
            "urn:uuid:00000000-0000-4000-8000-000000000000"
        );
    }

    #[test]
    fn the_documented_forms_parse() {
        for text in [
            "urn:uuid:00000000-0000-4000-8000-000000000000",
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        ] {
            assert_eq!(HostId::parse(text).unwrap().as_str(), text);
        }
    }

    #[test]
    fn personal_and_malformed_identifiers_do_not_parse() {
        for text in [
            "",
            "alex@example.com",
            "user-1234",
            "urn:uuid:00000000-0000-1000-8000-000000000000",
            "urn:uuid:00000000-0000-4000-c000-000000000000",
            "urn:uuid:00000000-0000-4000-8000-00000000000G",
            "URN:UUID:00000000-0000-4000-8000-000000000000",
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:",
            "did:key:z0",
        ] {
            assert!(HostId::parse(text).is_err(), "{text:?}");
        }
    }
}
