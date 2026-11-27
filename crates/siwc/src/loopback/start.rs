//! The start link: a local URL that only this wait knows.

use ring::hmac;
use zeroize::Zeroizing;

use crate::entropy::Entropy;
use crate::error::Error;
use crate::hex;
use crate::secret::SecretString;

/// Random bytes in a start token.
const TOKEN_BYTES: usize = 16;

/// Path prefix of every start link.
pub(super) const START_PREFIX: &str = "/start/";

/// `http://127.0.0.1:<port>/start/<token>`.
///
/// Request paths are checked through an HMAC under a key of this link
/// alone, whose fixed-length tag is compared in constant time; computing the
/// HMAC takes longer for a longer path.
pub(super) struct StartLink {
    link: SecretString,
    key: hmac::Key,
    tag: hmac::Tag,
}

impl StartLink {
    /// Draws a fresh token for the listener on `port`.
    pub(super) fn draw(entropy: &dyn Entropy, port: u16) -> Result<Self, Error> {
        let mut token = Zeroizing::new([0u8; TOKEN_BYTES]);
        entropy.fill(token.as_mut_slice())?;
        let mut path = Zeroizing::new(String::with_capacity(START_PREFIX.len() + 2 * TOKEN_BYTES));
        path.push_str(START_PREFIX);
        for &byte in token.iter() {
            hex::push(&mut path, byte);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        entropy.fill(key.as_mut_slice())?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, key.as_slice());
        let tag = hmac::sign(&key, path.as_bytes());
        let link = format!("http://127.0.0.1:{port}{}", path.as_str());
        Ok(Self {
            link: SecretString::new(link),
            key,
            tag,
        })
    }

    pub(super) fn link(&self) -> &str {
        self.link.expose()
    }

    /// Whether a request path is this link's path.
    pub(super) fn matches(&self, path: &str) -> bool {
        hmac::verify(&self.key, path.as_bytes(), self.tag.as_ref()).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(u8);

    impl Entropy for Fixed {
        fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = self.0.wrapping_add((index as u8).wrapping_mul(17));
            }
            Ok(())
        }
    }

    #[test]
    fn the_link_carries_sixteen_random_bytes_in_hex() {
        let start = StartLink::draw(&Fixed(0), 53124).unwrap();
        assert_eq!(
            start.link(),
            "http://127.0.0.1:53124/start/00112233445566778899aabbccddeeff"
        );
        assert!(start.matches("/start/00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn only_the_exact_path_matches() {
        let start = StartLink::draw(&Fixed(0), 53124).unwrap();
        for other in [
            "/start/00112233445566778899aabbccddeefe",
            "/start/00112233445566778899aabbccddeeff0",
            "/start/00112233445566778899aabbccddeef",
            "/start/00112233445566778899AABBCCDDEEFF",
            "/start/",
            "",
        ] {
            assert!(!start.matches(other), "{other}");
        }
        let another = StartLink::draw(&Fixed(1), 53124).unwrap();
        assert_ne!(start.link(), another.link());
    }

    #[test]
    fn without_random_bytes_there_is_no_link() {
        struct Empty;
        impl Entropy for Empty {
            fn fill(&self, _: &mut [u8]) -> Result<(), Error> {
                Err(Error::entropy_unavailable())
            }
        }
        assert!(StartLink::draw(&Empty, 53124).is_err());
    }
}
