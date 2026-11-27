//! Base64url without padding (RFC 4648 §5), as PKCE and JWTs use it, and
//! the standard encoding with padding (§4) that `Content-Security-Policy`
//! hashes and `data:` URIs need.

use zeroize::Zeroizing;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn encode(bytes: &[u8]) -> String {
    encode_with(bytes, ALPHABET, false)
}

/// Standard base64 with padding.
pub(crate) fn encode_standard(bytes: &[u8]) -> String {
    encode_with(bytes, STANDARD_ALPHABET, true)
}

fn encode_with(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut group = [0u8; 3];
        for (slot, byte) in group.iter_mut().zip(chunk) {
            *slot = *byte;
        }
        let bits = u32::from_be_bytes([0, group[0], group[1], group[2]]);
        // One more character than bytes: 1 byte needs 2, 2 need 3, 3 need 4.
        for position in 0..=chunk.len() {
            let sextet = (bits >> (18 - 6 * position)) & 0x3f;
            text.push(char::from(alphabet[sextet as usize]));
        }
        if pad {
            for _ in chunk.len()..3 {
                text.push('=');
            }
        }
    }
    text
}

/// Strict decoding: no padding, no characters outside the alphabet and no
/// set bits beyond the last byte, so every byte string has one encoding.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(text.len() / 4 * 3 + 2));
    for chunk in text.as_bytes().chunks(4) {
        let mut bits = 0u32;
        for &character in chunk {
            bits = bits << 6 | u32::from(sextet(character)?);
        }
        let [_, first, second, third] = match chunk.len() {
            4 => bits.to_be_bytes(),
            3 if bits & 0b11 == 0 => (bits << 6).to_be_bytes(),
            2 if bits & 0b1111 == 0 => (bits << 12).to_be_bytes(),
            _ => return None,
        };
        let decoded = [first, second, third];
        bytes.extend_from_slice(&decoded[..chunk.len() - 1]);
    }
    Some(std::mem::take(&mut *bytes))
}

fn sextet(character: u8) -> Option<u8> {
    match character {
        b'A'..=b'Z' => Some(character - b'A'),
        b'a'..=b'z' => Some(character - b'a' + 26),
        b'0'..=b'9' => Some(character - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors_encode_and_decode() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn rfc_4648_vectors_encode_in_the_standard_alphabet_with_padding() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_standard(plain.as_bytes()), encoded);
        }
        assert_eq!(encode_standard(&[0xfb, 0xff, 0xfe]), "+//+");
    }

    #[test]
    fn the_url_safe_alphabet_is_used() {
        assert_eq!(encode(&[0xfb, 0xff, 0xfe]), "-__-");
        assert_eq!(decode("-__-").unwrap(), [0xfb, 0xff, 0xfe]);
    }

    #[test]
    fn padding_other_alphabets_and_stray_bits_are_refused() {
        for text in ["Zg==", "Zm8=", "+/+/", "Zm 9v", "Z", "Zm9vY", "Zh", "Zm9"] {
            assert!(decode(text).is_none(), "{text:?}");
        }
    }

    #[test]
    fn every_length_survives_a_round_trip() {
        let bytes: Vec<u8> = (0..=255).collect();
        for length in 0..bytes.len() {
            assert_eq!(decode(&encode(&bytes[..length])).unwrap(), &bytes[..length]);
        }
    }
}
