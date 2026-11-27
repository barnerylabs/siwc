//! The key as the keychain holds it: 64 lowercase hex digits.

use zeroize::{Zeroize, Zeroizing};

use crate::hex;
use crate::store::KEY_LEN;

/// The key as text.
pub(super) fn encode(key: &[u8; KEY_LEN]) -> Zeroizing<Vec<u8>> {
    let mut text = Zeroizing::new(Vec::with_capacity(2 * KEY_LEN));
    for &byte in key {
        text.extend_from_slice(&hex::digits(byte));
    }
    text
}

/// Reads `text` into `key`, ignoring surrounding whitespace such as the
/// newline a tool prints; returns `false` and zeroes `key` when `text` is not
/// 64 hex digits.
pub(super) fn decode(text: &[u8], key: &mut [u8; KEY_LEN]) -> bool {
    let text = text.trim_ascii();
    if text.len() != 2 * KEY_LEN {
        key.zeroize();
        return false;
    }
    for (byte, &[high, low]) in key.iter_mut().zip(text.as_chunks::<2>().0) {
        let (Some(high), Some(low)) = (hex::value(high), hex::value(low)) else {
            key.zeroize();
            return false;
        };
        *byte = high << 4 | low;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_reads_back_from_its_text_with_a_trailing_newline() {
        let key: [u8; KEY_LEN] = std::array::from_fn(|at| u8::try_from(at * 7).unwrap());
        let mut text = encode(&key).to_vec();
        assert!(text.iter().all(|digit| b"0123456789abcdef".contains(digit)));
        text.push(b'\n');
        let mut read = [0; KEY_LEN];
        assert!(decode(&text, &mut read));
        assert_eq!(read, key);
    }

    #[test]
    fn upper_case_digits_read_as_the_same_key() {
        let key = [0xab; KEY_LEN];
        let mut read = [0; KEY_LEN];
        assert!(decode(&b"Ab".repeat(KEY_LEN), &mut read));
        assert_eq!(read, key);
    }

    #[test]
    fn text_that_is_not_64_hex_digits_is_no_key() {
        let mut key = [0; KEY_LEN];
        assert!(!decode(b"", &mut key));
        assert!(!decode(&[b'a'; 63], &mut key));
        assert!(!decode(&[b'a'; 65], &mut key));
        assert!(!decode(&[b'g'; 64], &mut key));
        assert!(!decode(&[b'+'; 64], &mut key));
    }
}
