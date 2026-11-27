//! Hexadecimal digits: the lowercase text of random IDs, start links and
//! keychain keys, and the value of a digit read back in either case. Percent
//! escapes reuse both.

const LOWER: &[u8; 16] = b"0123456789abcdef";

/// The two lowercase hex digits of `byte`, high nibble first.
pub(crate) fn digits(byte: u8) -> [u8; 2] {
    [
        LOWER[usize::from(byte >> 4)],
        LOWER[usize::from(byte & 0x0f)],
    ]
}

/// Appends the two lowercase hex digits of `byte` to `text`.
pub(crate) fn push(text: &mut String, byte: u8) {
    for digit in digits(byte) {
        text.push(char::from(digit));
    }
}

/// The value of one hex digit, uppercase or lowercase.
pub(crate) fn value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}
