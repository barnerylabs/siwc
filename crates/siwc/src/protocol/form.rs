//! `application/x-www-form-urlencoded`: the encoding of the authorization
//! query, the token request bodies and the callback query.

use zeroize::{Zeroize, Zeroizing};

use crate::hex;

/// A decoded name with its value. Both are wiped when dropped: a callback
/// query carries the authorization code.
pub(crate) type Pair = (Zeroizing<String>, Zeroizing<String>);

/// Longest query accepted from a callback, in bytes.
const MAX_LEN: usize = 8 * 1024;

/// Most parameters accepted from a callback.
const MAX_PAIRS: usize = 32;

/// Encodes name/value pairs. Everything outside the RFC 3986 unreserved set
/// is percent-encoded, which is valid in a query and in a form body alike.
pub(crate) fn encode(pairs: &[(&str, &str)]) -> String {
    // Reserve the worst case up front: the text may hold secrets, and a
    // buffer that never grows leaves no partial copies behind.
    let capacity = pairs
        .iter()
        .map(|(name, value)| 3 * (name.len() + value.len()) + 2)
        .sum();
    let mut text = String::with_capacity(capacity);
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            text.push('&');
        }
        push_encoded(&mut text, name);
        text.push('=');
        push_encoded(&mut text, value);
    }
    text
}

fn push_encoded(text: &mut String, plain: &str) {
    for &byte in plain.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            text.push(char::from(byte));
        } else {
            // RFC 3986 section 2.1: producers use upper-case digits.
            text.push('%');
            for digit in hex::digits(byte) {
                text.push(char::from(digit.to_ascii_uppercase()));
            }
        }
    }
}

/// Decodes a query string into its pairs, in order.
///
/// Strict: an oversized query, an empty pair, a broken percent escape or
/// bytes that are not UTF-8 make the whole query unreadable. Repeated names
/// are kept; the caller decides what a repetition means.
pub(crate) fn parse(query: &str) -> Option<Vec<Pair>> {
    if query.len() > MAX_LEN {
        return None;
    }
    if query.is_empty() {
        return Some(Vec::new());
    }
    let mut pairs = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() || pairs.len() == MAX_PAIRS {
            return None;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        pairs.push((decode(name)?, decode(value)?));
    }
    Some(pairs)
}

fn decode(encoded: &str) -> Option<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(encoded.len()));
    let mut rest = encoded.as_bytes().iter();
    while let Some(&byte) = rest.next() {
        bytes.push(match byte {
            b'+' => b' ',
            b'%' => hex::value(*rest.next()?)? << 4 | hex::value(*rest.next()?)?,
            other => other,
        });
    }
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Some(Zeroizing::new(text)),
        Err(error) => {
            error.into_bytes().zeroize();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn parsed(query: &str) -> Vec<(String, String)> {
        parse(query)
            .unwrap()
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn reserved_characters_are_percent_encoded() {
        assert_eq!(
            encode(&[
                ("redirect_uri", "http://127.0.0.1:1455/auth/callback"),
                ("n", "Ex App ä&=+")
            ]),
            "redirect_uri=http%3A%2F%2F127.0.0.1%3A1455%2Fauth%2Fcallback&n=Ex%20App%20%C3%A4%26%3D%2B"
        );
    }

    #[test]
    fn encoded_pairs_decode_to_themselves() {
        let pairs = [("a b", "ä=&+%"), ("", ""), ("~-._", "\u{1F600}")];
        assert_eq!(parsed(&encode(&pairs)), owned(&pairs));
    }

    #[test]
    fn plus_and_percent_escapes_decode() {
        assert_eq!(
            parsed("code=a+b%2Bc&state=x%3d&flag"),
            owned(&[("code", "a b+c"), ("state", "x="), ("flag", "")])
        );
        assert_eq!(parsed(""), owned(&[]));
    }

    #[test]
    fn broken_queries_are_unreadable() {
        let too_many = vec!["a=1"; MAX_PAIRS + 1].join("&");
        let too_long = format!("a={}", "x".repeat(MAX_LEN));
        for query in [
            "a=%", "a=%4", "a=%zz", "a=%ff", "a=1&&b=2", "&", &too_many, &too_long,
        ] {
            assert!(parse(query).is_none(), "{query:?}");
        }
    }
}
