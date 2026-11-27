//! Wire formats, written a second time for the fake provider: the tests
//! compare the crate's encoders against these decoders, not against itself.

use ring::digest;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn base64url(bytes: &[u8]) -> String {
    let mut bits = 0u32;
    let mut count = 0;
    let mut text = String::new();
    for &byte in bytes {
        bits = bits << 8 | u32::from(byte);
        count += 8;
        while count >= 6 {
            count -= 6;
            text.push(char::from(ALPHABET[(bits >> count) as usize & 63]));
        }
    }
    if count > 0 {
        text.push(char::from(ALPHABET[(bits << (6 - count)) as usize & 63]));
    }
    text
}

pub fn base64url_decode(text: &str) -> Vec<u8> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut bytes = Vec::new();
    for character in text.bytes() {
        let value = ALPHABET
            .iter()
            .position(|&c| c == character)
            .expect("base64url character");
        bits = bits << 6 | value as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push((bits >> count) as u8);
        }
    }
    bytes
}

pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, bytes).as_ref().to_vec()
}

/// Decodes a query or form body; panics on anything a server would refuse.
pub fn form_decode(text: &str) -> Vec<(String, String)> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').expect("name=value");
            (percent_decode(name), percent_decode(value))
        })
        .collect()
}

pub fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_decode(text: &str) -> String {
    let mut bytes = Vec::new();
    let mut rest = text.bytes();
    while let Some(byte) = rest.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let hex = [
                    rest.next().expect("hex digit"),
                    rest.next().expect("hex digit"),
                ];
                let hex = std::str::from_utf8(&hex).expect("ascii");
                bytes.push(u8::from_str_radix(hex, 16).expect("hex escape"));
            }
            other => bytes.push(other),
        }
    }
    String::from_utf8(bytes).expect("utf-8")
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(byte).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// The value of `name` in decoded pairs; panics when it is missing or repeated.
pub fn only<'a>(pairs: &'a [(String, String)], name: &str) -> &'a str {
    let mut values = pairs.iter().filter(|(key, _)| key == name);
    match (values.next(), values.next()) {
        (Some((_, value)), None) => value,
        (None, _) => panic!("missing parameter {name}"),
        _ => panic!("repeated parameter {name}"),
    }
}

pub fn optional<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}
