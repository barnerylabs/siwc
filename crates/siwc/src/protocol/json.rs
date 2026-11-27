//! Reading JSON objects from the provider and the store without keeping what
//! was read or accepting repeated member names.

mod strict;

use serde_json::{Map, Value};
use zeroize::Zeroize;

/// Largest JSON document accepted from the provider or from a token.
const MAX_LEN: usize = 1024 * 1024;

pub(crate) type Object = Map<String, Value>;

/// A parsed document whose remaining strings are wiped when it is dropped,
/// even when reading stops half-way.
pub(crate) struct Document(pub(crate) Object);

impl Drop for Document {
    fn drop(&mut self) {
        self.0.values_mut().for_each(wipe);
    }
}

/// Parses `bytes` as one JSON object, rejecting repeated member names at any
/// depth. The parser's own error is dropped on purpose: it can quote the
/// input, and the input can hold a token.
pub(crate) fn object(bytes: &[u8]) -> Option<Object> {
    strict::strict_object(bytes, MAX_LEN)
}

/// Like [`object`], for a document of at most `max_len` bytes that the app
/// wrote itself and that may therefore be larger than the provider's.
pub(crate) fn object_within(bytes: &[u8], max_len: usize) -> Option<Object> {
    strict::strict_object(bytes, max_len)
}

/// Whether `object` has exactly the members `names`.
pub(crate) fn exact(object: &Object, names: &[&str]) -> bool {
    object.len() == names.len() && names.iter().all(|name| object.contains_key(*name))
}

/// A member that is present but is not text of a usable length.
pub(crate) struct Unusable;

/// Moves an optional string member of 1 to `max_len` bytes out of the object,
/// so a secret ends up in exactly one buffer that its new owner can wipe.
/// An absent or `null` member is `None`; an unusable one is wiped.
pub(crate) fn take_text(
    object: &mut Object,
    name: &str,
    max_len: usize,
) -> Result<Option<String>, Unusable> {
    match object.remove(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if !text.is_empty() && text.len() <= max_len => Ok(Some(text)),
        Some(Value::String(mut text)) => {
            text.zeroize();
            Err(Unusable)
        }
        Some(mut value) => {
            wipe(&mut value);
            Err(Unusable)
        }
    }
}

/// Overwrites every string value in `value` before the document is dropped.
/// Best effort, as everywhere: copies the parser or the allocator made
/// earlier are out of reach.
pub(crate) fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(object) => object.values_mut().for_each(wipe),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// A string member, borrowed.
pub(crate) fn string<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    object.get(name).and_then(Value::as_str)
}

/// A JWT `NumericDate`: seconds since the epoch, possibly with a fraction.
pub(crate) fn seconds(object: &Object, name: &str) -> Option<u64> {
    let value = object.get(name)?;
    value.as_u64().or_else(|| {
        let seconds = value.as_f64()?;
        // The cast truncates the fraction; the range check keeps it exact
        // enough for any date this century and the next.
        (seconds.is_finite() && (0.0..=1.0e12).contains(&seconds)).then_some(seconds as u64)
    })
}
