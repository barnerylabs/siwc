//! Deserializes JSON objects while rejecting repeated member names at any
//! depth and wiping parsed strings if deserialization stops early.
//!
//! A number reads the same whichever `serde_json` features the
//! application's build enables: with `arbitrary_precision`, `serde_json`'s
//! private number map is accepted only as a single member holding a valid
//! number in the ordinary parser's range.

use std::fmt;

use serde_core::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{Object, wipe};

pub(super) fn strict_object(bytes: &[u8], max_len: usize) -> Option<Object> {
    if bytes.len() > max_len {
        return None;
    }
    let value = serde_json::from_slice::<WipingValue>(bytes).ok()?;
    match value.into_value() {
        Value::Object(object) => Some(object),
        mut other => {
            wipe(&mut other);
            None
        }
    }
}

struct WipingValue(Value);

impl WipingValue {
    fn into_value(mut self) -> Value {
        std::mem::take(&mut self.0)
    }
}

impl Drop for WipingValue {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl<'de> Deserialize<'de> for WipingValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = WipingValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without repeated members")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(WipingValue(Value::Null))
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(WipingValue(value.into()))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(WipingValue(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(WipingValue(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Ok(WipingValue(value.into()))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(WipingValue(Value::String(value)))
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Self::Value, S::Error> {
        let mut items = Vec::<WipingValue>::new();
        while let Some(item) = sequence.next_element()? {
            items.push(item);
        }
        Ok(WipingValue(Value::Array(
            items.into_iter().map(WipingValue::into_value).collect(),
        )))
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut members = WipingValue(Value::Object(Object::new()));
        let object = members
            .0
            .as_object_mut()
            .ok_or_else(|| de::Error::custom("expected a JSON object"))?;
        while let Some(mut key) = map.next_key::<String>()?.map(Zeroizing::new) {
            // With arbitrary_precision, serde_json delivers some numbers as
            // a single private member even when the input is a JSON scalar.
            if key.as_str() == "$serde_json::private::Number" {
                let invalid = || de::Error::custom("invalid JSON number");
                if !object.is_empty() {
                    return Err(invalid());
                }
                let text = Zeroizing::new(map.next_value::<String>()?);
                if text.trim_ascii() != *text || map.next_key::<de::IgnoredAny>()?.is_some() {
                    return Err(invalid());
                }
                // A numeric entry point uses the ordinary u64/i64/f64
                // visitor methods regardless of the dependency's features.
                let mut input = serde_json::Deserializer::from_str(&text);
                let number = input.deserialize_f64(self).map_err(|_| invalid())?;
                input.end().map_err(|_| invalid())?;
                return Ok(number);
            }
            if object.contains_key(key.as_str()) {
                return Err(de::Error::custom("repeated JSON member"));
            }
            let value = map.next_value::<WipingValue>()?;
            object.insert(std::mem::take(&mut *key), value.into_value());
        }
        Ok(members)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_core::de::value::{Error, MapDeserializer};

    #[test]
    fn the_private_number_map_yields_an_ordinary_json_number() {
        for (text, expected) in [
            ("1800.0", Value::from(1800.0)),
            ("-1.25e2", Value::from(-125.0)),
            ("18446744073709551616", Value::from(18446744073709551616.0)),
            ("18446744073709551615", Value::from(u64::MAX)),
        ] {
            let entries = [("$serde_json::private::Number", text)];
            let map = MapDeserializer::<_, Error>::new(entries.into_iter());
            assert_eq!(JsonVisitor.visit_map(map).unwrap().into_value(), expected);
        }
    }

    #[test]
    fn a_malformed_private_number_map_is_refused() {
        for members in [
            r#""$serde_json::private::Number":"1","extra":null"#,
            r#""extra":null,"$serde_json::private::Number":"1""#,
            r#""$serde_json::private::Number":"1","$serde_json::private::Number":"1""#,
            r#""$serde_json::private::Number":1"#,
        ] {
            let document = format!(r#"{{"value":{{{members}}}}}"#);
            assert!(
                strict_object(document.as_bytes(), 1024).is_none(),
                "{members}"
            );
        }
        for text in ["+1", "01", "1.", "1e", "NaN", " 1", "1 ", "1 2", "1e999"] {
            let map = MapDeserializer::<_, Error>::new(
                [("$serde_json::private::Number", text)].into_iter(),
            );
            assert!(JsonVisitor.visit_map(map).is_err(), "{text}");
        }
    }

    #[test]
    fn unique_members_are_required_even_inside_an_array() {
        assert!(strict_object(br#"{"result":[{"count":1,"done":true}]}"#, 1024).is_some());
        assert!(strict_object(br#"{"result":[{"count":1,"count":2}]}"#, 1024).is_none());
        assert!(strict_object(br#"{"result":null,"result":[]}"#, 1024).is_none());
    }
}
