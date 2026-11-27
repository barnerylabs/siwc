//! Reading failure events from a streamed Responses answer without I/O.
//!
//! Accepts either the JSON object of an event or a Server-Sent Events frame
//! (`data:` lines, with optional `event:`, `id:`, `retry:` or comment lines).

use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::DiagnosticText;
use crate::protocol::json;

use super::refusal::{MAX_BODY_LEN, sanitize_param, sanitize_refusal_code};

/// What a failed stream event carries: its sanitised error code and parameter.
pub(super) struct EventFailure {
    pub(super) code: Option<DiagnosticText>,
    pub(super) param: Option<DiagnosticText>,
}

/// Parses `bytes` as a streamed failure event. `None` when the event is not a
/// failure (such as `response.created`, `response.output_text.delta`,
/// `response.completed`, `response.incomplete`, `[DONE]` or a comment), or
/// cannot be read within [`MAX_BODY_LEN`].
pub(super) fn parse(bytes: &[u8]) -> Option<EventFailure> {
    if bytes.len() > MAX_BODY_LEN {
        return None;
    }
    let (payload, event) = json_payload(bytes)?;
    let document = json::Document(json::object(&payload)?);
    classify_object(&document.0, event)
}

/// Classifies an already-parsed JSON event object with an optional SSE `event:`
/// field name.
pub(super) fn classify_object(
    object: &json::Object,
    event_name: Option<&str>,
) -> Option<EventFailure> {
    let event_type = json::string(object, "type")
        .or_else(|| event_name.filter(|name| matches!(*name, "error" | "response.failed")));
    match event_type {
        Some("response.failed") => {
            let error = object
                .get("response")
                .and_then(Value::as_object)
                .and_then(|response| response.get("error"))
                .and_then(Value::as_object);
            Some(match error {
                Some(error) => extract_fields(error),
                None => EventFailure {
                    code: None,
                    param: None,
                },
            })
        }
        Some("error") => {
            let source = object
                .get("error")
                .and_then(Value::as_object)
                .unwrap_or(object);
            Some(extract_fields(source))
        }
        Some(_) => None,
        None => {
            let error = object.get("error")?.as_object()?;
            Some(extract_fields(error))
        }
    }
}

fn extract_fields(source: &json::Object) -> EventFailure {
    EventFailure {
        code: json::string(source, "code").and_then(sanitize_refusal_code),
        param: json::string(source, "param").and_then(sanitize_param),
    }
}

/// Extracts the JSON payload from either raw JSON bytes or an SSE frame.
fn json_payload(bytes: &[u8]) -> Option<(Zeroizing<Vec<u8>>, Option<&str>)> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let trimmed = bytes.trim_ascii();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with(b"{") {
        return Some((Zeroizing::new(trimmed.to_vec()), None));
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut joined = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut saw_data = false;
    let mut event = None;
    let mut ended = false;
    for line in sse_lines(text) {
        if line.is_empty() {
            if saw_data {
                ended = true;
            } else {
                event = None;
            }
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        if ended {
            return None;
        }
        let (field, rest) = match line.split_once(':') {
            Some((field, rest)) => (field, rest.strip_prefix(' ').unwrap_or(rest)),
            None => (line, ""),
        };
        match field {
            "data" => {
                if saw_data {
                    joined.push(b'\n');
                }
                joined.extend_from_slice(rest.as_bytes());
                saw_data = true;
            }
            "event" => event = (!rest.is_empty()).then_some(rest),
            "id" | "retry" => {}
            _ => return None,
        }
    }
    let payload = joined.trim_ascii();
    if !saw_data || payload.is_empty() || payload == b"[DONE]" {
        return None;
    }
    Some((joined, event))
}

/// Splits SSE text across `\r\n`, `\n` and standalone `\r` line endings.
fn sse_lines(mut rest: &str) -> impl Iterator<Item = &str> {
    let mut trailing_empty = false;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            if trailing_empty {
                trailing_empty = false;
                return Some("");
            }
            return None;
        }
        match rest.find(['\r', '\n']) {
            Some(pos) => {
                let line = &rest[..pos];
                let sep = rest.as_bytes()[pos];
                rest = &rest[pos + 1..];
                if sep == b'\r' {
                    rest = rest.strip_prefix('\n').unwrap_or(rest);
                }
                trailing_empty = rest.is_empty();
                Some(line)
            }
            None => {
                let line = rest;
                rest = "";
                Some(line)
            }
        }
    })
}
