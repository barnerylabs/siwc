//! What one event of a streamed `/v1/responses` answer means.
//!
//! The variants that may grow are `#[non_exhaustive]` rather than wrappers
//! around opaque payload types. That keeps plain field access
//! (`TextDelta { text, .. }`, `Incomplete { reason, .. }`), lets a later
//! field travel with the event through `ResponseEvent::into_event`, and
//! needs no accessor type per variant. Apps do not build these events:
//! `SseDecoder` and the streams produce them, and `testing::FakeResponse`
//! scripts a stream.

use std::fmt;

use serde_json::Value;

use crate::protocol::json;

use super::refusal::{Refusal, sanitize_code};
use super::sse::MAX_FRAME_LEN;

/// The reasons the provider documents for an answer that stops early. Only
/// these are named in `Debug` output and in error messages.
const KNOWN_REASONS: [&str; 2] = ["max_output_tokens", "content_filter"];

/// The event types that end an answer or report its failure. An event
/// whose `event:` field and JSON `type` disagree about one of these is
/// refused.
const DECISIVE_TYPES: [&str; 4] = [
    "response.completed",
    "response.incomplete",
    "response.failed",
    "error",
];

/// Whether an `event:` name or a JSON `type` is one that ends an answer.
pub(super) fn ends_an_answer(name: &str) -> bool {
    DECISIVE_TYPES.contains(&name)
}

/// One decoded event from a streamed `/v1/responses` answer.
///
/// `Debug` shows what kind of event it is and never its text: the length of
/// a [`TextDelta`](Self::TextDelta), and the reason of an
/// [`Incomplete`](Self::Incomplete) only when it is one the provider
/// documents.
///
/// # Room to grow
///
/// This is a coarse classification, enough to show a text answer and tell
/// how it ended. New event kinds become new variants, so match with a
/// wildcard arm. The variants that may carry more data later, such as an
/// output index beside a text delta or the usage of a completed answer,
/// are `#[non_exhaustive]`: match them as `TextDelta { text, .. }`,
/// `Completed { .. }` and `Incomplete { reason, .. }`, and a new field
/// breaks no match. Only the crate builds these variants. `Failed` carries
/// a [`Refusal`], whose fields are private and which gains accessors. Detail
/// that the crate does not decode stays on the
/// [`ResponseEvent`](crate::plan::ResponseEvent) that holds the event, in
/// its [`json`](crate::plan::ResponseEvent::json) and in any typed accessor
/// a later release adds there.
///
/// ```
/// use siwc::plan::{SseDecoder, StreamEvent};
///
/// let events = SseDecoder::new().feed(
///     b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello\"}\n\n",
/// )?;
/// let event = events.into_iter().next().unwrap().into_event();
/// assert!(!format!("{event:?}").contains("Hello"));
/// match event {
///     StreamEvent::TextDelta { text, .. } => assert_eq!(text, "Hello"),
///     StreamEvent::Completed { .. } => println!("done"),
///     _ => {}
/// }
/// # Ok::<(), siwc::Error>(())
/// ```
///
/// An app cannot build a variant that may still grow:
///
/// ```compile_fail,E0603
/// let _ = siwc::plan::StreamEvent::Completed;
/// ```
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamEvent {
    /// Text appended by a `response.output_text.delta` event.
    #[non_exhaustive]
    TextDelta {
        /// The appended text, from the event's `delta`.
        text: String,
    },
    /// The response completed (`response.completed`). Its usage and the
    /// rest of the response are in
    /// [`ResponseEvent::json`](crate::plan::ResponseEvent::json).
    #[non_exhaustive]
    Completed,
    /// The response stopped incomplete (`response.incomplete`), with the
    /// provider's sanitised reason code when present.
    #[non_exhaustive]
    Incomplete {
        /// The reason from `response.incomplete_details.reason` when it is
        /// 1–128 ASCII letters, digits, dots, underscores or hyphens.
        /// [`SseDecoder`](crate::plan::SseDecoder) also exposes the original
        /// value in [`ResponseEvent::json`](crate::plan::ResponseEvent::json).
        /// The built-in streams return [`ErrorKind::Incomplete`](crate::ErrorKind::Incomplete)
        /// instead of this event and name only `max_output_tokens` or `content_filter`.
        reason: Option<String>,
    },
    /// The stream reported a structured failure (`response.failed` or `error`).
    Failed(Refusal),
    /// Any other well-formed event frame (such as `response.created`).
    Other,
}

impl fmt::Debug for StreamEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextDelta { text } => f
                .debug_struct("TextDelta")
                .field("len", &text.len())
                .finish(),
            Self::Completed => f.write_str("Completed"),
            Self::Incomplete { reason } => f
                .debug_struct("Incomplete")
                .field("reason", &reason.as_deref().map(printable_reason))
                .finish(),
            Self::Failed(refusal) => f.debug_tuple("Failed").field(refusal).finish(),
            Self::Other => f.write_str("Other"),
        }
    }
}

/// `reason` if the provider documents it, otherwise a placeholder: a value
/// that only looks like an identifier may still be anything.
fn printable_reason(reason: &str) -> &'static str {
    known_incomplete_reason(reason).unwrap_or("other")
}

/// `reason` if it is one the provider documents for `response.incomplete`.
pub(crate) fn known_incomplete_reason(reason: &str) -> Option<&'static str> {
    KNOWN_REASONS.into_iter().find(|known| *known == reason)
}

/// The event in `payload`, sent under the SSE event name `event_name`, and
/// its `type`, kept only when it looks like an identifier. `None` when the
/// payload is not one JSON object, lacks what its type requires, or
/// contradicts its event name about how the answer ended.
pub(super) fn decode(
    payload: &[u8],
    event_name: Option<&str>,
) -> Option<(StreamEvent, Option<String>)> {
    // An event may be as large as the decoder lets one grow.
    let document = json::Document(json::object_within(payload, MAX_FRAME_LEN)?);
    let object = &document.0;
    let kind = json::string(object, "type");
    let decisive = ends_an_answer;
    match (event_name, kind) {
        (Some(name), Some(kind)) if name != kind && (decisive(name) || decisive(kind)) => {
            return None;
        }
        // A name that ends an answer needs a type that says the same; only
        // a failure is also read from its name alone.
        (Some(name), None) if decisive(name) && !matches!(name, "error" | "response.failed") => {
            return None;
        }
        _ => {}
    }
    let event = classify(object, event_name)?;
    Some((event, kind.and_then(sanitize_code)))
}

fn classify(object: &json::Object, event_name: Option<&str>) -> Option<StreamEvent> {
    if let Some(refusal) = Refusal::from_event_object(object, event_name) {
        return Some(StreamEvent::Failed(refusal));
    }
    Some(match json::string(object, "type") {
        Some("response.output_text.delta") => StreamEvent::TextDelta {
            text: json::string(object, "delta")?.to_owned(),
        },
        Some("response.completed") => StreamEvent::Completed,
        Some("response.incomplete") => {
            let reason = object
                .get("response")
                .and_then(Value::as_object)
                .and_then(|response| response.get("incomplete_details"))
                .and_then(Value::as_object)
                .and_then(|details| json::string(details, "reason"))
                .and_then(sanitize_code);
            StreamEvent::Incomplete { reason }
        }
        _ => StreamEvent::Other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_shows_the_kind_of_an_event_and_none_of_its_text() {
        let delta = StreamEvent::TextDelta {
            text: "secret-model-text".to_owned(),
        };
        assert_eq!(format!("{delta:?}"), "TextDelta { len: 17 }");
        let known = StreamEvent::Incomplete {
            reason: Some("max_output_tokens".to_owned()),
        };
        assert_eq!(
            format!("{known:?}"),
            "Incomplete { reason: Some(\"max_output_tokens\") }"
        );
        // A reason nobody documented may be an echo of anything.
        let unknown = StreamEvent::Incomplete {
            reason: Some("at-synthetic-token".to_owned()),
        };
        assert_eq!(
            format!("{unknown:?}"),
            "Incomplete { reason: Some(\"other\") }"
        );
        let none = StreamEvent::Incomplete { reason: None };
        assert_eq!(format!("{none:?}"), "Incomplete { reason: None }");
        assert_eq!(format!("{:?}", StreamEvent::Completed), "Completed");
        assert_eq!(format!("{:?}", StreamEvent::Other), "Other");
    }

    #[test]
    fn an_event_name_that_contradicts_the_type_about_the_ending_is_refused() {
        let completed = br#"{"type":"response.completed","response":{}}"#;
        let delta = br#"{"type":"response.output_text.delta","delta":"x"}"#;
        let failed = br#"{"type":"response.failed","response":{"error":{"code":"x"}}}"#;
        for (name, payload) in [
            ("error", &completed[..]),
            ("response.failed", completed),
            ("response.incomplete", completed),
            ("response.output_text.delta", completed),
            ("response.completed", delta),
            ("response.completed", failed),
            ("error", delta),
        ] {
            assert!(decode(payload, Some(name)).is_none(), "{name}");
        }
        // Agreement, no name, and names that decide nothing are fine.
        for (name, payload) in [
            (Some("response.completed"), &completed[..]),
            (None, completed),
            (Some("response.output_text.delta"), delta),
            (Some("message"), delta),
            (Some("response.failed"), failed),
        ] {
            assert!(decode(payload, name).is_some(), "{name:?}");
        }
        // A name alone still says that an event without a type is an error.
        let (event, kind) = decode(br#"{"code":"x"}"#, Some("error")).unwrap();
        assert!(matches!(event, StreamEvent::Failed(_)));
        assert_eq!(kind, None);
    }
}
