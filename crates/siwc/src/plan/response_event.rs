//! One event of a streamed answer together with the JSON it came as.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use super::stream_event::StreamEvent;

/// One event of a streamed `/v1/responses` answer: what the crate reads
/// from it, and its JSON for everything else.
///
/// [`event`](Self::event) is the part the crate decodes, enough to show a
/// text answer. [`json`](Self::json) is the event's whole JSON object as the
/// provider sent it, for an app that also reads tool calls, reasoning
/// summaries, the response ID or the usage of a `response.completed` event
/// with its own JSON library.
///
/// Its fields are private, so a later release can add typed accessors here,
/// such as a delta's output index or a completed answer's usage, without
/// changing [`StreamEvent`] or breaking a caller.
///
/// Dropping the event wipes its JSON and any decoded text delta it still
/// owns. `Debug` shows only the kind of event and lengths.
///
/// ```
/// use siwc::plan::{SseDecoder, StreamEvent};
///
/// let mut decoder = SseDecoder::new();
/// let events = decoder.feed(
///     b"data: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"delta\":\"Hi\"}\n\n",
/// )?;
/// let event = &events[0];
/// assert_eq!(event.text_delta(), Some("Hi"));
/// assert!(matches!(event.event(), StreamEvent::TextDelta { text, .. } if text == "Hi"));
/// assert!(event.json().contains("\"item_id\":\"msg_1\""));
/// // `Debug` shows what kind of event it is and how long, never its text.
/// assert!(!format!("{event:?}").contains("Hi"));
/// # Ok::<(), siwc::Error>(())
/// ```
pub struct ResponseEvent {
    kind: Option<Box<str>>,
    event: StreamEvent,
    json: Zeroizing<String>,
    #[cfg(test)]
    pub(crate) inspect_delta_before_free: Option<fn(&str)>,
}

impl ResponseEvent {
    pub(super) fn new(event: StreamEvent, kind: Option<&str>, json: &str) -> Self {
        Self {
            kind: kind.map(Box::from),
            event,
            json: Zeroizing::new(json.to_owned()),
            #[cfg(test)]
            inspect_delta_before_free: None,
        }
    }

    /// The event's `type`, such as `response.output_item.done`, to pick the
    /// events worth parsing. `None` when the event has no `type` of 1 to
    /// 128 ASCII letters, digits, `_`, `-` and `.`; a longer or stranger
    /// type of a later API is still in [`json`](Self::json).
    ///
    /// ```
    /// use siwc::plan::SseDecoder;
    ///
    /// let events = SseDecoder::new().feed(b"data: {\"type\":\"response.created\"}\n\n")?;
    /// assert_eq!(events[0].event_type(), Some("response.created"));
    /// # Ok::<(), siwc::Error>(())
    /// ```
    #[must_use]
    pub fn event_type(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    /// What the crate decoded from the event.
    #[must_use]
    pub fn event(&self) -> &StreamEvent {
        &self.event
    }

    /// The text this event appends to the answer, if it is a
    /// [`StreamEvent::TextDelta`].
    #[must_use]
    pub fn text_delta(&self) -> Option<&str> {
        match &self.event {
            StreamEvent::TextDelta { text } => Some(text),
            _ => None,
        }
    }

    /// The event's JSON object as the provider sent it, without the
    /// `data:` framing around it.
    #[must_use]
    pub fn json(&self) -> &str {
        &self.json
    }

    /// Moves the decoded event out and wipes the JSON. For a text delta,
    /// the caller now owns its `String`.
    #[must_use]
    pub fn into_event(mut self) -> StreamEvent {
        std::mem::replace(&mut self.event, StreamEvent::Other)
    }
}

impl Drop for ResponseEvent {
    fn drop(&mut self) {
        if let StreamEvent::TextDelta { text } = &mut self.event {
            text.as_mut_str().zeroize();
            #[cfg(test)]
            if let Some(inspect) = self.inspect_delta_before_free {
                inspect(text);
            }
        }
    }
}

impl fmt::Debug for ResponseEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseEvent")
            .field("event", &self.event)
            .field("json_len", &self.json.len())
            .finish()
    }
}
