//! Incremental Server-Sent Events (SSE) decoder for streamed `/v1/responses`
//! answers, without I/O.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind};
use crate::transport::buffer::reserve;

use super::response_event::ResponseEvent;
use super::stream_event;

mod ending;

use ending::{Fault, Tail};

/// Largest event before failing with `InvalidResponse` (16 MiB): the line
/// being read, the `data:` buffered so far and the `event:` name together.
/// The closing event of an answer repeats its whole output, and a tool
/// result can carry an image, so the limit is the one `into_text` has for
/// the text of an answer.
pub(super) const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Incremental, I/O-free decoder for `text/event-stream` responses from
/// [`RESPONSES_URL`](super::RESPONSES_URL).
///
/// Feed arbitrary byte chunks from your HTTP client with [`feed`](Self::feed),
/// act on each [`StreamEvent`](super::StreamEvent), and call [`finish`](Self::finish) at EOF:
/// it succeeds only for an answer that ended with
/// [`StreamEvent::Completed`](super::StreamEvent::Completed), so neither a connection cut off early nor an
/// answer that ended with [`StreamEvent::Failed`](super::StreamEvent::Failed) or
/// [`StreamEvent::Incomplete`](super::StreamEvent::Incomplete) is mistaken for a finished one. `Debug` shows
/// only buffered state and never exposes streamed model text.
///
/// The event that ends an answer is its last: after it the decoder accepts
/// blank lines, comments and one closing `data: [DONE]`, 4 KiB in all, and
/// anything else is an error, a last line without its line end included.
/// An event named `response.completed`, `response.incomplete`,
/// `response.failed` or `error` is never passed over: without data, with
/// empty data or with `[DONE]` for data it is an error. Around an event's
/// JSON only the white space of JSON (space, tab, CR, LF) is skipped.
///
/// What the decoder hands out does not depend on how the bytes were cut
/// into chunks: events that were complete before a broken one are returned
/// first, and the error comes from the next call. A decoder that has
/// reported an error reports it again for every later call.
///
/// ```
/// use siwc::plan::SseDecoder;
///
/// let mut decoder = SseDecoder::new();
/// # fn show(_: &str) {}
/// for chunk in [
///     &b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hel\"}\n\n"[..],
///     &b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"lo!\"}\n\n"[..],
///     &b"data: {\"type\":\"response.completed\",\"response\":{}}\n\n"[..],
/// ] {
///     for event in decoder.feed(chunk)? {
///         if let Some(text) = event.text_delta() {
///             show(text);
///         }
///     }
/// }
/// decoder.finish()?;
/// # Ok::<(), siwc::Error>(())
/// ```
pub struct SseDecoder {
    line_buf: Zeroizing<Vec<u8>>,
    data_buf: Zeroizing<Vec<u8>>,
    event_name: Option<String>,
    has_data: bool,
    pending_cr: bool,
    at_start: bool,
    /// The stream from the event that ended the answer on.
    tail: Option<Tail>,
    fault: Option<Fault>,
}

impl Default for SseDecoder {
    fn default() -> Self {
        Self {
            line_buf: Zeroizing::default(),
            data_buf: Zeroizing::default(),
            event_name: None,
            has_data: false,
            pending_cr: false,
            at_start: true,
            tail: None,
            fault: None,
        }
    }
}

impl fmt::Debug for SseDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SseDecoder")
            .field(
                "buffered_bytes",
                &(self.line_buf.len() + self.data_buf.len()),
            )
            .field("has_data", &self.has_data)
            .field("saw_terminal", &self.tail.is_some())
            .finish_non_exhaustive()
    }
}

impl SseDecoder {
    /// Creates a fresh stream decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds the next chunk of response bytes and returns all complete events
    /// decoded from it, each with what the crate reads from it
    /// ([`ResponseEvent::event`]) and its whole JSON
    /// ([`ResponseEvent::json`]) for everything else: tool calls, reasoning
    /// summaries or the usage a `response.completed` event reports.
    ///
    /// Per the Server-Sent Events specification, an event is dispatched when
    /// its terminating blank line (`\n\n`, `\r\n\r\n` or `\r\r`) arrives.
    ///
    /// ```
    /// use siwc::plan::{SseDecoder, StreamEvent};
    ///
    /// let mut decoder = SseDecoder::new();
    /// let events = decoder.feed(
    ///     b"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"total_tokens\":7}}}\n\n",
    /// )?;
    /// assert!(matches!(events[0].event(), StreamEvent::Completed { .. }));
    /// assert!(events[0].json().contains("\"total_tokens\":7"));
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidResponse`] when a line is not valid UTF-8, an
    /// event (its current line, the `data:` buffered so far and its `event:`
    /// name together) exceeds 16 MiB, a `data:` payload is malformed JSON,
    /// or an event's `event:` name and JSON `type` contradict each other
    /// about how the answer ended. Invalid material after a terminal event
    /// also fails validation. Events that were complete before the
    /// broken one are returned first; the error then comes from the next
    /// call, and from every call after it.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<ResponseEvent>, Error> {
        match self.feed_and_error(chunk) {
            (events, Some(error)) if events.is_empty() => Err(error),
            (events, _) => Ok(events),
        }
    }

    /// Feeds the next chunk and returns the events that were complete
    /// together with the error that ended the decoding, if one did.
    pub(crate) fn feed_and_error(&mut self, chunk: &[u8]) -> (Vec<ResponseEvent>, Option<Error>) {
        let mut events = Vec::new();
        if self.fault.is_none() {
            for &byte in chunk {
                if let Err(fault) = self.consume_byte(byte, &mut events) {
                    self.fault = Some(fault);
                    self.line_buf.clear();
                    self.data_buf.clear();
                    break;
                }
            }
        }
        (events, self.fault.map(Fault::error))
    }

    fn consume_byte(&mut self, byte: u8, events: &mut Vec<ResponseEvent>) -> Result<(), Fault> {
        if self.pending_cr {
            self.pending_cr = false;
            if byte == b'\n' {
                // The second byte of a line end. Behind the last event it
                // counts like every byte, unless it still ends that event.
                return match &mut self.tail {
                    Some(tail) if tail.has_begun() => tail.count_byte(),
                    _ => Ok(()),
                };
            }
        }
        if let Some(tail) = &mut self.tail {
            tail.count_byte()?;
        }
        match byte {
            b'\r' | b'\n' => {
                self.pending_cr = byte == b'\r';
                if let Some(tail) = &mut self.tail {
                    let checked = tail.line(&self.line_buf);
                    self.line_buf.clear();
                    checked?;
                } else {
                    events.extend(self.consume_line()?);
                }
            }
            _ => {
                if self.line_buf.len() + self.held_len() >= MAX_FRAME_LEN {
                    return Err(Fault::TooLarge);
                }
                reserve(&mut self.line_buf, 1, MAX_FRAME_LEN).ok_or(Fault::TooLarge)?;
                self.line_buf.push(byte);
            }
        }
        Ok(())
    }

    /// At the end of the body, for a stream whose last event was decoded:
    /// the error of a tail that was cut off inside a line.
    pub(crate) fn tail_at_end(&self) -> Result<(), Error> {
        match &self.tail {
            Some(tail) if !tail.is_whole(&self.line_buf) => Err(Fault::AfterEnd.error()),
            _ => Ok(()),
        }
    }

    /// The bytes of the event being put together, without its current line.
    fn held_len(&self) -> usize {
        self.data_buf.len() + self.event_name.as_ref().map_or(0, String::len)
    }

    /// Says at EOF whether the answer is complete: `Ok` only when the
    /// stream ended with `response.completed`. Call it once the HTTP client
    /// has reported the clean end of the body; an error of that client
    /// while reading means an incomplete answer whatever this returns.
    ///
    /// ```
    /// use siwc::ErrorKind;
    /// use siwc::plan::SseDecoder;
    ///
    /// let ending = |last_event: &str| {
    ///     let mut decoder = SseDecoder::new();
    ///     decoder.feed(last_event.as_bytes())?;
    ///     decoder.finish()
    /// };
    /// assert!(ending("data: {\"type\":\"response.completed\"}\n\n").is_ok());
    /// // The API stopped the answer early.
    /// let stopped = ending("data: {\"type\":\"response.incomplete\"}\n\n").unwrap_err();
    /// assert_eq!(stopped.kind(), ErrorKind::Incomplete);
    /// // The API reported a failure: the error of its refusal.
    /// let failed = ending(
    ///     "data: {\"type\":\"response.failed\",\"response\":{\"error\":\
    ///      {\"code\":\"subscription_sharing_usage_limit_exceeded\"}}}\n\n",
    /// )
    /// .unwrap_err();
    /// assert_eq!(failed.kind(), ErrorKind::UsageLimit);
    /// // The connection ended before any of these.
    /// let cut = ending("data: {\"type\":\"response.created\"}\n\n").unwrap_err();
    /// assert_eq!(cut.kind(), ErrorKind::Temporary);
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidResponse`] if decoding failed, even if `feed`
    /// already reported the error. A malformed tail takes precedence over
    /// a failure or incomplete event; the client stream reports that event
    /// immediately. This error also applies if the stream ended inside a line behind its
    /// last event; [`ErrorKind::Temporary`] if the stream ended before any
    /// event that ends an answer;
    /// [`ErrorKind::Incomplete`] after `response.incomplete`; and after a
    /// failure event the error of its [`Refusal`](super::Refusal), such as
    /// [`ErrorKind::UsageLimit`].
    pub fn finish(self) -> Result<(), Error> {
        if let Some(fault) = self.fault {
            return Err(fault.error());
        }
        match self.tail {
            None => Err(Error::new(
                ErrorKind::Temporary,
                "the response stream ended before response.completed",
            )),
            Some(tail) => tail.result(&self.line_buf),
        }
    }

    fn consume_line(&mut self) -> Result<Option<ResponseEvent>, Fault> {
        let was_at_start = self.at_start;
        self.at_start = false;
        if self.line_buf.is_empty() {
            if self.has_data {
                return self.dispatch_frame();
            }
            // An event without data says nothing, unless its name says
            // that the answer ended: that needs the JSON to go with it.
            return match self.event_name.take() {
                Some(name) if stream_event::ends_an_answer(&name) => Err(Fault::Malformed),
                _ => Ok(None),
            };
        }
        let raw_line = std::str::from_utf8(&self.line_buf).map_err(|_| Fault::Malformed)?;
        // Per WHATWG SSE §9.2.5, strip at most one leading U+FEFF BOM at stream start.
        let line = if was_at_start {
            raw_line.strip_prefix('\u{feff}').unwrap_or(raw_line)
        } else {
            raw_line
        };
        if line.starts_with(':') {
            self.line_buf.clear();
            return Ok(None);
        }
        let (field, rest) = match line.split_once(':') {
            Some((field, rest)) => (field, rest.strip_prefix(' ').unwrap_or(rest)),
            None => (line, ""),
        };
        match field {
            "data" => {
                let extra = rest.len() + usize::from(self.has_data);
                let name = self.event_name.as_ref().map_or(0, String::len);
                if self.data_buf.len() + extra + name > MAX_FRAME_LEN {
                    return Err(Fault::TooLarge);
                }
                reserve(&mut self.data_buf, extra, MAX_FRAME_LEN).ok_or(Fault::TooLarge)?;
                if self.has_data {
                    self.data_buf.push(b'\n');
                }
                self.data_buf.extend_from_slice(rest.as_bytes());
                self.has_data = true;
            }
            "event" => {
                if self.data_buf.len() + rest.len() > MAX_FRAME_LEN {
                    return Err(Fault::TooLarge);
                }
                self.event_name = (!rest.is_empty()).then(|| rest.to_owned());
            }
            // Per the W3C Server-Sent Events specification, `id`, `retry` and
            // unknown field names are ignored.
            _ => {}
        }
        self.line_buf.clear();
        Ok(None)
    }

    fn dispatch_frame(&mut self) -> Result<Option<ResponseEvent>, Fault> {
        let event_name = self.event_name.take();
        self.has_data = false;
        let payload = without_json_space(&self.data_buf);
        if payload.is_empty() || payload == b"[DONE]" {
            // Nothing to decode. Under a name that ends an answer that is
            // an event gone wrong, and never one to pass over.
            let named = event_name
                .as_deref()
                .is_some_and(stream_event::ends_an_answer);
            self.data_buf.clear();
            return if named {
                Err(Fault::Malformed)
            } else {
                Ok(None)
            };
        }
        let made =
            stream_event::decode(payload, event_name.as_deref()).and_then(|(event, kind)| {
                let tail = Tail::behind(&event);
                // The payload was put together from lines that are text.
                let json = std::str::from_utf8(payload).ok()?;
                Some((ResponseEvent::new(event, kind.as_deref(), json), tail))
            });
        self.data_buf.clear();
        let (made, tail) = made.ok_or(Fault::Malformed)?;
        if tail.is_some() {
            self.tail = tail;
        }
        Ok(Some(made))
    }
}
/// `bytes` without the white space JSON allows around a value: space, tab,
/// line feed and carriage return, and nothing else, so not a form feed.
fn without_json_space(mut bytes: &[u8]) -> &[u8] {
    while let [b' ' | b'\t' | b'\n' | b'\r', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' ' | b'\t' | b'\n' | b'\r'] = bytes {
        bytes = rest;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{Reason, StreamEvent};

    /// The decoded events alone, to compare them.
    trait Plain {
        fn feed_plain(&mut self, chunk: &[u8]) -> Result<Vec<StreamEvent>, Error>;
    }

    impl Plain for SseDecoder {
        fn feed_plain(&mut self, chunk: &[u8]) -> Result<Vec<StreamEvent>, Error> {
            let events = self.feed(chunk)?;
            Ok(events.into_iter().map(ResponseEvent::into_event).collect())
        }
    }

    #[test]
    fn handles_cr_only_lines_multiline_data_redacted_debug_and_all_failure_shapes() {
        // Leading UTF-8 BOM (`\xef\xbb\xbf`), standalone `\r`, and multi-line `data:`.
        let mut sse = SseDecoder::new();
        let out = sse
            .feed_plain(
                b"\xef\xbb\xbfdata: {\"type\":\"response.output_text.delta\",\rdata: \"delta\":\"A\"}\r\r",
            )
            .unwrap();
        assert_eq!(
            out,
            [StreamEvent::TextDelta {
                text: "A".to_owned()
            }]
        );

        // Unterminated data in `line_buf`/`data_buf` never appears in `Debug`,
        // and an EOF before the blank line ends with `Temporary`.
        sse.feed_plain(b"data: {\"delta\":\"secret-stream-text\"")
            .unwrap();
        let dbg = format!("{sse:?}");
        assert!(!dbg.contains("secret-stream-text"), "{dbg}");
        assert!(dbg.contains("buffered_bytes"));
        let cut_err = sse.finish().unwrap_err();
        assert_eq!(cut_err.kind(), ErrorKind::Temporary);
        assert!(cut_err.is_temporary());

        // Multi-line `event: error` without `"type"`, and large (> 64 KiB)
        // `response.failed` frames preserve their provider code.
        let mut named_err = SseDecoder::new();
        let events = named_err
            .feed_plain(
                b"event: error\ndata: {\ndata: \"code\":\"subscription_sharing_usage_limit_exceeded\"\ndata: }\n\n",
            )
            .unwrap();
        assert!(matches!(
            events.as_slice(),
            [StreamEvent::Failed(r)] if r.reason() == Reason::UsageLimit
        ));
        assert_eq!(
            named_err.finish().unwrap_err().kind(),
            ErrorKind::UsageLimit
        );

        let mut large_fail = SseDecoder::new();
        let frame = format!(
            "data: {{\"type\":\"response.failed\",\"response\":{{\"error\":{{\"code\":\"subscription_sharing_usage_limit_exceeded\"}}}},\"pad\":\"{}\"}}\n\n",
            "x".repeat(80 * 1024)
        );
        let events = large_fail.feed_plain(frame.as_bytes()).unwrap();
        assert!(matches!(
            events.as_slice(),
            [StreamEvent::Failed(r)] if r.reason() == Reason::UsageLimit
        ));
        assert_eq!(
            large_fail.finish().unwrap_err().kind(),
            ErrorKind::UsageLimit
        );

        // Codeless `response.failed` preserves `code() == None` rather than
        // fabricating an identifier.
        let mut codeless = SseDecoder::new();
        let events = codeless
            .feed_plain(b"data: {\"type\":\"response.failed\",\"response\":{\"error\":null}}\n\n")
            .unwrap();
        assert!(matches!(
            events.as_slice(),
            [StreamEvent::Failed(r)] if r.reason() == Reason::Other && r.provider_code().is_none()
        ));
        assert_eq!(codeless.finish().unwrap_err().kind(), ErrorKind::Rejected);

        // Bare `{"error": ...}` object with no `event:` or `"type"`.
        let mut bare_err = SseDecoder::new();
        let events = bare_err
            .feed_plain(
                b"data: {\"error\":{\"code\":\"subscription_sharing_user_not_eligible\"}}\n\n",
            )
            .unwrap();
        assert!(matches!(
            events.as_slice(),
            [StreamEvent::Failed(r)] if r.reason() == Reason::NotPermitted
        ));
        assert_eq!(
            bare_err.finish().unwrap_err().kind(),
            ErrorKind::NotPermitted
        );
    }

    #[test]
    fn rejects_invalid_utf8_malformed_json_missing_delta_and_oversized_frames() {
        let mut bad_utf8 = SseDecoder::new();
        assert_eq!(
            bad_utf8.feed_plain(b"data: \xff\n\n").unwrap_err().kind(),
            ErrorKind::InvalidResponse
        );

        let mut bad_json = SseDecoder::new();
        assert_eq!(
            bad_json
                .feed_plain(b"data: {broken\n\n")
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidResponse
        );

        let mut no_delta = SseDecoder::new();
        assert_eq!(
            no_delta
                .feed_plain(b"data: {\"type\":\"response.output_text.delta\"}\n\n")
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidResponse
        );

        // Single line exceeding `MAX_FRAME_LEN`.
        let mut huge_line = SseDecoder::new();
        let big = vec![b'a'; MAX_FRAME_LEN + 8];
        assert_eq!(
            huge_line.feed_plain(&big).unwrap_err().kind(),
            ErrorKind::InvalidResponse
        );

        // Multiple `data:` lines whose combined payload exceeds `MAX_FRAME_LEN`.
        let mut huge_multi = SseDecoder::new();
        let line = format!("data: {}\n", "x".repeat(MAX_FRAME_LEN / 4));
        for _ in 0..3 {
            huge_multi.feed_plain(line.as_bytes()).unwrap();
        }
        assert_eq!(
            huge_multi.feed_plain(line.as_bytes()).unwrap_err().kind(),
            ErrorKind::InvalidResponse
        );
    }

    #[test]
    fn the_line_and_data_buffers_grow_into_new_wiped_allocations() {
        // `reserve` sizes a new buffer to what is needed or twice the old
        // one, where a reallocation would start at 8 bytes and free the old
        // buffer unwiped.
        let mut decoder = SseDecoder::new();
        decoder.feed_plain(b"d").unwrap();
        assert_eq!(decoder.line_buf.capacity(), 1);
        decoder.feed_plain(b"ata: abc").unwrap();
        assert_eq!(decoder.line_buf.capacity(), 16);
        decoder.feed_plain(b"\n").unwrap();
        assert_eq!(decoder.data_buf.capacity(), 3);
        decoder.feed_plain(b"data: d\n").unwrap();
        assert_eq!(decoder.data_buf.capacity(), 6);
        assert_eq!(&decoder.data_buf[..], b"abc\nd");
    }
}
