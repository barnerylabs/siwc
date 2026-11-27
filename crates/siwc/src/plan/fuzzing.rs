//! Entry points for the cargo-fuzz harnesses, built only with
//! `--cfg fuzzing`.

use crate::error::ErrorKind;
use crate::protocol::HttpResponse;

use super::{Models, Refusal, ResponseRequest, SseDecoder, StreamEvent};

impl Models {
    /// Reads a model list for the cargo-fuzz harness.
    #[doc(hidden)]
    pub fn fuzz_response(response: &HttpResponse) {
        let _parsed = Self::from_response(response);
    }
}

impl Refusal {
    /// Reads a buffered refusal for the cargo-fuzz harness.
    #[doc(hidden)]
    pub fn fuzz_response(response: &HttpResponse) {
        let _parsed = Self::from_response(response.status(), response.body());
    }
}

/// What a decoder hands out for one input: each event with its type, its
/// JSON and what was read from it, and the kind of the error that decoding
/// or the end of the stream gave.
type Decoded = (
    Vec<(Option<String>, String, StreamEvent)>,
    Option<ErrorKind>,
);

/// Through the public `feed`, the way an app uses the decoder: what it
/// hands out, in the order it does, with an error that waited behind
/// events asked for by one more, empty, feed before `finish`.
fn decoded<'a>(pieces: impl Iterator<Item = &'a [u8]>) -> Decoded {
    let mut decoder = SseDecoder::new();
    let mut seen = Vec::new();
    for piece in pieces.chain(std::iter::once(&[][..])) {
        match decoder.feed(piece) {
            Ok(events) => {
                for event in events {
                    let kind = event.event_type().map(str::to_owned);
                    let json = event.json().to_owned();
                    seen.push((kind, json, event.into_event()));
                }
            }
            Err(error) => return (seen, Some(error.kind())),
        }
    }
    let end = decoder.finish().err().map(|error| error.kind());
    (seen, end)
}

/// The first byte sets the chunk size. Classifies the remaining payload
/// as a failure event and feeds it through [`SseDecoder`] whole and in chunks.
/// For cargo-fuzz harnesses only.
///
/// # Panics
///
/// When the events, their content or the error depend on how the bytes
/// were split. The message names none of the content.
pub fn fuzz_event(data: &[u8]) {
    if let Some((&step, rest)) = data.split_first() {
        let _parsed = Refusal::from_event(rest);
        let split = decoded(rest.chunks(usize::from(step.max(1))));
        let at_once = decoded(std::iter::once(rest));
        assert!(split == at_once, "the split changed what was decoded");
    }
}

/// Builds a plan request from `data`: as JSON text, and as a model name
/// and an input separated by the first line break. For cargo-fuzz
/// harnesses only.
///
/// # Panics
///
/// When a request that was accepted is not one JSON object within the
/// size limit that says `"store": false` and `"stream": true`.
pub fn fuzz_request(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(request) = ResponseRequest::from_json(text) {
        request.assert_sendable(None);
    }
    if let Some((model, input)) = text.split_once('\n') {
        if let Ok(request) = ResponseRequest::text(model, input) {
            request.assert_sendable(Some((model, input, None)));
        }
        if let Ok(request) = ResponseRequest::text_with_instructions(model, input, input) {
            request.assert_sendable(Some((model, input, Some(input))));
        }
    }
}
