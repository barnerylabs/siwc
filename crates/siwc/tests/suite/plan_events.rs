//! `SseDecoder` as an app with its own HTTP client uses it: what a feed
//! returns around a broken event, how large an event may be, and what
//! `Debug` shows of one.

use siwc::ErrorKind;
use siwc::plan::{SseDecoder, StreamEvent};

const DELTA: &[u8] = b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"Good\"}\n\n";

/// The text deltas and the kind of the error a decoder hands out for
/// `stream` cut into pieces of `piece` bytes.
fn decoded(stream: &[u8], piece: usize) -> (Vec<String>, Option<ErrorKind>) {
    let mut decoder = SseDecoder::new();
    let mut deltas = Vec::new();
    for chunk in stream.chunks(piece) {
        match decoder.feed(chunk) {
            Ok(events) => deltas.extend(
                events
                    .iter()
                    .filter_map(|event| event.text_delta().map(str::to_owned)),
            ),
            Err(error) => return (deltas, Some(error.kind())),
        }
    }
    (deltas, decoder.finish().err().map(|error| error.kind()))
}

#[test]
fn an_error_follows_the_events_that_were_complete_before_it() {
    let stream = [DELTA, b"data: {not json}\n\n", DELTA].concat();

    // In one feed: the event first, the error from the next call on.
    let mut decoder = SseDecoder::new();
    let events = decoder.feed(&stream).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].text_delta(), Some("Good"));
    for more in [&b""[..], DELTA] {
        let error = decoder.feed(more).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
    }
    assert_eq!(
        decoder.finish().unwrap_err().kind(),
        ErrorKind::InvalidResponse
    );

    // The same events and the same error however the bytes are cut.
    let whole = decoded(&stream, stream.len());
    assert_eq!(
        whole,
        (vec!["Good".to_owned()], Some(ErrorKind::InvalidResponse))
    );
    for piece in [1, 2, 7, 64, stream.len() - 1] {
        assert_eq!(decoded(&stream, piece), whole, "pieces of {piece}");
    }
}

#[test]
fn the_event_name_counts_towards_the_size_of_an_event() {
    const LIMIT: usize = 16 * 1024 * 1024;
    let name = "x".repeat(1000);
    // An event of `len` bytes: its name, the six bytes of `data: ` and the
    // JSON, padded inside the text.
    let event = |name: &str, len: usize| {
        let empty = r#"{"type":"response.output_text.delta","delta":""}"#;
        let text = "a".repeat(len - name.len() - "data: ".len() - empty.len());
        let named = if name.is_empty() {
            String::new()
        } else {
            format!("event: {name}\n")
        };
        format!("{named}data: {{\"type\":\"response.output_text.delta\",\"delta\":\"{text}\"}}\n\n")
    };

    let at_the_limit = decoded(event(&name, LIMIT).as_bytes(), 4096);
    assert_eq!(at_the_limit.0.len(), 1);
    assert_eq!(at_the_limit.1, Some(ErrorKind::Temporary), "no completed");
    let over = decoded(event(&name, LIMIT + 1).as_bytes(), 4096);
    assert_eq!(over, (Vec::new(), Some(ErrorKind::InvalidResponse)));
    // The same JSON without a name is within the limit: the name counted.
    let unnamed = decoded(event("", LIMIT + 1 - name.len()).as_bytes(), 4096);
    assert_eq!(unnamed.0.len(), 1);
}

#[test]
fn debug_of_an_event_shows_no_text_through_either_accessor() {
    let unknown = "zz_synthetic_reason_9";
    let incomplete = |reason: &str| {
        format!(
            "data: {{\"type\":\"response.incomplete\",\"response\":{{\"incomplete_details\":{{\"reason\":\"{reason}\"}}}}}}\n\n"
        )
    };
    // An answer ends once, so each ending has a stream of its own.
    let mut events = Vec::new();
    for stream in [
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"secret-model-text\"}\n\n",
        &incomplete(unknown),
        &incomplete("max_output_tokens"),
    ] {
        events.extend(SseDecoder::new().feed(stream.as_bytes()).unwrap());
    }
    assert_eq!(events.len(), 3);
    for event in &events {
        for debug in [format!("{event:?}"), format!("{:?}", event.event())] {
            assert!(!debug.contains("secret-model-text"), "{debug}");
            assert!(!debug.contains(unknown), "{debug}");
        }
    }

    // A documented reason is named.
    let known = events.pop().unwrap().into_event();
    assert_eq!(
        format!("{known:?}"),
        "Incomplete { reason: Some(\"max_output_tokens\") }"
    );
    // Any other is a placeholder in `Debug` and readable where an app asks
    // for it.
    let other = events.pop().unwrap().into_event();
    assert_eq!(
        format!("{other:?}"),
        "Incomplete { reason: Some(\"other\") }"
    );
    let reason = match other {
        StreamEvent::Incomplete { reason, .. } => reason,
        _ => None,
    };
    assert_eq!(reason.as_deref(), Some(unknown));
    let delta = events.pop().unwrap().into_event();
    assert_eq!(format!("{delta:?}"), "TextDelta { len: 17 }");
}

#[test]
fn events_that_may_carry_more_data_later_are_matched_with_a_rest_pattern() {
    let stream = [
        DELTA,
        b"data: {\"type\":\"response.completed\",\"response\":{}}\n\n",
    ]
    .concat();
    let mut events = SseDecoder::new().feed(&stream).unwrap().into_iter();
    let text = match events.next().unwrap().into_event() {
        StreamEvent::TextDelta { text, .. } => text,
        other => panic!("{other:?}"),
    };
    assert_eq!(text, "Good");
    assert!(matches!(
        events.next().unwrap().event(),
        StreamEvent::Completed { .. }
    ));
}
