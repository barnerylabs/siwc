//! The byte that controls chunking precedes the SSE frame in each seed.

use siwc::ErrorKind;
use siwc::plan::{Refusal, SseDecoder, StreamEvent};

/// Decode the corpus input with the same control byte as the fuzz target.
fn decode(seed: &[u8]) -> (Vec<siwc::plan::ResponseEvent>, Result<(), siwc::Error>) {
    let (&chunk, payload) = seed.split_first().unwrap();
    let mut decoder = SseDecoder::new();
    let events = payload
        .chunks(usize::from(chunk.max(1)))
        .flat_map(|part| decoder.feed(part).unwrap())
        .collect();
    (events, decoder.finish())
}

#[test]
fn completed_with_tail_keeps_its_delta_and_clean_ending() {
    let (events, ending) = decode(include_bytes!("../seeds/stream_event/completed_with_tail"));
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].text_delta(), Some("Half"));
    assert!(matches!(events[1].event(), StreamEvent::Completed { .. }));
    ending.unwrap();
}

#[test]
fn delta_then_error_keeps_its_delta_and_usage_limit() {
    let (events, ending) = decode(include_bytes!("../seeds/stream_event/delta_then_error"));
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].text_delta(), Some("Half"));
    assert!(matches!(events[1].event(), StreamEvent::Failed(_)));
    assert_eq!(ending.unwrap_err().kind(), ErrorKind::UsageLimit);
}

#[test]
fn stream_event_seeds_leave_their_first_sse_field_intact() {
    let cases = [
        (
            include_bytes!("../seeds/stream_event/done").as_slice(),
            "data: [DONE]",
            None,
        ),
        (
            include_bytes!("../seeds/stream_event/error_event").as_slice(),
            "event: error",
            Some("subscription_sharing_unsupported_capability"),
        ),
        (
            include_bytes!("../seeds/stream_event/response_failed").as_slice(),
            "event: response.failed",
            Some("subscription_sharing_usage_limit_exceeded"),
        ),
    ];
    for (seed, field, code) in cases {
        let (_, payload) = seed.split_first().unwrap();
        assert_eq!(
            payload.split(|&byte| byte == b'\n').next(),
            Some(field.as_bytes())
        );
        let refusal = Refusal::from_event(payload);
        assert_eq!(refusal.as_ref().and_then(Refusal::provider_code), code);
        let (events, _) = decode(seed);
        if let Some(code) = code {
            assert_eq!(events.len(), 1);
            assert!(
                matches!(events[0].event(), StreamEvent::Failed(refusal) if refusal.provider_code() == Some(code))
            );
        } else {
            assert!(events.is_empty());
        }
    }
}
