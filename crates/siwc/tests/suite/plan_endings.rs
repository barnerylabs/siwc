//! How `SseDecoder` ends a stream for an app with its own HTTP client:
//! what `finish` says after each kind of last event, what may follow that
//! event, and which names end an answer.

use siwc::ErrorKind;
use siwc::plan::{Reason, Refusal, SseDecoder, StreamEvent};

const COMPLETED: &str = "data: {\"type\":\"response.completed\"}\n\n";
const LIMIT: &str = "subscription_sharing_usage_limit_exceeded";

/// What `finish` says after `stream` was fed in pieces of `piece` bytes,
/// or the kind of the error a feed returned.
fn ending(stream: &[u8], piece: usize) -> Result<(), ErrorKind> {
    let mut decoder = SseDecoder::new();
    for chunk in stream.chunks(piece.max(1)) {
        decoder.feed(chunk).map_err(|error| error.kind())?;
    }
    decoder.finish().map_err(|error| error.kind())
}

/// The same for every way of cutting the stream that the tests use.
fn ending_however_cut(stream: &[u8]) -> Result<(), ErrorKind> {
    let whole = ending(stream, stream.len());
    for piece in [1, 2, 7, 4096] {
        assert_eq!(ending(stream, piece), whole, "pieces of {piece}");
    }
    whole
}

#[test]
fn finish_is_ok_after_completed_and_after_nothing_else() {
    assert_eq!(ending_however_cut(COMPLETED.as_bytes()), Ok(()));

    // An answer the API stopped early, with the documented reason.
    let stopped = "data: {\"type\":\"response.incomplete\",\"response\":\
                   {\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}\n\n";
    assert_eq!(
        ending_however_cut(stopped.as_bytes()),
        Err(ErrorKind::Incomplete)
    );
    let mut decoder = SseDecoder::new();
    decoder.feed(stopped.as_bytes()).unwrap();
    let error = decoder.finish().unwrap_err();
    assert_eq!(error.provider_code(), Some("max_output_tokens"));

    // A failure the API reported: the error of its refusal, both shapes.
    let failed = format!(
        "data: {{\"type\":\"response.failed\",\"response\":{{\"error\":{{\"code\":\"{LIMIT}\"}}}}}}\n\n"
    );
    let error_event = format!("event: error\ndata: {{\"code\":\"{LIMIT}\"}}\n\n");
    for stream in [failed, error_event] {
        assert_eq!(
            ending_however_cut(stream.as_bytes()),
            Err(ErrorKind::UsageLimit)
        );
        let mut decoder = SseDecoder::new();
        decoder.feed(stream.as_bytes()).unwrap();
        assert_eq!(decoder.finish().unwrap_err().provider_code(), Some(LIMIT));
    }

    // No event that ends an answer at all.
    let begun = b"data: {\"type\":\"response.created\"}\n\n";
    assert_eq!(ending_however_cut(begun), Err(ErrorKind::Temporary));
    assert_eq!(ending_however_cut(b""), Err(ErrorKind::Temporary));
}

#[test]
fn after_the_last_event_only_blank_lines_comments_and_one_closing_marker_follow() {
    for tail in [
        "",
        "\n\n\n",
        ": bye\n\n",
        "data: [DONE]\n\n",
        "data:[DONE]\n\n",
        "\n: one\n: two\n\ndata: [DONE]\n\n: three\n",
        "data: [DONE]\r\n\r\n",
        "data: [DONE]\r\r",
        ": the last line ends with a lone carriage return\r",
    ] {
        let stream = format!("{COMPLETED}{tail}");
        assert_eq!(ending_however_cut(stream.as_bytes()), Ok(()), "{tail:?}");
    }

    for tail in [
        // Fields the stream format knows, which the decoder ignores
        // before the last event.
        "id: 7\n\n",
        "retry: 1000\n\n",
        "event: ping\n\n",
        "unknown\n\n",
        // More events, whatever they are.
        "data: {\"type\":\"response.created\"}\n\n",
        "data: {\"type\":\"response.completed\"}\n\n",
        "data: {not json}\n\n",
        "data:\n\n",
        // The closing marker comes once, on a line of its own.
        "data: [DONE]\n\ndata: [DONE]\n\n",
        "data: [DONE]\ndata: [DONE]\n\n",
        "data: [DONE] \n\n",
        "data: [DONE]\n: comment inside the marker's event\n\n",
        // A line of a field that the end of the stream cut off.
        "data: {\"type\":\"respo",
        "data: [DO",
        "i",
        // A comment is a line too: cut off, the body did not end where
        // its sender meant it to.
        ": by",
        ":",
        ": bye\n\n: by",
        // A closing marker without the blank line that ends its event.
        "data: [DONE]\n",
        "data: [DONE]",
    ] {
        let stream = format!("{COMPLETED}{tail}");
        assert_eq!(
            ending_however_cut(stream.as_bytes()),
            Err(ErrorKind::InvalidResponse),
            "{tail:?}"
        );
    }

    // The same holds behind the other two endings: the tail is checked
    // before the ending is reported.
    let stopped = "data: {\"type\":\"response.incomplete\"}\n\nid: 7\n\n";
    assert_eq!(
        ending_however_cut(stopped.as_bytes()),
        Err(ErrorKind::InvalidResponse)
    );
}

#[test]
fn a_comment_behind_the_last_event_is_text_like_one_before_it() {
    for comment in [&b": caf\xc3\xa9\n"[..], b": \xf0\x9f\x99\x82\n\n"] {
        let stream = [COMPLETED.as_bytes(), comment].concat();
        assert_eq!(ending_however_cut(&stream), Ok(()));
    }
    for comment in [
        &b": caf\xff\n"[..],
        b": \xc3\n\n",
        b":\xf0\x9f\x99\n",
        b": fine\n: \x80\n",
    ] {
        let behind = [COMPLETED.as_bytes(), comment].concat();
        assert_eq!(
            ending_however_cut(&behind),
            Err(ErrorKind::InvalidResponse),
            "{comment:?}"
        );
        // As before the last event.
        let before = [comment, COMPLETED.as_bytes()].concat();
        assert_eq!(
            ending_however_cut(&before),
            Err(ErrorKind::InvalidResponse),
            "{comment:?}"
        );
    }
}

#[test]
fn a_name_that_ends_an_answer_is_checked_before_empty_data_and_the_closing_marker() {
    // Each of these is followed by a valid `response.completed`, which
    // must not turn the stream into a complete answer.
    for broken in [
        "event: response.incomplete\ndata:\n\n",
        "event: response.incomplete\ndata: \n\n",
        "event: error\ndata: [DONE]\n\n",
        "event: response.failed\ndata: [DONE]\n\n",
        "event: response.completed\ndata:\n\n",
        // The name alone, without a line of data.
        "event: response.incomplete\n\n",
        "event: error\n\n",
    ] {
        let stream = format!("{broken}{COMPLETED}");
        assert_eq!(
            ending_however_cut(stream.as_bytes()),
            Err(ErrorKind::InvalidResponse),
            "{broken:?}"
        );
    }

    // What says nothing still says nothing: a marker or empty data
    // without such a name, and a name the crate does not know.
    for quiet in [
        "data: [DONE]\n\n",
        "data:\n\n",
        "event: ping\ndata:\n\n",
        "event: ping\n\n",
        "event: response.future_kind\ndata: [DONE]\n\n",
    ] {
        let stream = format!("{quiet}{COMPLETED}");
        assert_eq!(ending_however_cut(stream.as_bytes()), Ok(()), "{quiet:?}");
    }
}

#[test]
fn only_the_white_space_of_json_may_stand_around_an_event() {
    let json = "{\"type\":\"response.completed\"}";
    for around in [" ", "\t", " \t  "] {
        let stream = format!("data: {around}{json}{around}\n\n");
        assert_eq!(ending_however_cut(stream.as_bytes()), Ok(()), "{around:?}");
    }
    // A form feed and a vertical tab are no white space in JSON.
    for around in ["\u{c}", "\u{b}"] {
        for stream in [
            format!("data: {around}{json}\n\n"),
            format!("data: {json}{around}\n\n"),
            format!("data: {around}\n\n{COMPLETED}"),
            format!("data: {around}[DONE]{around}\n\n{COMPLETED}"),
        ] {
            assert_eq!(
                ending_however_cut(stream.as_bytes()),
                Err(ErrorKind::InvalidResponse),
                "{stream:?}"
            );
        }
    }
}

#[test]
fn the_tail_holds_4096_bytes_counted_behind_the_whole_line_end() {
    // A comment of exactly `len` bytes with its line end.
    let comment =
        |len: usize, line_end: &str| format!(":{}{line_end}", "x".repeat(len - 1 - line_end.len()));
    for line_end in ["\n", "\r\n", "\r"] {
        let completed = COMPLETED.replace('\n', line_end);
        let fits = format!("{completed}{}", comment(4096, line_end));
        assert_eq!(ending_however_cut(fits.as_bytes()), Ok(()), "{line_end:?}");
        let over = format!("{completed}{}", comment(4097, line_end));
        assert_eq!(
            ending_however_cut(over.as_bytes()),
            Err(ErrorKind::InvalidResponse),
            "{line_end:?}"
        );
    }
}

#[test]
fn a_name_that_ends_an_answer_needs_a_type_that_says_the_same() {
    // Named as an ending, with JSON that says nothing or something else:
    // never an event to pass over, after which a `completed` would count.
    for (name, json) in [
        ("response.incomplete", "{}"),
        ("response.incomplete", "{\"type\":7}"),
        (
            "response.incomplete",
            "{\"response\":{\"status\":\"incomplete\"}}",
        ),
        ("response.completed", "{}"),
        ("response.completed", "{\"type\":null}"),
        (
            "response.incomplete",
            "{\"type\":\"response.output_text.delta\",\"delta\":\"x\"}",
        ),
    ] {
        let stream = format!("event: {name}\ndata: {json}\n\n{COMPLETED}");
        assert_eq!(
            ending_however_cut(stream.as_bytes()),
            Err(ErrorKind::InvalidResponse),
            "{name} {json}"
        );
    }

    // A failure is read from its name alone, as before.
    for (name, json) in [
        ("error", format!("{{\"code\":\"{LIMIT}\"}}")),
        (
            "response.failed",
            format!("{{\"response\":{{\"error\":{{\"code\":\"{LIMIT}\"}}}}}}"),
        ),
    ] {
        let stream = format!("event: {name}\ndata: {json}\n\n");
        let events = SseDecoder::new().feed(stream.as_bytes()).unwrap();
        assert!(matches!(
            events[0].event(),
            StreamEvent::Failed(refusal) if refusal.reason() == Reason::UsageLimit
        ));
    }

    // A name the crate does not know is still passed over.
    let stream = format!("event: response.future_thing\ndata: {{\"n\":1}}\n\n{COMPLETED}");
    assert_eq!(ending_however_cut(stream.as_bytes()), Ok(()));
    let events = SseDecoder::new().feed(stream.as_bytes()).unwrap();
    assert_eq!(events[0].event(), &StreamEvent::Other);
}

#[test]
fn debug_of_a_refusal_and_of_a_failure_event_names_only_documented_codes() {
    // An identifier is all a code has to look like: this could be a word
    // of the prompt or anything else the provider had at hand.
    let free = "zz_prompt_word_17";
    let body = format!(
        "{{\"error\":{{\"code\":\"{free}\",\"param\":\"{free}.param\",\"message\":\"m\"}}}}"
    );
    let refusal = Refusal::from_response(403, body.as_bytes())
        .unwrap()
        .with_request_id(Some("req_zz_free_text_17"))
        .with_retry_after(Some("814275"));
    // Readable where an app asks for it.
    assert_eq!(refusal.provider_code(), Some(free));
    assert_eq!(refusal.request_id(), Some("req_zz_free_text_17"));
    let debug = format!("{refusal:?}");
    assert_eq!(
        refusal.retry_after(),
        Some(std::time::Duration::from_secs(814275))
    );
    for debug in [&debug, &format!("{:?}", StreamEvent::Failed(refusal))] {
        assert!(!debug.contains("814275"), "{debug}");
        assert!(debug.contains("has_retry_after: true"), "{debug}");
    }
    assert!(!debug.contains("zz_"), "{debug}");
    assert!(
        debug.contains("NotPermitted") && debug.contains("403"),
        "{debug}"
    );

    let stream = format!(
        "data: {{\"type\":\"response.failed\",\"response\":{{\"error\":{{\"code\":\"{free}\"}}}}}}\n\n"
    );
    let events = SseDecoder::new().feed(stream.as_bytes()).unwrap();
    for debug in [format!("{events:?}"), format!("{:?}", events[0].event())] {
        assert!(!debug.contains("zz_"), "{debug}");
        assert!(debug.contains("Failed"), "{debug}");
    }

    // A code the provider documents is named.
    let known = Refusal::from_response(
        429,
        format!("{{\"error\":{{\"code\":\"{LIMIT}\"}}}}").as_bytes(),
    )
    .unwrap();
    assert!(format!("{known:?}").contains(LIMIT));
}
