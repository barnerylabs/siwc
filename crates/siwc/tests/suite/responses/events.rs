//! What the stream hands out: the events in order, and how an answer ends.

use siwc::ErrorKind;
use siwc::plan::{ResponseRequest, StreamEvent};
use siwc::testing::FakeResponse;

use crate::support::executor::block_on;

use super::{Desk, kinds, last_error, request, text};

#[test]
fn a_streamed_answer_hands_out_its_events_in_order_and_ends_after_completed() {
    let desk = Desk::new();
    desk.provider
        .push_response(FakeResponse::text(&["The sky ", "is blue."]));

    let mut stream = desk.client.stream_response(&desk.id, &request()).unwrap();
    assert!(stream.request_id().unwrap().starts_with("req_fake_"));
    let items: Vec<_> = stream.by_ref().collect();
    assert_eq!(
        kinds(&items),
        [
            "response.created",
            "response.in_progress",
            "response.output_text.delta",
            "response.output_text.delta",
            "response.completed",
        ]
    );
    assert_eq!(text(&items), "The sky is blue.");
    let completed = items.last().unwrap().as_ref().unwrap();
    assert!(matches!(completed.event(), StreamEvent::Completed { .. }));
    assert!(completed.json().contains("\"total_tokens\":2"));
    // The stream stays ended.
    assert!(stream.next().is_none());
    assert!(stream.next().is_none());

    desk.provider.push_response(FakeResponse::text(&["Again."]));
    let whole = desk.client.stream_response(&desk.id, &request()).unwrap();
    assert_eq!(whole.into_text().unwrap(), "Again.");
}

#[test]
fn the_request_carries_a_stateless_streaming_body_and_the_accounts_token() {
    let desk = Desk::new();
    let asked = ResponseRequest::from_json(
        r#"{"model":"example-small","input":[{"role":"user","content":"Hi"}]}"#,
    )
    .unwrap();
    let stream = desk.client.stream_response(&desk.id, &asked).unwrap();
    stream.into_text().unwrap();

    let bodies = desk.provider.plan_requests();
    assert_eq!(
        bodies,
        [
            r#"{"store":false,"stream":true,"model":"example-small","input":[{"role":"user","content":"Hi"}]}"#
        ]
    );
    // The token is in no body; the provider took it from the header.
    assert!(!bodies[0].contains(&desk.token()));
}

#[test]
fn events_cut_at_any_byte_decode_to_the_same_answer() {
    let said = "Gr\u{fc}\u{df}e, \u{4e16}\u{754c} \u{1f600}!";
    let script = || {
        FakeResponse::stream()
            .raw(b": a comment line\r\n\r\n")
            .created()
            .delta(said)
            .raw(b"event: response.output_text.delta\r\ndata: {\"type\":\"response.output_text.delta\",\r\ndata: \"delta\":\" More.\"}\r\n\r\n")
            .completed()
    };
    let desk = Desk::new();
    desk.provider.push_response(script());
    let whole = kinds(&desk.items().unwrap());

    for piece in 1_usize..=9 {
        desk.provider
            .push_response(script().split_every(piece.try_into().unwrap()));
        let items = desk.items().unwrap();
        assert_eq!(kinds(&items), whole, "pieces of {piece}");
        assert_eq!(text(&items), format!("{said} More."), "pieces of {piece}");
    }
}

#[test]
fn an_answer_that_stops_early_is_incomplete_with_its_reason() {
    let desk = Desk::new();
    desk.provider.push_response(
        FakeResponse::stream()
            .created()
            .delta("The first half")
            .incomplete("max_output_tokens"),
    );
    let items = desk.items().unwrap();
    assert_eq!(text(&items), "The first half");
    let error = last_error(&items);
    assert_eq!(error.kind(), ErrorKind::Incomplete);
    assert_eq!(error.provider_code(), Some("max_output_tokens"));
    assert!(error.request_id().is_some());
    assert!(!error.is_temporary());
    assert_eq!(desk.provider.plan_requests().len(), 1);

    desk.provider.push_response(
        FakeResponse::stream()
            .created()
            .incomplete("content_filter"),
    );
    let error = desk
        .client
        .stream_response(&desk.id, &request())
        .unwrap()
        .into_text()
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Incomplete);
}

#[test]
fn a_malformed_or_oversized_event_ends_the_stream_as_an_invalid_response() {
    let mut oversized = b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"".to_vec();
    oversized.resize(oversized.len() + 300 * 1024, b'a');
    for script in [
        FakeResponse::stream()
            .created()
            .raw(b"data: {not json}\n\n"),
        FakeResponse::stream().created().raw(b"data: \xff\xfe\n\n"),
        FakeResponse::stream().created().raw(&oversized),
        FakeResponse::stream()
            .created()
            .raw(b"data: {\"type\":\"response.output_text.delta\"}\n\n"),
    ] {
        let desk = Desk::new();
        desk.provider.push_response(script.completed());
        let items = desk.items().unwrap();
        let error = last_error(&items);
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
        assert_eq!(desk.provider.plan_requests().len(), 1);
    }
}

#[test]
fn debug_of_the_stream_shows_no_event_text() {
    let desk = Desk::new();
    desk.provider
        .push_response(FakeResponse::text(&["secret-model-text"]));
    let mut stream = desk.client.stream_response(&desk.id, &request()).unwrap();
    let first = stream.next().unwrap().unwrap();
    let delta = stream.nth(1).unwrap().unwrap();
    assert_eq!(delta.text_delta(), Some("secret-model-text"));
    for debug in [
        format!("{stream:?}"),
        format!("{first:?}"),
        format!("{delta:?}"),
        // The event behind either way an app gets at it.
        format!("{:?}", delta.event()),
        format!("{:?}", request()),
    ] {
        assert!(!debug.contains("secret-model-text"), "{debug}");
        assert!(!debug.contains("sky"), "{debug}");
    }
    let owned = format!("{:?}", delta.into_event());
    assert_eq!(owned, "TextDelta { len: 17 }");
}

#[test]
fn an_event_of_an_unknown_type_is_handed_out_and_never_ends_an_answer() {
    // The API adds event types; none of them stands in for
    // `response.completed`, whatever it calls itself.
    let unknown = r#"{"type":"response.done","response":{"status":"completed"}}"#;
    let desk = Desk::new();
    desk.provider.push_response(
        FakeResponse::stream()
            .created()
            .delta("All of it")
            .event(unknown),
    );
    let items = desk.items().unwrap();
    assert_eq!(
        kinds(&items),
        [
            "response.created",
            "response.in_progress",
            "response.output_text.delta",
            "response.done",
            "Temporary",
        ]
    );
    assert_eq!(items[3].as_ref().unwrap().event(), &StreamEvent::Other);

    desk.provider.push_response(
        FakeResponse::stream()
            .created()
            .delta("All of it")
            .event(unknown),
    );
    let whole = desk.client.stream_response(&desk.id, &request()).unwrap();
    assert_eq!(whole.into_text().unwrap_err().kind(), ErrorKind::Temporary);
}

#[test]
fn errors_and_debug_output_show_no_prompt_answer_or_token() {
    let desk = Desk::new();
    let token = desk.token();
    let secrets = [token.as_str(), "secret-answer", "sky", "secret-diagnostic"];
    let clean = |text: String| {
        for secret in secrets {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
    };

    // An answer that fails after output, with the provider's own message.
    let failed = r#"{"type":"response.failed","response":{"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"secret-diagnostic"}}}"#;
    let script = || {
        FakeResponse::stream()
            .created()
            .delta("secret-answer")
            .event(failed)
    };
    desk.provider.push_response(script());
    let mut stream = desk.client.stream_response(&desk.id, &request()).unwrap();
    clean(format!("{stream:?}"));
    let error = stream.by_ref().last().unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UsageLimit);
    clean(format!("{error:?} {error} {stream:?}"));

    // A refusal whose body quotes text back.
    desk.provider
        .push_response(FakeResponse::detail(400, "secret-diagnostic: sky"));
    let error = desk.items().unwrap_err();
    clean(format!("{error:?} {error}"));

    // The same through the async stream.
    desk.provider.push_response(script());
    block_on(async {
        let mut stream = desk
            .client
            .stream_response_async(&desk.id, &request())
            .await
            .unwrap();
        clean(format!("{stream:?}"));
        let mut last = None;
        while let Some(item) = stream.next().await {
            clean(format!("{item:?}"));
            last = Some(item);
        }
        let error = last.unwrap().unwrap_err();
        clean(format!("{error:?} {error} {stream:?}"));
    });
}
