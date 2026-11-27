//! Values the provider sends that end up in errors and `Debug` output: a
//! token that comes back is dropped, and a reason nobody documents is not
//! named.

use siwc::plan::{SseDecoder, StreamEvent};
use siwc::protocol::StreamingResponse;
use siwc::testing::{FakeProvider, FakeResponse};
use siwc::{Error, ErrorKind};

use crate::support::executor::block_on;

use super::answers::{Wired, delta, frame, opening};
use super::{Desk, items_async, kinds, last_error, request};

fn shows(error: &Error, secret: &str) -> bool {
    format!("{error:?} {error}").contains(secret)
        || error.provider_code() == Some(secret)
        || error.request_id() == Some(secret)
}

#[test]
fn a_token_the_provider_sends_back_is_in_no_error_and_no_debug_output() {
    let (wired, client, id, _clock) = Wired::desk();
    let token = client.access_token(&id).unwrap().expose().to_owned();

    // As the request ID and as the reason of an answer that stopped.
    let stopped = |token: &str| {
        let event = format!(
            r#"{{"type":"response.incomplete","response":{{"incomplete_details":{{"reason":"{token}"}}}}}}"#
        );
        [opening(), delta("Half"), frame(&event)].concat()
    };
    let queue = |wired: &Wired| {
        let served = wired.body(Vec::new());
        wired.answer(move |token| {
            let mut body = served;
            body.fill(stopped(token));
            StreamingResponse::new(200, body).with_request_id(Some(token))
        });
    };
    queue(&wired);
    let mut stream = client.stream_response(&id, &request()).unwrap();
    assert_eq!(stream.request_id(), None);
    assert!(!format!("{stream:?}").contains(&token));
    let error = stream.by_ref().last().unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Incomplete);
    assert!(!shows(&error, &token));
    assert!(!format!("{stream:?}").contains(&token));

    queue(&wired);
    block_on(async {
        let mut stream = client.stream_response_async(&id, &request()).await.unwrap();
        assert_eq!(stream.request_id(), None);
        let mut last = None;
        while let Some(item) = stream.next().await {
            assert!(!format!("{item:?} {stream:?}").contains(&token));
            last = Some(item);
        }
        assert!(!shows(&last.unwrap().unwrap_err(), &token));
    });

    // As the code of a failure inside the stream, after output.
    wired.answer({
        let served = wired.body(Vec::new());
        move |token| {
            let mut body = served;
            let failed = FakeProvider::failure_event(token, None);
            body.fill([opening(), delta("Half"), failed].concat());
            StreamingResponse::new(200, body).with_request_id(Some(token))
        }
    });
    let stream = client.stream_response(&id, &request()).unwrap();
    let error = stream.last().unwrap().unwrap_err();
    assert_eq!(error.provider_code(), None);
    assert!(!shows(&error, &token));

    // As the code and the request ID of a refusal.
    wired.answer({
        let served = wired.body(Vec::new());
        move |token| {
            let mut body = served;
            body.fill(FakeProvider::refusal_body(token, None));
            StreamingResponse::new(403, body).with_request_id(Some(token))
        }
    });
    let error = client.stream_response(&id, &request()).unwrap_err();
    assert_eq!(error.http_status(), Some(403));
    assert_eq!(error.provider_code(), None);
    assert_eq!(error.request_id(), None);
    assert!(!shows(&error, &token));
    assert_eq!(wired.sent(), 4);
}

#[test]
fn a_reason_the_provider_does_not_document_is_named_nowhere() {
    // It looks like an identifier, and could be anything.
    let unknown = "zz_synthetic_reason_9";
    let desk = Desk::new();
    let script = || {
        FakeResponse::stream()
            .created()
            .delta("Half")
            .incomplete(unknown)
    };
    desk.provider.push_response(script());
    desk.provider.push_response(script());
    let blocking = desk.items().unwrap();
    let awaited = items_async(&desk.client, &desk.id).unwrap();
    for items in [blocking, awaited] {
        assert_eq!(kinds(&items).last().unwrap(), "Incomplete");
        let error = last_error(&items);
        assert_eq!(error.provider_code(), None);
        assert!(!shows(error, unknown));
        assert!(!format!("{items:?}").contains(unknown));
    }

    // The two reasons the provider documents are named.
    for known in ["max_output_tokens", "content_filter"] {
        desk.provider
            .push_response(FakeResponse::stream().created().incomplete(known));
        let items = desk.items().unwrap();
        assert_eq!(last_error(&items).provider_code(), Some(known));
    }
}

#[test]
fn incomplete_reasons_have_distinct_raw_typed_and_stream_error_views() {
    let desk = Desk::new();
    for (reason, typed, code) in [
        ("two words", None, None),
        ("other.reason", Some("other.reason"), None),
        (
            "content_filter",
            Some("content_filter"),
            Some("content_filter"),
        ),
    ] {
        let json = serde_json::json!({
            "type": "response.incomplete",
            "response": { "incomplete_details": { "reason": reason } },
        })
        .to_string();
        let frame = frame(&json);
        let mut decoder = SseDecoder::new();
        let events = decoder.feed(&frame).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].json(), json);
        assert!(
            matches!(events[0].event(), StreamEvent::Incomplete { reason, .. } if reason.as_deref() == typed)
        );
        assert_eq!(decoder.finish().unwrap_err().kind(), ErrorKind::Incomplete);

        for _ in 0..2 {
            desk.provider
                .push_response(FakeResponse::stream().raw(&frame));
        }
        for items in [
            desk.items().unwrap(),
            items_async(&desk.client, &desk.id).unwrap(),
        ] {
            assert_eq!(kinds(&items), ["Incomplete"]);
            assert_eq!(last_error(&items).provider_code(), code);
        }
    }
}
