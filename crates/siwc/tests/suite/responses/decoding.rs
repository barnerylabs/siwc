//! Events the stream cannot take as they are: what comes out before the
//! error, and what the error says.

use std::num::NonZeroUsize;

use siwc::ErrorKind;
use siwc::testing::FakeResponse;

use super::{Desk, items_async, kinds, last_error, text};

#[test]
fn events_before_a_broken_one_come_out_first_however_the_bytes_arrive() {
    let script = || {
        FakeResponse::stream()
            .created()
            .delta("Good")
            .raw(b"data: {not json}\n\n")
            .delta("never shown")
            .completed()
    };
    // In one read, byte by byte, and cut inside the broken event.
    for piece in [usize::MAX, 1, 7, 200].map(|n| NonZeroUsize::new(n).unwrap()) {
        let desk = Desk::new();
        desk.provider.push_response(script().split_every(piece));
        desk.provider.push_response(script().split_every(piece));
        let blocking = desk.items().unwrap();
        let awaited = items_async(&desk.client, &desk.id).unwrap();
        for items in [blocking, awaited] {
            assert_eq!(
                kinds(&items),
                [
                    "response.created",
                    "response.in_progress",
                    "response.output_text.delta",
                    "InvalidResponse",
                ],
                "pieces of {piece}"
            );
            assert_eq!(text(&items), "Good");
            // The error says which answer it was.
            let id = last_error(&items).request_id().unwrap();
            assert!(id.starts_with("req_fake_"));
        }
    }
}

#[test]
fn an_event_named_one_ending_and_typed_another_ends_the_stream() {
    for contradiction in [
        &b"event: error\ndata: {\"type\":\"response.completed\"}\n\n"[..],
        b"event: response.failed\ndata: {\"type\":\"response.completed\"}\n\n",
        b"event: response.completed\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\n\n",
        b"event: response.completed\ndata: {\"type\":\"response.incomplete\"}\n\n",
    ] {
        let desk = Desk::new();
        desk.provider.push_response(
            FakeResponse::stream()
                .created()
                .delta("All of it")
                .raw(contradiction),
        );
        let items = desk.items().unwrap();
        assert_eq!(
            kinds(&items),
            [
                "response.created",
                "response.in_progress",
                "response.output_text.delta",
                "InvalidResponse",
            ]
        );
        assert_eq!(desk.provider.plan_requests().len(), 1);
    }

    // A name that says nothing about the ending is only a name.
    let desk = Desk::new();
    desk.provider.push_response(
        FakeResponse::stream()
            .created()
            .raw(b"event: message\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"Fine\"}\n\n")
            .completed(),
    );
    let items = desk.items().unwrap();
    assert_eq!(text(&items), "Fine");
    assert_eq!(kinds(&items).last().unwrap(), "response.completed");
}

#[test]
fn a_ninth_opening_event_ends_the_stream_before_anything_is_handed_out() {
    let opening = r#"{"type":"response.queued"}"#;
    let opened =
        |events: usize| (0..events).fold(FakeResponse::stream(), |script, _| script.event(opening));

    // Eight are held back and handed out with the first output.
    let desk = Desk::new();
    desk.provider
        .push_response(opened(8).delta("Here.").completed());
    let items = desk.items().unwrap();
    assert_eq!(items.len(), 10);
    assert!(items.iter().all(Result::is_ok));

    // Eight, then a failure: none of the held events leave the stream.
    let desk = Desk::new();
    desk.provider.push_response(opened(8).failed(super::BUSY));
    desk.provider
        .push_response(FakeResponse::text(&["never shown"]));
    let items = desk.items().unwrap();
    assert_eq!(kinds(&items), ["Temporary"]);
    assert_eq!(last_error(&items).provider_code(), Some(super::BUSY));
    assert_eq!(desk.provider.plan_requests().len(), 1);

    // A ninth is no answer the stream knows: nothing comes out but the
    // error, and nothing is sent again.
    let desk = Desk::new();
    desk.provider
        .push_response(opened(9).delta("never shown").completed());
    desk.provider
        .push_response(FakeResponse::text(&["never shown"]));
    let items = desk.items().unwrap();
    assert_eq!(kinds(&items), ["InvalidResponse"]);
    assert!(last_error(&items).request_id().is_some());
    assert_eq!(desk.provider.plan_requests().len(), 1);
}

#[test]
fn opening_events_larger_than_16_mib_together_end_the_stream() {
    const LIMIT: usize = 16 * 1024 * 1024;
    let frame = r#"{"type":"response.created","padding":""}"#;
    let opening = |len| frame.replace(r#""""#, &format!(r#""{}""#, "a".repeat(len - frame.len())));
    for extra in [0, 1] {
        let desk = Desk::new();
        desk.provider.push_response(
            FakeResponse::stream()
                .event(&opening(LIMIT / 2))
                .event(&opening(LIMIT / 2 + extra))
                .delta("ready")
                .completed(),
        );
        let items = desk.items().unwrap();
        if extra == 0 {
            assert_eq!(
                kinds(&items),
                [
                    "response.created",
                    "response.created",
                    "response.output_text.delta",
                    "response.completed"
                ]
            );
        } else {
            assert_eq!(kinds(&items), ["InvalidResponse"]);
        }
        assert_eq!(desk.provider.plan_requests().len(), 1);
    }
}

#[test]
fn an_unexpected_success_status_is_reported_with_the_status_it_was() {
    for status in [201, 202, 204, 206] {
        let desk = Desk::new();
        desk.provider
            .push_response(FakeResponse::detail(status, "nothing here"));
        desk.provider
            .push_response(FakeResponse::text(&["never shown"]));
        let error = desk.items().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
        assert_eq!(error.http_status(), Some(status));
        assert!(error.request_id().is_some());
        assert_eq!(desk.provider.plan_requests().len(), 1);
    }
}
