//! What stands between the last event of an answer and the end of its
//! body, and which endings need the body to be read to that end.

use std::num::NonZeroUsize;

use siwc::ErrorKind;
use siwc::testing::FakeResponse;

use super::{BUSY, Desk, INVALID_USER, items_async, kinds, last_error, request};

/// What a script does to an answer behind its last event.
type Ending = fn(FakeResponse) -> FakeResponse;

#[test]
fn a_field_or_a_cut_line_behind_completed_is_no_clean_end() {
    for tail in [
        &b"id: 7\n\n"[..],
        b"retry: 1000\n\n",
        b"data: [DONE]\n\ndata: [DONE]\n\n",
        // The body ends inside a line, or before the marker's blank line.
        &b"data: {\"type\":\"respo"[..],
        b"data: [DONE]\n",
        // A comment that is cut off, or is not text.
        b": by",
        b": caf\xff\n",
    ] {
        for piece in [NonZeroUsize::MAX, NonZeroUsize::MIN] {
            let desk = Desk::new();
            let script = || {
                FakeResponse::text(&["All of it"])
                    .raw(tail)
                    .split_every(piece)
            };
            for _ in 0..3 {
                desk.provider.push_response(script());
            }
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
                    "{:?} in pieces of {piece}",
                    String::from_utf8_lossy(tail)
                );
            }
            let whole = desk.client.stream_response(&desk.id, &request()).unwrap();
            assert_eq!(
                whole.into_text().unwrap_err().kind(),
                ErrorKind::InvalidResponse
            );
            assert_eq!(desk.provider.plan_requests().len(), 3);
        }
    }
}

#[test]
fn an_event_named_as_an_ending_without_its_json_is_never_passed_over() {
    for broken in [
        &b"event: response.incomplete\ndata:\n\n"[..],
        b"event: error\ndata: [DONE]\n\n",
        b"data: \x0c{\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\n\n",
    ] {
        let desk = Desk::new();
        let script = || FakeResponse::stream().delta("Some").raw(broken).completed();
        desk.provider.push_response(script());
        desk.provider.push_response(script());
        desk.provider.push_response(script());
        let blocking = desk.items().unwrap();
        let awaited = items_async(&desk.client, &desk.id).unwrap();
        for items in [blocking, awaited] {
            assert_eq!(
                kinds(&items),
                ["response.output_text.delta", "InvalidResponse"],
                "{:?}",
                String::from_utf8_lossy(broken)
            );
        }
        let whole = desk.client.stream_response(&desk.id, &request()).unwrap();
        assert_eq!(
            whole.into_text().unwrap_err().kind(),
            ErrorKind::InvalidResponse
        );
    }
}

#[test]
fn comments_of_4096_bytes_fit_behind_completed_with_either_line_end() {
    for line_end in ["\n", "\r\n"] {
        let answer = |comment_len: usize| {
            let events =
                "data: {\"type\":\"response.output_text.delta\",\"delta\":\"All of it\"}\n\n\
                          data: {\"type\":\"response.completed\"}\n\n"
                    .replace('\n', line_end);
            let comment = "x".repeat(comment_len - 1 - line_end.len());
            format!("{events}:{comment}{line_end}")
        };
        for piece in [usize::MAX, 1, 7].map(|n| NonZeroUsize::new(n).unwrap()) {
            let desk = Desk::new();
            let script = |len| FakeResponse::stream().raw(answer(len).as_bytes());
            desk.provider.push_response(script(4096).split_every(piece));
            let stream = desk.client.stream_response(&desk.id, &request()).unwrap();
            assert_eq!(
                stream.into_text().unwrap(),
                "All of it",
                "{line_end:?} in pieces of {piece}"
            );

            desk.provider.push_response(script(4097).split_every(piece));
            let items = desk.items().unwrap();
            assert_eq!(
                kinds(&items),
                ["response.output_text.delta", "InvalidResponse"],
                "{line_end:?} in pieces of {piece}"
            );
        }
    }
}

#[test]
fn an_early_failure_is_terminal_whatever_follows_it() {
    // A failure already ends the request. A clean end, malformed tail or
    // failed read behind it can neither replace it nor allow another POST.
    let endings: [Ending; 7] = [
        |script| script,
        |script| script.raw(b"data: [DONE]\n\n"),
        |script| script.raw(b": by"),
        |script| script.raw(b"id: 7\n\n"),
        FakeResponse::interrupted,
        FakeResponse::times_out,
        |script| script.raw(b"data: {\"type\":\"response.created\"}\n\n"),
    ];
    for (number, ending) in endings.into_iter().enumerate() {
        for piece in [NonZeroUsize::MAX, NonZeroUsize::MIN] {
            let desk = Desk::new();
            let token = desk.token();
            let early =
                |code| ending(FakeResponse::stream().created().failed(code)).split_every(piece);
            desk.provider.push_response(early(BUSY));
            desk.provider.push_response(early(INVALID_USER));
            let blocking = desk.items().unwrap();
            assert_eq!(desk.provider.plan_requests().len(), 1, "ending {number}");
            let awaited = items_async(&desk.client, &desk.id).unwrap();
            assert_eq!(desk.provider.plan_requests().len(), 2, "ending {number}");
            for (items, kind, code) in [
                (blocking, "Temporary", BUSY),
                (awaited, "TokenRejected", INVALID_USER),
            ] {
                assert_eq!(kinds(&items), [kind], "ending {number}, pieces of {piece}");
                let error = last_error(&items);
                assert_eq!(error.provider_code(), Some(code));
                assert_eq!(error.http_status(), None);
                assert!(error.request_id().is_some());
            }
            assert!(desk.clock.sleeps().is_empty(), "ending {number}");
            assert_eq!(desk.token(), token, "ending {number}");
        }
    }
}
