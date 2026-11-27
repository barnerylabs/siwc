//! When an answer counts as complete: `response.completed` and a body that
//! ended the way its head announced, and what `into_text` makes of it.

use std::num::NonZeroUsize;

use siwc::ErrorKind;
use siwc::protocol::StreamingResponse;
use siwc::testing::FakeResponse;

use crate::support::executor::block_on;

use super::answers::{Wired, completed, delta, opening};
use super::{Desk, items_async, kinds, last_error, request, text};

#[test]
fn completed_is_handed_out_only_once_the_body_has_ended_cleanly() {
    // What a transport reports when the last chunk was cut, its end marker
    // never came or bytes of the declared length are missing: the read
    // after the last event fails.
    let endings: [fn(FakeResponse) -> FakeResponse; 2] =
        [FakeResponse::interrupted, FakeResponse::times_out];
    for ending in endings {
        let desk = Desk::new();
        for _ in 0..3 {
            desk.provider
                .push_response(ending(FakeResponse::text(&["All of it"])));
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
                    "Temporary",
                ]
            );
            assert!(last_error(&items).request_id().is_some());
        }
        let whole = desk.client.stream_response(&desk.id, &request()).unwrap();
        assert_eq!(whole.into_text().unwrap_err().kind(), ErrorKind::Temporary);
        // A broken connection is never a reason to send again.
        assert_eq!(desk.provider.plan_requests().len(), 3);
        assert!(desk.clock.sleeps().is_empty());
    }
}

#[test]
fn after_completed_only_a_closing_marker_and_comments_may_follow() {
    for tail in [&b"data: [DONE]\n\n"[..], b": bye\n\n", b"\n\n\n"] {
        for piece in [NonZeroUsize::MAX, NonZeroUsize::MIN] {
            let desk = Desk::new();
            let script = FakeResponse::text(&["All of it"]).raw(tail);
            desk.provider.push_response(script.split_every(piece));
            let items = desk.items().unwrap();
            assert_eq!(kinds(&items).last().unwrap(), "response.completed");
            assert_eq!(text(&items), "All of it");
        }
    }

    // More than a closing marker's worth of bytes is not an ending.
    let long_comment = format!(": {}\n\n", "x".repeat(5000));
    for tail in [
        &b"data: {\"type\":\"response.output_text.delta\",\"delta\":\" and more\"}\n\n"[..],
        b"data: {\"type\":\"response.completed\"}\n\n",
        b"data: {\"type\":\"response.created\"}\n\n",
        b"data: {not json}\n\n",
        long_comment.as_bytes(),
    ] {
        for piece in [NonZeroUsize::MAX, NonZeroUsize::MIN] {
            let desk = Desk::new();
            let script = FakeResponse::text(&["All of it"]).raw(tail);
            desk.provider.push_response(script.split_every(piece));
            let items = desk.items().unwrap();
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
            assert!(last_error(&items).request_id().is_some());
            assert_eq!(desk.provider.plan_requests().len(), 1);
        }
    }
}

#[test]
fn into_text_refuses_an_answer_longer_than_sixteen_mebibytes() {
    // 85 pieces of 200 KiB: the 82nd crosses 16 MiB.
    let piece = "a".repeat(200 * 1024);
    let mut answer = opening();
    for _ in 0..85 {
        answer.extend(delta(&piece));
    }
    answer.extend(completed());
    let total = answer.len() as u64;

    let (wired, client, id, _clock) = Wired::desk();
    let request_id = Some("req_long_answer");
    let body = wired.body(answer.clone());
    wired.answer(move |_| StreamingResponse::new(200, body).with_request_id(request_id));
    let stream = client.stream_response(&id, &request()).unwrap();
    let sync_error = stream.into_text().unwrap_err();
    // Reading stopped where the budget was crossed.
    assert!(wired.served() < total - 400 * 1024, "{}", wired.served());

    let body = wired.body(answer.clone());
    wired.answer(move |_| StreamingResponse::new(200, body).with_request_id(request_id));
    let async_error = block_on(async {
        let stream = client.stream_response_async(&id, &request()).await?;
        stream.into_text().await
    })
    .unwrap_err();
    assert_eq!(sync_error.kind(), ErrorKind::InvalidResponse);
    assert_eq!(async_error.kind(), ErrorKind::InvalidResponse);
    assert_eq!(
        [sync_error.request_id(), async_error.request_id()],
        [request_id; 2]
    );

    // The iterator itself has no such limit.
    let body = wired.body(answer);
    wired.answer(move |_| StreamingResponse::new(200, body));
    let stream = client.stream_response(&id, &request()).unwrap();
    let read: usize = stream
        .map(|event| event.unwrap().text_delta().map_or(0, str::len))
        .sum();
    assert_eq!(read, 85 * piece.len());
}

#[test]
fn into_text_is_only_for_a_stream_nothing_was_read_from() {
    // 20 KiB of answer, so that the first event leaves most of it unread.
    let mut answer = opening();
    for _ in 0..300 {
        answer.extend(delta("0123456789"));
    }
    answer.extend(completed());

    let (wired, client, id, _clock) = Wired::desk();
    let body = wired.body(answer.clone());
    wired.answer(move |_| StreamingResponse::new(200, body));
    let mut stream = client.stream_response(&id, &request()).unwrap();
    stream.next().unwrap().unwrap();
    let read = wired.served();
    // The rest would not be the whole answer: an error, and nothing read.
    let error = stream.into_text().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(wired.served(), read);

    let body = wired.body(answer);
    wired.answer(move |_| StreamingResponse::new(200, body));
    let error = block_on(async {
        let mut stream = client.stream_response_async(&id, &request()).await?;
        stream.next().await.unwrap()?;
        stream.into_text().await
    })
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    // An answer whose error was already handed out never turns into text.
    let desk = Desk::new();
    let stopped = || {
        FakeResponse::stream()
            .created()
            .incomplete("max_output_tokens")
    };
    desk.provider.push_response(stopped());
    let mut stream = desk.client.stream_response(&desk.id, &request()).unwrap();
    let error = stream.by_ref().last().unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Incomplete);
    assert_eq!(
        stream.into_text().unwrap_err().kind(),
        ErrorKind::InvalidInput
    );

    desk.provider.push_response(stopped());
    let error = block_on(async {
        let mut stream = desk
            .client
            .stream_response_async(&desk.id, &request())
            .await?;
        let mut last = None;
        while let Some(item) = stream.next().await {
            last = Some(item);
        }
        assert_eq!(last.unwrap().unwrap_err().kind(), ErrorKind::Incomplete);
        stream.into_text().await
    })
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}
