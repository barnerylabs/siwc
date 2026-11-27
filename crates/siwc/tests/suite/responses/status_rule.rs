//! One rule for sending a refused request again, whichever way it was
//! sent: `Client::call`, `Client::call_async` or the stream. The HTTP
//! status decides, whatever code the body carries.

use std::cell::RefCell;
use std::future::ready;

use siwc::AccessToken;
use siwc::plan::{Refusal, SseDecoder, StreamEvent};
use siwc::testing::{FakeProvider, FakeResponse};
use siwc::{Error, ErrorKind};

use crate::support::executor::block_on;

use super::{BUSY, Desk, INVALID_USER, LIMIT, items_async, kinds, text};

/// The code OpenAI gives a server error: not the provider's "not now".
const SERVER_ERROR: &str = "server_error";

/// The provider's other unavailable code, beside `BUSY`.
const USER_BUSY: &str = "subscription_sharing_user_unavailable";

/// What an app's own HTTP client returns to `call`: the refusals of
/// `answers` in turn, then success. Every token it was called with is
/// noted in `sent`.
fn app_answer(
    answers: &[(u16, &str)],
    sent: &RefCell<Vec<String>>,
    token: &AccessToken,
) -> Result<Result<&'static str, Refusal>, Error> {
    let number = sent.borrow().len();
    sent.borrow_mut().push(token.expose().to_owned());
    Ok(match answers.get(number) {
        Some((status, code)) => {
            let body = FakeProvider::refusal_body(code, None);
            Err(Refusal::from_response(*status, &body).unwrap())
        }
        None => Ok("done"),
    })
}

/// The result and the tokens sent, through `call` and `call_async`.
fn called(desk: &Desk, answers: &[(u16, &str)]) -> [(Result<&'static str, Error>, Vec<String>); 2] {
    let sent = RefCell::new(Vec::new());
    let blocking = desk
        .client
        .call(&desk.id, |token| app_answer(answers, &sent, token));
    let blocking = (blocking, sent.take());
    let awaited = block_on(
        desk.client
            .call_async(&desk.id, |token| ready(app_answer(answers, &sent, &token))),
    );
    [blocking, (awaited, sent.take())]
}

#[test]
fn a_401_renews_the_token_once_whatever_code_it_carries() {
    for code in [BUSY, LIMIT, "zz_unknown_code"] {
        // Through the app's own HTTP client.
        let desk = Desk::new();
        for (result, sent) in called(&desk, &[(401, code)]) {
            assert_eq!(result.unwrap(), "done", "{code}");
            assert_eq!(sent.len(), 2, "{code}");
            assert_ne!(sent[0], sent[1], "{code}");
        }
        assert!(desk.clock.sleeps().is_empty(), "{code}");

        // Once: a second 401 is the result, with what its code says.
        for (result, sent) in called(&desk, &[(401, code), (401, code)]) {
            let error = result.unwrap_err();
            assert_eq!(error.http_status(), Some(401), "{code}");
            if code == LIMIT {
                assert_eq!(error.kind(), ErrorKind::UsageLimit);
            }
            assert_eq!(error.provider_code(), Some(code));
            assert_eq!(sent.len(), 2, "{code}");
            // A busy code does not make a refused token worth waiting for.
            assert_ne!(error.kind(), ErrorKind::Temporary, "{code}");
            assert!(!error.is_temporary(), "{code}");
        }
        assert!(desk.clock.sleeps().is_empty(), "{code}");

        // Through the stream, for both clients.
        let desk = Desk::new();
        let before = desk.token();
        desk.provider
            .push_response(FakeResponse::refusal(401, code));
        desk.provider.push_response(FakeResponse::text(&["Here."]));
        assert_eq!(text(&desk.items().unwrap()), "Here.", "{code}");
        assert_eq!(desk.provider.plan_requests().len(), 2, "{code}");
        assert_ne!(desk.token(), before, "{code}");

        desk.provider
            .push_response(FakeResponse::refusal(401, code));
        desk.provider.push_response(FakeResponse::text(&["Here."]));
        let items = items_async(&desk.client, &desk.id).unwrap();
        assert_eq!(text(&items), "Here.", "{code}");
        assert_eq!(desk.provider.plan_requests().len(), 4, "{code}");

        desk.provider
            .push_response(FakeResponse::refusal(401, code));
        desk.provider
            .push_response(FakeResponse::refusal(401, code));
        let error = desk.items().unwrap_err();
        assert_eq!(error.http_status(), Some(401), "{code}");
        if code == LIMIT {
            assert_eq!(error.kind(), ErrorKind::UsageLimit);
        }
        assert_ne!(error.kind(), ErrorKind::Temporary, "{code}");
        assert_eq!(desk.provider.plan_requests().len(), 6, "{code}");
        assert!(desk.clock.sleeps().is_empty(), "{code}");
    }
}

#[test]
fn no_code_turns_another_status_into_a_second_attempt() {
    for (status, code, kind) in [
        // A code that says "not now" on a status that says "no".
        (403, BUSY, ErrorKind::NotPermitted),
        (307, BUSY, ErrorKind::Rejected),
        (400, BUSY, ErrorKind::Rejected),
        (404, BUSY, ErrorKind::Rejected),
        // A code that says the token was refused, on any status but 401.
        (403, INVALID_USER, ErrorKind::TokenRejected),
        (503, INVALID_USER, ErrorKind::TokenRejected),
        // A usage limit is never waited out.
        (429, LIMIT, ErrorKind::UsageLimit),
        (503, LIMIT, ErrorKind::UsageLimit),
    ] {
        let desk = Desk::new();
        let token = desk.token();
        for (result, sent) in called(&desk, &[(status, code)]) {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), kind, "{status} {code}");
            assert!(!error.is_temporary(), "{status} {code}");
            assert_eq!(error.http_status(), Some(status));
            assert_eq!(error.provider_code(), Some(code));
            assert_eq!(sent, std::slice::from_ref(&token), "{status} {code}");
        }

        desk.provider
            .push_response(FakeResponse::refusal(status, code));
        let error = desk.items().unwrap_err();
        assert_eq!(error.kind(), kind, "{status} {code}");
        assert!(!error.is_temporary(), "{status} {code}");
        desk.provider
            .push_response(FakeResponse::refusal(status, code));
        let error = items_async(&desk.client, &desk.id).unwrap_err();
        assert_eq!(error.kind(), kind, "{status} {code}");
        assert!(!error.is_temporary(), "{status} {code}");
        assert_eq!(desk.provider.plan_requests().len(), 2, "{status} {code}");

        assert!(desk.clock.sleeps().is_empty(), "{status} {code}");
        assert_eq!(desk.token(), token, "{status} {code}");
    }
}

#[test]
fn a_429_or_5xx_without_a_code_that_forbids_it_is_waited_out_on_every_path() {
    for status in [429, 500, 503] {
        let desk = Desk::new();
        for (result, sent) in called(&desk, &[(status, BUSY)]) {
            assert_eq!(result.unwrap(), "done", "{status}");
            assert_eq!(sent.len(), 2, "{status}");
            assert_eq!(sent[0], sent[1], "{status}");
        }
        assert_eq!(desk.clock.sleeps().len(), 2, "{status}");

        desk.provider
            .push_response(FakeResponse::refusal(status, BUSY));
        desk.provider.push_response(FakeResponse::text(&["Here."]));
        let items = desk.items().unwrap();
        assert_eq!(kinds(&items).last().unwrap(), "response.completed");
        assert_eq!(desk.clock.sleeps().len(), 3, "{status}");
    }
}

#[test]
fn a_client_told_not_to_resend_after_a_5xx_sends_once_unless_the_provider_says_not_now() {
    for status in [500, 502, 503, 504] {
        let desk = Desk::sending_once_after_server_errors();
        for (result, sent) in called(&desk, &[(status, SERVER_ERROR)]) {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Temporary, "{status}");
            assert_eq!(error.http_status(), Some(status), "{status}");
            assert_eq!(sent.len(), 1, "{status}");
        }
        desk.provider
            .push_response(FakeResponse::refusal(status, SERVER_ERROR));
        assert_eq!(desk.items().unwrap_err().kind(), ErrorKind::Temporary);
        // A gateway's body carries no code at all.
        desk.provider
            .push_response(FakeResponse::detail(status, "Bad gateway"));
        let error = items_async(&desk.client, &desk.id).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Temporary, "{status}");
        assert_eq!(desk.provider.plan_requests().len(), 2, "{status}");
        assert!(desk.clock.sleeps().is_empty(), "{status}");
    }

    // The provider's own unavailable codes say the request was not served,
    // so a 5xx with one is still waited out, as is a 429; a 401 still
    // renews the token once.
    let desk = Desk::sending_once_after_server_errors();
    let answers = [
        (429, BUSY),
        (500, BUSY),
        (502, USER_BUSY),
        (503, BUSY),
        (504, USER_BUSY),
        (401, SERVER_ERROR),
    ];
    for (status, code) in answers {
        for (result, sent) in called(&desk, &[(status, code)]) {
            assert_eq!(result.unwrap(), "done", "{status}");
            assert_eq!(sent.len(), 2, "{status}");
        }
        for stream in 0..2 {
            desk.provider
                .push_response(FakeResponse::refusal(status, code));
            desk.provider.push_response(FakeResponse::text(&["Here."]));
            let items = if stream == 0 {
                desk.items().unwrap()
            } else {
                items_async(&desk.client, &desk.id).unwrap()
            };
            assert_eq!(text(&items), "Here.", "{status}");
        }
    }
    assert_eq!(desk.provider.plan_requests().len(), 4 * answers.len());
    // Four waits for each answer but the 401: one per call path and stream.
    assert_eq!(desk.clock.sleeps().len(), 4 * (answers.len() - 1));
}

/// A failure an app read from a stream of its own has no HTTP status.
/// `call` cannot know what of that answer the app already showed, so it
/// never sends such a request again.
#[test]
fn a_refusal_without_an_http_status_ends_call_after_one_send() {
    for (code, kind) in [
        (BUSY, ErrorKind::Temporary),
        (INVALID_USER, ErrorKind::TokenRejected),
    ] {
        let event = FakeProvider::failure_event(code, None);
        let refusal = || Refusal::from_event(&event).unwrap();
        assert_eq!(refusal().status(), None);
        let by_code = || Refusal::from_code(code);
        assert_eq!(by_code().status(), None);

        let desk = Desk::new();
        let token = desk.token();
        let sent = RefCell::new(0);
        let result: Result<&str, Error> = desk.client.call(&desk.id, |_| {
            *sent.borrow_mut() += 1;
            Ok(Err(refusal()))
        });
        assert_eq!(result.unwrap_err().kind(), kind, "{code}");
        assert_eq!(sent.take(), 1, "{code}");

        let result: Result<&str, Error> = block_on(desk.client.call_async(&desk.id, |_| {
            *sent.borrow_mut() += 1;
            ready(Ok(Err(refusal())))
        }));
        assert_eq!(result.unwrap_err().kind(), kind, "{code}");
        assert_eq!(sent.take(), 1, "{code}");

        let result: Result<&str, Error> = desk.client.call(&desk.id, |_| {
            *sent.borrow_mut() += 1;
            Ok(Err(by_code()))
        });
        assert_eq!(result.unwrap_err().kind(), kind, "{code}");
        assert_eq!(sent.take(), 1, "{code}");

        assert!(desk.clock.sleeps().is_empty(), "{code}");
        assert_eq!(desk.token(), token, "{code}");
    }
}

#[test]
fn a_retry_after_that_is_not_seconds_ends_call_on_both_paths() {
    let desk = Desk::new();
    let refusal = || {
        let body = FakeProvider::refusal_body(BUSY, None);
        Refusal::from_response(503, &body)
            .unwrap()
            .with_retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT"))
    };
    let sent = RefCell::new(0);
    let result: Result<&str, Error> = desk.client.call(&desk.id, |_| {
        *sent.borrow_mut() += 1;
        Ok(Err(refusal()))
    });
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Temporary);
    assert_eq!(sent.take(), 1);
    let result: Result<&str, Error> = block_on(desk.client.call_async(&desk.id, |_| {
        *sent.borrow_mut() += 1;
        ready(Ok(Err(refusal())))
    }));
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Temporary);
    assert_eq!(sent.take(), 1);
    assert!(desk.clock.sleeps().is_empty());
}

#[test]
fn an_empty_retry_after_is_no_header_on_every_path() {
    for asked in ["", "   "] {
        let desk = Desk::new();
        let refusal = || {
            let body = FakeProvider::refusal_body(BUSY, None);
            Refusal::from_response(503, &body)
                .unwrap()
                .with_retry_after(Some(asked))
        };
        assert_eq!(
            refusal(),
            Refusal::from_response(503, &FakeProvider::refusal_body(BUSY, None)).unwrap()
        );
        let sent = RefCell::new(0);
        let result: Result<&str, Error> = desk.client.call(&desk.id, |_| {
            *sent.borrow_mut() += 1;
            Ok(Err(refusal()))
        });
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::Temporary,
            "{asked:?}"
        );
        assert_eq!(sent.take(), 3, "{asked:?}");
        assert_eq!(desk.clock.sleeps().len(), 2, "{asked:?}");
    }
}

/// The documented way of reading a stream with an HTTP client of the
/// app's own, inside `call`: text is shown as it arrives, and a failure
/// event becomes the refusal.
#[test]
fn text_an_app_showed_before_a_failure_in_its_own_stream_is_shown_once() {
    let body = [
        &b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"part\"}\n\n"[..],
        &FakeProvider::failure_event(BUSY, None),
    ]
    .concat();
    let shown = RefCell::new(0);
    let read = || -> Result<Result<(), Refusal>, Error> {
        let mut decoder = SseDecoder::new();
        for event in decoder.feed(&body)? {
            if event.text_delta().is_some() {
                *shown.borrow_mut() += 1;
            }
            if let StreamEvent::Failed(refusal) = event.into_event() {
                return Ok(Err(refusal.with_retry_after(Some("0"))));
            }
        }
        decoder.finish()?;
        Ok(Ok(()))
    };
    let desk = Desk::new();
    let error = desk.client.call(&desk.id, |_| read()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert_eq!(shown.take(), 1);
    let error = block_on(desk.client.call_async(&desk.id, |_| ready(read()))).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert_eq!(shown.take(), 1);
    assert!(desk.clock.sleeps().is_empty());
}

#[test]
fn a_refusal_body_over_64_kib_ends_call_whatever_its_status() {
    for status in [401, 429, 503] {
        // A body that says "not now", or nothing a retry could not lift,
        // padded with the white space JSON allows.
        let padded = |len: usize| {
            let mut body = FakeProvider::refusal_body(BUSY, Some("input"));
            body.resize(len, b' ');
            body
        };
        let desk = Desk::new();
        let token = desk.token();

        // At the limit the body is read and the status rule holds.
        let fits = padded(64 * 1024);
        let sent = RefCell::new(0);
        let answer = || -> Result<Result<&str, Refusal>, Error> {
            *sent.borrow_mut() += 1;
            Ok(match *sent.borrow() {
                1 => Err(Refusal::from_response(status, &fits)
                    .unwrap()
                    .with_retry_after(Some("0"))),
                _ => Ok("done"),
            })
        };
        assert_eq!(desk.client.call(&desk.id, |_| answer()).unwrap(), "done");
        assert_eq!(sent.take(), 2, "{status}");
        let awaited = block_on(desk.client.call_async(&desk.id, |_| ready(answer())));
        assert_eq!(awaited.unwrap(), "done");
        assert_eq!(sent.take(), 2, "{status}");

        // One byte more: what the body says is unknown, and the status
        // alone is no reason to send again.
        let over = padded(64 * 1024 + 1);
        let refusal = || {
            Refusal::from_response(status, &over)
                .unwrap()
                .with_request_id(Some("req_zz_1"))
                .with_retry_after(Some("0"))
        };
        assert_eq!(refusal().provider_code(), None);
        assert_eq!(refusal().param(), None);
        let desk = Desk::new();
        let token_before = desk.token();
        let answer = || -> Result<Result<&str, Refusal>, Error> {
            *sent.borrow_mut() += 1;
            Ok(Err(refusal()))
        };
        let blocking = desk.client.call(&desk.id, |_| answer()).unwrap_err();
        assert_eq!(sent.take(), 1, "{status}");
        let awaited = block_on(desk.client.call_async(&desk.id, |_| ready(answer())));
        assert_eq!(sent.take(), 1, "{status}");
        for error in [blocking, awaited.unwrap_err()] {
            assert_eq!(error.kind(), ErrorKind::InvalidResponse, "{status}");
            assert_eq!(error.http_status(), Some(status));
            assert_eq!(error.request_id(), Some("req_zz_1"));
            assert_eq!(error.provider_code(), None);
        }
        assert!(desk.clock.sleeps().is_empty(), "{status}");
        assert_eq!(desk.token(), token_before, "{status}");
        drop(token);
    }
}
