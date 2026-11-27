//! What an error and `Debug` print of the values a provider sends: only
//! what the crate knows. Any other code, parameter or request ID is read
//! through its accessor, and not at all when a token is inside it.

use std::cell::RefCell;
use std::future::ready;
use std::sync::{Arc, Mutex};

use siwc::plan::Refusal;
use siwc::protocol::{HttpResponse, StreamingResponse};
use siwc::testing::{FakeProvider, FakeResponse};
use siwc::{Error, ErrorKind};

use crate::support::executor::block_on;

use super::answers::{Wired, completed, delta, opening};
use super::{Desk, INVALID_USER, LIMIT, items_async, last_error, request};

/// Whether `secret` can be read from `error` in any way.
fn reveals(error: &Error, secret: &str) -> bool {
    let has = |value: Option<&str>| value.is_some_and(|value| value.contains(secret));
    format!("{error:?} {error}").contains(secret)
        || has(error.provider_code())
        || has(error.request_id())
        || has(error.param())
}

#[test]
fn a_code_the_crate_does_not_know_is_printed_nowhere_and_read_on_request() {
    // An identifier is all a code has to look like: this could be a word
    // of the prompt.
    let free = "zz_prompt_word_17";
    let printed = |error: &Error| format!("{error} {error:?}");

    // As the code and the parameter of a refusal.
    let (wired, client, id, _clock) = Wired::desk();
    let body = wired.body(FakeProvider::refusal_body(free, Some("zz_input.name")));
    wired.answer(move |_| {
        StreamingResponse::new(403, body).with_request_id(Some("req_zz_synthetic_1"))
    });
    let error = client.stream_response(&id, &request()).unwrap_err();
    assert_eq!(error.provider_code(), Some(free));
    assert_eq!(error.param(), Some("zz_input.name"));
    assert_eq!(error.request_id(), Some("req_zz_synthetic_1"));
    assert_eq!(error.http_status(), Some(403));
    assert!(!printed(&error).contains("zz_"), "{}", printed(&error));
    assert!(printed(&error).contains("403"), "{}", printed(&error));

    // As the code of a failure inside the stream, for both clients.
    let desk = Desk::new();
    let script = || FakeResponse::stream().created().delta("Half").failed(free);
    desk.provider.push_response(script());
    desk.provider.push_response(script());
    let blocking = desk.items().unwrap();
    let awaited = items_async(&desk.client, &desk.id).unwrap();
    for items in [blocking, awaited] {
        let error = last_error(&items);
        assert_eq!(error.provider_code(), Some(free));
        assert!(!printed(error).contains("zz_"), "{}", printed(error));
        assert!(!format!("{items:?}").contains("zz_"));
    }

    // A code the provider documents is named, as before.
    desk.provider
        .push_response(FakeResponse::refusal(429, LIMIT));
    let error = desk.items().unwrap_err();
    assert!(error.to_string().contains(LIMIT));
    assert!(format!("{error:?}").contains(LIMIT));
}

#[test]
fn debug_of_a_stream_says_whether_there_is_a_request_id_and_not_which() {
    let (wired, client, id, _clock) = Wired::desk();
    let answer = || [opening(), delta("Hi"), completed()].concat();
    for _ in 0..2 {
        let body = wired.body(answer());
        wired.answer(move |_| {
            StreamingResponse::new(200, body).with_request_id(Some("req_zz_synthetic_2"))
        });
    }
    let stream = client.stream_response(&id, &request()).unwrap();
    assert_eq!(stream.request_id(), Some("req_zz_synthetic_2"));
    let debug = format!("{stream:?}");
    assert!(!debug.contains("zz_"), "{debug}");
    assert!(debug.contains("has_request_id: true"), "{debug}");

    let stream = block_on(client.stream_response_async(&id, &request())).unwrap();
    assert_eq!(stream.request_id(), Some("req_zz_synthetic_2"));
    let debug = format!("{stream:?}");
    assert!(!debug.contains("zz_"), "{debug}");
    assert!(debug.contains("has_request_id: true"), "{debug}");
}

#[test]
fn a_token_inside_a_longer_value_is_dropped_like_the_token_itself() {
    let (wired, client, id, _clock) = Wired::desk();
    let token = client.access_token(&id).unwrap().expose().to_owned();

    // In the code, the parameter and the request ID of a refusal.
    wired.answer({
        let served = wired.body(Vec::new());
        move |token| {
            let mut body = served;
            let code = format!("code_{token}_x");
            let param = format!("input.{token}");
            body.fill(FakeProvider::refusal_body(&code, Some(&param)));
            let request_id = format!("req-{token}-1");
            StreamingResponse::new(403, body).with_request_id(Some(&request_id))
        }
    });
    let error = client.stream_response(&id, &request()).unwrap_err();
    assert_eq!(error.http_status(), Some(403));
    assert_eq!(error.provider_code(), None);
    assert_eq!(error.param(), None);
    assert_eq!(error.request_id(), None);
    assert!(!reveals(&error, &token));

    // In the request ID of an accepted answer and in the code of a
    // failure it reports after output.
    let queue = |wired: &Wired| {
        let served = wired.body(Vec::new());
        wired.answer(move |token| {
            let mut body = served;
            let failed = FakeProvider::failure_event(&format!("code_{token}"), None);
            body.fill([opening(), delta("Half"), failed].concat());
            let request_id = format!("req-{token}");
            StreamingResponse::new(200, body).with_request_id(Some(&request_id))
        });
    };
    queue(&wired);
    let mut stream = client.stream_response(&id, &request()).unwrap();
    assert_eq!(stream.request_id(), None);
    let error = stream.by_ref().last().unwrap().unwrap_err();
    assert!(!reveals(&error, &token));
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
        assert!(!reveals(&last.unwrap().unwrap_err(), &token));
    });
}

#[test]
fn the_token_from_before_a_renewal_is_recognised_after_it() {
    let (wired, client, id, _clock) = Wired::desk();
    let first = client.access_token(&id).unwrap().expose().to_owned();

    // The API refuses the first token, and answers the request with the
    // renewed one by sending the first one back.
    let seen = Arc::new(Mutex::new(String::new()));
    wired.answer({
        let seen = Arc::clone(&seen);
        let body = wired.body(FakeProvider::refusal_body(INVALID_USER, None));
        move |token| {
            token.clone_into(&mut seen.lock().unwrap());
            StreamingResponse::new(401, body)
        }
    });
    wired.answer({
        let seen = Arc::clone(&seen);
        let served = wired.body(Vec::new());
        move |_| {
            let old = seen.lock().unwrap().clone();
            let mut body = served;
            body.fill(FakeProvider::refusal_body(&old, Some(&format!("p.{old}"))));
            StreamingResponse::new(403, body).with_request_id(Some(&old))
        }
    });
    let error = client.stream_response(&id, &request()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotPermitted);
    assert_eq!(wired.sent(), 2);
    assert_eq!(*seen.lock().unwrap(), first);
    assert_eq!(error.provider_code(), None);
    assert_eq!(error.param(), None);
    assert_eq!(error.request_id(), None);
    assert!(!reveals(&error, &first));
}

#[test]
fn debug_of_a_transport_response_says_whether_there_is_a_request_id_and_not_which() {
    // A request ID only has to look like an identifier, and so does a
    // short token: an adapter that logs the response must not print it.
    let id = "req-zz_synthetic_bearer_17-1";
    let streaming = StreamingResponse::new(503, std::io::empty())
        .with_request_id(Some(id))
        .with_retry_after(Some("zz_synthetic_wait"));
    let buffered = HttpResponse::new(503, b"zz_synthetic_body".to_vec())
        .with_request_id(Some(id))
        .with_retry_after(Some("zz_synthetic_wait"));
    assert_eq!(streaming.request_id(), Some(id));
    assert_eq!(buffered.request_id(), Some(id));
    for debug in [format!("{streaming:?}"), format!("{buffered:?}")] {
        assert!(!debug.contains("zz_"), "{debug}");
        assert!(debug.contains("503"), "{debug}");
        assert!(debug.contains("has_request_id: true"), "{debug}");
    }
    let bare = format!("{:?}", StreamingResponse::new(200, std::io::empty()));
    assert!(bare.contains("has_request_id: false"), "{bare}");
    let bare = format!("{:?}", HttpResponse::new(200, Vec::new()));
    assert!(bare.contains("has_request_id: false"), "{bare}");
}

/// A refusal with `inside` in its code, its parameter and its request ID.
fn echoing(status: u16, inside: &str) -> Refusal {
    let code = format!("code_{inside}_x");
    let param = format!("input.{inside}");
    Refusal::from_response(status, &FakeProvider::refusal_body(&code, Some(&param)))
        .unwrap()
        .with_request_id(Some(&format!("req-{inside}-1")))
}

#[test]
fn call_drops_a_value_with_a_token_in_it_as_the_stream_does() {
    // What an app's HTTP client got back, turned into a refusal the way
    // the documentation says. `answer` gets every token used so far.
    type Answer = fn(&[String]) -> Result<&'static str, Refusal>;
    let cases: [(Answer, usize, ErrorKind); 3] = [
        // The token of the only attempt.
        (
            |sent| Err(echoing(403, &sent[0])),
            1,
            ErrorKind::NotPermitted,
        ),
        // The token from before a renewal, sent back after it.
        (
            |sent| match sent {
                [_] => Err(Refusal::from_response(401, b"{}").unwrap()),
                [first, ..] => Err(echoing(403, first)),
                [] => Ok("never"),
            },
            2,
            ErrorKind::NotPermitted,
        ),
        // A refusal that ends the call because its wait is too long.
        (
            |sent| Err(echoing(503, &sent[0]).with_retry_after(Some("31"))),
            1,
            ErrorKind::Temporary,
        ),
    ];
    for (number, (answer, sends, kind)) in cases.into_iter().enumerate() {
        for awaited in [false, true] {
            let desk = Desk::new();
            let sent = RefCell::new(Vec::new());
            let send = |token: &str| -> Result<Result<&str, Refusal>, Error> {
                sent.borrow_mut().push(token.to_owned());
                Ok(answer(&sent.borrow()))
            };
            let result = if awaited {
                block_on(
                    desk.client
                        .call_async(&desk.id, |token| ready(send(token.expose()))),
                )
            } else {
                desk.client.call(&desk.id, |token| send(token.expose()))
            };
            let error = result.unwrap_err();
            let sent = sent.take();
            assert_eq!(sent.len(), sends, "case {number}");
            assert_eq!(error.kind(), kind, "case {number}");
            assert!(error.http_status().is_some(), "case {number}");
            assert_eq!(error.provider_code(), None, "case {number}");
            assert_eq!(error.param(), None, "case {number}");
            assert_eq!(error.request_id(), None, "case {number}");
            for token in &sent {
                assert!(!reveals(&error, token), "case {number}");
            }
        }
    }

    // A value without a token in it stays readable.
    let desk = Desk::new();
    let result: Result<(), Error> = desk
        .client
        .call(&desk.id, |_| Ok(Err(echoing(403, "zz_other_word"))));
    let error = result.unwrap_err();
    assert_eq!(error.provider_code(), Some("code_zz_other_word_x"));
    assert_eq!(error.param(), Some("input.zz_other_word"));
    assert_eq!(error.request_id(), Some("req-zz_other_word-1"));
}

#[test]
fn token_endpoint_errors_hide_bearers_from_earlier_attempts() {
    for asynchronous in [false, true] {
        for status in [401, 503] {
            let desk = Desk::new();
            let first = desk.token();
            let mut calls = 0;
            let mut refuse = |token: &siwc::AccessToken| -> Result<Result<(), Refusal>, Error> {
                calls += 1;
                // For the wait path, renew once first. A later token lookup
                // can fail with an echo of a token that has already rotated.
                if status == 503 && calls == 1 {
                    return Ok(Err(Refusal::from_response(401, b"{}").unwrap()));
                }
                if status == 503 {
                    assert_ne!(first, token.expose());
                    desk.clock.advance(std::time::Duration::from_secs(3600));
                }
                desk.provider.fail_next_request(503, Some(&first));
                Ok(Err(Refusal::from_response(status, b"{}")
                    .unwrap()
                    .with_retry_after(Some("0"))))
            };
            let error = if asynchronous {
                block_on(
                    desk.client
                        .call_async(&desk.id, |token| ready(refuse(&token))),
                )
            } else {
                desk.client.call(&desk.id, refuse)
            }
            .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Temporary);
            assert_eq!(error.http_status(), Some(503));
            assert!(error.request_id().is_some());
            assert!(!reveals(&error, &first));
        }
    }
}
