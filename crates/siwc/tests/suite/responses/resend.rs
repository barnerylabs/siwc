//! What allows a second POST and what never does: the status of a
//! refusal, a refusal body that did not arrive whole, and the wait the API
//! asks for.

use std::time::Duration;

use siwc::ErrorKind;
use siwc::protocol::StreamingResponse;
use siwc::testing::FakeResponse;

use super::answers::{Wired, completed, delta, opening};
use super::{BUSY, Desk, INVALID_USER, LIMIT, kinds, request};

#[test]
fn a_refusal_that_breaks_off_is_never_sent_again() {
    // The part that was lost may be what forbids another attempt: a `429`
    // can be a usage limit, which no waiting lifts.
    for (status, code) in [(429, LIMIT), (429, BUSY), (503, BUSY), (401, INVALID_USER)] {
        for ending in [FakeResponse::interrupted, FakeResponse::times_out] {
            let desk = Desk::new();
            let token = desk.token();
            desk.provider
                .push_response(ending(FakeResponse::refusal(status, code).retry_after(45)));
            desk.provider
                .push_response(FakeResponse::text(&["never shown"]));
            let error = desk.items().unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Temporary, "{status} {code}");
            assert_eq!(error.http_status(), Some(status));
            assert!(error.request_id().is_some());
            assert_eq!(error.retry_after(), Some(Duration::from_secs(45)));
            assert_eq!(desk.provider.plan_requests().len(), 1, "{status} {code}");
            assert!(desk.clock.sleeps().is_empty());
            assert_eq!(desk.token(), token, "no renewal either");
        }
    }
}

/// A `429` whose body names the usage limit, padded to `len` bytes.
fn limit_refusal(len: usize) -> Vec<u8> {
    let mut body =
        format!(r#"{{"error":{{"code":"{LIMIT}","message":"synthetic test refusal"}}}}"#)
            .into_bytes();
    body.resize(len, b' ');
    body
}

#[test]
fn a_refusal_body_is_read_to_64_kib_and_a_larger_one_ends_the_request() {
    // At the limit to the byte, the body still says what the refusal is.
    let (wired, client, id, clock) = Wired::desk();
    let body = wired.body(limit_refusal(65_536));
    wired.answer(move |_| StreamingResponse::new(429, body));
    let error = client.stream_response(&id, &request()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UsageLimit);
    assert_eq!(error.provider_code(), Some(LIMIT));
    assert_eq!(wired.served(), 65_536);
    assert_eq!(wired.sent(), 1);
    assert!(clock.sleeps().is_empty());

    // One byte more, and one megabyte more: one byte past the limit is
    // read and the request ends there, whatever the status would allow.
    // What was not read may be what forbids another attempt, so the
    // answer that waits for a second POST is never asked for.
    for (status, len) in [
        (429, 65_537),
        (429, 1024 * 1024),
        (503, 65_537),
        (401, 65_537),
    ] {
        let (wired, client, id, clock) = Wired::desk();
        let body = wired.body(limit_refusal(len));
        wired.answer(move |_| {
            StreamingResponse::new(status, body)
                .with_request_id(Some("req_large_1"))
                .with_retry_after(Some("45"))
        });
        let answer = wired.body([opening(), delta("Here."), completed()].concat());
        wired.answer(move |_| StreamingResponse::new(200, answer));
        let error = client.stream_response(&id, &request()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse, "{status} {len}");
        assert_eq!(error.http_status(), Some(status));
        assert_eq!(error.request_id(), Some("req_large_1"));
        assert_eq!(error.retry_after(), Some(Duration::from_secs(45)));
        assert_eq!(error.provider_code(), None);
        assert_eq!(wired.served(), 65_537, "{status} {len}");
        assert_eq!(wired.sent(), 1, "{status} {len}");
        assert!(clock.sleeps().is_empty());
    }
}

#[test]
fn the_status_decides_whether_a_refusal_is_sent_again_whatever_its_code() {
    for (status, code, kind) in [
        (403, BUSY, ErrorKind::NotPermitted),
        (307, BUSY, ErrorKind::Rejected),
        (400, BUSY, ErrorKind::Rejected),
        (403, INVALID_USER, ErrorKind::TokenRejected),
        (400, INVALID_USER, ErrorKind::TokenRejected),
        (500, INVALID_USER, ErrorKind::TokenRejected),
    ] {
        let desk = Desk::new();
        let token = desk.token();
        desk.provider
            .push_response(FakeResponse::refusal(status, code));
        desk.provider
            .push_response(FakeResponse::text(&["never shown"]));
        let error = desk.items().unwrap_err();
        assert_eq!(error.kind(), kind, "{status} {code}");
        assert!(!error.is_temporary(), "{status} {code}");
        assert_eq!(error.provider_code(), Some(code));
        assert_eq!(error.http_status(), Some(status));
        assert_eq!(desk.provider.plan_requests().len(), 1, "{status} {code}");
        assert!(desk.clock.sleeps().is_empty(), "{status} {code}");
        assert_eq!(desk.token(), token, "{status} {code}");
    }
}

#[test]
fn retry_after_does_not_make_a_failure_inside_the_stream_retryable() {
    for seconds in [0, 7, 31] {
        let desk = Desk::new();
        desk.provider.push_response(
            FakeResponse::stream()
                .created()
                .failed(BUSY)
                .retry_after(seconds),
        );
        desk.provider
            .push_response(FakeResponse::text(&["never shown"]));
        let items = desk.items().unwrap();
        assert_eq!(desk.provider.plan_requests().len(), 1, "{seconds}");
        assert_eq!(kinds(&items), ["Temporary"], "{seconds}");
        assert!(desk.clock.sleeps().is_empty(), "{seconds}");
    }
}

#[test]
fn a_wait_too_long_to_write_down_is_too_long_to_wait() {
    for asked in [
        // More seconds than fit into 64 bits, and more digits than a
        // header value is kept for.
        "18446744073709551616".to_owned(),
        "9".repeat(40),
        "9".repeat(200),
    ] {
        let (wired, client, id, clock) = Wired::desk();
        let refusal = wired.body(siwc::testing::FakeProvider::refusal_body(BUSY, None));
        let header = asked.clone();
        wired.answer(move |_| {
            StreamingResponse::new(503, refusal).with_retry_after(Some(header.as_str()))
        });
        let error = client.stream_response(&id, &request()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Temporary, "{asked}");
        assert_eq!(wired.sent(), 1, "{asked}");
        assert!(clock.sleeps().is_empty(), "{asked}");
    }
}

#[test]
fn a_wait_asked_for_as_a_date_is_not_guessed() {
    for asked in [
        "Wed, 21 Oct 2026 07:28:00 GMT".to_owned(),
        "5s".to_owned(),
        "1.5".to_owned(),
        // Too long to keep, and still not a number of seconds.
        "x".repeat(65),
    ] {
        let (wired, client, id, clock) = Wired::desk();
        let refusal = wired.body(siwc::testing::FakeProvider::refusal_body(BUSY, None));
        let header = asked.clone();
        wired.answer(move |_| {
            StreamingResponse::new(503, refusal).with_retry_after(Some(header.as_str()))
        });
        let error = client.stream_response(&id, &request()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Temporary, "{asked}");
        assert_eq!(error.retry_after(), None, "{asked}");
        assert_eq!(wired.sent(), 1, "{asked}");
        assert!(clock.sleeps().is_empty(), "{asked}");
    }
}

#[test]
fn leading_zeros_change_nothing_about_the_wait_the_api_asks_for() {
    let zeros = "0".repeat(65);
    for (asked, wait) in [
        (format!("{zeros}1"), Some(1)),
        (format!("{zeros}30"), Some(30)),
        (zeros.clone(), Some(0)),
        ("0".to_owned(), Some(0)),
        ("1".to_owned(), Some(1)),
        // Too long to wait, with or without zeros in front.
        (format!("{zeros}31"), None),
        (format!("{zeros}{}", "9".repeat(70)), None),
    ] {
        // Streamed, and as a transport without streaming hands it over.
        for buffered in [false, true] {
            let (wired, client, id, clock) = Wired::desk();
            let refusal = siwc::testing::FakeProvider::refusal_body(BUSY, None);
            let header = asked.clone();
            if buffered {
                wired.answer(move |_| {
                    siwc::protocol::HttpResponse::new(503, refusal)
                        .with_retry_after(Some(header.as_str()))
                        .into()
                });
            } else {
                let body = wired.body(refusal);
                wired.answer(move |_| {
                    StreamingResponse::new(503, body).with_retry_after(Some(header.as_str()))
                });
            }
            let answer = wired.body([opening(), delta("Here."), completed()].concat());
            wired.answer(move |_| StreamingResponse::new(200, answer));
            let opened = client.stream_response(&id, &request());
            match wait {
                Some(seconds) => {
                    assert_eq!(opened.unwrap().into_text().unwrap(), "Here.", "{asked}");
                    assert_eq!(clock.sleeps(), [Duration::from_secs(seconds)], "{asked}");
                    assert_eq!(wired.sent(), 2);
                }
                None => {
                    assert_eq!(opened.unwrap_err().kind(), ErrorKind::Temporary, "{asked}");
                    assert!(clock.sleeps().is_empty(), "{asked}");
                    assert_eq!(wired.sent(), 1);
                }
            }
        }
    }
}
