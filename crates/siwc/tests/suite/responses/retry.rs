//! What is sent again and what never is: token renewal, refusals, waits,
//! and the line that the first output draws.

use std::time::Duration;

use siwc::plan::Refusal;
use siwc::testing::{FakeProvider, FakeResponse, FakeUser};
use siwc::{Error, ErrorKind};

use super::{BUSY, Desk, INVALID_USER, LIMIT, items_async, kinds, last_error, request, text};

#[test]
fn a_refused_token_is_renewed_once_and_the_request_sent_again() {
    for refused in [
        FakeResponse::refusal(401, INVALID_USER),
        // Admission answers without an error code.
        FakeResponse::detail(401, "Could not validate credentials"),
    ] {
        let desk = Desk::new();
        let first = desk.token();
        desk.provider.push_response(refused);
        desk.provider.push_response(FakeResponse::text(&["Hello"]));

        let stream = desk.client.stream_response(&desk.id, &request()).unwrap();
        assert_eq!(stream.into_text().unwrap(), "Hello");
        assert_eq!(desk.provider.plan_requests().len(), 2);
        assert_ne!(desk.token(), first, "the token was renewed");
        assert!(
            desk.clock.sleeps().is_empty(),
            "a renewal waits for nothing"
        );
    }
}

#[test]
fn a_token_refused_again_after_its_renewal_is_the_error() {
    let desk = Desk::new();
    desk.provider
        .push_response(FakeResponse::detail(401, "Could not validate credentials"));
    desk.provider
        .push_response(FakeResponse::refusal(401, INVALID_USER));
    let error = desk.items().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TokenRejected);
    assert_eq!(error.http_status(), Some(401));
    assert_eq!(error.provider_code(), Some(INVALID_USER));
    assert!(error.request_id().unwrap().starts_with("req_fake_"));
    assert_eq!(desk.provider.plan_requests().len(), 2);
}

#[test]
fn a_refusal_means_what_it_means_for_call_and_is_not_sent_again() {
    for (status, code, kind) in [
        (429, LIMIT, ErrorKind::UsageLimit),
        (
            403,
            "subscription_sharing_user_not_eligible",
            ErrorKind::NotPermitted,
        ),
        (
            403,
            "chatpass_v2_scope_not_authorized",
            ErrorKind::PlanUseNotGranted,
        ),
        (
            400,
            "subscription_sharing_unsupported_capability",
            ErrorKind::Rejected,
        ),
        (
            403,
            "subscription_sharing_route_not_supported",
            ErrorKind::Rejected,
        ),
        (404, "something_new", ErrorKind::Rejected),
    ] {
        let desk = Desk::new();
        desk.provider
            .push_response(FakeResponse::refusal(status, code));
        let error = desk.items().unwrap_err();

        // The same refusal, classified the way an app does it for `call`.
        let body = FakeProvider::refusal_body(code, None);
        let by_call = Error::from(Refusal::from_response(status, &body).unwrap());
        assert_eq!(error.kind(), by_call.kind(), "{code}");
        assert_eq!(error.kind(), kind, "{code}");
        assert_eq!(error.provider_code(), Some(code));
        assert_eq!(error.http_status(), Some(status));
        assert!(error.request_id().is_some());
        assert_eq!(desk.provider.plan_requests().len(), 1, "{code}");
        assert!(desk.clock.sleeps().is_empty(), "{code}");
    }

    // Admission's `detail` answers carry no code: the status decides.
    for (status, kind) in [(403, ErrorKind::NotPermitted), (400, ErrorKind::Rejected)] {
        let desk = Desk::new();
        desk.provider
            .push_response(FakeResponse::detail(status, "synthetic diagnostic text"));
        let error = desk.items().unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(error.provider_code(), None);
        assert!(!format!("{error:?} {error}").contains("synthetic diagnostic"));
        assert_eq!(desk.provider.plan_requests().len(), 1);
    }
}

#[test]
fn a_busy_api_is_asked_again_after_growing_waits_three_times_in_all() {
    let desk = Desk::new();
    desk.provider
        .push_response(FakeResponse::refusal(503, BUSY));
    desk.provider
        .push_response(FakeResponse::detail(503, "Service unavailable"));
    desk.provider.push_response(FakeResponse::text(&["Here."]));
    let stream = desk.client.stream_response(&desk.id, &request()).unwrap();
    assert_eq!(stream.into_text().unwrap(), "Here.");
    assert_eq!(desk.provider.plan_requests().len(), 3);
    let waits = desk.clock.sleeps();
    assert_eq!(waits.len(), 2);
    let half = Duration::from_millis(500);
    assert!((half..=half * 2).contains(&waits[0]), "{waits:?}");
    assert!((half * 2..=half * 4).contains(&waits[1]), "{waits:?}");

    // A third refusal in a row is the error; a fourth request never goes out.
    let desk = Desk::new();
    for _ in 0..4 {
        desk.provider
            .push_response(FakeResponse::refusal(429, "rate_limit_exceeded"));
    }
    let error = desk.items().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert_eq!(error.http_status(), Some(429));
    assert_eq!(desk.provider.plan_requests().len(), 3);
    assert_eq!(desk.clock.sleeps().len(), 2);
}

#[test]
fn the_wait_the_api_asks_for_is_taken_up_to_thirty_seconds() {
    let desk = Desk::new();
    desk.provider
        .push_response(FakeResponse::refusal(503, BUSY).retry_after(7));
    desk.provider
        .push_response(FakeResponse::detail(429, "slow down").retry_after(30));
    desk.provider.push_response(FakeResponse::text(&["Here."]));
    let stream = desk.client.stream_response(&desk.id, &request()).unwrap();
    assert_eq!(stream.into_text().unwrap(), "Here.");
    assert_eq!(
        desk.clock.sleeps(),
        [Duration::from_secs(7), Duration::from_secs(30)]
    );

    // A longer wait is the app's decision: the refusal comes back at once.
    let desk = Desk::new();
    desk.provider
        .push_response(FakeResponse::refusal(503, BUSY).retry_after(31));
    let error = desk.items().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert_eq!(error.retry_after(), Some(Duration::from_secs(31)));
    assert!(desk.clock.sleeps().is_empty());
    assert_eq!(desk.provider.plan_requests().len(), 1);
}

#[test]
fn an_account_without_plan_use_sends_nothing() {
    let user = FakeUser::new("owner@example.invalid").without_plan_use();
    let desk = Desk::with_user(user);
    let error = desk.items().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PlanUseNotGranted);
    assert!(desk.provider.plan_requests().is_empty());
}

#[test]
fn a_statusless_failure_before_output_ends_the_accepted_request() {
    for (code, kind) in [
        (BUSY, ErrorKind::Temporary),
        (INVALID_USER, ErrorKind::TokenRejected),
        (LIMIT, ErrorKind::UsageLimit),
    ] {
        let error = format!(r#"{{"type":"error","code":"{code}"}}"#);
        for failure in [
            FakeResponse::stream().event(&error),
            FakeResponse::stream().created().failed(code),
        ] {
            for asynchronous in [false, true] {
                let desk = Desk::new();
                let token = desk.token();
                desk.provider.push_response(failure.clone());
                desk.provider
                    .push_response(FakeResponse::text(&["never shown"]));
                let items = if asynchronous {
                    items_async(&desk.client, &desk.id)
                } else {
                    desk.items()
                }
                .unwrap();

                assert_eq!(desk.provider.plan_requests().len(), 1, "{code}");
                assert_eq!(items.len(), 1, "no opening events leave the stream");
                let error = last_error(&items);
                assert_eq!(error.kind(), kind);
                assert_eq!(error.http_status(), None);
                assert_eq!(error.provider_code(), Some(code));
                assert!(error.request_id().is_some());
                assert!(desk.clock.sleeps().is_empty());
                assert_eq!(desk.token(), token);
            }
        }
    }
}

#[test]
fn after_output_nothing_is_sent_again() {
    for (code, kind) in [
        (BUSY, ErrorKind::Temporary),
        (LIMIT, ErrorKind::UsageLimit),
        (INVALID_USER, ErrorKind::TokenRejected),
    ] {
        let desk = Desk::new();
        let token = desk.token();
        desk.provider.push_response(
            FakeResponse::stream()
                .created()
                .delta("Once upon")
                .failed(code),
        );
        desk.provider
            .push_response(FakeResponse::text(&["never shown"]));

        let items = desk.items().unwrap();
        assert_eq!(
            kinds(&items),
            [
                "response.created",
                "response.in_progress",
                "response.output_text.delta",
                &format!("{kind:?}"),
            ],
            "{code}"
        );
        assert_eq!(text(&items), "Once upon");
        let error = last_error(&items);
        assert_eq!(error.provider_code(), Some(code));
        assert_eq!(error.http_status(), None);
        assert!(error.request_id().is_some());
        // One request, no wait, no renewal: the text was shown already.
        assert_eq!(desk.provider.plan_requests().len(), 1, "{code}");
        assert!(desk.clock.sleeps().is_empty(), "{code}");
        assert_eq!(desk.token(), token, "{code}");
    }
}

#[test]
fn an_event_other_than_an_opening_one_counts_as_output() {
    // A tool call is output an app acts on, text or not.
    let call =
        r#"{"type":"response.output_item.added","item":{"type":"function_call","name":"lookup"}}"#;
    let desk = Desk::new();
    desk.provider
        .push_response(FakeResponse::stream().created().event(call).failed(BUSY));
    desk.provider
        .push_response(FakeResponse::text(&["never shown"]));
    let items = desk.items().unwrap();
    assert_eq!(
        kinds(&items),
        [
            "response.created",
            "response.in_progress",
            "response.output_item.added",
            "Temporary",
        ]
    );
    assert_eq!(items[2].as_ref().unwrap().json(), call);
    assert_eq!(desk.provider.plan_requests().len(), 1);
}

#[test]
fn a_stream_that_breaks_before_completed_is_temporary_and_never_retried() {
    let endings: [fn(FakeResponse) -> FakeResponse; 3] = [
        // The body ends cleanly, but `response.completed` never came.
        |script| script,
        FakeResponse::interrupted,
        FakeResponse::times_out,
    ];
    for (number, ending) in endings.into_iter().enumerate() {
        for script in [
            // Before any output: the API may still have run the request.
            FakeResponse::stream().created(),
            FakeResponse::stream().created().delta("Half an ans"),
            // A frame without its blank line is not an event.
            FakeResponse::stream()
                .created()
                .delta("Half")
                .raw(b"data: {\"type\":\"response.completed\"}"),
        ] {
            let desk = Desk::new();
            desk.provider.push_response(ending(script));
            desk.provider
                .push_response(FakeResponse::text(&["never shown"]));
            let items = desk.items().unwrap();
            let error = last_error(&items);
            assert_eq!(error.kind(), ErrorKind::Temporary, "ending {number}");
            assert!(error.is_temporary());
            assert!(error.request_id().is_some());
            assert!(!text(&items).contains("never shown"));
            assert_eq!(desk.provider.plan_requests().len(), 1, "ending {number}");
            assert!(desk.clock.sleeps().is_empty());
        }
    }
}

#[test]
fn a_transport_failure_before_the_answer_is_returned_without_another_attempt() {
    let desk = Desk::new();
    desk.provider.fail_next_request(0, None);
    let error = desk.items().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert!(desk.provider.plan_requests().is_empty());
    assert!(desk.clock.sleeps().is_empty());
    // The next request is a new decision of the app, and works.
    assert!(desk.items().unwrap().iter().all(Result::is_ok));
}

#[test]
fn a_redirect_is_an_error_and_is_never_followed() {
    for status in [301, 302, 307, 308] {
        let desk = Desk::new();
        desk.provider
            .push_response(FakeResponse::detail(status, "moved"));
        desk.provider
            .push_response(FakeResponse::text(&["never shown"]));
        let error = desk.items().unwrap_err();
        assert!(!error.is_temporary(), "{status}");
        assert_eq!(error.http_status(), Some(status));
        assert_eq!(desk.provider.plan_requests().len(), 1, "{status}");
        assert!(desk.clock.sleeps().is_empty());
    }
}
