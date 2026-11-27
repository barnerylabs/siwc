//! The fake provider's `/v1/responses` route itself: what it counts, how
//! large a request it takes and how it frames an event.

use std::time::Duration;

use siwc::UnixTime;
use siwc::plan::ResponseRequest;
use siwc::testing::{FakeClock, FakeProvider, FakeResponse, FakeUser};

use super::{Desk, kinds, request, sign_in, text};

#[test]
fn the_fake_counts_a_plan_request_it_answers_with_an_injected_status() {
    let desk = Desk::new();
    desk.provider.fail_next_request(403, None);
    let error = desk.items().unwrap_err();
    assert_eq!(error.http_status(), Some(403));
    // The request arrived, and is in the list, once.
    assert_eq!(desk.provider.plan_requests().len(), 1);

    // An injected status that is sent again shows up as two requests.
    desk.provider.fail_next_request(503, None);
    desk.provider.push_response(FakeResponse::text(&["Here."]));
    assert_eq!(text(&desk.items().unwrap()), "Here.");
    assert_eq!(desk.provider.plan_requests().len(), 3);
}

#[test]
fn debug_of_a_scripted_answer_shows_its_status_end_and_length_only() {
    let script = FakeResponse::text(&["secret-scripted-text"]).interrupted();
    let debug = format!("{script:?}");
    assert!(!debug.contains("secret"), "{debug}");
    // Not as the numbers of its bytes either: `s`, `e`, `c`.
    assert!(!debug.contains("115, 101, 99"), "{debug}");
    assert!(debug.contains("status: 200"), "{debug}");
    assert!(debug.contains("Broken"), "{debug}");
    assert!(debug.contains("body_len"), "{debug}");
}

#[test]
fn the_fake_counts_a_plan_request_it_refuses_for_its_token() {
    // The provider's clock runs ahead of the app's: the app sends a token
    // it takes for valid, and the provider has let it expire.
    let apps = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let providers = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&providers);
    let client = Desk::client_over(provider.transport(), &apps);
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    providers.advance(Duration::from_secs(48 * 60 * 60));

    let stream = client.stream_response(&id, &request()).unwrap();
    stream.into_text().unwrap();
    // The request the provider refused and the one after the renewal:
    // both arrived, and both are in the list.
    assert_eq!(provider.plan_requests().len(), 2);
}

#[test]
fn the_fake_takes_a_request_as_large_as_the_crate_builds() {
    let desk = Desk::new();
    let long = "a".repeat(3 * 1024 * 1024);
    let asked = ResponseRequest::text("example-large", &long).unwrap();
    desk.provider.push_response(FakeResponse::text(&["Read."]));
    let stream = desk.client.stream_response(&desk.id, &asked).unwrap();
    assert_eq!(stream.into_text().unwrap(), "Read.");
    assert!(desk.provider.plan_requests()[0].len() > long.len());
}

#[test]
fn the_fake_frames_json_written_over_several_lines_as_one_event() {
    // Lines that end the three ways the stream format knows, and all of
    // them in one text.
    for line_end in ["\n", "\r\n", "\r"] {
        let indented = [
            "{",
            "  \"type\": \"response.output_text.delta\",",
            "  \"delta\": \"Hi\"",
            "}",
        ]
        .join(line_end);
        let mixed = "{\n  \"type\": \"response.output_text.delta\",\r\n  \"delta\":\r \"Hi\"\n}";
        for json in [indented.as_str(), mixed] {
            let desk = Desk::new();
            desk.provider
                .push_response(FakeResponse::stream().created().event(json).completed());
            let items = desk.items().unwrap();
            assert_eq!(text(&items), "Hi", "{line_end:?}");
            assert_eq!(kinds(&items).last().unwrap(), "response.completed");
        }
    }
}

#[test]
fn the_fake_frames_a_type_with_a_line_break_in_it_like_plain_data() {
    // Valid JSON: the line break is escaped inside the string. Written
    // into an `event:` line it would be a real one.
    for line_break in ["\\n", "\\r", "\\r\\n"] {
        let json = format!("{{\"type\":\"future{line_break}data: extra\"}}");
        let desk = Desk::new();
        let framed = format!("data: {json}\n\n");
        desk.provider
            .push_response(FakeResponse::stream().raw(framed.as_bytes()).completed());
        desk.provider
            .push_response(FakeResponse::stream().event(&json).completed());
        let plain = desk.items().unwrap();
        let built = desk.items().unwrap();
        assert_eq!(kinds(&plain), ["?", "response.completed"], "{line_break}");
        assert_eq!(kinds(&built), kinds(&plain), "{line_break}");
        let jsons = |items: &[Result<siwc::plan::ResponseEvent, siwc::Error>]| {
            let first = items[0].as_ref().unwrap();
            first.json().to_owned()
        };
        assert_eq!(jsons(&built), json);
        assert_eq!(jsons(&plain), json);
    }
}
