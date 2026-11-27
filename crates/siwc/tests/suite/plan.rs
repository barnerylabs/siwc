//! Plan use after sign-in: the model list and what the API's refusals mean.

use serde_json::{Value, json};
use siwc::plan::{MANAGE_USAGE_URL, Models, Reason, Refusal, wording};
use siwc::protocol::{HttpResponse, Method};
use siwc::{Error, ErrorKind};

use crate::support::provider::{User, model_list};
use crate::support::random::Generator;
use crate::support::{NOW, World};

/// Every documented code with the reason and error kind it stands for.
const CODES: [(&str, Reason, ErrorKind); 10] = [
    (
        "subscription_sharing_usage_limit_exceeded",
        Reason::UsageLimit,
        ErrorKind::UsageLimit,
    ),
    (
        "subscription_sharing_user_not_eligible",
        Reason::NotPermitted,
        ErrorKind::NotPermitted,
    ),
    (
        "chatpass_v2_scope_not_authorized",
        Reason::PlanUseNotGranted,
        ErrorKind::PlanUseNotGranted,
    ),
    (
        "chatpass_v2_invalid_authorization_context",
        Reason::PlanUseNotGranted,
        ErrorKind::PlanUseNotGranted,
    ),
    (
        "subscription_sharing_invalid_user",
        Reason::TokenRejected,
        ErrorKind::TokenRejected,
    ),
    (
        "subscription_sharing_usage_unavailable",
        Reason::Unavailable,
        ErrorKind::Temporary,
    ),
    (
        "subscription_sharing_user_unavailable",
        Reason::Unavailable,
        ErrorKind::Temporary,
    ),
    (
        "subscription_sharing_unsupported_capability",
        Reason::Unsupported,
        ErrorKind::Rejected,
    ),
    (
        "subscription_sharing_route_not_supported",
        Reason::RouteNotSupported,
        ErrorKind::Rejected,
    ),
    ("example_unknown_code", Reason::Other, ErrorKind::Rejected),
];

fn models_from(status: u16, body: &[u8]) -> Result<Models, Error> {
    Models::from_response(&HttpResponse::new(status, body.to_vec()))
}

fn models_of(body: &Value) -> Vec<(String, String)> {
    models_from(200, body.to_string().as_bytes())
        .unwrap()
        .iter()
        .map(|model| (model.id().to_owned(), model.display_name().to_owned()))
        .collect()
}

fn refusal(status: u16, body: &Value) -> Refusal {
    Refusal::from_response(status, body.to_string().as_bytes()).unwrap()
}

fn error_body(code: &str) -> Value {
    json!({ "error": { "code": code, "message": "synthetic message" } })
}

#[test]
fn models_are_requested_with_the_access_token_in_a_header_only() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let token = signed_in.credentials().access_token().expose().to_owned();
    let request = Models::request(signed_in.credentials().access_token());

    assert_eq!(request.method(), Method::Get);
    assert_eq!(request.url(), "https://api.openai.com/v1/models");
    assert!(request.body().is_empty());
    let headers: Vec<_> = request.headers().collect();
    assert_eq!(
        headers,
        [
            ("accept", "application/json"),
            ("authorization", format!("Bearer {token}").as_str()),
        ]
    );
    assert!(!request.url().contains(&token));
    let printed = format!("{request:?}");
    assert!(!printed.contains(&token), "{printed}");
    assert!(!printed.contains("access-"), "{printed}");
}

#[test]
fn a_signed_in_account_reads_its_listed_models_in_the_providers_order() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());

    let request = Models::request(signed_in.credentials().access_token());
    let models = Models::from_response(&world.provider.send(&request)).unwrap();

    let listed: Vec<_> = models
        .iter()
        .map(|model| (model.id(), model.display_name()))
        .collect();
    assert_eq!(
        listed,
        [
            ("example-large", "Example Large"),
            ("example-small", "Example Small"),
            ("example-mini", "example-mini"),
        ]
    );
    assert_eq!(models.len(), 3);
    assert!(!models.is_empty());
}

#[test]
fn an_expired_or_unknown_token_is_rejected_as_a_token_to_refresh() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let request = Models::request(signed_in.credentials().access_token());

    world.provider.set_now(NOW + 3600);
    let error = Models::from_response(&world.provider.send(&request)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TokenRejected);
    assert_eq!(
        error.provider_code(),
        Some("subscription_sharing_invalid_user")
    );
    assert!(!error.is_temporary());

    let other = World::new();
    let error = Models::from_response(&other.provider.send(&request)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TokenRejected);
}

#[test]
fn an_identity_only_sign_in_is_told_that_plan_use_was_not_granted() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex().without_plan_use());
    let request = Models::request(signed_in.credentials().access_token());

    let error = Models::from_response(&world.provider.send(&request)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PlanUseNotGranted);
    assert_eq!(
        error.provider_code(),
        Some("chatpass_v2_scope_not_authorized")
    );
}

#[test]
fn a_refused_model_request_reports_the_kind_and_code_of_the_refusal() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let request = Models::request(signed_in.credentials().access_token());

    let body = error_body("subscription_sharing_usage_limit_exceeded").to_string();
    world.provider.refuse_next_api_request(429, &body);
    let error = Models::from_response(&world.provider.send(&request)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UsageLimit);
    assert_eq!(
        error.provider_code(),
        Some("subscription_sharing_usage_limit_exceeded")
    );

    world.provider.refuse_next_api_request(503, "");
    let error = Models::from_response(&world.provider.send(&request)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert_eq!(error.provider_code(), None);

    assert_eq!(
        Models::from_response(&world.provider.send(&request))
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn only_listed_entries_with_a_usable_slug_are_kept() {
    let long = "x".repeat(129);
    let body = json!({ "models": [
        { "slug": "example-a", "display_name": "A", "visibility": "list" },
        { "slug": "example-b", "display_name": "B", "visibility": "List" },
        { "slug": "example-c", "display_name": "C", "visibility": " list" },
        { "slug": "example-d", "display_name": "D" },
        { "slug": "example-e", "display_name": "E", "visibility": ["list"] },
        { "slug": "example f", "visibility": "list" },
        { "slug": "example-g\n", "visibility": "list" },
        { "slug": "bad\"quote", "visibility": "list" },
        { "slug": "bad\\slash", "visibility": "list" },
        { "slug": "non-ascii-\u{e4}", "visibility": "list" },
        { "slug": "", "visibility": "list" },
        { "slug": long, "visibility": "list" },
        { "slug": 7, "visibility": "list" },
        { "slug": null, "visibility": "list" },
        "example-h",
        null,
        { "slug": "example-i", "display_name": "", "visibility": "list" },
        { "slug": "example-j", "display_name": "J\u{7}", "visibility": "list" },
        { "slug": "example-k", "display_name": long, "visibility": "list" },
        { "slug": "example-l", "display_name": 12, "visibility": "list" },
        { "slug": "example-m", "display_name": "Example M with spaces", "visibility": "list",
          "owned_by": "example", "extra": { "nested": [1, 2] } },
        { "slug": "x".repeat(128), "display_name": "\u{e4}".repeat(128), "visibility": "list" },
    ], "unknown": true });

    let owned = |slug: &str, name: &str| (slug.to_owned(), name.to_owned());
    assert_eq!(
        models_of(&body),
        [
            owned("example-a", "A"),
            owned("example-i", "example-i"),
            owned("example-j", "example-j"),
            owned("example-k", "example-k"),
            owned("example-l", "example-l"),
            owned("example-m", "Example M with spaces"),
            owned(&"x".repeat(128), &"\u{e4}".repeat(128)),
        ]
    );
}

#[test]
fn at_most_256_models_are_kept() {
    let entries: Vec<Value> = (0..300)
        .map(|index| json!({ "slug": format!("example-{index}"), "visibility": "list" }))
        .collect();
    let models = models_of(&json!({ "models": entries }));
    assert_eq!(models.len(), 256);
    assert_eq!(models.first().unwrap().0, "example-0");
    assert_eq!(models.last().unwrap().0, "example-255");
}

#[test]
fn an_answer_without_a_model_list_is_invalid() {
    let oversized = format!(r#"{{"models":[],"padding":"{}"}}"#, "x".repeat(1024 * 1024));
    for body in [
        "",
        "not json",
        "[]",
        "null",
        r#"{"data":[]}"#,
        r#"{"models":{}}"#,
        r#"{"models":null}"#,
        r#"{"models":"example-large"}"#,
        r#"{"models":[{"slug":"example-large","visibility":"list"}]"#,
        oversized.as_str(),
    ] {
        let error = models_from(200, body.as_bytes()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse, "{:.40}", body);
    }
}

#[test]
fn an_empty_model_list_is_valid_and_empty() {
    let models = models_from(200, br#"{"models":[]}"#).unwrap();
    assert!(models.is_empty());
    assert_eq!(models.len(), 0);
    assert_eq!(models.iter().count(), 0);
}

#[test]
fn another_success_status_is_not_a_model_list() {
    for status in [201, 204, 299] {
        let body = model_list().to_string();
        let error = models_from(status, body.as_bytes()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
    }
}

#[test]
fn the_code_is_read_from_the_error_object_or_from_the_top_level() {
    let nested = refusal(
        400,
        &json!({ "error": {
            "code": "subscription_sharing_unsupported_capability",
            "param": "tools[0].type",
            "type": "invalid_request_error",
        } }),
    );
    assert_eq!(nested.reason(), Reason::Unsupported);
    assert_eq!(
        nested.provider_code(),
        Some("subscription_sharing_unsupported_capability")
    );
    assert_eq!(nested.param(), Some("tools[0].type"));

    let top = refusal(
        400,
        &json!({ "code": "subscription_sharing_user_not_eligible" }),
    );
    assert_eq!(top.reason(), Reason::NotPermitted);
    assert_eq!(
        top.provider_code(),
        Some("subscription_sharing_user_not_eligible")
    );
    assert_eq!(top.param(), None);

    let detail = refusal(
        401,
        &json!({ "detail": "subscription_sharing_usage_limit_exceeded" }),
    );
    assert_eq!(detail.reason(), Reason::TokenRejected);
    assert_eq!(detail.provider_code(), None);
}

#[test]
fn detail_and_message_texts_are_never_kept() {
    let secret = "synthetic-secret-text";
    for body in [
        json!({ "detail": secret }),
        json!({ "error": { "code": "example_code", "message": secret } }),
        json!({ "error": { "message": secret, "param": "model" }, "detail": secret }),
    ] {
        let refusal = refusal(403, &body);
        let error = Error::from(refusal.clone());
        let printed = format!("{refusal:?} {error:?} {error}");
        assert!(!printed.contains(secret), "{printed}");
        assert_ne!(refusal.provider_code(), Some(secret));
        assert_ne!(refusal.param(), Some(secret));
    }
}

#[test]
fn an_unreadable_body_classifies_by_status_alone_and_an_oversized_one_by_nothing() {
    let code = "subscription_sharing_usage_limit_exceeded";
    let oversized = format!(
        r#"{{"error":{{"code":"{code}"}},"padding":"{}"}}"#,
        "x".repeat(64 * 1024)
    );
    let just_fits = format!(
        r#"{{"error":{{"code":"{code}"}},"padding":"{}"}}"#,
        "x".repeat(64 * 1024 - 100)
    );
    assert!(just_fits.len() <= 64 * 1024);
    let truncated = error_body(code).to_string();
    let truncated = &truncated[..truncated.len() - 2];
    for body in [&b""[..], b"not json", b"\xff\xfe", truncated.as_bytes()] {
        let refusal = Refusal::from_response(429, body).unwrap();
        assert_eq!(refusal.reason(), Reason::Unavailable);
        assert_eq!(refusal.provider_code(), None);
    }
    let refusal = Refusal::from_response(429, just_fits.as_bytes()).unwrap();
    assert_eq!(refusal.reason(), Reason::UsageLimit);

    // Of a body above 64 KiB nothing is known, the status's usual meaning
    // included: the unread part may be what says why.
    for status in [401, 403, 429, 503] {
        let refusal = Refusal::from_response(status, oversized.as_bytes())
            .unwrap()
            .with_request_id(Some("req_zz_7"));
        assert_eq!(refusal.reason(), Reason::Other);
        assert_eq!(refusal.provider_code(), None);
        assert_eq!(refusal.status(), Some(status));
        assert!(format!("{refusal:?}").contains("body_too_large: true"));
        let error = Error::from(refusal);
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
        assert_eq!(error.http_status(), Some(status));
        assert_eq!(error.request_id(), Some("req_zz_7"));
    }
    assert_eq!(Refusal::from_response(200, oversized.as_bytes()), None);
}

#[test]
fn codes_and_params_outside_the_allowed_characters_are_dropped_not_cut() {
    let longest = "a".repeat(128);
    let too_long = "a".repeat(129);
    let kept = refusal(
        400,
        &json!({ "error": { "code": longest, "param": "input[3].content-type_x.y" } }),
    );
    assert_eq!(kept.provider_code(), Some(longest.as_str()));
    assert_eq!(kept.param(), Some("input[3].content-type_x.y"));

    for bad in [
        too_long.as_str(),
        "",
        "with space",
        "semi;colon",
        "<script>",
        "line\nbreak",
        "\u{e4}",
    ] {
        let dropped = refusal(400, &json!({ "error": { "code": bad, "param": bad } }));
        assert_eq!(dropped.provider_code(), None, "{bad:?}");
        assert_eq!(dropped.param(), None, "{bad:?}");
        assert_eq!(dropped.reason(), Reason::Other);
    }
    let bracket = refusal(
        400,
        &json!({ "error": { "code": "a[0]", "param": "a[0]" } }),
    );
    assert_eq!(bracket.provider_code(), None);
    assert_eq!(bracket.param(), Some("a[0]"));
    let mistyped = refusal(
        400,
        &json!({ "error": { "code": 429, "param": ["model"] } }),
    );
    assert_eq!((mistyped.provider_code(), mistyped.param()), (None, None));
}

#[test]
fn every_documented_code_gives_its_reason_and_error_kind() {
    for (code, reason, kind) in CODES {
        // An unavailable code needs a status that allows another attempt.
        let status = if reason == Reason::Unavailable {
            503
        } else {
            400
        };
        let refusal = refusal(status, &error_body(code));
        assert_eq!(refusal.reason(), reason, "{code}");
        assert_eq!(refusal.provider_code(), Some(code));
        let error = Error::from(refusal);
        assert_eq!(error.kind(), kind, "{code}");
        assert_eq!(error.provider_code(), Some(code));
    }
}

#[test]
fn a_bare_status_gives_its_reason() {
    let cases = [
        (401, Reason::TokenRejected, ErrorKind::TokenRejected),
        (403, Reason::NotPermitted, ErrorKind::NotPermitted),
        (429, Reason::Unavailable, ErrorKind::Temporary),
        (500, Reason::Unavailable, ErrorKind::Temporary),
        (502, Reason::Unavailable, ErrorKind::Temporary),
        (503, Reason::Unavailable, ErrorKind::Temporary),
        (504, Reason::Unavailable, ErrorKind::Temporary),
        (400, Reason::Other, ErrorKind::Rejected),
        (404, Reason::Other, ErrorKind::Rejected),
        (408, Reason::Other, ErrorKind::Rejected),
        (501, Reason::Unavailable, ErrorKind::Temporary),
    ];
    for (status, reason, kind) in cases {
        for body in [&b""[..], br#"{"detail":"Forbidden"}"#, br#"{"error":{}}"#] {
            let refusal = Refusal::from_response(status, body).unwrap();
            assert_eq!(refusal.reason(), reason, "{status}");
            let error = Error::from(refusal);
            assert_eq!(error.kind(), kind, "{status}");
            assert_eq!(error.provider_code(), None);
        }
    }
}

#[test]
fn a_known_code_decides_the_reason_unless_it_suggests_retrying_a_final_status() {
    let cases = [
        (
            503,
            "subscription_sharing_usage_limit_exceeded",
            Reason::UsageLimit,
        ),
        (
            401,
            "subscription_sharing_user_not_eligible",
            Reason::NotPermitted,
        ),
        (
            429,
            "chatpass_v2_scope_not_authorized",
            Reason::PlanUseNotGranted,
        ),
        (
            403,
            "subscription_sharing_invalid_user",
            Reason::TokenRejected,
        ),
        (400, "subscription_sharing_user_unavailable", Reason::Other),
        (
            500,
            "subscription_sharing_route_not_supported",
            Reason::RouteNotSupported,
        ),
    ];
    for (status, code, reason) in cases {
        assert_eq!(
            refusal(status, &error_body(code)).reason(),
            reason,
            "{code}"
        );
    }
}

#[test]
fn an_unknown_code_is_kept_and_decided_by_the_status() {
    let teapot = refusal(418, &error_body("example_unknown_code"));
    assert_eq!(teapot.reason(), Reason::Other);
    assert_eq!(teapot.provider_code(), Some("example_unknown_code"));
    let error = Error::from(teapot);
    assert_eq!(error.kind(), ErrorKind::Rejected);
    assert_eq!(error.provider_code(), Some("example_unknown_code"));

    for status in 500..=599 {
        let busy = refusal(status, &error_body("example_unknown_code"));
        assert_eq!(busy.reason(), Reason::Unavailable);
    }
}

#[test]
fn success_statuses_are_no_refusal_and_other_statuses_are_classified() {
    for status in 200..=299 {
        assert_eq!(Refusal::from_response(status, b""), None, "{status}");
    }
    for status in [100, 101, 199, 300, 301, 304, 399, 0, 600, u16::MAX] {
        let refusal = Refusal::from_response(status, b"").unwrap();
        assert_eq!(refusal.reason(), Reason::Other, "{status}");
    }
}

#[test]
fn a_code_from_a_stream_event_is_classified_like_one_in_a_body() {
    for (code, reason, _) in CODES {
        let refusal = Refusal::from_code(code);
        assert_eq!(refusal.reason(), reason, "{code}");
        assert_eq!(refusal.provider_code(), Some(code));
        assert_eq!(refusal.param(), None);
    }
    for bad in ["", "with space", "a[0]", "a".repeat(129).as_str()] {
        let refusal = Refusal::from_code(bad);
        assert_eq!(refusal.reason(), Reason::Other);
        assert_eq!(refusal.provider_code(), None, "{bad:?}");
    }
}

#[test]
fn only_an_unavailable_refusal_is_temporary() {
    for (code, reason, _) in CODES {
        let error = Error::from(Refusal::from_code(code));
        assert_eq!(
            error.is_temporary(),
            reason == Reason::Unavailable,
            "{code}"
        );
    }
}

#[test]
fn the_manage_usage_link_and_the_wording_are_pinned() {
    let host = MANAGE_USAGE_URL
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next());
    assert_eq!(host, Some("chatgpt.com"));
    assert_eq!(MANAGE_USAGE_URL, "https://chatgpt.com/settings/usage");
    assert_eq!(wording::SIGN_IN, "Continue with ChatGPT");
    assert_eq!(wording::WELCOME, "You're using your ChatGPT plan");
    assert_eq!(wording::USING_PLAN, "Using ChatGPT plan");
    assert_eq!(wording::MANAGE_USAGE, "Manage usage");
}

/// A body built from a plausible answer by random damage: cuts, flipped
/// bytes, invalid UTF-8, wrong types, deep nesting and long strings.
fn hostile_body(generator: &mut Generator) -> Vec<u8> {
    let starts: [&[u8]; 9] = [
        br#"{"models":[{"slug":"example-large","display_name":"Example Large","visibility":"list"}]}"#,
        br#"{"error":{"code":"subscription_sharing_usage_limit_exceeded","param":"tools[0]"}}"#,
        br#"{"code":"subscription_sharing_invalid_user"}"#,
        br#"{"detail":"synthetic detail"}"#,
        br#"{"models":{"slug":1},"error":"text"}"#,
        br#"{"models":[null,1,"x",[],{"visibility":true}],"error":[1,2]}"#,
        b"[]",
        b"",
        b"null",
    ];
    let mut body = generator.pick(&starts).to_vec();
    for _ in 0..generator.below(4) {
        match generator.below(6) {
            0 => body.truncate(generator.below(body.len() + 1)),
            1 if !body.is_empty() => {
                let index = generator.below(body.len());
                body[index] = generator.next_u64() as u8;
            }
            2 => {
                let depth = generator.pick(&[10, 127, 129, 5000]);
                let open = generator.pick(&[&b"["[..], br#"{"models":"#, br#"{"error":"#]);
                let mut nested = open.repeat(depth);
                nested.extend_from_slice(&body);
                body = nested;
            }
            3 => {
                let length = generator.pick(&[128, 129, 70_000, 1_100_000]);
                let text = generator
                    .pick(&["a", "\u{e4}", " ", "\\u0000"])
                    .repeat(length);
                body = format!(
                    r#"{{"models":[{{"slug":"{text}","display_name":"{text}","visibility":"list"}}],"error":{{"code":"{text}","param":"{text}"}}}}"#
                )
                .into_bytes();
            }
            4 => body.extend_from_slice(generator.pick(&[&b"\xff\xfe"[..], b"\xc3", b"}", b","])),
            _ => body.extend_from_within(..),
        }
    }
    body
}

#[test]
fn hostile_bodies_never_panic_and_keep_only_clean_values() {
    let mut generator = Generator::new(4242);
    let statuses = [200, 200, 200, 400, 401, 403, 429, 500, 503, 418];
    let allowed = |text: &str, extra: &[u8]| {
        text.len() <= 128
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b) || extra.contains(&b))
    };
    for _ in 0..400 {
        let body = hostile_body(&mut generator);
        let status = generator.pick(&statuses);

        if let Some(refusal) = Refusal::from_response(status, &body) {
            assert!(
                refusal
                    .provider_code()
                    .is_none_or(|code| allowed(code, b""))
            );
            assert!(refusal.param().is_none_or(|param| allowed(param, b"[]")));
        }
        if let Some(refusal) = Refusal::from_event(&body) {
            assert!(
                refusal
                    .provider_code()
                    .is_none_or(|code| allowed(code, b""))
            );
            assert!(refusal.param().is_none_or(|param| allowed(param, b"[]")));
            assert_eq!(refusal.status(), None);
        }
        if let Ok(models) = models_from(status, &body) {
            assert!(models.len() <= 256);
            for model in models.iter() {
                assert!(!model.id().is_empty() && model.id().chars().count() <= 128);
                assert!(!model.id().chars().any(char::is_whitespace));
                assert!(!model.display_name().chars().any(char::is_control));
            }
        }
    }
}

#[test]
fn retry_after_is_read_in_whole_seconds_only() {
    let refusal = Refusal::from_response(503, b"{}").unwrap();
    let read = |header: &str| refusal.clone().with_retry_after(Some(header)).retry_after();
    assert_eq!(read("0"), Some(std::time::Duration::ZERO));
    assert_eq!(read(" 120 "), Some(std::time::Duration::from_secs(120)));
    for not_seconds in ["", "+5", "-1", "1.5", "5s", "Wed, 21 Oct 2026 07:28:00 GMT"] {
        assert_eq!(read(not_seconds), None, "{not_seconds:?}");
    }
    // More seconds than fit are a wait too long to take, not a missing one.
    for too_long in ["18446744073709551616", "99999999999999999999999"] {
        assert_eq!(
            read(too_long),
            Some(std::time::Duration::from_secs(u64::MAX)),
            "{too_long}"
        );
    }
    assert_eq!(refusal.with_retry_after(None).retry_after(), None);
}

#[test]
fn stream_failure_events_are_classified_from_json_and_sse_frames() {
    for (code, expected_reason, expected_kind) in CODES {
        let failed = json!({
            "type": "response.failed",
            "response": {
                "id": "resp_synthetic",
                "status": "failed",
                "error": {
                    "code": code,
                    "param": "tools[0].type",
                    "message": "synthetic secret detail"
                }
            }
        });
        let raw = Refusal::from_event(failed.to_string().as_bytes()).unwrap();
        assert_eq!(raw.reason(), expected_reason);
        assert_eq!(raw.provider_code(), Some(code));
        assert_eq!(raw.param(), Some("tools[0].type"));
        assert_eq!(raw.status(), None);

        let sse = format!(
            ": keep-alive\r\nevent: response.failed\r\nid: 7\r\ndata: {}\r\n\r\n",
            failed
        );
        let framed = Refusal::from_event(sse.as_bytes()).unwrap();
        assert_eq!(framed, raw);

        let error = Error::from(framed.with_request_id(Some("req_stream_1")));
        assert_eq!(error.kind(), expected_kind);
        assert_eq!(error.request_id(), Some("req_stream_1"));
        assert_eq!(error.param(), Some("tools[0].type"));
        assert!(!format!("{error} {error:?}").contains("synthetic secret detail"));
    }

    let named_error = concat!(
        "event: error\n",
        "data: {\"code\":\"subscription_sharing_user_not_eligible\"}\n\n"
    );
    assert_eq!(
        Refusal::from_event(named_error.as_bytes())
            .unwrap()
            .reason(),
        Reason::NotPermitted
    );

    let named_failure = concat!(
        "event: response.failed\n",
        "data: {\"response\":{\"error\":{\"code\":\"subscription_sharing_usage_unavailable\"}}}\n\n"
    );
    assert_eq!(
        Refusal::from_event(named_failure.as_bytes())
            .unwrap()
            .reason(),
        Reason::Unavailable
    );

    // Multi-line SSE `data:` frames and both `error` event shapes.
    let multiline = concat!(
        "event: error\n",
        "data: {\"type\":\"error\",\n",
        "data: \"code\":\"subscription_sharing_usage_unavailable\",\n",
        "data: \"param\":\"model\"}\n\n"
    );
    let top_error = Refusal::from_event(multiline.as_bytes()).unwrap();
    assert_eq!(top_error.reason(), Reason::Unavailable);
    assert_eq!(
        top_error.provider_code(),
        Some("subscription_sharing_usage_unavailable")
    );
    assert_eq!(top_error.param(), Some("model"));

    let nested_error = Refusal::from_event(
        br#"data:{"type":"error","error":{"code":"subscription_sharing_user_not_eligible"}}"#,
    )
    .unwrap();
    assert_eq!(nested_error.reason(), Reason::NotPermitted);

    let message = b"event: message\ndata: {\"error\":{\"code\":\"subscription_sharing_user_not_eligible\"}}\n\n";
    assert_eq!(
        Refusal::from_event(message).unwrap().reason(),
        Reason::NotPermitted
    );
    let block_without_data = b"event: error\n\ndata: {\"code\":\"example-progress\"}\n\n";
    assert!(Refusal::from_event(block_without_data).is_none());

    let bare_error = Refusal::from_event(
        br#"{"error":{"code":"subscription_sharing_unsupported_capability","param":"temperature"}}"#,
    )
    .unwrap();
    assert_eq!(bare_error.reason(), Reason::Unsupported);
    assert_eq!(bare_error.param(), Some("temperature"));

    // A `response.failed` or `error` event without an error code still counts as a refusal.
    let without_code =
        Refusal::from_event(br#"{"type":"response.failed","response":{"error":null}}"#).unwrap();
    assert_eq!(without_code.reason(), Reason::Other);
    assert_eq!(without_code.provider_code(), None);
}

#[test]
fn non_failure_stream_events_and_oversized_frames_are_ignored() {
    for benign in [
        &b""[..],
        b"   ",
        b": heartbeat\n\n",
        b"data: [DONE]\n\n",
        b"event: message\n\n",
        b"unknown: field\ndata: {\"type\":\"error\"}\n",
        br#"{"type":"response.created","response":{"status":"in_progress","error":null}}"#,
        br#"{"type":"response.in_progress","response":{"status":"in_progress","error":null}}"#,
        br#"data: {"type":"response.output_text.delta","delta":"hello"}"#,
        br#"data: {"type":"response.completed","response":{"status":"completed","error":null}}"#,
        br#"data: {"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}}"#,
        br#"{"error":null}"#,
        br#"{"detail":"not an error object"}"#,
    ] {
        assert_eq!(
            Refusal::from_event(benign),
            None,
            "{:?}",
            String::from_utf8_lossy(benign)
        );
    }

    let padded = format!(
        r#"{{"type":"response.failed","response":{{"error":{{"code":"subscription_sharing_usage_limit_exceeded"}}}},"pad":"{}"}}"#,
        "x".repeat(64 * 1024)
    );
    assert_eq!(Refusal::from_event(padded.as_bytes()), None);

    let unsafe_fields = Refusal::from_event(
        br#"{"type":"error","code":"bad code!","param":"bad param!","message":"secret"}"#,
    )
    .unwrap();
    assert_eq!(unsafe_fields.reason(), Reason::Other);
    assert_eq!(unsafe_fields.provider_code(), None);
    assert_eq!(unsafe_fields.param(), None);
}

#[test]
fn sse_decoder_streams_deltas_across_chunk_splits_and_requires_completed() {
    use siwc::plan::{MODELS_URL, RESPONSES_URL, SseDecoder, StreamEvent};

    assert_eq!(MODELS_URL, "https://api.openai.com/v1/models");
    assert_eq!(RESPONSES_URL, "https://api.openai.com/v1/responses");

    let stream = concat!(
        ": keep-alive\r\n",
        "event: response.created\r\n",
        "data: {\"type\":\"response.created\"}\r\n\r\n",
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hel\"}\r\n\r\n",
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"lo!\"}\n\n",
        "data: {\"type\":\"response.completed\",\"response\":{}}\n\n",
        "data: [DONE]\n\n",
    );

    // Feed 3 bytes at a time so `\r\n` pairs and UTF-8 lines split across chunks.
    let mut decoder = SseDecoder::new();
    let mut text = String::new();
    let mut completed = false;
    for chunk in stream.as_bytes().chunks(3) {
        for event in decoder.feed(chunk).unwrap() {
            match event.into_event() {
                StreamEvent::TextDelta { text: delta, .. } => text.push_str(&delta),
                StreamEvent::Completed { .. } => completed = true,
                _ => {}
            }
        }
    }
    decoder.finish().unwrap();
    assert!(completed);
    assert_eq!(text, "Hello!");

    // Standalone `\r` line endings work in `Refusal::from_event` as well.
    let cr_only =
        b"event: error\rdata: {\"code\":\"subscription_sharing_usage_limit_exceeded\"}\r\r";
    assert_eq!(
        Refusal::from_event(cr_only).unwrap().reason(),
        Reason::UsageLimit
    );

    // Premature EOF before `response.completed` (including mid-line / mid-UTF-8
    // network drops) is flagged as `Temporary`.
    let mut cut_off = SseDecoder::new();
    let events = cut_off
        .feed(b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"Half\"}\n\ndata: \xff")
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].text_delta(), Some("Half"));
    assert_eq!(cut_off.finish().unwrap_err().kind(), ErrorKind::Temporary);

    // Mid-stream `response.failed` and `response.incomplete` surface cleanly.
    let mut failed = SseDecoder::new();
    let events = failed
        .feed(b"data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"subscription_sharing_usage_limit_exceeded\"}}}\n\n")
        .unwrap();
    assert!(matches!(
        events[0].event(),
        StreamEvent::Failed(refusal) if refusal.reason() == Reason::UsageLimit
    ));
    // Neither ends in success: `finish` is `Ok` after `response.completed`
    // alone.
    assert_eq!(failed.finish().unwrap_err().kind(), ErrorKind::UsageLimit);

    let mut incomplete = SseDecoder::new();
    let events = incomplete
        .feed(b"data: {\"type\":\"response.incomplete\",\"response\":{\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}\n\n")
        .unwrap();
    assert!(matches!(
        events[0].event(),
        StreamEvent::Incomplete { reason: Some(reason), .. } if reason == "max_output_tokens"
    ));
    let stopped = incomplete.finish().unwrap_err();
    assert_eq!(stopped.kind(), ErrorKind::Incomplete);
    assert_eq!(stopped.provider_code(), Some("max_output_tokens"));
}

#[test]
fn invalid_http_statuses_do_not_classify_provider_codes() {
    for status in [0, 99, 600, u16::MAX] {
        let body = br#"{"error":"invalid_client"}"#;
        let response = HttpResponse::new(status, body.to_vec());
        assert_eq!(
            siwc::protocol::Jwks::from_response(&response)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidResponse
        );
        let refusal = Refusal::from_response(status, body).unwrap();
        assert_eq!(Error::from(refusal).kind(), ErrorKind::InvalidResponse);
    }
}

#[test]
fn model_list_size_includes_trailing_whitespace() {
    let mut body = br#"{"models":[]}"#.to_vec();
    body.resize(1024 * 1024, b' ');
    assert!(models_from(200, &body).unwrap().is_empty());
    body.push(b' ');
    assert_eq!(
        models_from(200, &body).unwrap_err().kind(),
        ErrorKind::InvalidResponse
    );
}

#[test]
fn standalone_decoder_checks_the_tail_after_a_terminal_failure() {
    let mut decoder = siwc::plan::SseDecoder::new();
    decoder
        .feed(b"data: {\"type\":\"error\",\"code\":\"subscription_sharing_invalid_user\"}\n\n")
        .unwrap();
    assert!(decoder.feed(b"id: 7\n\n").is_err());
    assert_eq!(
        decoder.finish().unwrap_err().kind(),
        ErrorKind::InvalidResponse
    );
}
