//! The code exchange and what a completed sign-in holds.

use serde_json::json;
use siwc::ErrorKind;
use siwc::protocol::{Exchange, HttpRequest, HttpResponse, Method};

use crate::support::provider::{REVOKE_URL, Request, TOKEN_URL, User};
use crate::support::wire::{form_decode, only};
use crate::support::{NOW, World};

#[test]
fn the_code_is_exchanged_with_verifier_client_redirect_and_resource() {
    let world = World::new();
    let exchange = world.authorized(&User::alex());
    let request = exchange.request();
    assert_eq!(request.method(), Method::Post);
    assert_eq!(request.url(), TOKEN_URL);

    world.provider.send(&request);
    let seen = world.provider.last_seen();
    assert_eq!(seen.field("grant_type"), Some("authorization_code"));
    assert_eq!(seen.field("client_id"), Some(exchange.client_id().as_str()));
    assert_eq!(
        seen.field("redirect_uri"),
        Some("http://127.0.0.1:53124/auth/callback")
    );
    assert_eq!(seen.field("resource"), Some("https://api.openai.com/v1"));
    assert_eq!(seen.field("code_verifier").map(str::len), Some(43));
    assert!(
        seen.field("code")
            .is_some_and(|code| code.starts_with("code-"))
    );
}

#[test]
fn the_same_request_can_be_built_until_an_answer_arrives() {
    let world = World::new();
    let exchange = world.authorized(&User::alex());
    assert_eq!(exchange.request().body(), exchange.request().body());
}

#[test]
fn exchange_errors_drop_the_authorization_code_and_pkce_verifier() {
    let world = World::new();
    for (code_field, id_field) in [("code", "code_verifier"), ("code_verifier", "code")] {
        let exchange = world.authorized(&User::alex());
        let request = exchange.request();
        let fields = form_decode(std::str::from_utf8(request.body()).unwrap());
        let code = format!("error.{}", only(&fields, code_field));
        let id = format!("req.{}", only(&fields, id_field));
        let answer = HttpResponse::new(503, json!({"error": code}).to_string().into_bytes())
            .with_request_id(Some(&id));

        let error = exchange.response(answer, world.now()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Temporary);
        assert_eq!(error.http_status(), Some(503));
        assert_eq!(error.provider_code(), None, "echoed {code_field}");
        assert_eq!(error.request_id(), None, "echoed {id_field}");
    }
}

fn exchange_with_refresh(world: &World, exchange: &Exchange) -> (HttpResponse, String) {
    let answer = world.provider.answer(&Request::of(&exchange.request()));
    let body: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
    let refresh = body["refresh_token"].as_str().unwrap().to_owned();
    (HttpResponse::new(answer.status, answer.body), refresh)
}

fn assert_revocation(request: &HttpRequest, client: &str, refresh: &str) {
    assert_eq!(request.url(), REVOKE_URL);
    assert_eq!(request.method(), Method::Post);
    let fields = form_decode(std::str::from_utf8(request.body()).unwrap());
    assert_eq!(only(&fields, "client_id"), client);
    assert_eq!(only(&fields, "token_type_hint"), "refresh_token");
    assert_eq!(only(&fields, "token"), refresh);
}

#[test]
fn a_protocol_caller_can_revoke_when_the_exchange_has_no_id_token() {
    let world = World::new();
    let exchange = world.authorized(&User::alex());
    let client = exchange.client_id().as_str().to_owned();
    world.provider.alter_next_response(|body| {
        body.remove("id_token");
    });
    let (answer, refresh) = exchange_with_refresh(&world, &exchange);

    let mut revocation = None;
    let error = exchange
        .response_with_revocation(answer, world.now(), |request| revocation = Some(request))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidResponse);
    assert_revocation(&revocation.unwrap(), &client, &refresh);
}

#[test]
fn a_protocol_caller_can_revoke_when_any_token_member_is_unusable() {
    let world = World::new();
    for (member, value) in [
        ("access_token", None),
        ("access_token", Some(json!("not a bearer token"))),
        ("token_type", Some(json!("Basic"))),
        ("expires_in", Some(json!("later"))),
        ("scope", Some(json!(["openid"]))),
        ("id_token", Some(json!(42))),
    ] {
        let exchange = world.authorized(&User::alex());
        let client = exchange.client_id().as_str().to_owned();
        world.provider.alter_next_response(move |body| {
            if let Some(value) = value {
                body.insert(member.into(), value);
            } else {
                body.remove(member);
            }
        });
        let (answer, refresh) = exchange_with_refresh(&world, &exchange);

        let mut revocation = None;
        let error = exchange
            .response_with_revocation(answer, world.now(), |request| revocation = Some(request))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse, "{member}");
        let revocation = revocation.unwrap_or_else(|| panic!("no revocation for {member}"));
        assert_revocation(&revocation, &client, &refresh);
    }
}

#[test]
fn a_protocol_sign_in_drops_token_echoes_from_key_set_errors() {
    let world = World::new();
    let exchange = world.authorized(&User::alex());
    world.provider.alter_next_response(|body| {
        body.insert("access_token".into(), json!("access-synthetic"));
        body.insert("refresh_token".into(), json!("refresh-synthetic"));
        body.insert("id_token".into(), json!("synthetic.id.token"));
    });
    let (answer, _) = exchange_with_refresh(&world, &exchange);
    let unverified = exchange.response(answer, world.now()).unwrap();
    for (request_id, expected) in [
        ("req.access-synthetic", None),
        ("req.refresh-synthetic", None),
        ("req.synthetic.id.token", None),
        ("req.synthetic-diagnostic", Some("req.synthetic-diagnostic")),
    ] {
        let keys = HttpResponse::new(503, b"{}".to_vec()).with_request_id(Some(request_id));
        let error = unverified.keys_from_response(&keys).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Temporary);
        assert_eq!(error.http_status(), Some(503));
        assert_eq!(error.request_id(), expected);
    }
}

#[test]
fn a_protocol_caller_can_revoke_when_verification_fails() {
    let world = World::new();
    let exchange = world.authorized(&User::alex());
    let client = exchange.client_id().as_str().to_owned();
    world.provider.alter_next_response(|body| {
        body.insert("id_token".into(), json!("synthetic"));
    });
    let (answer, refresh) = exchange_with_refresh(&world, &exchange);

    let unverified = exchange.response(answer, world.now()).unwrap();
    let revocation = unverified.revoke_request().unwrap();
    let error = unverified.verify(&world.keys(), world.now()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::IdentityRejected);
    assert_revocation(&revocation, &client, &refresh);
    assert_eq!(world.provider.send(&revocation).status(), 200);
}

#[test]
fn a_first_sign_in_ends_with_a_verified_identity_and_plan_use() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());

    let identity = signed_in.identity();
    assert_eq!(identity.subject(), "user-alex-0001");
    assert_eq!(identity.email(), Some("alex@example.com"));
    assert!(identity.email_verified());
    assert_eq!(identity.name(), Some("Alex Example"));
    assert_eq!(identity.picture(), None);

    let credentials = signed_in.credentials();
    assert!(credentials.scopes().grants_plan_use());
    assert!(credentials.scopes().contains("offline_access"));
    assert_eq!(credentials.expires_at().as_secs(), NOW + 3600);
    assert!(!credentials.needs_refresh(world.now()));
    assert_eq!(
        credentials.earliest_refresh_at(),
        Some("\"synthetic-earliest\"")
    );
    assert!(credentials.access_token().expose().starts_with("access-"));

    let (identity, credentials) = signed_in.into_parts();
    assert!(credentials.client_id().as_str().starts_with("app_issued"));
    assert_eq!(identity.subject(), "user-alex-0001");
    assert_eq!(credentials.subject(), "user-alex-0001");
}

#[test]
fn an_identity_only_grant_is_signed_in_without_plan_use() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex().without_plan_use());

    assert_eq!(signed_in.identity().subject(), "user-alex-0001");
    assert!(!signed_in.credentials().scopes().grants_plan_use());
    assert!(signed_in.credentials().scopes().contains("openid"));
}

#[test]
fn an_answer_without_scope_grants_what_was_requested() {
    let world = World::new();
    world.provider.alter_next_response(|body| {
        body.remove("scope");
        body.remove("earliest_refresh_at");
    });
    let signed_in = world.sign_in(&User::alex());

    assert!(signed_in.credentials().scopes().grants_plan_use());
    assert_eq!(signed_in.credentials().earliest_refresh_at(), None);
}

#[test]
fn a_refused_code_is_rejected_with_the_providers_code() {
    let world = World::new();
    let exchange = world.authorized(&User::alex());
    world
        .provider
        .fail_next(400, r#"{"error":"invalid_grant"}"#);

    let error = world.finish(exchange).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Rejected);
    assert_eq!(error.provider_code(), Some("invalid_grant"));
    assert_eq!(
        error.to_string(),
        "the provider refused the authorization code (invalid_grant)"
    );
    assert!(!error.is_temporary());
}

#[test]
fn an_unavailable_provider_is_a_temporary_failure() {
    let world = World::new();
    for (status, body) in [(503, "<html>upstream</html>"), (429, "{}"), (500, "")] {
        let exchange = world.authorized(&User::alex());
        world.provider.fail_next(status, body);

        let error = world.finish(exchange).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Temporary, "{status}");
        assert!(error.is_temporary());
    }
}

#[test]
fn a_client_the_provider_no_longer_knows_is_reported_as_such() {
    let world = World::new();
    let exchange = world.authorized(&User::alex());
    world
        .provider
        .fail_next(401, r#"{"error":"invalid_client"}"#);

    assert_eq!(
        world.finish(exchange).unwrap_err().kind(),
        ErrorKind::ClientRejected
    );
}

#[test]
fn an_unknown_refusal_is_rejected_without_a_retry_hint() {
    let world = World::new();
    let exchange = world.authorized(&User::alex());
    world
        .provider
        .fail_next(400, r#"{"error":"unsupported_grant_type"}"#);

    let error = world.finish(exchange).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Rejected);
    assert_eq!(
        error.to_string(),
        "the provider refused the request (unsupported_grant_type)"
    );
}

#[test]
fn a_token_response_with_an_unusable_member_is_invalid() {
    let malformed = "the token response is malformed";
    let cases: [(&str, Option<serde_json::Value>, &str); 13] = [
        ("access_token", None, malformed),
        ("access_token", Some(json!("")), malformed),
        ("access_token", Some(json!(17)), malformed),
        (
            "access_token",
            Some(json!("x".repeat(16 * 1024 + 1))),
            malformed,
        ),
        ("refresh_token", Some(json!("")), malformed),
        ("refresh_token", Some(json!(["refresh-0001"])), malformed),
        (
            "id_token",
            Some(json!("x".repeat(16 * 1024 + 1))),
            malformed,
        ),
        ("id_token", None, "the token response carries no ID token"),
        ("expires_in", Some(json!(-1)), malformed),
        ("expires_in", Some(json!("soon")), malformed),
        (
            "scope",
            Some(json!(["openid", "chatgpt.tokens.use.direct"])),
            malformed,
        ),
        (
            "token_type",
            Some(json!("mac")),
            "the token response names a token type other than Bearer",
        ),
        (
            "token_type",
            Some(json!(7)),
            "the token response names a token type other than Bearer",
        ),
    ];
    let world = World::new();
    for (member, value, message) in cases {
        let exchange = world.authorized(&User::alex());
        let case = format!("{member} = {value:?}");
        world.provider.alter_next_response(move |body| match value {
            Some(value) => drop(body.insert(member.into(), value)),
            None => drop(body.remove(member)),
        });

        let error = world.finish(exchange).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse, "{case}");
        assert_eq!(error.to_string(), message, "{case}");
    }
}

#[test]
fn absent_or_null_optional_members_take_their_defaults() {
    let world = World::new();
    world.provider.alter_next_response(|body| {
        body.remove("expires_in");
        body.insert("refresh_token".into(), json!(null));
        body.insert("scope".into(), json!(null));
        body.insert("token_type".into(), json!(null));
    });
    let signed_in = world.sign_in(&User::alex());
    let credentials = signed_in.credentials();

    assert_eq!(credentials.expires_at().as_secs(), NOW + 3600);
    assert!(credentials.refresh_request().is_none());
    assert!(credentials.scopes().grants_plan_use());
}

#[test]
fn a_success_status_with_another_body_is_invalid() {
    let world = World::new();
    for body in [
        "",
        "<html>ok</html>",
        "[]",
        "\"text\"",
        "{\"access_token\":",
    ] {
        let exchange = world.authorized(&User::alex());
        world.provider.fail_next(200, body);
        assert_eq!(
            world.finish(exchange).unwrap_err().kind(),
            ErrorKind::InvalidResponse
        );
    }
}

#[test]
fn an_access_token_that_could_not_be_a_bearer_header_is_invalid() {
    let world = World::new();
    for access in [
        "access token",
        "access\r\nx-injected: 1",
        "access=token",
        "\u{e4}",
    ] {
        let exchange = world.authorized(&User::alex());
        world.provider.alter_next_response(move |body| {
            drop(body.insert("access_token".into(), json!(access)))
        });
        let error = world.finish(exchange).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse, "{access:?}");
        assert_eq!(
            error.to_string(),
            "the token response is malformed",
            "{access:?}"
        );
    }
}

#[test]
fn a_token_response_of_another_token_type_is_invalid() {
    let world = World::new();
    for token_type in [json!("mac"), json!("DPoP"), json!(7)] {
        let exchange = world.authorized(&User::alex());
        world
            .provider
            .alter_next_response(move |body| drop(body.insert("token_type".into(), token_type)));
        let error = world.finish(exchange).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
        assert_eq!(
            error.to_string(),
            "the token response names a token type other than Bearer"
        );
    }
}

#[test]
fn a_bearer_token_type_in_any_case_is_accepted() {
    let world = World::new();
    world
        .provider
        .alter_next_response(|body| drop(body.insert("token_type".into(), json!("bearer"))));
    assert!(
        world
            .sign_in(&User::alex())
            .credentials()
            .scopes()
            .grants_plan_use()
    );
}

#[test]
fn an_error_never_repeats_what_the_provider_wrote() {
    let world = World::new();
    let exchange = world.authorized(&User::alex());
    world.provider.fail_next(
        400,
        r#"{"error":"invalid_grant","error_description":"detail-4711 for alex@example.com"}"#,
    );

    let error = world.finish(exchange).unwrap_err();
    let printed = format!("{error} {error:?}");
    assert!(
        !printed.contains("4711") && !printed.contains("alex"),
        "{printed}"
    );
}

#[test]
fn exchange_accepts_a_token_member_at_16_kib() {
    let world = World::new();
    let exchange = world.authorized(&User::alex());
    world.provider.alter_next_response(|body| {
        body.insert("access_token".into(), json!("x".repeat(16 * 1024)));
    });
    assert!(world.finish(exchange).is_ok());
}
