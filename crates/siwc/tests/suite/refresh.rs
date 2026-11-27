//! Renewal: timing, rotation and which failures end a session.

use serde_json::json;
use siwc::protocol::{Credentials, Registration, Returning};
use siwc::{ErrorKind, UnixTime};

use crate::support::provider::{TOKEN_URL, User};
use crate::support::{NOW, World};

fn at(offset: u64) -> UnixTime {
    UnixTime::from_secs(NOW + offset)
}

/// Sends the refresh for `credentials` and reads the answer.
fn renew(world: &World, credentials: &Credentials) -> Result<Credentials, siwc::Error> {
    let request = credentials.refresh_request().unwrap();
    credentials.refreshed(world.provider.send(&request), world.now())
}

fn refresh_token_sent(world: &World) -> String {
    world
        .provider
        .last_seen()
        .field("refresh_token")
        .unwrap()
        .to_owned()
}

#[test]
fn a_token_is_renewed_from_a_minute_before_it_expires() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let credentials = signed_in.credentials();

    assert!(!credentials.needs_refresh(at(0)));
    assert!(!credentials.needs_refresh(at(3539)));
    assert!(credentials.needs_refresh(at(3540)));
    assert!(credentials.needs_refresh(at(3600)));
    assert!(credentials.needs_refresh(at(86_400)));
}

#[test]
fn a_refresh_sends_the_latest_token_for_the_issued_client() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let request = signed_in.credentials().refresh_request().unwrap();
    assert_eq!(request.url(), TOKEN_URL);

    world.provider.send(&request);
    let seen = world.provider.last_seen();
    assert_eq!(seen.field("grant_type"), Some("refresh_token"));
    assert_eq!(
        seen.field("client_id"),
        Some(signed_in.client_id().as_str())
    );
    assert_eq!(seen.field("resource"), Some("https://api.openai.com/v1"));
    assert_eq!(seen.field("scope"), None);
    assert!(
        seen.field("refresh_token")
            .is_some_and(|token| token.starts_with("refresh-"))
    );
}

#[test]
fn every_refresh_rotates_the_refresh_token() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());

    world.provider.set_now(NOW + 3600);
    let request = signed_in.credentials().refresh_request().unwrap();
    let second = signed_in
        .credentials()
        .refreshed(world.provider.send(&request), at(3600))
        .unwrap();
    let first_token = refresh_token_sent(&world);

    let third = renew(&world, &second).unwrap();
    let second_token = refresh_token_sent(&world);
    renew(&world, &third).unwrap();
    let third_token = refresh_token_sent(&world);

    assert_ne!(first_token, second_token);
    assert_ne!(second_token, third_token);
    assert_ne!(
        signed_in.credentials().access_token().expose(),
        second.access_token().expose()
    );
    assert_eq!(second.expires_at(), at(7200));
    assert!(second.scopes().grants_plan_use());
}

#[test]
fn a_token_that_was_already_rotated_requires_a_new_sign_in() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    renew(&world, signed_in.credentials()).unwrap();

    let error = renew(&world, signed_in.credentials()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::SignInRequired);
    assert_eq!(error.provider_code(), Some("refresh_token_reused"));
    assert_eq!(
        error.to_string(),
        "the session can no longer be renewed (refresh_token_reused)"
    );
}

#[test]
fn refresh_errors_drop_echoes_of_the_spent_refresh_token() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let credentials = signed_in.credentials();
    world.provider.send(&credentials.refresh_request().unwrap());
    let token = refresh_token_sent(&world);
    let embedded = format!("prefix.{token}.suffix");
    for (code, id, kept_code, kept_id) in [
        (token.as_str(), "req_example", None, Some("req_example")),
        ("slow_down", token.as_str(), Some("slow_down"), None),
        (embedded.as_str(), embedded.as_str(), None, None),
    ] {
        let body = json!({ "error": code }).to_string().into_bytes();
        let answer = siwc::protocol::HttpResponse::new(503, body).with_request_id(Some(id));
        let error = credentials.refreshed(answer, world.now()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Temporary);
        assert_eq!(error.http_status(), Some(503));
        assert_eq!(
            (error.provider_code(), error.request_id()),
            (kept_code, kept_id)
        );
    }
}

#[test]
fn every_terminal_refresh_error_requires_a_new_sign_in() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    for code in [
        "invalid_grant",
        "invalid_refresh_token",
        "token_expired",
        "refresh_token_expired",
        "refresh_token_invalidated",
        "refresh_token_reused",
    ] {
        for body in [
            json!({ "error": code }),
            json!({ "error": { "code": code } }),
        ] {
            world.provider.fail_next(400, &body.to_string());
            let error = renew(&world, signed_in.credentials()).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::SignInRequired, "{body}");
            assert_eq!(error.provider_code(), Some(code));
        }
    }
}

#[test]
fn a_temporary_failure_keeps_the_session() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    for (status, body) in [
        (503, "<html>"),
        (500, "{}"),
        (429, r#"{"error":"slow_down"}"#),
        (408, ""),
    ] {
        world.provider.fail_next(status, body);
        let error = renew(&world, signed_in.credentials()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Temporary, "{status}");
        assert!(error.is_temporary());
    }

    assert!(
        renew(&world, signed_in.credentials()).is_ok(),
        "the token was never used up"
    );
}

#[test]
fn other_refusals_keep_the_session_and_say_what_they_are() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());

    world
        .provider
        .fail_next(401, r#"{"error":"invalid_client"}"#);
    let error = renew(&world, signed_in.credentials()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ClientRejected);
    assert_eq!(
        error.to_string(),
        "the provider no longer accepts the issued client ID (invalid_client)"
    );

    world
        .provider
        .fail_next(400, r#"{"error":"invalid_request"}"#);
    let error = renew(&world, signed_in.credentials()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Rejected);

    world.provider.fail_next(403, "forbidden");
    let error = renew(&world, signed_in.credentials()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Rejected);
    assert_eq!(error.provider_code(), None);
}

#[test]
fn an_answer_without_optional_fields_keeps_the_scopes_and_clears_the_refresh_hint() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex().without_plan_use());
    world.provider.alter_next_response(|body| {
        for name in ["scope", "id_token", "earliest_refresh_at"] {
            body.remove(name);
        }
    });
    let renewed = renew(&world, signed_in.credentials()).unwrap();

    assert_eq!(renewed.scopes(), signed_in.credentials().scopes());
    assert_eq!(renewed.earliest_refresh_at(), None);
}

#[test]
fn a_refresh_answer_without_a_replacement_refresh_token_is_rejected() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    world.provider.alter_next_response(|body| {
        body.remove("refresh_token");
    });

    let error = renew(&world, signed_in.credentials()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidResponse);
    assert_eq!(
        error.to_string(),
        "the token response carries no refresh token"
    );

    // The provider already rotated its copy, so the next refresh fails
    // terminally instead of stranding the session without a refresh token.
    let next = renew(&world, signed_in.credentials()).unwrap_err();
    assert_eq!(next.kind(), ErrorKind::SignInRequired);
}

#[test]
fn a_renewed_grant_replaces_the_scopes() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    world
        .provider
        .alter_next_response(|body| drop(body.insert("scope".into(), json!("openid email"))));
    let renewed = renew(&world, signed_in.credentials()).unwrap();

    assert!(!renewed.scopes().grants_plan_use());
}

#[test]
fn the_id_token_of_a_refresh_is_not_adopted() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let hint_sent = |credentials: &Credentials| {
        let returning = Returning::signed_in(signed_in.identity(), credentials).with_hints();
        let attempt = world.attempt(Registration::Saved(returning));
        world
            .provider
            .authorize(attempt.authorization_url(), &User::alex());
        world
            .provider
            .last_seen()
            .field("id_token_hint")
            .unwrap()
            .to_owned()
    };
    let verified = hint_sent(signed_in.credentials());

    world.provider.alter_next_id_token(|draft| {
        drop(draft.claims.insert("sub".into(), json!("user-sam-0002")))
    });
    let renewed = renew(&world, signed_in.credentials()).unwrap();

    assert_eq!(hint_sent(&renewed), verified);

    world.provider.alter_next_response(|body| {
        drop(body.insert(
            "id_token".into(),
            json!({"unexpected":"synthetic metadata"}),
        ));
    });
    let renewed = renew(&world, &renewed).unwrap();
    assert_eq!(hint_sent(&renewed), verified);
}

#[test]
fn a_malformed_answer_is_invalid_and_leaves_the_credentials_usable() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    world.provider.fail_next(200, "<html>ok</html>");

    let error = renew(&world, signed_in.credentials()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidResponse);
    assert!(signed_in.credentials().refresh_request().is_some());
}

#[test]
fn a_session_without_a_refresh_token_cannot_be_renewed_or_revoked() {
    let world = World::new();
    world
        .provider
        .alter_next_response(|body| drop(body.remove("refresh_token")));
    let signed_in = world.sign_in(&User::alex());

    assert!(signed_in.credentials().refresh_request().is_none());
    assert!(signed_in.credentials().revoke_request().is_none());
}

#[test]
fn a_lifetime_longer_than_a_day_is_not_believed() {
    let world = World::new();
    world
        .provider
        .alter_next_response(|body| drop(body.insert("expires_in".into(), json!(u64::MAX))));
    let signed_in = world.sign_in(&User::alex());

    assert_eq!(signed_in.credentials().expires_at(), at(86_400));
}

#[test]
fn a_lifetime_as_text_or_with_a_fraction_is_read() {
    for lifetime in [json!("1800"), json!(1800.0), json!(1800.9)] {
        let world = World::new();
        world
            .provider
            .alter_next_response(move |body| drop(body.insert("expires_in".into(), lifetime)));
        let signed_in = world.sign_in(&User::alex());

        assert_eq!(signed_in.credentials().expires_at(), at(1800));
    }
}

#[test]
fn a_short_lived_token_is_renewed_halfway_and_not_on_every_use() {
    let world = World::new();
    world
        .provider
        .alter_next_response(|body| drop(body.insert("expires_in".into(), json!(30))));
    let signed_in = world.sign_in(&User::alex());
    let credentials = signed_in.credentials();

    assert!(!credentials.needs_refresh(at(0)));
    assert!(!credentials.needs_refresh(at(14)));
    assert!(credentials.needs_refresh(at(15)));
}

#[test]
fn a_refresh_answer_without_a_lifetime_lasts_the_documented_hour() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    world.provider.alter_next_response(|body| {
        body.remove("expires_in");
        body.remove("token_type");
    });
    let renewed = renew(&world, signed_in.credentials()).unwrap();

    assert_eq!(renewed.expires_at(), at(3600));
    assert_ne!(
        renewed.access_token().expose(),
        signed_in.credentials().access_token().expose()
    );
}

/// The provider has rotated the token, but its successor cannot be read.
/// Falling back to the spent token and reporting success would hide that.
#[test]
fn an_unreadable_successor_is_not_reported_as_a_renewal() {
    for unusable in [json!(""), json!(17), json!("x".repeat(16 * 1024 + 1))] {
        let world = World::new();
        let signed_in = world.sign_in(&User::alex());
        world.provider.alter_next_response(move |body| {
            drop(body.insert("refresh_token".into(), unusable));
        });
        let error = renew(&world, signed_in.credentials()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);

        // The spent token then ends the session the documented way.
        let error = renew(&world, signed_in.credentials()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SignInRequired);
    }
}

#[test]
fn earliest_refresh_at_delays_proactive_renewal_until_its_timestamp_but_never_past_expiry() {
    // 1. Numeric Unix seconds later than `expires_at - 60`.
    let world = World::new();
    let target = at(3585).as_secs();
    world.provider.alter_next_response(move |body| {
        drop(body.insert("earliest_refresh_at".into(), json!(target)));
    });
    let signed_in = world.sign_in(&User::alex());
    let creds = signed_in.credentials();
    assert_eq!(creds.earliest_refresh_time(), Some(at(3585)));
    assert!(!creds.needs_refresh(at(3540)));
    assert!(!creds.needs_refresh(at(3584)));
    assert!(creds.needs_refresh(at(3585)));

    // 2. RFC 3339 timestamp past `expires_at`: capped at `expires_at` so an
    //    expired access token is never kept without renewal.
    let world = World::new();
    world.provider.alter_next_response(|body| {
        drop(body.insert("earliest_refresh_at".into(), json!("2099-01-01T00:00:00Z")));
    });
    let signed_in = world.sign_in(&User::alex());
    let creds = signed_in.credentials();
    assert!(!creds.needs_refresh(at(3599)));
    assert!(creds.needs_refresh(at(3600)));
}
