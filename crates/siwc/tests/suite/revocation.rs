//! Revocation at sign-out.

use siwc::ErrorKind;
use siwc::protocol::HttpResponse;

use crate::support::World;
use crate::support::provider::{REVOKE_URL, User};

#[test]
fn sign_out_revokes_the_refresh_token_of_the_issued_client() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let request = signed_in.credentials().revoke_request().unwrap();
    assert_eq!(request.url(), REVOKE_URL);

    let response = world.provider.send(&request);
    let seen = world.provider.last_seen();
    assert_eq!(seen.field("token_type_hint"), Some("refresh_token"));
    assert_eq!(
        seen.field("client_id"),
        Some(signed_in.client_id().as_str())
    );
    assert!(
        seen.field("token")
            .is_some_and(|token| token.starts_with("refresh-"))
    );
    assert!(
        signed_in
            .credentials()
            .revocation_confirmed(&response)
            .is_ok()
    );
}

#[test]
fn a_revoked_session_can_no_longer_be_renewed() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let credentials = signed_in.credentials();
    world.provider.send(&credentials.revoke_request().unwrap());

    let response = world.provider.send(&credentials.refresh_request().unwrap());
    let error = credentials.refreshed(response, world.now()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::SignInRequired);
}

#[test]
fn an_unconfirmed_revocation_is_reported() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let request = signed_in.credentials().revoke_request().unwrap();

    for (status, body, kind) in [
        (503, "", ErrorKind::Temporary),
        (429, "{}", ErrorKind::Temporary),
        (400, r#"{"error":"invalid_request"}"#, ErrorKind::Rejected),
        (
            401,
            r#"{"error":"invalid_client"}"#,
            ErrorKind::ClientRejected,
        ),
    ] {
        world.provider.fail_next(status, body);
        let error = signed_in
            .credentials()
            .revocation_confirmed(&world.provider.send(&request))
            .unwrap_err();
        assert_eq!(error.kind(), kind, "{status}");
    }
}

#[test]
fn revocation_errors_drop_echoes_of_the_refresh_token() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let request = signed_in.credentials().revoke_request().unwrap();
    let fields = crate::support::wire::form_decode(std::str::from_utf8(request.body()).unwrap());
    let token = crate::support::wire::only(&fields, "token");
    let embedded = format!("prefix.{token}.suffix");
    for (code, id, kept_code, kept_id) in [
        (token, "req_example", None, Some("req_example")),
        ("slow_down", token, Some("slow_down"), None),
        (embedded.as_str(), embedded.as_str(), None, None),
    ] {
        let body = serde_json::json!({ "error": code })
            .to_string()
            .into_bytes();
        let response = HttpResponse::new(503, body).with_request_id(Some(id));
        let error = signed_in
            .credentials()
            .revocation_confirmed(&response)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Temporary);
        assert_eq!(error.http_status(), Some(503));
        assert_eq!(
            (error.provider_code(), error.request_id()),
            (kept_code, kept_id)
        );
    }
}
