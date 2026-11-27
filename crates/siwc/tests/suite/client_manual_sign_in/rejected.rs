//! Failed sign-ins through a synthetic provider and transport.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use siwc::plan::Refusal;
use siwc::protocol::{HttpRequest, HttpResponse};
use siwc::{AppName, Client, Error, ErrorKind, Transport};

use crate::support::NOW;
use crate::support::provider::{JWKS_URL, Signer, TOKEN_URL, User};
use crate::support::recording::{Failure, RecordingTransport};
use crate::support::rig::Rig;
use crate::support::wire::{form_decode, only};

use super::approved_address;

const ACCESS: &str = "access-synthetic";
const REFRESH: &str = "refresh-synthetic";
const ID_TOKEN: &str = "synthetic.id.token";

fn finish(rig: &Rig, client: &Client) -> Error {
    let mut sign_in = client.add_account_manually().unwrap();
    sign_in
        .finish(&approved_address(rig, &sign_in, &User::alex()))
        .unwrap_err()
}

fn assert_revoked(
    rig: &Rig,
    kind: ErrorKind,
    message: &str,
    alter_response: impl FnOnce(&mut serde_json::Map<String, Value>) + Send + 'static,
) {
    let issued_refresh = Arc::new(Mutex::new(String::new()));
    let captured = Arc::clone(&issued_refresh);
    rig.provider.alter_next_response(move |body| {
        *captured.lock().unwrap() = body["refresh_token"].as_str().unwrap().to_owned();
        alter_response(body);
    });
    let error = finish(rig, &rig.client);
    assert_eq!(error.kind(), kind);
    assert_eq!(error.to_string(), message);
    assert_eq!(rig.journal.count("send revoke"), 1);
    let revoke = rig.provider.last_seen();
    assert_eq!(
        revoke.field("client_id"),
        Some(rig.provider.issued_clients()[0].as_str())
    );
    assert_eq!(revoke.field("token_type_hint"), Some("refresh_token"));
    assert_eq!(
        revoke.field("token"),
        Some(issued_refresh.lock().unwrap().as_str())
    );
    assert!(rig.client.accounts().unwrap().is_empty());
    assert!(rig.journal.about("write account-").is_empty());
}

#[test]
fn a_missing_id_token_revokes_the_fresh_session() {
    assert_revoked(
        &Rig::new(),
        ErrorKind::InvalidResponse,
        "the token response carries no ID token",
        |body| {
            body.remove("id_token");
        },
    );
}

#[test]
fn a_malformed_id_token_revokes_the_fresh_session() {
    assert_revoked(
        &Rig::new(),
        ErrorKind::IdentityRejected,
        "the ID token is not a signed JWT",
        |body| {
            body.insert("id_token".into(), json!("synthetic"));
        },
    );
}

#[test]
fn an_unusable_id_token_member_revokes_the_fresh_session() {
    assert_revoked(
        &Rig::new(),
        ErrorKind::InvalidResponse,
        "the token response is malformed",
        |body| {
            body.insert("id_token".into(), json!(123));
        },
    );
}

#[test]
fn an_unusable_access_token_member_revokes_the_fresh_session() {
    assert_revoked(
        &Rig::new(),
        ErrorKind::InvalidResponse,
        "the token response is malformed",
        |body| {
            body.insert("access_token".into(), json!("not a bearer token"));
        },
    );
}

#[test]
fn an_expired_id_token_revokes_the_fresh_session() {
    let rig = Rig::new();
    rig.provider.alter_next_id_token(|draft| {
        draft.claims.insert("exp".into(), json!(NOW - 60));
    });
    assert_revoked(
        &rig,
        ErrorKind::IdentityRejected,
        "the ID token has expired",
        |_| {},
    );
}

#[test]
fn an_id_token_for_another_client_revokes_the_fresh_session() {
    let rig = Rig::new();
    rig.provider.alter_next_id_token(|draft| {
        draft
            .claims
            .insert("aud".into(), json!("app_synthetic_other"));
    });
    assert_revoked(
        &rig,
        ErrorKind::IdentityRejected,
        "the ID token was issued to another client",
        |_| {},
    );
}

#[test]
fn an_id_token_with_a_bad_signature_revokes_the_fresh_session() {
    let rig = Rig::new();
    rig.provider
        .alter_next_id_token(|draft| draft.signer = Signer::Other);
    assert_revoked(
        &rig,
        ErrorKind::IdentityRejected,
        "the ID token signature is invalid",
        |_| {},
    );
}

#[test]
fn an_id_token_with_no_matching_key_revokes_the_fresh_session() {
    let rig = Rig::new();
    rig.provider.alter_next_id_token(|draft| {
        draft
            .header
            .insert("kid".into(), json!("synthetic-unknown"));
    });
    assert_revoked(
        &rig,
        ErrorKind::IdentityRejected,
        "no published key matches the ID token",
        |_| {},
    );
}

#[derive(Debug)]
enum Echo {
    ExchangeTransport,
    KeysHttp(&'static str),
    KeysTransport,
}

#[derive(Debug)]
struct EchoingTransport {
    inner: Arc<RecordingTransport>,
    echo: Echo,
}

impl Transport for EchoingTransport {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        match (request.url(), &self.echo) {
            (TOKEN_URL, Echo::ExchangeTransport) => {
                let fields = form_decode(std::str::from_utf8(request.body()).unwrap());
                let id = format!("req.{}", only(&fields, "code"));
                Err(refusal(only(&fields, "code_verifier"), &id, "grant_type"))
            }
            (JWKS_URL, Echo::KeysHttp(secret)) => {
                let id = format!("req.{secret}");
                Ok(HttpResponse::new(503, b"{}".to_vec()).with_request_id(Some(&id)))
            }
            (JWKS_URL, Echo::KeysTransport) => Err(refusal(
                ID_TOKEN,
                &format!("req.{REFRESH}"),
                &format!("meta.{ACCESS}"),
            )),
            _ => self.inner.send(request),
        }
    }
}

fn refusal(code: &str, request_id: &str, param: &str) -> Error {
    let body = json!({"error": {"code": code, "param": param}});
    Refusal::from_response(503, body.to_string().as_bytes())
        .unwrap()
        .with_request_id(Some(request_id))
        .into()
}

fn with_transport(rig: &Rig, echo: Echo) -> Client {
    Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        rig.store.clone(),
        EchoingTransport {
            inner: rig.transport.clone(),
            echo,
        },
    )
    .clock(rig.clock.clone())
    .build()
}

#[test]
fn an_exchange_transport_error_drops_the_code_and_verifier() {
    let rig = Rig::new();
    let error = finish(&rig, &with_transport(&rig, Echo::ExchangeTransport));
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert_eq!(error.http_status(), Some(503));
    assert_eq!(error.param(), Some("grant_type"));
    assert_eq!((error.provider_code(), error.request_id()), (None, None));
}

fn fail_key_fetch_and_revoke(echo: Echo) -> Error {
    let rig = Rig::new();
    rig.provider.alter_next_response(|body| {
        body.insert("access_token".into(), json!(ACCESS));
        body.insert("refresh_token".into(), json!(REFRESH));
        body.insert("id_token".into(), json!(ID_TOKEN));
    });
    rig.transport.fail("revoke", 1, Failure::Status(400, "{}"));
    let error = finish(&rig, &with_transport(&rig, echo));
    assert_eq!(rig.journal.count("send revoke"), 1);
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert_eq!(error.http_status(), Some(503));
    assert!(rig.client.accounts().unwrap().is_empty());
    error
}

#[test]
fn a_key_response_error_drops_echoed_tokens_even_if_revocation_fails() {
    for token in [ACCESS, REFRESH, ID_TOKEN] {
        let error = fail_key_fetch_and_revoke(Echo::KeysHttp(token));
        assert_eq!(error.request_id(), None, "token in request ID");
    }
    let error = fail_key_fetch_and_revoke(Echo::KeysHttp("synthetic-request-id"));
    assert_eq!(error.request_id(), Some("req.synthetic-request-id"));
}

#[test]
fn a_key_transport_error_drops_all_echoed_tokens_even_if_revocation_fails() {
    let error = fail_key_fetch_and_revoke(Echo::KeysTransport);
    assert_eq!(
        (error.provider_code(), error.request_id(), error.param()),
        (None, None, None)
    );
}
