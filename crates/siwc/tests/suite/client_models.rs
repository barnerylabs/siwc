//! Plan grants and error diagnostics on the built-in models route.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use siwc::plan::MODELS_URL;
use siwc::protocol::{HttpRequest, HttpResponse};
use siwc::{AppName, Client, Error, ErrorKind, Transport};

use crate::support::provider::User;
use crate::support::recording::{Failure, RecordingTransport};
use crate::support::rig::Rig;

#[test]
fn models_sends_nothing_for_an_identity_only_grant() {
    let rig = Rig::new();
    let account = rig.add(&User::alex().without_plan_use());
    rig.transport
        .fail("models", 1, Failure::Status(200, r#"{"models":[]}"#));
    rig.journal.clear();

    let result = rig.client.models(account.id());
    assert!(rig.journal.about("send").is_empty());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::PlanUseNotGranted);
}

#[test]
fn models_returns_a_403_without_renewing_even_if_its_code_rejects_the_token() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let body = r#"{"error":{"code":"subscription_sharing_invalid_user"}}"#;
    rig.transport.fail("models", 1, Failure::Status(403, body));
    rig.journal.clear();

    let result = rig.client.models(account.id());
    assert_eq!(rig.journal.about("send"), ["send models"]);
    assert_eq!(result.unwrap_err().kind(), ErrorKind::TokenRejected);
}

#[test]
fn models_renews_once_on_a_401_even_if_its_code_reports_a_usage_limit() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let body = r#"{"error":{"code":"subscription_sharing_usage_limit_exceeded"}}"#;
    rig.transport.fail("models", 1, Failure::Status(401, body));
    rig.journal.clear();

    let result = rig.client.models(account.id());
    assert_eq!(
        rig.journal.about("send"),
        ["send models", "send refresh", "send models"]
    );
    assert!(!result.unwrap().is_empty());

    rig.provider
        .refuse_next_api_request(401, &" ".repeat(64 * 1024 + 1));
    rig.journal.clear();
    let error = rig.client.models(account.id()).unwrap_err();
    assert_eq!(rig.journal.about("send"), ["send models"]);
    assert_eq!(error.kind(), ErrorKind::InvalidResponse);
}

#[test]
fn models_does_not_resend_when_the_renewal_drops_the_grant() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    rig.transport.fail("models", 1, Failure::Status(401, "{}"));
    rig.provider.alter_next_response(|body| {
        body.insert("scope".into(), json!("openid profile email offline_access"));
    });
    rig.journal.clear();

    let result = rig.client.models(account.id());
    assert_eq!(rig.journal.about("send"), ["send models", "send refresh"]);
    assert_eq!(result.unwrap_err().kind(), ErrorKind::PlanUseNotGranted);
}

#[derive(Debug)]
struct ModelsRefusal {
    transport: Arc<RecordingTransport>,
    renew_first: bool,
    earlier_token: Mutex<Option<String>>,
}

impl Transport for ModelsRefusal {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        if request.url() != MODELS_URL {
            return self.transport.send(request);
        }
        let bearer = request
            .headers()
            .find_map(|(name, value)| {
                (name == "authorization").then(|| value.strip_prefix("Bearer ").unwrap())
            })
            .unwrap();
        let mut earlier = self.earlier_token.lock().unwrap();
        if self.renew_first && earlier.is_none() {
            *earlier = Some(bearer.to_owned());
            return Ok(HttpResponse::new(401, Vec::new()));
        }
        let code = format!("code.{bearer}");
        let request_id = format!("req.{}", earlier.as_deref().unwrap_or(bearer));
        let body = json!({"error":{"code":code,"param":"model"}})
            .to_string()
            .into_bytes();
        Ok(HttpResponse::new(403, body).with_request_id(Some(&request_id)))
    }
}

fn models_refusal_hides_sent_tokens(renew_first: bool) {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        rig.store.clone(),
        ModelsRefusal {
            transport: rig.transport.clone(),
            renew_first,
            earlier_token: Mutex::new(None),
        },
    )
    .clock(rig.clock.clone())
    .build();
    rig.journal.clear();

    let error = client.models(account.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotPermitted);
    assert_eq!(error.http_status(), Some(403));
    assert_eq!(error.param(), Some("model"));
    assert_eq!(rig.journal.count("send refresh"), usize::from(renew_first));
    assert_eq!((error.provider_code(), error.request_id()), (None, None));
}

#[test]
fn models_drops_the_bearer_from_a_refusal() {
    models_refusal_hides_sent_tokens(false);
}

#[test]
fn models_drops_both_bearers_from_a_refusal_after_renewal() {
    models_refusal_hides_sent_tokens(true);
}

/// Answers the model list with a `429` that asks for a long wait, after a
/// `401` when `renew_first` is set.
#[derive(Debug)]
struct ModelsBusy {
    transport: Arc<RecordingTransport>,
    renew_first: bool,
    refused_once: Mutex<bool>,
}

impl Transport for ModelsBusy {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        if request.url() != MODELS_URL {
            return self.transport.send(request);
        }
        let mut refused_once = self.refused_once.lock().unwrap();
        if self.renew_first && !*refused_once {
            *refused_once = true;
            return Ok(HttpResponse::new(401, Vec::new()));
        }
        let body = br#"{"error":{"code":"subscription_sharing_usage_unavailable"}}"#;
        Ok(HttpResponse::new(429, body.to_vec()).with_retry_after(Some("90")))
    }
}

fn models_refusal_keeps_its_wait(renew_first: bool) {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        rig.store.clone(),
        ModelsBusy {
            transport: rig.transport.clone(),
            renew_first,
            refused_once: Mutex::new(false),
        },
    )
    .clock(rig.clock.clone())
    .build();

    let error = client.models(account.id()).unwrap_err();
    assert_eq!(error.http_status(), Some(429));
    assert_eq!(error.retry_after(), Some(Duration::from_secs(90)));
}

#[test]
fn models_keeps_the_wait_a_refusal_asks_for() {
    models_refusal_keeps_its_wait(false);
}

#[test]
fn models_keeps_the_wait_a_refusal_after_renewal_asks_for() {
    models_refusal_keeps_its_wait(true);
}
