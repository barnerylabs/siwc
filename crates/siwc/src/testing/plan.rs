//! Model discovery and bearer checks shared by the fake plan endpoints.

mod responses;

use serde_json::{Value, json};

use crate::protocol::{HttpRequest, HttpResponse};

use super::oauth::OAuth;

pub(super) use responses::{RESPONSES_URL, Responses};

pub(super) const MODELS_URL: &str = "https://api.openai.com/v1/models";

pub(super) struct Models {
    listed: Vec<(String, String)>,
    refuse_next: Option<(u16, Vec<u8>)>,
}

impl Models {
    pub(super) fn new() -> Self {
        Self {
            listed: vec![
                ("example-large".to_owned(), "Example Large".to_owned()),
                ("example-small".to_owned(), "Example Small".to_owned()),
            ],
            refuse_next: None,
        }
    }

    pub(super) fn set(&mut self, models: &[(&str, &str)]) {
        self.listed = models
            .iter()
            .map(|(slug, name)| ((*slug).to_owned(), (*name).to_owned()))
            .collect();
    }

    pub(super) fn refuse_next(&mut self, status: u16, body: Vec<u8>) {
        self.refuse_next = Some((status, body));
    }

    pub(super) fn answer(
        &mut self,
        oauth: &OAuth,
        request: &HttpRequest,
        now: u64,
    ) -> HttpResponse {
        if let Some((status, body)) = self.refuse_next.take() {
            return HttpResponse::new(status, body);
        }
        if let Err(refused) = require_plan(oauth, request, now) {
            return refused;
        }
        let models: Vec<Value> = self
            .listed
            .iter()
            .map(|(slug, name)| {
                json!({
                    "slug": slug,
                    "display_name": name,
                    "visibility": "list",
                })
            })
            .collect();
        HttpResponse::new(200, json!({ "models": models }).to_string().into_bytes())
    }
}

fn require_plan(oauth: &OAuth, request: &HttpRequest, now: u64) -> Result<(), HttpResponse> {
    let bearer = request
        .headers()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .and_then(|(_, value)| value.strip_prefix("Bearer "));
    match bearer.and_then(|token| oauth.plan_use(token, now)) {
        Some(true) => Ok(()),
        Some(false) => Err(api_error(403, "chatpass_v2_scope_not_authorized")),
        None => Err(api_error(401, "subscription_sharing_invalid_user")),
    }
}

fn api_error(status: u16, code: &str) -> HttpResponse {
    HttpResponse::new(
        status,
        json!({ "error": { "code": code, "message": "synthetic test error" } })
            .to_string()
            .into_bytes(),
    )
}
