//! Synthetic registrations and their authorization, token and revocation exchanges.

mod authorize;

use std::collections::{HashMap, HashSet};

use ring::digest::{SHA256, digest};
use serde_json::{Value, json};

use crate::protocol::{HttpResponse, base64url, form};

use super::key::Signer;
use super::user::FakeUser;

const ISSUER: &str = "https://auth.openai.com";
pub(super) const TOKEN_URL: &str = "https://auth.openai.com/api/accounts/oauth/token";
pub(super) const REVOKE_URL: &str = "https://auth.openai.com/api/accounts/oauth/revoke";
pub(super) const JWKS_URL: &str = "https://auth.openai.com/.well-known/jwks.json";
const RESOURCE: &str = "https://api.openai.com/v1";

const FULL_SCOPE: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const IDENTITY_RENEWABLE_SCOPE: &str = "openid profile email offline_access";
const PLAN_NONRENEWABLE_SCOPE: &str =
    "openid profile email resource.invoke chatgpt.tokens.use.direct";
const IDENTITY_NONRENEWABLE_SCOPE: &str = "openid profile email";

const ACCESS_LIFETIME_SECS: u64 = 3600;

struct PendingCode {
    client_id: String,
    code_challenge: String,
    redirect_uri: String,
    nonce: String,
    user: FakeUser,
}

#[derive(Clone)]
struct RefreshSession {
    client_id: String,
    user: FakeUser,
}

#[derive(Clone)]
struct AccessRecord {
    expires_at: u64,
    plan_use: bool,
}

pub(super) struct OAuth {
    signer: Signer,
    counter: u64,
    registered_clients: HashSet<String>,
    rejected_clients: HashSet<String>,
    codes: HashMap<String, PendingCode>,
    /// `Some(session)` while active; `None` once rotated or revoked.
    refresh_tokens: HashMap<String, Option<RefreshSession>>,
    access_tokens: HashMap<String, AccessRecord>,
}

impl OAuth {
    pub(super) fn new(instance: u64) -> Self {
        Self {
            signer: Signer::new(instance),
            counter: 0,
            registered_clients: HashSet::new(),
            rejected_clients: HashSet::new(),
            codes: HashMap::new(),
            refresh_tokens: HashMap::new(),
            access_tokens: HashMap::new(),
        }
    }

    pub(super) fn jwks(&self) -> HttpResponse {
        HttpResponse::new(200, self.signer.jwks_json())
    }

    /// Whether an active bearer grants plan use; `None` for an unusable bearer.
    pub(super) fn plan_use(&self, bearer: &str, now: u64) -> Option<bool> {
        self.access_tokens
            .get(bearer)
            .filter(|record| now < record.expires_at)
            .map(|record| record.plan_use)
    }

    pub(super) fn revoke_refresh_tokens(&mut self) {
        for slot in self.refresh_tokens.values_mut() {
            *slot = None;
        }
    }

    pub(super) fn reject_registrations(&mut self) {
        let all: Vec<String> = self.registered_clients.iter().cloned().collect();
        self.rejected_clients.extend(all);
        for slot in self.refresh_tokens.values_mut() {
            *slot = None;
        }
        self.access_tokens.clear();
    }

    pub(super) fn token(&mut self, body: &[u8], now: u64) -> HttpResponse {
        let Ok(body_str) = std::str::from_utf8(body) else {
            return oauth_error(400, "invalid_request");
        };
        let Some(params) = form::parse(body_str) else {
            return oauth_error(400, "invalid_request");
        };
        let Some(client_id) = optional(&params, "client_id") else {
            return oauth_error(400, "invalid_request");
        };
        if self.rejected_clients.contains(client_id) || !self.registered_clients.contains(client_id)
        {
            return oauth_error(401, "invalid_client");
        }
        if optional(&params, "resource") != Some(RESOURCE) {
            return oauth_error(400, "invalid_target");
        }
        match optional(&params, "grant_type") {
            Some("authorization_code") => self.exchange_code(&params, client_id, now),
            Some("refresh_token") => self.refresh_token(&params, client_id, now),
            _ => oauth_error(400, "unsupported_grant_type"),
        }
    }

    fn exchange_code(&mut self, params: &[form::Pair], client_id: &str, now: u64) -> HttpResponse {
        let (Some(code), Some(verifier), Some(redirect_uri)) = (
            optional(params, "code"),
            optional(params, "code_verifier"),
            optional(params, "redirect_uri"),
        ) else {
            return oauth_error(400, "invalid_request");
        };
        let Some(pending) = self.codes.remove(code) else {
            return oauth_error(400, "invalid_grant");
        };
        let challenge = base64url::encode(digest(&SHA256, verifier.as_bytes()).as_ref());
        if pending.client_id != client_id
            || pending.redirect_uri != redirect_uri
            || pending.code_challenge != challenge
        {
            return oauth_error(400, "invalid_grant");
        }

        let mut claims = serde_json::Map::new();
        claims.insert("iss".to_owned(), ISSUER.into());
        claims.insert("sub".to_owned(), pending.user.subject.clone().into());
        claims.insert("aud".to_owned(), client_id.into());
        claims.insert("iat".to_owned(), now.into());
        claims.insert(
            "exp".to_owned(),
            now.saturating_add(ACCESS_LIFETIME_SECS).into(),
        );
        claims.insert("nonce".to_owned(), pending.nonce.into());
        if let Some(email) = &pending.user.email {
            claims.insert("email".to_owned(), email.clone().into());
            claims.insert(
                "email_verified".to_owned(),
                pending.user.email_verified.into(),
            );
        }
        if let Some(name) = &pending.user.name {
            claims.insert("name".to_owned(), name.clone().into());
        }
        if let Some(picture) = &pending.user.picture {
            claims.insert("picture".to_owned(), picture.clone().into());
        }
        let Ok(id_token) = self.signer.sign_jwt(&Value::Object(claims)) else {
            return oauth_error(500, "server_error");
        };
        self.issue_tokens(client_id, &pending.user, Some(id_token), now)
    }

    fn refresh_token(&mut self, params: &[form::Pair], client_id: &str, now: u64) -> HttpResponse {
        let Some(refresh_token) = optional(params, "refresh_token") else {
            return oauth_error(400, "invalid_request");
        };
        let Some(slot) = self.refresh_tokens.get_mut(refresh_token) else {
            return oauth_error(400, "invalid_grant");
        };
        // Another registration's call is refused without spending the token.
        match slot.take_if(|session| session.client_id == client_id) {
            Some(session) => self.issue_tokens(client_id, &session.user, None, now),
            None if slot.is_some() => oauth_error(400, "invalid_grant"),
            None => oauth_error(400, "refresh_token_reused"),
        }
    }

    fn issue_tokens(
        &mut self,
        client_id: &str,
        user: &FakeUser,
        id_token: Option<String>,
        now: u64,
    ) -> HttpResponse {
        self.counter += 1;
        let access = format!("access_fake_{:04}", self.counter);
        self.access_tokens.insert(
            access.clone(),
            AccessRecord {
                expires_at: now.saturating_add(ACCESS_LIFETIME_SECS),
                plan_use: user.plan_use,
            },
        );
        let scope = match (user.plan_use, user.renewable) {
            (true, true) => FULL_SCOPE,
            (false, true) => IDENTITY_RENEWABLE_SCOPE,
            (true, false) => PLAN_NONRENEWABLE_SCOPE,
            (false, false) => IDENTITY_NONRENEWABLE_SCOPE,
        };
        let mut response = serde_json::Map::new();
        response.insert("access_token".to_owned(), access.into());
        response.insert("token_type".to_owned(), "Bearer".into());
        response.insert("expires_in".to_owned(), ACCESS_LIFETIME_SECS.into());
        response.insert("scope".to_owned(), scope.into());
        if user.renewable {
            self.counter += 1;
            let refresh = format!("refresh_fake_{:04}", self.counter);
            self.refresh_tokens.insert(
                refresh.clone(),
                Some(RefreshSession {
                    client_id: client_id.to_owned(),
                    user: user.clone(),
                }),
            );
            response.insert("refresh_token".to_owned(), refresh.into());
        }
        if let Some(id_token) = id_token {
            response.insert("id_token".to_owned(), id_token.into());
        }
        HttpResponse::new(200, Value::Object(response).to_string().into_bytes())
    }

    pub(super) fn revoke(&mut self, body: &[u8]) -> HttpResponse {
        let Ok(body_str) = std::str::from_utf8(body) else {
            return oauth_error(400, "invalid_request");
        };
        let Some(params) = form::parse(body_str) else {
            return oauth_error(400, "invalid_request");
        };
        let Some(client_id) = optional(&params, "client_id") else {
            return oauth_error(400, "invalid_request");
        };
        if self.rejected_clients.contains(client_id) || !self.registered_clients.contains(client_id)
        {
            return oauth_error(401, "invalid_client");
        }
        if let Some(token) = optional(&params, "token")
            && let Some(slot) = self.refresh_tokens.get_mut(token)
        {
            // RFC 7009 section 2.1: a token issued to another client is
            // refused and stays usable.
            if slot
                .as_ref()
                .is_some_and(|session| session.client_id != client_id)
            {
                return oauth_error(400, "invalid_grant");
            }
            *slot = None;
        }
        HttpResponse::new(200, Vec::new())
    }
}

fn optional<'a>(params: &'a [form::Pair], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(key, _)| key.as_str() == name)
        .map(|(_, value)| value.as_str())
}

pub(super) fn oauth_error(status: u16, code: &str) -> HttpResponse {
    HttpResponse::new(status, json!({ "error": code }).to_string().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::authorize::DYNAMIC_CLIENT;
    use super::*;
    use crate::protocol::{AUTHORIZE_URL, HttpRequest};
    use crate::testing::provider::ProviderCore;
    use crate::time::SystemClock;

    /// Signs a synthetic user in under a new registration and returns its
    /// client ID and refresh token.
    fn register(core: &ProviderCore) -> (String, String) {
        let verifier = "synthetic-code-verifier";
        let challenge = base64url::encode(digest(&SHA256, verifier.as_bytes()).as_ref());
        let redirect_uri = "http://127.0.0.1:1455/auth/callback";
        let query = form::encode(&[
            ("client_id", DYNAMIC_CLIENT),
            ("agent_name_hint", "Synthetic App"),
            ("redirect_uri", redirect_uri),
            ("state", "synthetic-state"),
            ("nonce", "synthetic-nonce"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("response_type", "code"),
            ("resource", RESOURCE),
        ]);
        let user = FakeUser::new("owner@example.invalid");
        let (_, callback) = core
            .authorize(&format!("{AUTHORIZE_URL}?{query}"), user)
            .unwrap();
        let callback = form::parse(&callback).unwrap();
        let client_id = optional(&callback, "client_id").unwrap();
        let exchanged = core
            .handle(&HttpRequest::post_form(
                TOKEN_URL,
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", client_id),
                    ("code", optional(&callback, "code").unwrap()),
                    ("code_verifier", verifier),
                    ("redirect_uri", redirect_uri),
                    ("resource", RESOURCE),
                ],
            ))
            .unwrap();
        let body: Value = serde_json::from_slice(exchanged.body()).unwrap();
        let refresh = body["refresh_token"].as_str().unwrap().to_owned();
        (client_id.to_owned(), refresh)
    }

    fn refresh(core: &ProviderCore, client_id: &str, token: &str) -> u16 {
        let request = HttpRequest::post_form(
            TOKEN_URL,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", token),
                ("resource", RESOURCE),
            ],
        );
        core.handle(&request).unwrap().status()
    }

    #[test]
    fn a_refresh_under_another_registration_leaves_the_session_usable() {
        let core = ProviderCore::new(0, Box::new(SystemClock));
        let (owner, token) = register(&core);
        let (other, _) = register(&core);

        assert_eq!(refresh(&core, &other, &token), 400);
        assert_eq!(refresh(&core, &owner, &token), 200);
    }

    #[test]
    fn a_revocation_under_another_registration_leaves_the_session_usable() {
        let core = ProviderCore::new(0, Box::new(SystemClock));
        let (owner, token) = register(&core);
        let (other, _) = register(&core);

        let revoke =
            HttpRequest::post_form(REVOKE_URL, &[("client_id", &other), ("token", &token)]);
        assert_eq!(core.handle(&revoke).unwrap().status(), 400);
        assert_eq!(refresh(&core, &owner, &token), 200);
    }
}
