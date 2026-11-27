//! Authorization URLs and synthetic browser callbacks.

use crate::error::{Error, ErrorKind};
use crate::protocol::{AUTHORIZE_URL, form};

use super::{OAuth, PendingCode, RESOURCE, optional};
use crate::testing::FakeUser;

pub(super) const DYNAMIC_CLIENT: &str = "dynamic_agent_client";

impl OAuth {
    /// Approves `authorization_url` for `user` and returns `(redirect_uri, callback_query)`.
    pub(in crate::testing) fn authorize(
        &mut self,
        authorization_url: &str,
        mut user: FakeUser,
    ) -> Result<(String, String), Error> {
        let params = parse_authorize_url(authorization_url)?;
        let requested_client = required(&params, "client_id")?;
        let redirect_uri = required(&params, "redirect_uri")?.to_owned();
        let state_param = required(&params, "state")?.to_owned();
        let nonce = required(&params, "nonce")?.to_owned();
        let code_challenge = required(&params, "code_challenge")?.to_owned();
        if required(&params, "code_challenge_method")? != "S256"
            || required(&params, "response_type")? != "code"
            || required(&params, "resource")? != RESOURCE
        {
            return Err(invalid_auth("unsupported authorization parameter"));
        }
        // Consent re-authorization upgrades an identity-only user to plan use.
        if optional(&params, "prompt") == Some("consent") {
            user.plan_use = true;
        }

        let (client_id, first_registration) = if requested_client == DYNAMIC_CLIENT {
            let _hint = required(&params, "agent_name_hint")?;
            self.counter += 1;
            let issued = format!("client_fake_{:04}", self.counter);
            self.registered_clients.insert(issued.clone());
            (issued, true)
        } else if self.registered_clients.contains(requested_client) {
            (requested_client.to_owned(), false)
        } else {
            let query = form::encode(&[("error", "invalid_client"), ("state", &state_param)]);
            return Ok((redirect_uri, query));
        };

        self.counter += 1;
        let code = format!("code_fake_{:04}", self.counter);
        self.codes.insert(
            code.clone(),
            PendingCode {
                client_id: client_id.clone(),
                code_challenge,
                redirect_uri: redirect_uri.clone(),
                nonce,
                user,
            },
        );
        let query = if first_registration {
            form::encode(&[
                ("code", &code),
                ("state", &state_param),
                ("client_id", &client_id),
            ])
        } else {
            form::encode(&[("code", &code), ("state", &state_param)])
        };
        Ok((redirect_uri, query))
    }

    /// Builds an OAuth error callback `(redirect_uri, callback_query)` for `authorization_url`.
    pub(in crate::testing) fn fail_authorization(
        authorization_url: &str,
        error_code: &str,
    ) -> Result<(String, String), Error> {
        let params = parse_authorize_url(authorization_url)?;
        let redirect_uri = required(&params, "redirect_uri")?.to_owned();
        let state_param = required(&params, "state")?.to_owned();
        let query = form::encode(&[("error", error_code), ("state", &state_param)]);
        Ok((redirect_uri, query))
    }
}

fn parse_authorize_url(url: &str) -> Result<Vec<form::Pair>, Error> {
    let query = url
        .strip_prefix(AUTHORIZE_URL)
        .and_then(|rest| rest.strip_prefix('?'))
        .ok_or_else(|| invalid_auth("not an authorization URL"))?;
    form::parse(query).ok_or_else(|| invalid_auth("the authorization query cannot be read"))
}

fn required<'a>(params: &'a [form::Pair], name: &str) -> Result<&'a str, Error> {
    optional(params, name).ok_or_else(|| invalid_auth("missing required authorization parameter"))
}

fn invalid_auth(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}
