//! Reading token endpoint answers before the tokens belong to a verified account.

use serde_json::Value;

use crate::error::{Error, ErrorKind};
use crate::secret::{AccessToken, IdToken, RefreshToken};

use super::client_id::IssuedClientId;
use super::http::{HttpRequest, HttpResponse, is_b64token};
use super::scope::Scopes;
use super::{REVOKE_URL, json, provider_error};

/// The documented access token lifetime, used when an answer states none.
const DOCUMENTED_LIFETIME_SECS: u64 = 60 * 60;

/// Longest access token lifetime believed from an answer.
const MAX_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// Longest token and longest `earliest_refresh_at` text kept, in bytes.
pub(super) const MAX_TOKEN_LEN: usize = 16 * 1024;
pub(super) const MAX_EARLIEST_REFRESH_LEN: usize = 128;

/// The members of a successful token response, before they belong to an
/// account.
pub(super) struct TokenResponse {
    pub(super) access: AccessToken,
    pub(super) lifetime_secs: u64,
    pub(super) refresh: Option<RefreshToken>,
    pub(super) scopes: Option<Scopes>,
    pub(super) earliest_refresh_at: Option<String>,
}

impl TokenResponse {
    /// Revokes the refresh token received in a successful code exchange,
    /// even if its ID token has not yet been verified.
    pub(super) fn revoke_request(&self, client_id: &IssuedClientId) -> Option<HttpRequest> {
        revoke_request(client_id, self.refresh.as_ref())
    }

    /// Reads the answer to a code exchange, which has to carry an ID token.
    /// The token is returned on its own, for the caller to verify.
    pub(super) fn from_exchange(
        response: &HttpResponse,
        client_id: &IssuedClientId,
        revoke: impl FnOnce(HttpRequest),
    ) -> Result<(Self, IdToken), Error> {
        if response.status() != 200 {
            return Err(failure(response, |code| {
                (code == "invalid_grant").then_some((
                    ErrorKind::Rejected,
                    "the provider refused the authorization code",
                ))
            }));
        }
        let (mut document, mut refresh) = document_and_refresh(response)?;
        let id_token = take_token(&mut document.0, "id_token").and_then(|token| {
            token.map(IdToken::new).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidResponse,
                    "the token response carries no ID token",
                )
            })
        });
        id_token
            .and_then(|id_token| {
                Self::read_members(&mut document.0, &mut refresh).map(|tokens| (tokens, id_token))
            })
            .inspect_err(|_| {
                if let Some(request) = revoke_request(client_id, refresh.as_ref()) {
                    revoke(request);
                }
            })
    }

    /// Reads a successful refresh answer. A refresh keeps the original ID
    /// token, so any ID token the provider sends here is ignored.
    pub(super) fn read(response: &HttpResponse) -> Result<Self, Error> {
        let (mut document, mut refresh) = document_and_refresh(response)?;
        Self::read_members(&mut document.0, &mut refresh)
    }

    /// Reads a `200` answer of the token endpoint.
    ///
    /// The access token, a `b64token` (RFC 6750, section 2.1), is required. A
    /// `token_type` other than `Bearer`, in any letter case, is refused; an
    /// absent one counts as `Bearer`. An optional member that is absent or
    /// `null` keeps its default; one that is present but unusable makes the
    /// whole answer invalid, so nothing is guessed from a broken answer.
    /// Take the refresh token only after validation, so the code exchange
    /// can still revoke it on error.
    fn read_members(
        object: &mut json::Object,
        refresh: &mut Option<RefreshToken>,
    ) -> Result<Self, Error> {
        // An app's own transport puts the token into a header as it is.
        let access = take_token(object, "access_token")?
            .map(AccessToken::new)
            .filter(|access| is_b64token(access.expose()))
            .ok_or_else(malformed)?;
        let member = |name| object.get(name).filter(|value| !value.is_null());
        // RFC 6749 section 5.1 requires `token_type`, but the provider
        // documents the members of its refresh answer only by example, so an
        // absent one counts as Bearer; any other type is refused.
        if member("token_type").is_some_and(|kind| {
            !kind
                .as_str()
                .is_some_and(|kind| kind.eq_ignore_ascii_case("bearer"))
        }) {
            return Err(Error::new(
                ErrorKind::InvalidResponse,
                "the token response names a token type other than Bearer",
            ));
        }
        // RFC 6749 §5.1 only recommends `expires_in`; servers also send it
        // as a decimal string or with a fraction.
        let lifetime_secs = match member("expires_in") {
            None => DOCUMENTED_LIFETIME_SECS,
            Some(Value::String(text)) => text.parse().map_err(|_| malformed())?,
            Some(_) => json::seconds(object, "expires_in").ok_or_else(malformed)?,
        };
        let scopes = match member("scope") {
            None => None,
            Some(Value::String(text)) => Some(Scopes::parse(text)),
            Some(_) => return Err(malformed()),
        };
        let earliest_refresh_at = member("earliest_refresh_at")
            .map(Value::to_string)
            .filter(|text| text.len() <= MAX_EARLIEST_REFRESH_LEN);
        Ok(Self {
            access,
            lifetime_secs: lifetime_secs.min(MAX_LIFETIME_SECS),
            refresh: refresh.take(),
            scopes,
            earliest_refresh_at,
        })
    }
}

fn document_and_refresh(
    response: &HttpResponse,
) -> Result<(json::Document, Option<RefreshToken>), Error> {
    let mut document = json::Document(json::object(response.body()).ok_or_else(malformed)?);
    let refresh = take_token(&mut document.0, "refresh_token")?.map(RefreshToken::new);
    Ok((document, refresh))
}

fn take_token(object: &mut json::Object, name: &str) -> Result<Option<String>, Error> {
    json::take_text(object, name, MAX_TOKEN_LEN).map_err(|json::Unusable| malformed())
}

fn malformed() -> Error {
    Error::new(
        ErrorKind::InvalidResponse,
        "the token response is malformed",
    )
}

pub(super) fn revoke_request(
    client_id: &IssuedClientId,
    refresh: Option<&RefreshToken>,
) -> Option<HttpRequest> {
    Some(HttpRequest::post_form(
        REVOKE_URL,
        &[
            ("token", refresh?.expose()),
            ("token_type_hint", "refresh_token"),
            ("client_id", client_id.as_str()),
        ],
    ))
}

/// Turns an error response of the token or revocation endpoint into an
/// error. `terminal` names the codes that have a meaning of their own for the
/// request at hand; the rest is classified the same way everywhere.
pub(super) fn failure(
    response: &HttpResponse,
    terminal: impl Fn(&str) -> Option<(ErrorKind, &'static str)>,
) -> Error {
    let code = provider_error::code(response);
    let (kind, message) = if provider_error::is_temporary(response.status()) {
        (
            ErrorKind::Temporary,
            "the provider is temporarily unavailable",
        )
    } else {
        code.as_deref()
            .and_then(|code| match code {
                "invalid_client" => Some((
                    ErrorKind::ClientRejected,
                    "the provider no longer accepts the issued client ID",
                )),
                other => terminal(other),
            })
            .unwrap_or((ErrorKind::Rejected, "the provider refused the request"))
    };
    Error::new(kind, message)
        .with_code(code)
        .with_response(response)
}
