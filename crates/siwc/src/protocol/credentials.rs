//! The token set of one signed-in account: use, renewal and revocation.

#[cfg(fuzzing)]
mod fuzzing;
mod stored;
mod timestamp;

/// Exercises `earliest_refresh_at` timestamp parsing for cargo-fuzz harnesses.
#[cfg(fuzzing)]
pub(crate) fn fuzz_timestamp(text: &str) {
    let _parsed = timestamp::parse(text);
}

use std::fmt;

use crate::error::{Error, ErrorKind};
use crate::secret::{AccessToken, IdToken, RefreshToken};
use crate::time::UnixTime;

use super::client_id::IssuedClientId;
use super::http::{HttpRequest, HttpResponse};
use super::scope::Scopes;
use super::token_response::{TokenResponse, failure, revoke_request};
use super::{REQUESTED_SCOPE, RESOURCE, TOKEN_URL};

/// Renew this long before the access token expires, or halfway through a
/// lifetime that is shorter than two such margins.
const REFRESH_MARGIN_SECS: u64 = 60;

/// Refresh errors after which the stored tokens are useless.
const TERMINAL_REFRESH_CODES: [&str; 6] = [
    "invalid_grant",
    "invalid_refresh_token",
    "token_expired",
    "refresh_token_expired",
    "refresh_token_invalidated",
    "refresh_token_reused",
];

/// The tokens of one account, with what was granted and when they expire.
///
/// Credentials know which registration and which account they belong to:
/// the issued client ID and the verified subject are part of them, and every
/// renewal, revocation and account hint takes both from here. Tokens of one
/// account can therefore not be sent under the registration of another.
///
/// The access token is the only part an app reads. The refresh token and the
/// ID token leave only in the requests this type builds, in
/// [`to_stored`](Self::to_stored), whose bytes are as secret as the tokens,
/// and as the ID token hint of an [`Attempt`](super::Attempt) for a returning
/// account when the caller opts in with
/// [`Returning::with_hints`](super::Returning::with_hints).
///
/// Renewal rotates the refresh token, so two rules keep a session alive:
/// send one refresh at a time per account, across threads and processes, and
/// store the successor before using its access token.
///
/// ```no_run
/// # use siwc::protocol::{Credentials, HttpRequest, HttpResponse};
/// # fn send(_: HttpRequest) -> HttpResponse { todo!() }
/// # fn renew(credentials: Credentials) -> Result<Credentials, siwc::Error> {
/// let now = siwc::UnixTime::now();
/// if !credentials.needs_refresh(now) {
///     return Ok(credentials);
/// }
/// match credentials.refresh_request() {
///     Some(request) => credentials.refreshed(send(request), now),
///     None => Ok(credentials), // not renewable: sign in again once it expires
/// }
/// # }
/// ```
pub struct Credentials {
    client_id: IssuedClientId,
    subject: String,
    access: AccessToken,
    expires_at: UnixTime,
    renew_at: UnixTime,
    refresh: Option<RefreshToken>,
    id_token: Option<IdToken>,
    scopes: Scopes,
    earliest_refresh_at: Option<String>,
}

impl Credentials {
    /// Whether both credential sets came from the same verified sign-in.
    /// Refresh carries its original nonce-bound ID token forward unchanged.
    pub(crate) fn same_sign_in(&self, other: &Self) -> bool {
        matches!((&self.id_token, &other.id_token), (Some(left), Some(right)) if left.expose() == right.expose())
    }

    /// The credentials of a completed sign-in: the tokens of a code exchange
    /// whose ID token was verified for `client_id` and names `subject`.
    pub(super) fn issued(
        tokens: TokenResponse,
        id_token: IdToken,
        client_id: IssuedClientId,
        subject: &str,
        received: UnixTime,
    ) -> Self {
        let (expires_at, renew_at) = validity(received, tokens.lifetime_secs);
        Self {
            client_id,
            subject: subject.to_owned(),
            access: tokens.access,
            expires_at,
            renew_at,
            refresh: tokens.refresh,
            id_token: Some(id_token),
            // RFC 6749 §5.1: an answer without `scope` grants what was asked.
            scopes: tokens
                .scopes
                .unwrap_or_else(|| Scopes::parse(REQUESTED_SCOPE)),
            earliest_refresh_at: tokens.earliest_refresh_at,
        }
    }

    /// The registration these tokens were issued to.
    #[must_use]
    pub fn client_id(&self) -> &IssuedClientId {
        &self.client_id
    }

    /// The verified subject of the account these tokens belong to, equal to
    /// [`Identity::subject`](super::Identity::subject) of that account.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The bearer token for API requests.
    ///
    /// Check [`needs_refresh`](Self::needs_refresh) first, and
    /// [`Scopes::grants_plan_use`] before sending requests that use the plan.
    #[must_use]
    pub fn access_token(&self) -> &AccessToken {
        &self.access
    }

    /// When the access token expires. A lifetime the provider stated above a
    /// day counts as a day.
    #[must_use]
    pub fn expires_at(&self) -> UnixTime {
        self.expires_at
    }

    /// Whether the access token has expired or is due for proactive renewal.
    ///
    /// Renews a minute before [`expires_at`](Self::expires_at), or halfway
    /// through a lifetime shorter than two minutes. When the provider sent a
    /// parseable [`earliest_refresh_time`](Self::earliest_refresh_time) later
    /// than that default point, proactive renewal waits until that timestamp
    /// (unless [`expires_at`](Self::expires_at) has already arrived).
    #[must_use]
    pub fn needs_refresh(&self, now: UnixTime) -> bool {
        let effective = match self.earliest_refresh_time() {
            Some(earliest) => self.renew_at.max(earliest).min(self.expires_at),
            None => self.renew_at,
        };
        now >= effective
    }

    /// The scopes granted with these tokens.
    #[must_use]
    pub fn scopes(&self) -> &Scopes {
        &self.scopes
    }

    /// The provider's `earliest_refresh_at` value as JSON text, if it sent
    /// one.
    #[must_use]
    pub fn earliest_refresh_at(&self) -> Option<&str> {
        self.earliest_refresh_at.as_deref()
    }

    /// [`earliest_refresh_at`](Self::earliest_refresh_at) parsed as a
    /// [`UnixTime`] when the provider sent Unix seconds or an RFC 3339
    /// timestamp.
    #[must_use]
    pub fn earliest_refresh_time(&self) -> Option<UnixTime> {
        self.earliest_refresh_at
            .as_deref()
            .and_then(timestamp::parse)
    }

    /// The request that renews the session, or `None` when no refresh token
    /// was granted.
    #[must_use]
    pub fn refresh_request(&self) -> Option<HttpRequest> {
        let refresh = self.refresh.as_ref()?;
        Some(HttpRequest::post_form(
            TOKEN_URL,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", self.client_id.as_str()),
                ("refresh_token", refresh.expose()),
                ("resource", RESOURCE),
            ],
        ))
    }

    /// The successor of these credentials, read from the answer to a
    /// [`refresh_request`](Self::refresh_request).
    ///
    /// Store the result before using it. A replacement refresh token is
    /// required because the provider rotates single-use refresh tokens on
    /// every renewal. Omitted scopes keep their previous value, a missing
    /// lifetime defaults to the documented hour, and `earliest_refresh_at`
    /// only describes the new token. An ID token in the answer is not used:
    /// the one verified at sign-in stays, so no unverified identity enters
    /// the session.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::SignInRequired`]: the provider ended the session;
    ///   delete the tokens and sign in again with the same client ID.
    /// - [`ErrorKind::Temporary`]: keep the credentials and retry later.
    /// - [`ErrorKind::ClientRejected`] and [`ErrorKind::Rejected`]: keep the
    ///   credentials; repeating the request will not help.
    /// - [`ErrorKind::InvalidResponse`]: the answer cannot be used (including
    ///   when it omits the replacement refresh token), so it is unknown
    ///   whether the provider rotated the refresh token. Keep the
    ///   credentials: the API may still accept the access token until it
    ///   expires, and a later refresh may succeed or ask for a new sign-in.
    pub fn refreshed(&self, response: HttpResponse, now: UnixTime) -> Result<Self, Error> {
        if response.status() != 200 {
            let error = failure(&response, |code| {
                TERMINAL_REFRESH_CODES.contains(&code).then_some((
                    ErrorKind::SignInRequired,
                    "the session can no longer be renewed",
                ))
            });
            return Err(self.without_credential_echo(error));
        }
        let tokens = TokenResponse::read(&response)?;
        let refresh = tokens.refresh.ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidResponse,
                "the token response carries no refresh token",
            )
        })?;
        let (expires_at, renew_at) = validity(now, tokens.lifetime_secs);
        Ok(Self {
            client_id: self.client_id.clone(),
            subject: self.subject.clone(),
            access: tokens.access,
            expires_at,
            renew_at,
            refresh: Some(refresh),
            id_token: self.id_token.clone(),
            scopes: tokens.scopes.unwrap_or_else(|| self.scopes.clone()),
            earliest_refresh_at: tokens.earliest_refresh_at,
        })
    }

    /// The request that revokes the renewable session at sign-out, or `None`
    /// when there is no refresh token to revoke.
    ///
    /// Delete the local tokens whatever the outcome, and keep the issued
    /// client ID and the host ID: revocation does not remove the
    /// registration.
    #[must_use]
    pub fn revoke_request(&self) -> Option<HttpRequest> {
        revoke_request(&self.client_id, self.refresh.as_ref())
    }

    /// Reads the answer to these credentials' [`revoke_request`](Self::revoke_request).
    /// An error omits a provider code or request ID containing the refresh token.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Temporary`] when a retry can still confirm it, otherwise
    /// [`ErrorKind::ClientRejected`] or [`ErrorKind::Rejected`]. After an
    /// unconfirmed revocation, tell the user that the app may still be
    /// connected in their ChatGPT settings.
    pub fn revocation_confirmed(&self, response: &HttpResponse) -> Result<(), Error> {
        if response.status() == 200 {
            Ok(())
        } else {
            Err(self.without_credential_echo(failure(response, |_| None)))
        }
    }

    pub(crate) fn without_credential_echo(&self, error: Error) -> Error {
        error.without(|value| {
            value.contains(self.access.expose())
                || self
                    .refresh
                    .as_ref()
                    .is_some_and(|token| value.contains(token.expose()))
                || self
                    .id_token
                    .as_ref()
                    .is_some_and(|token| value.contains(token.expose()))
        })
    }

    /// The retained ID token, for the account hint of a later sign-in.
    pub(crate) fn id_token(&self) -> Option<&IdToken> {
        self.id_token.as_ref()
    }

    /// Whether a refresh token was granted, so the session can be renewed.
    #[must_use]
    pub fn has_refresh_token(&self) -> bool {
        self.refresh.is_some()
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("client_id", &self.client_id)
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .field("renewable", &self.refresh.is_some())
            .finish_non_exhaustive()
    }
}

/// When a token received at `received` expires and when to renew it.
fn validity(received: UnixTime, lifetime_secs: u64) -> (UnixTime, UnixTime) {
    // A margin of the whole lifetime would renew a short-lived token on
    // every use, and each renewal rotates the refresh token.
    let margin = REFRESH_MARGIN_SECS.min(lifetime_secs / 2);
    (
        received.plus(lifetime_secs),
        received.plus(lifetime_secs.saturating_sub(margin)),
    )
}
