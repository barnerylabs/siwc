//! The code exchange and the verification that turns its answer into a
//! signed-in account.

use std::fmt;

use crate::error::Error;
use crate::secret::{AuthorizationCode, IdToken, PkceVerifier, SecretString};
use crate::time::UnixTime;

use super::client_id::IssuedClientId;
use super::credentials::Credentials;
use super::http::{HttpRequest, HttpResponse};
use super::id_token::{self, Expected};
use super::identity::Identity;
use super::jwks::Jwks;
use super::token_response::TokenResponse;
use super::{RESOURCE, TOKEN_URL};

/// An accepted authorization code, ready to be traded for tokens.
///
/// ```no_run
/// # use siwc::protocol::{Exchange, HttpRequest, HttpResponse, Jwks, SignedIn};
/// # fn send(_: HttpRequest) -> HttpResponse { todo!() }
/// # fn finish(exchange: Exchange) -> Result<SignedIn, siwc::Error> {
/// let now = siwc::UnixTime::now();
/// let revoke = |request| { let _ = send(request); };
/// let answer = send(exchange.request());
/// let unverified = exchange.response_with_revocation(answer, now, revoke)?;
/// let revocation = unverified.revoke_request();
/// unverified.keys_from_response(&send(Jwks::request()))
///     .and_then(|keys| unverified.verify(&keys, now))
///     .inspect_err(|_| {
///         if let Some(request) = revocation {
///             revoke(request);
///         }
///     })
/// # }
/// ```
#[must_use = "send `Exchange::request` and pass the answer to `Exchange::response`"]
pub struct Exchange {
    pub(super) client_id: IssuedClientId,
    pub(super) code: AuthorizationCode,
    pub(super) verifier: PkceVerifier,
    pub(super) redirect_uri: String,
    pub(super) nonce: SecretString,
    pub(super) account: Option<String>,
}

impl Exchange {
    /// The client ID the code was issued to.
    #[must_use]
    pub fn client_id(&self) -> &IssuedClientId {
        &self.client_id
    }

    /// The token request for this code.
    ///
    /// The code works once. If no answer arrives, the same request may be
    /// sent again; an answer of any kind ends the exchange.
    #[must_use]
    pub fn request(&self) -> HttpRequest {
        HttpRequest::post_form(
            TOKEN_URL,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", self.client_id.as_str()),
                ("code", self.code.expose()),
                ("code_verifier", self.verifier.expose()),
                ("redirect_uri", &self.redirect_uri),
                ("resource", RESOURCE),
            ],
        )
    }

    /// Reads the provider's answer to [`request`](Self::request).
    ///
    /// The tokens it returns are not trusted until
    /// [`Unverified::verify`] has checked the ID token.
    /// To handle revocation when the answer has a refresh token but cannot
    /// be used, use [`response_with_revocation`](Self::response_with_revocation).
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::Rejected`](crate::ErrorKind::Rejected) with the code
    ///   `invalid_grant`: the authorization code was refused; start a new
    ///   attempt with the stored client ID. Other unclassified refusals and
    ///   unexpected success statuses can also return `Rejected`.
    /// - [`ErrorKind::ClientRejected`](crate::ErrorKind::ClientRejected): the
    ///   provider no longer accepts the client ID.
    /// - [`ErrorKind::Temporary`](crate::ErrorKind::Temporary): the provider
    ///   is unavailable; start a new attempt later.
    /// - [`ErrorKind::InvalidResponse`](crate::ErrorKind::InvalidResponse):
    ///   the answer is not a token response with an ID token.
    pub fn response(self, response: HttpResponse, now: UnixTime) -> Result<Unverified, Error> {
        self.response_with_revocation(response, now, |_| {})
    }

    /// Reads the answer like [`response`](Self::response). When a successful
    /// HTTP 200 answer carries a usable refresh token but any other required
    /// or present member fails validation, passes a revocation request to
    /// `revoke` before returning the original error. Send that request on a
    /// best-effort basis.
    ///
    /// See the [`Exchange`] example for the entire sign-in.
    ///
    /// # Errors
    ///
    /// The same errors as [`response`](Self::response).
    pub fn response_with_revocation(
        self,
        response: HttpResponse,
        now: UnixTime,
        revoke: impl FnOnce(HttpRequest),
    ) -> Result<Unverified, Error> {
        let (tokens, id_token) = TokenResponse::from_exchange(&response, &self.client_id, revoke)
            .map_err(|error| self.without_echoes(error))?;
        Ok(Unverified {
            client_id: self.client_id,
            nonce: self.nonce,
            account: self.account,
            id_token,
            tokens,
            received: now,
        })
    }

    pub(crate) fn without_echoes(&self, error: Error) -> Error {
        error.without(|text| {
            text.contains(self.code.expose()) || text.contains(self.verifier.expose())
        })
    }
}

impl fmt::Debug for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchange")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Tokens from the code exchange whose ID token is still unchecked.
///
/// Its tokens are usable only through [`verify`](Self::verify), apart
/// from a [revocation request](Self::revoke_request) that abandons the session.
#[must_use = "the tokens are unusable until the ID token is verified"]
pub struct Unverified {
    client_id: IssuedClientId,
    nonce: SecretString,
    account: Option<String>,
    id_token: IdToken,
    tokens: TokenResponse,
    received: UnixTime,
}

impl Unverified {
    /// Reads the signing keys for this exchange and removes diagnostics that
    /// echo any of its new tokens. Use this to parse the response to
    /// [`Jwks::request`] during sign-in.
    ///
    /// See the [`Exchange`] example for verification and revocation.
    ///
    /// # Errors
    ///
    /// The same kinds as [`Jwks::from_response`].
    pub fn keys_from_response(&self, response: &HttpResponse) -> Result<Jwks, Error> {
        Jwks::from_response(response).map_err(|error| self.without_echoes(error))
    }

    /// Verifies the ID token against the provider's keys: RS256 signature,
    /// issuer, the issued client ID as audience, validity at `now`, this
    /// attempt's nonce and a non-empty subject.
    ///
    /// Prepare a [`revoke_request`](Self::revoke_request) before calling this
    /// method to revoke the fresh session on failure.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::IdentityRejected`](crate::ErrorKind::IdentityRejected):
    ///   a check failed; the tokens are dropped.
    /// - [`ErrorKind::AccountMismatch`](crate::ErrorKind::AccountMismatch):
    ///   the token is valid but for another account than the one the
    ///   [`Returning`](super::Returning) sign-in named; the stored
    ///   credentials of that account stay untouched.
    pub fn verify(self, keys: &Jwks, now: UnixTime) -> Result<SignedIn, Error> {
        self.verify_with(keys, now, |_| {})
    }

    /// Lets the client revoke the newly issued session if verification fails.
    pub(crate) fn verify_with(
        self,
        keys: &Jwks,
        now: UnixTime,
        revoke: impl FnOnce(HttpRequest),
    ) -> Result<SignedIn, Error> {
        let expected = Expected {
            client_id: &self.client_id,
            nonce: self.nonce.expose(),
            subject: self.account.as_deref(),
        };
        let identity = id_token::verify(self.id_token.expose(), keys, &expected, now)
            .map_err(|error| self.reject(error, revoke))?;
        let credentials = Credentials::issued(
            self.tokens,
            self.id_token,
            self.client_id,
            identity.subject(),
            self.received,
        );
        Ok(SignedIn {
            identity,
            credentials,
        })
    }

    /// Prepares a request to the provider's revocation endpoint, or returns
    /// `None` if the exchange issued no refresh token. As in the [`Exchange`]
    /// example, prepare it before [`verify`](Self::verify) consumes this value,
    /// and send it only if obtaining keys or verifying the identity fails.
    #[must_use]
    pub fn revoke_request(&self) -> Option<HttpRequest> {
        self.tokens.revoke_request(&self.client_id)
    }

    /// Report the original failure with no echoes of the fresh tokens, and
    /// let the client abandon the session while it still has the refresh token.
    pub(crate) fn reject(&self, error: Error, revoke: impl FnOnce(HttpRequest)) -> Error {
        let error = self.without_echoes(error);
        if let Some(request) = self.revoke_request() {
            revoke(request);
        }
        error
    }

    fn without_echoes(&self, error: Error) -> Error {
        error.without(|text| {
            text.contains(self.tokens.access.expose())
                || self
                    .tokens
                    .refresh
                    .as_ref()
                    .is_some_and(|token| text.contains(token.expose()))
                || text.contains(self.id_token.expose())
        })
    }
}

impl fmt::Debug for Unverified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unverified")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// A completed sign-in: a verified identity with its credentials.
///
/// Store both for the account, keyed by client ID and subject; the
/// credentials carry the two themselves. Check
/// [`Scopes::grants_plan_use`](super::Scopes::grants_plan_use) before
/// reporting that the ChatGPT plan is in use.
///
/// ```
/// # fn report(signed_in: &siwc::protocol::SignedIn) -> &'static str {
/// if signed_in.credentials().scopes().grants_plan_use() {
///     "Using ChatGPT plan"
/// } else {
///     "Signed in. ChatGPT plan use is not enabled."
/// }
/// # }
/// ```
#[derive(Debug)]
#[must_use = "store the verified `SignedIn` identity and credentials"]
pub struct SignedIn {
    identity: Identity,
    credentials: Credentials,
}

impl SignedIn {
    /// The registration the account signed in with.
    #[must_use]
    pub fn client_id(&self) -> &IssuedClientId {
        self.credentials.client_id()
    }

    /// The verified identity.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The tokens and granted scopes.
    #[must_use]
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// Splits the result into its parts for storing.
    #[must_use]
    pub fn into_parts(self) -> (Identity, Credentials) {
        (self.identity, self.credentials)
    }
}
