//! The documented protocol as plain data and pure functions, without I/O.
//!
//! Nothing here opens a socket, reads a clock or draws random bytes on its
//! own: callers pass the time and [`OsEntropy`](crate::OsEntropy), send each
//! [`HttpRequest`] with the HTTP client they already have and hand the
//! [`HttpResponse`] back. The `testing` feature lets tests pass their own
//! entropy source. This makes the flow usable from any runtime and testable
//! offline.
//!
//! One sign-in runs through these steps:
//!
//! 1. [`Attempt::start`] builds the authorization URL for the browser.
//! 2. [`Attempt::accept`] checks the callback, or [`Attempt::accept_redirect`]
//!    the redirect address the user pasted, and yields an [`Exchange`]; a
//!    first registration also yields the [`IssuedClientId`] to store first.
//! 3. [`Exchange::request`] and [`Exchange::response`] trade the code for
//!    tokens.
//! 4. [`Unverified::verify`] checks the ID token against the provider's
//!    [`Jwks`] and returns the [`SignedIn`] result.
//!
//! Afterwards [`Credentials`] renews and revokes the session.
//!
//! Several accounts can be signed in side by side. Each one has its own
//! registration, so each has its own [`IssuedClientId`], [`Identity`] and
//! [`Credentials`]; the credentials name the registration and the account
//! they belong to, and no function here combines the parts of two accounts.

mod attempt;
pub(crate) mod base64url;
mod client_id;
mod credentials;
mod exchange;
pub(crate) mod form;
mod http;
mod id_token;
mod identity;
pub(crate) mod json;
mod jwks;
pub(crate) mod provider_error;
mod scope;
mod streaming;
mod token_response;

pub use attempt::{Accepted, Attempt, Callback, NewRegistration, Registration, Returning};
pub use client_id::IssuedClientId;
pub use credentials::Credentials;
#[cfg(fuzzing)]
pub(crate) use credentials::fuzz_timestamp;
pub use exchange::{Exchange, SignedIn, Unverified};
pub(crate) use http::is_token;
pub use http::{HttpRequest, HttpResponse, Method};
#[cfg(any(feature = "https", feature = "ureq"))]
pub(crate) use http::{UNREAD_WAIT, consider_wait};
pub(crate) use id_token::verify_bundle_identity;
pub use identity::Identity;
pub use jwks::Jwks;
pub use scope::{ScopeIter, Scopes};
pub use streaming::StreamingResponse;

/// Path of the loopback redirect URI.
///
/// A registration keeps the scheme, host and path it was created with; only
/// the port may differ between sign-ins. This value therefore never changes.
pub const CALLBACK_PATH: &str = "/auth/callback";

const ISSUER: &str = "https://auth.openai.com";
pub(crate) const AUTHORIZE_URL: &str = "https://auth.openai.com/api/accounts/authorize";
const TOKEN_URL: &str = "https://auth.openai.com/api/accounts/oauth/token";
const REVOKE_URL: &str = "https://auth.openai.com/api/accounts/oauth/revoke";
const JWKS_URL: &str = "https://auth.openai.com/.well-known/jwks.json";

/// The API the tokens are for; sent as `resource` in every request.
const RESOURCE: &str = "https://api.openai.com/v1";

/// The full set: identity, a renewable session and use of the ChatGPT plan.
const REQUESTED_SCOPE: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";

/// The scope that decides whether the plan may be used.
const PLAN_USE_SCOPE: &str = "chatgpt.tokens.use.direct";

/// Entry point for a first registration. Never a registration itself.
const DYNAMIC_CLIENT: &str = "dynamic_agent_client";
