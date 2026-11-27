//! ID token verification: the only way an [`Identity`] comes into being.

use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind};
use crate::secret::IdToken;
use crate::time::UnixTime;

use super::client_id::IssuedClientId;
use super::identity::Identity;
use super::jwks::{Jwks, SignatureError};
use super::{ISSUER, base64url, json};

/// Tolerated difference between this machine's clock and the provider's.
const CLOCK_SKEW_SECS: u64 = 60;

/// Longest subject, in ASCII characters (OpenID Connect Core, section 2).
const MAX_SUBJECT_LEN: usize = 255;

/// Longest display claim kept, in bytes.
pub(super) const MAX_DISPLAY_LEN: usize = 512;

/// What the token has to prove for this sign-in.
pub(crate) struct Expected<'a> {
    /// The issued client ID: the token's audience.
    pub(crate) client_id: &'a IssuedClientId,
    /// The nonce sent with the authorization request.
    pub(crate) nonce: &'a str,
    /// The account a returning sign-in asked for.
    pub(crate) subject: Option<&'a str>,
}

/// Checks signature, issuer, audience, validity period, nonce and subject.
///
/// Only RS256 is accepted, the algorithm the provider advertises. The header
/// cannot select another one, so no key can be misused under a different
/// algorithm.
pub(crate) fn verify(
    token: &str,
    keys: &Jwks,
    expected: &Expected<'_>,
    now: UnixTime,
) -> Result<Identity, Error> {
    let claims = signed_claims(token, keys, expected.client_id)?;
    check_time(&claims.0, now, Lifetime::Current)?;
    if json::string(&claims.0, "nonce") != Some(expected.nonce) {
        return Err(rejected("the ID token belongs to another sign-in attempt"));
    }
    identity(&claims.0, expected.subject)
}

/// A moved session proves its identity with the ID token from its original
/// sign-in. That proof can be expired and there is no new nonce to check.
pub(crate) fn verify_bundle_identity(
    token: &IdToken,
    keys: &Jwks,
    client_id: &IssuedClientId,
    subject: &str,
    now: UnixTime,
) -> Result<Identity, Error> {
    let claims = signed_claims(token.expose(), keys, client_id)?;
    check_time(&claims.0, now, Lifetime::Historical)?;
    identity(&claims.0, Some(subject))
}

fn signed_claims(
    token: &str,
    keys: &Jwks,
    client_id: &IssuedClientId,
) -> Result<json::Document, Error> {
    let mut segments = token.split('.');
    let (Some(header), Some(claims), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(rejected("the ID token is not a signed JWT"));
    };

    let malformed = || rejected("the ID token is malformed");
    let header_doc = decode_object(header).ok_or_else(malformed)?;
    let header_fields = &header_doc.0;
    if json::string(header_fields, "alg") != Some("RS256") {
        return Err(rejected("the ID token is not signed with RS256"));
    }
    if header_fields.contains_key("crit") {
        return Err(rejected("the ID token requires an unknown extension"));
    }
    let kid = match header_fields.get("kid") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .filter(|kid| !kid.is_empty())
                .ok_or_else(malformed)?,
        ),
    };
    let signature = base64url::decode(signature).ok_or_else(malformed)?;
    let signed = &token.as_bytes()[..header.len() + 1 + claims.len()];
    keys.verify(kid, signed, &signature).map_err(|error| {
        rejected(match error {
            SignatureError::UnknownKey => "no published key matches the ID token",
            SignatureError::Invalid => "the ID token signature is invalid",
        })
    })?;

    // Everything below reads claims the provider signed.
    let claims_doc = decode_object(claims).ok_or_else(malformed)?;
    let claims = &claims_doc.0;
    if json::string(claims, "iss") != Some(ISSUER) {
        return Err(rejected("the ID token comes from another issuer"));
    }
    if !audience_is(claims, client_id.as_str()) {
        return Err(rejected("the ID token was issued to another client"));
    }
    Ok(claims_doc)
}

enum Lifetime {
    Current,
    Historical,
}

fn check_time(claims: &json::Object, now: UnixTime, lifetime: Lifetime) -> Result<(), Error> {
    let now = now.as_secs();
    let malformed = || rejected("the ID token is malformed");
    let expires = json::seconds(claims, "exp").ok_or_else(malformed)?;
    if matches!(lifetime, Lifetime::Current) && now >= expires.saturating_add(CLOCK_SKEW_SECS) {
        return Err(rejected("the ID token has expired"));
    }
    let issued = json::seconds(claims, "iat").ok_or_else(malformed)?;
    let not_before = match claims.get("nbf") {
        None => 0,
        Some(_) => json::seconds(claims, "nbf").ok_or_else(malformed)?,
    };
    if issued.max(not_before) > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(rejected("the ID token is not valid yet"));
    }
    Ok(())
}

fn identity(claims: &json::Object, expected_subject: Option<&str>) -> Result<Identity, Error> {
    let subject = json::string(claims, "sub")
        .filter(|subject| is_subject(subject))
        .ok_or_else(|| rejected("the ID token names no subject"))?;
    if claims
        .get("sid")
        .is_some_and(|sid| sid.as_str().is_none_or(str::is_empty))
    {
        return Err(rejected("the ID token is malformed"));
    }
    if expected_subject.is_some_and(|expected| expected != subject) {
        return Err(Error::new(
            ErrorKind::AccountMismatch,
            "the browser signed in to a different account",
        ));
    }

    let display = |name| {
        json::string(claims, name)
            .filter(|text| is_display_text(text))
            .map(str::to_owned)
    };
    Ok(Identity {
        subject: subject.to_owned(),
        email: display("email"),
        email_verified: claims
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        name: display("name"),
        picture: json::string(claims, "picture")
            .filter(|text| is_picture_url(text))
            .map(str::to_owned),
    })
}

/// Whether `text` can be a subject: 1 to 255 printable ASCII characters
/// (OpenID Connect Core, section 2). Applies to ID tokens and to every
/// stored copy of a subject.
pub(super) fn is_subject(text: &str) -> bool {
    (1..=MAX_SUBJECT_LEN).contains(&text.len())
        && text.bytes().all(|byte| matches!(byte, b' '..=b'~'))
}

pub(super) fn is_display_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_DISPLAY_LEN && !crate::app::has_disallowed_chars(text)
}

pub(super) fn is_picture_url(text: &str) -> bool {
    text.len() <= MAX_DISPLAY_LEN
        && text
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty())
        && text.bytes().all(|b| b.is_ascii_graphic())
}

fn decode_object(segment: &str) -> Option<json::Document> {
    let bytes = Zeroizing::new(base64url::decode(segment)?);
    json::object(&bytes).map(json::Document)
}

/// OpenID Connect Core §3.1.3.7: the client must be the audience, a token
/// with an audience the client does not trust is rejected, and an `azp`
/// claim must name the client. This client trusts no audience but itself.
fn audience_is(claims: &json::Object, client_id: &str) -> bool {
    let is_client = |value: &Value| value.as_str() == Some(client_id);
    let sole_audience = match claims.get("aud") {
        Some(Value::Array(audiences)) => !audiences.is_empty() && audiences.iter().all(is_client),
        Some(audience) => is_client(audience),
        None => false,
    };
    sole_audience && claims.get("azp").is_none_or(is_client)
}

fn rejected(message: &'static str) -> Error {
    Error::new(ErrorKind::IdentityRejected, message)
}
