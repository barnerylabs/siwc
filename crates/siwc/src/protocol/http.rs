//! Requests and responses as values: the seam between the protocol and
//! whatever sends bytes over the network.

use std::fmt;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::secret::{AccessToken, SecretBytes, SecretString};

use super::{form, provider_error};

/// The HTTP method of an [`HttpRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
}

impl Method {
    /// The method name as it appears on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// A request for the app's HTTP client to send exactly as given.
///
/// The URL is always one of the provider's documented HTTPS endpoints. Send
/// it without following redirects, with a deadline and a response size limit,
/// and pass the answer back as an [`HttpResponse`]. The body and header
/// values can hold tokens: do not log them.
///
/// ```
/// let request = siwc::protocol::Jwks::request();
/// assert_eq!(request.method().as_str(), "GET");
/// assert_eq!(request.url(), "https://auth.openai.com/.well-known/jwks.json");
/// ```
pub struct HttpRequest {
    method: Method,
    url: &'static str,
    headers: Vec<(&'static str, SecretString)>,
    body: Arc<SecretBytes>,
}

impl HttpRequest {
    pub(crate) fn get(url: &'static str) -> Self {
        Self {
            method: Method::Get,
            url,
            headers: vec![("accept", plain("application/json"))],
            body: Arc::new(SecretBytes::new(Vec::new())),
        }
    }

    /// A `GET` that carries `token` as `authorization: Bearer`.
    pub(crate) fn get_with_bearer(url: &'static str, token: &AccessToken) -> Self {
        let mut request = Self::get(url);
        let value = format!("Bearer {}", token.expose());
        request
            .headers
            .push(("authorization", SecretString::new(value)));
        request
    }

    /// A `POST` of a JSON document that carries `token` as
    /// `authorization: Bearer` and asks for an event stream.
    pub(crate) fn post_json_with_bearer(
        url: &'static str,
        token: &AccessToken,
        body: Arc<SecretBytes>,
    ) -> Self {
        let bearer = format!("Bearer {}", token.expose());
        Self {
            method: Method::Post,
            url,
            headers: vec![
                ("accept", plain("text/event-stream")),
                ("content-type", plain("application/json")),
                ("authorization", SecretString::new(bearer)),
            ],
            body,
        }
    }

    pub(crate) fn post_form(url: &'static str, fields: &[(&str, &str)]) -> Self {
        Self {
            method: Method::Post,
            url,
            headers: vec![
                ("accept", plain("application/json")),
                ("content-type", plain("application/x-www-form-urlencoded")),
            ],
            body: Arc::new(SecretBytes::new(form::encode(fields).into_bytes())),
        }
    }

    /// The method to use.
    #[must_use]
    pub fn method(&self) -> Method {
        self.method
    }

    /// The absolute `https` URL to send to.
    #[must_use]
    pub fn url(&self) -> &str {
        self.url
    }

    /// Header names in lowercase with their values.
    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers
            .iter()
            .map(|(name, value)| (*name, value.expose()))
    }

    /// The body to send; empty for `GET`.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.expose()
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

fn plain(value: &str) -> SecretString {
    SecretString::new(value.to_owned())
}

/// An RFC 6750 `b64token`, the only text a bearer token may hold in an
/// `Authorization` header: letters, digits and `-._~+/`, then any number
/// of `=`.
pub(crate) fn is_b64token(text: &str) -> bool {
    let body = text.trim_end_matches('=');
    !body.is_empty()
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
}

/// An RFC 9110 token: a method or a header name.
pub(crate) fn is_token(text: &[u8]) -> bool {
    !text.is_empty()
        && text
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
}

/// The provider's answer to an [`HttpRequest`]: status code, body and, if
/// the transport read one, the request ID the provider assigned.
///
/// The body is wiped when the value is dropped and never printed, and so
/// are the two header values: `Debug` says whether there is a request ID,
/// not which, since a provider decides what stands there.
///
/// ```
/// let response = siwc::protocol::HttpResponse::new(503, Vec::new());
/// assert_eq!(response.status(), 503);
/// ```
pub struct HttpResponse {
    pub(super) status: u16,
    pub(super) body: SecretBytes,
    /// Checked for its form only: a provider can send anything that looks
    /// like an identifier, so both header values are wiped when dropped.
    pub(super) request_id: Option<Zeroizing<String>>,
    pub(super) retry_after: Option<Zeroizing<String>>,
}

/// Longest `Retry-After` value kept as sent.
const MAX_RETRY_AFTER_LEN: usize = 64;

/// What stands in for a number of seconds too long to keep: more seconds
/// than any wait the crate takes.
const TOO_LONG_TO_WAIT: &str = "99999999999999999999";

/// What stands in for a value that is not a number of seconds and too
/// long to keep, or that a transport could not read as text: a wait that
/// is unknown, so the request is not sent again.
pub(crate) const UNREAD_WAIT: &str = "unreadable";

/// The value of a `Retry-After` header as a response keeps it: trimmed and
/// at most 64 bytes. A number of seconds is kept without its leading
/// zeros, which say nothing about it; one that is longer even so stays a
/// wait that is too long instead of being dropped. Any other long value
/// becomes [`UNREAD_WAIT`]. An empty value is no header.
pub(crate) fn retry_after_value(header: &str) -> Option<Zeroizing<String>> {
    let value = header.trim_ascii();
    let kept = if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        // Leading zeros change nothing about the number.
        let digits = value.trim_start_matches('0');
        match digits.len() {
            0 => "0",
            1..=MAX_RETRY_AFTER_LEN => digits,
            _ => TOO_LONG_TO_WAIT,
        }
    } else if value.is_empty() {
        return None;
    } else if value.len() <= MAX_RETRY_AFTER_LEN {
        value
    } else {
        UNREAD_WAIT
    };
    Some(Zeroizing::new(kept.to_owned()))
}

/// Retains the longest numeric wait across repeated fields. A sole
/// nonnumeric value stays available to callers that inspect the raw field.
#[cfg(any(feature = "https", feature = "ureq"))]
pub(crate) fn consider_wait(current: &mut Option<Zeroizing<String>>, header: &str) {
    let Some(value) = retry_after_value(header) else {
        return;
    };
    let seconds = crate::plan::delta_seconds(&value);
    if current
        .as_ref()
        .is_none_or(|old| seconds >= crate::plan::delta_seconds(old))
    {
        *current = Some(value);
    }
}

impl HttpResponse {
    /// Wraps a received status code and body.
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body: SecretBytes::new(body),
            request_id: None,
            retry_after: None,
        }
    }

    /// Adds the value of the response's `Retry-After` header, so a plan
    /// request refused with this response waits as long as the provider
    /// asks, or is not sent again when that is too long. The value is
    /// trimmed, and a number of seconds loses its leading zeros. An empty
    /// value counts as no header. What is then longer than 64 bytes is
    /// replaced: a number of seconds by one too long to wait, anything else
    /// by a value that is not seconds, so the request is not sent again.
    /// For repeated fields, pass the longest numeric wait in seconds. Use a
    /// nonnumeric value only when none of the fields contains a numeric wait.
    ///
    /// ```
    /// use siwc::protocol::HttpResponse;
    ///
    /// let response = HttpResponse::new(503, Vec::new()).with_retry_after(Some("12"));
    /// assert_eq!(response.retry_after(), Some("12"));
    /// // A long header that says one second.
    /// let padded = format!("{}1", "0".repeat(80));
    /// let response = HttpResponse::new(503, Vec::new()).with_retry_after(Some(&padded));
    /// assert_eq!(response.retry_after(), Some("1"));
    /// ```
    #[must_use]
    pub fn with_retry_after(mut self, header: Option<&str>) -> Self {
        self.retry_after = header.and_then(retry_after_value);
        self
    }

    /// The value of the `Retry-After` header, if the transport read one,
    /// as [`with_retry_after`](Self::with_retry_after) kept it.
    #[must_use]
    pub fn retry_after(&self) -> Option<&str> {
        self.retry_after.as_ref().map(|wait| wait.as_str())
    }

    /// Adds the value of the response's `x-request-id` header, so an error
    /// made from this response carries it ([`Error::request_id`]). A value
    /// that is not made of letters, digits, `_`, `-` and `.` is dropped.
    ///
    /// ```
    /// let response = siwc::protocol::HttpResponse::new(401, Vec::new())
    ///     .with_request_id(Some("req_0123abcd"));
    /// assert_eq!(response.request_id(), Some("req_0123abcd"));
    /// ```
    ///
    /// [`Error::request_id`]: crate::Error::request_id
    #[must_use]
    pub fn with_request_id(mut self, id: Option<&str>) -> Self {
        self.request_id = id
            .and_then(provider_error::sanitize_request_id)
            .map(Zeroizing::new);
        self
    }

    /// The HTTP status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The request ID the provider assigned, if the transport read one.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_ref().map(|id| id.as_str())
    }

    pub(crate) fn body(&self) -> &[u8] {
        self.body.expose()
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body", &self.body)
            .field("has_request_id", &self.request_id.is_some())
            .finish_non_exhaustive()
    }
}
