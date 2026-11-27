//! What a refusal by the API means for a request that used the plan.

use std::fmt;
use std::time::Duration;

use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{Answer, DiagnosticText, Error, ErrorKind};
use crate::protocol::{json, provider_error};

use super::event;

/// Largest error body or event frame that is read.
pub(super) const MAX_BODY_LEN: usize = 64 * 1024;

/// Longest error code or parameter name that is kept.
const MAX_NAME_LEN: usize = 128;

/// Why the API refused a request that used the plan.
///
/// It keeps the reason, the HTTP status, the provider's error code, the
/// request member the provider named and, if the app passes it on, the
/// request ID, each reduced to a short identifier. Messages and `detail`
/// texts are never read.
///
/// ```
/// use siwc::ErrorKind;
/// use siwc::plan::{Reason, Refusal};
///
/// let body = br#"{"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"..."}}"#;
/// let refusal = Refusal::from_response(429, body).unwrap();
/// assert_eq!(refusal.reason(), Reason::UsageLimit);
///
/// // The value of the answer's `x-request-id` header, if there was one.
/// let error = siwc::Error::from(refusal.with_request_id(Some("req_0123abcd")));
/// assert_eq!(error.kind(), ErrorKind::UsageLimit);
/// assert_eq!(
///     error.provider_code(),
///     Some("subscription_sharing_usage_limit_exceeded")
/// );
/// assert_eq!(error.http_status(), Some(429));
/// assert_eq!(error.request_id(), Some("req_0123abcd"));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Refusal {
    reason: Reason,
    status: Option<u16>,
    code: Option<DiagnosticText>,
    param: Option<DiagnosticText>,
    request_id: Option<Box<str>>,
    retry_after: Option<Duration>,
    /// A `Retry-After` was given but not in whole seconds, such as a date.
    wait_unread: bool,
    /// The body was larger than what is read: what it says is unknown.
    body_too_large: bool,
}

/// The reason behind a [`Refusal`], one per action an app takes.
///
/// New reasons may be added; match with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reason {
    /// A usage limit for plan requests is reached; see
    /// [`ErrorKind::UsageLimit`].
    UsageLimit,
    /// The user, workspace or a policy does not allow plan use; see
    /// [`ErrorKind::NotPermitted`].
    NotPermitted,
    /// The sign-in does not cover plan use; see
    /// [`ErrorKind::PlanUseNotGranted`].
    PlanUseNotGranted,
    /// The access token was not accepted; see [`ErrorKind::TokenRejected`].
    TokenRejected,
    /// Plan use is unavailable for now; see [`ErrorKind::Temporary`].
    Unavailable,
    /// The request uses a feature, model or option this route does not
    /// support; [`Refusal::param`] names it. Change the request.
    Unsupported,
    /// The method or endpoint is not available for plan use.
    RouteNotSupported,
    /// Not classified; repeating the request will not help.
    Other,
}

impl Refusal {
    /// Reads the status and body of an API answer. `None` for a `2xx`
    /// status.
    ///
    /// The code comes from `{"error":{"code":…,"param":…}}` or a top-level
    /// `{"code":…}`. A known code usually decides the reason. An unavailable
    /// code on a status that rules out another attempt, such as `403` or a
    /// redirect, is kept for diagnosis but the status decides the reason.
    /// The status also decides when there is no known code.
    ///
    /// At most 64 KiB of body are read. A larger one leaves a refusal with
    /// [`Reason::Other`] and no code, whatever the status: the part that
    /// was not read may be what says why. Its error is
    /// [`ErrorKind::InvalidResponse`], and [`Client::call`](crate::Client::call)
    /// never sends the request again for it.
    ///
    /// ```
    /// use siwc::plan::{Reason, Refusal};
    ///
    /// let body = vec![b' '; 64 * 1024 + 1];
    /// let refusal = Refusal::from_response(429, &body).unwrap();
    /// assert_eq!(refusal.reason(), Reason::Other);
    /// assert_eq!(siwc::Error::from(refusal).kind(), siwc::ErrorKind::InvalidResponse);
    /// ```
    #[must_use]
    pub fn from_response(status: u16, body: &[u8]) -> Option<Self> {
        if (200..=299).contains(&status) {
            return None;
        }
        if body.len() > MAX_BODY_LEN || !(100..=599).contains(&status) {
            return Some(Self {
                reason: Reason::Other,
                status: Some(status),
                code: None,
                param: None,
                request_id: None,
                retry_after: None,
                wait_unread: false,
                body_too_large: body.len() > MAX_BODY_LEN,
            });
        }
        let (code, param) = code_and_param(body);
        let reason = code
            .as_ref()
            .and_then(|code| by_code(code))
            .filter(|reason| *reason != Reason::Unavailable || matches!(status, 429 | 500..=599))
            .unwrap_or_else(|| by_status(status));
        Some(Self {
            reason,
            status: Some(status),
            code,
            param,
            request_id: None,
            retry_after: None,
            wait_unread: false,
            body_too_large: false,
        })
    }

    /// Classifies a failure event from a streamed Responses answer: either
    /// the JSON object itself or an SSE frame (`data:` lines, with optional
    /// `event:`, `id:`, `retry:` or comment lines) of at most 64 KiB.
    ///
    /// Recognises `{"type":"response.failed","response":{"error":{...}}}`,
    /// `{"type":"error",...}` (with `code` and `param` either inside `error`
    /// or on the event object itself) and a bare `{"error":{...}}` object.
    /// Returns `None` for normal stream progress (`response.created`,
    /// `response.output_text.delta`, `response.completed`,
    /// `response.incomplete`, `data: [DONE]` and comments), so an app can
    /// pass every SSE frame through this check on the way to its stream
    /// consumer while still verifying that `response.completed` arrived.
    ///
    /// ```
    /// use siwc::plan::{Reason, Refusal};
    ///
    /// let frame = br#"event: response.failed
    /// data: {"type":"response.failed","response":{"error":{"code":"subscription_sharing_usage_limit_exceeded"}}}"#;
    /// let refusal = Refusal::from_event(frame).unwrap();
    /// assert_eq!(refusal.reason(), Reason::UsageLimit);
    /// assert!(Refusal::from_event(b"data: [DONE]\n\n").is_none());
    /// ```
    #[must_use]
    pub fn from_event(event: &[u8]) -> Option<Self> {
        event::parse(event).map(Self::from_event_failure)
    }

    pub(super) fn from_event_object(
        object: &json::Object,
        event_name: Option<&str>,
    ) -> Option<Self> {
        event::classify_object(object, event_name).map(Self::from_event_failure)
    }

    fn from_event_failure(parsed: event::EventFailure) -> Self {
        let reason = parsed
            .code
            .as_ref()
            .and_then(|code| by_code(code))
            .unwrap_or(Reason::Other);
        Self {
            reason,
            status: None,
            code: parsed.code,
            param: parsed.param,
            request_id: None,
            retry_after: None,
            wait_unread: false,
            body_too_large: false,
        }
    }

    /// Classifies an error code that arrived inside a stream event, such as
    /// the `code` of a `response.failed` event.
    ///
    /// ```
    /// use siwc::plan::{Reason, Refusal};
    ///
    /// let refusal = Refusal::from_code("subscription_sharing_usage_unavailable");
    /// assert_eq!(refusal.reason(), Reason::Unavailable);
    /// ```
    #[must_use]
    pub fn from_code(code: &str) -> Self {
        let code = sanitize_refusal_code(code);
        Self {
            reason: code
                .as_ref()
                .and_then(|code| by_code(code))
                .unwrap_or(Reason::Other),
            status: None,
            code,
            param: None,
            request_id: None,
            retry_after: None,
            wait_unread: false,
            body_too_large: false,
        }
    }

    /// Whether the body this refusal was read from was larger than what
    /// is read, so that nothing is known of what it said.
    pub(crate) fn body_was_too_large(&self) -> bool {
        self.body_too_large
    }

    /// Adds the request ID of the refused request: the value of the
    /// answer's `x-request-id` header. OpenAI asks apps to keep it, notably
    /// for `subscription_sharing_invalid_user`. A value that is not made of
    /// letters, digits, `_`, `-` and `.` is dropped.
    #[must_use]
    pub fn with_request_id(mut self, id: Option<&str>) -> Self {
        self.request_id = id
            .and_then(provider_error::sanitize_request_id)
            .map(String::into_boxed_str);
        self
    }

    /// Adds the wait the answer's `Retry-After` header asks for. An empty
    /// header counts as none. Only whole seconds are read; a date or any
    /// other text is left out of
    /// [`retry_after`](Self::retry_after), and
    /// [`Client::call`](crate::Client::call) then does not send the request
    /// again, since the wait it asks for is unknown.
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use siwc::plan::Refusal;
    ///
    /// let refusal = Refusal::from_response(503, b"{}").unwrap();
    /// let asked = refusal.clone().with_retry_after(Some("12"));
    /// assert_eq!(asked.retry_after(), Some(Duration::from_secs(12)));
    /// let dated = refusal.with_retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT"));
    /// assert_eq!(dated.retry_after(), None);
    /// ```
    #[must_use]
    pub fn with_retry_after(mut self, header: Option<&str>) -> Self {
        // An empty header asks for nothing.
        let header = header
            .map(str::trim_ascii)
            .filter(|value| !value.is_empty());
        self.retry_after = header.and_then(delta_seconds).map(Duration::from_secs);
        self.wait_unread = header.is_some() && self.retry_after.is_none();
        self
    }

    /// The wait `call` weighs before sending again: an unread one counts as
    /// longer than any it takes.
    pub(crate) fn wait_asked(&self) -> Option<Duration> {
        self.retry_after
            .or(self.wait_unread.then_some(Duration::MAX))
    }

    /// The wait the API asked for before the request is sent again, from
    /// [`with_retry_after`](Self::with_retry_after).
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// Why the request was refused.
    #[must_use]
    pub fn reason(&self) -> Reason {
        self.reason
    }

    /// The provider's error code, kept only if it consists of letters,
    /// digits, `_`, `-` and `.`: the same kind of value as
    /// [`Error::provider_code`](crate::Error::provider_code).
    #[must_use]
    pub fn provider_code(&self) -> Option<&str> {
        self.code.as_ref().map(AsRef::as_ref)
    }

    /// Whether the provider's own error code says that it cannot serve plan
    /// use for now, as opposed to a status alone saying so.
    pub(crate) fn unavailable_by_code(&self) -> bool {
        self.provider_code().and_then(by_code) == Some(Reason::Unavailable)
    }

    /// The request member the provider named, such as `tools[0].type`, kept
    /// only if it consists of letters, digits, `_`, `-`, `.`, `[` and `]`.
    #[must_use]
    pub fn param(&self) -> Option<&str> {
        self.param.as_ref().map(AsRef::as_ref)
    }

    /// The HTTP status of the answer; `None` for a refusal made from a
    /// stream event's code.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    /// The request ID passed to [`with_request_id`](Self::with_request_id).
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
}

/// Shows what the crate itself knows: the reason, the status, a code only
/// when it is a documented one, and whether a parameter, a request ID
/// and a retry delay are there. Other provider values can be read through
/// the accessors.
impl fmt::Debug for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.provider_code().map(|code| {
            if is_documented_code(code) {
                code
            } else {
                "other"
            }
        });
        f.debug_struct("Refusal")
            .field("reason", &self.reason)
            .field("status", &self.status)
            .field("provider_code", &code)
            .field("has_param", &self.param.is_some())
            .field("has_request_id", &self.request_id.is_some())
            .field("has_retry_after", &self.retry_after.is_some())
            .field("body_too_large", &self.body_too_large)
            .finish()
    }
}

/// Whether `code` is one of the codes the provider documents for plan use.
pub(crate) fn is_documented_code(code: &str) -> bool {
    by_code(code).is_some()
}

impl From<Refusal> for Error {
    fn from(refusal: Refusal) -> Self {
        if refusal
            .status
            .is_some_and(|status| !(100..=599).contains(&status))
        {
            return Self::invalid_status();
        }
        if refusal.body_too_large {
            return Self::new(
                ErrorKind::InvalidResponse,
                "the API's refusal of a plan request is larger than 64 KiB",
            )
            .with_answer(Answer {
                status: refusal.status,
                request_id: refusal.request_id,
                retry_after: refusal.retry_after,
                ..Answer::default()
            });
        }
        let (kind, message) = match refusal.reason {
            Reason::UsageLimit => (
                ErrorKind::UsageLimit,
                "the usage limit for plan requests is reached",
            ),
            Reason::NotPermitted => (
                ErrorKind::NotPermitted,
                "plan use is not permitted for this account",
            ),
            Reason::PlanUseNotGranted => (
                ErrorKind::PlanUseNotGranted,
                "the sign-in does not grant plan use",
            ),
            Reason::TokenRejected => (
                ErrorKind::TokenRejected,
                "the access token was not accepted",
            ),
            Reason::Unavailable => (ErrorKind::Temporary, "plan use is unavailable for now"),
            Reason::Unsupported => (
                ErrorKind::Rejected,
                "the request uses a feature the plan route does not support",
            ),
            Reason::RouteNotSupported => (
                ErrorKind::Rejected,
                "the method or endpoint is not available for plan use",
            ),
            Reason::Other => (ErrorKind::Rejected, "the API refused the request"),
        };
        Self::new(kind, message)
            .with_owned_code(refusal.code)
            .with_answer(Answer {
                status: refusal.status,
                request_id: refusal.request_id,
                param: refusal.param,
                retry_after: refusal.retry_after,
            })
    }
}

/// The documented codes and what each means.
fn by_code(code: &str) -> Option<Reason> {
    Some(match code {
        "subscription_sharing_usage_limit_exceeded" => Reason::UsageLimit,
        "subscription_sharing_user_not_eligible" => Reason::NotPermitted,
        "chatpass_v2_scope_not_authorized" | "chatpass_v2_invalid_authorization_context" => {
            Reason::PlanUseNotGranted
        }
        "subscription_sharing_invalid_user" => Reason::TokenRejected,
        "subscription_sharing_usage_unavailable" | "subscription_sharing_user_unavailable" => {
            Reason::Unavailable
        }
        "subscription_sharing_unsupported_capability" => Reason::Unsupported,
        "subscription_sharing_route_not_supported" => Reason::RouteNotSupported,
        _ => return None,
    })
}

/// The `delta-seconds` form of `Retry-After`: digits only, as many seconds
/// as fit; anything else, such as an HTTP date, is `None`.
pub(crate) fn delta_seconds(header: &str) -> Option<u64> {
    let digits = header.trim_ascii();
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    // More seconds than fit are still seconds: longer than any wait.
    Some(digits.parse().unwrap_or(u64::MAX))
}

/// The reason a status gives on its own, without a known code.
fn by_status(status: u16) -> Reason {
    match status {
        401 => Reason::TokenRejected,
        403 => Reason::NotPermitted,
        429 | 500..=599 => Reason::Unavailable,
        _ => Reason::Other,
    }
}

/// Code and parameter of an error body, each sanitised. A `detail` text is
/// not a code, and a body that cannot be read yields neither.
fn code_and_param(body: &[u8]) -> (Option<DiagnosticText>, Option<DiagnosticText>) {
    let Some(object) = json::object(body) else {
        return (None, None);
    };
    let document = json::Document(object);
    let source = match document.0.get("error") {
        Some(Value::Object(error)) => error,
        _ => &document.0,
    };
    let code = json::string(source, "code").and_then(sanitize_refusal_code);
    let param = json::string(source, "param").and_then(sanitize_param);
    (code, param)
}

pub(super) fn sanitize_code(code: &str) -> Option<String> {
    provider_error::sanitize_with(code, MAX_NAME_LEN, b"")
}

pub(super) fn sanitize_refusal_code(code: &str) -> Option<DiagnosticText> {
    sanitize_code(code).map(|value| Zeroizing::new(value.into_boxed_str()))
}

pub(super) fn sanitize_param(param: &str) -> Option<DiagnosticText> {
    provider_error::sanitize_param(param).map(|value| Zeroizing::new(value.into_boxed_str()))
}

#[cfg(test)]
impl Refusal {
    pub(super) fn assert_wiping_diagnostics(&self) {
        use std::any::Any;

        // Check the owners themselves. Reading freed heap memory would be
        // undefined even if the allocation was wiped.
        for (name, field) in [("code", &self.code), ("parameter", &self.param)] {
            let owner: &dyn Any = field.as_ref().unwrap();
            assert!(
                owner.is::<zeroize::Zeroizing<Box<str>>>(),
                "{name} must wipe on drop"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_alone_never_claims_a_reason_only_a_code_can_give() {
        for status in 0..=u16::MAX {
            let reason = by_status(status);
            assert!(
                !matches!(
                    reason,
                    Reason::UsageLimit
                        | Reason::PlanUseNotGranted
                        | Reason::Unsupported
                        | Reason::RouteNotSupported
                ),
                "{status} gives {reason:?}"
            );
        }
    }

    #[test]
    fn a_refusal_too_large_to_read_keeps_the_wait_it_asked_for() {
        let body = vec![b' '; MAX_BODY_LEN + 1];
        let refusal = Refusal::from_response(429, &body)
            .unwrap()
            .with_retry_after(Some("90"));
        let error = Error::from(refusal);
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
        assert_eq!(error.retry_after(), Some(Duration::from_secs(90)));
    }
}
