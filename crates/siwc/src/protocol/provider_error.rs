//! What is kept from an error the provider reports: its code, nothing else.

use serde_json::Value;

use super::http::HttpResponse;
use super::json;

const MAX_CODE_LEN: usize = 64;

/// Longest request ID or parameter name that is kept.
const MAX_NAME_LEN: usize = 128;

/// The error code of an error response, in either documented shape:
/// `{"error": "invalid_grant"}` or `{"error": {"code": "..."}}`.
///
/// Descriptions and messages are never read: they are free text from outside
/// and can repeat request data.
pub(crate) fn code(response: &HttpResponse) -> Option<String> {
    let document = json::Document(json::object(response.body())?);
    match document.0.get("error")? {
        Value::String(code) => sanitize(code),
        Value::Object(error) => json::string(error, "code")
            .or_else(|| json::string(error, "type"))
            .and_then(sanitize),
        _ => None,
    }
}

/// Keeps a code only if it looks like one, so it is safe to log and show.
pub(crate) fn sanitize(code: &str) -> Option<String> {
    sanitize_with(code, MAX_CODE_LEN, b"")
}

/// Keeps a request ID, such as the value of an `x-request-id` header, only
/// if it is made of letters, digits, `_`, `-` and `.`.
pub(crate) fn sanitize_request_id(id: &str) -> Option<String> {
    sanitize_with(id.trim_ascii(), MAX_NAME_LEN, b"")
}

/// Keeps a request member the provider named, such as `tools[0].type`,
/// only if it is made of letters, digits, `_`, `-`, `.`, `[` and `]`.
pub(crate) fn sanitize_param(param: &str) -> Option<String> {
    sanitize_with(param, MAX_NAME_LEN, b"[]")
}

/// Keeps `text` only if it has 1 to `max_len` bytes, each a letter, a digit,
/// `_`, `-`, `.` or one of `extra`. Anything else is dropped, never cut.
pub(crate) fn sanitize_with(text: &str, max_len: usize, extra: &[u8]) -> Option<String> {
    let well_formed = !text.is_empty()
        && text.len() <= max_len
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.') || extra.contains(&b)
        });
    well_formed.then(|| text.to_owned())
}

/// Statuses that say "not now" rather than "no": server errors, rate limits
/// and request timeouts. Credentials survive these.
pub(crate) fn is_temporary(status: u16) -> bool {
    status >= 500 || status == 429 || status == 408
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_of(body: &str) -> Option<String> {
        code(&HttpResponse::new(400, body.as_bytes().to_vec()))
    }

    #[test]
    fn both_documented_shapes_yield_the_code() {
        assert_eq!(
            code_of(r#"{"error":"invalid_grant"}"#).as_deref(),
            Some("invalid_grant")
        );
        assert_eq!(
            code_of(r#"{"error":{"code":"refresh_token_reused","message":"m"}}"#).as_deref(),
            Some("refresh_token_reused")
        );
        assert_eq!(
            code_of(r#"{"error":{"type":"invalid_request"}}"#).as_deref(),
            Some("invalid_request")
        );
    }

    #[test]
    fn free_text_and_other_shapes_yield_nothing() {
        for body in [
            "",
            "not json",
            r#"{"detail":"Unauthorized"}"#,
            r#"{"error":"a sentence with spaces"}"#,
            r#"{"error":"<script>"}"#,
            r#"{"error":42}"#,
            r#"{"error":{"message":"only text"}}"#,
        ] {
            assert_eq!(code_of(body), None, "{body}");
        }
        assert_eq!(sanitize(&"x".repeat(MAX_CODE_LEN + 1)), None);
    }
}
