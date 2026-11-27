//! Writing one HTTP/1.1 request into a buffer that is wiped when dropped.

use zeroize::Zeroizing;

use crate::protocol::{Method, is_token};

/// The `User-Agent` of every request: the crate and its version, nothing
/// about the app or the machine.
pub(super) const USER_AGENT: &str = concat!("siwc/", env!("CARGO_PKG_VERSION"));

/// The bytes of a request for `target` on `host`: request line, `Host`,
/// `headers` exactly as given, `Content-Length` when there is a body or the
/// method is `POST`, `Connection: close`, `User-Agent`, then `body`.
///
/// `None` when a header name or value would break the request's framing.
/// The buffer is sized up front, so no partial copy is left unwiped.
pub(super) fn write(
    method: Method,
    host: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if headers
        .iter()
        .any(|(name, value)| !is_token(name.as_bytes()) || !is_field_value(value))
    {
        return None;
    }
    let length = (!body.is_empty() || method == Method::Post).then(|| body.len().to_string());
    let mut fields: Vec<(&str, &str)> = vec![("Host", host)];
    fields.extend_from_slice(headers);
    if let Some(length) = &length {
        fields.push(("Content-Length", length));
    }
    fields.push(("Connection", "close"));
    fields.push(("User-Agent", USER_AGENT));

    let method = method.as_str();
    let size = method.len()
        + 1
        + target.len()
        + " HTTP/1.1\r\n".len()
        + fields
            .iter()
            .map(|(name, value)| name.len() + ": ".len() + value.len() + 2)
            .sum::<usize>()
        + 2
        + body.len();
    let mut bytes = Zeroizing::new(Vec::with_capacity(size));
    for part in [method, " ", target, " HTTP/1.1\r\n"] {
        bytes.extend_from_slice(part.as_bytes());
    }
    for (name, value) in fields {
        for part in [name, ": ", value, "\r\n"] {
            bytes.extend_from_slice(part.as_bytes());
        }
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(body);
    Some(bytes)
}

/// A header value without control characters, so it cannot end the line.
fn is_field_value(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).unwrap()
    }

    #[test]
    fn a_get_carries_host_its_headers_connection_close_and_the_user_agent() {
        let headers = [
            ("accept", "application/json"),
            ("authorization", "Bearer t"),
        ];
        let bytes = write(
            Method::Get,
            "api.openai.com",
            "/v1/models?x=1",
            &headers,
            b"",
        )
        .unwrap();
        assert_eq!(
            text(&bytes),
            format!(
                "GET /v1/models?x=1 HTTP/1.1\r\n\
                 Host: api.openai.com\r\n\
                 accept: application/json\r\n\
                 authorization: Bearer t\r\n\
                 Connection: close\r\n\
                 User-Agent: siwc/{}\r\n\r\n",
                env!("CARGO_PKG_VERSION")
            )
        );
        assert_eq!(bytes.len(), bytes.capacity(), "the buffer never grew");
    }

    #[test]
    fn a_post_carries_its_length_and_body() {
        let headers = [("content-type", "application/x-www-form-urlencoded")];
        let bytes = write(
            Method::Post,
            "auth.openai.com",
            "/oauth/token",
            &headers,
            b"a=b&c=d",
        )
        .unwrap();
        let text = text(&bytes);
        assert!(text.starts_with("POST /oauth/token HTTP/1.1\r\nHost: auth.openai.com\r\n"));
        assert!(text.contains("\r\ncontent-type: application/x-www-form-urlencoded\r\n"));
        assert!(text.contains("\r\nContent-Length: 7\r\nConnection: close\r\n"));
        assert!(text.ends_with("\r\n\r\na=b&c=d"));
        assert_eq!(bytes.len(), bytes.capacity(), "the buffer never grew");
    }

    #[test]
    fn an_empty_post_says_its_length_is_zero_and_an_empty_get_says_nothing() {
        let post = write(Method::Post, "h", "/", &[], b"").unwrap();
        assert!(text(&post).contains("\r\nContent-Length: 0\r\n"));
        let get = write(Method::Get, "h", "/", &[], b"").unwrap();
        assert!(!text(&get).contains("Content-Length"));
    }

    #[test]
    fn a_header_that_would_break_the_framing_is_refused() {
        for header in [
            ("x", "a\r\nInjected: yes"),
            ("x", "a\nb"),
            ("x", "a\0b"),
            ("x y", "v"),
            ("x:", "v"),
            ("", "v"),
        ] {
            let written = write(Method::Get, "h", "/", &[header], b"");
            assert!(written.is_none(), "{header:?}");
        }
        let tab = write(Method::Get, "h", "/", &[("x", "a\tb")], b"");
        assert!(tab.is_some());
    }
}
