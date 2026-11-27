//! The causes `Ureq` names when a forward proxy's `CONNECT` answer fails.
//!
//! ureq reports a tunnel the proxy did not open as one variant holding only
//! text, so where `Https` tells a refusal, a `5xx`, an overlong head and an
//! early close apart, `Ureq` names `Io(NotConnected)` for all of them.

use std::io::ErrorKind as IoKind;

use super::Ureq;
use crate::error::{Error, ErrorCause};
use crate::https::proxy_tests::{overlong_connect_answer, proxy_answering};
use crate::https::tests::{assert_unavailable, token_request};
use crate::transport::Transport;

/// Sends a token request through a proxy answering `answer`; returns the
/// error.
fn through_proxy_answering(answer: &'static [u8]) -> Error {
    let (url, proxy) = proxy_answering(answer);
    let error = Ureq::builder()
        .proxy(&url)
        .unwrap()
        .build()
        .unwrap()
        .send(&token_request())
        .unwrap_err();
    proxy.join().unwrap();
    error
}

#[test]
fn a_malformed_connect_answer_is_invalid_framing() {
    for malformed in [
        &b"HTTP/1.1 200 OK\r\nBroken Header\r\n\r\n"[..],
        b"HTTP/2 200\r\n\r\n",
    ] {
        let error = through_proxy_answering(malformed);
        assert_unavailable(&error);
        assert_eq!(error.cause(), Some(ErrorCause::InvalidFraming));
    }
}

#[test]
fn a_tunnel_the_proxy_did_not_open_names_not_connected() {
    for answer in [
        &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
        b"HTTP/1.1 403 Forbidden\r\n\r\n",
        b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
        overlong_connect_answer(),
        b"",
        b"HTTP/1.1 200 OK\r\n",
    ] {
        let error = through_proxy_answering(answer);
        assert_unavailable(&error);
        assert_eq!(
            error.cause(),
            Some(ErrorCause::Io(IoKind::NotConnected)),
            "{:?}",
            answer.get(..12)
        );
    }
}
