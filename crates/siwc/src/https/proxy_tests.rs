//! The causes `Https` names when a forward proxy's `CONNECT` answer fails.

use std::io::{ErrorKind as IoKind, Read, Write};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::Https;
use super::response::HEAD_LIMIT;
use super::tests::{assert_unavailable, token_request};
use crate::error::{Error, ErrorCause};
use crate::transport::Transport;

/// A plain proxy on a loopback port that reads one `CONNECT` head, answers
/// `answer` and closes; returns the proxy URL.
pub(crate) fn proxy_answering(answer: &'static [u8]) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let proxy = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tcp.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let _ = tcp.write_all(answer);
    });
    (url, proxy)
}

/// A `CONNECT` head larger than the head limit.
pub(crate) fn overlong_connect_answer() -> &'static [u8] {
    let mut overlong = b"HTTP/1.1 200 OK\r\nx-filler: ".to_vec();
    overlong.resize(HEAD_LIMIT + 1, b'x');
    overlong.extend_from_slice(b"\r\n\r\n");
    overlong.leak()
}

/// Sends a token request through a proxy answering `answer`; returns the
/// error.
fn through_proxy_answering(answer: &'static [u8]) -> Error {
    let (url, proxy) = proxy_answering(answer);
    let error = Https::builder()
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
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
    ] {
        let error = through_proxy_answering(malformed);
        assert_unavailable(&error);
        assert_eq!(error.cause(), Some(ErrorCause::InvalidFraming));
    }
}

#[test]
fn a_connect_answer_above_the_head_limit_is_too_large() {
    let error = through_proxy_answering(overlong_connect_answer());
    assert_unavailable(&error);
    assert_eq!(error.cause(), Some(ErrorCause::ResponseTooLarge));
}

#[test]
fn a_proxy_refusal_names_only_that_access_was_denied() {
    for refusal in [
        &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
        b"HTTP/1.1 403 Forbidden\r\n\r\n",
    ] {
        let error = through_proxy_answering(refusal);
        assert_unavailable(&error);
        assert_eq!(
            error.cause(),
            Some(ErrorCause::Io(IoKind::PermissionDenied))
        );
    }
}

#[test]
fn a_proxy_that_cannot_reach_the_provider_names_no_tunnel_not_a_denial() {
    for failure in [
        &b"HTTP/1.1 502 Bad Gateway\r\n\r\n"[..],
        b"HTTP/1.1 503 Service Unavailable\r\n\r\n",
        b"HTTP/1.1 504 Gateway Timeout\r\n\r\n",
    ] {
        let error = through_proxy_answering(failure);
        assert_unavailable(&error);
        assert_eq!(error.cause(), Some(ErrorCause::Io(IoKind::NotConnected)));
    }
}

#[test]
fn a_proxy_that_closes_before_its_answer_is_complete_names_a_closed_connection() {
    for cut in [&b""[..], b"HTTP/1.1 200 OK\r\n"] {
        let error = through_proxy_answering(cut);
        assert_unavailable(&error);
        assert_eq!(error.cause(), Some(ErrorCause::ConnectionClosed));
    }
}
