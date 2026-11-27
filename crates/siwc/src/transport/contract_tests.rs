//! The same loopback contract checks run against both shipped transports.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::cancel::Canceller;
use crate::error::{ErrorCause, ErrorKind};
use crate::https::{Https, tests as https_tests};
use crate::protocol::HttpRequest;
use crate::transport::Transport;

const CA: &[u8] = include_bytes!("../../tests/support/tls/ca.pem");
const SERVER: &[u8] = include_bytes!("../../tests/support/tls/server.pem");
const WRONG_NAME: &[u8] = include_bytes!("../../tests/support/tls/wrong-name.pem");
const UNKNOWN_ISSUER: &[u8] = include_bytes!("../../tests/support/tls/unknown-issuer.pem");
const PROXY_CA: &[u8] = include_bytes!("../../tests/support/tls/proxy-ca.pem");
const PROXY_CERT: &[u8] = include_bytes!("../../tests/support/tls/proxy.pem");
const KEY: &[u8] = include_bytes!("../../tests/support/tls/server.key");

#[derive(Clone, Copy, Debug)]
enum Kind {
    Https,
    Ureq,
}

const KINDS: [Kind; 2] = [Kind::Https, Kind::Ureq];

#[expect(clippy::unwrap_used, reason = "synthetic test roots and valid limits")]
fn transport(
    kind: Kind,
    address: SocketAddr,
    max_len: usize,
    timeout: Duration,
) -> Box<dyn Transport> {
    match kind {
        Kind::Https => {
            let mut http = Https::builder()
                .max_response_len(max_len)
                .total_timeout(timeout)
                .add_root_certificates_pem(CA)
                .unwrap()
                .build()
                .unwrap();
            http.connect_to = Some(address);
            Box::new(http)
        }
        Kind::Ureq => {
            let mut http = crate::ureq::Ureq::builder()
                .max_response_len(max_len)
                .total_timeout(timeout)
                .add_root_certificates_pem(CA)
                .unwrap()
                .build()
                .unwrap();
            http.connect_to = Some(address);
            Box::new(http)
        }
    }
}

#[test]
fn the_transport_contract_returns_status_headers_and_body_without_following_redirects() {
    for kind in KINDS {
        let (address, server) = https_tests::serve(
            SERVER,
            b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\nx-request-id: req_old\r\nx-request-id: req_123\r\nRetry-After: 2\r\nRetry-After: 12\r\nRetry-After: invalid\r\nRetry-After: 3\r\nContent-Length: 4\r\n\r\nnext",
        );
        let response = transport(kind, address, 1024, Duration::from_secs(3))
            .send(&https_tests::token_request())
            .unwrap();
        assert_eq!(response.status(), 302, "{kind:?}");
        assert_eq!(response.body(), b"next", "{kind:?}");
        assert_eq!(response.request_id(), Some("req_123"));
        assert_eq!(response.retry_after(), Some("12"));
        assert!(!server.join().unwrap().received.is_empty());
    }
}

#[test]
fn the_transport_contract_rejects_outside_hosts_before_connection() {
    for kind in KINDS {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let http = transport(
            kind,
            listener.local_addr().unwrap(),
            1024,
            Duration::from_secs(3),
        );
        let bad = HttpRequest::get("https://example.invalid/");
        assert_eq!(http.send(&bad).unwrap_err().kind(), ErrorKind::InvalidInput);
        assert!(listener.accept().is_err());
    }
}

#[test]
fn the_transport_contract_rejects_oversized_and_truncated_buffered_bodies() {
    for kind in KINDS {
        let (address, server) =
            https_tests::serve(SERVER, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        let error = transport(kind, address, 4, Duration::from_secs(3))
            .send(&https_tests::token_request())
            .unwrap_err();
        https_tests::assert_unavailable(&error);
        assert_eq!(
            error.cause(),
            Some(ErrorCause::ResponseTooLarge),
            "{kind:?}"
        );
        server.join().unwrap();

        let (address, server) =
            https_tests::serve(SERVER, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi");
        let error = transport(kind, address, 1024, Duration::from_secs(3))
            .send(&https_tests::token_request())
            .unwrap_err();
        https_tests::assert_unavailable(&error);
        assert_eq!(
            error.cause(),
            Some(ErrorCause::ConnectionClosed),
            "{kind:?}"
        );
        server.join().unwrap();
    }
}

#[test]
fn a_timeout_and_malformed_framing_give_distinct_causes_on_both_transports() {
    for kind in KINDS {
        let (release, blocked) = mpsc::channel();
        let (address, server) = https_tests::serve_before_answer(
            SERVER,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
            move || {
                let _ = blocked.recv_timeout(Duration::from_secs(3));
            },
        );
        let timed_out = transport(kind, address, 1024, Duration::from_millis(100))
            .send(&https_tests::token_request())
            .unwrap_err();
        release.send(()).unwrap();
        server.join().unwrap();

        let (address, server) = https_tests::serve(SERVER, b"HTTP/1.1 200 OK\r\nbroken\r\n\r\n");
        let malformed = transport(kind, address, 1024, Duration::from_secs(3))
            .send(&https_tests::token_request())
            .unwrap_err();
        server.join().unwrap();

        for error in [&timed_out, &malformed] {
            https_tests::assert_unavailable(error);
            let source = std::error::Error::source(error).map(ToString::to_string);
            assert_eq!(source, error.cause().map(|cause| cause.to_string()));
        }
        assert_eq!(timed_out.cause(), Some(ErrorCause::TimedOut), "{kind:?}");
        assert_eq!(
            malformed.cause(),
            Some(ErrorCause::InvalidFraming),
            "{kind:?}"
        );
    }
}

#[test]
fn the_transport_contract_rejects_a_malformed_response_head() {
    for kind in KINDS {
        let (address, server) = https_tests::serve(
            SERVER,
            b"HTTP/1.1 200 OK\r\nContent-Length: not-a-number\r\n\r\n",
        );
        let error = transport(kind, address, 1024, Duration::from_secs(3))
            .send(&https_tests::token_request())
            .unwrap_err();
        https_tests::assert_unavailable(&error);
        assert_eq!(error.cause(), Some(ErrorCause::InvalidFraming), "{kind:?}");
        server.join().unwrap();
    }
}

#[test]
fn the_transport_contract_rejects_untrusted_or_wrong_name_certificates_before_request_bytes() {
    for kind in KINDS {
        for certificate in [WRONG_NAME, UNKNOWN_ISSUER] {
            let (address, server) = https_tests::serve(
                certificate,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
            );
            let error = transport(kind, address, 1024, Duration::from_secs(3))
                .send(&https_tests::token_request())
                .unwrap_err();
            https_tests::assert_unavailable(&error);
            assert_eq!(error.cause(), Some(ErrorCause::Tls), "{kind:?}");
            assert!(server.join().unwrap().received.is_empty(), "{kind:?}");
        }
    }
}

#[test]
fn the_transport_contract_streams_decoded_chunks_and_rejects_a_cut_stream() {
    for kind in KINDS {
        let (address, server) = https_tests::serve(
            SERVER,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n",
        );
        let mut response = transport(kind, address, 1024, Duration::from_secs(3))
            .send_streaming(&https_tests::token_request(), &Canceller::new())
            .unwrap();
        let mut body = Vec::new();
        response.body_mut().read_to_end(&mut body).unwrap();
        assert_eq!(body, b"onetwo", "{kind:?}");
        server.join().unwrap();

        let (address, server) = https_tests::serve(
            SERVER,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhi",
        );
        let mut response = transport(kind, address, 1024, Duration::from_secs(3))
            .send_streaming(&https_tests::token_request(), &Canceller::new())
            .unwrap();
        let cut = response
            .body_mut()
            .read_to_end(&mut Vec::new())
            .unwrap_err();
        assert_eq!(
            ErrorCause::from_io(&cut),
            ErrorCause::ConnectionClosed,
            "{kind:?}"
        );
        server.join().unwrap();
    }
}

#[test]
fn ureq_accepts_a_tls12_only_server_with_the_ring_provider() {
    let (address, server) =
        https_tests::serve_tls12(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
    let response = transport(Kind::Ureq, address, 1024, Duration::from_secs(3))
        .send(&https_tests::token_request())
        .unwrap();
    assert_eq!(response.body(), b"{}");
    assert!(!server.join().unwrap().is_empty());
}

#[test]
fn the_transport_contract_times_out_while_waiting_for_a_response_head() {
    for kind in KINDS {
        let (release, blocked) = mpsc::channel();
        let (address, server) = https_tests::serve_before_answer(
            SERVER,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
            move || {
                let _ = blocked.recv_timeout(Duration::from_secs(3));
            },
        );
        let started = Instant::now();
        let error = transport(kind, address, 1024, Duration::from_millis(100))
            .send(&https_tests::token_request())
            .unwrap_err();
        https_tests::assert_unavailable(&error);
        assert!(started.elapsed() < Duration::from_secs(2), "{kind:?}");
        release.send(()).unwrap();
        server.join().unwrap();
    }
}

#[test]
fn the_transport_contract_refuses_a_pre_cancelled_stream() {
    for kind in KINDS {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let http = transport(
            kind,
            listener.local_addr().unwrap(),
            1024,
            Duration::from_secs(3),
        );
        let stop = Canceller::new();
        stop.cancel();
        let error = http
            .send_streaming(&https_tests::token_request(), &stop)
            .unwrap_err();
        https_tests::assert_unavailable(&error);
        assert_eq!(error.cause(), None, "{kind:?}");
        assert!(listener.accept().is_err());

        let error = http
            .send_cancellable(&https_tests::token_request(), &stop)
            .unwrap_err();
        https_tests::assert_unavailable(&error);
        assert_eq!(error.cause(), None, "{kind:?}");
    }
}

/// A TLS server that completes the handshake, reads the request, answers
/// `head`, calls `answered` and, once released, writes a TLS record that
/// cannot be decrypted.
#[expect(
    clippy::unwrap_used,
    reason = "synthetic test certificate on a loopback port"
)]
fn serve_corrupt_record(
    head: &'static [u8],
    answered: impl FnOnce() + Send + 'static,
) -> (SocketAddr, mpsc::Sender<()>, thread::JoinHandle<()>) {
    let (release, released) = mpsc::channel();
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(SERVER)
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let connection = ServerConnection::new(std::sync::Arc::new(config)).unwrap();
        let mut tls = StreamOwned::new(connection, tcp);
        let mut received = Vec::new();
        let mut buffer = [0; 4096];
        while !https_tests::complete(&received) {
            match tls.read(&mut buffer) {
                Ok(0) | Err(_) => return,
                Ok(read) => received.extend_from_slice(&buffer[..read]),
            }
        }
        tls.write_all(head).unwrap();
        tls.flush().unwrap();
        answered();
        let _ = released.recv_timeout(Duration::from_secs(3));
        // Application data under the right header, but garbage inside.
        let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x20];
        record.extend_from_slice(&[0x55; 0x20]);
        tls.sock.write_all(&record).unwrap();
        // The client fails on the record and closes; wait for that.
        let _ = tls.sock.read(&mut buffer);
    });
    (address, release, server)
}

#[test]
fn a_tls_record_that_fails_after_the_handshake_is_tls_on_both_transports() {
    const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    for kind in KINDS {
        // In the head, then in a buffered body.
        for head in [&b""[..], HEAD] {
            let (address, release, server) = serve_corrupt_record(head, || {});
            release.send(()).unwrap();
            let error = transport(kind, address, 1024, Duration::from_secs(3))
                .send(&https_tests::token_request())
                .unwrap_err();
            https_tests::assert_unavailable(&error);
            assert_eq!(error.cause(), Some(ErrorCause::Tls), "{kind:?}");
            server.join().unwrap();
        }

        let (address, release, server) = serve_corrupt_record(HEAD, || {});
        let mut response = transport(kind, address, 1024, Duration::from_secs(3))
            .send_streaming(&https_tests::token_request(), &Canceller::new())
            .unwrap();
        release.send(()).unwrap();
        let failed = response
            .body_mut()
            .read_to_end(&mut Vec::new())
            .unwrap_err();
        assert_eq!(ErrorCause::from_io(&failed), ErrorCause::Tls, "{kind:?}");
        drop(response);
        server.join().unwrap();
    }
}

#[test]
fn the_transport_contract_hands_over_the_head_of_a_streamed_refusal_that_is_too_large() {
    const LIMIT: usize = 64 * 1024;
    let mut answer = format!(
        "HTTP/1.1 503 Unavailable\r\nx-request-id: req_503\r\nRetry-After: 90\r\nContent-Length: {}\r\n\r\n",
        LIMIT + 2
    )
    .into_bytes();
    answer.resize(answer.len() + LIMIT + 2, b'x');
    let answer: &'static [u8] = answer.leak();
    for kind in KINDS {
        let (address, server) = https_tests::serve(SERVER, answer);
        let mut response = transport(kind, address, 1024, Duration::from_secs(3))
            .send_streaming(&https_tests::token_request(), &Canceller::new())
            .unwrap();
        assert_eq!(response.status(), 503, "{kind:?}");
        assert_eq!(response.request_id(), Some("req_503"), "{kind:?}");
        assert_eq!(response.retry_after(), Some("90"), "{kind:?}");
        // One byte past the limit is there to read: the body is too large.
        let mut body = Vec::new();
        let read = response
            .body_mut()
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(read, LIMIT + 1, "{kind:?}");
        drop(response);
        server.join().unwrap();
    }
}

#[test]
fn ureq_hands_out_one_byte_more_than_a_streamed_refusal_may_have() {
    const LIMIT: usize = 64 * 1024;
    let mut answer = format!(
        "HTTP/1.1 503 Unavailable\r\nContent-Length: {}\r\n\r\n",
        LIMIT + 2
    )
    .into_bytes();
    answer.resize(answer.len() + LIMIT + 2, b'x');
    let (address, server) = https_tests::serve(SERVER, answer.leak());
    let mut response = transport(Kind::Ureq, address, 1024, Duration::from_secs(3))
        .send_streaming(&https_tests::token_request(), &Canceller::new())
        .unwrap();
    let mut body = Vec::new();
    assert_eq!(
        response.body_mut().read_to_end(&mut body).unwrap(),
        LIMIT + 1
    );
    drop(response);
    server.join().unwrap();
}

#[test]
fn ureq_debug_prints_only_numeric_limits() {
    let http = crate::ureq::Ureq::builder()
        .proxy("http://proxy.corp.example.invalid:8080")
        .unwrap()
        .build()
        .unwrap();
    let debug = format!("{http:?}");
    assert!(debug.contains("connect_timeout: 10s"));
    assert!(!debug.contains("proxy"));
    assert!(!debug.contains("corp"));
}

#[test]
fn ureq_tunnels_through_an_explicit_http_proxy() {
    let (upstream_address, upstream) =
        https_tests::serve(SERVER, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let proxy = thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let mut upstream_socket = TcpStream::connect(upstream_address).unwrap();
        upstream_socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        let mut client_to_upstream = client.try_clone().unwrap();
        let mut upstream_writer = upstream_socket.try_clone().unwrap();
        let forward = thread::spawn(move || {
            let _ = std::io::copy(&mut client_to_upstream, &mut upstream_writer);
            let _ = upstream_writer.shutdown(std::net::Shutdown::Write);
        });
        let _ = std::io::copy(&mut upstream_socket, &mut client);
        let _ = client.shutdown(std::net::Shutdown::Write);
        forward.join().unwrap();
        head
    });

    let http = crate::ureq::Ureq::builder()
        .add_root_certificates_pem(CA)
        .unwrap()
        .proxy(&format!("http://127.0.0.1:{}", proxy_address.port()))
        .unwrap()
        .build()
        .unwrap();
    let response = http.send(&https_tests::token_request()).unwrap();
    assert_eq!(response.body(), b"{}");
    let head = String::from_utf8(proxy.join().unwrap()).unwrap();
    assert!(head.starts_with("CONNECT auth.openai.com:443 HTTP/1.1\r\n"));
    assert!(!upstream.join().unwrap().received.is_empty());
}

#[test]
fn ureq_verifies_an_https_proxy_and_refuses_its_407_answer() {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(PROXY_CERT)
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut tls = StreamOwned::new(
            ServerConnection::new(std::sync::Arc::new(config)).unwrap(),
            tcp,
        );
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tls.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        tls.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .unwrap();
        tls.flush().unwrap();
        head
    });
    let http = crate::ureq::Ureq::builder()
        .add_root_certificates_pem(CA)
        .unwrap()
        .add_root_certificates_pem(PROXY_CA)
        .unwrap()
        .proxy(&format!("https://127.0.0.1:{}", address.port()))
        .unwrap()
        .build()
        .unwrap();
    https_tests::assert_unavailable(&http.send(&https_tests::token_request()).unwrap_err());
    let head = String::from_utf8(proxy.join().unwrap()).unwrap();
    assert!(head.starts_with("CONNECT auth.openai.com:443 HTTP/1.1\r\n"));
}

#[test]
fn the_transports_reject_statuses_above_599() {
    for kind in KINDS {
        let (address, server) =
            https_tests::serve(SERVER, b"HTTP/1.1 600 Invalid\r\nContent-Length: 0\r\n\r\n");
        let error = transport(kind, address, 64, Duration::from_secs(3))
            .send(&https_tests::token_request())
            .unwrap_err();
        https_tests::assert_unavailable(&error);
        server.join().unwrap();
    }
}

#[test]
fn both_transports_bound_the_decoded_buffered_body() {
    for kind in KINDS {
        for limit in [4, 5] {
            let (address, server) = https_tests::serve(
                SERVER,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            );
            let result = transport(kind, address, limit, Duration::from_secs(3))
                .send(&https_tests::token_request());
            if limit == 5 {
                assert_eq!(result.unwrap().body(), b"hello");
            } else {
                https_tests::assert_unavailable(&result.unwrap_err());
            }
            server.join().unwrap();
        }
    }
}

#[test]
fn a_buffered_exchange_finished_after_cancellation_keeps_the_cause_of_its_failure() {
    const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    for kind in KINDS {
        // In the head, then in the body: the request was written in full,
        // so the exchange runs on after the cancellation and fails on its
        // own account.
        for head in [&b""[..], HEAD] {
            let stop = Canceller::new();
            let trigger = stop.clone();
            let (address, release, server) = serve_corrupt_record(head, move || trigger.cancel());
            release.send(()).unwrap();
            let error = transport(kind, address, 1024, Duration::from_secs(3))
                .send_cancellable(&https_tests::token_request(), &stop)
                .unwrap_err();
            assert!(stop.is_cancelled(), "{kind:?}");
            https_tests::assert_unavailable(&error);
            assert_eq!(error.cause(), Some(ErrorCause::Tls), "{kind:?}");
            server.join().unwrap();
        }
    }
}

#[test]
fn a_cancelled_stream_read_fails_promptly_with_connection_aborted_and_no_cause_on_both_transports()
{
    const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    // Cancelled before the read on both, then once the reader is on its
    // way into a read that waits for bytes. `Ureq` notices a cancellation
    // in a blocked socket read only at its read timeout, as documented, so
    // the waiting read is checked on `Https`, which promises about 50 ms.
    let cases = [
        (Kind::Https, true),
        (Kind::Ureq, true),
        (Kind::Https, false),
    ];
    for (kind, cancel_first) in cases {
        let (address, release, server) = serve_corrupt_record(HEAD, || {});
        let stop = Canceller::new();
        let mut response = transport(kind, address, 1024, Duration::from_secs(3))
            .send_streaming(&https_tests::token_request(), &stop)
            .unwrap();
        if cancel_first {
            stop.cancel();
        }
        let (reading, started) = mpsc::channel();
        let (done, finished) = mpsc::channel();
        // The reader runs apart, so a read that never ends fails the test
        // instead of hanging it.
        thread::spawn(move || {
            let _ = reading.send(());
            let _ = done.send(response.body_mut().read_to_end(&mut Vec::new()));
        });
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        stop.cancel();
        let result = finished.recv_timeout(Duration::from_secs(2));
        release.send(()).unwrap();
        assert!(result.is_ok(), "{kind:?}: the cancelled read did not end");
        let error = result.unwrap().unwrap_err();
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionAborted,
            "{kind:?}"
        );
        assert!(
            error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<ErrorCause>())
                .is_none(),
            "{kind:?}: a cancelled read names no cause"
        );
        server.join().unwrap();
    }
}
