//! `Https::send_streaming` against a TLS server on a loopback port that
//! sends its answer in scripted steps.

use std::io::{ErrorKind as IoKind, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::cancel::Canceller;
use crate::plan::{RESPONSES_URL, ResponseRequest};
use crate::protocol::HttpRequest;
use crate::secret::AccessToken;
use crate::transport::Transport;
#[cfg(feature = "ureq")]
use crate::ureq::Ureq;

use super::Https;
use super::connect::waiting::{self, Wait};
use super::tests::{KEY, assert_unavailable, complete, finish};

/// A self-signed certificate for `api.openai.com`, the host of plan
/// requests; the tests trust it as their only extra root.
const API_LEAF: &[u8] = include_bytes!("../../tests/support/tls/self-signed-api-leaf.pem");

/// A transport that connects to `address` whatever the host.
fn loopback(address: SocketAddr, total_timeout: Duration) -> Https {
    let mut https = Https::builder()
        .total_timeout(total_timeout)
        .add_root_certificates_pem(API_LEAF)
        .unwrap()
        .build()
        .unwrap();
    https.connect_to = Some(address);
    https
}

fn https_transport(address: SocketAddr, timeout: Duration) -> Box<dyn Transport> {
    Box::new(loopback(address, timeout))
}

#[cfg(feature = "ureq")]
fn ureq_transport(address: SocketAddr, timeout: Duration) -> Box<dyn Transport> {
    let mut http = Ureq::builder()
        .total_timeout(timeout)
        .add_root_certificates_pem(API_LEAF)
        .unwrap()
        .build()
        .unwrap();
    http.connect_to = Some(address);
    Box::new(http)
}

type TransportFactory = fn(SocketAddr, Duration) -> Box<dyn Transport>;
#[cfg(feature = "ureq")]
const TRANSPORTS: [TransportFactory; 2] = [https_transport, ureq_transport];
#[cfg(not(feature = "ureq"))]
const TRANSPORTS: [TransportFactory; 1] = [https_transport];

const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nx-request-id: req_stream_1\r\nTransfer-Encoding: chunked\r\n\r\n";

/// One step of a scripted answer.
enum Step {
    /// Writes and flushes these bytes as one TLS record.
    Send(Vec<u8>),
    /// Waits until the test sends a go, or drops its sender.
    Hold(Receiver<()>),
    #[cfg(feature = "testing")]
    ObserveClose(Sender<bool>),
}

/// A TLS 1.3 server that reads one request, plays `steps` and closes the
/// connection, with `close_notify` if `clean`. Returns what it received.
fn serve(steps: Vec<Step>, clean: bool) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(API_LEAF)
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let thread = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let connection = ServerConnection::new(config).unwrap();
        let mut tls = StreamOwned::new(connection, tcp);
        let mut received = Vec::new();
        let mut buffer = [0; 4096];
        while !complete(&received) {
            match tls.read(&mut buffer) {
                Ok(0) | Err(_) => return received,
                Ok(read) => received.extend_from_slice(&buffer[..read]),
            }
        }
        for step in steps {
            match step {
                // A client that stopped reading closes its side: not an
                // error of the server.
                Step::Send(bytes) => {
                    if tls.write_all(&bytes).and_then(|()| tls.flush()).is_err() {
                        return received;
                    }
                }
                #[cfg(feature = "testing")]
                Step::ObserveClose(result) => {
                    let closed = match tls.read(&mut buffer) {
                        Ok(count) => count == 0,
                        Err(error) => matches!(
                            error.kind(),
                            IoKind::UnexpectedEof | IoKind::ConnectionReset
                        ),
                    };
                    let _ = result.send(closed);
                }
                Step::Hold(go) => {
                    let _ = go.recv_timeout(Duration::from_secs(10));
                }
            }
        }
        if clean {
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
        received
    });
    (address, thread)
}

/// Whether the server received the whole plan request: the client came as
/// far as waiting for the answer.
fn was_asked(received: &[u8]) -> bool {
    received.starts_with(b"POST /v1/responses HTTP/1.1\r\n") && complete(received)
}

fn hold() -> (Sender<()>, Step) {
    let (go, held) = mpsc::channel();
    (go, Step::Hold(held))
}

fn chunk(body: &str) -> Vec<u8> {
    format!("{:x}\r\n{body}\r\n", body.len()).into_bytes()
}

fn plan_request() -> HttpRequest {
    let request = ResponseRequest::text("example-large", "Hello").unwrap();
    request.http_request(&AccessToken::new("at-synthetic".to_owned()))
}

fn read_some(body: &mut (dyn Read + Send)) -> std::io::Result<String> {
    let mut buffer = [0; 256];
    let count = body.read(&mut buffer)?;
    Ok(String::from_utf8(buffer[..count].to_vec()).unwrap())
}

#[test]
fn a_streamed_answer_is_handed_out_while_the_server_is_still_sending() {
    for make in TRANSPORTS {
        let (go, held) = hold();
        let mut first = HEAD.to_vec();
        first.extend(chunk("data: one\n\n"));
        let mut last = chunk("data: two\n\n");
        last.extend_from_slice(b"0\r\n\r\n");
        let (address, server) = serve(vec![Step::Send(first), held, Step::Send(last)], true);

        let http = make(address, Duration::from_secs(10));
        let mut response = http
            .send_streaming(&plan_request(), &Canceller::new())
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.request_id(), Some("req_stream_1"));
        // The first event is readable although the server has not sent the rest.
        assert_eq!(read_some(response.body_mut()).unwrap(), "data: one\n\n");
        go.send(()).unwrap();
        let mut rest = String::new();
        response.body_mut().read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "data: two\n\n");
        let received = String::from_utf8(finish(address, server)).unwrap();
        assert!(
            received.starts_with("POST /v1/responses HTTP/1.1\r\n"),
            "{received}"
        );
        let head = received
            .split_once("\r\n\r\n")
            .unwrap()
            .0
            .to_ascii_lowercase();
        assert!(head.contains("\r\nhost: api.openai.com\r\n"));
        assert!(
            head.contains(concat!("\r\nuser-agent: siwc/", env!("CARGO_PKG_VERSION"))),
            "{head}"
        );
        assert!(head.contains("\r\naccept: text/event-stream\r\n"));
        assert!(head.contains("\r\ncontent-type: application/json\r\n"));
        assert!(!head.contains("\r\naccept-encoding:"));
        assert!(
            head.contains("\r\nauthorization: bearer at-synthetic"),
            "{head}"
        );
        assert!(
            received.ends_with(r#""store":false,"stream":true}"#),
            "{received}"
        );
    }
    assert_eq!(plan_request().url(), RESPONSES_URL);
}

#[test]
fn chunks_split_at_every_byte_boundary_decode_to_the_same_body() {
    for make in TRANSPORTS {
        let text = "data: {\"delta\":\"gr\u{fc}\u{df}e \u{1f600}\"}\n\n";
        let mut wire = HEAD.to_vec();
        for piece in [&text[..9], &text[9..17], &text[17..]] {
            wire.extend(format!("{:x};note=1\r\n", piece.len()).into_bytes());
            wire.extend_from_slice(piece.as_bytes());
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\nTrailer: ignored\r\n\r\n");
        // One TLS record per byte: every split a network can make.
        let steps = wire.iter().map(|byte| Step::Send(vec![*byte])).collect();
        let (address, server) = serve(steps, true);

        let http = make(address, Duration::from_secs(10));
        let mut response = http
            .send_streaming(&plan_request(), &Canceller::new())
            .unwrap();
        let mut body = String::new();
        response.body_mut().read_to_string(&mut body).unwrap();
        assert_eq!(body, text);
        finish(address, server);
    }
}

#[test]
fn a_stream_that_falls_silent_fails_after_the_idle_time_not_the_total_one() {
    let (go, held) = hold();
    let mut first = HEAD.to_vec();
    first.extend(chunk("data: one\n\n"));
    let (address, server) = serve(vec![Step::Send(first), held], true);

    // The total time has to cover the connection, the handshake and the
    // head on a busy machine, and the idle time has to outlast it: a read
    // that fails later than the total time allows was not cut by it.
    let total = Duration::from_secs(1);
    let idle = Duration::from_millis(1200);
    let mut https = loopback(address, total);
    https.limits.stream_idle_timeout = idle;
    let mut response = https
        .send_streaming(&plan_request(), &Canceller::new())
        .unwrap();
    assert_eq!(read_some(response.body_mut()).unwrap(), "data: one\n\n");

    let started = Instant::now();
    let error = read_some(response.body_mut()).unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(error.kind(), IoKind::ConnectionAborted);
    assert!(
        elapsed >= idle,
        "the total timeout cut the stream: {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    // A failed body keeps failing; it never turns into a clean end.
    assert!(read_some(response.body_mut()).is_err());
    drop(go);
    finish(address, server);
}

#[test]
fn a_fragmented_chunk_size_shares_one_deadline_until_payload_arrives() {
    let mut steps = vec![Step::Send(HEAD.to_vec())];
    let mut fragments = Vec::new();
    for piece in [
        &b"1"[..],
        b";",
        b"n",
        b"=",
        b"v",
        b"\r",
        b"\nx\r\n0\r\n\r\n",
    ] {
        let (go, held) = hold();
        steps.extend([held, Step::Send(piece.to_vec())]);
        fragments.push(go);
    }
    let (address, server) = serve(steps, true);
    let mut https = loopback(address, Duration::from_secs(10));
    https.limits.stream_idle_timeout = Duration::from_millis(250);
    let mut response = https
        .send_streaming(&plan_request(), &Canceller::new())
        .unwrap();

    let (waiting, waits) = mpsc::channel();
    let reader = thread::spawn(move || {
        waiting::observe(waiting);
        read_some(response.body_mut())
    });
    // Each fragment follows one 50 ms socket wait. Only their combined
    // time exceeds the idle limit of the single decoded read.
    for go in fragments {
        let wait = waits.recv_timeout(Duration::from_secs(3));
        if wait == Err(mpsc::RecvTimeoutError::Disconnected) {
            break;
        }
        assert_eq!(wait, Ok(Wait::Read));
        let _ = go.send(());
    }
    assert_eq!(
        reader.join().unwrap().unwrap_err().kind(),
        IoKind::ConnectionAborted
    );
    assert!(was_asked(&finish(address, server)));
}

#[test]
fn cancelling_a_direct_read_refuses_already_buffered_bytes() {
    let mut wire = HEAD.to_vec();
    wire.extend(chunk("buffered"));
    wire.extend_from_slice(b"0\r\n\r\n");
    let (address, server) = serve(vec![Step::Send(wire)], true);
    let stop = Canceller::new();
    let mut response = loopback(address, Duration::from_secs(10))
        .send_streaming(&plan_request(), &stop)
        .unwrap();
    let mut byte = [0];
    response.body_mut().read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"b");
    stop.cancel();
    assert_eq!(
        response.body_mut().read(&mut byte).unwrap_err().kind(),
        IoKind::ConnectionAborted
    );
    assert!(was_asked(&finish(address, server)));
}

#[test]
fn cancelling_ends_a_read_that_waits_for_the_next_bytes() {
    let (go, held) = hold();
    let mut first = HEAD.to_vec();
    first.extend(chunk("data: one\n\n"));
    let (address, server) = serve(vec![Step::Send(first), held], true);

    let https = loopback(address, Duration::from_secs(10));
    let canceller = Canceller::new();
    let mut response = https.send_streaming(&plan_request(), &canceller).unwrap();
    assert_eq!(read_some(response.body_mut()).unwrap(), "data: one\n\n");

    let (returned, read_over) = mpsc::channel();
    let (waiting, waits) = mpsc::channel();
    let reader = thread::spawn(move || {
        waiting::observe(waiting);
        let outcome = read_some(response.body_mut());
        returned.send(()).unwrap();
        outcome
    });
    // The read is in its socket and got nothing for one slice: it waits,
    // and the cancellation below finds it there. The timeout only keeps a
    // broken test from hanging.
    assert_eq!(
        waits.recv_timeout(Duration::from_secs(30)).unwrap(),
        Wait::Read
    );
    assert!(
        read_over.try_recv().is_err(),
        "the read returned without bytes"
    );
    canceller.cancel();
    // The idle time is five minutes: only the canceller ends this read.
    read_over.recv_timeout(Duration::from_secs(30)).unwrap();
    let outcome = reader.join().unwrap();
    let error = outcome.unwrap_err();
    assert_eq!(error.kind(), IoKind::ConnectionAborted);
    // A cancelled read names no cause, not the closed wait it interrupted.
    assert!(
        error.get_ref().is_none(),
        "the cancelled read named a cause"
    );
    drop(go);
    assert!(was_asked(&finish(address, server)));
}

#[test]
fn a_request_cancelled_before_it_is_sent_opens_no_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let canceller = Canceller::new();
    canceller.cancel();
    let error = loopback(address, Duration::from_secs(10))
        .send_streaming(&plan_request(), &canceller)
        .unwrap_err();
    assert_unavailable(&error);
    // Not even a connection was made: one would be waiting here.
    let nobody = listener.accept().unwrap_err();
    assert_eq!(nobody.kind(), IoKind::WouldBlock);
}

#[test]
fn a_refusal_comes_back_as_a_response_with_its_headers_and_body() {
    let answer = b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 7\r\nX-Request-Id: req_stream_2\r\nContent-Length: 17\r\n\r\n{\"detail\":\"busy\"}";
    let (address, server) = serve(vec![Step::Send(answer.to_vec())], false);
    let mut response = loopback(address, Duration::from_secs(10))
        .send_streaming(&plan_request(), &Canceller::new())
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(response.retry_after(), Some("7"));
    assert_eq!(response.request_id(), Some("req_stream_2"));
    let mut body = String::new();
    response.body_mut().read_to_string(&mut body).unwrap();
    assert_eq!(body, "{\"detail\":\"busy\"}");
    finish(address, server);
}

#[test]
fn a_stream_cut_inside_its_framing_is_an_error_and_never_a_clean_end() {
    for (tail, clean) in [
        // The connection closes cleanly, but the last chunk never came.
        (chunk("data: one\n\n"), true),
        // A chunk announces more bytes than arrive.
        (b"ff\r\ndata: on".to_vec(), true),
        // The peer vanishes without `close_notify`.
        (chunk("data: one\n\n"), false),
    ] {
        let mut wire = HEAD.to_vec();
        wire.extend(tail);
        let (address, server) = serve(vec![Step::Send(wire)], clean);
        let mut response = loopback(address, Duration::from_secs(10))
            .send_streaming(&plan_request(), &Canceller::new())
            .unwrap();
        let mut body = Vec::new();
        let error = response.body_mut().read_to_end(&mut body).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                IoKind::UnexpectedEof | IoKind::ConnectionAborted
            ),
            "{error:?}"
        );
        finish(address, server);
    }
}

#[test]
fn a_head_that_never_arrives_ends_at_the_total_timeout() {
    let (go, held) = hold();
    let (address, server) = serve(vec![held], true);
    let total = Duration::from_secs(1);
    let started = Instant::now();
    let error = loopback(address, total)
        .send_streaming(&plan_request(), &Canceller::new())
        .unwrap_err();
    let elapsed = started.elapsed();
    assert_unavailable(&error);
    assert!(elapsed >= total, "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    drop(go);
    // The request was sent: it was the head the client waited for.
    assert!(was_asked(&finish(address, server)));
}

#[test]
fn a_refusal_whose_body_stalls_ends_at_the_total_timeout_not_the_idle_one() {
    // The head of a `503` arrives in time, with the first bytes of a body
    // that never goes on.
    let head = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 17\r\n\r\n{\"det";
    let (go, held) = hold();
    let (address, server) = serve(vec![Step::Send(head.to_vec()), held], true);
    let total = Duration::from_secs(1);
    let mut https = loopback(address, total);
    // Only an accepted answer is a stream that may fall silent this long.
    https.limits.stream_idle_timeout = Duration::from_secs(60);
    let started = Instant::now();
    let mut response = https
        .send_streaming(&plan_request(), &Canceller::new())
        .unwrap();
    assert_eq!(response.status(), 503);
    let mut body = Vec::new();
    let error = response.body_mut().read_to_end(&mut body).unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(error.kind(), IoKind::ConnectionAborted);
    assert_eq!(body, b"{\"det");
    assert!(elapsed >= total, "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    drop(go);
    assert!(was_asked(&finish(address, server)));
}

/// Sends plan requests over TLS to the loopback server and everything else
/// to the fake provider, so that a signed-in `Client` reads a real HTTP
/// body.
#[cfg(feature = "testing")]
#[derive(Debug)]
struct PlanOverTls {
    provider: crate::testing::FakeProvider,
    https: Https,
}

#[cfg(feature = "testing")]
impl Transport for PlanOverTls {
    fn send(&self, request: &HttpRequest) -> Result<crate::protocol::HttpResponse, crate::Error> {
        self.provider.send(request)
    }

    fn send_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<crate::protocol::StreamingResponse, crate::Error> {
        if request.url() == RESPONSES_URL {
            self.https.send_streaming(request, canceller)
        } else {
            self.provider.send_streaming(request, canceller)
        }
    }
}

#[cfg(feature = "testing")]
fn plan_client(address: SocketAddr) -> (crate::Client, crate::AccountId) {
    use crate::testing::{FakeProvider, FakeUser};
    use crate::{AppName, Client, store::MemoryStore};
    let provider = FakeProvider::new();
    let transport = PlanOverTls {
        provider: provider.clone(),
        https: loopback(address, Duration::from_secs(10)),
    };
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        MemoryStore::new(),
        transport,
    )
    .build();
    let mut sign_in = client.add_account_manually().unwrap();
    let user = FakeUser::new("owner@example.invalid");
    let redirect = provider.approve_manual(&sign_in, user).unwrap();
    let id = sign_in.finish(&redirect).unwrap().account().id().clone();
    (client, id)
}

#[cfg(feature = "testing")]
#[test]
fn cancelling_a_paused_stream_closes_its_tls_socket() {
    let (closed, observed) = mpsc::channel();
    let (address, server) = serve(
        vec![Step::Send(HEAD.to_vec()), Step::ObserveClose(closed)],
        false,
    );
    let (client, id) = plan_client(address);
    let stop = Canceller::new();
    let request = ResponseRequest::text("example", "Hello").unwrap();
    let mut stream = client
        .stream_response_cancellable(&id, &request, &stop)
        .unwrap();
    stop.cancel();
    assert!(
        observed
            .recv_timeout(Duration::from_secs(3))
            .expect("idle socket must close")
    );
    assert_eq!(
        stream.next().unwrap().unwrap_err().kind(),
        crate::ErrorKind::Cancelled
    );
    assert!(was_asked(&finish(address, server)));
}

#[cfg(feature = "testing")]
#[test]
fn a_completed_answer_cut_inside_its_framing_is_an_error_of_the_stream() {
    use crate::ErrorKind;

    let events = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"All of it\"}\n\n\
                  data: {\"type\":\"response.completed\"}\n\n";
    let chunked = |tail: &[u8]| [HEAD, tail].concat();
    let declared = |length: usize| {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n{events}").into_bytes()
    };
    let one_byte_short = format!("{:x}\r\n{events}", events.len() + 1).into_bytes();
    for (wire, complete) in [
        (
            chunked(&[chunk(events), b"0\r\n\r\n".to_vec()].concat()),
            true,
        ),
        (declared(events.len()), true),
        // Every event arrived, and the body did not end as announced: the
        // last chunk lacks a byte, its end marker never came, a byte of
        // the declared length is missing.
        (chunked(&one_byte_short), false),
        (chunked(&chunk(events)), false),
        (
            chunked(&[chunk(events), b"0 \r\n\r\n".to_vec()].concat()),
            false,
        ),
        (declared(events.len() + 1), false),
    ] {
        let (address, server) = serve(vec![Step::Send(wire)], true);
        let (client, id) = plan_client(address);

        let request = ResponseRequest::text("example-large", "Hello").unwrap();
        let items: Vec<_> = client.stream_response(&id, &request).unwrap().collect();
        let text: String = items
            .iter()
            .filter_map(|item| item.as_ref().ok()?.text_delta())
            .collect();
        assert_eq!(text, "All of it");
        let completed = items
            .iter()
            .flatten()
            .any(|event| event.event_type() == Some("response.completed"));
        assert_eq!(completed, complete);
        match items.last().unwrap() {
            Ok(_) => assert!(complete),
            Err(error) => {
                assert!(!complete);
                assert_eq!(error.kind(), ErrorKind::Temporary);
            }
        }
        finish(address, server);
    }
}

#[test]
fn cancellation_ends_a_tls_handshake_waiting_for_the_server_hello() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let https = loopback(listener.local_addr().unwrap(), Duration::from_secs(60));
    let stop = Canceller::new();
    let client_stop = stop.clone();
    let (blocked, waits) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let client = thread::spawn(move || {
        waiting::observe(blocked);
        let result = https.send_streaming(&plan_request(), &client_stop);
        done.send(result).unwrap();
    });
    let guard = Duration::from_secs(3);
    assert_eq!(waits.recv_timeout(guard).unwrap(), Wait::Read);
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(guard)).unwrap();
    let mut prefix = [0; 6];
    peer.read_exact(&mut prefix).unwrap();
    // A TLS handshake record carrying a ClientHello. The peer stays open
    // without sending a ServerHello until the cancelled client returns.
    assert_eq!((prefix[0], prefix[5]), (22, 1));
    stop.cancel();
    assert_unavailable(&finished.recv_timeout(guard).unwrap().unwrap_err());
    client.join().unwrap();
}
