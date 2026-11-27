//! A loopback TLS peer that keeps sending chunk trailers after the last chunk.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::cancel::Canceller;
use crate::error::ErrorCause;
use crate::protocol::Jwks;
use crate::transport::Transport;

use super::Ureq;

const CA: &[u8] = include_bytes!("../../tests/support/tls/ca.pem");
const SERVER: &[u8] = include_bytes!("../../tests/support/tls/server.pem");
const KEY: &[u8] = include_bytes!("../../tests/support/tls/server.key");
const REFUSAL: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nTransfer-Encoding: chunked\r\n\r\n6\r\ndata:\n\r\n0\r\n";
const SUCCESS: &[u8] =
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\ndata:\n\r\n0\r\n";

fn read_head(stream: &mut impl Read) {
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap_or(0) == 0 {
            break;
        }
        head.push(byte[0]);
    }
}

struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    resume: mpsc::Sender<()>,
    ready: mpsc::Receiver<()>,
    handle: JoinHandle<()>,
}

fn serve(head: &'static [u8]) -> Server {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(SERVER)
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let running = Arc::clone(&stop);
    let (started, ready) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut stream = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), tcp);
        read_head(&mut stream);
        if stream.write_all(head).is_err() {
            return;
        }
        for index in 0.. {
            if running.load(Ordering::Acquire)
                || stream
                    .write_all(b"x-pad: 1\r\n")
                    .and_then(|()| stream.flush())
                    .is_err()
            {
                break;
            }
            if index == 64
                && (started.send(()).is_err()
                    || resumed.recv_timeout(Duration::from_secs(5)).is_err())
            {
                break;
            }
        }
    });
    Server {
        address,
        stop,
        ready,
        resume,
        handle,
    }
}

fn transport(address: SocketAddr) -> Ureq {
    let mut http = Ureq::builder()
        .total_timeout(Duration::from_secs(2))
        .stream_idle_timeout(Duration::from_secs(2))
        .add_root_certificates_pem(CA)
        .unwrap()
        .build()
        .unwrap();
    http.connect_to = Some(address);
    http
}

fn trailer_error(head: &'static [u8], cancel: bool) -> io::Error {
    let server = serve(head);
    let http = transport(server.address);
    let stop = Canceller::new();
    let mut response = http.send_streaming(&Jwks::request(), &stop).unwrap();
    assert_eq!(response.status(), if head == REFUSAL { 503 } else { 200 });
    let mut prefix = [0; 6];
    response.body_mut().read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"data:\n");
    let (reading, started) = mpsc::sync_channel(0);
    let (done, finished) = mpsc::channel();
    let client = thread::spawn(move || {
        reading.send(()).unwrap();
        let _ = done.send(response.body_mut().read(&mut [0; 1]));
    });
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    server.ready.recv_timeout(Duration::from_secs(2)).unwrap();
    if cancel {
        stop.cancel();
    }
    server.resume.send(()).unwrap();
    let result = finished.recv_timeout(Duration::from_secs(2));
    server.stop.store(true, Ordering::Release);
    server.handle.join().unwrap();
    client.join().unwrap();
    result.expect("trailer read did not stop").unwrap_err()
}

#[test]
fn ureq_streamed_refusal_with_endless_trailers_returns() {
    assert_cancelled(trailer_error(REFUSAL, true));
}

#[test]
fn ureq_streamed_body_read_with_endless_trailers_returns() {
    assert_cancelled(trailer_error(SUCCESS, true));
}

fn assert_cancelled(error: io::Error) {
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert!(error.get_ref().is_none(), "a cancelled read names no cause");
}

#[test]
fn ureq_streamed_body_without_cancellation_caps_raw_trailers() {
    let error = trailer_error(SUCCESS, false);
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    // The same cause `Https` names for trailers beyond its budget.
    assert_eq!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ErrorCause>()),
        Some(&ErrorCause::ResponseTooLarge)
    );
}
