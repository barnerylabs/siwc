//! A blocking HTTPS transport for the crate's requests: sign-in, token
//! renewal, revocation, the JWKS, the model list and streamed plan requests
//! to `/v1/responses`.
//!
//! It sends only the [`HttpRequest`]s this crate builds. With it a
//! [`Client`](crate::Client) needs no HTTP client from the app:
//! [`Client::stream_response`](crate::Client::stream_response) sends a plan
//! request through [`Transport::send_streaming`] and hands out the answer
//! while it arrives.
//!
//! Requires the `https` feature. TLS is `rustls` with `ring` and the bundled
//! Mozilla roots; the HTTP/1.1 around it is written here, for exactly one
//! request and one response per connection.

mod body;
mod connect;
mod deadline;
mod exchange;
#[cfg(fuzzing)]
mod fuzzing;
mod input;
mod proxy;
#[cfg(test)]
pub(crate) mod proxy_tests;
#[cfg(test)]
mod renewal_tests;
mod request;
mod resolve;
mod response;
#[cfg(test)]
mod stream_tests;

use std::fmt;
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::Resumption;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

use crate::error::{Error, ErrorKind};
#[cfg(any(test, doc))]
use crate::protocol::HttpRequest;
#[cfg(any(test, doc))]
use crate::transport::Transport;
use crate::transport::roots;

#[cfg(fuzzing)]
#[doc(hidden)]
pub use fuzzing::{fuzz_response, fuzz_stream};

/// Longest timeout a builder accepts.
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// A blocking HTTPS client for the provider's two hosts.
///
/// Requires the `https` feature. It sends a request only to
/// `auth.openai.com` and `api.openai.com` on port 443, over TLS 1.3 with the
/// certificate checked against the Mozilla root certificates bundled into
/// the crate (plus any root certificates the app explicitly adds via
/// [`HttpsBuilder::add_root_certificates_pem`]). Each request opens its own
/// connection and follows no redirect. A status outside 100–599 is malformed
/// and returns [`Error::transport_unavailable`]. Environment proxy variables are never read implicitly; an app
/// may configure an explicit `http://` or `https://` forward `CONNECT` proxy
/// via [`HttpsBuilder::proxy`].
///
/// [`send`](Transport::send) returns a whole body, limited in size, within
/// one deadline. One instance and its clones run at most four system DNS
/// lookups at once, counting lookups that outlived their exchange; a further
/// exchange waits for a free one within its own deadline.
/// [`send_streaming`](Transport::send_streaming) returns when
/// the response head is there and reads the body as it arrives: memory
/// stays at one 16 KiB buffer however long the answer is. Which timeout
/// then holds depends on the status. Behind a `2xx` head a read of the
/// body fails when it yields no data within
/// [`stream_idle_timeout`](HttpsBuilder::stream_idle_timeout), however long
/// the answer takes in all; TLS records and chunk framing that arrive
/// meanwhile do not extend that wait. The body of any other
/// answer, a refusal, stays under
/// [`total_timeout`](HttpsBuilder::total_timeout) like a buffered one.
///
/// ```no_run
/// use siwc::protocol::Jwks;
/// use siwc::{Https, Transport};
///
/// let https = Https::new()?;
/// let keys = Jwks::from_response(&https.send(&Jwks::request())?)?;
/// # Ok::<(), siwc::Error>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "https")))]
#[derive(Clone)]
pub struct Https {
    config: Arc<ClientConfig>,
    limits: Limits,
    proxy: Option<proxy::Proxy>,
    resolver: resolve::Resolver,
    /// Where the tests' loopback server listens, in place of DNS.
    #[cfg(test)]
    pub(crate) connect_to: Option<SocketAddr>,
}

impl Https {
    /// Bundled root certificates, TLS 1.3, 10 s to connect, 30 s for the
    /// whole exchange (for a streamed answer with a `2xx` status: up to
    /// its response head), 1 MiB response body, and 5 minutes without a
    /// byte before the streamed body of a `2xx` answer fails. A streamed
    /// refusal has the 30 s for its body as well.
    ///
    /// ```
    /// let https = siwc::Https::new()?;
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::transport_unavailable`] if the TLS library refuses its
    /// configuration, which does not happen with the bundled one.
    pub fn new() -> Result<Self, Error> {
        Self::builder().build()
    }

    /// Starts from the limits of [`Https::new`].
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// let https = siwc::Https::builder()
    ///     .total_timeout(Duration::from_secs(10))
    ///     .build()?;
    /// # Ok::<(), siwc::Error>(())
    /// ```
    pub fn builder() -> HttpsBuilder {
        HttpsBuilder {
            limits: Limits {
                connect_timeout: Duration::from_secs(10),
                total_timeout: Duration::from_secs(30),
                max_response_len: 1024 * 1024,
                stream_idle_timeout: Duration::from_secs(300),
            },
            extra_roots: Vec::new(),
            proxy: None,
        }
    }

    fn with_roots(
        limits: Limits,
        roots: RootCertStore,
        proxy: Option<proxy::Proxy>,
    ) -> Result<Self, Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::transport_unavailable())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = Resumption::disabled();
        Ok(Self {
            config: Arc::new(config),
            limits,
            proxy,
            resolver: resolve::Resolver::default(),
            #[cfg(test)]
            connect_to: None,
        })
    }
}

impl fmt::Debug for Https {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.limits.fmt_fields(f.debug_struct("Https"))
    }
}

/// Settings for an [`Https`] transport, from [`Https::builder`].
///
/// Requires the `https` feature.
///
/// ```
/// use std::time::Duration;
///
/// let https = siwc::Https::builder()
///     .connect_timeout(Duration::from_secs(5))
///     .total_timeout(Duration::from_secs(20))
///     .max_response_len(256 * 1024)
///     .build()?;
/// # Ok::<(), siwc::Error>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "https")))]
#[must_use]
pub struct HttpsBuilder {
    limits: Limits,
    extra_roots: Vec<CertificateDer<'static>>,
    proxy: Option<proxy::Proxy>,
}

impl HttpsBuilder {
    /// Time to open the TCP connection to one address of the host (or proxy).
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.limits.connect_timeout = timeout;
        self
    }

    /// Time for the whole exchange, from the first lookup to the last byte
    /// of the answer. For a streamed answer
    /// ([`Transport::send_streaming`]) with a `2xx` status it ends with the
    /// response head, and
    /// [`stream_idle_timeout`](Self::stream_idle_timeout) bounds each read
    /// from there. Any other streamed answer is a refusal, and its body is
    /// still read within this time.
    pub fn total_timeout(mut self, timeout: Duration) -> Self {
        self.limits.total_timeout = timeout;
        self
    }

    /// Largest response body in bytes; a larger one fails as soon as the
    /// limit is crossed. A streamed answer has no limit and is never held
    /// whole.
    pub fn max_response_len(mut self, bytes: usize) -> Self {
        self.limits.max_response_len = bytes;
        self
    }

    /// Longest wait for decoded body bytes in one read of a `2xx` stream;
    /// 5 minutes unless set. TLS records and chunk framing read along the
    /// way share that deadline. A model may think before it writes, so a
    /// short timeout can cut off slow answers.
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// let https = siwc::Https::builder()
    ///     .stream_idle_timeout(Duration::from_secs(120))
    ///     .build()?;
    /// # Ok::<(), siwc::Error>(())
    /// ```
    pub fn stream_idle_timeout(mut self, timeout: Duration) -> Self {
        self.limits.stream_idle_timeout = timeout;
        self
    }

    /// Adds one or more PEM-encoded X.509 trust anchors alongside the bundled
    /// Mozilla roots, for a corporate TLS-inspecting gateway or a private
    /// internal CA (such as `mkcert` or `step-ca`).
    ///
    /// Standard WebPKI rules still hold: server leaf certificates must carry a
    /// matching `subjectAltName` (DNS name or IP address) and must not set
    /// `basicConstraints` `CA:TRUE` (issue a `CA:FALSE` leaf under your CA, or
    /// set `basicConstraints=CA:FALSE` when pinning a self-signed leaf). May be
    /// called more than once.
    ///
    /// Text outside the `CERTIFICATE` blocks is ignored, so the output of
    /// `openssl pkcs12 -nokeys` or `openssl s_client -showcerts` can be passed
    /// as it is. Any other PEM block, such as a private key, is refused.
    ///
    /// ```no_run
    /// let ca_pem = std::fs::read("/etc/corp/root-ca.pem")?;
    /// let https = siwc::Https::builder()
    ///     .add_root_certificates_pem(&ca_pem)?
    ///     .build()?;
    /// # drop(https);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when `pem` is empty, larger than 4 MiB, or
    /// contains a malformed PEM block or certificate.
    pub fn add_root_certificates_pem(mut self, pem: &[u8]) -> Result<Self, Error> {
        self.extra_roots.extend(roots::parse_pem(pem)?);
        Ok(self)
    }

    /// Tunnels every request through an explicit HTTP `CONNECT` forward proxy
    /// (`http://<host>:<port>` or `https://<host>:<port>`, with a domain name,
    /// IPv4 address or bracketed IPv6 address).
    ///
    /// For an `https://` proxy, an outer TLS 1.3 handshake to the proxy is
    /// verified against the transport's root certificates (including any added
    /// with [`add_root_certificates_pem`](Self::add_root_certificates_pem))
    /// before `CONNECT` is sent; the inner end-to-end TLS 1.3 handshake to
    /// `auth.openai.com` or `api.openai.com` always runs inside the tunnel
    /// before any request byte is written. User info (`user:pass@`), paths,
    /// queries and other schemes are refused, and environment variables such
    /// as `HTTPS_PROXY` are never read implicitly.
    ///
    /// ```
    /// let https = siwc::Https::builder()
    ///     .proxy("http://proxy.corp.example.invalid:8080")?
    ///     .build()?;
    /// # drop(https);
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when `url` is not a valid `http://` or
    /// `https://` `host:port` authority without credentials or path.
    pub fn proxy(mut self, url: &str) -> Result<Self, Error> {
        self.proxy = Some(proxy::Proxy::parse(url)?);
        Ok(self)
    }

    /// The transport with these settings.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when a timeout is zero or longer than a
    /// day, or the response limit is zero.
    /// [`Error::transport_unavailable`] if the TLS library refuses its
    /// configuration.
    pub fn build(self) -> Result<Https, Error> {
        let limits = self.limits;
        let timeout_ok = |timeout: Duration| !timeout.is_zero() && timeout <= MAX_TIMEOUT;
        if !timeout_ok(limits.connect_timeout)
            || !timeout_ok(limits.total_timeout)
            || !timeout_ok(limits.stream_idle_timeout)
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "an HTTPS timeout is zero or longer than a day",
            ));
        }
        if limits.max_response_len == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "the HTTPS response limit is zero",
            ));
        }
        let mut roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        for cert in self.extra_roots {
            roots.add(cert).map_err(|_| {
                Error::new(ErrorKind::InvalidInput, "a root certificate is invalid")
            })?;
        }
        Https::with_roots(limits, roots, self.proxy)
    }
}

impl fmt::Debug for HttpsBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.limits.fmt_fields(f.debug_struct("HttpsBuilder"))
    }
}

/// The four limits of an exchange.
#[derive(Debug, Clone, Copy)]
struct Limits {
    connect_timeout: Duration,
    total_timeout: Duration,
    max_response_len: usize,
    stream_idle_timeout: Duration,
}

impl Limits {
    fn fmt_fields(&self, mut debug: fmt::DebugStruct<'_, '_>) -> fmt::Result {
        debug
            .field("connect_timeout", &self.connect_timeout)
            .field("total_timeout", &self.total_timeout)
            .field("max_response_len", &self.max_response_len)
            .field("stream_idle_timeout", &self.stream_idle_timeout)
            .finish()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::{ErrorKind as IoKind, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};

    use super::*;

    const CA: &[u8] = include_bytes!("../tests/support/tls/ca.pem");
    const PROXY_CA: &[u8] = include_bytes!("../tests/support/tls/proxy-ca.pem");
    const PROXY_CERT: &[u8] = include_bytes!("../tests/support/tls/proxy.pem");
    const SELF_SIGNED_LEAF: &[u8] = include_bytes!("../tests/support/tls/self-signed-leaf.pem");
    const SELF_SIGNED_CA_LEAF: &[u8] =
        include_bytes!("../tests/support/tls/self-signed-ca-leaf.pem");
    pub(super) const KEY: &[u8] = include_bytes!("../tests/support/tls/server.key");
    pub(super) const SERVER: &[u8] = include_bytes!("../tests/support/tls/server.pem");
    const WRONG_NAME: &[u8] = include_bytes!("../tests/support/tls/wrong-name.pem");
    const UNKNOWN_ISSUER: &[u8] = include_bytes!("../tests/support/tls/unknown-issuer.pem");

    /// A transport that trusts only the test CA and connects to `address`
    /// whatever the host.
    pub(crate) fn loopback(address: SocketAddr, total_timeout: Duration) -> Https {
        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(CA) {
            roots.add(certificate.unwrap()).unwrap();
        }
        let mut limits = Https::builder().limits;
        limits.total_timeout = total_timeout;
        let mut https = Https::with_roots(limits, roots, None).unwrap();
        https.connect_to = Some(address);
        https
    }

    /// What a test server saw: the plaintext it received and the protocol
    /// it agreed on.
    #[derive(Debug)]
    pub(crate) struct Seen {
        pub(crate) received: Vec<u8>,
        alpn: Option<Vec<u8>>,
    }

    /// A TLS 1.3 server on a loopback port that presents `chain`, reads one
    /// request and answers with `answer`, then closes without `close_notify`.
    pub(crate) fn serve(chain: &[u8], answer: &'static [u8]) -> (SocketAddr, JoinHandle<Seen>) {
        serve_before_answer(chain, answer, || {})
    }

    /// A TLS 1.2-only peer, used to guard the version pin when ureq enables
    /// the `tls12` rustls feature in the same build.
    #[cfg(feature = "ureq")]
    pub(crate) fn serve_tls12(answer: &'static [u8]) -> (SocketAddr, JoinHandle<Vec<u8>>) {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(SERVER)
            .map(Result::unwrap)
            .collect();
        let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), tcp);
            let mut received = Vec::new();
            let mut buffer = [0; 4096];
            while !complete(&received) {
                match tls.read(&mut buffer) {
                    Ok(0) | Err(_) => return received,
                    Ok(read) => received.extend_from_slice(&buffer[..read]),
                }
            }
            tls.write_all(answer).unwrap();
            tls.flush().unwrap();
            received
        });
        (address, server)
    }

    #[cfg(feature = "ureq")]
    #[test]
    fn tls12_only_server_is_refused_even_when_ureq_enables_rustls_tls12() {
        let (address, server) = serve_tls12(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        let error = loopback(address, Duration::from_secs(3))
            .send(&token_request())
            .unwrap_err();
        assert_unavailable(&error);
        assert!(server.join().unwrap().is_empty());
    }

    pub(crate) fn serve_before_answer(
        chain: &[u8],
        answer: &'static [u8],
        on_request: impl FnOnce() + Send + 'static,
    ) -> (SocketAddr, JoinHandle<Seen>) {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain)
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
                    Ok(0) | Err(_) => break,
                    Ok(read) => received.extend_from_slice(&buffer[..read]),
                }
            }
            let alpn = tls.conn.alpn_protocol().map(<[u8]>::to_vec);
            if complete(&received) {
                on_request();
                tls.write_all(answer).unwrap();
                tls.flush().unwrap();
            }
            Seen { received, alpn }
        });
        (address, thread)
    }

    /// What the server received, once its thread has ended. A server that
    /// still waits for a connection, because the client gave up before it
    /// made one, gets one here that says nothing: the test fails on what it
    /// asserts next and never hangs on the thread.
    pub(crate) fn finish<T>(address: SocketAddr, server: JoinHandle<T>) -> T {
        drop(TcpStream::connect_timeout(&address, Duration::from_secs(1)));
        server.join().unwrap()
    }

    /// Whether `bytes` hold a whole request: the head and the body its
    /// `Content-Length` announces.
    pub(crate) fn complete(bytes: &[u8]) -> bool {
        let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
            return false;
        };
        let head = std::str::from_utf8(&bytes[..end]).unwrap();
        let length = head
            .split("\r\n")
            .find_map(|line| {
                line.split_once(": ")
                    .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
                    .map(|(_, value)| value)
            })
            .map_or(0, |value| value.parse::<usize>().unwrap());
        bytes.len() >= end + 4 + length
    }

    pub(crate) fn token_request() -> HttpRequest {
        HttpRequest::post_form(
            "https://auth.openai.com/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", "rt-synthetic"),
            ],
        )
    }

    pub(crate) fn assert_unavailable(error: &Error) {
        assert!(error.is_temporary());
        assert_eq!(error.to_string(), "the provider could not be reached");
        let debug = format!("{error:?}");
        for detail in ["127.0.0.1", "auth.openai.com", "certificate", "os error"] {
            assert!(!debug.contains(detail), "{debug}");
        }
    }

    #[test]
    fn a_request_and_its_answer_arrive_intact_over_tls() {
        let (address, server) = serve(
            SERVER,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        );
        let response = loopback(address, Duration::from_secs(10))
            .send(&token_request())
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"{\"ok\":true}");

        let seen = server.join().unwrap();
        let expected = format!(
            "POST /oauth/token HTTP/1.1\r\n\
             Host: auth.openai.com\r\n\
             accept: application/json\r\n\
             content-type: application/x-www-form-urlencoded\r\n\
             Content-Length: 51\r\n\
             Connection: close\r\n\
             User-Agent: siwc/{}\r\n\r\n\
             grant_type=refresh_token&refresh_token=rt-synthetic",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(String::from_utf8(seen.received).unwrap(), expected);
        assert_eq!(seen.alpn.as_deref(), Some(&b"http/1.1"[..]));
    }

    #[test]
    fn a_redirect_is_returned_and_not_followed() {
        let (address, server) = serve(
            SERVER,
            b"HTTP/1.1 302 Found\r\nLocation: https://api.openai.com/elsewhere\r\nContent-Length: 5\r\n\r\nmoved",
        );
        let response = loopback(address, Duration::from_secs(10))
            .send(&token_request())
            .unwrap();
        assert_eq!(response.status(), 302);
        assert_eq!(response.body(), b"moved");
        assert!(!server.join().unwrap().received.is_empty());
    }

    #[test]
    fn a_certificate_for_another_name_fails_before_any_request_byte() {
        let (address, server) = serve(WRONG_NAME, b"");
        let error = loopback(address, Duration::from_secs(10))
            .send(&token_request())
            .unwrap_err();
        assert_unavailable(&error);
        assert!(server.join().unwrap().received.is_empty());
    }

    #[test]
    fn a_certificate_from_an_unknown_ca_fails_before_any_request_byte() {
        let (address, server) = serve(UNKNOWN_ISSUER, b"");
        let error = loopback(address, Duration::from_secs(10))
            .send(&token_request())
            .unwrap_err();
        assert_unavailable(&error);
        assert!(server.join().unwrap().received.is_empty());
    }

    #[test]
    fn a_server_that_never_answers_ends_at_the_total_timeout() {
        // Connections complete in the kernel's backlog; nobody accepts them.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let total = Duration::from_millis(300);
        let started = Instant::now();
        let error = loopback(listener.local_addr().unwrap(), total)
            .send(&token_request())
            .unwrap_err();
        let elapsed = started.elapsed();
        assert_unavailable(&error);
        assert!(elapsed >= total, "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }

    #[test]
    fn a_url_outside_the_two_hosts_is_refused_without_a_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let https = loopback(listener.local_addr().unwrap(), Duration::from_secs(10));
        for url in [
            "https://example.com/oauth/token",
            "https://auth.openai.com:8443/oauth/token",
            "http://auth.openai.com/oauth/token",
        ] {
            let error = https.send(&HttpRequest::get(url)).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{url}");
        }
        listener.set_nonblocking(true).unwrap();
        let pending = listener.accept().unwrap_err();
        assert_eq!(pending.kind(), IoKind::WouldBlock, "no connection was made");
    }

    #[test]
    fn the_defaults_load_the_bundled_roots_and_offer_http_1_1_only() {
        assert!(!webpki_roots::TLS_SERVER_ROOTS.is_empty());
        let https = Https::new().unwrap();
        assert_eq!(https.config.alpn_protocols, [b"http/1.1".to_vec()]);
    }

    #[test]
    fn debug_shows_the_limits_and_nothing_else() {
        let builder = Https::builder().max_response_len(4096);
        assert_eq!(
            format!("{builder:?}"),
            "HttpsBuilder { connect_timeout: 10s, total_timeout: 30s, max_response_len: 4096, stream_idle_timeout: 300s }"
        );
        let https = builder.build().unwrap();
        assert_eq!(
            format!("{https:?}"),
            "Https { connect_timeout: 10s, total_timeout: 30s, max_response_len: 4096, stream_idle_timeout: 300s }"
        );
    }

    #[test]
    fn zero_or_overlong_limits_are_refused() {
        let zero = Duration::ZERO;
        let long = MAX_TIMEOUT + Duration::from_secs(1);
        for builder in [
            Https::builder().connect_timeout(zero),
            Https::builder().total_timeout(zero),
            Https::builder().total_timeout(long),
            Https::builder().connect_timeout(long),
            Https::builder().stream_idle_timeout(zero),
            Https::builder().stream_idle_timeout(long),
            Https::builder().max_response_len(0),
        ] {
            let error = builder.build().unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
        assert!(Https::builder().total_timeout(MAX_TIMEOUT).build().is_ok());
    }

    #[test]
    fn extra_root_certificates_trust_enterprise_and_homelab_cas_under_webpki_rules() {
        let (address, server) = serve(SERVER, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        let mut https = Https::builder()
            .add_root_certificates_pem(CA)
            .unwrap()
            .build()
            .unwrap();
        https.connect_to = Some(address);
        let response = https.send(&token_request()).unwrap();
        assert_eq!(response.status(), 200);
        assert!(!server.join().unwrap().received.is_empty());

        // A pinned self-signed homelab leaf with CA:FALSE + SAN verifies cleanly.
        let (leaf_addr, leaf_server) = serve(
            SELF_SIGNED_LEAF,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        );
        let mut pinned = Https::builder()
            .add_root_certificates_pem(SELF_SIGNED_LEAF)
            .unwrap()
            .build()
            .unwrap();
        pinned.connect_to = Some(leaf_addr);
        assert_eq!(pinned.send(&token_request()).unwrap().status(), 200);
        assert!(!leaf_server.join().unwrap().received.is_empty());

        // A self-signed cert with CA:TRUE presented as a server leaf is rejected before any byte.
        let (ca_leaf_addr, ca_leaf_server) = serve(SELF_SIGNED_CA_LEAF, b"");
        let mut wrong_ku = Https::builder()
            .add_root_certificates_pem(SELF_SIGNED_CA_LEAF)
            .unwrap()
            .build()
            .unwrap();
        wrong_ku.connect_to = Some(ca_leaf_addr);
        let error = wrong_ku.send(&token_request()).unwrap_err();
        assert_unavailable(&error);
        assert!(ca_leaf_server.join().unwrap().received.is_empty());
    }

    #[test]
    fn an_http_connect_proxy_tunnels_end_to_end_tls_without_seeing_plaintext() {
        let (upstream_addr, upstream_server) = serve(
            SERVER,
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        );
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_thread = thread::spawn(move || {
            let (mut client, _) = proxy_listener.accept().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                client.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            let connect_req = String::from_utf8(head).unwrap();
            // Answer HTTP/1.0 200 as classic forward proxies (Squid, tinyproxy) do.
            client
                .write_all(b"HTTP/1.0 200 Connection established\r\n\r\n")
                .unwrap();
            let mut upstream = std::net::TcpStream::connect(upstream_addr).unwrap();
            let mut client_clone = client.try_clone().unwrap();
            let mut upstream_clone = upstream.try_clone().unwrap();
            let c2u = thread::spawn(move || {
                let mut copied = Vec::new();
                let mut buf = [0u8; 4096];
                while let Ok(n) = client_clone.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    copied.extend_from_slice(&buf[..n]);
                    if upstream_clone.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                let _ = upstream_clone.shutdown(std::net::Shutdown::Write);
                copied
            });
            let _ = std::io::copy(&mut upstream, &mut client);
            let _ = client.shutdown(std::net::Shutdown::Write);
            (connect_req, c2u.join().unwrap())
        });

        let https = Https::builder()
            .add_root_certificates_pem(CA)
            .unwrap()
            .proxy(&format!("http://127.0.0.1:{}", proxy_addr.port()))
            .unwrap()
            .build()
            .unwrap();
        // Debug never reveals the proxy host or port.
        assert_eq!(
            format!("{https:?}"),
            "Https { connect_timeout: 10s, total_timeout: 30s, max_response_len: 1048576, stream_idle_timeout: 300s }"
        );
        // Non-provider URLs are still refused before opening any connection to the proxy.
        assert_eq!(
            https
                .send(&HttpRequest::get("https://example.com/"))
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );

        let response = https.send(&token_request()).unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"{\"ok\":true}");

        let (connect_req, tunneled_bytes) = proxy_thread.join().unwrap();
        assert!(
            connect_req.starts_with(
                "CONNECT auth.openai.com:443 HTTP/1.1\r\nHost: auth.openai.com:443\r\n"
            )
        );
        assert!(
            !String::from_utf8_lossy(&tunneled_bytes).contains("rt-synthetic"),
            "proxy sees only encrypted TLS records"
        );
        assert!(!upstream_server.join().unwrap().received.is_empty());
    }

    #[test]
    fn an_https_connect_proxy_with_a_homelab_ca_tunnels_end_to_end_tls_and_refuses_bad_status() {
        let (upstream_addr, upstream_server) =
            serve(SERVER, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        let proxy_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(PROXY_CERT)
            .map(Result::unwrap)
            .collect();
        let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut proxy_tls_cfg = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(proxy_chain, key)
            .unwrap();
        proxy_tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let proxy_tls_cfg = Arc::new(proxy_tls_cfg);

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let cfg_clone = Arc::clone(&proxy_tls_cfg);
        let proxy_thread = thread::spawn(move || {
            let (tcp, _) = proxy_listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let conn = ServerConnection::new(cfg_clone).unwrap();
            let mut outer = StreamOwned::new(conn, tcp);
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                outer.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            outer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
            outer.flush().unwrap();

            let mut upstream = std::net::TcpStream::connect(upstream_addr).unwrap();
            outer.sock.set_nonblocking(true).unwrap();
            upstream.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut c_buf = [0u8; 4096];
            let mut u_buf = [0u8; 4096];
            while Instant::now() < deadline {
                let mut progressed = false;
                match outer.read(&mut c_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        progressed = true;
                        upstream.set_nonblocking(false).unwrap();
                        if upstream.write_all(&c_buf[..n]).is_err() {
                            break;
                        }
                        upstream.set_nonblocking(true).unwrap();
                    }
                    Err(e) if e.kind() == IoKind::WouldBlock => {}
                    Err(_) => break,
                }
                match upstream.read(&mut u_buf) {
                    Ok(0) => {
                        outer.sock.set_nonblocking(false).unwrap();
                        outer.conn.send_close_notify();
                        let _ = outer.flush();
                        break;
                    }
                    Ok(n) => {
                        progressed = true;
                        outer.sock.set_nonblocking(false).unwrap();
                        if outer.write_all(&u_buf[..n]).is_err() || outer.flush().is_err() {
                            break;
                        }
                        outer.sock.set_nonblocking(true).unwrap();
                    }
                    Err(e) if e.kind() == IoKind::WouldBlock => {}
                    Err(_) => break,
                }
                if !progressed {
                    thread::yield_now();
                }
            }
            String::from_utf8(head).unwrap()
        });

        // Connect over HTTPS using the IPv4 SAN (127.0.0.1) in `proxy.pem`, trusting `PROXY_CA` + `CA`.
        let https = Https::builder()
            .add_root_certificates_pem(PROXY_CA)
            .unwrap()
            .add_root_certificates_pem(CA)
            .unwrap()
            .proxy(&format!("https://127.0.0.1:{}", proxy_addr.port()))
            .unwrap()
            .build()
            .unwrap();
        let response = https.send(&token_request()).unwrap();
        assert_eq!(response.status(), 200);
        let connect_head = proxy_thread.join().unwrap();
        assert!(connect_head.starts_with("CONNECT auth.openai.com:443 HTTP/1.1\r\n"));
        assert!(!upstream_server.join().unwrap().received.is_empty());

        // A proxy answering 407 fails before any inner TLS handshake or request byte.
        let refusing_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let refusing_addr = refusing_proxy.local_addr().unwrap();
        let refuser = thread::spawn(move || {
            let (mut tcp, _) = refusing_proxy.accept().unwrap();
            let mut buf = [0u8; 512];
            let _ = tcp.read(&mut buf);
            tcp.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .unwrap();
        });
        let denied = Https::builder()
            .proxy(&format!("http://127.0.0.1:{}", refusing_addr.port()))
            .unwrap()
            .build()
            .unwrap()
            .send(&token_request())
            .unwrap_err();
        assert_unavailable(&denied);
        refuser.join().unwrap();
    }
}
