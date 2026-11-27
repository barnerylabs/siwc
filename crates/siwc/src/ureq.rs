//! Blocking HTTP transport backed by the `ureq` crate.
//!
//! Requires the `ureq` feature. It sends the same requests as `Https`. Every
//! call opens a new connection and checks the server's certificate against
//! the Mozilla roots that carry no name constraint, which gives the same
//! trust as `Https` for the provider's two hosts.

mod cause;
mod exchange;
mod lookup;
mod proxy;
#[cfg(test)]
#[cfg(feature = "https")]
mod proxy_tests;
mod stream_guard;
#[cfg(test)]
mod stream_tests;
#[cfg(test)]
pub(crate) mod tests;

use std::fmt;
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use ureq::config::{AutoHeaderValue, Config};
use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};

use crate::error::{Error, ErrorKind};
use crate::transport::roots;

use self::proxy::parse_proxy;
use self::stream_guard::{GuardConnector, StreamGuard};

/// Largest timeout accepted by a builder.
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const USER_AGENT: &str = concat!("siwc/", env!("CARGO_PKG_VERSION"));

/// A blocking transport for the provider's two HTTPS hosts using `ureq`.
///
/// Requires the `ureq` feature. It verifies certificates against Mozilla DER
/// roots except those whose `Https` anchor carries a name constraint, with
/// any PEM roots supplied through [`UreqBuilder::add_root_certificates_pem`].
/// This matches `Https` trust for the two provider hosts. Only explicit
/// `http://` or `https://` forward `CONNECT` proxies are used. Environment
/// proxy variables are ignored. Each exchange uses a fresh agent, follows
/// no redirect and sends no `Accept-Encoding`. If another crate enables a
/// ureq decompressor, ureq may decode an unsolicited encoded body. Body limits apply to the bytes
/// read from ureq. Cookies and connections do not carry across exchanges.
/// The user agent is `siwc/<version>`.
///
/// `ureq` uses TLS 1.2 and 1.3 because its TLS configuration cannot restrict
/// protocol versions. The bundled `ring` provider is selected explicitly.
/// Ureq emits nothing unless the app installs a `log` logger and enables its
/// targets.
/// Its TRACE logs under the `ureq` and `ureq_proto` targets contain unredacted
/// request and response data, including bearer and refresh tokens. At DEBUG,
/// `ureq` logs selected request and response headers. An embedding app must
/// not enable TRACE or DEBUG for either target outside local debugging.
/// `Https` itself never logs. This feature turns on rustls's `logging`
/// feature for every rustls connection in the build, those of `Https`
/// included; it writes TLS protocol diagnostics without key material or
/// application plaintext.
///
/// The total timeout covers all of [`send`](crate::Transport::send). For
/// streaming responses, ureq applies a timeout to each connection phase and
/// each socket read. Those phase budgets do not form one total budget up to
/// the response head. After the head, every streamed body read also checks
/// cancellation and a 64 KiB raw-input budget between decoded output; a
/// refusal has a separate total body budget. A blocked socket read can take
/// up to its read timeout to notice cancellation or the refusal deadline.
/// Once the canceller fired, a body read fails with
/// [`std::io::ErrorKind::ConnectionAborted`] and no cause, as with `Https`,
/// except that a refusal body already read to its budget ends with `Ok(0)`.
/// Before the head, ureq checks the canceller only before it opens the
/// connection: an exchange cancelled later in its setup runs on, and a
/// failure there keeps its cause.
///
/// ```no_run
/// use siwc::{Transport, Ureq, protocol::Jwks};
/// let http = Ureq::new()?;
/// let response = http.send(&Jwks::request())?;
/// # let _ = response;
/// # Ok::<(), siwc::Error>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "ureq")))]
#[derive(Clone)]
pub struct Ureq {
    buffered: Config,
    streaming: Config,
    limits: Limits,
    #[cfg(test)]
    pub(crate) connect_to: Option<SocketAddr>,
}

impl Ureq {
    /// Uses a 10-second connection timeout, 30-second buffered exchange
    /// timeout, 1 MiB buffered body limit and 5-minute streaming read timeout.
    ///
    /// ```
    /// let http = siwc::Ureq::new()?;
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// The fixed defaults satisfy all builder checks; this constructor currently
    /// has no failing configuration.
    pub fn new() -> Result<Self, Error> {
        Self::builder().build()
    }

    /// Starts a builder with the defaults of [`Ureq::new`].
    ///
    /// ```
    /// let http = siwc::Ureq::builder().build()?;
    /// # Ok::<(), siwc::Error>(())
    /// ```
    pub fn builder() -> UreqBuilder {
        UreqBuilder {
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

    fn agent(&self, streaming: bool, guard: Option<Arc<StreamGuard>>) -> ureq::Agent {
        let config = if streaming {
            self.streaming.clone()
        } else {
            self.buffered.clone()
        };
        if let Some(guard) = guard {
            let connector = GuardConnector::new(guard);
            #[cfg(test)]
            if let Some(address) = self.connect_to {
                return ureq::Agent::with_parts(
                    config,
                    connector,
                    tests::LoopbackResolver(address),
                );
            }
            return ureq::Agent::with_parts(config, connector, lookup::Lookup::default());
        }
        #[cfg(test)]
        if let Some(address) = self.connect_to {
            return ureq::Agent::with_parts(
                config,
                ureq::unversioned::transport::DefaultConnector::new(),
                tests::LoopbackResolver(address),
            );
        }
        ureq::Agent::with_parts(
            config,
            ureq::unversioned::transport::DefaultConnector::new(),
            lookup::Lookup::default(),
        )
    }
}

impl fmt::Debug for Ureq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.limits.fmt_fields(f.debug_struct("Ureq"))
    }
}

/// Settings for a [`Ureq`] transport.
///
/// ```
/// use std::time::Duration;
/// let http = siwc::Ureq::builder()
///     .total_timeout(Duration::from_secs(20))
///     .build()?;
/// # Ok::<(), siwc::Error>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "ureq")))]
#[must_use]
pub struct UreqBuilder {
    limits: Limits,
    extra_roots: Vec<CertificateDer<'static>>,
    proxy: Option<ureq::Proxy>,
}

impl UreqBuilder {
    /// Maximum time to connect to one address, including TLS and proxy setup.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.limits.connect_timeout = timeout;
        self
    }

    /// Maximum time for a buffered exchange. Streaming uses this as the
    /// budget for each phase up to the response head and, separately, for a
    /// streamed refusal body. A blocked socket read can extend the refusal
    /// body call by up to the configured read timeout.
    pub fn total_timeout(mut self, timeout: Duration) -> Self {
        self.limits.total_timeout = timeout;
        self
    }

    /// Largest buffered response body in bytes. A streamed `2xx` body has
    /// no total size limit; each decoded read has a 64 KiB raw-input budget
    /// and a streamed refusal hands out at most 64 KiB and one byte of
    /// decoded body data, after its status and request ID.
    pub fn max_response_len(mut self, bytes: usize) -> Self {
        self.limits.max_response_len = bytes;
        self
    }

    /// Maximum wait per network read of a streamed response body.
    pub fn stream_idle_timeout(mut self, timeout: Duration) -> Self {
        self.limits.stream_idle_timeout = timeout;
        self
    }

    /// Adds PEM-encoded root certificates alongside the bundled Mozilla roots.
    /// The same 4 MiB validation as `HttpsBuilder`
    /// applies to each call.
    ///
    /// ```
    /// let result = siwc::Ureq::builder().add_root_certificates_pem(b"no certificate");
    /// assert_eq!(result.unwrap_err().kind(), siwc::ErrorKind::InvalidInput);
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] if the input exceeds 4 MiB, contains no roots,
    /// or a certificate block is malformed, even alongside a valid root.
    pub fn add_root_certificates_pem(mut self, pem: &[u8]) -> Result<Self, Error> {
        self.extra_roots.extend(roots::parse_pem(pem)?);
        Ok(self)
    }

    /// Uses an explicit HTTP or HTTPS forward `CONNECT` proxy.
    /// The URL must have a host and explicit nonzero port, without credentials,
    /// path, query or fragment. Environment proxy variables are ignored.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] for a proxy URL outside that syntax.
    pub fn proxy(mut self, url: &str) -> Result<Self, Error> {
        self.proxy = Some(parse_proxy(url)?);
        Ok(self)
    }

    /// Builds the transport and its TLS and timeout configuration.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] if a timeout or response limit is zero,
    /// or a timeout is longer than one day.
    pub fn build(self) -> Result<Ureq, Error> {
        let limits = self.limits;
        let timeout_ok = |duration: Duration| !duration.is_zero() && duration <= MAX_TIMEOUT;
        if !timeout_ok(limits.connect_timeout)
            || !timeout_ok(limits.total_timeout)
            || !timeout_ok(limits.stream_idle_timeout)
            || limits.max_response_len == 0
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "a ureq transport limit is invalid",
            ));
        }
        let mut certificates = mozilla_certificates();
        certificates.extend(
            self.extra_roots
                .iter()
                .map(|cert| Certificate::from_der(cert.as_ref()).to_owned()),
        );
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(RootCerts::new_with_certs(&certificates))
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .build();
        let base = || {
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .https_only(true)
                .max_redirects(0)
                .max_redirects_will_error(false)
                .proxy(self.proxy.clone())
                .tls_config(tls.clone())
                .user_agent(USER_AGENT)
                .accept(AutoHeaderValue::None)
                .accept_encoding(AutoHeaderValue::None)
                .max_response_header_size(16 * 1024)
                .input_buffer_size(16 * 1024)
                .output_buffer_size(16 * 1024)
                .max_idle_connections(0)
                .max_idle_connections_per_host(0)
                .timeout_connect(Some(limits.connect_timeout))
                .timeout_resolve(Some(limits.total_timeout))
        };
        let buffered = base().timeout_global(Some(limits.total_timeout)).build();
        let streaming = base()
            .timeout_send_request(Some(limits.total_timeout))
            .timeout_send_body(Some(limits.total_timeout))
            .timeout_recv_response(Some(limits.total_timeout))
            .timeout_per_read(Some(limits.stream_idle_timeout))
            .timeout_recv_body(None)
            .build();
        Ok(Ureq {
            buffered,
            streaming,
            limits,
            #[cfg(test)]
            connect_to: None,
        })
    }
}

fn mozilla_certificates() -> Vec<Certificate<'static>> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|cert| {
            let mut parsed = rustls::RootCertStore::empty();
            parsed.add(cert.clone()).ok()?;
            let anchor = parsed.roots.first()?;
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .any(|known| {
                    known.name_constraints.is_none()
                        && known.subject == anchor.subject
                        && known.subject_public_key_info == anchor.subject_public_key_info
                })
                .then(|| Certificate::from_der(cert.as_ref()).to_owned())
        })
        .collect()
}

impl fmt::Debug for UreqBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.limits.fmt_fields(f.debug_struct("UreqBuilder"))
    }
}

#[derive(Clone, Copy)]
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
