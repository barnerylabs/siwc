//! Local resolver and builder checks for the ureq transport.

use std::net::SocketAddr;
use std::time::Duration;

use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::NextTimeout;

use super::*;

#[derive(Debug)]
pub(super) struct LoopbackResolver(pub(super) SocketAddr);

impl Resolver for LoopbackResolver {
    fn resolve(
        &self,
        _uri: &Uri,
        _config: &Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let mut addresses = self.empty();
        addresses.push(self.0);
        Ok(addresses)
    }
}

#[test]
fn invalid_builder_limits_and_proxy_urls_are_refused() {
    for builder in [
        Ureq::builder().connect_timeout(Duration::ZERO),
        Ureq::builder().total_timeout(Duration::from_secs(86_401)),
        Ureq::builder().stream_idle_timeout(Duration::ZERO),
        Ureq::builder().max_response_len(0),
    ] {
        assert_eq!(builder.build().unwrap_err().kind(), ErrorKind::InvalidInput);
    }
    for url in [
        "https://proxy.invalid",
        "http://proxy.invalid:0",
        "https://user:secret@proxy.invalid:443",
        "socks5://proxy.invalid:1080",
        "http://proxy.invalid:443/path",
        "http://proxy.invalid:443?x=1",
        "http://proxy.invalid:443#part",
        "http://127.0.0.999:8080",
        "http://bad_host.invalid:8080",
        "http://-bad.invalid:8080",
        "http://bad-.invalid:8080",
        "http://[::zzz]:8080",
        "http://proxy.invalid:08080",
    ] {
        assert_eq!(
            Ureq::builder().proxy(url).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }
    for url in [
        "http://127.0.0.1:8080",
        "https://[::1]:8443",
        "https://proxy.example.invalid:443/",
    ] {
        Ureq::builder().proxy(url).unwrap().build().unwrap();
    }
}

#[test]
fn both_agents_report_a_failed_name_lookup_as_not_found() {
    // A label above 63 bytes: the system lookup refuses the name before
    // it would ask a name server, so nothing leaves the machine.
    let url = format!("https://{}.invalid/", "a".repeat(64));
    let http = Ureq::builder().build().unwrap();
    let guard = Arc::new(StreamGuard::new(None));
    for agent in [http.agent(false, None), http.agent(true, Some(guard))] {
        let error = agent.get(&url).call().unwrap_err();
        assert_eq!(
            cause::unavailable(&error).cause(),
            Some(crate::error::ErrorCause::Io(std::io::ErrorKind::NotFound))
        );
    }
}

#[test]
fn ureq_root_set_matches_unconstrained_https_anchors() {
    let mut actual = rustls::RootCertStore::empty();
    let certificates: Vec<_> = mozilla_certificates()
        .iter()
        .map(|certificate| CertificateDer::from(certificate.der().to_vec()))
        .collect();
    let (added, ignored) = actual.add_parsable_certificates(certificates);
    assert_eq!(ignored, 0);
    assert_eq!(added, actual.roots.len());
    let expected: Vec<_> = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .filter(|anchor| anchor.name_constraints.is_none())
        .collect();
    assert_eq!(actual.roots.len(), expected.len());
    for anchor in &actual.roots {
        assert!(anchor.name_constraints.is_none());
        assert!(expected.iter().any(|candidate| {
            anchor.subject == candidate.subject
                && anchor.subject_public_key_info == candidate.subject_public_key_info
        }));
    }
    for anchor in expected {
        assert_eq!(
            actual
                .roots
                .iter()
                .filter(|candidate| {
                    anchor.subject == candidate.subject
                        && anchor.subject_public_key_info == candidate.subject_public_key_info
                })
                .count(),
            1
        );
    }
}
