//! Reading extra PEM root certificates for enterprise gateways and homelabs.

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::error::{Error, ErrorKind};

/// Largest PEM input accepted in one call: large enough for a system bundle
/// such as `/etc/ssl/certs/ca-certificates.crt` while bounding allocations.
const MAX_PEM_LEN: usize = 4 * 1024 * 1024;

/// Parses one or more X.509 certificates from `pem` and checks that each can
/// serve as a trust anchor in [`RootCertStore`]. Text outside the certificate
/// blocks is ignored; any other `-----` boundary line is refused.
///
/// # Errors
///
/// [`ErrorKind::InvalidInput`] when `pem` exceeds 4 MiB, holds a malformed PEM
/// block or certificate, or contains no certificate at all.
pub(crate) fn parse_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, Error> {
    let invalid = |message| Error::new(ErrorKind::InvalidInput, message);
    if pem.len() > MAX_PEM_LEN {
        return Err(invalid("the root certificate PEM is larger than 4 MiB"));
    }
    let mut inside = false;
    for line in pem.split(|&byte| matches!(byte, b'\r' | b'\n')) {
        let line = line.trim_ascii_end();
        match line {
            b"-----BEGIN CERTIFICATE-----" if !inside => inside = true,
            b"-----END CERTIFICATE-----" if inside => inside = false,
            // RFC 7468 allows explanatory text between blocks, such as the
            // `Bag Attributes`, `subject=` and `issuer=` lines from `openssl`.
            _ if !line.starts_with(b"-----") => {}
            _ => return Err(invalid("the root certificate PEM cannot be read")),
        }
    }
    if inside {
        return Err(invalid("the root certificate PEM cannot be read"));
    }
    let mut check_store = RootCertStore::empty();
    let mut parsed = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem) {
        let cert = item.map_err(|_| invalid("the root certificate PEM cannot be read"))?;
        check_store
            .add(cert.clone())
            .map_err(|_| invalid("a root certificate in the PEM input is not valid"))?;
        parsed.push(cert);
    }
    if parsed.is_empty() {
        return Err(invalid("the PEM input contains no certificate"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &[u8] = include_bytes!("../../tests/support/tls/ca.pem");
    const PROXY_CA: &[u8] = include_bytes!("../../tests/support/tls/proxy-ca.pem");

    #[test]
    fn valid_pem_bundles_with_comments_and_multiple_anchors_are_accepted() {
        let mut bundle = b"# local homelab and enterprise roots\r\n".to_vec();
        bundle.extend_from_slice(CA);
        bundle.extend_from_slice(b"\n");
        bundle.extend_from_slice(PROXY_CA);

        let anchors = parse_pem(&bundle).unwrap();
        assert_eq!(anchors.len(), 2);
        let cr_terminated = String::from_utf8_lossy(CA)
            .replace("-----\n", "-----  \n")
            .replace('\n', "\r");
        assert_eq!(parse_pem(cr_terminated.as_bytes()).unwrap().len(), 1);
    }

    #[test]
    fn explanatory_text_from_openssl_around_certificates_is_ignored() {
        let mut bundle = b"Bag Attributes\n    localKeyID: 01 02 03\n".to_vec();
        bundle.extend_from_slice(b"subject=CN = Synthetic Test CA\n");
        bundle.extend_from_slice(b"issuer=CN = Synthetic Test CA\n");
        bundle.extend_from_slice(CA);
        bundle.extend_from_slice(b"---\nServer certificate\n");
        bundle.extend_from_slice(b" 1 s:CN = Synthetic Proxy CA\n");
        bundle.extend_from_slice(PROXY_CA);
        bundle.extend_from_slice(b"trailing text\n");

        assert_eq!(parse_pem(&bundle).unwrap().len(), 2);
    }

    #[test]
    fn empty_malformed_or_oversized_pem_inputs_are_refused() {
        let truncated = &CA[..CA.len() / 2];
        let bad_der = b"-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----\n";
        let oversized = vec![b' '; MAX_PEM_LEN + 1];
        let mut stray_end = CA.to_vec();
        stray_end.extend_from_slice(b"-----END CERTIFICATE-----\n");
        let mut private_key =
            b"-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----\n".to_vec();
        private_key.extend_from_slice(CA);
        let mut boundary_inside = CA.to_vec();
        let body = b"-----BEGIN CERTIFICATE-----\n".len();
        boundary_inside.splice(body..body, b"-----\n".iter().copied());

        for bad in [
            &b""[..],
            b"not a pem certificate",
            truncated,
            bad_der,
            &stray_end,
            &private_key,
            &boundary_inside,
            &oversized,
        ] {
            let error = parse_pem(bad).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
    }
}
