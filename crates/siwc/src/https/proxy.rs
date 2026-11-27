//! Explicit forward `CONNECT` proxy configuration and tunnel handshake.
//!
//! Supports both `http://host:port` and `https://host:port` proxies (including
//! IPv4 and bracketed IPv6 literals) without reading environment variables or
//! accepting credentials in URLs.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustls::pki_types::ServerName;
use zeroize::Zeroizing;

use crate::error::{Error, ErrorCause, ErrorKind};

use super::request::USER_AGENT;
use super::response::{HEAD_LIMIT, parse_connect_head};

/// Target port on the provider's hosts.
const TARGET_PORT: u16 = 443;

/// Whether the connection to the proxy itself uses plain TCP or TLS 1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProxyScheme {
    Http,
    Https,
}

/// A validated forward `CONNECT` proxy endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Proxy {
    pub(super) scheme: ProxyScheme,
    /// Unbracketed host or IP literal for DNS resolution and `ServerName`.
    pub(super) host: String,
    pub(super) port: u16,
    server_name: ServerName<'static>,
}

impl Proxy {
    /// Parses `http://host:port` or `https://host:port` (an optional single
    /// trailing `/` is permitted; user info, paths, queries and fragments are
    /// refused).
    pub(super) fn parse(url: &str) -> Result<Self, Error> {
        let invalid = || {
            Error::new(
                ErrorKind::InvalidInput,
                "the proxy URL must be http://<host>:<port> or https://<host>:<port>",
            )
        };
        if url.is_empty() || !url.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(invalid());
        }
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (ProxyScheme::Https, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (ProxyScheme::Http, rest)
        } else {
            return Err(invalid());
        };
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
        {
            return Err(invalid());
        }
        let (host, port_str, server_name) = split_authority(authority).ok_or_else(invalid)?;
        let port = parse_port(port_str).ok_or_else(invalid)?;
        Ok(Self {
            scheme,
            host,
            port,
            server_name,
        })
    }

    pub(super) fn server_name(&self) -> ServerName<'static> {
        self.server_name.clone()
    }
}

fn split_authority(authority: &str) -> Option<(String, &str, ServerName<'static>)> {
    if let Some(after_open) = authority.strip_prefix('[') {
        let (ipv6_str, after_close) = after_open.split_once(']')?;
        let port_str = after_close.strip_prefix(':')?;
        let addr: Ipv6Addr = ipv6_str.parse().ok()?;
        let server_name = ServerName::IpAddress(IpAddr::V6(addr).into());
        return Some((ipv6_str.to_owned(), port_str, server_name));
    }
    let (host, port_str) = authority.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        let server_name = ServerName::IpAddress(IpAddr::V4(addr).into());
        return Some((host.to_owned(), port_str, server_name));
    }
    if !is_dns_name(host) {
        return None;
    }
    let server_name = ServerName::try_from(host.to_owned()).ok()?;
    Some((host.to_owned(), port_str, server_name))
}

fn is_dns_name(host: &str) -> bool {
    host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        // Reject all-numeric TLDs such as `127.0.0.999` that failed IPv4 parsing.
        && host
            .rsplit_once('.')
            .map_or(host, |(_, last)| last)
            .bytes()
            .any(|b| b.is_ascii_alphabetic())
}

fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Sends `CONNECT <target_host>:443 HTTP/1.1` on `stream` and reads the proxy's
/// response head byte by byte so no tunneled TLS byte after `\r\n\r\n` is
/// consumed ahead of the TLS handshake.
pub(super) fn establish_tunnel(
    stream: &mut (impl Read + Write),
    target_host: &'static str,
) -> io::Result<()> {
    let request = format!(
        "CONNECT {target_host}:{TARGET_PORT} HTTP/1.1\r\n\
         Host: {target_host}:{TARGET_PORT}\r\n\
         User-Agent: {USER_AGENT}\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    read_connect_response(stream)
}

/// Reads a `CONNECT` response head (skipping interim `1xx` heads within the
/// 16 KiB head budget) and succeeds on `2xx`. A malformed head or a `101`
/// carries [`ErrorCause::InvalidFraming`], heads beyond the budget
/// [`ErrorCause::ResponseTooLarge`], as on the provider's own answer. A
/// `403` or `407` is `Io(PermissionDenied)`: the proxy refused this client.
/// Every other status, such as a `502` when the proxy could not reach the
/// provider, is `Io(NotConnected)`: the tunnel was never opened.
pub(super) fn read_connect_response(reader: &mut impl Read) -> io::Result<()> {
    let mut budget = HEAD_LIMIT;
    loop {
        let head = read_head_bytes(reader, &mut budget)?;
        let status = parse_connect_head(&head).map_err(|_| invalid(ErrorCause::InvalidFraming))?;
        if status == 101 {
            return Err(invalid(ErrorCause::InvalidFraming));
        }
        if status < 200 {
            continue;
        }
        if (200..=299).contains(&status) {
            return Ok(());
        }
        let kind = match status {
            403 | 407 => io::ErrorKind::PermissionDenied,
            _ => io::ErrorKind::NotConnected,
        };
        return Err(refused(kind));
    }
}

/// An unusable `CONNECT` answer, naming why.
fn invalid(cause: ErrorCause) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, cause)
}

/// A `CONNECT` the proxy did not grant. The cause rides along, so `kind`
/// is not read again as a closed connection.
fn refused(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, ErrorCause::Io(kind))
}

fn read_head_bytes(reader: &mut impl Read, budget: &mut usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut head = Zeroizing::new(Vec::with_capacity(*budget));
    let mut one = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if *budget == 0 {
            return Err(invalid(ErrorCause::ResponseTooLarge));
        }
        loop {
            match reader.read(&mut one) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(_) => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        *budget -= 1;
        head.push(one[0]);
    }
    Ok(head)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn http_and_https_proxy_urls_with_domains_ipv4_and_ipv6_parse() {
        let http = Proxy::parse("http://proxy.corp.example.invalid:8080").unwrap();
        assert_eq!(http.scheme, ProxyScheme::Http);
        assert_eq!(http.host, "proxy.corp.example.invalid");
        assert_eq!(http.port, 8080);

        let https = Proxy::parse("https://proxy.homelab.invalid:8443/").unwrap();
        assert_eq!(https.scheme, ProxyScheme::Https);
        assert_eq!(https.host, "proxy.homelab.invalid");
        assert_eq!(https.port, 8443);

        let v4 = Proxy::parse("https://127.0.0.1:3128").unwrap();
        assert_eq!(v4.host, "127.0.0.1");
        assert_eq!(v4.port, 3128);

        let v6 = Proxy::parse("http://[::1]:8888").unwrap();
        assert_eq!(v6.host, "::1");
        assert_eq!(v6.port, 8888);
    }

    #[test]
    fn proxy_urls_with_userinfo_paths_missing_ports_or_other_schemes_are_refused() {
        for bad in [
            "",
            "socks5://127.0.0.1:1080",
            "ftp://proxy.example:8080",
            "http://proxy.example",
            "http://proxy.example:0",
            "http://proxy.example:08080",
            "http://proxy.example:65536",
            "http://user:secret@proxy.example:8080",
            "http://user@proxy.example:8080",
            "http://proxy.example:8080/path",
            "http://proxy.example:8080?x=1",
            "http://proxy.example:8080#frag",
            "http://127.0.0.999:8080",
            "http://[::1]:bad",
            "http://[not-ipv6]:8080",
            "http://-bad.example:8080",
            "http://.bad.example:8080",
            "http://proxy.example :8080",
        ] {
            let error = Proxy::parse(bad).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{bad:?}");
        }
    }

    #[test]
    fn connect_reads_http_1_0_and_1_1_heads_without_consuming_tunnel_bytes() {
        let mut cursor = Cursor::new(
            b"HTTP/1.0 200 Connection established\r\nProxy-Agent: tinyproxy\r\n\r\n\x16\x03\x03"
                .to_vec(),
        );
        read_connect_response(&mut cursor).unwrap();
        let mut remaining = Vec::new();
        cursor.read_to_end(&mut remaining).unwrap();
        assert_eq!(
            remaining, b"\x16\x03\x03",
            "TLS handshake bytes after the blank line stay unread"
        );

        let mut interim =
            Cursor::new(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\nnext".to_vec());
        read_connect_response(&mut interim).unwrap();
        let mut after = Vec::new();
        interim.read_to_end(&mut after).unwrap();
        assert_eq!(after, b"next");

        for refused in [
            &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"[..],
            b"HTTP/1.1 403 Forbidden\r\n\r\n",
            b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
            b"HTTP/2 200\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBroken Header\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n",
        ] {
            assert!(read_connect_response(&mut Cursor::new(refused)).is_err());
        }
    }
}
