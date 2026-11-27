//! Reading a safe cause off a ureq error without keeping any of it.

use std::io;

use crate::error::{Error, ErrorCause};
use crate::transport::cause;

/// The cause of a failed ureq exchange, when its variant says one. The
/// ureq error, which can quote a URL, a header or a certificate, is only
/// matched on and then dropped.
pub(super) fn of(error: &ureq::Error) -> Option<ErrorCause> {
    match error {
        ureq::Error::Timeout(_) => Some(ErrorCause::TimedOut),
        ureq::Error::Io(error) => Some(cause::of_io(error)),
        ureq::Error::Protocol(_) => Some(ErrorCause::InvalidFraming),
        ureq::Error::LargeResponseHeader(..) | ureq::Error::BodyExceedsLimit(_) => {
            Some(ErrorCause::ResponseTooLarge)
        }
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => Some(ErrorCause::Tls),
        // No address to connect to, as when `Https` resolves none.
        ureq::Error::HostNotFound => Some(ErrorCause::Io(io::ErrorKind::NotFound)),
        // No connector set up a connection: the request never got one.
        ureq::Error::ConnectionFailed => Some(ErrorCause::Io(io::ErrorKind::NotConnected)),
        // The proxy did not open the tunnel. The variant holds only text,
        // which is never read, so a refused `CONNECT`, a proxy that could
        // not reach the provider and one that closed early look the same.
        ureq::Error::ConnectProxyFailed(_) => Some(ErrorCause::Io(io::ErrorKind::NotConnected)),
        _ => None,
    }
}

/// [`Error::transport_unavailable`] with the cause `error` names, if any.
pub(super) fn unavailable(error: &ureq::Error) -> Error {
    match of(error) {
        Some(found) => cause::unavailable(found),
        None => Error::transport_unavailable(),
    }
}

/// An I/O error for a streamed body that keeps only `error`'s cause, so
/// no ureq text reaches the reader's caller.
pub(super) fn io(error: &ureq::Error) -> io::Error {
    let found = of(error).unwrap_or(ErrorCause::Io(io::ErrorKind::Other));
    let kind = match found {
        ErrorCause::Io(kind) => kind,
        ErrorCause::TimedOut => io::ErrorKind::TimedOut,
        ErrorCause::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        ErrorCause::ConnectionClosed => io::ErrorKind::ConnectionAborted,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_lookup_names_no_address_found() {
        assert_eq!(
            of(&ureq::Error::HostNotFound),
            Some(ErrorCause::Io(io::ErrorKind::NotFound))
        );
        assert_eq!(
            unavailable(&ureq::Error::HostNotFound).cause(),
            Some(ErrorCause::Io(io::ErrorKind::NotFound))
        );
    }

    #[test]
    fn a_tunnel_the_proxy_did_not_open_names_not_connected_without_reading_its_text() {
        let failed = ureq::Error::ConnectProxyFailed("secret-token at proxy.invalid".into());
        assert_eq!(
            of(&failed),
            Some(ErrorCause::Io(io::ErrorKind::NotConnected))
        );
        assert!(!format!("{:?}", unavailable(&failed)).contains("secret"));
    }

    #[test]
    fn a_connection_that_could_not_be_set_up_names_not_connected() {
        assert_eq!(
            of(&ureq::Error::ConnectionFailed),
            Some(ErrorCause::Io(io::ErrorKind::NotConnected))
        );
        assert_eq!(
            io(&ureq::Error::ConnectionFailed).kind(),
            io::ErrorKind::NotConnected
        );
    }
}
