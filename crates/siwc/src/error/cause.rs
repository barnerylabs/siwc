//! The safe underlying cause an [`Error`](super::Error) can name.

use std::error::Error as StdError;
use std::fmt;
use std::io;

/// Why a connection or a read failed, as far as the crate can say without
/// repeating anything it was told.
///
/// [`Error::source`](std::error::Error::source) and
/// [`Error::cause`](crate::Error::cause) return it where the crate knows the
/// cause: the built-in transports `Https` and `Ureq` when no answer arrived
/// or a streamed body broke off, a streamed body read through any
/// transport (from the `io::ErrorKind` of its reader), and the keychain
/// helpers' deadlines. Every other error has no cause: provider refusals,
/// whose diagnostics are the error's own accessors, local input and store
/// errors, an exchange the app cancelled, and an app's own `Transport`
/// error.
///
/// Both built-in transports name the same cause for the same failure, with
/// one exception: a forward proxy that does not open the `CONNECT` tunnel.
/// `Https` says why: `Io(PermissionDenied)` for a `403` or `407`,
/// `Io(NotConnected)` for any other refusing status such as a `502`,
/// `InvalidFraming` for a `101`, `ResponseTooLarge` for an answer head
/// beyond 16 KiB and `ConnectionClosed` for a proxy that closes before its
/// answer is complete. ureq reports all of these as one error that holds
/// only text, which the crate does not read, so `Ureq` names
/// `Io(NotConnected)` for each. A malformed proxy answer is
/// `InvalidFraming` on both.
///
/// Each value is a fixed category. It never wraps a dependency's error and
/// never holds provider text, a URL, a path or a secret, so its `Display`
/// and `Debug` are safe to log. Its text may change; match on the variant.
///
/// ```
/// use std::error::Error as _;
///
/// fn log_chain(error: &siwc::Error) {
///     eprintln!("{error}");
///     if let Some(cause) = error.source() {
///         eprintln!("  caused by: {cause}");
///     }
/// }
/// # log_chain(&siwc::Error::transport_unavailable());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCause {
    /// A deadline passed: the connect, total or idle timeout.
    TimedOut,
    /// The server refused the connection.
    ConnectionRefused,
    /// The connection was reset, or it closed before the answer was
    /// complete.
    ConnectionClosed,
    /// The TLS handshake or the TLS connection failed, for example because
    /// the certificate did not verify.
    Tls,
    /// The answer broke the HTTP/1.1 framing rules: a malformed head, chunk
    /// or header, also in a proxy's answer to `CONNECT`.
    InvalidFraming,
    /// The answer was larger than the transport's limit: its body, its head
    /// or a streamed body's trailers.
    ResponseTooLarge,
    /// Another input or output failure, of this kind. For example, a host
    /// name the system resolver cannot look up, or one without an address,
    /// is `NotFound`, and a request that never got a connection, or a
    /// tunnel the proxy did not open, `NotConnected`.
    Io(io::ErrorKind),
}

impl ErrorCause {
    /// The cause behind an I/O error: the crate's own cause when the error
    /// carries one, otherwise one read from its kind alone. Nothing else of
    /// the error is looked at.
    pub(crate) fn from_io(error: &io::Error) -> Self {
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Self>())
            .copied()
            .unwrap_or_else(|| Self::from_io_kind(error.kind()))
    }

    pub(crate) fn from_io_kind(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::TimedOut,
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof => Self::ConnectionClosed,
            other => Self::Io(other),
        }
    }
}

/// One fixed phrase per cause; `Io` adds the standard library's fixed name
/// of its kind.
impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut => f.write_str("a deadline passed"),
            Self::ConnectionRefused => f.write_str("the connection was refused"),
            Self::ConnectionClosed => f.write_str("the connection was reset or closed early"),
            Self::Tls => f.write_str("the TLS connection failed"),
            Self::InvalidFraming => f.write_str("the answer broke the HTTP framing"),
            Self::ResponseTooLarge => f.write_str("the answer was larger than the limit"),
            Self::Io(kind) => write!(f, "input or output failed: {kind}"),
        }
    }
}

impl StdError for ErrorCause {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_crates_own_cause_wins_over_the_io_kind() {
        let error = io::Error::new(io::ErrorKind::InvalidData, ErrorCause::ResponseTooLarge);
        assert_eq!(ErrorCause::from_io(&error), ErrorCause::ResponseTooLarge);
    }

    #[test]
    fn a_foreign_inner_error_is_ignored_and_only_its_kind_is_read() {
        let error = io::Error::new(io::ErrorKind::TimedOut, "secret-token in a message");
        let cause = ErrorCause::from_io(&error);
        assert_eq!(cause, ErrorCause::TimedOut);
        assert!(!format!("{cause} {cause:?}").contains("secret"));

        let other = ErrorCause::from_io(&io::Error::other("https://example.invalid/path"));
        assert_eq!(other, ErrorCause::Io(io::ErrorKind::Other));
        assert!(!format!("{other} {other:?}").contains("example"));
    }

    #[test]
    fn every_cause_displays_one_lowercase_phrase() {
        for cause in [
            ErrorCause::TimedOut,
            ErrorCause::ConnectionRefused,
            ErrorCause::ConnectionClosed,
            ErrorCause::Tls,
            ErrorCause::InvalidFraming,
            ErrorCause::ResponseTooLarge,
            ErrorCause::Io(io::ErrorKind::PermissionDenied),
        ] {
            let text = cause.to_string();
            assert!(text.starts_with(|c: char| c.is_ascii_lowercase()), "{text}");
            assert!(!text.ends_with('.'), "{text}");
        }
    }
}
