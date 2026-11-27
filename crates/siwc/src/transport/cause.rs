//! The safe cause of a failed exchange of a built-in transport.

use std::io;

use crate::error::{Error, ErrorCause};

/// The cause behind an I/O error of a connection: a TLS failure when rustls
/// reported it, otherwise what [`ErrorCause::from_io`] reads. The rustls
/// error itself is only recognised, never kept.
pub(crate) fn of_io(error: &io::Error) -> ErrorCause {
    if error
        .get_ref()
        .is_some_and(|inner| inner.is::<rustls::Error>())
    {
        ErrorCause::Tls
    } else {
        ErrorCause::from_io(error)
    }
}

/// [`Error::transport_unavailable`] that names `cause`.
pub(crate) fn unavailable(cause: ErrorCause) -> Error {
    Error::transport_unavailable().with_cause(cause)
}
