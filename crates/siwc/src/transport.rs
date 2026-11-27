//! The seam between the crate and the network.

use std::fmt;
use std::sync::Arc;

use crate::cancel::Canceller;
use crate::error::Error;
use crate::protocol::{HttpRequest, HttpResponse, StreamingResponse};

pub(crate) mod buffer;
#[cfg(any(feature = "https", feature = "ureq"))]
pub(crate) mod cause;
#[cfg(all(test, feature = "https", feature = "ureq"))]
mod contract_tests;
#[cfg(any(feature = "https", feature = "ureq"))]
pub(crate) mod endpoint;
#[cfg(any(feature = "https", feature = "ureq"))]
pub(crate) mod roots;

/// Sends the crate's requests to the provider.
///
/// The crate builds every request as an [`HttpRequest`] and reads every
/// response as an [`HttpResponse`]; a transport carries them and decides
/// nothing. An app that already has an HTTP client implements this trait
/// over it.
///
/// An implementation has to
///
/// - send the method, URL, headers and body exactly as given;
/// - verify the server's certificate;
/// - follow no redirect;
/// - give up after a deadline, and refuse a response body above a limit of
///   its choice (one mebibyte is plenty);
/// - return valid final statuses, including `4xx` and `5xx`, so the crate can
///   read the provider's error. Reject statuses outside 100–599 as malformed;
/// - for repeated `Retry-After` fields, pass the longest numeric wait in seconds.
///   Use a nonnumeric value only if there is no numeric wait;
/// - treat requests and responses as secrets, including when logging.
///
/// `Https` emits no logs. `Ureq` uses dependencies whose `log` TRACE output
/// includes unredacted requests and responses if the app enables those targets;
/// its `ureq::Ureq` documentation describes the required logging settings.
///
/// [`send`](Self::send) is the only required method. Override
/// [`send_cancellable`](Self::send_cancellable) to stop a token renewal during
/// connection setup. A transport that can stream a response body implements
/// [`send_streaming`](Self::send_streaming), which
/// [`Client::stream_response`](crate::Client::stream_response) uses.
///
/// **Compatibility:** a release that is not a breaking one adds no required
/// method or supertrait to this trait and keeps it usable as
/// `dyn Transport`. A new method comes with a default, and new response
/// metadata goes onto [`HttpResponse`] and [`StreamingResponse`].
///
/// ```
/// use siwc::protocol::{HttpRequest, HttpResponse, Jwks};
/// use siwc::{Error, Transport};
///
/// /// Stands in for the app's HTTP client.
/// #[derive(Debug)]
/// struct Offline;
///
/// impl Transport for Offline {
///     fn send(&self, _request: &HttpRequest) -> Result<HttpResponse, Error> {
///         // A real implementation sends the request here and wraps the
///         // status and body it received in `HttpResponse::new`.
///         Err(Error::transport_unavailable())
///     }
/// }
///
/// let error = Offline.send(&Jwks::request()).unwrap_err();
/// assert!(error.is_temporary());
/// ```
pub trait Transport: Send + Sync + fmt::Debug {
    /// Sends `request` and returns the status and body of the response.
    ///
    /// # Errors
    ///
    /// [`Error::transport_unavailable`] when no response arrived: no
    /// connection, a failed TLS handshake, a deadline or a body above the
    /// limit, or a malformed status outside 100–599. A valid refusal is a response.
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error>;

    /// Sends a buffered request that may be stopped up to its first write.
    ///
    /// The client uses this for token renewal and the buffered streaming
    /// fallback. Check `canceller` during connection setup and immediately
    /// before writing the first request byte.
    /// Once writing starts, finish the exchange under the usual deadline: the
    /// provider may have rotated the refresh token and the client needs its answer.
    ///
    /// The default checks once before calling [`send`](Self::send). Override
    /// it if the underlying HTTP client can also cancel connection setup.
    ///
    /// A protocol caller can use the same method to fetch verification keys.
    /// Leave renewal to [`Client`](crate::Client), which stores the successor
    /// under the account lock even if cancellation arrived after the first write.
    ///
    /// ```
    /// use siwc::{Canceller, Error, Transport, protocol::Jwks};
    ///
    /// # fn keys(transport: &dyn Transport, stop: &Canceller) -> Result<Jwks, Error> {
    /// let response = transport.send_cancellable(&Jwks::request(), stop)?;
    /// Jwks::from_response(&response)
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send). A cancellation before writing is a transport
    /// failure; the client reports [`Cancelled`](crate::ErrorKind::Cancelled).
    fn send_cancellable(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<HttpResponse, Error> {
        if canceller.is_cancelled() {
            return Err(Error::transport_unavailable());
        }
        self.send(request)
    }

    /// Sends `request` and returns as soon as the response head is there,
    /// with the body left to read piece by piece.
    ///
    /// [`Client::stream_response`](crate::Client::stream_response) sends a
    /// plan request this way, so an answer shows up while the model writes
    /// it. The rules of [`send`](Self::send) hold, with two changes for an
    /// answer with a `2xx` status: there is no limit on the body's length,
    /// and the deadline of `send` ends with the response head. After it,
    /// the body obeys the rules listed on [`StreamingResponse`]: a bounded
    /// wait per read and bounded memory. The body of any other answer is a
    /// refusal the client reads whole, at most 64 KiB of it; a transport
    /// does well to keep the deadline of `send` running to its end, as
    /// `Https` does.
    ///
    /// `canceller` belongs to the caller who may stop the request. A
    /// transport that can interrupt a blocked read watches
    /// [`Canceller::is_cancelled`] and fails the read once it is `true`. A
    /// transport that cannot may ignore it: the client checks it after the
    /// head arrived and before and after every read of the body, so such a
    /// transport is asked for nothing more once its current read returns.
    ///
    /// The default calls [`send_cancellable`](Self::send_cancellable) with
    /// the caller's canceller and moves its buffered body into the reader.
    /// The answer arrives in one piece under the buffered transport's
    /// deadline and body limit.
    ///
    /// ```no_run
    /// use siwc::protocol::{HttpRequest, HttpResponse, StreamingResponse};
    /// use siwc::{Canceller, Error, Transport};
    ///
    /// # struct Answer { status: u16, request_id: Option<String>, retry_after: Option<String>, body: std::fs::File }
    /// # fn open(_: &HttpRequest) -> Result<Answer, Error> { unimplemented!() }
    /// #[derive(Debug)]
    /// struct MyHttpClient;
    ///
    /// impl Transport for MyHttpClient {
    ///     fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
    ///         # let _ = request;
    ///         // As before.
    ///         # unimplemented!()
    ///     }
    ///
    ///     fn send_streaming(
    ///         &self,
    ///         request: &HttpRequest,
    ///         _canceller: &Canceller,
    ///     ) -> Result<StreamingResponse, Error> {
    ///         // `open` stands for the app's HTTP client: it returns once
    ///         // the head is read, and `answer.body` implements `Read`.
    ///         let answer = open(request)?;
    ///         Ok(StreamingResponse::new(answer.status, answer.body)
    ///             .with_request_id(answer.request_id.as_deref())
    ///             .with_retry_after(answer.retry_after.as_deref()))
    ///     }
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send), for everything up to the response head.
    fn send_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<StreamingResponse, Error> {
        self.send_cancellable(request, canceller)
            .map(StreamingResponse::from)
    }
}

impl<T: Transport + ?Sized> Transport for Arc<T> {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        (**self).send(request)
    }

    fn send_cancellable(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<HttpResponse, Error> {
        (**self).send_cancellable(request, canceller)
    }

    fn send_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<StreamingResponse, Error> {
        (**self).send_streaming(request, canceller)
    }
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        (**self).send(request)
    }

    fn send_cancellable(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<HttpResponse, Error> {
        (**self).send_cancellable(request, canceller)
    }

    fn send_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<StreamingResponse, Error> {
        (**self).send_streaming(request, canceller)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Echo;

    impl Transport for Echo {
        fn send(&self, _request: &HttpRequest) -> Result<HttpResponse, Error> {
            Ok(HttpResponse::new(204, Vec::new()))
        }
    }

    /// A transport with a streaming path of its own.
    #[derive(Debug)]
    struct Live;

    impl Transport for Live {
        fn send(&self, _request: &HttpRequest) -> Result<HttpResponse, Error> {
            Ok(HttpResponse::new(500, Vec::new()))
        }

        fn send_streaming(
            &self,
            _request: &HttpRequest,
            _canceller: &Canceller,
        ) -> Result<StreamingResponse, Error> {
            Ok(StreamingResponse::new(200, &b"live"[..]))
        }
    }

    #[test]
    fn arc_and_box_transports_delegate_requests() {
        let req = crate::protocol::Jwks::request();
        let boxed: Box<dyn Transport> = Box::new(Echo);
        let shared: Arc<dyn Transport> = Arc::new(Echo);
        assert_eq!(boxed.send(&req).unwrap().status(), 204);
        assert_eq!(shared.send(&req).unwrap().status(), 204);
    }

    #[test]
    fn a_transport_without_streaming_serves_the_buffered_answer() {
        let req = crate::protocol::Jwks::request();
        let mut response = Echo.send_streaming(&req, &Canceller::new()).unwrap();
        assert_eq!(response.status(), 204);
        let mut body = Vec::new();
        response.body_mut().read_to_end(&mut body).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn arc_and_box_transports_keep_a_streaming_path_of_their_own() {
        let req = crate::protocol::Jwks::request();
        let canceller = Canceller::new();
        let boxed: Box<dyn Transport> = Box::new(Live);
        let shared: Arc<dyn Transport> = Arc::new(Live);
        for transport in [&boxed as &dyn Transport, &shared] {
            let mut response = transport.send_streaming(&req, &canceller).unwrap();
            let mut body = Vec::new();
            response.body_mut().read_to_end(&mut body).unwrap();
            assert_eq!((response.status(), body.as_slice()), (200, &b"live"[..]));
        }
    }
}
