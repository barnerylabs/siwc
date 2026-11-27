//! Sending a buffered or streamed request on one verified TLS connection.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use crate::cancel::Canceller;
use crate::error::{Error, ErrorCause, ErrorKind};
use crate::protocol::{HttpRequest, HttpResponse, StreamingResponse};
use crate::transport::{Transport, cause, endpoint};

use super::deadline::{Deadline, stop_if_cancelled};
use super::{Https, body::Body, connect, request, response};

enum Exchange<'a> {
    Buffered(Option<&'a Canceller>),
    Streaming(&'a Canceller),
}

impl Https {
    /// Writes `request` for one of the two hosts into a wiping buffer and
    /// opens a verified connection that has sent it. Every failure on the
    /// way is the same temporary error.
    fn deliver(
        &self,
        request: &HttpRequest,
        exchange: Exchange<'_>,
    ) -> Result<connect::Stream, Error> {
        let canceller = match exchange {
            Exchange::Buffered(stop) => stop,
            Exchange::Streaming(stop) => Some(stop),
        };
        let endpoint = endpoint::parse(request.url()).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "the HTTPS transport sends only to the provider's hosts",
            )
        })?;
        let headers: Vec<(&str, &str)> = request.headers().collect();
        let message = request::write(
            request.method(),
            endpoint.host,
            endpoint.target,
            &headers,
            request.body(),
        )
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "a request header cannot be sent over HTTP/1.1",
            )
        })?;
        let deadline =
            Deadline::after(self.limits.total_timeout).ok_or_else(Error::transport_unavailable)?;
        let host = endpoint.host;
        let unavailable = |error: io::Error| failed(canceller, cause::of_io(&error));
        let mut stream = match &self.proxy {
            None => {
                let addresses = self
                    .addresses(host, connect::PORT, deadline, canceller)
                    .map_err(unavailable)?;
                connect::open(
                    &self.config,
                    host,
                    &addresses,
                    self.limits.connect_timeout,
                    deadline,
                    canceller,
                )
                .map_err(unavailable)?
            }
            Some(proxy) => {
                let addresses = self
                    .addresses(&proxy.host, proxy.port, deadline, canceller)
                    .map_err(unavailable)?;
                connect::open_via_proxy(
                    &self.config,
                    proxy,
                    &addresses,
                    host,
                    self.limits.connect_timeout,
                    deadline,
                    canceller,
                )
                .map_err(unavailable)?
            }
        };
        #[cfg(test)]
        {
            if let Some(stop) = super::renewal_tests::BEFORE_WRITE.take() {
                stop.cancel();
            }
            stream.sock.socket_mut().after_first_byte =
                super::renewal_tests::AFTER_FIRST_BYTE.take();
        }
        stop_if_cancelled(canceller).map_err(|_| Error::transport_unavailable())?;
        let watched = if matches!(exchange, Exchange::Buffered(Some(_))) {
            // The first write can spend the token. Keep the deadline, but
            // let all remaining writes and reads finish after cancellation:
            // a failure from here on is the exchange's own and keeps its
            // cause.
            stream.sock.socket_mut().finish_after_cancel();
            None
        } else {
            canceller
        };
        let unavailable = |error: io::Error| failed(watched, cause::of_io(&error));
        stream.write_all(&message).map_err(unavailable)?;
        stream.flush().map_err(unavailable)?;
        Ok(stream)
    }

    fn send_buffered(
        &self,
        request: &HttpRequest,
        stop: Option<&Canceller>,
    ) -> Result<HttpResponse, Error> {
        let mut stream = self.deliver(request, Exchange::Buffered(stop))?;
        // The request is out and the exchange runs to its end whatever
        // the canceller does, so a failure keeps its cause.
        response::read(&mut stream, self.limits.max_response_len)
            .map_err(|failure| cause::unavailable(failure.cause()))
    }

    #[cfg(not(test))]
    fn addresses(
        &self,
        host: &str,
        port: u16,
        deadline: Deadline,
        canceller: Option<&Canceller>,
    ) -> std::io::Result<Vec<SocketAddr>> {
        self.resolver.resolve(host, port, deadline, canceller)
    }

    #[cfg(test)]
    fn addresses(
        &self,
        host: &str,
        port: u16,
        deadline: Deadline,
        canceller: Option<&Canceller>,
    ) -> std::io::Result<Vec<SocketAddr>> {
        match self.connect_to {
            Some(address) => Ok(vec![address]),
            None => self.resolver.resolve(host, port, deadline, canceller),
        }
    }
}

impl Transport for Https {
    /// Sends `request` to its host and returns the status and body.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when the URL is not on one of the two
    /// hosts or a header cannot be written; nothing is sent then.
    /// [`Error::transport_unavailable`] for everything that goes wrong on
    /// the way: no connection, a failed handshake or certificate check, a
    /// deadline, a malformed answer or a body above the limit. Its
    /// [`Error::cause`] names which, except when a cancellation stopped the
    /// exchange. A buffered request that was cancelled after its first
    /// byte was written runs to its end, and a failure then keeps its
    /// cause.
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.send_buffered(request, None)
    }

    fn send_cancellable(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<HttpResponse, Error> {
        self.send_buffered(request, Some(canceller))
    }

    /// Sends `request` to its host and returns once the response head is
    /// read, with the body still on the connection.
    ///
    /// The total timeout covers everything up to the head. After a `2xx`
    /// head, each read of the body waits at most the stream idle timeout
    /// for its bytes; the body of any other status, an error document,
    /// stays under the total timeout. The body has no length limit and is
    /// never held whole: chunked transfer encoding is decoded as it
    /// arrives. Within about 50 ms after `canceller` is triggered, a body
    /// read fails with [`io::ErrorKind::ConnectionAborted`] and no cause.
    /// The wait for the resolver, the handshake, the writing of the request
    /// and the wait for the head end just as soon, with an error without a
    /// cause; no further address is tried.
    /// Only a TCP connect in progress runs on, to the connect timeout at
    /// most.
    ///
    /// # Errors
    ///
    /// As [`send`](Transport::send), for everything up to the response
    /// head.
    fn send_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<StreamingResponse, Error> {
        let stream = self.deliver(request, Exchange::Streaming(canceller))?;
        let (head, body) = response::open(stream, None)
            .map_err(|failure| failed(Some(canceller), failure.cause()))?;
        Ok(StreamingResponse::new(
            head.status,
            StreamingBody {
                body,
                idle: (200..=299)
                    .contains(&head.status)
                    .then_some(self.limits.stream_idle_timeout),
                stop: canceller.clone(),
            },
        )
        .with_request_id(head.request_id())
        .with_retry_after(head.retry_after()))
    }
}

/// The error of a failed exchange: it names `cause`, unless `canceller`
/// was triggered. Then the cancellation is what ended the exchange, and
/// whatever failed on the way because of it is no cause of its own.
fn failed(canceller: Option<&Canceller>, cause: ErrorCause) -> Error {
    if canceller.is_some_and(Canceller::is_cancelled) {
        Error::transport_unavailable()
    } else {
        cause::unavailable(cause)
    }
}

/// A read can be served entirely from TLS or framing buffers, without
/// reaching the cancellation check on the underlying socket. Every blocking
/// operation for a successful body read shares its deadline. A read that
/// fails once the canceller fired is `ConnectionAborted` without a cause:
/// whatever broke on the way did so because of the cancellation.
struct StreamingBody {
    body: Body<connect::Stream>,
    idle: Option<Duration>,
    stop: Canceller,
}

impl Read for StreamingBody {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        stop_if_cancelled(Some(&self.stop))?;
        if let Some(idle) = self.idle {
            let deadline = Deadline::after(idle).ok_or(io::ErrorKind::TimedOut)?;
            self.body
                .reader_mut()
                .sock
                .socket_mut()
                .set_deadline(deadline);
        }
        self.body.read(buffer).map_err(|error| {
            if self.stop.is_cancelled() {
                io::ErrorKind::ConnectionAborted.into()
            } else {
                error
            }
        })
    }
}
