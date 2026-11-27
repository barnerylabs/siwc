//! Request delivery and bounded response reading through ureq.

use std::io::{self, Read};
use std::sync::Arc;

use ureq::http::Response;
use zeroize::Zeroizing;

use crate::cancel::Canceller;
use crate::error::{Error, ErrorCause, ErrorKind};
use crate::protocol::{HttpRequest, HttpResponse, Method, StreamingResponse, is_token};
use crate::transport::buffer::reserve;
use crate::transport::{Transport, endpoint};

use super::cause;

use super::Ureq;
use super::stream_guard::StreamGuard;

/// What a streamed refusal hands out of its body: the 64 KiB a refusal may
/// have and one byte more, which shows its reader that it is larger.
const REFUSAL_READ: u64 = 64 * 1024 + 1;
type Opened = (Response<ureq::Body>, ureq::Agent, Option<Arc<StreamGuard>>);

impl Ureq {
    fn open(
        &self,
        request: &HttpRequest,
        streaming: bool,
        stop: Option<&Canceller>,
    ) -> Result<Opened, Error> {
        endpoint::parse(request.url()).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "the ureq transport sends only to the provider's hosts",
            )
        })?;
        if request.headers().any(|(name, value)| {
            !is_token(name.as_bytes())
                || !value
                    .bytes()
                    .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
        }) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "a request header cannot be sent over HTTP/1.1",
            ));
        }

        let guard = streaming.then(|| Arc::new(StreamGuard::new(stop.cloned())));
        let agent = self.agent(streaming, guard.clone());
        let unavailable = |error: ureq::Error| cause::unavailable(&error);
        let response = match request.method() {
            Method::Get => {
                let mut call = agent.get(request.url()).header("Connection", "close");
                for (name, value) in request.headers() {
                    call = call.header(name, value);
                }
                call.call().map_err(unavailable)?
            }
            Method::Post => {
                let mut call = agent.post(request.url()).header("Connection", "close");
                for (name, value) in request.headers() {
                    call = call.header(name, value);
                }
                call.send(request.body()).map_err(unavailable)?
            }
        };
        if !(100..=599).contains(&response.status().as_u16()) {
            return Err(Error::transport_unavailable().with_cause(ErrorCause::InvalidFraming));
        }
        Ok((response, agent, guard))
    }

    fn buffered(
        &self,
        request: &HttpRequest,
        stop: Option<&Canceller>,
    ) -> Result<HttpResponse, Error> {
        check_cancelled(stop).map_err(|_| Error::transport_unavailable())?;
        let (response, _agent, _guard) = self.open(request, false, stop)?;
        if response
            .body()
            .content_length()
            .is_some_and(|length| length > self.limits.max_response_len as u64)
        {
            return Err(Error::transport_unavailable().with_cause(ErrorCause::ResponseTooLarge));
        }
        let status = response.status().as_u16();
        let id = header(&response, "x-request-id");
        let retry_after = header(&response, "retry-after");
        let body = read_limited(
            response
                .into_body()
                .into_with_config()
                .limit(u64::MAX)
                .reader(),
            self.limits.max_response_len,
        )?;
        Ok(HttpResponse::new(status, body)
            .with_request_id(id.as_deref().map(String::as_str))
            .with_retry_after(retry_after.as_deref().map(String::as_str)))
    }
}

impl Transport for Ureq {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.buffered(request, None)
    }

    fn send_cancellable(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<HttpResponse, Error> {
        self.buffered(request, Some(canceller))
    }

    fn send_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<StreamingResponse, Error> {
        check_cancelled(Some(canceller)).map_err(|_| Error::transport_unavailable())?;
        let (response, agent, guard) = self.open(request, true, Some(canceller))?;
        let status = response.status().as_u16();
        let refused = !(200..=299).contains(&status);
        let id = header(&response, "x-request-id");
        let retry_after = header(&response, "retry-after");
        let reader = response
            .into_body()
            .into_with_config()
            .limit(u64::MAX)
            .reader();
        let guard = guard.ok_or_else(Error::transport_unavailable)?;
        guard.start();
        if refused {
            guard.refusal_deadline(self.limits.total_timeout);
        }
        let body = CancellableBody {
            reader: Box::new(reader),
            guard,
            _agent: agent,
        };
        // A refusal goes to the caller with its status and request ID
        // before its body is read, so a body that is too large or breaks
        // still says which answer it belonged to.
        let answer = if refused {
            StreamingResponse::new(status, body.take(REFUSAL_READ))
        } else {
            StreamingResponse::new(status, body)
        };
        Ok(answer
            .with_request_id(id.as_deref().map(String::as_str))
            .with_retry_after(retry_after.as_deref().map(String::as_str)))
    }
}

fn check_cancelled(stop: Option<&Canceller>) -> io::Result<()> {
    if stop.is_some_and(Canceller::is_cancelled) {
        Err(io::ErrorKind::ConnectionAborted.into())
    } else {
        Ok(())
    }
}

fn header(response: &Response<ureq::Body>, name: &str) -> Option<Zeroizing<String>> {
    let values = response.headers().get_all(name);
    if name == "retry-after" {
        let mut longest = None;
        for value in values.iter() {
            // A value that is not visible text is a wait nobody can read.
            let value = value.to_str().unwrap_or(crate::protocol::UNREAD_WAIT);
            crate::protocol::consider_wait(&mut longest, value);
        }
        return longest;
    }
    values
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .map(|value| Zeroizing::new(value.to_owned()))
}

fn read_limited(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, Error> {
    let mut body = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0u8; 16 * 1024]);
    loop {
        let room = limit
            .saturating_sub(body.len())
            .saturating_add(1)
            .min(buffer.len());
        let read = reader
            .read(&mut buffer[..room])
            .map_err(|error| cause::unavailable(&ureq::Error::from(error)))?;
        if read == 0 {
            return Ok(std::mem::take(&mut *body));
        }
        reserve(&mut body, read, limit).ok_or_else(|| {
            Error::transport_unavailable().with_cause(ErrorCause::ResponseTooLarge)
        })?;
        body.extend_from_slice(&buffer[..read]);
        buffer[..read].fill(0);
    }
}

struct CancellableBody {
    reader: Box<dyn Read + Send>,
    guard: Arc<StreamGuard>,
    _agent: ureq::Agent,
}

impl CancellableBody {
    fn read_guarded(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.guard.begin_read().map_err(|error| cause::io(&error))?;
        let read = self
            .reader
            .read(buffer)
            .map_err(|error| cause::io(&ureq::Error::from(error)))?;
        self.guard.check().map_err(|error| cause::io(&error))?;
        Ok(read)
    }
}

/// A read that fails once the canceller fired is `ConnectionAborted`
/// without a cause, as with `Https`: whatever broke on the way did so
/// because of the cancellation.
impl Read for CancellableBody {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.read_guarded(buffer) {
            Err(_) if self.guard.is_cancelled() => Err(io::ErrorKind::ConnectionAborted.into()),
            result => result,
        }
    }
}
