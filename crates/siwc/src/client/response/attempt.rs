//! Getting a plan request accepted: one attempt after another, and what a
//! refusal allows before the next one.

use std::io::{self, Read};

use zeroize::Zeroizing;

use crate::account::AccountId;
use crate::cancel::Canceller;
use crate::error::{Answer, Error, ErrorCause, ErrorKind};
use crate::plan::{Refusal, ResponseRequest};

use super::super::call::{ATTEMPTS, Next, call_cancelled};
use super::super::echo::Sent;
use super::{Client, READ_SIZE};

/// Largest refusal body that is read. A larger one ends the request.
const REFUSAL_BODY_LIMIT: usize = 64 * 1024;

/// Cancellation and checked metadata shared by the opener and the reader.
/// The request ID stays readable when cancellation takes the idle connection.
pub(super) struct Attempts {
    pub(super) canceller: Canceller,
    pub(super) sent: Sent,
    pub(super) request_id: Option<Box<str>>,
}

impl Attempts {
    pub(super) fn stop_if_cancelled(&self) -> Result<(), Error> {
        if self.canceller.is_cancelled() {
            Err(call_cancelled())
        } else {
            Ok(())
        }
    }

    /// Retries at most 31 consecutive interruptions without progress. A
    /// failed read gives `failed()` with the safe cause of the reader's
    /// error: only its kind, or the crate's own cause a built-in transport
    /// put into it.
    pub(super) fn read_body(
        &self,
        reader: &mut dyn Read,
        buffer: &mut [u8],
        failed: impl Fn() -> Error,
    ) -> Result<usize, Error> {
        for _ in 0..32 {
            self.stop_if_cancelled()?;
            let read = reader.read(buffer);
            self.stop_if_cancelled()?;
            match read {
                Ok(count) if count <= buffer.len() => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(failed().with_cause(ErrorCause::from_io(&error))),
                Ok(_) => break,
            }
        }
        Err(failed())
    }

    /// Sends the request until the API accepts it or an HTTP refusal ends
    /// the attempts. Only the accepted body goes to the reader.
    pub(super) fn open(
        &mut self,
        client: &Client,
        id: &AccountId,
        request: &ResponseRequest,
    ) -> Result<Box<dyn Read + Send>, Error> {
        let mut token = client.plan_access_token(id, None, &self.canceller)?;
        let mut renewed = false;
        let mut attempt = 1;
        loop {
            self.stop_if_cancelled()?;
            self.sent.add(&token);
            let http = request.http_request(&token);
            let sent = client
                .inner
                .transport
                .send_streaming(&http, &self.canceller);
            drop(http);
            // A request cancelled on its way has no answer to accept,
            // whatever the transport returned.
            self.stop_if_cancelled()?;
            let response = sent?;
            let status = response.status();
            if !(100..=599).contains(&status) {
                return Err(Error::invalid_status());
            }
            // Of an accepted head, only the checked request ID stays.
            self.request_id = response
                .request_id()
                .filter(|id| !self.sent.echoes(id))
                .map(Box::from);
            if (200..=299).contains(&status) {
                if status != 200 {
                    return Err(self.answered(
                        Error::new(
                            ErrorKind::InvalidResponse,
                            "the API answered a plan request with an unexpected status",
                        ),
                        Some(status),
                    ));
                }
                return Ok(response.into_body());
            }
            let asked = response
                .retry_after()
                .filter(|wait| !self.sent.echoes(wait))
                .map(Box::<str>::from);
            // A refusal that did not arrive whole says nothing reliable:
            // the part that was lost may be what forbids another attempt.
            let body = self.refusal_body(response.into_body()).map_err(|error| {
                if error.kind() == ErrorKind::Cancelled {
                    return error;
                }
                error.with_answer(Answer {
                    status: Some(status),
                    request_id: self.request_id.clone(),
                    retry_after: asked
                        .as_deref()
                        .and_then(crate::plan::delta_seconds)
                        .map(std::time::Duration::from_secs),
                    ..Answer::default()
                })
            })?;
            let refusal = Refusal::from_response(status, &body)
                .ok_or_else(|| self.answered(unreadable_refusal(), Some(status)))?
                .with_request_id(self.request_id.as_deref())
                .with_retry_after(asked.as_deref());
            let rejected = match client.next_step(&refusal) {
                Next::Renew if !renewed => {
                    renewed = true;
                    Some(&token)
                }
                Next::Wait if attempt < ATTEMPTS => {
                    let Some(wait) = client.wait_before(attempt + 1, refusal.wait_asked()) else {
                        return Err(refusal.into());
                    };
                    if !client.sleep_cancellable(wait, &self.canceller) {
                        return Err(call_cancelled());
                    }
                    attempt += 1;
                    // A wait can bring the token close to expiry.
                    None
                }
                _ => return Err(refusal.into()),
            };
            token = client.plan_access_token(id, rejected, &self.canceller)?;
        }
    }

    /// Adds the request ID of the answer being read, and its status when
    /// that is what the error is about, to `error`.
    pub(super) fn answered(&self, error: Error, status: Option<u16>) -> Error {
        error.with_answer(Answer {
            status,
            request_id: self.request_id.clone(),
            ..Answer::default()
        })
    }

    /// The body of an answer that is not `2xx`, read to its end, with a
    /// look at the canceller around every read.
    ///
    /// # Errors
    ///
    /// When the body breaks off, cannot be read or is larger than 64 KiB.
    /// It is then neither classified nor a reason to send the request
    /// again: what was not read may be what forbids another attempt.
    fn refusal_body(&self, mut body: Box<dyn Read + Send>) -> Result<Zeroizing<Vec<u8>>, Error> {
        // Room for all of it, so that no part is left behind by growing.
        let mut text = Zeroizing::new(Vec::with_capacity(REFUSAL_BODY_LIMIT));
        let mut buffer = Zeroizing::new(vec![0; READ_SIZE]);
        loop {
            self.stop_if_cancelled()?;
            // One byte past the limit shows that the body is larger.
            let wanted = (REFUSAL_BODY_LIMIT + 1 - text.len()).min(READ_SIZE);
            match self.read_body(&mut body, &mut buffer[..wanted], unreadable_refusal)? {
                0 => return Ok(text),
                count => {
                    let piece = buffer.get(..count).unwrap_or_default();
                    if text.len() + piece.len() > REFUSAL_BODY_LIMIT {
                        let too_large = Error::new(
                            ErrorKind::InvalidResponse,
                            "the API's refusal of a plan request is larger than 64 KiB",
                        );
                        return Err(too_large);
                    }
                    text.extend_from_slice(piece);
                }
            }
        }
    }
}

fn unreadable_refusal() -> Error {
    Error::new(
        ErrorKind::Temporary,
        "the API's refusal of a plan request could not be read to its end",
    )
}
