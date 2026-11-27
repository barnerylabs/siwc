//! One plan request sent through the client's transport and read as a stream.

use std::fmt;
use std::iter::FusedIterator;
use std::sync::Arc;

use crate::error::Error;
use crate::plan::{ResponseEvent, StreamEvent};

use super::Client;
use super::call::call_cancelled;

mod attempt;
mod idle;
mod read;
mod start;
pub(super) mod text;

use attempt::Attempts;
use idle::Idle;
use read::Reading;
use text::Collected;

/// Bytes asked from the transport in one read.
const READ_SIZE: usize = 8 * 1024;

/// The streamed answer to one plan request, from
/// [`Client::stream_response`].
///
/// The request has been sent and accepted by the time a stream exists; the
/// stream reads the answer as its events are asked for.
///
/// An iterator of [`ResponseEvent`]s with one rule about its end: **the
/// answer is complete only if the iterator ends without an error.** It
/// hands out `response.completed` as its last event
/// ([`StreamEvent::Completed`](crate::plan::StreamEvent::Completed)), and
/// only once the HTTP body behind it has ended the way its head announced.
/// Every other ending is an `Err` as the last item, so text received before
/// an error is never mistaken for a complete answer. After its last item,
/// an event or an error, the iterator returns `None`.
///
/// - a failure the API reports in the stream (`response.failed` or an
///   `error` event) is the error of its [`Refusal`](crate::plan::Refusal),
///   such as [`ErrorKind::UsageLimit`](crate::ErrorKind::UsageLimit),
///   exactly as [`Client::call`] reports it;
/// - an answer the API stopped early with `response.incomplete` is
///   [`ErrorKind::Incomplete`](crate::ErrorKind::Incomplete), with the
///   reason as [`Error::provider_code`] when it is one the provider
///   documents (`max_output_tokens`, `content_filter`);
/// - a connection that ends, breaks or stalls before the answer does, also
///   between `response.completed` and the end of the body, is
///   [`ErrorKind::Temporary`](crate::ErrorKind::Temporary);
/// - a cancelled stream is
///   [`ErrorKind::Cancelled`](crate::ErrorKind::Cancelled);
/// - more than eight opening events before any other kind of event, an
///   event that cannot be read, one larger than 16 MiB, one whose `event:`
///   name says that the answer ended while its `type` says
///   something else or nothing, or anything after `response.completed`
///   but blank lines, comments and one closing `data: [DONE]`, 4 KiB in
///   all and the last line complete, is
///   [`ErrorKind::InvalidResponse`](crate::ErrorKind::InvalidResponse).
///
/// # What is sent again, and what never is
///
/// Only a qualifying HTTP refusal can trigger another attempt, as described
/// by [`Client::stream_response`]: one renewal on `401`, or bounded backoff
/// on `429` or `5xx` if the code and
/// [`ClientBuilder::resend_after_server_error`](crate::ClientBuilder::resend_after_server_error)
/// allow it. Once the API accepts the POST,
/// it may already have counted it. A failure event has no refusal status
/// and ends the stream, even before output or a clean end to the body.
/// A connection that breaks is never retried either, at any point.
///
/// Opening events say only that an answer began
/// (`response.created`, `response.in_progress`, `response.queued`); the
/// stream holds those back until another kind of event arrives and drops
/// them if that event reports a failure.
///
/// Memory stays bounded while the answer streams: the stream holds one
/// read buffer, one event being put together (at most 16 MiB, in a line
/// and a data buffer that keep their size for the next event) and the
/// events of the last read, plus up to eight held opening events (at most
/// 16 MiB of event data together). Decoding an event briefly takes several
/// times its size: about four times for one long text, up to about 26
/// times for JSON made of many tiny values such as `[0,0,…]`.
///
/// An error carries its kind, the HTTP status where there is one, and the
/// provider's code, parameter and request ID when they look like
/// identifiers. Such a value is whatever the provider chose to send, so
/// `Display` and `Debug` of an error and `Debug` of a stream print a code
/// only when it is one the crate knows, and of the others their length or
/// that they are there; [`Error::provider_code`], [`Error::param`],
/// [`Error::request_id`] and [`request_id`](Self::request_id) return them
/// to code that asks. A value with an access token of this request
/// anywhere in it, the one before a renewal included, is dropped
/// altogether. No text of the request or the answer is in an error or in
/// `Debug` output.
///
/// Dropping the stream closes the connection. Cancelling between reads
/// also closes it and drops buffered events, even if the app never calls
/// `next` again.
///
/// ```no_run
/// use siwc::plan::{ResponseRequest, StreamEvent};
///
/// # fn show(_: &str) {}
/// # fn record_usage(_completed_event: &str) {}
/// # fn example(client: &siwc::Client, id: &siwc::AccountId) -> Result<(), siwc::Error> {
/// let request = ResponseRequest::from_json(
///     r#"{"model": "example-large", "input": [{"role": "user", "content": "Hello"}]}"#,
/// )?;
/// for event in client.stream_response(id, &request)? {
///     let event = event?;
///     match event.event() {
///         StreamEvent::TextDelta { text, .. } => show(text),
///         // The whole last event as JSON, the answer's `output` included:
///         // the app's own parser takes `response.usage` out of it.
///         StreamEvent::Completed { .. } => record_usage(event.json()),
///         _ => {}
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[must_use = "the request was already sent; read the stream to get its answer, or drop it to close the connection"]
pub struct ResponseStream {
    attempts: Attempts,
    idle: Arc<Idle>,
    /// Whether the iterator was asked for an item.
    touched: bool,
    ended: bool,
}

impl ResponseStream {
    /// The request ID the provider assigned to the answer being read: the
    /// value of its `x-request-id` header, if the transport read one and it
    /// looks like an identifier. Keep it for support requests.
    ///
    /// ```no_run
    /// # fn example(stream: &siwc::ResponseStream) {
    /// if let Some(id) = stream.request_id() {
    ///     println!("request {id}");
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.attempts.request_id.as_deref()
    }

    /// Reads the stream to its end and returns the whole text of the
    /// answer, for an app that has no use for the pieces. At most 16 MiB of
    /// text are collected. Iterating over the stream does not lift that
    /// bound: the closing `response.completed` event repeats the whole
    /// output and, like every event, holds at most 16 MiB, so a complete
    /// answer has somewhat less text than that.
    ///
    /// ```no_run
    /// use siwc::plan::ResponseRequest;
    ///
    /// # fn example(client: &siwc::Client, id: &siwc::AccountId) -> Result<(), siwc::Error> {
    /// let request = ResponseRequest::text("example-large", "Name three colours.")?;
    /// let answer = client.stream_response(id, &request)?.into_text()?;
    /// println!("{answer}");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The error the stream ends with; the text read before it is dropped.
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput), without
    /// reading anything, on a stream that has already handed out an item:
    /// the rest would not be the whole answer.
    /// [`ErrorKind::InvalidResponse`](crate::ErrorKind::InvalidResponse)
    /// when the text is longer than 16 MiB or memory for it could not be allocated.
    /// The size error carries the current request ID when available. The
    /// local `InvalidInput` error has no request ID.
    pub fn into_text(mut self) -> Result<String, Error> {
        if self.touched {
            return Err(text::already_read());
        }
        let mut text = Collected::new();
        while let Some(event) = self.next() {
            text.collect(&event?, self.request_id())?;
        }
        Ok(text.into_string())
    }
}

impl Iterator for ResponseStream {
    type Item = Result<ResponseEvent, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }
        self.touched = true;
        let item = self
            .idle
            .take()
            .ok_or_else(call_cancelled)
            .and_then(|reading| {
                let (event, more) = reading.advance(&self.attempts)?;
                if let Some(reading) = more {
                    self.idle.park(reading, &self.attempts.canceller);
                }
                Ok(event)
            });
        let item = self
            .attempts
            .stop_if_cancelled()
            .and(item)
            .map_err(|error| self.attempts.sent.filter(error));
        self.ended = is_last(&item);
        Some(item)
    }
}

/// Whether `item` ends its stream: `response.completed` is the last item,
/// like an error.
pub(super) fn is_last(item: &Result<ResponseEvent, Error>) -> bool {
    match item {
        Ok(event) => matches!(event.event(), StreamEvent::Completed),
        Err(_) => true,
    }
}

impl FusedIterator for ResponseStream {}

impl fmt::Debug for ResponseStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseStream")
            .field("has_request_id", &self.request_id().is_some())
            .field("started", &self.touched)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}
