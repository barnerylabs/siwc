//! Scripted answers of the fake provider's `/v1/responses` route.

use std::fmt;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::time::Duration;

use serde_json::json;

use crate::cancel::Canceller;
use crate::error::Error;
use crate::protocol::{HttpResponse, StreamingResponse};

/// One scripted answer of [`FakeProvider`](super::FakeProvider) to a plan
/// request: a refusal, or an event stream that ends the way the test needs.
///
/// Queue it with [`FakeProvider::push_response`](super::FakeProvider::push_response).
/// A stream is put together event by event and ends cleanly unless told
/// otherwise; nothing adds `response.completed` on its own, so a script
/// without [`completed`](Self::completed) is an answer that was cut off.
///
/// ```
/// use siwc::testing::FakeResponse;
///
/// // A complete answer in two pieces.
/// let complete = FakeResponse::text(&["Hel", "lo"]);
/// // An answer that starts and then hits a usage limit.
/// let limited = FakeResponse::stream()
///     .created()
///     .delta("Once upon")
///     .failed("subscription_sharing_usage_limit_exceeded");
/// // The API is busy: try again in two seconds.
/// let busy = FakeResponse::refusal(503, "subscription_sharing_usage_unavailable").retry_after(2);
/// # drop((complete, limited, busy));
/// ```
#[derive(Clone)]
#[must_use]
pub struct FakeResponse {
    status: u16,
    retry_after: Option<String>,
    body: Vec<u8>,
    end: End,
    /// Most bytes one read hands out.
    piece: NonZeroUsize,
}

/// What a read finds after the scripted bytes.
#[derive(Debug, Clone, Copy)]
enum End {
    /// The body ends as its framing says.
    Clean,
    /// The connection breaks.
    Broken(io::ErrorKind),
    /// Nothing arrives until the request is cancelled.
    Hangs,
}

/// Shows the status, how the body ends and how long it is. The body is the
/// scripted answer of a model and stays out of test logs.
impl fmt::Debug for FakeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeResponse")
            .field("status", &self.status)
            .field("end", &self.end)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl FakeResponse {
    /// A complete answer: `response.created`, `response.in_progress`, one
    /// `response.output_text.delta` per entry of `deltas`, then
    /// `response.completed`.
    pub fn text(deltas: &[&str]) -> Self {
        deltas
            .iter()
            .fold(Self::stream().created(), |stream, delta| {
                stream.delta(delta)
            })
            .completed()
    }

    /// A `200` event stream without any event yet.
    pub fn stream() -> Self {
        Self {
            status: 200,
            retry_after: None,
            body: Vec::new(),
            end: End::Clean,
            piece: NonZeroUsize::MAX,
        }
    }

    /// A refusal with `status` and the structured error `code`, such as
    /// `429` with `"subscription_sharing_usage_limit_exceeded"`.
    pub fn refusal(status: u16, code: &str) -> Self {
        let body = json!({ "error": { "code": code, "message": "synthetic test refusal" } });
        Self {
            status,
            body: body.to_string().into_bytes(),
            ..Self::stream()
        }
    }

    /// A refusal as admission answers before a stream begins:
    /// `{"detail": "..."}` without an error code.
    pub fn detail(status: u16, detail: &str) -> Self {
        Self {
            status,
            body: json!({ "detail": detail }).to_string().into_bytes(),
            ..Self::stream()
        }
    }

    /// Adds a `Retry-After` header of `seconds`.
    pub fn retry_after(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds.to_string());
        self
    }

    /// Adds `response.created` and `response.in_progress`, the events every
    /// answer opens with.
    pub fn created(self) -> Self {
        let response = json!({ "id": "resp_fake", "status": "in_progress" });
        self.event(&json!({ "type": "response.created", "response": response }).to_string())
            .event(&json!({ "type": "response.in_progress", "response": response }).to_string())
    }

    /// Adds a `response.output_text.delta` event with `text`.
    pub fn delta(self, text: &str) -> Self {
        let event = json!({
            "type": "response.output_text.delta",
            "item_id": "msg_fake",
            "output_index": 0,
            "content_index": 0,
            "delta": text,
        });
        self.event(&event.to_string())
    }

    /// Adds `response.completed`, with a small `usage` object.
    pub fn completed(self) -> Self {
        let event = json!({
            "type": "response.completed",
            "response": {
                "id": "resp_fake",
                "status": "completed",
                "usage": { "input_tokens": 1, "output_tokens": 1, "total_tokens": 2 },
            },
        });
        self.event(&event.to_string())
    }

    /// Adds `response.failed` with the error `code`.
    pub fn failed(mut self, code: &str) -> Self {
        self.body
            .extend(super::FakeProvider::failure_event(code, None));
        self
    }

    /// Adds `response.incomplete` with `reason`, such as
    /// `"max_output_tokens"`.
    pub fn incomplete(self, reason: &str) -> Self {
        let event = json!({
            "type": "response.incomplete",
            "response": {
                "id": "resp_fake",
                "status": "incomplete",
                "incomplete_details": { "reason": reason },
            },
        });
        self.event(&event.to_string())
    }

    /// Adds one event with this JSON, framed as `event:` and `data:` lines.
    /// For events the other methods do not write, such as a tool call:
    /// the `event:` line repeats the JSON's `"type"`, and JSON written over
    /// several lines, whether they end with `\n`, `\r\n` or `\r`, gets one
    /// `data:` line each, as the stream format asks. A type with a line
    /// break in it cannot stand in an `event:` line and gets none.
    pub fn event(mut self, json: &str) -> Self {
        let kind = crate::protocol::json::object(json.as_bytes())
            .and_then(|object| crate::protocol::json::string(&object, "type").map(str::to_owned))
            .filter(|kind| !kind.contains(['\r', '\n']));
        if let Some(kind) = kind {
            self.body
                .extend_from_slice(format!("event: {kind}\n").as_bytes());
        }
        for line in json.replace("\r\n", "\n").split(['\n', '\r']) {
            self.body
                .extend_from_slice(format!("data: {line}\n").as_bytes());
        }
        self.body.push(b'\n');
        self
    }

    /// Adds bytes to the body exactly as given: a comment line, `\r\n` line
    /// ends, a frame that is not JSON.
    pub fn raw(mut self, bytes: &[u8]) -> Self {
        self.body.extend_from_slice(bytes);
        self
    }

    /// After the scripted events the connection breaks: the next read
    /// fails.
    pub fn interrupted(mut self) -> Self {
        self.end = End::Broken(io::ErrorKind::ConnectionReset);
        self
    }

    /// After the scripted events nothing arrives and the read gives up, as
    /// a transport's idle timeout does: the next read fails with
    /// `TimedOut` at once. [`hangs`](Self::hangs) blocks instead.
    pub fn times_out(mut self) -> Self {
        self.end = End::Broken(io::ErrorKind::TimedOut);
        self
    }

    /// After the scripted events nothing arrives until the request is
    /// cancelled: the read blocks, as on a connection that stays open.
    pub fn hangs(mut self) -> Self {
        self.end = End::Hangs;
        self
    }

    /// Hands the body out in pieces of at most `bytes` bytes, so events
    /// arrive cut at arbitrary places: inside a line, between `\r` and
    /// `\n`, inside a multi-byte character.
    ///
    /// ```
    /// use std::num::NonZeroUsize;
    /// use siwc::testing::FakeResponse;
    ///
    /// let script = FakeResponse::text(&["hello"]).split_every(NonZeroUsize::MIN);
    /// # drop(script);
    /// ```
    ///
    /// ```compile_fail
    /// use siwc::testing::FakeResponse;
    ///
    /// let script = FakeResponse::stream().split_every(0);
    /// ```
    pub fn split_every(mut self, bytes: NonZeroUsize) -> Self {
        self.piece = bytes;
        self
    }

    /// The answer as a transport without streaming returns it. A body that
    /// does not end cleanly never arrives whole.
    pub(super) fn into_whole(self, request_id: &str) -> Result<HttpResponse, Error> {
        match self.end {
            End::Clean => Ok(HttpResponse::new(self.status, self.body)
                .with_request_id(Some(request_id))
                .with_retry_after(self.retry_after.as_deref())),
            End::Broken(_) | End::Hangs => Err(Error::transport_unavailable()),
        }
    }

    /// The answer as a streaming transport returns it, read piece by piece.
    pub(super) fn into_streaming(
        self,
        request_id: &str,
        canceller: &Canceller,
    ) -> StreamingResponse {
        let playback = Playback {
            body: self.body,
            at: 0,
            piece: self.piece,
            end: self.end,
            canceller: canceller.clone(),
        };
        StreamingResponse::new(self.status, playback)
            .with_request_id(Some(request_id))
            .with_retry_after(self.retry_after.as_deref())
    }
}

/// The body of a scripted answer on its way to the reader. Like a
/// transport that watches its canceller, a read fails once the request is
/// cancelled.
struct Playback {
    body: Vec<u8>,
    at: usize,
    piece: NonZeroUsize,
    end: End,
    canceller: Canceller,
}

impl Read for Playback {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.canceller.is_cancelled() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let rest = self.body.get(self.at..).unwrap_or_default();
        if rest.is_empty() {
            return match self.end {
                End::Clean => Ok(0),
                End::Broken(kind) => Err(kind.into()),
                End::Hangs => {
                    // Returns only once the canceller is triggered.
                    while self.canceller.wait(Duration::from_secs(3600)) {}
                    Err(io::ErrorKind::ConnectionAborted.into())
                }
            };
        }
        let count = self.piece.get().min(rest.len()).min(buffer.len());
        let (Some(target), Some(source)) = (buffer.get_mut(..count), rest.get(..count)) else {
            return Ok(0);
        };
        target.copy_from_slice(source);
        self.at += count;
        Ok(count)
    }
}
