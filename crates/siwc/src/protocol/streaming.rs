//! A response whose body is read piece by piece instead of being held whole.

use std::fmt;
use std::io::{self, Read};

use zeroize::Zeroizing;

use crate::secret::SecretBytes;

use super::http::{self, HttpResponse};
use super::provider_error;

/// The provider's answer to an [`HttpRequest`](super::HttpRequest) with a
/// body that arrives over time: the status, the two headers the crate reads,
/// and the body as a [`Read`].
///
/// [`Transport::send_streaming`](crate::Transport::send_streaming) returns
/// one as soon as the response head is there. What a transport's body owes:
///
/// - `read` returns the body's bytes in order, without transfer framing such
///   as chunk sizes, and blocks only until some bytes are there;
/// - `Ok(0)` means the body ended the way its framing says. A connection cut
///   before that is an error, never a clean end;
/// - a read gives up with an error when no byte arrived for a time the
///   transport chooses, and holds no more than a bounded buffer in memory.
///
/// The owned reader can move between threads (`Send`); callers need
/// exclusive access to read it. The body can hold a model's answer: it is never printed. `Debug`
/// shows the status and whether there is a request ID, not which: a
/// provider decides what stands in a header. Both header values are wiped
/// when the response is dropped.
///
/// ```
/// use std::io::Read;
///
/// use siwc::protocol::StreamingResponse;
///
/// let mut response = StreamingResponse::new(200, &b"data: {}\n\n"[..])
///     .with_request_id(Some("req_0123abcd"));
/// assert_eq!(response.status(), 200);
/// assert_eq!(response.request_id(), Some("req_0123abcd"));
/// let mut body = Vec::new();
/// response.body_mut().read_to_end(&mut body)?;
/// assert_eq!(body, b"data: {}\n\n");
/// # Ok::<(), std::io::Error>(())
/// ```
#[must_use = "read the status and consume the response body"]
pub struct StreamingResponse {
    status: u16,
    request_id: Option<Zeroizing<String>>,
    retry_after: Option<Zeroizing<String>>,
    body: Box<dyn Read + Send>,
}

impl StreamingResponse {
    /// Wraps a received status code and the reader of the body that follows.
    pub fn new(status: u16, body: impl Read + Send + 'static) -> Self {
        Self {
            status,
            request_id: None,
            retry_after: None,
            body: Box::new(body),
        }
    }

    /// Adds the value of the response's `x-request-id` header, as
    /// [`HttpResponse::with_request_id`] does.
    pub fn with_request_id(mut self, id: Option<&str>) -> Self {
        self.request_id = id
            .and_then(provider_error::sanitize_request_id)
            .map(Zeroizing::new);
        self
    }

    /// Adds the value of the response's `Retry-After` header, so a refusal
    /// made from this response knows how long the provider asks to wait
    /// ([`Refusal::with_retry_after`](crate::plan::Refusal::with_retry_after)).
    /// The value is trimmed, and a number of seconds loses its leading
    /// zeros. An empty value counts as no header. What is then longer than
    /// 64 bytes is replaced: a number of seconds by one too long to wait,
    /// anything else by a value that is not seconds, so the request is not
    /// sent again.
    /// For repeated fields, pass the longest numeric wait in seconds. Use a
    /// nonnumeric value only when none of the fields contains a numeric wait.
    ///
    /// ```
    /// use siwc::protocol::StreamingResponse;
    ///
    /// let response = StreamingResponse::new(503, std::io::empty()).with_retry_after(Some("12"));
    /// assert_eq!(response.retry_after(), Some("12"));
    /// // A long header that says one second.
    /// let padded = format!("{}1", "0".repeat(80));
    /// let response = StreamingResponse::new(503, std::io::empty()).with_retry_after(Some(&padded));
    /// assert_eq!(response.retry_after(), Some("1"));
    /// ```
    pub fn with_retry_after(mut self, header: Option<&str>) -> Self {
        self.retry_after = header.and_then(http::retry_after_value);
        self
    }

    /// The HTTP status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The request ID the provider assigned, if the transport read one.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_ref().map(|id| id.as_str())
    }

    /// The `Retry-After` header as
    /// [`with_retry_after`](Self::with_retry_after) kept it: trimmed, and
    /// a number of seconds without its leading zeros.
    #[must_use]
    pub fn retry_after(&self) -> Option<&str> {
        self.retry_after.as_ref().map(|wait| wait.as_str())
    }

    /// The body, to read on from where the last read stopped.
    pub fn body_mut(&mut self) -> &mut (dyn Read + Send) {
        &mut *self.body
    }

    /// The body alone, without the head it came with.
    pub(crate) fn into_body(self) -> Box<dyn Read + Send> {
        self.body
    }
}

/// A response that arrived whole, served from memory: what a transport
/// without streaming of its own returns from
/// [`Transport::send_streaming`](crate::Transport::send_streaming).
impl From<HttpResponse> for StreamingResponse {
    fn from(response: HttpResponse) -> Self {
        Self {
            status: response.status,
            request_id: response.request_id,
            retry_after: response.retry_after,
            body: Box::new(Held {
                bytes: response.body,
                read: 0,
            }),
        }
    }
}

impl fmt::Debug for StreamingResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingResponse")
            .field("status", &self.status)
            .field("has_request_id", &self.request_id.is_some())
            .finish_non_exhaustive()
    }
}

/// A whole body in memory, wiped when dropped.
struct Held {
    bytes: SecretBytes,
    read: usize,
}

impl Read for Held {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        #[cfg(test)]
        tests::READ_FROM.set(self.bytes.expose().as_ptr());
        let rest = self.bytes.expose().get(self.read..).unwrap_or_default();
        let count = rest.len().min(buffer.len());
        let (Some(target), Some(source)) = (buffer.get_mut(..count), rest.get(..count)) else {
            return Ok(0);
        };
        target.copy_from_slice(source);
        self.read += count;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        pub(super) static READ_FROM: std::cell::Cell<*const u8> = const { std::cell::Cell::new(std::ptr::null()) };
    }

    #[test]
    fn converting_a_buffered_response_reuses_the_body_and_header_allocations() {
        let whole = HttpResponse::new(429, vec![42; 1024])
            .with_request_id(Some("req_buffer"))
            .with_retry_after(Some("12"));
        let body = whole.body().as_ptr();
        let id = whole.request_id().unwrap().as_ptr();
        let wait = whole.retry_after().unwrap().as_ptr();
        let mut stream = StreamingResponse::from(whole);
        stream.body_mut().read_exact(&mut [0]).unwrap();
        assert_eq!(READ_FROM.get(), body);
        assert_eq!(stream.request_id().unwrap().as_ptr(), id);
        assert_eq!(stream.retry_after().unwrap().as_ptr(), wait);
    }

    #[test]
    fn a_whole_response_is_served_from_memory_in_pieces() {
        let whole = HttpResponse::new(429, b"0123456789".to_vec()).with_request_id(Some("req_1"));
        let mut response = StreamingResponse::from(whole);
        assert_eq!(response.status(), 429);
        assert_eq!(response.request_id(), Some("req_1"));
        assert_eq!(response.retry_after(), None);

        let mut seen = Vec::new();
        let mut piece = [0; 4];
        loop {
            let count = response.body_mut().read(&mut piece).unwrap();
            if count == 0 {
                break;
            }
            seen.extend_from_slice(&piece[..count]);
        }
        assert_eq!(seen, b"0123456789");
        assert_eq!(response.body_mut().read(&mut piece).unwrap(), 0);
    }

    #[test]
    fn headers_are_kept_only_when_they_are_short_and_clean() {
        let response = StreamingResponse::new(503, io::empty())
            .with_request_id(Some("req bad\r\nid"))
            .with_retry_after(Some(&"x".repeat(65)));
        assert_eq!(response.request_id(), None);
        // Too long to keep, yet a wait was asked for: it stays unreadable.
        assert_eq!(response.retry_after(), Some(super::http::UNREAD_WAIT));
        let empty = StreamingResponse::new(503, io::empty()).with_retry_after(Some("  "));
        assert_eq!(empty.retry_after(), None);
        let kept = StreamingResponse::new(503, io::empty()).with_retry_after(Some(" 30 "));
        assert_eq!(kept.retry_after(), Some("30"));
    }

    #[test]
    fn a_wait_too_long_to_write_down_stays_too_long_and_a_buffered_answer_keeps_its_wait() {
        let long = StreamingResponse::new(503, io::empty()).with_retry_after(Some(&"9".repeat(65)));
        let overflowing =
            StreamingResponse::new(503, io::empty()).with_retry_after(Some("18446744073709551616"));
        for response in [long, overflowing] {
            let asked = crate::plan::Refusal::from_response(503, b"{}")
                .unwrap()
                .with_retry_after(response.retry_after());
            assert_eq!(
                asked.retry_after(),
                Some(std::time::Duration::from_secs(u64::MAX))
            );
        }
        let whole = HttpResponse::new(429, Vec::new()).with_retry_after(Some(" 7 "));
        assert_eq!(whole.retry_after(), Some("7"));
        assert_eq!(StreamingResponse::from(whole).retry_after(), Some("7"));
    }

    #[test]
    fn debug_shows_the_status_and_never_the_body_or_a_header_value() {
        let response = StreamingResponse::new(200, &b"secret-model-text"[..])
            .with_request_id(Some("req_2"))
            .with_retry_after(Some("5"));
        let debug = format!("{response:?}");
        assert!(debug.contains("200"), "{debug}");
        assert!(debug.contains("has_request_id: true"), "{debug}");
        assert!(!debug.contains("req_2"), "{debug}");
        assert!(!debug.contains("secret-model-text"), "{debug}");
    }
}
