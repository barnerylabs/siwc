//! Writing responses to the browser, including the answer to the callback.

use std::fmt;
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::page::{self, Answer, Page, Text};

/// Time a response has to reach the browser.
pub(super) const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// The statuses this listener answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Status {
    Ok,
    Found,
    BadRequest,
    NotFound,
    MethodNotAllowed,
    HeaderFieldsTooLarge,
}

impl Status {
    fn line(self) -> &'static str {
        match self {
            Self::Ok => "200 OK",
            Self::Found => "302 Found",
            Self::BadRequest => "400 Bad Request",
            Self::NotFound => "404 Not Found",
            Self::MethodNotAllowed => "405 Method Not Allowed",
            Self::HeaderFieldsTooLarge => "431 Request Header Fields Too Large",
        }
    }
}

/// A tiny plain-text answer that names only the status.
pub(super) fn plain(status: Status) -> Response {
    let extra = if status == Status::MethodNotAllowed {
        "Allow: GET\r\n"
    } else {
        ""
    };
    let line = status.line();
    let body = format!("{line}\n");
    Response::new(
        status,
        extra,
        Some("text/plain; charset=utf-8"),
        &body,
        &page::policy(None, false),
    )
}

/// Sends the browser on to `location`.
pub(super) fn redirect(location: &str) -> Response {
    let mut extra = Zeroizing::new(String::with_capacity(12 + location.len()));
    extra.push_str("Location: ");
    extra.push_str(location);
    extra.push_str("\r\n");
    Response::new(Status::Found, &extra, None, "", &page::policy(None, false))
}

/// `page` showing `text`, under the page's own policy.
pub(super) fn html(status: Status, page: &Page, text: &Text) -> Response {
    Response::new(
        status,
        "",
        Some("text/html; charset=utf-8"),
        &page.html(text),
        &page.policy(),
    )
}

/// An answer that can make progress without blocking the listener.
pub(super) struct Response {
    bytes: Zeroizing<String>,
    sent: usize,
}

impl Response {
    /// Every answer carries `Cache-Control: no-store`,
    /// `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, the
    /// page's `Content-Security-Policy` and `Connection: close`.
    fn new(
        status: Status,
        extra: &str,
        content_type: Option<&str>,
        body: &str,
        policy: &str,
    ) -> Self {
        // Large enough for everything below, so the text is never moved: a
        // redirect carries the authorization URL in `extra`.
        let mut response = Zeroizing::new(String::with_capacity(
            1024 + extra.len() + body.len() + policy.len(),
        ));
        response.push_str("HTTP/1.1 ");
        response.push_str(status.line());
        response.push_str("\r\n");
        if let Some(content_type) = content_type {
            response.push_str("Content-Type: ");
            response.push_str(content_type);
            response.push_str("\r\n");
        }
        response.push_str(&format!("Content-Length: {}\r\n", body.len()));
        response.push_str(
            "Cache-Control: no-store\r\n\
             Referrer-Policy: no-referrer\r\n\
             X-Content-Type-Options: nosniff\r\n",
        );
        response.push_str("Content-Security-Policy: ");
        response.push_str(policy);
        response.push_str("\r\n");
        response.push_str("Connection: close\r\n");
        response.push_str(extra);
        response.push_str("\r\n");
        response.push_str(body);
        Self {
            bytes: response,
            sent: 0,
        }
    }

    /// Returns whether the nonblocking stream still has bytes to send.
    pub(super) fn pending(&mut self, stream: &mut TcpStream) -> bool {
        match stream.write(&self.bytes.as_bytes()[self.sent..]) {
            Ok(0) => false,
            Ok(written) => {
                self.sent += written;
                self.sent < self.bytes.len()
            }
            Err(error) => matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ),
        }
    }

    /// Sends the final page after the listener has returned, within one deadline.
    fn send(mut self, mut stream: TcpStream) {
        if stream.set_nonblocking(false).is_err() {
            return;
        }
        let started = Instant::now();
        while let Some(left) = WRITE_TIMEOUT
            .checked_sub(started.elapsed())
            .filter(|left| !left.is_zero())
        {
            if stream.set_write_timeout(Some(left)).is_err() {
                return;
            }
            if !self.pending(&mut stream) {
                let _closed = stream.shutdown(Shutdown::Write);
                return;
            }
        }
    }
}

/// The browser tab that sent the callback and still waits for its page.
///
/// Send the [`Answer`] once the sign-in is settled, for example after the
/// code exchange. A reply dropped without an answer shows the
/// [`Answer::Failed`] page.
#[must_use = "call `Reply::send` with the outcome; dropping it sends `Answer::Failed`"]
pub struct Reply {
    stream: Option<TcpStream>,
    page: Page,
}

impl Reply {
    pub(super) fn new(stream: TcpStream, page: Page) -> Self {
        Self {
            stream: Some(stream),
            page,
        }
    }

    /// Writes the answer page and closes the connection.
    ///
    /// Best effort: a tab that is gone is not an error.
    pub fn send(mut self, answer: Answer) {
        self.answer(answer);
    }

    fn answer(&mut self, answer: Answer) {
        if let Some(stream) = self.stream.take() {
            html(Status::Ok, &self.page, self.page.text(answer)).send(stream);
        }
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        self.answer(Answer::Failed);
    }
}

impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("sent", &self.stream.is_none())
            .finish_non_exhaustive()
    }
}
