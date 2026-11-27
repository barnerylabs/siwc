//! Reading one HTTP/1.x response from a stream, within size limits: the
//! head here, the body through [`Body`].

use std::io::{self, Read};

use zeroize::Zeroizing;

use crate::error::ErrorCause;
use crate::protocol::HttpResponse;
use crate::transport::buffer::reserve;

use super::body::{Body, Framing, field, is_text};
pub(super) use super::input::Failure;
use super::input::{Input, READ_SIZE};

/// Largest response head, all interim `1xx` heads before it included.
pub(super) const HEAD_LIMIT: usize = 16 * 1024;

/// What the head of a final response says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Head {
    pub(super) status: u16,
    /// The `x-request-id` header, if it is text. Unchecked: whatever the
    /// provider sent, so this copy and the next are wiped when dropped.
    pub(super) request_id: Option<Zeroizing<String>>,
    /// The `retry-after` header, if it is text.
    pub(super) retry_after: Option<Zeroizing<String>>,
}

impl Head {
    pub(super) fn request_id(&self) -> Option<&str> {
        self.request_id.as_ref().map(|id| id.as_str())
    }

    pub(super) fn retry_after(&self) -> Option<&str> {
        self.retry_after.as_ref().map(|wait| wait.as_str())
    }
}

/// Reads the final response from `reader`: interim `1xx` responses are
/// skipped, the body is framed by `Content-Length`, chunked encoding or the
/// end of the stream, and may hold at most `body_limit` bytes.
pub(super) fn read(reader: &mut impl Read, body_limit: usize) -> Result<HttpResponse, Failure> {
    let (head, mut body) = open(reader, Some(body_limit))?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut piece = Zeroizing::new(vec![0; READ_SIZE]);
    loop {
        let count = body.pull(&mut piece)?;
        if count == 0 {
            break;
        }
        reserve(&mut bytes, count, body_limit).ok_or(Failure::TooLarge)?;
        bytes.extend_from_slice(
            piece
                .get(..count)
                .ok_or(Failure::Read(ErrorCause::Io(io::ErrorKind::Other)))?,
        );
    }
    Ok(HttpResponse::new(head.status, take(bytes))
        .with_request_id(head.request_id())
        .with_retry_after(head.retry_after()))
}

/// Reads the head of the final response from `reader` and returns it with
/// the body that follows, still unread. With a `body_limit`, a body that
/// declares more bytes fails here and one that delivers more fails when the
/// limit is crossed.
pub(super) fn open<R: Read>(
    reader: R,
    body_limit: Option<usize>,
) -> Result<(Head, Body<R>), Failure> {
    let mut input = Input::new(reader);
    let mut head_budget = HEAD_LIMIT;
    loop {
        let bytes = input.until(b"\r\n\r\n", &mut head_budget)?;
        let (head, framing) = parse_head(&bytes)?;
        if head.status == 101 {
            return Err(Failure::Malformed);
        }
        if head.status < 200 {
            continue;
        }
        let framing = if head.status == 204 || head.status == 304 {
            Framing::None
        } else {
            framing
        };
        return Ok((head, Body::new(input, framing, body_limit)?));
    }
}

/// Moves the bytes out of a wiping buffer without leaving a copy behind.
fn take(mut body: Zeroizing<Vec<u8>>) -> Vec<u8> {
    std::mem::take(&mut *body)
}

/// Checks a head (terminator included) and returns what it says and how
/// its body is framed.
fn parse_head(head: &[u8]) -> Result<(Head, Framing), Failure> {
    // Every line keeps its `\r`; the blank line at the end goes.
    let head = head.strip_suffix(b"\n\r\n").ok_or(Failure::Malformed)?;
    let mut lines = head.split(|byte| *byte == b'\n');
    let status_line = lines.next().ok_or(Failure::Malformed)?;
    let (version, status) = parse_status_line(line_text(status_line)?)?;

    let mut length = None;
    let mut chunked = false;
    let mut encodings = 0_usize;
    let mut request_id = None;
    let mut retry_after = None;
    let text = |value: &[u8]| {
        let value = std::str::from_utf8(value).ok()?;
        Some(Zeroizing::new(value.to_owned()))
    };
    for line in lines {
        let (name, value) = field(line_text(line)?)?;
        let value = value.trim_ascii();
        if name.eq_ignore_ascii_case(b"content-length") {
            if length.is_some() {
                return Err(Failure::Malformed);
            }
            length = Some(parse_decimal(value)?);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            encodings += 1;
            chunked = value.eq_ignore_ascii_case(b"chunked");
        } else if name.eq_ignore_ascii_case(b"x-request-id") {
            request_id = text(value);
        } else if name.eq_ignore_ascii_case(b"retry-after") {
            // A value that is not text is a wait nobody can read.
            let value = std::str::from_utf8(value).unwrap_or(crate::protocol::UNREAD_WAIT);
            crate::protocol::consider_wait(&mut retry_after, value);
        }
    }
    let framing = match (length, encodings) {
        (Some(_), 1..) => return Err(Failure::Malformed),
        (Some(length), 0) => Framing::Length(length),
        (None, 1) if chunked && version == Version::Http11 => Framing::Chunked,
        (None, 1..) => return Err(Failure::Malformed),
        (None, 0) => Framing::UntilClose,
    };
    let head = Head {
        status,
        request_id,
        retry_after,
    };
    Ok((head, framing))
}

/// Checks a `CONNECT` response head (terminator included) and returns its
/// status code. Per RFC 9110 §9.3.6 a `2xx` answer switches to tunnel mode
/// immediately after the blank line with no body.
pub(super) fn parse_connect_head(head: &[u8]) -> Result<u16, Failure> {
    let head = head.strip_suffix(b"\n\r\n").ok_or(Failure::Malformed)?;
    let mut lines = head.split(|byte| *byte == b'\n');
    let status_line = lines.next().ok_or(Failure::Malformed)?;
    let (_, status) = parse_status_line(line_text(status_line)?)?;
    for line in lines {
        field(line_text(line)?)?;
    }
    Ok(status)
}

/// One head line without its `\r`; a stray `\r` or other control byte
/// inside it is malformed.
fn line_text(line: &[u8]) -> Result<&[u8], Failure> {
    line.strip_suffix(b"\r")
        .filter(|line| is_text(line))
        .ok_or(Failure::Malformed)
}

#[derive(PartialEq, Eq)]
enum Version {
    Http10,
    Http11,
}

/// Keeps the HTTP version because it determines which framing is legal.
fn parse_status_line(line: &[u8]) -> Result<(Version, u16), Failure> {
    let (prefix, rest) = line.split_at_checked(9).ok_or(Failure::Malformed)?;
    let version = match prefix {
        b"HTTP/1.0 " => Version::Http10,
        b"HTTP/1.1 " => Version::Http11,
        _ => return Err(Failure::Malformed),
    };
    let (code, reason) = rest.split_at_checked(3).ok_or(Failure::Malformed)?;
    if !(reason.is_empty() || reason.starts_with(b" ")) {
        return Err(Failure::Malformed);
    }
    let [a, b, c] = code else {
        return Err(Failure::Malformed);
    };
    if !matches!(a, b'1'..=b'5') || !b.is_ascii_digit() || !c.is_ascii_digit() {
        return Err(Failure::Malformed);
    }
    let status = u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0');
    Ok((version, status))
}

/// A `Content-Length` value: decimal digits only.
fn parse_decimal(value: &[u8]) -> Result<u64, Failure> {
    if value.is_empty() {
        return Err(Failure::Malformed);
    }
    value.iter().try_fold(0_u64, |total, byte| {
        let digit = byte.is_ascii_digit().then(|| u64::from(byte - b'0'));
        digit
            .and_then(|digit| total.checked_mul(10)?.checked_add(digit))
            .ok_or(Failure::Malformed)
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;

    use super::super::body::LINE_LIMIT;
    use super::*;

    const LIMIT: usize = 64;

    /// A stream, scripted: each read hands out the next piece, at most as
    /// many bytes as fit; an empty script reads as a clean end.
    struct Script(VecDeque<Result<Vec<u8>, io::ErrorKind>>);

    impl Script {
        fn new(pieces: impl IntoIterator<Item = Result<Vec<u8>, io::ErrorKind>>) -> Self {
            Self(pieces.into_iter().collect())
        }

        fn whole(bytes: impl Into<Vec<u8>>) -> Self {
            Self::new([Ok(bytes.into())])
        }

        /// Bytes no read has asked for yet.
        fn unread(&self) -> usize {
            self.0
                .iter()
                .map(|piece| piece.as_ref().map_or(0, Vec::len))
                .sum()
        }
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.pop_front() {
                None => Ok(0),
                Some(Err(kind)) => Err(kind.into()),
                Some(Ok(mut piece)) => {
                    let count = piece.len().min(buf.len());
                    buf[..count].copy_from_slice(&piece[..count]);
                    let rest = piece.split_off(count);
                    if !rest.is_empty() {
                        self.0.push_front(Ok(rest));
                    }
                    Ok(count)
                }
            }
        }
    }

    /// A stream that hands out one byte per read.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match (self.0.split_first(), buf.first_mut()) {
                (Some((byte, rest)), Some(slot)) => {
                    *slot = *byte;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    fn parse(bytes: &[u8]) -> Result<(u16, Vec<u8>), Failure> {
        let response = read(&mut Script::whole(bytes), LIMIT)?;
        Ok((response.status(), response.body().to_vec()))
    }

    fn ok(status: u16, body: &[u8]) -> Result<(u16, Vec<u8>), Failure> {
        Ok((status, body.to_vec()))
    }

    #[test]
    fn http_1_0_refuses_transfer_encoding() {
        let wire = b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
        assert_eq!(parse(wire), Err(Failure::Malformed));
        assert!(matches!(
            open(wire.as_slice(), None),
            Err(Failure::Malformed)
        ));
    }

    #[test]
    fn a_body_is_framed_by_content_length() {
        assert_eq!(
            parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
            ok(200, b"hello")
        );
        assert_eq!(
            parse(b"HTTP/1.0 404\r\ncontent-length:  0 \r\n\r\n"),
            ok(404, b"")
        );
    }

    #[test]
    fn bytes_after_a_content_length_body_are_never_read() {
        let mut script = Script::new([
            Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".to_vec()),
            Ok(b"ok".to_vec()),
            Err(io::ErrorKind::UnexpectedEof),
        ]);
        let response = read(&mut script, LIMIT).unwrap();
        assert_eq!(response.body(), b"ok");
        assert_eq!(script.0.len(), 1, "the missing close_notify was not read");
    }

    #[test]
    fn a_chunked_body_is_joined_skipping_extensions_and_trailers() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n\
            5;name=value\r\nhello\r\n\
            1 ; a ; b=\"c\"\r\n,\r\n\
            A\r\n world!!!!\r\n\
            0;last\r\nTrailer-One: x\r\nTrailer-Two: y\r\n\r\n";
        assert_eq!(parse(response), ok(200, b"hello, world!!!!"));
        let mut tail = Script::new([Ok(response.to_vec()), Err(io::ErrorKind::UnexpectedEof)]);
        assert!(
            read(&mut tail, LIMIT).is_ok(),
            "nothing is read past the trailers"
        );
    }

    #[test]
    fn a_body_without_framing_runs_until_a_clean_close() {
        assert_eq!(
            parse(b"HTTP/1.1 200 OK\r\n\r\nall of it"),
            ok(200, b"all of it")
        );
    }

    #[test]
    fn a_body_cut_off_without_close_notify_fails() {
        let mut script = Script::new([
            Ok(b"HTTP/1.1 200 OK\r\n\r\npart".to_vec()),
            Err(io::ErrorKind::UnexpectedEof),
        ]);
        assert_eq!(
            read(&mut script, LIMIT).unwrap_err(),
            Failure::Read(ErrorCause::ConnectionClosed)
        );
    }

    #[test]
    fn a_response_read_one_byte_at_a_time_is_the_same() {
        let cases: [&[u8]; 3] = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;x\r\nhe\r\n3\r\nllo\r\n0\r\nT: v\r\n\r\n",
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\nhello",
        ];
        for bytes in cases {
            let response = read(&mut Trickle(bytes), LIMIT).unwrap();
            assert_eq!((response.status(), response.body()), (200, &b"hello"[..]));
        }
    }

    #[test]
    fn a_failed_or_timed_out_read_fails_and_an_interrupted_one_is_retried() {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::ConnectionReset,
        ] {
            let mut script = Script::new([Ok(b"HTTP/1.1 200 OK\r\nCont".to_vec()), Err(kind)]);
            assert_eq!(
                read(&mut script, LIMIT).unwrap_err(),
                Failure::Read(ErrorCause::from_io_kind(kind)),
                "{kind:?}"
            );
        }
        let mut script = Script::new([
            Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".to_vec()),
            Err(io::ErrorKind::Interrupted),
            Ok(b"ok".to_vec()),
        ]);
        assert_eq!(read(&mut script, LIMIT).unwrap().body(), b"ok");
    }

    #[test]
    fn interim_responses_are_skipped_and_no_body_statuses_have_none() {
        assert_eq!(
            parse(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nx"),
            ok(201, b"x")
        );
        // Without the rule these would read until the close and fail on it.
        for status in ["204 No Content", "304 Not Modified"] {
            let mut script = Script::new([
                Ok(format!("HTTP/1.1 {status}\r\nContent-Length: 9\r\n\r\n").into_bytes()),
                Err(io::ErrorKind::TimedOut),
            ]);
            let response = read(&mut script, LIMIT).unwrap();
            assert!(response.body().is_empty(), "{status}");
        }
        assert_eq!(
            parse(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"),
            Err(Failure::Malformed)
        );
    }

    #[test]
    fn redirects_and_error_statuses_come_back_as_responses() {
        assert_eq!(
            parse(b"HTTP/1.1 302 Found\r\nLocation: https://example.com/\r\nContent-Length: 3\r\n\r\nbye"),
            ok(302, b"bye")
        );
        assert_eq!(
            parse(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\n\r\n{}"),
            ok(503, b"{}")
        );
    }

    #[test]
    fn a_safe_request_id_header_is_kept_and_any_other_dropped() {
        let request_id = |head: &str| {
            let bytes =
                format!("HTTP/1.1 429 Too Many Requests\r\n{head}Content-Length: 0\r\n\r\n");
            read(&mut Script::whole(bytes.into_bytes()), LIMIT)
                .unwrap()
                .request_id()
                .map(str::to_owned)
        };
        assert_eq!(
            request_id("X-Request-Id:  req_0123abcd \r\n").as_deref(),
            Some("req_0123abcd")
        );
        assert_eq!(
            request_id("x-request-id: req_0123abcd\r\n").as_deref(),
            Some("req_0123abcd")
        );
        assert_eq!(request_id(""), None);
        assert_eq!(request_id("X-Request-Id: req 0123\r\n"), None);
        assert_eq!(request_id("X-Request-Id: <script>\r\n"), None);
    }

    #[test]
    fn conflicting_or_broken_framing_is_malformed() {
        for head in [
            "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: chunked\r\nContent-Length: 1\r\n",
            "Content-Length: 1\r\nContent-Length: 1\r\n",
            "Content-Length: 1\r\ncontent-length: 2\r\n",
            "Content-Length: 1,1\r\n",
            "Content-Length: +1\r\n",
            "Content-Length: 0x1\r\n",
            "Content-Length: \r\n",
            "Content-Length: 99999999999999999999999\r\n",
            "Transfer-Encoding: gzip\r\n",
            "Transfer-Encoding: gzip, chunked\r\n",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        ] {
            let bytes = format!("HTTP/1.1 200 OK\r\n{head}\r\nx");
            assert_eq!(parse(bytes.as_bytes()), Err(Failure::Malformed), "{head:?}");
        }
    }

    #[test]
    fn malformed_status_lines_and_header_lines_are_refused() {
        for bytes in [
            "HTTP/2 200 OK\r\n\r\n",
            "HTTP/1.1 20 OK\r\n\r\n",
            "HTTP/1.1 2000 OK\r\n\r\n",
            "HTTP/1.1 600 Odd\r\n\r\n",
            "HTTP/1.1 099 Odd\r\n\r\n",
            "HTTP/1.1  200 OK\r\n\r\n",
            "HTTP/1.1 2x0 OK\r\n\r\n",
            "http/1.1 200 OK\r\n\r\n",
            "\r\nHTTP/1.1 200 OK\r\n\r\n",
            "HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nNo colon\r\n\r\n",
            "HTTP/1.1 200 OK\r\n folded: value\r\n\r\n",
            "HTTP/1.1 200 OK\r\nName : value\r\n\r\n",
            "HTTP/1.1 200 OK\r\nA: b\rc\r\n\r\n",
            "HTTP/1.1 200 OK\r\nA: b\0\r\n\r\n",
        ] {
            assert_eq!(
                parse(bytes.as_bytes()),
                Err(Failure::Malformed),
                "{bytes:?}"
            );
        }
    }

    #[test]
    fn malformed_chunks_are_refused() {
        for chunks in [
            "x\r\nhello\r\n0\r\n\r\n",
            "\r\nhello\r\n0\r\n\r\n",
            "-5\r\nhello\r\n0\r\n\r\n",
            "5 x\r\nhello\r\n0\r\n\r\n",
            "5\r\nhelloX\r\n0\r\n\r\n",
            "5\nhello\r\n0\r\n\r\n",
            "11111111111111111\r\n",
        ] {
            let bytes = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{chunks}");
            assert_eq!(
                parse(bytes.as_bytes()),
                Err(Failure::Malformed),
                "{chunks:?}"
            );
        }
    }

    #[test]
    fn a_body_that_ends_early_is_truncated() {
        for bytes in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nTrailer: x\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n",
            b"",
        ] {
            assert_eq!(parse(bytes), Err(Failure::Truncated), "{bytes:?}");
        }
    }

    #[test]
    fn a_body_of_exactly_the_limit_is_read_and_one_byte_more_fails() {
        let body = vec![b'a'; LIMIT];
        let over = vec![b'a'; LIMIT + 1];
        let length = |body: &[u8]| {
            let mut bytes =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
            bytes.extend_from_slice(body);
            bytes
        };
        let chunked = |body: &[u8]| {
            let mut bytes = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for chunk in body.chunks(10) {
                bytes.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                bytes.extend_from_slice(chunk);
                bytes.extend_from_slice(b"\r\n");
            }
            bytes.extend_from_slice(b"0\r\n\r\n");
            bytes
        };
        let until_close = |body: &[u8]| {
            let mut bytes = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
            bytes.extend_from_slice(body);
            bytes
        };
        for frame in [&length as &dyn Fn(&[u8]) -> Vec<u8>, &chunked, &until_close] {
            assert_eq!(parse(&frame(&body)), ok(200, &body));
            assert_eq!(parse(&frame(&over)), Err(Failure::TooLarge));
        }
    }

    #[test]
    fn a_declared_length_above_the_limit_fails_before_any_body_byte() {
        let mut script = Script::new([
            Ok(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", LIMIT + 1).into_bytes()),
            Ok(vec![b'a'; LIMIT + 1]),
        ]);
        assert_eq!(read(&mut script, LIMIT).unwrap_err(), Failure::TooLarge);
        assert_eq!(script.unread(), LIMIT + 1);

        let mut chunk = Script::new([
            Ok(format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                LIMIT + 1
            )
            .into_bytes()),
            Ok(vec![b'a'; LIMIT + 1]),
        ]);
        assert_eq!(read(&mut chunk, LIMIT).unwrap_err(), Failure::TooLarge);
        assert_eq!(chunk.unread(), LIMIT + 1);
    }

    #[test]
    fn a_body_that_crosses_the_limit_fails_without_reading_the_rest() {
        let mut script = Script::new([
            Ok(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
            Ok(vec![b'a'; LIMIT + 1000]),
        ]);
        assert_eq!(read(&mut script, LIMIT).unwrap_err(), Failure::TooLarge);
        assert_eq!(
            script.unread(),
            1000 - 1,
            "one byte past the limit was read"
        );
    }

    #[test]
    fn a_head_of_exactly_the_limit_is_read_and_one_byte_more_is_too_large() {
        let start = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Fill: ";
        let fill = HEAD_LIMIT - start.len() - 4;
        let fits = format!("{start}{}\r\n\r\n", "a".repeat(fill));
        assert_eq!(fits.len(), HEAD_LIMIT);
        assert_eq!(parse(fits.as_bytes()), ok(200, b""));
        let over = format!("{start}{}\r\n\r\n", "a".repeat(fill + 1));
        assert_eq!(parse(over.as_bytes()), Err(Failure::TooLarge));
    }

    #[test]
    fn interim_heads_count_against_the_head_limit() {
        let interim = "HTTP/1.1 100 Continue\r\n\r\n";
        let mut bytes = interim.repeat(HEAD_LIMIT / interim.len() + 1);
        bytes.push_str("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(parse(bytes.as_bytes()), Err(Failure::TooLarge));
    }

    #[test]
    fn overlong_chunk_lines_and_trailers_are_too_large() {
        let long = "a".repeat(LINE_LIMIT);
        for chunks in [
            format!("1;{long}\r\nx\r\n0\r\n\r\n"),
            format!("0\r\nTrailer: {long}\r\n\r\n"),
        ] {
            let bytes = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{chunks}");
            assert_eq!(parse(bytes.as_bytes()), Err(Failure::TooLarge));
        }
    }

    /// xorshift64*: enough randomness to shake a parser, same every run.
    struct Seeded(u64);

    impl Seeded {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % bound as u64).unwrap()
        }
    }

    #[test]
    fn random_and_truncated_responses_never_panic() {
        let valid: [&[u8]; 4] = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;e=1\r\nhello\r\n0\r\nT: x\r\n\r\n",
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.0 302 Found\r\n\r\nmoved",
            b"HTTP/1.1 204 No Content\r\n\r\n",
        ];
        let alphabet = b"HTTP/1.0 2345\r\n:;aAfF-ChunkedContent-LengthTransfer-Encoding";
        let mut random = Seeded(0x5157_c0de_2026_1123);
        let mut parsed = 0;
        for round in 0..600 {
            let source = valid[round % valid.len()];
            let mut bytes = source.to_vec();
            match round % 3 {
                0 => bytes.truncate(random.below(source.len() + 1)),
                1 => {
                    for _ in 0..1 + random.below(4) {
                        let at = random.below(bytes.len());
                        bytes[at] = alphabet[random.below(alphabet.len())];
                    }
                }
                _ => {
                    bytes = (0..random.below(200))
                        .map(|_| alphabet[random.below(alphabet.len())])
                        .collect();
                }
            }
            // Split into random pieces so every boundary gets hit.
            let mut pieces = Vec::new();
            let mut rest = bytes.as_slice();
            while !rest.is_empty() {
                let (piece, tail) = rest.split_at(1 + random.below(rest.len()));
                pieces.push(Ok(piece.to_vec()));
                rest = tail;
            }
            if read(&mut Script::new(pieces), 16).is_ok() {
                parsed += 1;
            }
        }
        assert!(parsed > 0, "some mutations still parse");
    }
}
