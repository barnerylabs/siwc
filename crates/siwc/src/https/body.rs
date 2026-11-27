//! The body of one HTTP/1.x response, decoded from its framing piece by
//! piece.
//!
//! The decoder keeps no body bytes of its own: what it hands out comes
//! straight from the input's fixed read buffer, so memory stays the same
//! however long the body is.

use std::io::{self, Read};

use crate::error::ErrorCause;
use crate::protocol::is_token;

use super::input::{Failure, Input};

/// Largest chunk-size line, extensions included, and largest trailer
/// section of a chunked body.
pub(super) const LINE_LIMIT: usize = 4 * 1024;

/// How the body of a response is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Framing {
    /// No body at all, as after `204` and `304`.
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

/// A response body behind its framing. [`pull`](Self::pull) and `Read`
/// hand out the body's bytes and end only where the framing says so.
pub(super) struct Body<R> {
    input: Input<R>,
    state: State,
    /// Bytes the body may still hand out; `None` without a limit.
    allowance: Option<usize>,
}

/// Where the decoder is in the body.
#[derive(Debug, Clone, Copy)]
enum State {
    /// Inside a `Content-Length` body with this many bytes to go.
    Length(u64),
    /// Before a chunk-size line.
    ChunkSize,
    /// Inside a chunk with this many bytes to go, then its `\r\n`.
    Chunk(u64),
    /// After the last chunk, before the blank line that ends the trailers.
    Trailers,
    /// A body that runs until the stream ends cleanly.
    UntilClose,
    Done,
    Failed(Failure),
}

impl<R: Read> Body<R> {
    /// The body that follows a head in `input`. With an `allowance`, a body
    /// that declares or delivers more bytes than that is too large.
    pub(super) fn new(
        input: Input<R>,
        framing: Framing,
        allowance: Option<usize>,
    ) -> Result<Self, Failure> {
        let mut body = Self {
            input,
            state: State::Done,
            allowance,
        };
        body.state = match framing {
            Framing::None => State::Done,
            Framing::Length(length) => {
                body.admit(length)?;
                State::Length(length)
            }
            Framing::Chunked => State::ChunkSize,
            Framing::UntilClose => State::UntilClose,
        };
        Ok(body)
    }

    /// The stream the body is read from.
    pub(super) fn reader_mut(&mut self) -> &mut R {
        self.input.reader_mut()
    }

    /// Copies the next bytes of the body into `buffer` and returns how
    /// many; `0` at the end of the body, and for an empty `buffer`. After a
    /// failure every further call fails the same way.
    pub(super) fn pull(&mut self, buffer: &mut [u8]) -> Result<usize, Failure> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let step = self.step(buffer);
        if let Err(failure) = step {
            self.state = State::Failed(failure);
        }
        step
    }

    fn step(&mut self, buffer: &mut [u8]) -> Result<usize, Failure> {
        loop {
            match self.state {
                State::Done => return Ok(0),
                State::Failed(failure) => return Err(failure),
                State::Length(0) => self.state = State::Done,
                State::Length(left) => {
                    let count = self.data(left, buffer)?;
                    self.state = State::Length(left.saturating_sub(wide(count)));
                    return Ok(count);
                }
                State::ChunkSize => {
                    let mut budget = LINE_LIMIT;
                    let size = parse_chunk_size(&self.input.line(&mut budget)?)?;
                    if size == 0 {
                        self.state = State::Trailers;
                    } else {
                        self.admit(size)?;
                        self.state = State::Chunk(size);
                    }
                }
                State::Chunk(0) => {
                    if [self.input.byte()?, self.input.byte()?] != *b"\r\n" {
                        return Err(Failure::Malformed);
                    }
                    self.state = State::ChunkSize;
                }
                State::Chunk(left) => {
                    let count = self.data(left, buffer)?;
                    self.state = State::Chunk(left.saturating_sub(wide(count)));
                    return Ok(count);
                }
                State::Trailers => {
                    // Trailer fields are checked and dropped up to the
                    // blank line.
                    let mut budget = LINE_LIMIT;
                    loop {
                        let line = self.input.line(&mut budget)?;
                        if line.is_empty() {
                            break;
                        }
                        field(&line)?;
                    }
                    self.state = State::Done;
                }
                State::UntilClose => {
                    // One byte past the allowance is enough to know it is
                    // crossed.
                    let room = self
                        .allowance
                        .map_or(buffer.len(), |left| left.saturating_add(1));
                    let bytes = self.input.next(room.min(buffer.len()))?;
                    if bytes.is_empty() {
                        self.state = State::Done;
                        return Ok(0);
                    }
                    if self.allowance.is_some_and(|left| bytes.len() > left) {
                        return Err(Failure::TooLarge);
                    }
                    let count = copy(bytes, buffer)?;
                    self.spend(count);
                    return Ok(count);
                }
            }
        }
    }

    /// Refuses a declared length above what the body may still hand out.
    fn admit(&self, declared: u64) -> Result<(), Failure> {
        match self.allowance {
            Some(left) if usize::try_from(declared).map_or(true, |size| size > left) => {
                Err(Failure::TooLarge)
            }
            _ => Ok(()),
        }
    }

    /// Copies up to `left` bytes of a length-delimited part into `buffer`;
    /// the stream ending inside it is a truncation.
    fn data(&mut self, left: u64, buffer: &mut [u8]) -> Result<usize, Failure> {
        let most = usize::try_from(left)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let bytes = self.input.next(most)?;
        if bytes.is_empty() {
            return Err(Failure::Truncated);
        }
        let count = copy(bytes, buffer)?;
        self.spend(count);
        Ok(count)
    }

    fn spend(&mut self, count: usize) {
        if let Some(left) = &mut self.allowance {
            *left = left.saturating_sub(count);
        }
    }
}

/// A body read to its end returns `Ok(0)`; a stream that fails, ends inside
/// the framing or breaks it is an error, never a clean end.
impl<R: Read> Read for Body<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // The crate's own cause rides along, so the client can tell a
        // stalled body from a malformed one without parsing anything.
        self.pull(buffer).map_err(|failure| {
            let kind = match failure {
                Failure::Read(_) => io::ErrorKind::ConnectionAborted,
                Failure::Truncated => io::ErrorKind::UnexpectedEof,
                Failure::Malformed | Failure::TooLarge => io::ErrorKind::InvalidData,
            };
            io::Error::new(kind, failure.cause())
        })
    }
}

/// Copies `bytes` to the start of `buffer`, which is at least as long.
fn copy(bytes: &[u8], buffer: &mut [u8]) -> Result<usize, Failure> {
    let target = buffer
        .get_mut(..bytes.len())
        .ok_or(Failure::Read(ErrorCause::Io(io::ErrorKind::Other)))?;
    target.copy_from_slice(bytes);
    Ok(bytes.len())
}

fn wide(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// Whether `line` holds no control byte other than a tab.
pub(super) fn is_text(line: &[u8]) -> bool {
    line.iter()
        .all(|byte| *byte == b'\t' || (*byte >= b' ' && *byte != 0x7f))
}

/// One header or trailer field without its line end, as name and value: a
/// token, a colon and text. A name with spaces, a folded continuation line
/// or a line without a colon is malformed.
pub(super) fn field(line: &[u8]) -> Result<(&[u8], &[u8]), Failure> {
    let colon = line.iter().position(|byte| *byte == b':');
    let parts = colon.and_then(|colon| Some((line.get(..colon)?, line.get(colon + 1..)?)));
    match parts {
        Some((name, value)) if is_token(name) && is_text(value) => Ok((name, value)),
        _ => Err(Failure::Malformed),
    }
}

/// A chunk-size line: hexadecimal digits, then optional extensions, which
/// are checked and dropped.
fn parse_chunk_size(line: &[u8]) -> Result<u64, Failure> {
    let digits = line
        .iter()
        .position(|byte| !byte.is_ascii_hexdigit())
        .unwrap_or(line.len());
    let (size, rest) = line.split_at_checked(digits).ok_or(Failure::Malformed)?;
    if size.is_empty() {
        return Err(Failure::Malformed);
    }
    check_extensions(rest)?;
    size.iter().try_fold(0_u64, |total, byte| {
        let digit = char::from(*byte).to_digit(16).map(u64::from);
        digit
            .and_then(|digit| total.checked_mul(16)?.checked_add(digit))
            .ok_or(Failure::Malformed)
    })
}

/// The extensions of a chunk-size line: any number of `;name` or
/// `;name=value`, where a name is a token and a value a token or a quoted
/// string. RFC 9112 §7.1.1 allows blanks around `;` and `=` only as
/// part of the extension that supplies the delimiter.
fn check_extensions(mut rest: &[u8]) -> Result<(), Failure> {
    while !rest.is_empty() {
        let extension = after_blanks(rest)
            .strip_prefix(b";")
            .ok_or(Failure::Malformed)?;
        rest = after_token(after_blanks(extension))?;
        if let Some(value) = after_blanks(rest).strip_prefix(b"=") {
            let value = after_blanks(value);
            rest = match value.strip_prefix(b"\"") {
                Some(quoted) => after_quoted(quoted)?,
                None => after_token(value)?,
            };
        }
    }
    Ok(())
}

fn after_blanks(text: &[u8]) -> &[u8] {
    let blanks = text
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(text.len());
    text.get(blanks..).unwrap_or_default()
}

/// What follows the token `text` starts with; no token there is malformed.
fn after_token(text: &[u8]) -> Result<&[u8], Failure> {
    let len = text
        .iter()
        .position(|byte| !is_token(std::slice::from_ref(byte)))
        .unwrap_or(text.len());
    match text.split_at_checked(len) {
        Some((token, rest)) if !token.is_empty() => Ok(rest),
        _ => Err(Failure::Malformed),
    }
}

/// What follows the closing quote of a quoted string whose opening quote
/// was just read. A backslash takes the next byte as it is, a quote
/// included, but that byte is text like every other: no control byte.
fn after_quoted(text: &[u8]) -> Result<&[u8], Failure> {
    let mut bytes = text.iter();
    while let Some(byte) = bytes.next() {
        let checked = match byte {
            b'"' => return Ok(bytes.as_slice()),
            b'\\' => bytes.next(),
            _ => Some(byte),
        };
        if !checked.is_some_and(|byte| is_text(std::slice::from_ref(byte))) {
            break;
        }
    }
    Err(Failure::Malformed)
}

#[cfg(test)]
mod tests {
    use super::super::input::READ_SIZE;
    use super::*;

    /// Hands out at most `step` bytes per read, then the scripted end.
    struct Pieces<'a> {
        rest: &'a [u8],
        step: usize,
        end: io::Result<usize>,
    }

    impl<'a> Pieces<'a> {
        fn new(bytes: &'a [u8], step: usize) -> Self {
            Self {
                rest: bytes,
                step,
                end: Ok(0),
            }
        }
    }

    impl Read for Pieces<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.rest.is_empty() {
                return match &self.end {
                    Ok(count) => Ok(*count),
                    Err(error) => Err(error.kind().into()),
                };
            }
            let count = self.step.min(self.rest.len()).min(buffer.len());
            let (piece, rest) = self.rest.split_at(count);
            buffer[..count].copy_from_slice(piece);
            self.rest = rest;
            Ok(count)
        }
    }

    /// The body `wire` decodes to, read through a buffer of `room` bytes,
    /// with every piece that came out and how the reading ended.
    fn pieces(
        wire: &[u8],
        framing: Framing,
        step: usize,
        room: usize,
    ) -> (Vec<Vec<u8>>, io::Result<()>) {
        let input = Input::new(Pieces::new(wire, step));
        let mut body = Body::new(input, framing, None).unwrap();
        let mut seen = Vec::new();
        let mut buffer = vec![0; room];
        loop {
            match body.read(&mut buffer) {
                Ok(0) => return (seen, Ok(())),
                Ok(count) => seen.push(buffer[..count].to_vec()),
                Err(error) => return (seen, Err(error)),
            }
        }
    }

    const CHUNKED: &[u8] =
        b"5;ext=1\r\nhello\r\n1\r\n,\r\nA\r\n world!!!!\r\n0\r\nTrailer: x\r\n\r\n";

    #[test]
    fn a_chunked_body_decodes_the_same_however_the_bytes_and_reads_are_split() {
        for step in [1, 2, 3, 5, 7, 16, 1000] {
            for room in [1, 2, 3, 4, 64] {
                let (seen, end) = pieces(CHUNKED, Framing::Chunked, step, room);
                end.unwrap();
                assert_eq!(seen.concat(), b"hello, world!!!!", "{step} {room}");
                assert!(seen.iter().all(|piece| piece.len() <= room));
            }
        }
    }

    #[test]
    fn a_chunk_is_handed_out_as_soon_as_its_first_bytes_arrive() {
        // The second chunk never completes, yet the first one is delivered.
        let wire = b"5\r\nhello\r\n5\r\nwo";
        let (seen, end) = pieces(wire, Framing::Chunked, 1000, 64);
        assert_eq!(seen, [b"hello".to_vec(), b"wo".to_vec()]);
        assert_eq!(end.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_body_of_a_declared_length_ends_there_and_reads_nothing_after_it() {
        let input = Input::new(Pieces {
            rest: b"hello",
            step: 2,
            end: Err(io::ErrorKind::UnexpectedEof.into()),
        });
        let mut body = Body::new(input, Framing::Length(5), None).unwrap();
        let mut text = String::new();
        body.read_to_string(&mut text).unwrap();
        assert_eq!(text, "hello");
        assert_eq!(body.read(&mut [0; 8]).unwrap(), 0);
    }

    #[test]
    fn a_body_until_close_ends_with_a_clean_end_and_fails_with_a_broken_one() {
        let (seen, end) = pieces(b"all of it", Framing::UntilClose, 4, 64);
        end.unwrap();
        assert_eq!(seen.concat(), b"all of it");

        let input = Input::new(Pieces {
            rest: b"cut",
            step: 8,
            end: Err(io::ErrorKind::UnexpectedEof.into()),
        });
        let mut body = Body::new(input, Framing::UntilClose, None).unwrap();
        let mut buffer = [0; 8];
        assert_eq!(body.read(&mut buffer).unwrap(), 3);
        let error = body.read(&mut buffer).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[test]
    fn a_broken_or_cut_chunk_fails_and_keeps_failing() {
        for (wire, kind) in [
            (&b"zz\r\nhello\r\n"[..], io::ErrorKind::InvalidData),
            (b"5\r\nhelloXX0\r\n\r\n", io::ErrorKind::InvalidData),
            (b"5\r\nhel", io::ErrorKind::UnexpectedEof),
            (b"5\r\nhello\r\n", io::ErrorKind::UnexpectedEof),
            (b"5\r\nhello\r\n0\r\n", io::ErrorKind::UnexpectedEof),
            (b"", io::ErrorKind::UnexpectedEof),
        ] {
            let input = Input::new(Pieces::new(wire, 3));
            let mut body = Body::new(input, Framing::Chunked, None).unwrap();
            // Reading to the end fails; the body never ends cleanly.
            let first = body.read_to_end(&mut Vec::new()).unwrap_err();
            let mut buffer = [0; 16];
            assert_eq!(first.kind(), kind, "{wire:?}");
            assert_eq!(body.read(&mut buffer).unwrap_err().kind(), kind);
        }
    }

    #[test]
    fn an_empty_body_and_an_empty_buffer_read_nothing() {
        let input = Input::new(Pieces {
            rest: b"",
            step: 1,
            end: Err(io::ErrorKind::UnexpectedEof.into()),
        });
        let mut body = Body::new(input, Framing::None, None).unwrap();
        assert_eq!(body.read(&mut [0; 4]).unwrap(), 0);

        let input = Input::new(Pieces::new(b"5\r\nhello\r\n0\r\n\r\n", 100));
        let mut body = Body::new(input, Framing::Chunked, None).unwrap();
        assert_eq!(body.read(&mut []).unwrap(), 0);
        let mut text = String::new();
        body.read_to_string(&mut text).unwrap();
        assert_eq!(text, "hello");
    }

    /// A chunked body that never ends: the same chunk again and again.
    struct Endless {
        chunk: Vec<u8>,
        at: usize,
        served: u64,
    }

    impl Read for Endless {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let rest = &self.chunk[self.at..];
            let count = rest.len().min(buffer.len());
            buffer[..count].copy_from_slice(&rest[..count]);
            self.at = (self.at + count) % self.chunk.len();
            self.served += count as u64;
            Ok(count)
        }
    }

    #[test]
    fn a_body_of_any_length_passes_through_one_fixed_buffer() {
        // 64 MiB of chunks of 100 000 bytes each, larger than the buffer.
        const CHUNK: usize = 100_000;
        const TOTAL: u64 = 64 * 1024 * 1024;
        let mut chunk = format!("{CHUNK:x}\r\n").into_bytes();
        chunk.extend(std::iter::repeat_n(b'a', CHUNK));
        chunk.extend_from_slice(b"\r\n");
        let wire_per_chunk = chunk.len() as u64;
        let source = Endless {
            chunk,
            at: 0,
            served: 0,
        };
        let mut body = Body::new(Input::new(source), Framing::Chunked, None).unwrap();
        let mut buffer = [0; 4096];
        let mut read = 0_u64;
        while read < TOTAL {
            let count = body.read(&mut buffer).unwrap();
            assert!(count > 0);
            read += count as u64;
        }
        // The decoder never ran ahead of its reader by more than its one
        // buffer, so it cannot be holding the body.
        let consumed = read / CHUNK as u64 * wire_per_chunk + wire_per_chunk;
        let served = body.reader_mut().served;
        assert!(served <= consumed + READ_SIZE as u64, "{served} {consumed}");
    }

    #[test]
    fn chunk_sizes_are_hexadecimal_with_optional_extensions() {
        assert_eq!(parse_chunk_size(b"0"), Ok(0));
        assert_eq!(parse_chunk_size(b"1f;name=value"), Ok(31));
        assert_eq!(parse_chunk_size(b"A ; b"), Ok(10));
        assert_eq!(parse_chunk_size(b"ffffffffffffffff"), Ok(u64::MAX));
        for line in [&b""[..], b";x", b"g", b"1 2", b"-1", b"10000000000000000"] {
            assert_eq!(parse_chunk_size(line), Err(Failure::Malformed), "{line:?}");
        }
    }

    #[test]
    fn chunk_extensions_are_names_with_optional_token_or_quoted_values() {
        for line in [
            &b"1;a"[..],
            b"1;a;b",
            b"1 ; a = b ; c",
            b"1;a=\"b c; \\\" d\"",
            b"1;a=\"\";b=1",
            b"1\t; a \t= b\t; c",
        ] {
            assert_eq!(parse_chunk_size(line), Ok(1), "{line:?}");
        }
        for line in [
            &b"1;"[..],
            b"1;=",
            b"1;=b",
            b"1;a=",
            b"1;a=;b",
            b"1;a b",
            b"1;a=b c",
            b"1;a=\"b",
            b"1;a=\"b\\",
            b"1;a=\"b\"c",
            b"1;a=\"\x01\"",
            b"1;a=\"\\\x00\"",
            b"1;a=\"\\\x7f\"",
            b"1;a;",
            b"1;a,b",
            b"1 ",
            b"0\t",
            b"1;a ",
            b"1;a=b\t",
            b"0;a=\"b\" ",
        ] {
            assert_eq!(parse_chunk_size(line), Err(Failure::Malformed), "{line:?}");
        }
    }

    #[test]
    fn trailers_are_header_fields_or_the_body_is_malformed() {
        let read = |wire: &[u8]| {
            let input = Input::new(Pieces::new(wire, 3));
            let mut body = Body::new(input, Framing::Chunked, None).unwrap();
            let mut text = Vec::new();
            body.read_to_end(&mut text).map(|_| text)
        };
        assert_eq!(read(b"1\r\na\r\n0\r\n\r\n").unwrap(), b"a");
        let fields = b"1\r\na\r\n0\r\nChecksum: abc\r\nEmpty:\r\n\r\n";
        assert_eq!(read(fields).unwrap(), b"a");
        for wire in [
            &b"1\r\na\r\n0\r\nno-colon\r\n\r\n"[..],
            b"1\r\na\r\n0\r\n: no name\r\n\r\n",
            b"1\r\na\r\n0\r\nA name: x\r\n\r\n",
            b"1\r\na\r\n0\r\nOne: x\r\n folded\r\n\r\n",
            b"1\r\na\r\n0\r\nOne: \x00\r\n\r\n",
            b"1;=\r\na\r\n0\r\n\r\n",
        ] {
            let error = read(wire).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{wire:?}");
        }
    }
}
