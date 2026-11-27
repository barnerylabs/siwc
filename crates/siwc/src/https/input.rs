//! A byte stream with a read buffer in front of it, read within limits.
//!
//! The buffer knows nothing about sockets or time: the stream it is given
//! enforces the deadline and reports it as a failed read.

use std::io::{self, Read};

use zeroize::Zeroizing;

use crate::error::ErrorCause;
use crate::transport::cause;

/// Bytes asked from the stream in one read.
pub(super) const READ_SIZE: usize = 16 * 1024;

/// Why no response, or no more of its body, came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Failure {
    /// The stream failed for this cause, including a deadline, a TLS close
    /// without `close_notify` or a TLS record that did not verify.
    Read(ErrorCause),
    /// The stream ended before the response did.
    Truncated,
    /// The bytes are not an HTTP/1.x response this reader accepts.
    Malformed,
    /// The head or the body is larger than its limit.
    TooLarge,
}

impl Failure {
    /// The safe cause an error about this failure carries.
    pub(super) fn cause(self) -> ErrorCause {
        match self {
            Self::Read(cause) => cause,
            Self::Truncated => ErrorCause::ConnectionClosed,
            Self::Malformed => ErrorCause::InvalidFraming,
            Self::TooLarge => ErrorCause::ResponseTooLarge,
        }
    }
}

/// The stream with a read buffer in front of it. The buffer has one fixed
/// size and is wiped when dropped.
pub(super) struct Input<R> {
    reader: R,
    buffer: Zeroizing<Vec<u8>>,
    start: usize,
    end: usize,
}

impl<R: Read> Input<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Zeroizing::new(vec![0; READ_SIZE]),
            start: 0,
            end: 0,
        }
    }

    /// The stream behind the buffer.
    pub(super) fn reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Up to `most` buffered bytes, reading once from the stream if none are
    /// left; empty at the end of the stream.
    pub(super) fn next(&mut self, most: usize) -> Result<&[u8], Failure> {
        if self.start == self.end {
            let room = most.min(READ_SIZE);
            let spare = self
                .buffer
                .get_mut(..room)
                .ok_or(Failure::Read(ErrorCause::Io(io::ErrorKind::Other)))?;
            let read = loop {
                match self.reader.read(spare) {
                    Ok(read) => break read.min(room),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(Failure::Read(cause::of_io(&error))),
                }
            };
            self.start = 0;
            self.end = read;
        }
        let end = self.end.min(self.start.saturating_add(most));
        let bytes = self
            .buffer
            .get(self.start..end)
            .ok_or(Failure::Read(ErrorCause::Io(io::ErrorKind::Other)))?;
        self.start = end;
        Ok(bytes)
    }

    /// The next byte, or `Truncated` at the end of the stream.
    pub(super) fn byte(&mut self) -> Result<u8, Failure> {
        match self.next(1)? {
            [byte] => Ok(*byte),
            _ => Err(Failure::Truncated),
        }
    }

    /// Bytes up to and including `terminator`, taken from `budget`.
    pub(super) fn until(
        &mut self,
        terminator: &[u8],
        budget: &mut usize,
    ) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(*budget));
        while !bytes.ends_with(terminator) {
            if *budget == 0 {
                return Err(Failure::TooLarge);
            }
            *budget -= 1;
            bytes.push(self.byte()?);
        }
        Ok(bytes)
    }

    /// One line up to `\r\n`, which is not included, taken from `budget`.
    pub(super) fn line(&mut self, budget: &mut usize) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let mut line = self.until(b"\r\n", budget)?;
        let content = line.len().saturating_sub(2);
        line.truncate(content);
        if line.contains(&b'\r') || line.contains(&b'\n') {
            return Err(Failure::Malformed);
        }
        Ok(line)
    }
}
