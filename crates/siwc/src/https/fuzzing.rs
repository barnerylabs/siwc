//! Entry points for the cargo-fuzz harnesses, built only with
//! `--cfg fuzzing`.

use std::io::Read;

use super::input::Failure;
use super::{proxy, response};
use crate::transport::roots;

/// Largest body the harnesses read.
const BODY_LIMIT: usize = 64 * 1024;

/// Hands out at most `size` bytes per read, then the end of the stream.
struct Pieces<'a> {
    rest: &'a [u8],
    size: usize,
}

impl Read for Pieces<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.size.min(self.rest.len()).min(buffer.len());
        let (piece, rest) = self.rest.split_at(count);
        buffer[..count].copy_from_slice(piece);
        self.rest = rest;
        Ok(count)
    }
}

/// Reads `data` as one HTTP/1.x response, in pieces of the size the first
/// byte names. For cargo-fuzz harnesses only.
pub fn fuzz_response(data: &[u8]) {
    let Some((&size, rest)) = data.split_first() else {
        return;
    };
    let mut response_reader = Pieces {
        rest,
        size: usize::from(size.max(1)),
    };
    let _parsed = response::read(&mut response_reader, BODY_LIMIT);
    let mut connect_reader = Pieces { rest, size: 1 };
    let _tunnel = proxy::read_connect_response(&mut connect_reader);
    let _roots = roots::parse_pem(rest);
    if let Ok(text) = std::str::from_utf8(rest) {
        let _proxy = proxy::Proxy::parse(text);
    }
}

/// What reading a response piece by piece gave: the status with the body
/// read before the end, and how reading ended.
type Streamed = Result<(response::Head, Vec<u8>, Result<(), Failure>), Failure>;

/// Reads the response in `wire` as a stream: the socket hands out `step`
/// bytes per read and the caller asks for `room` bytes at a time.
fn streamed(wire: &[u8], step: usize, room: usize) -> Streamed {
    let reader = Pieces {
        rest: wire,
        size: step,
    };
    let (head, mut body) = response::open(reader, None)?;
    let mut bytes = Vec::new();
    let mut buffer = vec![0; room];
    let end = loop {
        match body.pull(&mut buffer) {
            Ok(0) => break Ok(()),
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(failure) => break Err(failure),
        }
        if bytes.len() > BODY_LIMIT {
            return Ok((head, Vec::new(), Err(Failure::TooLarge)));
        }
    };
    Ok((head, bytes, end))
}

/// Reads `data` as one HTTP/1.x response whose body is streamed. The first
/// byte names how many bytes the socket hands out per read, the second how
/// many the reader asks for. For cargo-fuzz harnesses only.
///
/// # Panics
///
/// When the decoded body depends on how the bytes were split, or when the
/// streamed body differs from the one [`fuzz_response`]'s reader returns
/// whole.
#[expect(
    clippy::panic,
    reason = "a harness reports a broken property to the fuzzer by panicking"
)]
pub fn fuzz_stream(data: &[u8]) {
    let [step, room, wire @ ..] = data else {
        return;
    };
    let step = usize::from((*step).max(1));
    let room = usize::from((*room).max(1));
    let split = streamed(wire, step, room);
    let byte_wise = streamed(wire, 1, 1);
    assert_eq!(split, byte_wise, "the split changed what was decoded");

    let mut reader = Pieces {
        rest: wire,
        size: step,
    };
    let whole = response::read(&mut reader, BODY_LIMIT);
    match (&split, &whole) {
        (Ok((head, body, Ok(()))), Ok(response)) => {
            let streamed = crate::protocol::StreamingResponse::new(head.status, std::io::empty())
                .with_request_id(head.request_id())
                .with_retry_after(head.retry_after());
            assert_eq!(streamed.status(), response.status());
            assert_eq!(streamed.request_id(), response.request_id());
            assert_eq!(streamed.retry_after(), response.retry_after());
            assert_eq!(body.as_slice(), response.body());
        }
        (Ok((_, body, Ok(()))), Err(_)) => {
            panic!("a clean stream of {} bytes failed whole", body.len());
        }
        (_, Ok(_)) => panic!("a whole response did not stream cleanly"),
        (_, Err(_)) => {}
    }
}
