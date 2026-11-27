//! How a stream ended, and what may stand behind its last event.

use crate::error::{Error, ErrorKind};

use super::super::refusal::Refusal;
use super::super::stream_event::{StreamEvent, known_incomplete_reason};

/// Most bytes that may follow the event that ended an answer (4 KiB): room
/// for blank lines, comments and one closing `data: [DONE]`.
const MAX_TAIL_LEN: usize = 4096;

/// Why a stream can no longer be decoded. A decoder that met one of these
/// stays failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    TooLarge,
    Malformed,
    /// Something other than the allowed tail followed the last event.
    AfterEnd,
}

impl Fault {
    pub(super) fn error(self) -> Error {
        let message = match self {
            Self::TooLarge => "the streamed response frame exceeds the size limit",
            Self::Malformed => "the streamed response event is malformed",
            Self::AfterEnd => "the response stream went on after the event that ended it",
        };
        Error::new(ErrorKind::InvalidResponse, message)
    }
}

/// How an answer ended, as its last event said.
enum Ending {
    Completed,
    /// With the reason, if it is one the provider documents.
    Incomplete(Option<&'static str>),
    Failed(Box<Refusal>),
}

/// A stream from its last event on: how the answer ended, and the bytes
/// that followed. Those may be blank lines, comments that are text and one
/// complete `data: [DONE]` event, and nothing else; the last line has its
/// line end.
pub(super) struct Tail {
    ending: Ending,
    /// Bytes since the whole line end of the last event.
    len: usize,
    /// Whether the closing marker was seen.
    marked: bool,
    /// Whether the marker still waits for the blank line that ends it.
    in_marker: bool,
}

impl Tail {
    /// The tail that begins behind `event`, if that event ends an answer.
    pub(super) fn behind(event: &StreamEvent) -> Option<Self> {
        let ending = match event {
            StreamEvent::Completed => Ending::Completed,
            StreamEvent::Incomplete { reason } => {
                Ending::Incomplete(reason.as_deref().and_then(known_incomplete_reason))
            }
            StreamEvent::Failed(refusal) => Ending::Failed(Box::new(refusal.clone())),
            _ => return None,
        };
        Some(Self {
            ending,
            len: 0,
            marked: false,
            in_marker: false,
        })
    }

    /// Whether a byte was counted: the line end of the last event is over.
    pub(super) fn has_begun(&self) -> bool {
        self.len > 0
    }

    /// Counts one byte, from the first one behind the last event's whole
    /// line end.
    pub(super) fn count_byte(&mut self) -> Result<(), Fault> {
        self.len += 1;
        if self.len > MAX_TAIL_LEN {
            Err(Fault::AfterEnd)
        } else {
            Ok(())
        }
    }

    /// Takes one line without its line end: blank, a comment in UTF-8
    /// like every line before the last event, or the closing
    /// `data: [DONE]`, which comes once and is followed by its blank line.
    pub(super) fn line(&mut self, line: &[u8]) -> Result<(), Fault> {
        let allowed = match line {
            [] => {
                self.in_marker = false;
                true
            }
            [b':', ..] => !self.in_marker && std::str::from_utf8(line).is_ok(),
            b"data: [DONE]" | b"data:[DONE]" if !self.marked => {
                self.marked = true;
                self.in_marker = true;
                true
            }
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(Fault::AfterEnd)
        }
    }

    /// Whether the tail is whole at the end of the stream, with
    /// `unfinished` as the line that had no line end yet: there is no such
    /// line, a comment included, since a body that stops inside a line did
    /// not end where its sender meant it to; and a closing marker has its
    /// blank line.
    pub(super) fn is_whole(&self, unfinished: &[u8]) -> bool {
        !self.in_marker && unfinished.is_empty()
    }

    /// What the stream came to: `Ok` only for a whole tail behind
    /// `response.completed`.
    pub(super) fn result(self, unfinished: &[u8]) -> Result<(), Error> {
        if !self.is_whole(unfinished) {
            return Err(Fault::AfterEnd.error());
        }
        match self.ending {
            Ending::Completed => Ok(()),
            Ending::Incomplete(reason) => Err(Error::new(
                ErrorKind::Incomplete,
                "the answer stopped before it was complete",
            )
            .with_code(reason.map(str::to_owned))),
            Ending::Failed(refusal) => Err(Error::from(*refusal)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::SseDecoder;
    use super::*;

    #[test]
    #[expect(clippy::panic, reason = "unexpected decoder variants fail this test")]
    fn a_failure_event_and_the_saved_ending_both_own_wiping_diagnostics() {
        let mut decoder = SseDecoder::new();
        let events = decoder
            .feed(b"data: {\"type\":\"error\",\"code\":\"access_fake_1\",\"param\":\"access_fake_1\"}\n\n")
            .unwrap();
        let StreamEvent::Failed(original) = events[0].event() else {
            panic!("expected a failure event");
        };
        let Ending::Failed(saved) = &decoder.tail.as_ref().unwrap().ending else {
            panic!("expected a saved failure");
        };
        for refusal in [original, saved.as_ref()] {
            assert_eq!(refusal.provider_code(), Some("access_fake_1"));
            assert_eq!(refusal.param(), Some("access_fake_1"));
            refusal.assert_wiping_diagnostics();
        }
    }
}
