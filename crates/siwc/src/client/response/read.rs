//! Reading an accepted answer: which event is handed out next, and how the
//! answer ends.

use std::collections::VecDeque;
use std::io::Read;

use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind};
use crate::plan::{ResponseEvent, SseDecoder, StreamEvent, known_incomplete_reason};

use super::Attempts;

/// Most opening events held back until the first one that carries output.
const HELD_EVENTS: usize = 8;

/// Most JSON those held events have together (16 MiB): the size one event
/// may have, so holding several back costs no more memory than one.
const HELD_BYTES: usize = 16 * 1024 * 1024;

/// The reader and undelivered events of an accepted answer.
pub(super) struct Reading {
    body: Box<dyn Read + Send>,
    decoder: SseDecoder,
    buffer: Zeroizing<Vec<u8>>,
    ready: VecDeque<ResponseEvent>,
    /// Opening events held until the first event of another kind.
    held: Option<VecDeque<ResponseEvent>>,
    broken: Option<Error>,
}

impl Reading {
    pub(super) fn new(body: Box<dyn Read + Send>) -> Self {
        Self {
            body,
            decoder: SseDecoder::new(),
            buffer: Zeroizing::new(vec![0; super::READ_SIZE]),
            ready: VecDeque::new(),
            held: Some(VecDeque::new()),
            broken: None,
        }
    }

    /// The next event and the reader to park, if more events can follow.
    pub(super) fn advance(
        mut self,
        attempts: &Attempts,
    ) -> Result<(ResponseEvent, Option<Self>), Error> {
        loop {
            // A cancelled stream hands out nothing more, read or not.
            attempts.stop_if_cancelled()?;
            let Some(event) = self.ready.pop_front() else {
                if let Some(error) = self.broken.take() {
                    return Err(attempts.answered(error, None));
                }
                self.fill(attempts)?;
                continue;
            };
            if let StreamEvent::Failed(refusal) = event.event() {
                // The HTTP head already accepted this POST. Return the
                // refusal without reading further or sending again.
                return Err(refusal
                    .clone()
                    .with_request_id(attempts.request_id.as_deref())
                    .into());
            }
            if let Some(held) = &mut self.held
                && opens_an_answer(&event)
            {
                let bytes = held.iter().map(|held| held.json().len()).sum::<usize>();
                if held.len() >= HELD_EVENTS || bytes + event.json().len() > HELD_BYTES {
                    return Err(attempts.answered(
                        Error::new(
                            ErrorKind::InvalidResponse,
                            "the answer opened with more events than a stream holds back",
                        ),
                        None,
                    ));
                }
                held.push_back(event);
                continue;
            }
            if let Some(held) = self.held.take().filter(|held| !held.is_empty()) {
                self.ready.push_front(event);
                for opening in held.into_iter().rev() {
                    self.ready.push_front(opening);
                }
                continue;
            }
            match event.event() {
                StreamEvent::Incomplete { reason } => {
                    // Only a documented reason is named; any other value
                    // could be anything the provider echoed.
                    let reason = reason.as_deref().and_then(known_incomplete_reason);
                    return Err(attempts.answered(
                        Error::new(
                            ErrorKind::Incomplete,
                            "the answer stopped before it was complete",
                        )
                        .with_code(reason.map(str::to_owned)),
                        None,
                    ));
                }
                StreamEvent::Completed => {
                    self.confirm_end(attempts)?;
                    return Ok((event, None));
                }
                _ => return Ok((event, Some(self))),
            }
        }
    }

    /// Reads once from the connection and decodes what arrived.
    fn fill(&mut self, attempts: &Attempts) -> Result<(), Error> {
        let Some(count) = self.read(attempts)? else {
            return Err(attempts.answered(
                Error::new(
                    ErrorKind::Temporary,
                    "the response stream ended before response.completed",
                ),
                None,
            ));
        };
        let bytes = self.buffer.get(..count).unwrap_or_default();
        // Events that were complete go out before the error that follows
        // them, however the bytes were split into reads.
        let (events, error) = self.decoder.feed_and_error(bytes);
        self.ready.extend(events);
        self.broken = error;
        Ok(())
    }

    /// After the event that ended the answer: reads the body to the end of
    /// its framing. Only an answer whose body ended the way its head
    /// announced has ended; a cut chunk or a missing byte of the declared
    /// length would otherwise go unnoticed behind the last event. What the
    /// body may still hold is the decoder's to say: blank lines, comments
    /// and one closing `data: [DONE]`, 4 KiB in all.
    fn confirm_end(&mut self, attempts: &Attempts) -> Result<(), Error> {
        if let Some(error) = self.broken.take() {
            return Err(attempts.answered(error, None));
        }
        loop {
            let count = self.read(attempts)?;
            let checked = match count {
                None => {
                    return self
                        .decoder
                        .tail_at_end()
                        .map_err(|e| attempts.answered(e, None));
                }
                Some(count) => {
                    let bytes = self.buffer.get(..count).unwrap_or_default();
                    self.decoder.feed_and_error(bytes).1
                }
            };
            if let Some(error) = checked {
                return Err(attempts.answered(error, None));
            }
        }
    }

    /// Reads once into the buffer: the number of bytes, or `None` at the
    /// clean end of the body. The canceller is looked at before every call
    /// of the transport's reader and after it, so a reader that does not
    /// watch it itself is asked no more than once after a cancellation, and
    /// neither bytes nor the end of a cancelled answer are accepted.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Cancelled`] when the stream was cancelled, otherwise
    /// [`ErrorKind::Temporary`] when the body broke off or stalled.
    fn read(&mut self, attempts: &Attempts) -> Result<Option<usize>, Error> {
        let count = attempts.read_body(&mut self.body, &mut self.buffer, || {
            attempts.answered(
                Error::new(
                    ErrorKind::Temporary,
                    "the response stream broke off before its end",
                ),
                None,
            )
        })?;
        Ok((count != 0).then_some(count))
    }
}

/// Whether `event` only says that an answer began, without output.
fn opens_an_answer(event: &ResponseEvent) -> bool {
    matches!(event.event(), StreamEvent::Other)
        && matches!(
            event.event_type(),
            Some("response.created" | "response.in_progress" | "response.queued")
        )
}
