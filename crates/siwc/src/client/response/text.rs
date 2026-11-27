//! The whole text of an answer, collected within a fixed budget.

use zeroize::{Zeroize, Zeroizing};

use crate::error::{Answer, Error, ErrorKind};
use crate::plan::ResponseEvent;

/// Most bytes of text `into_text` collects: 16 MiB.
pub(in crate::client) const TEXT_LIMIT: usize = 16 * 1024 * 1024;

/// The text of an answer while it is put together. What was collected is
/// wiped unless the answer completes, and so is every buffer the text
/// outgrew on the way.
pub(in crate::client) struct Collected(Zeroizing<String>);

impl Collected {
    pub(in crate::client) fn new() -> Self {
        Self(Zeroizing::new(String::new()))
    }

    /// Collects the event's text, keeping its answer's checked ID on errors.
    pub(in crate::client) fn collect(
        &mut self,
        event: &ResponseEvent,
        request_id: Option<&str>,
    ) -> Result<(), Error> {
        if let Some(delta) = event.text_delta() {
            self.push(delta).map_err(|error| {
                error.with_answer(Answer {
                    request_id: request_id.map(Box::from),
                    ..Answer::default()
                })
            })?;
        }
        Ok(())
    }

    fn push(&mut self, delta: &str) -> Result<(), Error> {
        let needed = self
            .0
            .len()
            .checked_add(delta.len())
            .filter(|needed| *needed <= TEXT_LIMIT)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidResponse,
                    "the answer is longer than the 16 MiB into_text collects",
                )
            })?;
        if needed > self.0.capacity() {
            // Into a larger buffer of its own: a reallocation would free
            // the old one as it is, and this way it is wiped.
            let capacity = needed
                .max(self.0.capacity().saturating_mul(2))
                .min(TEXT_LIMIT);
            let mut larger = text_buffer(capacity)?;
            larger.push_str(&self.0);
            self.0.as_mut_str().zeroize();
            #[cfg(test)]
            tests::observe_before_free(&self.0);
            self.0 = larger;
        }
        self.0.push_str(delta);
        Ok(())
    }

    pub(in crate::client) fn into_string(mut self) -> String {
        std::mem::take(&mut *self.0)
    }
}

fn text_buffer(capacity: usize) -> Result<Zeroizing<String>, Error> {
    let mut buffer = Zeroizing::new(String::new());
    buffer.try_reserve_exact(capacity).map_err(|_| {
        Error::new(
            ErrorKind::InvalidResponse,
            "could not allocate memory for the answer text",
        )
    })?;
    Ok(buffer)
}

/// The error of `into_text` on a stream that has handed out an item: the
/// text read from here on would not be the whole answer, and an error that
/// was already returned must not turn into a success.
pub(in crate::client) fn already_read() -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        "into_text collects a whole answer and needs a stream nothing was read from",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_text_reservation_reports_the_allocation_failure() {
        // Exercise the allocator's error path without exhausting the machine.
        let error = text_buffer(usize::MAX).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
        assert_eq!(
            error.to_string(),
            "could not allocate memory for the answer text"
        );
    }

    thread_local! {
        static RETIRED: std::cell::Cell<Option<(*const u8, usize, bool)>> = const { std::cell::Cell::new(None) };
    }

    pub(super) fn observe_before_free(old: &str) {
        RETIRED.set(Some((
            old.as_ptr(),
            old.len(),
            old.bytes().all(|byte| byte == 0),
        )));
    }

    #[test]
    fn growing_the_text_wipes_the_old_bytes_before_freeing_the_buffer() {
        let mut text = Collected::new();
        text.push("three").unwrap();
        let old = text.0.as_ptr();
        RETIRED.set(None);
        text.push(" more bytes").unwrap();
        assert_eq!(RETIRED.take(), Some((old, 5, true)));
        assert_eq!(text.into_string(), "three more bytes");
    }

    #[test]
    fn text_is_collected_up_to_the_limit_and_one_byte_more_is_refused() {
        let mut text = Collected::new();
        let piece = "a".repeat(1024 * 1024);
        for _ in 0..16 {
            text.push(&piece).unwrap();
        }
        // Exactly at the limit: nothing more fits, an empty piece does.
        text.push("").unwrap();
        let error = text.push("b").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidResponse);
        assert_eq!(text.0.capacity(), TEXT_LIMIT);
        assert_eq!(text.into_string().len(), TEXT_LIMIT);

        // Room is made in a buffer of its own, sized for what is needed
        // or twice the old one, so the old one is dropped and wiped.
        let mut grown = Collected::new();
        grown.push("abc").unwrap();
        assert_eq!(grown.0.capacity(), 3);
        grown.push("d").unwrap();
        assert_eq!(grown.0.capacity(), 6);
        grown.push("ef").unwrap();
        assert_eq!(grown.0.capacity(), 6);
        grown.push(&"g".repeat(20)).unwrap();
        assert_eq!(grown.0.capacity(), 26);
        assert_eq!(grown.into_string(), format!("abcdef{}", "g".repeat(20)));

        let mut short = Collected::new();
        short.push("Hel").unwrap();
        short.push("lo").unwrap();
        assert_eq!(short.into_string(), "Hello");
    }
}
