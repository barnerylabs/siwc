//! Recognising an access token when the provider sends it back.

use ring::digest::{Digest, SHA256, digest};

use crate::error::Error;
use crate::plan::Refusal;
use crate::secret::AccessToken;

/// The length and a fingerprint of each bearer sent across a call's attempts.
///
/// A request ID or an error code is kept only when it looks like an
/// identifier, and a token looks like one. The streams, `Client::call` and
/// `Client::models` use these fingerprints to discard values that contain a
/// sent token.
/// The stream drops the token itself as soon as the HTTP head is accepted.
pub(super) struct Sent(Vec<(usize, Digest)>);

impl Sent {
    pub(super) fn none() -> Self {
        Self(Vec::new())
    }

    /// Remembers `token` as sent.
    pub(super) fn add(&mut self, token: &AccessToken) {
        let token = token.expose().as_bytes();
        self.0.push((token.len(), digest(&SHA256, token)));
    }

    /// Whether a token that was sent is `value` or a part of it. The
    /// values asked about are short, so every part of a token's length is
    /// looked at.
    pub(super) fn echoes(&self, value: &str) -> bool {
        self.0.iter().any(|(len, sent)| {
            *len > 0
                && value
                    .as_bytes()
                    .windows(*len)
                    .any(|part| digest(&SHA256, part).as_ref() == sent.as_ref())
        })
    }

    /// The error of `refusal` without any code, request ID or parameter
    /// that has one of the tokens in it.
    pub(super) fn error_of(&self, refusal: Refusal) -> Error {
        self.filter(Error::from(refusal))
    }

    /// Removes echoes from provider metadata, including token endpoint errors.
    pub(super) fn filter(&self, error: Error) -> Error {
        error.without(|value| self.echoes(value))
    }
}
