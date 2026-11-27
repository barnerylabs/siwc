//! One API request with an account's access token: renewed once when the
//! API refuses it, and sent again after a bounded wait when the API cannot
//! serve it for now.

use std::time::Duration;

use crate::account::AccountId;
use crate::cancel::Canceller;
use crate::error::{Error, ErrorKind};
use crate::plan::{Reason, Refusal};
use crate::secret::AccessToken;

use super::Client;
use super::echo::Sent;

#[cfg(not(feature = "testing"))]
use crate::entropy::Entropy;

/// How often `call` sends a request the API cannot serve for now, the
/// first time included.
pub(super) const ATTEMPTS: u32 = 3;

/// The wait before the second of those attempts; it doubles for each
/// further one, and a random part of up to half of it is left out.
const FIRST_WAIT: Duration = Duration::from_secs(1);

/// The longest wait `call` takes from `Retry-After`. A longer one ends the
/// call with the refusal, so the app decides whether to wait that long.
const LONGEST_WAIT: Duration = Duration::from_secs(30);

impl Client {
    /// Sends one API request of the app with the account's access token.
    ///
    /// `send` makes the request with the app's own HTTP client and returns
    /// what came back: the app's value, or the [`Refusal`] for an answer
    /// that is not `2xx`, built with [`Refusal::from_response`] and, from
    /// the answer's headers, [`Refusal::with_request_id`] and
    /// [`Refusal::with_retry_after`]. Before every attempt, the token is
    /// used only if the credentials it comes from grant plan use. Then:
    ///
    /// - When the API refuses the token (a `401`, whatever code its body
    ///   carries), it is renewed with
    ///   [`access_token_after_rejection`](Self::access_token_after_rejection)
    ///   and `send` runs once more. A second 401 ends the call; its code
    ///   determines the final error when it names a specific refusal.
    /// - When the API cannot serve the request for now
    ///   ([`Reason::Unavailable`] with a status of `429` or `5xx`), `send`
    ///   runs again after a wait, so that such refusals get
    ///   at most three attempts; together with the one renewal above, `send`
    ///   runs at most four times per call. The wait is the refusal's
    ///   `Retry-After` if it has one of at most 30 seconds; a longer one, or
    ///   one that is not in whole seconds, such as a date, ends the call at
    ///   once. Without one, the wait grows from about a second
    ///   and holds a random part, so many clients do not retry in step. The
    ///   client's [`Clock`](crate::Clock) waits. OpenAI's Python and Node
    ///   SDKs also send a request again twice by default after a `429` or
    ///   `5xx`; unlike them, this client never does so after a broken
    ///   connection, a `408` or a `409`.
    ///   [`ClientBuilder::resend_after_server_error`](crate::ClientBuilder::resend_after_server_error)
    ///   turns the repeat off for a `5xx` without the provider's own
    ///   "not now" code.
    /// - Any other refusal, such as a usage limit, which a retry cannot
    ///   lift, becomes the error, with its kind, code, status and request
    ///   ID ([`Error::request_id`]). The status decides whether `send` may
    ///   run again at all: no code turns a `403`, a redirect or another
    ///   `4xx` into a second attempt.
    /// - A refusal without an HTTP status, one the app read from the
    ///   stream of an answer the API had accepted
    ///   ([`Refusal::from_event`], [`Refusal::from_code`]), is never a
    ///   reason to run `send` again, whatever it says: the provider may
    ///   already have counted the POST. It becomes the error.
    /// - A refusal whose body was larger than the 64 KiB
    ///   [`Refusal::from_response`] reads ends the call with
    ///   [`ErrorKind::InvalidResponse`], whatever its status: what the body
    ///   says is unknown, and it may be what forbids another attempt.
    ///
    /// Errors from refusals and subsequent token lookups never carry a code,
    /// a parameter or a request ID that has a sent token in it, the one
    /// from before a renewal included: a provider that sends the token
    /// back does not get it into the app's log this way.
    ///
    /// A `2xx` only says that an answer began. An app that reads the
    /// stream itself takes the answer for complete when
    /// [`SseDecoder::finish`](crate::plan::SseDecoder::finish) returns
    /// `Ok` at the end of the body, and not before. To wake a backoff
    /// sleep early when the user stops the request, use
    /// [`call_cancellable`](Self::call_cancellable).
    ///
    /// ```no_run
    /// use siwc::plan::Refusal;
    ///
    /// # struct Answer { status: u16, request_id: Option<String>, retry_after: Option<String>, body: Vec<u8> }
    /// # fn post(_bearer: &str) -> std::io::Result<Answer> { unimplemented!() }
    /// # fn example(client: &siwc::Client, id: &siwc::AccountId) -> Result<(), Box<dyn std::error::Error>> {
    /// // `post` stands for the app's HTTP client.
    /// let body = client.call(id, |token| -> Result<_, Box<dyn std::error::Error>> {
    ///     let answer = post(token.expose())?;
    ///     Ok(match Refusal::from_response(answer.status, &answer.body) {
    ///         Some(refusal) => Err(refusal
    ///             .with_request_id(answer.request_id.as_deref())
    ///             .with_retry_after(answer.retry_after.as_deref())),
    ///         None => Ok(answer.body),
    ///     })
    /// })?;
    /// # drop(body);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The errors of [`access_token`](Self::access_token);
    /// [`ErrorKind::PlanUseNotGranted`] when the credentials of the token
    /// about to be sent do not grant plan use, for example after a renewal
    /// dropped that grant, in which case `send` does not run with it (see
    /// [`enable_plan_use`](Self::enable_plan_use)); the error of the
    /// final refusal, such as [`ErrorKind::UsageLimit`],
    /// [`ErrorKind::Temporary`] once the attempts are used up, or
    /// [`ErrorKind::TokenRejected`] when the renewed token is refused as
    /// well; and whatever `send` returns itself.
    pub fn call<T, E>(
        &self,
        id: &AccountId,
        send: impl FnMut(&AccessToken) -> Result<Result<T, Refusal>, E>,
    ) -> Result<T, E>
    where
        E: From<Error>,
    {
        self.call_cancellable(id, &Canceller::unshared(), send)
    }

    /// Sends one API request like [`call`](Self::call), stopping before an
    /// attempt or waking out of a retry wait as soon as `canceller` is
    /// triggered.
    ///
    /// A token renewal that was sent is never cut off mid-rotation;
    /// cancellation is checked before the initial token lookup, after a
    /// refused attempt before renewing or sleeping, while a renewal waits
    /// for an account or installation lock, immediately before sending the
    /// renewal, and during any retry sleep: at once with
    /// [`SystemClock`](crate::SystemClock), after its `sleep` with another
    /// [`Clock`](crate::Clock).
    ///
    /// ```no_run
    /// use siwc::Canceller;
    /// use siwc::plan::Refusal;
    ///
    /// # fn post(_bearer: &str) -> std::io::Result<(u16, Vec<u8>)> { unimplemented!() }
    /// # fn example(client: &siwc::Client, id: &siwc::AccountId) -> Result<(), Box<dyn std::error::Error>> {
    /// let canceller = Canceller::new();
    /// let body = client.call_cancellable(id, &canceller, |token| -> Result<_, Box<dyn std::error::Error>> {
    ///     let (status, body) = post(token.expose())?;
    ///     Ok(match Refusal::from_response(status, &body) {
    ///         Some(refusal) => Err(refusal),
    ///         None => Ok(body),
    ///     })
    /// })?;
    /// # drop(body);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Cancelled`] when `canceller` was triggered before an
    /// attempt or during a retry sleep, plus every error of [`call`](Self::call).
    pub fn call_cancellable<T, E>(
        &self,
        id: &AccountId,
        canceller: &Canceller,
        mut send: impl FnMut(&AccessToken) -> Result<Result<T, Refusal>, E>,
    ) -> Result<T, E>
    where
        E: From<Error>,
    {
        if canceller.is_cancelled() {
            return Err(call_cancelled().into());
        }
        let mut token = self.plan_access_token(id, None, canceller)?;
        // Every token `send` got, so none of them comes back in an error.
        let mut sent = Sent::none();
        let mut renewed = false;
        let mut attempt = 1;
        loop {
            if canceller.is_cancelled() {
                return Err(call_cancelled().into());
            }
            sent.add(&token);
            let refusal = match send(&token)? {
                Ok(value) => return Ok(value),
                Err(refusal) => refusal,
            };
            if canceller.is_cancelled() {
                return Err(call_cancelled().into());
            }
            match self.next_step(&refusal) {
                Next::Renew if !renewed => {
                    token = self
                        .plan_access_token(id, Some(&token), canceller)
                        .map_err(|error| sent.filter(error))?;
                    renewed = true;
                }
                Next::Wait if attempt < ATTEMPTS => {
                    let Some(wait) = self.wait_before(attempt + 1, refusal.wait_asked()) else {
                        return Err(sent.error_of(refusal).into());
                    };
                    if !self.sleep_cancellable(wait, canceller) {
                        return Err(call_cancelled().into());
                    }
                    attempt += 1;
                    // The wait may have brought the token close to expiry.
                    token = self
                        .plan_access_token(id, None, canceller)
                        .map_err(|error| sent.filter(error))?;
                }
                _ => return Err(sent.error_of(refusal).into()),
            }
        }
    }

    /// The wait before attempt number `attempt` (2 or more): the one the
    /// API asked for, if `call` accepts it, or the growing one with its
    /// random part.
    pub(super) fn wait_before(&self, attempt: u32, asked: Option<Duration>) -> Option<Duration> {
        if let Some(asked) = asked {
            return (asked <= LONGEST_WAIT).then_some(asked);
        }
        let full = FIRST_WAIT.saturating_mul(1 << (attempt - 2).min(16));
        let mut random = [0; 1];
        // Without random bytes the whole wait is taken.
        let left_out = match self.inner.entropy.fill(&mut random) {
            Ok(()) => full / 2 * u32::from(random[0]) / u32::from(u8::MAX),
            Err(_) => Duration::ZERO,
        };
        Some(full - left_out)
    }

    /// Waits with the client's clock.
    pub(super) fn sleep_cancellable(&self, wait: Duration, canceller: &Canceller) -> bool {
        self.inner.clock.sleep_cancellable(wait, canceller)
    }
}

impl Client {
    /// [`next_after`], with a `5xx` made terminal when the client does not
    /// send a plan request again after one. A `5xx` with the provider's own
    /// "not now" code is still waited out: the provider says it did not
    /// serve the request.
    pub(super) fn next_step(&self, refusal: &Refusal) -> Next {
        match next_after(refusal) {
            Next::Wait
                if !self.inner.resend_after_server_error
                    && refusal.status().is_some_and(|status| status >= 500)
                    && !refusal.unavailable_by_code() =>
            {
                Next::Stop
            }
            next => next,
        }
    }
}

/// What a refusal allows before the request is sent again.
pub(super) enum Next {
    /// Renew the access token, once.
    Renew,
    /// Wait, then send again.
    Wait,
    /// Nothing: the refusal is the result.
    Stop,
}

/// The one rule for sending a request again that was refused with an HTTP
/// status, for [`Client::call`], [`Client::call_async`] and
/// [`Client::stream_response`].
///
/// The status decides what may follow: a `401` renews the token whatever
/// code its body carries, a `429` or `5xx` is waited out unless a code
/// says that waiting cannot help, and no code turns any other status into
/// a second attempt. A refusal without a status was read from an accepted
/// answer and is terminal. So is a refusal whose body was too large to
/// read: the unread part could be what rules out another attempt.
pub(super) fn next_after(refusal: &Refusal) -> Next {
    if refusal.body_was_too_large() {
        return Next::Stop;
    }
    match (refusal.status(), refusal.reason()) {
        (Some(401), _) => Next::Renew,
        (Some(429 | 500..=599), Reason::Unavailable) => Next::Wait,
        _ => Next::Stop,
    }
}

pub(super) fn call_cancelled() -> Error {
    Error::new(ErrorKind::Cancelled, "the app cancelled the request")
}
