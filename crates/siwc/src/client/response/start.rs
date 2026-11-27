//! Opening a plan response stream for the app.

use crate::account::AccountId;
use crate::cancel::Canceller;
use crate::error::Error;
use crate::plan::ResponseRequest;

use super::super::{Client, call::call_cancelled, echo::Sent};
use super::{Attempts, Idle, Reading, ResponseStream};

impl Client {
    /// Sends `request` to the Responses API on the account's plan and
    /// returns the answer as a stream of events.
    ///
    /// The request goes out through the client's
    /// [`Transport`](crate::Transport) with the account's access token, so
    /// the app needs no HTTP client of its own. With `Https` (feature
    /// `https`), or any transport that implements
    /// [`Transport::send_streaming`](crate::Transport::send_streaming), the
    /// events arrive while the model writes.
    ///
    /// The call returns once the API has accepted the request. Until then it
    /// follows the rules of [`call`](Self::call):
    ///
    /// - the token is sent only if its credentials grant plan use;
    /// - a token refused with `401` is renewed once and the request sent
    ///   again, whatever code the refusal carries;
    /// - a request the API cannot serve for now (a `5xx` or a `429`, unless
    ///   its code says that waiting cannot help, as a usage limit does) is
    ///   sent again after a bounded wait, at most twice, taking a
    ///   `Retry-After` of at most 30 seconds and ending at a longer one or
    ///   one that is not in whole seconds; a `5xx` without the provider's
    ///   own "not now" code only while
    ///   [`ClientBuilder::resend_after_server_error`](crate::ClientBuilder::resend_after_server_error)
    ///   allows it;
    /// - any other refusal is the error, with its kind, code, status and
    ///   request ID. The status decides whether a request may be sent
    ///   again at all: no error code turns a `403`, a redirect or another
    ///   `4xx` into a second attempt.
    ///
    /// One call therefore sends the request four times at most: the first
    /// attempt, two repeats for "not now", and one after a token renewal.
    /// A refusal whose body cannot be read to its end, or is larger than
    /// 64 KiB, is an error and never a reason to send again. When a buffered
    /// transport fails before delivering a head, no status or wait is available.
    ///
    /// The returned [`ResponseStream`] hands out the events and says how
    /// the answer ended.
    ///
    /// ```no_run
    /// use std::io::Write;
    ///
    /// use siwc::plan::ResponseRequest;
    ///
    /// # fn example(client: &siwc::Client, id: &siwc::AccountId) -> Result<(), Box<dyn std::error::Error>> {
    /// let models = client.models(id)?;
    /// let Some(model) = models.as_slice().first() else {
    ///     println!("This account may not use any model.");
    ///     return Ok(());
    /// };
    /// let request = ResponseRequest::text(model.id(), "Why is the sky blue?")?;
    /// for event in client.stream_response(id, &request)? {
    ///     if let Some(text) = event?.text_delta() {
    ///         print!("{text}");
    ///         std::io::stdout().flush()?;
    ///     }
    /// }
    /// // The loop ended without an error: the answer is complete.
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The errors of [`access_token`](Self::access_token);
    /// [`ErrorKind::PlanUseNotGranted`](crate::ErrorKind::PlanUseNotGranted)
    /// when the account's credentials do not grant plan use, in which case
    /// no plan request is sent. Obtaining the token may still renew it
    /// (see [`enable_plan_use`](Self::enable_plan_use)); the
    /// error of the final refusal, such as
    /// [`ErrorKind::UsageLimit`](crate::ErrorKind::UsageLimit),
    /// [`ErrorKind::NotPermitted`](crate::ErrorKind::NotPermitted),
    /// [`ErrorKind::Temporary`](crate::ErrorKind::Temporary) once the
    /// attempts are used up, or
    /// [`ErrorKind::TokenRejected`](crate::ErrorKind::TokenRejected) for a second 401 without a more specific
    /// terminal code (a usage-limit code still gives `UsageLimit`);
    /// [`ErrorKind::Temporary`](crate::ErrorKind::Temporary) when the
    /// transport got no answer or a refusal broke off, neither of which is
    /// sent again because the API may have started on the request; and
    /// [`ErrorKind::InvalidResponse`](crate::ErrorKind::InvalidResponse) for
    /// a success status other than `200` and for a refusal larger than
    /// 64 KiB.
    pub fn stream_response(
        &self,
        id: &AccountId,
        request: &ResponseRequest,
    ) -> Result<ResponseStream, Error> {
        self.stream_response_cancellable(id, request, &Canceller::unshared())
    }

    /// Like [`stream_response`](Self::stream_response), with a `canceller`
    /// that stops the request from another thread: before it is sent, in a
    /// wait between two attempts or for a store lock, and while the
    /// returned stream waits for the next event. A cancelled stream hands
    /// out nothing more, including events it had already read, and a head
    /// that arrives for a cancelled request is not accepted. An answer that
    /// was complete before the cancellation stays complete: after
    /// `response.completed` the stream has ended.
    ///
    /// `Https` notices a cancellation within about 50 ms while it looks up
    /// the host, performs the TLS handshake, writes or waits for bytes.
    /// The one exception is a TCP connection being opened: that attempt
    /// runs until it succeeds or reaches
    /// its `connect_timeout` (`HttpsBuilder::connect_timeout`), 10 seconds
    /// unless set, and the cancellation is seen before the next address is
    /// tried and before anything is written. A transport that cannot
    /// interrupt a read notices a cancellation when that read returns; the
    /// client looks at the canceller around every read.
    ///
    /// A token renewal that was sent is never cut off: its successor is
    /// stored when available. Once the required store writes finish, a
    /// cancellation takes precedence over either success or a renewal failure.
    /// With `Https` a cancellation during connection setup still prevents
    /// the refresh POST. A custom transport can provide the same guarantee
    /// through [`Transport::send_cancellable`](crate::Transport::send_cancellable).
    ///
    /// ```no_run
    /// use siwc::plan::ResponseRequest;
    /// use siwc::{Canceller, ErrorKind};
    ///
    /// # fn example(client: &siwc::Client, id: &siwc::AccountId, request: &ResponseRequest) -> Result<(), siwc::Error> {
    /// let canceller = Canceller::new();
    /// // Hand a clone to the code behind the Stop button; it calls `cancel`.
    /// let stop = canceller.clone();
    /// # drop(stop);
    /// let stream = client.stream_response_cancellable(id, request, &canceller)?;
    /// match stream.into_text() {
    ///     Err(error) if error.kind() == ErrorKind::Cancelled => println!("stopped"),
    ///     other => println!("{}", other?),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Cancelled`](crate::ErrorKind::Cancelled) when
    /// `canceller` was triggered, plus every error of
    /// [`stream_response`](Self::stream_response).
    pub fn stream_response_cancellable(
        &self,
        id: &AccountId,
        request: &ResponseRequest,
        canceller: &Canceller,
    ) -> Result<ResponseStream, Error> {
        if canceller.is_cancelled() {
            return Err(call_cancelled());
        }
        let mut attempts = Attempts {
            canceller: canceller.clone(),
            sent: Sent::none(),
            request_id: None,
        };
        let body = attempts
            .open(self, id, request)
            .map_err(|error| attempts.sent.filter(error))?;
        let idle = Idle::new(Reading::new(body), canceller);
        attempts.stop_if_cancelled()?;
        Ok(ResponseStream {
            attempts,
            idle,
            touched: false,
            ended: false,
        })
    }
}
