//! The `async` methods of [`Client`](crate::Client) for tokens, the model
//! list, sign-out, forgetting an account and [`Client::call_async`].
//!
//! They are built on [`background`](crate::background) and the standard
//! library's [`Future`], so they run on Tokio, `smol`, `async-std` or a GUI
//! toolkit's executor, keep its worker threads free, and add no runtime
//! dependency.

use std::future::Future;

use crate::account::AccountId;
use crate::cancel::Canceller;
use crate::error::Error;
use crate::plan::{Models, Refusal};
use crate::secret::AccessToken;

use super::call::{ATTEMPTS, Next, call_cancelled};
use super::echo::Sent;
use super::{Client, SignOut};

/// Cancels its canceller when dropped, so work behind a dropped future
/// stops.
pub(super) struct CancelOnDrop(pub(super) Canceller);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl Client {
    /// Async counterpart of [`access_token`](Self::access_token), running
    /// store locks and token renewal on a background thread.
    ///
    /// # Errors
    ///
    /// As [`access_token`](Self::access_token). A worker that cannot start returns
    /// [`Temporary`](crate::ErrorKind::Temporary).
    pub async fn access_token_async(&self, id: &AccountId) -> Result<AccessToken, Error> {
        let client = self.clone();
        let id = id.clone();
        self.background(move || client.access_token(&id))?.await
    }

    /// Async counterpart of
    /// [`access_token_after_rejection`](Self::access_token_after_rejection).
    ///
    /// # Errors
    ///
    /// As [`access_token_after_rejection`](Self::access_token_after_rejection). A worker that cannot start returns
    /// [`Temporary`](crate::ErrorKind::Temporary).
    pub async fn access_token_after_rejection_async(
        &self,
        id: &AccountId,
        rejected: &AccessToken,
    ) -> Result<AccessToken, Error> {
        let client = self.clone();
        let id = id.clone();
        let rejected = rejected.clone();
        self.background(move || client.access_token_after_rejection(&id, &rejected))?
            .await
    }

    /// Async counterpart of `plan_access_token`: a token only when its
    /// credentials grant plan use.
    async fn plan_access_token_async(
        &self,
        id: &AccountId,
        rejected: Option<AccessToken>,
        canceller: &Canceller,
    ) -> Result<AccessToken, Error> {
        let client = self.clone();
        let id = id.clone();
        let stop = canceller.clone();
        self.background(move || client.plan_access_token(&id, rejected.as_ref(), &stop))?
            .await
    }

    /// Async counterpart of [`models`](Self::models).
    ///
    /// # Errors
    ///
    /// As [`models`](Self::models). A worker that cannot start returns
    /// [`Temporary`](crate::ErrorKind::Temporary).
    pub async fn models_async(&self, id: &AccountId) -> Result<Models, Error> {
        let client = self.clone();
        let id = id.clone();
        self.background(move || client.models(&id))?.await
    }

    /// Async counterpart of [`sign_out`](Self::sign_out), running session
    /// revocation and local credential removal on a background thread.
    ///
    /// # Errors
    ///
    /// As [`sign_out`](Self::sign_out). A worker that cannot start returns
    /// [`Temporary`](crate::ErrorKind::Temporary).
    pub async fn sign_out_async(&self, id: &AccountId) -> Result<SignOut, Error> {
        let client = self.clone();
        let id = id.clone();
        self.background(move || client.sign_out(&id))?.await
    }

    /// Async counterpart of [`forget`](Self::forget), running session
    /// revocation and account removal on a background thread.
    ///
    /// # Errors
    ///
    /// As [`forget`](Self::forget). A worker that cannot start returns
    /// [`Temporary`](crate::ErrorKind::Temporary).
    pub async fn forget_async(&self, id: &AccountId) -> Result<SignOut, Error> {
        let client = self.clone();
        let id = id.clone();
        self.background(move || client.forget(&id))?.await
    }

    /// Sends one async API request with `id`'s access token, renewing a
    /// rejected token once and retrying temporary `429` or `5xx` refusals with
    /// bounded backoff (a `5xx` without one of the provider's unavailable
    /// codes only while
    /// [`ClientBuilder::resend_after_server_error`](crate::ClientBuilder::resend_after_server_error)
    /// allows it).
    ///
    /// The rule is the one of [`call`](Self::call): the HTTP status of a
    /// refusal decides, and a refusal without one, read from the stream of
    /// an accepted answer with [`Refusal::from_event`] or
    /// [`Refusal::from_code`], never runs `send` again. An app that reads
    /// the stream itself takes the answer for complete when its HTTP client
    /// reported the clean end of the body and
    /// [`SseDecoder::finish`](crate::plan::SseDecoder::finish) returns `Ok`.
    ///
    /// `send` receives an owned [`AccessToken`] so ordinary `async move`
    /// closures work on every executor without higher-ranked lifetime bounds,
    /// and its returned future is polled directly on the caller's executor.
    /// Dropping the returned future during a retry backoff sleep wakes the
    /// background sleep thread at once with [`SystemClock`](crate::SystemClock);
    /// another [`Clock`](crate::Clock) notices it after its `sleep`.
    ///
    /// ```no_run
    /// use siwc::plan::Refusal;
    ///
    /// # async fn post(_bearer: &str) -> Result<(u16, Vec<u8>), siwc::Error> { unimplemented!() }
    /// # async fn example(client: &siwc::Client, id: &siwc::AccountId) -> Result<Vec<u8>, siwc::Error> {
    /// client
    ///     .call_async(id, |token| async move {
    ///         let (status, body) = post(token.expose()).await?;
    ///         Ok(match Refusal::from_response(status, &body) {
    ///             Some(refusal) => Err(refusal),
    ///             None => Ok(body),
    ///         })
    ///     })
    ///     .await
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`call`](Self::call). A worker that cannot start returns
    /// [`Temporary`](crate::ErrorKind::Temporary).
    pub async fn call_async<T, E, F, Fut>(&self, id: &AccountId, send: F) -> Result<T, E>
    where
        E: From<Error>,
        F: FnMut(AccessToken) -> Fut,
        Fut: Future<Output = Result<Result<T, Refusal>, E>>,
    {
        let guard = CancelOnDrop(Canceller::unshared());
        self.call_async_cancellable(id, &guard.0, send).await
    }

    /// Like [`call_async`](Self::call_async), stopping before an attempt or
    /// waking out of a retry backoff sleep as soon as `canceller` is triggered.
    ///
    /// # Errors
    ///
    /// As [`call_cancellable`](Self::call_cancellable). A worker that cannot start returns
    /// [`Temporary`](crate::ErrorKind::Temporary).
    pub async fn call_async_cancellable<T, E, F, Fut>(
        &self,
        id: &AccountId,
        canceller: &Canceller,
        mut send: F,
    ) -> Result<T, E>
    where
        E: From<Error>,
        F: FnMut(AccessToken) -> Fut,
        Fut: Future<Output = Result<Result<T, Refusal>, E>>,
    {
        if canceller.is_cancelled() {
            return Err(call_cancelled().into());
        }
        let mut token = self.plan_access_token_async(id, None, canceller).await?;
        // Every token `send` got, so none of them comes back in an error.
        let mut sent = Sent::none();
        let mut renewed = false;
        let mut attempt = 1;
        loop {
            if canceller.is_cancelled() {
                return Err(call_cancelled().into());
            }
            sent.add(&token);
            let refusal = match send(token.clone()).await? {
                Ok(value) => return Ok(value),
                Err(refusal) => refusal,
            };
            if canceller.is_cancelled() {
                return Err(call_cancelled().into());
            }
            match self.next_step(&refusal) {
                Next::Renew if !renewed => {
                    token = self
                        .plan_access_token_async(id, Some(token), canceller)
                        .await
                        .map_err(|error| sent.filter(error))?;
                    renewed = true;
                }
                Next::Wait if attempt < ATTEMPTS => {
                    let Some(wait) = self.wait_before(attempt + 1, refusal.wait_asked()) else {
                        return Err(sent.error_of(refusal).into());
                    };
                    let client = self.clone();
                    let guard = CancelOnDrop(canceller.child());
                    let stop = guard.0.clone();
                    if !self
                        .background(move || client.sleep_cancellable(wait, &stop))?
                        .await
                    {
                        return Err(call_cancelled().into());
                    }
                    attempt += 1;
                    token = self
                        .plan_access_token_async(id, None, canceller)
                        .await
                        .map_err(|error| sent.filter(error))?;
                }
                _ => return Err(sent.error_of(refusal).into()),
            }
        }
    }
}
