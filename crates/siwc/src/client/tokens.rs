//! Access tokens for a named account, renewed one at a time under that
//! account's lock, and the models the account may use.

use crate::account::{AccountId, AccountState, plan_use_not_granted};
use crate::cancel::Canceller;
use crate::error::{Error, ErrorKind};
use crate::plan::{Models, Refusal};
use crate::protocol::{Credentials, HttpResponse};
use crate::secret::AccessToken;

use super::call::{Next, call_cancelled, next_after};
use super::echo::Sent;
use super::entries::{account_mut, registration_rejected, sign_in_required};
use super::records::AccountRecord;
use super::{Client, Inner};

impl Client {
    /// The access token of one account, for the `Authorization: Bearer`
    /// header of the app's API requests.
    ///
    /// A token that is not close to expiry comes straight from the store,
    /// without a request or taking an account or installation lock, when
    /// the account record reflects its plan-use grant. Otherwise the stored
    /// credentials are read again under the account's lock and renewed
    /// only if needed. The successor and its grant are stored before the
    /// access token is returned. Two threads or two processes asking at
    /// once cause one renewal. The built-in keychain store keeps the key
    /// available for this write before sending the refresh. It can finish
    /// across a service activation or a temporary keychain failure and
    /// waits for a running reset within the keychain's write-lock budget.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::UnknownAccount`].
    /// - [`ErrorKind::SignInRequired`] for an account that is signed out or
    ///   whose session ended; offer [`sign_in_again`](Self::sign_in_again).
    ///   When the provider ends a session, the account's tokens are deleted
    ///   and its registration is kept for that sign-in.
    /// - [`ErrorKind::ClientRejected`] when the provider no longer accepts
    ///   the account's registration, for example because the user removed
    ///   the app in their ChatGPT settings. The account stays in
    ///   [`AccountState::RegistrationRejected`] and signing in again cannot
    ///   work: [`forget`](Self::forget) it and add it again.
    /// - [`ErrorKind::Temporary`]: the stored credentials are kept; try again
    ///   later. When a refresh request reached the provider but its answer was
    ///   lost, the provider may have rotated the refresh token, and the next
    ///   renewal can end in [`ErrorKind::SignInRequired`].
    /// - [`ErrorKind::Rejected`] and [`ErrorKind::InvalidResponse`]: the
    ///   stored credentials are kept, but repeating the renewal unchanged is
    ///   unlikely to help. After `InvalidResponse` the provider may have
    ///   rotated the refresh token, so the next renewal can end in
    ///   [`ErrorKind::SignInRequired`]. One `InvalidResponse` replaces them:
    ///   a renewal whose new access token has already expired stores its
    ///   rotated refresh token, and the next call renews again.
    /// - [`ErrorKind::StoreCorrupt`] when the stored credentials cannot be
    ///   read or belong to another account; nothing was sent.
    /// - [`ErrorKind::InvalidInput`] when another keychain service sealed
    ///   the entry and this release cannot read it. Use the release that
    ///   can open the store before signing out.
    /// - Storage errors include [`ErrorKind::StoreNotPrivate`],
    ///   [`ErrorKind::StoreUnsupported`], [`ErrorKind::SealingKeyMissing`]
    ///   and sealing [`ErrorKind::Randomness`]. A failure recording a terminal
    ///   refusal, or the end of a session without a refresh token, still
    ///   returns `SignInRequired` or `ClientRejected`, with
    ///   [`Error::state_saved`] `false`. If the successor
    ///   could not be stored after renewal, the account will likely need a
    ///   new sign-in. If only the plan-use update failed, the next call
    ///   that can use the successor repairs the account record.
    pub fn access_token(&self, id: &AccountId) -> Result<AccessToken, Error> {
        self.inner.token(id, None).map(|granted| granted.token)
    }

    /// A new access token after the API refused `rejected`, the token this
    /// client handed out for the same account.
    ///
    /// Under the account's lock: if another thread or process renewed the
    /// token meanwhile and that token is not due itself, the stored one is
    /// returned without a request; otherwise the token is renewed now, even
    /// if it is not due.
    ///
    /// ```no_run
    /// # fn retry(client: &siwc::Client, id: &siwc::AccountId, rejected: &siwc::AccessToken) -> Result<(), siwc::Error> {
    /// // The API returned 401 for this token. Obtain its replacement once.
    /// let replacement = client.access_token_after_rejection(id, rejected)?;
    /// # drop(replacement);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`access_token`](Self::access_token).
    pub fn access_token_after_rejection(
        &self,
        id: &AccountId,
        rejected: &AccessToken,
    ) -> Result<AccessToken, Error> {
        self.inner
            .renew(id, Some(rejected), None)
            .map(|granted| granted.token)
    }

    /// Like [`access_token`](Self::access_token), or with `rejected` like
    /// [`access_token_after_rejection`](Self::access_token_after_rejection),
    /// but only a token whose credentials grant plan use. The grant is read
    /// from the same credentials the token comes from.
    ///
    /// A triggered `stop` ends the wait for the account's lock and keeps a
    /// renewal from being sent. One that was sent is seen through: its
    /// successor is stored whatever happens to the request it was for.
    pub(super) fn plan_access_token(
        &self,
        id: &AccountId,
        rejected: Option<&AccessToken>,
        stop: &Canceller,
    ) -> Result<AccessToken, Error> {
        let granted = match rejected {
            None => self.inner.token(id, Some(stop)),
            Some(rejected) => self.inner.renew(id, Some(rejected), Some(stop)),
        };
        if stop.is_cancelled() {
            return Err(call_cancelled().displacing(&granted));
        }
        granted?.into_plan_token()
    }

    /// The models this account may use.
    ///
    /// Each request requires credentials that grant plan use. The client
    /// renews the token once after an HTTP `401` with a refusal body of at
    /// most 64 KiB. It asks again only if the renewed credentials still
    /// grant plan use. Errors omit diagnostics that contain a bearer sent
    /// by this call.
    ///
    /// # Errors
    ///
    /// The errors of [`access_token`](Self::access_token), and those of
    /// [`Models::from_response`], such as [`ErrorKind::UsageLimit`] or
    /// [`ErrorKind::PlanUseNotGranted`].
    pub fn models(&self, id: &AccountId) -> Result<Models, Error> {
        let inner = &self.inner;
        let token = inner.token(id, None)?.into_plan_token()?;
        let mut sent = Sent::none();
        let mut response = inner.request_models(&token, &mut sent)?;
        if let Some(refusal) = Refusal::from_response(response.status(), response.body()) {
            if !matches!(next_after(&refusal), Next::Renew) {
                let refusal = refusal
                    .with_request_id(response.request_id())
                    .with_retry_after(response.retry_after());
                return Err(sent.error_of(refusal));
            }
            drop(response);
            let token = inner
                .renew(id, Some(&token), None)
                .and_then(Granted::into_plan_token)
                .map_err(|error| sent.filter(error))?;
            response = inner.request_models(&token, &mut sent)?;
        }
        Models::from_response(&response).map_err(|error| sent.filter(error))
    }
}

/// An access token, and whether the credentials it came from grant plan
/// use.
struct Granted {
    token: AccessToken,
    plan_use: bool,
}

impl Granted {
    fn into_plan_token(self) -> Result<AccessToken, Error> {
        if self.plan_use {
            Ok(self.token)
        } else {
            Err(plan_use_not_granted())
        }
    }
}

fn plan_use_is_current(record: &AccountRecord, plan_use: bool) -> bool {
    record.plan_use == plan_use
}

impl Inner {
    fn request_models(&self, token: &AccessToken, sent: &mut Sent) -> Result<HttpResponse, Error> {
        sent.add(token);
        self.send(&Models::request(token))
            .map_err(|error| sent.filter(error))
    }

    /// The account's access token: from the store when it is not due and
    /// the record reflects its grant, renewed under the lock otherwise.
    fn token(&self, id: &AccountId, stop: Option<&Canceller>) -> Result<Granted, Error> {
        let record = self.token_record(id, stop)?;
        let credentials = self.usable_credentials(&record, stop)?;
        let plan_use = credentials.scopes().grants_plan_use();
        if !credentials.needs_refresh(self.clock.now()) && plan_use_is_current(&record, plan_use) {
            return Ok(Granted {
                token: credentials.access_token().clone(),
                plan_use,
            });
        }
        self.renew(id, None, stop)
    }

    /// Reads the account record. For a rejected registration or a session
    /// that ended, retries removing tokens left behind and returns the
    /// account's error, or the cancellation when `stop` was triggered
    /// meanwhile.
    fn token_record(
        &self,
        id: &AccountId,
        stop: Option<&Canceller>,
    ) -> Result<AccountRecord, Error> {
        let (_, record) = self.record(id, stop)?;
        let error = match record.state {
            AccountState::RegistrationRejected => registration_rejected(),
            AccountState::SignInRequired => sign_in_required(),
            AccountState::SignedIn | AccountState::SignedOut => return Ok(record),
        };
        self.retry_cleanup(id, record.state, stop);
        if stop.is_some_and(Canceller::is_cancelled) {
            return Err(call_cancelled());
        }
        Err(error)
    }

    /// The credentials of a signed-in account.
    fn usable_credentials(
        &self,
        record: &AccountRecord,
        stop: Option<&Canceller>,
    ) -> Result<Credentials, Error> {
        match record.state {
            AccountState::SignedIn => {}
            AccountState::RegistrationRejected => return Err(registration_rejected()),
            AccountState::SignedOut | AccountState::SignInRequired => {
                return Err(sign_in_required());
            }
        }
        // A signed-in account without credentials is in the middle of a
        // sign-out by another thread or process.
        self.credentials(record, stop)?.ok_or_else(sign_in_required)
    }

    /// Updates the plan-use grant before returning the token. The caller
    /// holds the account's lock and has read or written these credentials.
    fn reconciled_access_token(
        &self,
        record: &AccountRecord,
        credentials: &Credentials,
        stop: Option<&Canceller>,
    ) -> Result<Granted, Error> {
        let plan_use = credentials.scopes().grants_plan_use();
        if !plan_use_is_current(record, plan_use) {
            self.change_installation_unless(stop, |installation| {
                let stored = account_mut(installation, &record.id)?;
                stored.plan_use = plan_use;
                Ok(())
            })?;
        }
        Ok(Granted {
            token: credentials.access_token().clone(),
            plan_use,
        })
    }

    /// Renews the account's token under its lock: when it is due, or, with
    /// `rejected`, when the stored token is still the rejected one. With
    /// `stop`, a cancellation ends the wait for the lock and is looked for
    /// once more under the lock, right before the renewal is sent.
    fn renew(
        &self,
        id: &AccountId,
        rejected: Option<&AccessToken>,
        stop: Option<&Canceller>,
    ) -> Result<Granted, Error> {
        self.token_record(id, stop)?;
        let _lock = self.lock_account_unless(id, stop)?;
        let (_, record) = self.record(id, stop)?;
        if matches!(
            record.state,
            AccountState::RegistrationRejected | AccountState::SignInRequired
        ) {
            self.remove_dead_credentials(id, stop);
        }
        let credentials = self.usable_credentials(&record, stop)?;
        let now = self.clock.now();
        let current = match rejected {
            None => !credentials.needs_refresh(now),
            // Somebody else renewed it meanwhile; a token that is due
            // itself would only be refused next.
            Some(rejected) => {
                credentials.access_token().expose() != rejected.expose()
                    && !credentials.needs_refresh(now)
            }
        };
        if current {
            return self.reconciled_access_token(&record, &credentials, stop);
        }
        let Some(request) = credentials.refresh_request() else {
            // Without a refresh token the session lasts as long as its
            // access token, unless that is the one the API refused.
            let refused = rejected
                .is_some_and(|rejected| credentials.access_token().expose() == rejected.expose());
            if !refused && now < credentials.expires_at() {
                return self.reconciled_access_token(&record, &credentials, stop);
            }
            // The session ended like a provider refusal ends it, so
            // `SignInRequired` stays the error when recording that fails.
            // A cancellation that stopped the recording wins, and reports
            // that the ended session was not saved.
            let ended = self.end_session(id, stop);
            return Err(match ended {
                Err(error) if error.kind() == ErrorKind::Cancelled => {
                    call_cancelled().after_recording(Err(error))
                }
                ended => sign_in_required().after_recording(ended),
            });
        };
        // A transport that can stop during connection setup checks once more
        // before writing. From that write on we need the answer and its successor.
        if stop.is_some_and(Canceller::is_cancelled) {
            return Err(call_cancelled());
        }
        let answer = match stop {
            Some(stop) => self.transport.send_cancellable(&request, stop),
            None => self.send(&request),
        }
        .map_err(|error| credentials.without_credential_echo(error))?;
        let received = self.clock.now();
        match credentials.refreshed(answer, received) {
            Ok(successor) => {
                // The refresh token rotated, so the successor is kept even
                // when its access token is of no use.
                self.write_credentials(id, &successor)?;
                if received >= successor.expires_at() {
                    return Err(Error::new(
                        ErrorKind::InvalidResponse,
                        "the renewed access token has already expired",
                    ));
                }
                self.reconciled_access_token(&record, &successor, None)
            }
            // The provider's refusal decides what the user does next, so it
            // stays the error even when recording it fails.
            Err(error) if error.kind() == ErrorKind::SignInRequired => {
                Err(error.after_recording(self.end_session(id, None)))
            }
            Err(error) if error.kind() == ErrorKind::ClientRejected => {
                Err(error.after_recording(self.mark_registration_rejected(id)))
            }
            Err(error) => Err(error),
        }
    }
}
