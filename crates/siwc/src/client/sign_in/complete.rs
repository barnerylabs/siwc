//! Completing one sign-in and committing the verified account to the store.

use super::{Completed, Inner, Purpose, cancelled};
use crate::account::{AccountId, AccountState};
use crate::cancel::Canceller;
use crate::client::entries::{
    account_mut, registration_rejected, sign_in_required, unknown_account,
};
use crate::error::{Error, ErrorKind};
use crate::protocol::{Accepted, Credentials, Exchange, HttpRequest, Identity, SignedIn};

mod add;

/// Only this sign-in stops watching the shared signal once its final
/// write begins. Other operations can keep using the same canceller.
struct Commit<'a>(Option<&'a Canceller>);

impl Commit<'_> {
    fn is_cancelled(&self) -> bool {
        self.0.is_some_and(Canceller::is_cancelled)
    }

    fn begin(&mut self) -> bool {
        if self.is_cancelled() {
            return false;
        }
        self.0 = None;
        true
    }
}

impl Inner {
    pub(in crate::client) fn complete(
        &self,
        outcome: Result<Accepted, Error>,
        purpose: Purpose,
        stop: Option<&Canceller>,
    ) -> Result<Completed, Error> {
        let mut commit = Commit(stop);
        let result = match purpose {
            Purpose::Add { pending } => self.complete_add(outcome, pending, &mut commit),
            Purpose::Again { id, sign_outs } => {
                self.complete_again(outcome, &id, sign_outs, &mut commit)
            }
        };
        if commit.is_cancelled() {
            Err(cancelled().displacing(&result))
        } else {
            result
        }
    }

    /// Exchanges the code, fetches the keys and verifies the ID token.
    ///
    /// Keys are fetched after the exchange so a key the provider rotated in
    /// while issuing the token is already in the set.
    fn signed_in(&self, exchange: Exchange) -> Result<SignedIn, Error> {
        let revoke = |request| self.revoke_quietly(Some(request));
        let answer = self
            .send(&exchange.request())
            .map_err(|error| exchange.without_echoes(error))?;
        let unverified = exchange.response_with_revocation(answer, self.clock.now(), revoke)?;
        let keys = self
            .provider_keys()
            .map_err(|error| unverified.reject(error, revoke))?;
        unverified.verify_with(&keys, self.clock.now(), revoke)
    }

    /// Marks a listed account signed in with the identity as verified now.
    /// The caller holds the account's lock and has written `credentials`.
    fn mark_signed_in(
        &self,
        id: &AccountId,
        identity: Identity,
        credentials: &Credentials,
        commit: &mut Commit<'_>,
    ) -> Result<Completed, Error> {
        let plan_use = credentials.scopes().grants_plan_use();
        self.change_installation(|installation| {
            let record = account_mut(installation, id)?;
            if !commit.begin() {
                return Err(cancelled());
            }
            record.state = AccountState::SignedIn;
            record.identity = identity;
            record.plan_use = plan_use;
            let plan_use_started = plan_use && !record.welcomed;
            record.welcomed |= plan_use;
            let account = installation
                .as_ref()
                .and_then(|installation| installation.snapshot_of(id))
                .ok_or_else(unknown_account)?;
            Ok(Completed {
                account,
                plan_use_started,
            })
        })
    }

    /// A failed write may have published the new credentials. Under the
    /// account lock, only a readable different value proves it did not.
    fn revoke_if_credentials_unpublished(&self, id: &AccountId, credentials: &Credentials) {
        if let Ok(stored) = self.stored_credentials(id, None)
            && !stored
                .as_ref()
                .is_some_and(|value| value.same_sign_in(credentials))
        {
            self.revoke_quietly(credentials.revoke_request());
        }
    }

    /// The credentials write succeeded, but marking the account failed.
    /// A readable non-signed-in record proves the installation write did
    /// not publish the new session.
    fn revoke_if_installation_unpublished(&self, id: &AccountId, credentials: &Credentials) {
        if let Ok((_, record)) = self.record(id, None)
            && record.state != AccountState::SignedIn
        {
            let _removed = self.remove_credentials(id);
            self.revoke_quietly(credentials.revoke_request());
        }
    }

    /// Completes a sign-in to an existing account.
    fn complete_again(
        &self,
        outcome: Result<Accepted, Error>,
        id: &AccountId,
        expected_sign_outs: u64,
        commit: &mut Commit<'_>,
    ) -> Result<Completed, Error> {
        if commit.is_cancelled() {
            return Err(cancelled());
        }
        let exchange = match outcome? {
            Accepted::Returning(exchange) => exchange,
            Accepted::NewRegistration(_) => return Err(unexpected_callback()),
        };
        let (identity, credentials) = match self.signed_in(exchange) {
            Ok(signed_in) => signed_in.into_parts(),
            // The token endpoint's refusal is what the app needs to see,
            // also when recording it fails.
            Err(error) if error.kind() == ErrorKind::ClientRejected => {
                return Err(error.after_recording(self.reject_registration(id)));
            }
            Err(error) => return Err(error),
        };

        if let Err(error) = self.record(id, None) {
            self.revoke_quietly(credentials.revoke_request());
            return Err(error);
        }
        let _lock = self.lock_account(id).inspect_err(|_| {
            self.revoke_quietly(credentials.revoke_request());
        })?;
        let unchanged = self.record(id, None).and_then(|(_, record)| {
            if record.client_id != *credentials.client_id()
                || record.identity.subject() != identity.subject()
            {
                Err(Error::new(
                    ErrorKind::AccountMismatch,
                    "the browser signed in to a different account",
                ))
            } else if record.state == AccountState::RegistrationRejected {
                Err(registration_rejected())
            } else if record.sign_outs != expected_sign_outs {
                Err(Error::new(
                    ErrorKind::SignInRequired,
                    "the account was signed out while its sign-in completed",
                ))
            } else {
                Ok(record.state)
            }
        });
        let state = match unchanged {
            Ok(state) => state,
            Err(error) => {
                self.revoke_quietly(credentials.revoke_request());
                return Err(error);
            }
        };
        // A signed-in account's new token becomes visible at this write.
        // Preserve the old session if cancellation won before that point.
        if !commit.begin() {
            if state != AccountState::SignedIn {
                self.revoke_quietly(credentials.revoke_request());
            }
            return Err(cancelled());
        }
        if let Err(error) = self.write_credentials(id, &credentials) {
            self.revoke_if_credentials_unpublished(id, &credentials);
            return Err(error);
        }
        let marked = self.mark_signed_in(id, identity, &credentials, commit);
        if marked
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::Cancelled)
            && state != AccountState::SignedIn
        {
            // Cancellation in mark_signed_in occurs before its installation
            // write. This credentials write was confirmed successful.
            let _removed = self.remove_credentials(id);
            self.revoke_quietly(credentials.revoke_request());
        } else if marked.is_err() {
            self.revoke_if_installation_unpublished(id, &credentials);
        }
        marked
    }

    /// Records that the provider no longer accepts an account's
    /// registration, and removes any dead tokens stored for it. An account
    /// forgotten meanwhile has nothing left to record.
    fn reject_registration(&self, id: &AccountId) -> Result<(), Error> {
        let recorded = self.record(id, None).and_then(|_| {
            let _lock = self.lock_account(id)?;
            self.mark_registration_rejected(id)
        });
        match recorded {
            Err(error) if error.kind() == ErrorKind::UnknownAccount => Ok(()),
            recorded => recorded,
        }
    }

    /// Revokes a session this client will not keep. The outcome changes
    /// nothing, so it is not reported.
    fn revoke_quietly(&self, request: Option<HttpRequest>) {
        if let Some(request) = request {
            let _sent = self.send(&request);
        }
    }
}

fn unexpected_callback() -> Error {
    Error::new(
        ErrorKind::CallbackRejected,
        "the callback does not match the registration this sign-in used",
    )
}
