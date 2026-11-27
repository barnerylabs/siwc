//! Staging a new registration and keeping its account only after sign-in commits.

use crate::account::{AccountId, AccountState};
use crate::client::records::{AccountRecord, MAX_ACCOUNTS, Pending};
use crate::client::sign_in::{account_limit, installation_missing};
use crate::error::{Error, ErrorKind};
use crate::protocol::{Accepted, Credentials, Identity};

use super::{Commit, Completed, Inner, cancelled, sign_in_required, unexpected_callback};

impl Inner {
    /// Completes a new account. A registration that the token endpoint
    /// no longer accepts is cleared, so the next attempt registers anew: a
    /// resumed one, and one issued by this very callback, which `add`
    /// stores as pending before its first exchange. A refusal in the
    /// browser callback is not an authenticated answer and clears nothing.
    pub(super) fn complete_add(
        &self,
        outcome: Result<Accepted, Error>,
        pending: Option<Pending>,
        commit: &mut Commit<'_>,
    ) -> Result<Completed, Error> {
        let used = match &outcome {
            Ok(Accepted::NewRegistration(registration)) => Some(registration.client_id().clone()),
            Ok(Accepted::Returning(_)) => pending.as_ref().map(|pending| pending.client_id.clone()),
            Err(_) => None,
        };
        match (self.add(outcome, pending.as_ref(), commit), used) {
            (Err(error), Some(used)) if error.kind() == ErrorKind::ClientRejected => {
                // The sign-in's own error is what the app needs to see; a
                // pending registration that stays is retried and cleared
                // the next time.
                let cleared = self.change_installation(|installation| {
                    if let Some(installation) = installation.as_mut()
                        && installation
                            .pending
                            .as_ref()
                            .is_some_and(|stored| stored.client_id == used)
                    {
                        installation.pending = None;
                    }
                    Ok(())
                });
                Err(error.after_recording(cleared))
            }
            (result, _) => result,
        }
    }

    fn add(
        &self,
        outcome: Result<Accepted, Error>,
        pending: Option<&Pending>,
        commit: &mut Commit<'_>,
    ) -> Result<Completed, Error> {
        if commit.is_cancelled() {
            return Err(cancelled());
        }
        let (exchange, registered_as) = match outcome? {
            Accepted::NewRegistration(registration) => {
                let fresh = Pending {
                    client_id: registration.client_id().clone(),
                    registered_as: self.app.as_str().to_owned(),
                };
                let registered_as = fresh.registered_as.clone();
                // Stored before the exchange: if the exchange fails, the
                // next attempt completes this registration.
                self.change_installation(|installation| {
                    let installation = installation.as_mut().ok_or_else(installation_missing)?;
                    if installation
                        .accounts
                        .iter()
                        .any(|record| record.client_id == fresh.client_id)
                    {
                        return Err(Error::new(
                            ErrorKind::InvalidResponse,
                            "the provider issued a client ID an account already holds",
                        ));
                    }
                    installation.pending = Some(fresh);
                    Ok(())
                })?;
                (registration.saved(), registered_as)
            }
            Accepted::Returning(exchange) => {
                let pending = pending.ok_or_else(unexpected_callback)?;
                (exchange, pending.registered_as.clone())
            }
        };
        if commit.is_cancelled() {
            return Err(cancelled());
        }
        let (identity, credentials) = self.signed_in(exchange)?.into_parts();
        self.store_new(identity, credentials, registered_as, commit)
    }

    /// Stores a new account in three steps: the account is listed as one
    /// that still has to sign in, its credentials are written under its
    /// lock, and then it is marked signed in.
    ///
    /// A credentials entry therefore only ever exists for a listed account.
    /// A sign-in that is cut off in between leaves an account the user
    /// signs in again, never tokens that no account owns. If a step fails,
    /// the account is taken off the list again, its registration is kept
    /// for the next attempt and the new session is revoked.
    fn store_new(
        &self,
        identity: Identity,
        credentials: Credentials,
        registered_as: String,
        commit: &mut Commit<'_>,
    ) -> Result<Completed, Error> {
        if commit.is_cancelled() {
            self.revoke_quietly(credentials.revoke_request());
            return Err(cancelled());
        }
        let id = AccountId::generate(self.entropy.as_ref()).inspect_err(|_| {
            self.revoke_quietly(credentials.revoke_request());
        })?;
        let pending = Pending {
            client_id: credentials.client_id().clone(),
            registered_as: registered_as.clone(),
        };
        let record = AccountRecord {
            id: id.clone(),
            client_id: pending.client_id.clone(),
            registered_as,
            label: None,
            identity: identity.clone(),
            state: AccountState::SignInRequired,
            plan_use: false,
            welcomed: false,
            sign_outs: 0,
            bundle_receipt: None,
        };
        let listed = self.change_installation(|installation| {
            if commit.is_cancelled() {
                return Err(cancelled());
            }
            let installation = installation.as_mut().ok_or_else(installation_missing)?;
            if installation.accounts.len() >= MAX_ACCOUNTS {
                return Err(account_limit());
            }
            if installation.account(&id).is_some() {
                return Err(repeated_id());
            }
            if installation
                .accounts
                .iter()
                .any(|other| other.client_id == record.client_id)
            {
                return Err(Error::new(
                    ErrorKind::SignInInProgress,
                    "another sign-in completed this registration first",
                ));
            }
            if installation
                .pending
                .as_ref()
                .is_some_and(|pending| pending.client_id == record.client_id)
            {
                installation.pending = None;
            }
            installation.accounts.push(record);
            Ok(())
        });
        if let Err(error) = listed {
            self.revoke_quietly(credentials.revoke_request());
            return Err(error);
        }

        // The lock is held until the end, also while a failed step is
        // undone. Without it nothing was written for this account: it
        // stays listed as one that has to sign in.
        let _lock = match self.lock_account(&id) {
            Ok(lock) => lock,
            Err(error) => {
                self.revoke_quietly(credentials.revoke_request());
                return Err(error);
            }
        };
        // A sign-out or a removal by another process between the listing
        // and the lock stands: this sign-in gives way.
        match self.record(&id, None) {
            Ok((_, record))
                if record.state == AccountState::SignInRequired && record.sign_outs == 0 => {}
            Ok((_, record)) => {
                if record.state != AccountState::SignedIn {
                    self.revoke_quietly(credentials.revoke_request());
                }
                return Err(Error::new(
                    ErrorKind::SignInRequired,
                    "the account changed while its sign-in completed",
                ));
            }
            Err(error) => {
                self.revoke_quietly(credentials.revoke_request());
                return Err(error);
            }
        }
        match self.stored_credentials(&id, None) {
            Ok(None) => {}
            Ok(Some(previous)) => {
                if !previous.same_sign_in(&credentials) {
                    self.revoke_quietly(credentials.revoke_request());
                }
                return Err(sign_in_required());
            }
            Err(error) => {
                self.revoke_quietly(credentials.revoke_request());
                return Err(error);
            }
        }
        if commit.is_cancelled() {
            let _unlisted = self.change_installation(|installation| {
                if let Some(installation) = installation.as_mut() {
                    installation.remove_account(&id);
                    installation.pending.get_or_insert(pending);
                }
                Ok(())
            });
            self.revoke_quietly(credentials.revoke_request());
            return Err(cancelled());
        }

        if let Err(error) = self.write_credentials(&id, &credentials) {
            self.revoke_if_credentials_unpublished(&id, &credentials);
            return Err(error);
        }
        let marked = self.mark_signed_in(&id, identity, &credentials, commit);
        if marked
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::Cancelled)
        {
            // Cancellation occurs before mark_signed_in writes installation.
            // The credentials write above succeeded, so undo is unambiguous.
            if self.remove_credentials(&id).is_ok() {
                let _unlisted = self.change_installation(|installation| {
                    if let Some(installation) = installation.as_mut() {
                        installation.remove_account(&id);
                        installation.pending.get_or_insert(pending);
                    }
                    Ok(())
                });
            }
            self.revoke_quietly(credentials.revoke_request());
        } else if marked.is_err() {
            self.revoke_if_installation_unpublished(&id, &credentials);
        }
        marked
    }
}

fn repeated_id() -> Error {
    Error::new(
        ErrorKind::Randomness,
        "the random source repeated an account ID",
    )
}
