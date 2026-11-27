//! Reading and changing the client's store entries under the lock rules.
//!
//! - The `installation` lock is held for each read-modify-write of the
//!   installation entry and for nothing else: never across a request or a
//!   wait for the browser. Readers take no installation lock.
//! - An `account-<id>` lock is held while that account's credentials
//!   change: a refresh, a completed sign-in, a sign-out.
//! - An `account-<id>` entry exists only for an account the installation
//!   record lists: a new account is listed before its credentials are
//!   written, and a forgotten one loses them before it leaves the list.
//! - An account lock is taken before the installation lock, never after it,
//!   and never two account locks at once.

use std::time::{Duration, Instant};

use crate::account::{AccountId, AccountState};
use crate::cancel::Canceller;
use crate::error::{Error, ErrorKind};
use crate::protocol::{Credentials, HttpRequest, HttpResponse, Jwks};
use crate::store::{EntryName, Lock, Store, reading};

use super::Inner;
use super::call::call_cancelled;
use super::records::{AccountRecord, Installation};

/// The entry with the installation record.
const INSTALLATION: &str = "installation";

/// Longest store lock attempt before checking for cancellation again.
const LOCK_SLICE: Duration = Duration::from_millis(50);

impl Inner {
    /// Every store call sets its own scope, including calls without a
    /// canceller that a custom store makes through another client.
    pub(super) fn with_store<'a, T>(
        &'a self,
        stop: Option<&Canceller>,
        call: impl FnOnce(&'a dyn Store) -> T,
    ) -> T {
        reading::with_canceller(stop, || call(self.store.as_ref()))
    }

    /// The installation record; `None` before the first account was added.
    pub(super) fn installation(
        &self,
        stop: Option<&Canceller>,
    ) -> Result<Option<Installation>, Error> {
        let entry = EntryName::new(INSTALLATION)?;
        match self.with_store(stop, |store| store.read(&entry))? {
            None => Ok(None),
            Some(stored) => Installation::from_bytes(stored.expose()).map(Some),
        }
    }

    /// The installation record and one account in it.
    pub(super) fn record(
        &self,
        id: &AccountId,
        stop: Option<&Canceller>,
    ) -> Result<(Installation, AccountRecord), Error> {
        let installation = self.installation(stop)?.ok_or_else(unknown_account)?;
        let record = installation
            .account(id)
            .cloned()
            .ok_or_else(unknown_account)?;
        Ok((installation, record))
    }

    /// Changes the installation record under its lock: reads it again,
    /// applies `change` and writes the result when it differs from what was
    /// read. Nothing is written when `change` fails.
    pub(super) fn change_installation<T>(
        &self,
        change: impl FnOnce(&mut Option<Installation>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.change_installation_unless(None, change)
    }

    /// As `change_installation`, with cancellation while waiting for the
    /// installation lock or the keys needed to read and seal its entry.
    pub(super) fn change_installation_unless<T>(
        &self,
        stop: Option<&Canceller>,
        change: impl FnOnce(&mut Option<Installation>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let entry = EntryName::new(INSTALLATION)?;
        let _lock = self.lock_unless(&entry, stop)?;
        let before = self.installation(stop)?;
        let mut installation = before.clone();
        let result = change(&mut installation)?;
        if let Some(installation) = installation.as_ref() {
            if !installation.is_consistent() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "the change would break the installation record",
                ));
            }
            if before.as_ref() != Some(installation) {
                if stop.is_some_and(Canceller::is_cancelled) {
                    return Err(call_cancelled());
                }
                self.with_store(stop, |store| store.write(&entry, &installation.to_bytes()))?;
            }
        }
        Ok(result)
    }

    /// The credentials stored for `record`'s account; `None` when there are
    /// none.
    ///
    /// The entry has to repeat the account's client ID and subject. An entry
    /// that names another account, for example one copied into the wrong
    /// slot, is refused as a whole.
    pub(super) fn credentials(
        &self,
        record: &AccountRecord,
        stop: Option<&Canceller>,
    ) -> Result<Option<Credentials>, Error> {
        let Some(credentials) = self.stored_credentials(&record.id, stop)? else {
            return Ok(None);
        };
        if *credentials.client_id() != record.client_id
            || credentials.subject() != record.identity.subject()
        {
            return Err(Error::corrupt_entry(
                "the stored credentials belong to another account",
            ));
        }
        Ok(Some(credentials))
    }

    /// The credentials entry of an account as it reads, without checking
    /// whom it names; `None` when there is none.
    pub(super) fn stored_credentials(
        &self,
        id: &AccountId,
        stop: Option<&Canceller>,
    ) -> Result<Option<Credentials>, Error> {
        let entry = account_entry(id)?;
        match self.with_store(stop, |store| store.read(&entry))? {
            None => Ok(None),
            Some(stored) => Credentials::from_stored(stored.expose()).map(Some),
        }
    }

    /// Replaces the credentials of an account.
    pub(super) fn write_credentials(
        &self,
        id: &AccountId,
        credentials: &Credentials,
    ) -> Result<(), Error> {
        let entry = account_entry(id)?;
        self.with_store(None, |store| {
            store.write(&entry, credentials.to_stored().expose())
        })
    }

    /// Removes the credentials of an account.
    pub(super) fn remove_credentials(&self, id: &AccountId) -> Result<(), Error> {
        let entry = account_entry(id)?;
        self.with_store(None, |store| store.remove(&entry))
    }

    /// Records the provider's rejection under the account lock the caller
    /// holds, then deletes the tokens, which no longer work. A failed
    /// removal can be retried from the rejected state. If recording fails,
    /// the tokens stay, so the next renewal meets the refusal again and
    /// retries the recording instead of reporting `SignInRequired`.
    pub(super) fn mark_registration_rejected(&self, id: &AccountId) -> Result<(), Error> {
        self.set_state(id, AccountState::RegistrationRejected, None)?;
        self.remove_dead_credentials(id, None);
        Ok(())
    }

    /// Records that the provider ended the account's session, under the
    /// account lock the caller holds, then deletes the tokens, which no
    /// longer work; the registration stays for the next sign-in. A failed
    /// removal keeps the state and is retried by the next token call. If
    /// recording fails, the tokens stay, so the next renewal is refused
    /// again and retries the recording.
    pub(super) fn end_session(
        &self,
        id: &AccountId,
        stop: Option<&Canceller>,
    ) -> Result<(), Error> {
        self.set_state(id, AccountState::SignInRequired, stop)?;
        self.remove_dead_credentials(id, stop);
        Ok(())
    }

    /// Retries the cleanup of an account in `state` (rejected, or a session
    /// that ended) without taking its lock when the entry is already gone.
    /// Rechecks the state once locked. With `stop`, a cancellation ends the
    /// wait for the lock, and the cleanup is left to the next call.
    pub(super) fn retry_cleanup(
        &self,
        id: &AccountId,
        state: AccountState,
        stop: Option<&Canceller>,
    ) {
        if self.credentials_may_exist(id, stop)
            && let Ok(_lock) = self.lock_account_unless(id, stop)
            && self
                .record(id, stop)
                .is_ok_and(|(_, record)| record.state == state)
        {
            self.remove_dead_credentials(id, stop);
        }
    }

    /// Drops credentials that can no longer be used while the caller holds
    /// the account lock. A cleanup failure does not change the error
    /// reported to the app.
    pub(super) fn remove_dead_credentials(&self, id: &AccountId, stop: Option<&Canceller>) {
        if self.credentials_may_exist(id, stop) {
            let _removed = self.remove_credentials(id);
        }
    }

    fn credentials_may_exist(&self, id: &AccountId, stop: Option<&Canceller>) -> bool {
        account_entry(id).is_ok_and(|entry| {
            let read = self.with_store(stop, |store| store.read(&entry));
            !stop.is_some_and(Canceller::is_cancelled) && !matches!(read, Ok(None))
        })
    }

    /// Takes the lock of a listed account or a locally generated ID that
    /// is about to be staged during import.
    pub(super) fn lock_account(&self, id: &AccountId) -> Result<Lock<'_>, Error> {
        self.lock_account_unless(id, None)
    }

    pub(super) fn lock_account_unless(
        &self,
        id: &AccountId,
        stop: Option<&Canceller>,
    ) -> Result<Lock<'_>, Error> {
        self.lock_unless(&account_entry(id)?, stop)
    }

    fn lock_unless(&self, entry: &EntryName, stop: Option<&Canceller>) -> Result<Lock<'_>, Error> {
        let Some(stop) = stop else {
            return self.with_store(None, |store| store.lock(entry, self.lock_patience));
        };
        let started = Instant::now();
        loop {
            if stop.is_cancelled() {
                return Err(call_cancelled());
            }
            let left = self.lock_patience.saturating_sub(started.elapsed());
            let locked =
                self.with_store(Some(stop), |store| store.lock(entry, left.min(LOCK_SLICE)));
            if stop.is_cancelled() {
                return Err(call_cancelled());
            }
            match locked {
                Err(error) if error.kind() == ErrorKind::StoreBusy && left > LOCK_SLICE => {}
                result => return result,
            }
        }
    }

    /// Sets an account's state under the installation lock.
    fn set_state(
        &self,
        id: &AccountId,
        state: AccountState,
        stop: Option<&Canceller>,
    ) -> Result<(), Error> {
        self.change_installation_unless(stop, |installation| {
            account_mut(installation, id)?.state = state;
            Ok(())
        })
    }

    /// Sends one request.
    pub(super) fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.transport.send(request)
    }

    /// Fetches the provider's current signing keys for identity verification.
    pub(super) fn provider_keys(&self) -> Result<Jwks, Error> {
        Jwks::from_response(&self.send(&Jwks::request())?)
    }
}

/// The account with this ID in a record being changed.
pub(super) fn account_mut<'a>(
    installation: &'a mut Option<Installation>,
    id: &AccountId,
) -> Result<&'a mut AccountRecord, Error> {
    installation
        .as_mut()
        .and_then(|installation| installation.account_mut(id))
        .ok_or_else(unknown_account)
}

pub(super) fn unknown_account() -> Error {
    Error::new(
        ErrorKind::UnknownAccount,
        "no account with this ID exists in this installation",
    )
}

pub(super) fn sign_in_required() -> Error {
    Error::new(
        ErrorKind::SignInRequired,
        "the account has to be signed in again",
    )
}

pub(super) fn registration_rejected() -> Error {
    Error::new(
        ErrorKind::ClientRejected,
        "the provider no longer accepts this account's registration",
    )
}

/// `account-<id>`.
pub(super) fn account_entry(id: &AccountId) -> Result<EntryName, Error> {
    EntryName::new(&format!("account-{id}"))
}
