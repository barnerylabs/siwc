//! Signing an account out, and forgetting it.

use std::time::Duration;

use crate::account::{AccountId, AccountState};
use crate::error::{Error, ErrorKind};
use crate::protocol::Credentials;

use super::entries::account_mut;
use super::{Client, Inner};

/// The wait before a revocation is sent once more after a temporary
/// failure.
const REVOCATION_RETRY_WAIT: Duration = Duration::from_secs(1);

/// How a sign-out went.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use = "tell the user when the revocation was not confirmed"]
pub struct SignOut {
    /// Whether the provider confirmed that the session is revoked. The local
    /// tokens are deleted either way.
    revocation_confirmed: bool,
    /// The app name the registration was requested under, to help the user
    /// find it in their ChatGPT settings and remove it by hand. The user may
    /// have edited it on the consent screen.
    registered_as: String,
}

impl SignOut {
    /// Whether the provider confirmed revocation. Local tokens are deleted either way.
    #[must_use]
    pub fn revocation_confirmed(&self) -> bool {
        self.revocation_confirmed
    }

    /// The name the app requested at registration. The user may have edited
    /// it on the consent screen; use it to help them find the app in settings.
    #[must_use]
    pub fn registered_as(&self) -> &str {
        &self.registered_as
    }
}

impl Client {
    /// Signs one account out: revokes its session, deletes its tokens and
    /// keeps the account with its registration, so
    /// [`sign_in_again`](Self::sign_in_again) brings it back under the same
    /// entry in the user's ChatGPT settings. Other accounts stay signed in.
    ///
    /// The revocation is sent once more, a second later, after a temporary
    /// failure; the account's lock is held meanwhile. The tokens are deleted
    /// whatever the provider answered; stored credentials reported as
    /// [`ErrorKind::StoreCorrupt`] are deleted without a revocation. A
    /// rejected registration is cleaned up without reading its credentials or
    /// contacting the provider. For other states, an unsupported credential
    /// format returns [`ErrorKind::StoreUnsupported`] and leaves the entry intact.
    /// If a keychain entry will not open and the recorded service is unconfigured, the call
    /// returns [`ErrorKind::InvalidInput`] and leaves the session intact.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::UnknownAccount`]; store errors, after which the tokens
    /// may still be stored.
    pub fn sign_out(&self, id: &AccountId) -> Result<SignOut, Error> {
        self.inner.sign_out(id, false)
    }

    /// Signs the account out like [`sign_out`](Self::sign_out), then removes
    /// it; its ID is unknown afterwards. An account that is already signed
    /// out is removed without a request.
    ///
    /// The registration stays with the provider: tell the user where to
    /// remove it with [`SignOut::registered_as`].
    ///
    /// # Errors
    ///
    /// As [`sign_out`](Self::sign_out).
    pub fn forget(&self, id: &AccountId) -> Result<SignOut, Error> {
        self.inner.sign_out(id, true)
    }
}

impl Inner {
    fn sign_out(&self, id: &AccountId, forget: bool) -> Result<SignOut, Error> {
        self.record(id, None)?;
        let _lock = self.lock_account(id)?;
        let (_, record) = self.record(id, None)?;
        let next_sign_out = (!forget).then(|| record.next_sign_out()).transpose()?;
        let credentials = if record.state == AccountState::RegistrationRejected {
            None
        } else {
            match self.credentials(&record, None) {
                Ok(credentials) => credentials,
                Err(error) if error.kind() == ErrorKind::StoreCorrupt => None,
                Err(error) => return Err(error),
            }
        };
        let revocation_confirmed = credentials
            .as_ref()
            .is_some_and(|credentials| self.revoke(credentials));
        self.remove_credentials(id)?;
        self.change_installation(|installation| {
            if let Some(next) = next_sign_out {
                let record = account_mut(installation, id)?;
                record.sign_outs = next;
                // A registration the provider gave up stays marked: signing
                // in again could not work.
                if record.state != AccountState::RegistrationRejected {
                    record.state = AccountState::SignedOut;
                }
            } else if let Some(installation) = installation.as_mut() {
                installation.remove_account(id);
            }
            Ok(())
        })?;
        Ok(SignOut {
            revocation_confirmed,
            registered_as: record.registered_as,
        })
    }

    /// Sends a revocation, once more after a temporary failure and a short
    /// wait. Whether the provider confirmed it.
    fn revoke(&self, credentials: &Credentials) -> bool {
        let Some(request) = credentials.revoke_request() else {
            return false;
        };
        for attempt in 0..2 {
            if attempt > 0 {
                self.clock.sleep(REVOCATION_RETRY_WAIT);
            }
            match self
                .send(&request)
                .and_then(|answer| credentials.revocation_confirmed(&answer))
            {
                Ok(()) => return true,
                Err(error) if error.kind() == ErrorKind::Temporary => {}
                Err(_) => return false,
            }
        }
        false
    }
}
