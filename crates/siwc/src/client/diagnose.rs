//! Diagnosing a client from what its store holds now.

use std::time::Duration;

use crate::account::AccountId;
use crate::error::ErrorKind;
use crate::protocol::Credentials;
use crate::time::UnixTime;

use super::diagnosis::{
    AccountCheck, CredentialsCheck, Diagnosis, InstallationCheck, LockCheck, Timing, TokenCheck,
};
use super::entries::account_entry;
use super::records::AccountRecord;
use super::{Client, Inner};

impl Client {
    /// A redacted snapshot of this client and its accounts, for the app's
    /// user to paste into a support request: see [`Diagnosis`].
    ///
    /// It sends nothing and writes no accounts or credentials.
    /// Each account's lock is tried once, without waiting, to tell whether
    /// a renewal or a sign-in holds it. A store that cannot be read is part
    /// of the diagnosis, not an error.
    pub fn diagnose(&self) -> Diagnosis {
        self.inner.diagnose()
    }
}

impl Inner {
    fn diagnose(&self) -> Diagnosis {
        let now = self.clock.now();
        let (installation, accounts) = match self.installation(None) {
            Err(error) => (InstallationCheck::Unreadable(error.kind()), Vec::new()),
            Ok(None) => (InstallationCheck::Missing, Vec::new()),
            Ok(Some(installation)) => {
                let shown = installation
                    .accounts
                    .iter()
                    .map(|record| self.check_account(record, now))
                    .collect();
                let check = InstallationCheck::Present {
                    accounts: installation.accounts.len(),
                    pending: installation.pending.is_some(),
                };
                (check, shown)
            }
        };
        Diagnosis {
            version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            store_shared: self.with_store(None, |store| store.shared_across_processes()),
            clock: now,
            installation,
            accounts,
        }
    }

    fn check_account(&self, record: &AccountRecord, now: UnixTime) -> AccountCheck {
        let credentials = match self.stored_credentials(&record.id, None) {
            Err(error) => CredentialsCheck::Unreadable(error.kind()),
            Ok(None) => CredentialsCheck::Missing,
            Ok(Some(credentials)) => {
                let client_id = *credentials.client_id() == record.client_id;
                let subject = credentials.subject() == record.identity.subject();
                if client_id && subject {
                    CredentialsCheck::Usable(token_check(&credentials, now))
                } else {
                    CredentialsCheck::Mismatch { client_id, subject }
                }
            }
        };
        AccountCheck {
            id: record.id.clone(),
            state: record.state,
            plan_use: record.plan_use,
            credentials,
            lock: self.check_lock(&record.id),
        }
    }

    /// Tries the account's lock once and lets go of it at once.
    fn check_lock(&self, id: &AccountId) -> LockCheck {
        let taken = account_entry(id)
            .and_then(|entry| self.with_store(None, |store| store.lock(&entry, Duration::ZERO)));
        match taken {
            Ok(_released) => LockCheck::Free,
            Err(error) if error.kind() == ErrorKind::StoreBusy => LockCheck::Held,
            Err(error) => LockCheck::Unknown(error.kind()),
        }
    }
}

fn token_check(credentials: &Credentials, now: UnixTime) -> TokenCheck {
    let expires_at = credentials.expires_at().as_secs();
    let now_secs = now.as_secs();
    let timing = if now_secs >= expires_at {
        Timing::Expired {
            minutes_ago: (now_secs - expires_at) / 60,
        }
    } else if credentials.needs_refresh(now) {
        Timing::Due {
            minutes_left: (expires_at - now_secs) / 60,
        }
    } else {
        Timing::Valid {
            minutes_left: (expires_at - now_secs) / 60,
        }
    };
    TokenCheck {
        timing,
        renewable: credentials.has_refresh_token(),
    }
}
