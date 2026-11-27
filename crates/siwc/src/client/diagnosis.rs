//! What a diagnosis holds and how it reads as text.
//!
//! Everything here is a state, a yes or no, an error kind, a whole number
//! of minutes or an account ID: nothing that names a person, a
//! registration, a machine or a path, and no token.

use std::fmt;

use crate::account::{AccountId, AccountState};
use crate::error::ErrorKind;
use crate::time::UnixTime;

/// A redacted snapshot of a client and its store, for a support request.
///
/// [`Client::diagnose`](crate::Client::diagnose) makes one. Its text
/// (`Display`) is for people and its wording may change: one fact per line, the crate's
/// version, the platform, the store, the installation, and for
/// each account its ID, state, plan use, whether its credentials are
/// there, readable and its own, how long its access token lasts in whole
/// minutes, and whether its refresh lock is held.
///
/// Neither the text nor `Debug` holds a token, a code, a client ID, a
/// subject, an e-mail address, a name, a label, the host ID, a path or a
/// start link. Accounts appear by their random [`AccountId`].
///
/// ```
/// use siwc::store::MemoryStore;
/// use siwc::{AppName, Client};
/// # #[derive(Debug)]
/// # struct MyHttpClient;
/// # impl siwc::Transport for MyHttpClient {
/// #     fn send(&self, _: &siwc::protocol::HttpRequest) -> Result<siwc::protocol::HttpResponse, siwc::Error> { todo!() }
/// # }
///
/// let client = Client::new(AppName::new("Paste Perfect")?, MemoryStore::new(), MyHttpClient);
/// println!("{}", client.diagnose());
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Diagnosis {
    pub(super) version: &'static str,
    pub(super) os: &'static str,
    pub(super) arch: &'static str,
    pub(super) store_shared: bool,
    pub(super) clock: UnixTime,
    pub(super) installation: InstallationCheck,
    pub(super) accounts: Vec<AccountCheck>,
}

/// The installation record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum InstallationCheck {
    /// No account was ever added.
    Missing,
    /// The record could not be read, with the reason.
    Unreadable(ErrorKind),
    Present {
        accounts: usize,
        pending: bool,
    },
}

/// One account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AccountCheck {
    pub(super) id: AccountId,
    pub(super) state: AccountState,
    pub(super) plan_use: bool,
    pub(super) credentials: CredentialsCheck,
    pub(super) lock: LockCheck,
}

/// An account's credentials entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CredentialsCheck {
    Missing,
    Unreadable(ErrorKind),
    /// Readable, but issued to another registration or another person.
    Mismatch {
        client_id: bool,
        subject: bool,
    },
    Usable(TokenCheck),
}

/// The access token, relative to the client's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TokenCheck {
    pub(super) timing: Timing,
    /// Whether a refresh token was granted.
    pub(super) renewable: bool,
}

/// How long the access token lasts, in whole minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Timing {
    Valid {
        minutes_left: u64,
    },
    /// Renewed on the next call.
    Due {
        minutes_left: u64,
    },
    Expired {
        minutes_ago: u64,
    },
}

/// The account's lock, tried once without waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LockCheck {
    Free,
    Held,
    Unknown(ErrorKind),
}

impl fmt::Display for Diagnosis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "siwc {} on {} {}", self.version, self.os, self.arch)?;
        writeln!(
            f,
            "store shared across processes: {}",
            yes(self.store_shared)
        )?;
        writeln!(f, "clock: {} (Unix seconds)", self.clock.as_secs())?;
        match &self.installation {
            InstallationCheck::Missing => writeln!(f, "installation: none yet")?,
            InstallationCheck::Unreadable(kind) => {
                writeln!(f, "installation: unreadable ({})", kind.name())?;
            }
            InstallationCheck::Present { accounts, pending } => writeln!(
                f,
                "installation: {accounts} account(s), unfinished registration: {}",
                yes(*pending)
            )?,
        }
        for account in &self.accounts {
            write!(f, "{account}")?;
        }
        Ok(())
    }
}

impl fmt::Display for AccountCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "account {}", self.id)?;
        writeln!(
            f,
            "  state: {}, plan use: {}",
            self.state.name(),
            yes(self.plan_use)
        )?;
        match &self.credentials {
            CredentialsCheck::Missing => writeln!(f, "  credentials: missing")?,
            CredentialsCheck::Unreadable(kind) => {
                writeln!(f, "  credentials: unreadable ({})", kind.name())?;
            }
            CredentialsCheck::Mismatch { client_id, subject } => writeln!(
                f,
                "  credentials: another account's (client ID matches: {}, subject matches: {})",
                yes(*client_id),
                yes(*subject)
            )?,
            CredentialsCheck::Usable(token) => {
                writeln!(f, "  credentials: present, client ID and subject match")?;
                let renewable = if token.renewable {
                    "renewable"
                } else {
                    "not renewable"
                };
                match token.timing {
                    Timing::Valid { minutes_left } => writeln!(
                        f,
                        "  access token: valid for {minutes_left} more minute(s), {renewable}"
                    )?,
                    Timing::Due { minutes_left } => writeln!(
                        f,
                        "  access token: due for renewal, expires in {minutes_left} minute(s), {renewable}"
                    )?,
                    Timing::Expired { minutes_ago } => writeln!(
                        f,
                        "  access token: expired {minutes_ago} minute(s) ago, {renewable}"
                    )?,
                }
            }
        }
        match self.lock {
            LockCheck::Free => writeln!(f, "  refresh lock: free"),
            LockCheck::Held => writeln!(f, "  refresh lock: held by another thread or process"),
            LockCheck::Unknown(kind) => {
                writeln!(f, "  refresh lock: unknown ({})", kind.name())
            }
        }
    }
}

fn yes(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
