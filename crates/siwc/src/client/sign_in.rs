//! Browser sign-ins: adding an account, signing one in again, enabling plan
//! use, and storing what they bring.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::account::{Account, AccountId, AccountState};
use crate::error::{Error, ErrorKind};
use crate::host::HostId;
use crate::loopback::{Answer, Canceller, Listener, Page, Received, Waiting};
use crate::protocol::{Attempt, Registration, Returning};

use super::entries::registration_rejected;
use super::records::{Installation, MAX_ACCOUNTS, Pending};
use super::{Client, Inner};

mod complete;
mod finish_async;

impl Client {
    /// Starts adding an account: a new registration with the provider.
    ///
    /// No account hint is sent, and the user can sign in to any account,
    /// including one that is already stored here (it is kept as an account of
    /// its own, see [`Account::shares_login_with`]). A browser already signed
    /// in to ChatGPT is shown an account chooser that also offers another or a
    /// new account; OpenAI documents the chooser only for signing in again, so
    /// show the identity of the account that was added. If it is not the one
    /// the user meant, [`forget`](Self::forget) it and add again. The
    /// provider binds the registration to the workspace picked here.
    ///
    /// An earlier attempt that got as far as a registration but not to a
    /// stored account is not continued: that is
    /// [`resume_unfinished_registration`](Self::resume_unfinished_registration),
    /// and [`unfinished_registration`](Self::unfinished_registration) tells
    /// whether there is one to offer. Once this sign-in's registration
    /// arrives it takes the earlier one's place, which then stays listed in
    /// the user's ChatGPT settings without an account here.
    ///
    /// The first account added creates the installation's host ID.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::AccountLimit`] when 32 accounts are stored;
    /// [`ErrorKind::SignInInProgress`] while another [`SignIn`] of this
    /// client is alive; [`ErrorKind::Loopback`] when the callback port
    /// cannot be bound; store errors, among them
    /// [`ErrorKind::StoreCorrupt`]; [`ErrorKind::Randomness`].
    pub fn add_account(&self) -> Result<SignIn, Error> {
        self.start_add(Adding::New)
    }

    /// Continues the registration that an earlier
    /// [`add_account`](Self::add_account) got from the provider without
    /// storing an account, for example because its code exchange failed.
    /// The provider shows no workspace chooser: the registration stays in
    /// the workspace it was created in.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when there is no unfinished registration;
    /// otherwise as [`add_account`](Self::add_account).
    pub fn resume_unfinished_registration(&self) -> Result<SignIn, Error> {
        self.start_add(Adding::Unfinished)
    }

    fn start_add(&self, adding: Adding) -> Result<SignIn, Error> {
        let (waiting, purpose, slot) = self.begin_add(adding, Inner::serve)?;
        Ok(SignIn {
            client: self.clone(),
            waiting: Box::new(waiting),
            purpose,
            _slot: slot,
        })
    }

    /// Starts signing an existing account in again, for example after a
    /// sign-out or when its session ended.
    ///
    /// The provider is not told which account to expect, so it shows its
    /// account chooser; a sign-in completed by a different user fails with
    /// [`ErrorKind::AccountMismatch`] without touching this account.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::UnknownAccount`]; [`ErrorKind::ClientRejected`] for an
    /// account whose registration the provider no longer accepts
    /// ([`AccountState::RegistrationRejected`]): no browser is opened,
    /// [`forget`](Self::forget) the account and add it again;
    /// [`ErrorKind::SignInInProgress`] while another [`SignIn`] of this
    /// client is alive; [`ErrorKind::StoreCorrupt`] when the stored
    /// credentials cannot be read or name another account (sign the account
    /// out first); [`ErrorKind::Randomness`] when creating the attempt;
    /// [`ErrorKind::Loopback`] when binding the port or configuring the
    /// browser listener; other store errors.
    pub fn sign_in_again(&self, id: &AccountId) -> Result<SignIn, Error> {
        self.start_again(id, false)
    }

    /// Like [`sign_in_again`](Self::sign_in_again), and asks the provider to
    /// show the consent screen again, so the user can allow use of their
    /// ChatGPT plan. Call it only when the user asked for that.
    ///
    /// # Errors
    ///
    /// As [`sign_in_again`](Self::sign_in_again).
    pub fn enable_plan_use(&self, id: &AccountId) -> Result<SignIn, Error> {
        self.start_again(id, true)
    }

    fn start_again(&self, id: &AccountId, consent: bool) -> Result<SignIn, Error> {
        let (waiting, purpose, slot) = self.begin_again(id, consent, Inner::serve)?;
        Ok(SignIn {
            client: self.clone(),
            waiting: Box::new(waiting),
            purpose,
            _slot: slot,
        })
    }

    /// Takes the client's sign-in slot and picks the registration for a new
    /// account; `start` begins the sign-in with it.
    pub(super) fn begin_add<T>(
        &self,
        adding: Adding,
        start: impl FnOnce(&Inner, Registration<'_>, &HostId) -> Result<T, Error>,
    ) -> Result<(T, Purpose, Slot), Error> {
        let inner = &self.inner;
        let slot = Slot::take(&inner.signing_in)?;
        let installation = match inner.installation(None)? {
            Some(installation) if installation.accounts.len() >= MAX_ACCOUNTS => {
                return Err(account_limit());
            }
            Some(installation) => installation,
            None if matches!(adding, Adding::Unfinished) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "there is no unfinished registration to resume",
                ));
            }
            // The first account: the installation gets its host ID, unless
            // another process gave it one meanwhile.
            None => inner.change_installation(|installation| {
                if installation.is_none() {
                    *installation = Some(Installation::new(HostId::generate_inner(
                        inner.entropy.as_ref(),
                    )?));
                }
                installation.clone().ok_or_else(installation_missing)
            })?,
        };
        let pending = match adding {
            Adding::New => None,
            Adding::Unfinished => Some(installation.pending.ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "there is no unfinished registration to resume",
                )
            })?),
        };
        let registration = match &pending {
            Some(pending) => Registration::Saved(Returning::unfinished(&pending.client_id)),
            None => Registration::New(&inner.app),
        };
        let started = start(inner, registration, &installation.host)?;
        Ok((started, Purpose::Add { pending }, slot))
    }

    /// Takes the client's sign-in slot for an existing account and picks
    /// its registration; `start` begins the sign-in with it.
    pub(super) fn begin_again<T>(
        &self,
        id: &AccountId,
        consent: bool,
        start: impl FnOnce(&Inner, Registration<'_>, &HostId) -> Result<T, Error>,
    ) -> Result<(T, Purpose, Slot), Error> {
        let inner = &self.inner;
        let (installation, record) = inner.record(id, None)?;
        if record.state == AccountState::RegistrationRejected {
            inner.retry_cleanup(id, AccountState::RegistrationRejected, None);
            return Err(registration_rejected());
        }
        let slot = Slot::take(&inner.signing_in)?;
        let credentials = inner.credentials(&record, None)?;
        // No hint: the start link hands the authorization URL to whoever
        // opens it, and the link reaches the opener's command line, so the
        // URL carries no ID token and no e-mail address.
        let returning = match &credentials {
            Some(credentials) => Returning::signed_in(&record.identity, credentials),
            None => Returning::signed_out(&record.client_id, &record.identity),
        }
        .without_hints();
        let returning = if consent {
            returning.ask_consent()
        } else {
            returning
        };
        let started = start(inner, Registration::Saved(returning), &installation.host)?;
        Ok((
            started,
            Purpose::Again {
                id: id.clone(),
                sign_outs: record.sign_outs,
            },
            slot,
        ))
    }
}

/// A sign-in that waits for the user in the browser.
///
/// Open [`start_link`](Self::start_link) in the browser, then call
/// [`finish`](Self::finish), which blocks until the browser comes back.
/// A client has at most one sign-in at a time; dropping this value ends it
/// and lets the next one start.
#[must_use = "call `SignIn::finish` to wait for the browser; dropping it cancels the sign-in"]
pub struct SignIn {
    client: Client,
    waiting: Box<Waiting>,
    purpose: Purpose,
    _slot: Slot,
}

/// Which registration a new account gets.
#[derive(Clone, Copy)]
pub(super) enum Adding {
    /// A new one, in the workspace the user picks.
    New,
    /// The installation's unfinished one.
    Unfinished,
}

/// What a sign-in is for.
pub(super) enum Purpose {
    /// A new account, completing the pending registration when one is given.
    Add { pending: Option<Pending> },
    /// An existing account, with the sign-out count observed when started.
    Again { id: AccountId, sign_outs: u64 },
}

impl SignIn {
    /// `http://127.0.0.1:<port>/start/<token>`: the local link that sends
    /// the browser to the provider.
    ///
    /// Show it when [`open_browser`](Self::open_browser) fails, and keep it
    /// out of logs. It stops working when [`finish`](Self::finish) returns.
    ///
    /// The link holds a random path that only this wait knows. Whoever opens
    /// it before the wait ends is sent on to the authorization URL, which
    /// carries this attempt's `state`, `nonce` and PKCE challenge but no
    /// account hint: no ID token and no e-mail address. The listener holds
    /// the PKCE verifier, so that person can end the attempt or, when adding
    /// an account, complete it with an account of their own; signing an
    /// existing account in again rejects a different user. Give the link to
    /// the user only, and after adding an account show the identity it
    /// signed in, so the user notices an account that is not theirs.
    /// [`open_browser`](Self::open_browser) passes the link to the opener on
    /// its command line, which other local users can read on Linux and
    /// macOS.
    #[must_use]
    pub fn start_link(&self) -> &str {
        self.waiting.start_link()
    }

    /// Opens the start link in the system browser.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Cancelled`] when the sign-in was cancelled;
    /// [`ErrorKind::BrowserUnavailable`] when the opener fails, then show
    /// [`start_link`](Self::start_link) instead.
    pub fn open_browser(&self) -> Result<(), Error> {
        self.waiting.open_browser()
    }

    /// A handle that requests cancellation from another thread. See
    /// [`finish`](Self::finish) for when the request takes effect. Once
    /// sign-in completes, this handle can still cancel other work.
    #[must_use]
    pub fn canceller(&self) -> Canceller {
        self.waiting.canceller()
    }

    /// Waits for the browser, exchanges the code, verifies the identity,
    /// stores the account and answers the tab.
    ///
    /// The tab reports success once everything is stored.
    ///
    /// A new account accepts cancellation until the final installation
    /// update starts under the installation lock. An existing account
    /// accepts it until the credential write starts under its account lock.
    /// An in-flight request or store operation can delay the result.
    /// An accepted cancellation takes priority over a later failure and
    /// leaves previously stored credentials in place when their
    /// registration still works. A provider rejection can invalidate the
    /// registration independently. A new registration may remain unfinished,
    /// for [`Client::resume_unfinished_registration`].
    ///
    /// # Errors
    ///
    /// [`ErrorKind::TimedOut`], [`ErrorKind::Cancelled`],
    /// [`ErrorKind::AccessDenied`] when the user declined,
    /// [`ErrorKind::ClientRejected`] when the provider refused the app's
    /// registration, in the browser or at the token endpoint (only the
    /// token endpoint's answer marks an account
    /// [`AccountState::RegistrationRejected`] or clears an unfinished
    /// registration; see [`ErrorKind::ClientRejected`]),
    /// [`ErrorKind::AccountMismatch`] when signing in again was completed by
    /// a different user, [`ErrorKind::AccountLimit`] when other sign-ins
    /// filled the installation meanwhile, [`ErrorKind::UnknownAccount`] when
    /// the account was forgotten meanwhile, [`ErrorKind::SignInRequired`]
    /// when another thread or process signed the account out or changed it
    /// while this sign-in completed. Adding an account can return
    /// [`ErrorKind::Randomness`] generating its ID, [`ErrorKind::SignInInProgress`]
    /// for a competing registration, or [`ErrorKind::InvalidResponse`] for
    /// a duplicate issued ID. Finish also forwards errors of the callback, the code
    /// exchange, the ID token check, the transport and the store.
    pub fn finish(self, timeout: Duration) -> Result<Completed, Error> {
        let Self {
            client,
            waiting,
            purpose,
            _slot,
        } = self;
        let canceller = waiting.canceller();
        let Received { outcome, reply } = waiting.wait(timeout).map_err(|error| {
            if canceller.is_cancelled() {
                cancelled()
            } else {
                error
            }
        })?;
        let result = client.inner.complete(outcome, purpose, Some(&canceller));
        reply.send(match &result {
            Ok(completed) if completed.account().plan_use() => Answer::SignedIn,
            Ok(_) => Answer::SignedInPlanUseOff,
            Err(error) if error.kind() == ErrorKind::AccessDenied => Answer::Declined,
            Err(_) => Answer::Failed,
        });
        result
    }
}

impl fmt::Debug for SignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("SignIn");
        match &self.purpose {
            Purpose::Add { .. } => debug.field("adds_account", &true),
            Purpose::Again { id, .. } => debug.field("account", id),
        };
        debug
            .field("waiting", &self.waiting)
            .finish_non_exhaustive()
    }
}

/// How a sign-in ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Completed {
    /// The account as it is stored now.
    account: Account,
    /// True once per account: the first time a sign-in ends with plan use
    /// granted. The app shows its welcome note then.
    plan_use_started: bool,
}

impl Completed {
    /// The stored account after sign-in.
    #[must_use]
    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Takes ownership of the stored account after sign-in.
    #[must_use]
    pub fn into_account(self) -> Account {
        self.account
    }

    /// Whether to show the first plan-use welcome.
    #[must_use]
    pub fn plan_use_started(&self) -> bool {
        self.plan_use_started
    }
}

/// The one sign-in a client can have at a time; freed when dropped.
pub(super) struct Slot(Arc<AtomicBool>);

impl Slot {
    pub(super) fn take(signing_in: &Arc<AtomicBool>) -> Result<Self, Error> {
        signing_in
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                Error::new(
                    ErrorKind::SignInInProgress,
                    "this client already has a sign-in waiting for the browser",
                )
            })?;
        Ok(Self(Arc::clone(signing_in)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Inner {
    /// Binds the listener, starts the attempt with its port and serves it.
    fn serve(&self, registration: Registration<'_>, host: &HostId) -> Result<Waiting, Error> {
        let page = Page::with_texts(&self.app, self.texts.clone()).with_style(self.style.clone());
        let host = self.send_host_id.then_some(host);
        let listener = if self.callback_port == 0 {
            Listener::bind()?
        } else {
            Listener::bind_port(self.callback_port)?
        };
        let attempt =
            Attempt::start_inner(registration, host, listener.port(), self.entropy.as_ref())?;
        listener.serve_inner(attempt, page, self.entropy.as_ref())
    }
}

fn account_limit() -> Error {
    Error::new(
        ErrorKind::AccountLimit,
        "the installation already holds 32 accounts",
    )
}

fn installation_missing() -> Error {
    Error::corrupt_entry("the installation record disappeared during the sign-in")
}

fn cancelled() -> Error {
    Error::new(
        ErrorKind::Cancelled,
        "the app cancelled the wait for the browser",
    )
}
