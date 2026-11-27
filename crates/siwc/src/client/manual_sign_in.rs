//! Manual sign-ins: the user opens the authorization link on any machine
//! and pastes the address the browser was sent back to.

use std::fmt;

use crate::account::AccountId;
use crate::error::{Error, ErrorKind};
use crate::host::HostId;
use crate::loopback::Listener;
use crate::protocol::{Attempt, Callback, Registration};
use crate::secret::SecretString;

use super::sign_in::{Adding, Completed, Purpose, Slot};
use super::{Client, Inner};

impl Client {
    /// Starts adding an account without a loopback listener, for an app
    /// that runs on another machine than the user's browser: a remote
    /// shell, a virtual machine or a container. The user opens
    /// [`authorization_link`](ManualSignIn::authorization_link) anywhere,
    /// signs in, and copies the `http://127.0.0.1:...` address the browser is
    /// then sent to; [`finish`](ManualSignIn::finish) takes that text. The
    /// page normally fails to load. A program listening on that port on the
    /// browser's machine sees the authorization code, which is useless
    /// without the PKCE verifier that stays in this process.
    ///
    /// Otherwise it works as [`add_account`](Self::add_account) does, with
    /// a new registration, the same account limit and the same one sign-in
    /// per client at a time.
    ///
    /// ```no_run
    /// # fn run(client: &siwc::Client, read_line: impl Fn() -> String) -> Result<(), siwc::Error> {
    /// let mut sign_in = client.add_account_manually()?;
    /// println!("Open this link in a browser and sign in:");
    /// println!("{}", sign_in.authorization_link());
    /// println!("Then paste the address of the page that failed to load.");
    /// let account = loop {
    ///     match sign_in.finish(&read_line()) {
    ///         Err(_) if sign_in.is_open() => {
    ///             println!("That is not the address. Paste it again.");
    ///         }
    ///         result => break result?.into_account(),
    ///     }
    /// };
    /// # drop(account);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`add_account`](Self::add_account).
    pub fn add_account_manually(&self) -> Result<ManualSignIn, Error> {
        self.start_add_manually(Adding::New)
    }

    /// Resumes an unfinished registration like
    /// [`resume_unfinished_registration`](Self::resume_unfinished_registration),
    /// completed with a pasted redirect as in
    /// [`add_account_manually`](Self::add_account_manually).
    ///
    /// # Errors
    ///
    /// As [`resume_unfinished_registration`](Self::resume_unfinished_registration).
    pub fn resume_unfinished_registration_manually(&self) -> Result<ManualSignIn, Error> {
        self.start_add_manually(Adding::Unfinished)
    }

    fn start_add_manually(&self, adding: Adding) -> Result<ManualSignIn, Error> {
        let (attempt, purpose, slot) = self.begin_add(adding, Inner::manual_attempt)?;
        Ok(ManualSignIn::new(self, attempt, purpose, slot))
    }

    /// Signs an account in again like [`sign_in_again`](Self::sign_in_again),
    /// completed with a pasted redirect as in
    /// [`add_account_manually`](Self::add_account_manually).
    ///
    /// The authorization link names no account: the provider shows its
    /// account chooser, and a sign-in completed by a different user still
    /// fails with [`ErrorKind::AccountMismatch`].
    ///
    /// # Errors
    ///
    /// As [`sign_in_again`](Self::sign_in_again).
    pub fn sign_in_again_manually(&self, id: &AccountId) -> Result<ManualSignIn, Error> {
        self.start_again_manually(id, false)
    }

    /// Asks for plan use like [`enable_plan_use`](Self::enable_plan_use),
    /// completed with a pasted redirect as in
    /// [`add_account_manually`](Self::add_account_manually).
    ///
    /// # Errors
    ///
    /// As [`sign_in_again`](Self::sign_in_again).
    pub fn enable_plan_use_manually(&self, id: &AccountId) -> Result<ManualSignIn, Error> {
        self.start_again_manually(id, true)
    }

    fn start_again_manually(&self, id: &AccountId, consent: bool) -> Result<ManualSignIn, Error> {
        let (attempt, purpose, slot) = self.begin_again(id, consent, Inner::manual_attempt)?;
        Ok(ManualSignIn::new(self, attempt, purpose, slot))
    }
}

impl Inner {
    /// Starts an attempt that nothing listens for. Its redirect port is
    /// one the system had free a moment ago; with nothing bound to it, a
    /// browser on this machine is refused at once and shows the address.
    /// Like every sign-in of the client, it carries no account hint.
    fn manual_attempt(
        &self,
        registration: Registration<'_>,
        host: &HostId,
    ) -> Result<Attempt, Error> {
        let port = Listener::bind()?.port();
        let host = self.send_host_id.then_some(host);
        Attempt::start_inner(registration, host, port, self.entropy.as_ref())
    }
}

/// A sign-in that the user completes by pasting the address their browser
/// was sent back to.
///
/// Show [`authorization_link`](Self::authorization_link), then pass what
/// the user pastes to [`finish`](Self::finish). Text that is not this
/// sign-in's redirect is refused and the sign-in stays open; anything else
/// ends it. A client has at most one sign-in at a time, manual or not;
/// dropping this value ends it and lets the next one start. It has no
/// timeout of its own: the provider's code expires, and the app drops the
/// value when the user gives up.
#[must_use = "call `ManualSignIn::finish` with the pasted redirect URL; dropping it cancels the sign-in"]
pub struct ManualSignIn {
    link: SecretString,
    client: Client,
    open: Option<(Attempt, Purpose)>,
    account: Option<AccountId>,
    /// The client's sign-in slot; `None` once the sign-in has ended.
    slot: Option<Slot>,
}

impl ManualSignIn {
    fn new(client: &Client, attempt: Attempt, purpose: Purpose, slot: Slot) -> Self {
        let account = match &purpose {
            Purpose::Add { .. } => None,
            Purpose::Again { id, .. } => Some(id.clone()),
        };
        Self {
            link: SecretString::new(attempt.authorization_url().to_owned()),
            client: client.clone(),
            open: Some((attempt, purpose)),
            account,
            slot: Some(slot),
        }
    }

    /// The provider's authorization URL, for the user to open in a browser
    /// on any machine.
    ///
    /// It carries this sign-in's `state`, `nonce` and PKCE challenge, but
    /// no token and nothing about the user. Show it to the user; keep it
    /// out of logs.
    #[must_use]
    pub fn authorization_link(&self) -> &str {
        self.link.expose()
    }

    /// Takes the text the user pasted: the address the browser was sent
    /// to after the sign-in, `http://127.0.0.1:<port>/auth/callback?…`.
    /// Then exchanges the code, verifies the identity and stores the
    /// account, as [`SignIn::finish`](crate::SignIn::finish) does.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::CallbackRejected`] for text that is not this sign-in's
    /// redirect: another address, another port, or a `state` that is not
    /// this sign-in's. The sign-in stays open, and the user can paste
    /// again.
    ///
    /// Every other outcome ends the sign-in and frees the client for the
    /// next one: [`ErrorKind::AccessDenied`] when the user declined,
    /// [`ErrorKind::AccountMismatch`] when signing in again was completed by
    /// a different user, and the other errors of
    /// [`SignIn::finish`](crate::SignIn::finish) except the timeout and the
    /// cancellation. A redirect with this sign-in's `state` that breaks a
    /// rule of the callback ends it with `CallbackRejected` too, so ask
    /// [`is_open`](Self::is_open) whether to let the user paste again. Once
    /// the sign-in has ended, `finish` returns [`ErrorKind::InvalidInput`].
    pub fn finish(&mut self, pasted: &str) -> Result<Completed, Error> {
        if self.slot.is_none() {
            return Err(Error::new(ErrorKind::InvalidInput, "the sign-in has ended"));
        }
        let result = finish_here(&self.client, &mut self.open, pasted);
        if self.open.is_none() {
            self.slot = None;
        }
        result
    }

    /// Whether the sign-in still waits for pasted text. After an error
    /// from [`finish`](Self::finish) it tells the app whether to ask the
    /// user to paste again or to report the error.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.slot.is_some()
    }
}

/// Offers the pasted text to the attempt in `open` and completes the
/// sign-in when it is the attempt's redirect.
fn finish_here(
    client: &Client,
    open: &mut Option<(Attempt, Purpose)>,
    pasted: &str,
) -> Result<Completed, Error> {
    let (attempt, purpose) = open.take().ok_or_else(not_the_redirect)?;
    let outcome = match attempt.accept_redirect(pasted) {
        Callback::Unrelated(attempt) => {
            *open = Some((attempt, purpose));
            return Err(not_the_redirect());
        }
        Callback::Final(outcome) => outcome,
    };
    client.inner.complete(outcome, purpose, None)
}

fn not_the_redirect() -> Error {
    Error::new(
        ErrorKind::CallbackRejected,
        "the pasted text is not the address this sign-in redirects to",
    )
}

impl fmt::Debug for ManualSignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("ManualSignIn");
        match &self.account {
            None => debug.field("adds_account", &true),
            Some(id) => debug.field("account", id),
        };
        debug
            .field("open", &self.slot.is_some())
            .finish_non_exhaustive()
    }
}
