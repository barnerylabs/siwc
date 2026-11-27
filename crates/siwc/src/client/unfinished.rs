//! The registration whose first sign-in never completed: whether there is
//! one, and discarding it.

use crate::error::Error;

use super::Client;
use super::sign_in::Slot;

impl Client {
    /// The app name the unfinished registration was requested under, or
    /// `None` when there is none. The user may have edited it on the consent
    /// screen, so their ChatGPT settings can list it under another name.
    ///
    /// An earlier [`add_account`](Self::add_account) leaves one when the
    /// provider registered the app but no account was stored, for example
    /// because the code exchange failed. Offer
    /// [`resume_unfinished_registration`](Self::resume_unfinished_registration)
    /// to finish it in the workspace it was created in, and
    /// [`discard_unfinished_registration`](Self::discard_unfinished_registration)
    /// to drop it.
    ///
    /// # Errors
    ///
    /// Store errors.
    pub fn unfinished_registration(&self) -> Result<Option<String>, Error> {
        Ok(self
            .inner
            .installation(None)?
            .and_then(|installation| installation.pending)
            .map(|pending| pending.registered_as))
    }

    /// Discards the registration that an earlier
    /// [`add_account`](Self::add_account) got from the provider without
    /// storing an account, so that it is no longer offered.
    ///
    /// The provider binds a registration to the workspace chosen when it was
    /// created, and resuming it shows no workspace chooser. Offer this
    /// beside [`resume_unfinished_registration`](Self::resume_unfinished_registration)
    /// for a user who wants another workspace or no longer wants the
    /// registration; a new [`add_account`](Self::add_account) replaces it
    /// as well once its own registration arrives. A stored account is
    /// bound the same way; [`forget`](Self::forget) frees it.
    ///
    /// Returns the app name the discarded registration was requested under
    /// (see [`unfinished_registration`](Self::unfinished_registration)); it
    /// stays in the user's ChatGPT settings until the user removes it,
    /// or `None` when there was none. A sign-in of another process that
    /// already started with the registration may still complete it.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::SignInInProgress`](crate::ErrorKind::SignInInProgress)
    /// while a [`SignIn`](crate::SignIn) of this client is alive; store
    /// errors.
    pub fn discard_unfinished_registration(&self) -> Result<Option<String>, Error> {
        let _slot = Slot::take(&self.inner.signing_in)?;
        self.inner.change_installation(|installation| {
            Ok(installation
                .as_mut()
                .and_then(|installation| installation.pending.take())
                .map(|pending| pending.registered_as))
        })
    }
}
