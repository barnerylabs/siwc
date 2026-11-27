//! Accounts as an app sees them: a local name and a snapshot of the record.

use std::fmt;
use std::str::FromStr;

use crate::entropy::Entropy;
use crate::error::{Error, ErrorKind};
use crate::hex;
use crate::protocol::Identity;

/// Random bytes in an account ID.
const ID_BYTES: usize = 16;

/// The local, random, non-secret name of one account. Safe to show, log and
/// keep in a config file.
///
/// The client draws it when an account is added; it says nothing about the
/// person, the e-mail address or the registration. Every operation on an
/// account takes its ID, so which account a token belongs to never depends
/// on what happened before.
///
/// ```
/// use siwc::AccountId;
///
/// let id: AccountId = "0f1e2d3c4b5a69788796a5b4c3d2e1f0".parse()?;
/// assert_eq!(id.as_str(), "0f1e2d3c4b5a69788796a5b4c3d2e1f0");
/// assert_eq!(id.to_string(), id.as_str());
///
/// assert!(AccountId::parse("0F1E2D3C4B5A69788796A5B4C3D2E1F0").is_err());
/// assert!(AccountId::parse("alex@example.com").is_err());
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountId(String);

impl AccountId {
    /// Reads an account ID: exactly 32 lowercase hexadecimal characters.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] for any other text.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let well_formed = text.len() == 2 * ID_BYTES
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if well_formed {
            Ok(Self(text.to_owned()))
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "the account ID is not 32 lowercase hexadecimal characters",
            ))
        }
    }

    /// A fresh ID from `entropy`.
    pub(crate) fn generate(entropy: &dyn Entropy) -> Result<Self, Error> {
        let mut bytes = [0u8; ID_BYTES];
        entropy.fill(&mut bytes)?;
        let mut text = String::with_capacity(2 * ID_BYTES);
        for byte in bytes {
            hex::push(&mut text, byte);
        }
        Ok(Self(text))
    }

    /// The ID as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for AccountId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for AccountId {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text)
    }
}

/// Whether an account can hand out access tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccountState {
    /// The account holds credentials and hands out access tokens.
    SignedIn,
    /// The user signed the account out; its registration is kept for the
    /// next sign-in.
    SignedOut,
    /// The provider ended the session and its tokens were deleted; the
    /// registration is kept, and the user has to sign in again.
    SignInRequired,
    /// The provider no longer accepts the account's registration, for
    /// example because the user removed the app in their ChatGPT settings.
    /// Signing in again cannot work; the app forgets the account and adds
    /// it again.
    RegistrationRejected,
}

impl AccountState {
    /// The state's name in the installation record and in a diagnosis.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::SignedIn => "signed_in",
            Self::SignedOut => "signed_out",
            Self::SignInRequired => "sign_in_required",
            Self::RegistrationRejected => "registration_rejected",
        }
    }

    /// Reads what [`name`](Self::name) wrote.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "signed_in" => Some(Self::SignedIn),
            "signed_out" => Some(Self::SignedOut),
            "sign_in_required" => Some(Self::SignInRequired),
            "registration_rejected" => Some(Self::RegistrationRejected),
            _ => None,
        }
    }
}

/// A snapshot of one account as the store holds it.
///
/// It is read when it is asked for and does not change afterwards; ask the
/// [`Client`](crate::Client) again for the current state, or let
/// [`Client::changes`](crate::Client::changes) say what changed. `Debug` shows the
/// ID, the state and the registration's name, but nothing personal: no
/// label, e-mail address, name or subject.
#[derive(Clone, PartialEq, Eq)]
pub struct Account {
    pub(crate) id: AccountId,
    pub(crate) label: Option<String>,
    pub(crate) identity: Identity,
    pub(crate) state: AccountState,
    pub(crate) plan_use: bool,
    pub(crate) registered_as: String,
    pub(crate) shares_login_with: Vec<AccountId>,
}

impl Account {
    /// The account's local ID.
    #[must_use]
    pub fn id(&self) -> &AccountId {
        &self.id
    }

    /// The label the app gave the account, such as "Work".
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// The identity verified at the last sign-in, on this installation or on
    /// the one that exported the account.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Whether the account hands out access tokens.
    #[must_use]
    pub fn state(&self) -> AccountState {
        self.state
    }

    /// Whether the session last stored for this account granted use of the
    /// ChatGPT plan.
    ///
    /// The value stays when the account signs out or its session ends, so
    /// it says what the user allowed, not that a request can be sent now:
    /// look at [`state`](Self::state) as well.
    #[must_use]
    pub fn plan_use(&self) -> bool {
        self.plan_use
    }

    /// Returns `Ok(())` when [`plan_use`](Self::plan_use) is `true`, or an
    /// [`ErrorKind::PlanUseNotGranted`] error (with `provider_code() == None`)
    /// when the user signed in without granting plan use.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::PlanUseNotGranted`] when `!self.plan_use()`. An `Ok` does
    /// not mean the account is signed in; see [`plan_use`](Self::plan_use).
    pub fn check_plan_use(&self) -> Result<(), Error> {
        if self.plan_use {
            Ok(())
        } else {
            Err(plan_use_not_granted())
        }
    }

    /// The app name this account's registration was requested under, even
    /// after the app was renamed. The user may have edited it on the consent
    /// screen, so the entry in their ChatGPT settings can differ.
    #[must_use]
    pub fn registered_as(&self) -> &str {
        &self.registered_as
    }

    /// Other accounts of the same person (the same verified subject), for
    /// example a personal and a team workspace. Each keeps its own
    /// registration; the app may label or forget one.
    #[must_use]
    pub fn shares_login_with(&self) -> &[AccountId] {
        &self.shares_login_with
    }
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("plan_use", &self.plan_use)
            .field("registered_as", &self.registered_as)
            .field("shares_login_with", &self.shares_login_with)
            .finish_non_exhaustive()
    }
}

/// The error for a session whose grant does not include plan use.
pub(crate) fn plan_use_not_granted() -> Error {
    Error::new(
        ErrorKind::PlanUseNotGranted,
        "the sign-in does not grant plan use",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(u8);

    impl Entropy for Fixed {
        fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = self.0.wrapping_add((index as u8).wrapping_mul(17));
            }
            Ok(())
        }
    }

    #[test]
    fn a_generated_id_is_sixteen_random_bytes_in_lower_case_hex() {
        let id = AccountId::generate(&Fixed(0)).unwrap();
        assert_eq!(id.as_str(), "00112233445566778899aabbccddeeff");
        assert_eq!(AccountId::parse(id.as_str()).unwrap(), id);
    }

    #[test]
    fn every_state_reads_back_from_its_name() {
        for state in [
            AccountState::SignedIn,
            AccountState::SignedOut,
            AccountState::SignInRequired,
            AccountState::RegistrationRejected,
        ] {
            assert_eq!(AccountState::from_name(state.name()), Some(state));
        }
        assert_eq!(AccountState::from_name("SignedIn"), None);
    }

    #[test]
    fn only_32_lower_case_hex_characters_parse() {
        for text in [
            "",
            "00112233445566778899aabbccddeef",
            "00112233445566778899aabbccddeeff0",
            "00112233445566778899aabbccddeefg",
            "00112233445566778899AABBCCDDEEFF",
            "../112233445566778899aabbccddeef",
        ] {
            assert!(AccountId::parse(text).is_err(), "{text:?}");
        }
    }
}
