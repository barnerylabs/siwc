//! The client ID the provider issues for one registration.

use std::fmt;

use crate::error::{Error, ErrorKind};

use super::DYNAMIC_CLIENT;

const MAX_LEN: usize = 256;

/// The client ID issued for one registration of the app.
///
/// A first sign-in registers the app for one user and workspace and returns
/// this ID on the callback. Store it before the code exchange and keep it
/// across sign-outs: every later sign-in for that account sends it, which is
/// what keeps the app a single entry under one name in the user's ChatGPT
/// settings. It is an identifier, not a secret.
///
/// ```
/// use siwc::protocol::IssuedClientId;
///
/// let id = IssuedClientId::parse("app_Ex4mpl3")?;
/// assert_eq!(id.as_str(), "app_Ex4mpl3");
///
/// // The registration entry point is never a registration.
/// assert!(IssuedClientId::parse("dynamic_agent_client").is_err());
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IssuedClientId(String);

impl IssuedClientId {
    /// Reads a client ID from the callback or from storage.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when the text is empty, longer than 256
    /// bytes, contains anything but visible ASCII, or is the registration
    /// entry point `dynamic_agent_client`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let well_formed = !text.is_empty()
            && text.len() <= MAX_LEN
            && text.bytes().all(|byte| byte.is_ascii_graphic())
            && text != DYNAMIC_CLIENT;
        if well_formed {
            Ok(Self(text.to_owned()))
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "the text is not an issued client ID",
            ))
        }
    }

    /// The ID as text, for storing.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IssuedClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for IssuedClientId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for IssuedClientId {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_formats_and_rejects_reserved_or_non_graphic_ids() {
        let id: IssuedClientId = "app_Ex4mpl3".parse().unwrap();
        let slice: &str = id.as_ref();
        assert_eq!(slice, "app_Ex4mpl3");
        assert_eq!(id.to_string(), "app_Ex4mpl3");
        assert!(IssuedClientId::parse("").is_err());
        assert!(IssuedClientId::parse("dynamic_agent_client").is_err());
        assert!(IssuedClientId::parse("app with space").is_err());
        assert!(IssuedClientId::parse(&"a".repeat(MAX_LEN + 1)).is_err());
    }
}
