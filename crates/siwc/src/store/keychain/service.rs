//! The name a keychain item goes by.

use crate::error::{Error, ErrorKind};

/// The longest service name.
pub(super) const MAX_LEN: usize = 128;

/// A keychain item's service: 1 to 128 ASCII letters, digits, `.`, `_` and
/// `-`, starting with a letter or digit.
///
/// The rule keeps the name one word on the command line of `security -i`,
/// which splits at spaces and quotes, and keeps it from reading as an
/// option to any of the tools.
#[derive(Debug, Clone, Eq)]
pub(crate) struct ServiceName(String);

impl PartialEq for ServiceName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl ServiceName {
    pub(crate) fn new(name: &str) -> Result<Self, Error> {
        let starts_well = name
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric());
        let allowed = name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if starts_well && allowed && name.len() <= MAX_LEN {
            Ok(Self(name.to_owned()))
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "the keychain service is not 1 to 128 characters of A-Z, a-z, 0-9, '.', '_' and '-' starting with a letter or digit",
            ))
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// The Credential Manager target, `sealing-key.<service>`. It is spelled
    /// out here rather than left to the backend's default naming, so every
    /// build finds the key an earlier one stored.
    #[cfg(any(windows, test))]
    pub(super) fn credential_target(&self) -> String {
        format!("{}.{}", super::ACCOUNT, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_identifier_is_a_service_name() {
        let name = ServiceName::new("com.example.Paste_Perfect-2").unwrap();
        assert_eq!(name.as_str(), "com.example.Paste_Perfect-2");
        assert!(ServiceName::new(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn the_windows_credential_target_is_the_account_and_the_service() {
        let name = ServiceName::new("com.example.desktop").unwrap();
        assert_eq!(name.credential_target(), "sealing-key.com.example.desktop");
    }

    #[test]
    fn a_name_outside_the_rule_is_refused() {
        for name in [
            "",
            "-s",
            ".hidden",
            "two words",
            "quote\"d",
            "new\nline",
            "ümlaut",
            &"a".repeat(129),
        ] {
            let error = ServiceName::new(name).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{name:?}");
        }
    }
}
