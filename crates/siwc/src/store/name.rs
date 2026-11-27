//! The names entries go by.

use crate::error::{Error, ErrorKind};

/// The longest entry name.
const MAX_LEN: usize = 64;

/// The name of an entry: 1 to 64 characters of `a-z`, `0-9` and `-`, not
/// starting or ending with `-`, and none of the device names Windows
/// reserves (`con`, `nul`, `com1` and the like).
///
/// The rule keeps a name usable as a file name on every platform and leaves
/// no way to name a path, a hidden file or a lock file.
///
/// ```
/// use siwc::store::EntryName;
///
/// assert_eq!(EntryName::new("account-1")?.as_str(), "account-1");
/// assert!(EntryName::new("../account").is_err());
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntryName(String);

impl EntryName {
    /// Checks `name` against the rule.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when the name breaks the rule.
    pub fn new(name: &str) -> Result<Self, Error> {
        if is_valid(name) {
            Ok(Self(name.to_owned()))
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "the entry name is not 1 to 64 characters of a-z, 0-9 and inner hyphens, or is a reserved device name",
            ))
        }
    }

    pub(super) fn is_client_entry(&self) -> bool {
        self.0 == "installation" || self.0.starts_with("account-")
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EntryName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for EntryName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for EntryName {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

/// Whether `name` follows the rule of [`EntryName`].
pub(super) fn is_valid(name: &str) -> bool {
    (1..=MAX_LEN).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !is_device(name)
}

/// Whether Windows treats `name` as a device whatever directory it is in.
pub(super) fn is_device(name: &str) -> bool {
    let numbered = |prefix: &str| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| rest.len() == 1 && rest.bytes().all(|b| b.is_ascii_digit()))
    };
    matches!(name, "con" | "prn" | "aux" | "nul") || numbered("com") || numbered("lpt")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_names_parse_display_and_refuse_devices_or_outer_hyphens() {
        let entry: EntryName = "account-01".parse().unwrap();
        let slice: &str = entry.as_ref();
        assert_eq!(slice, "account-01");
        assert_eq!(entry.to_string(), "account-01");

        for bad in ["", "-leading", "trailing-", "Upper", "con", "com1", "lpt9"] {
            assert!(bad.parse::<EntryName>().is_err(), "{bad}");
        }
    }
}
