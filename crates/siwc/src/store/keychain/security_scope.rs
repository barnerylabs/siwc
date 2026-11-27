//! What the answers of macOS `/usr/bin/security` prove: which keychain is
//! the default one, and when a key is missing rather than locked away or
//! kept in another keychain.

use crate::error::{Error, ErrorKind};

use super::tool_failed;

/// What `security` exits with when no item matches (`errSecItemNotFound`).
/// A locked keychain gives another code: 36 without a user interface, 128
/// after its unlock dialog was dismissed.
const NOT_FOUND: i32 = 44;

/// The path that `security default-keychain -d user` prints: one quoted
/// absolute path on a line of its own.
pub(super) fn default_keychain(output: &[u8]) -> Result<&str, Error> {
    let line = std::str::from_utf8(output)
        .map_err(|_| tool_failed())?
        .trim();
    let path = line
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(tool_failed)?;
    if path.starts_with('/') && !path.contains(['"', '\n', '\0']) {
        Ok(path)
    } else {
        Err(tool_failed())
    }
}

/// `path` as one word of a `security -i` command line, which takes no
/// quoting this crate relies on.
pub(super) fn one_word(path: &str) -> Result<&str, Error> {
    if path.contains(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '\\')) {
        Err(Error::new(
            ErrorKind::Store,
            "the default keychain path cannot be passed to the keychain tool",
        ))
    } else {
        Ok(path)
    }
}

/// Whether the key exists, from the exit code of `find-generic-password`
/// in the default keychain. When that finds no item, `search_list` runs the
/// same lookup across the user's keychain search list: the key is missing
/// only if that finds no item either.
pub(super) fn found(
    in_default: Option<i32>,
    search_list: impl FnOnce() -> Result<Option<i32>, Error>,
) -> Result<bool, Error> {
    match in_default {
        Some(0) => Ok(true),
        Some(NOT_FOUND) => match search_list()? {
            Some(NOT_FOUND) => Ok(false),
            Some(0) => Err(Error::new(
                ErrorKind::Store,
                "the sealing key is in a keychain other than the default one",
            )),
            _ => Err(tool_failed()),
        },
        _ => Err(tool_failed()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands for a search list that must not be asked: its answer is a
    /// kind `found` never returns on its own.
    fn never() -> Result<Option<i32>, Error> {
        Err(Error::new(
            ErrorKind::InvalidInput,
            "the search list was asked",
        ))
    }

    #[test]
    fn a_key_in_the_default_keychain_is_found_without_asking_the_search_list() {
        assert!(found(Some(0), never).unwrap());
    }

    #[test]
    fn a_key_is_missing_only_when_neither_the_default_keychain_nor_the_search_list_has_it() {
        assert!(!found(Some(NOT_FOUND), || Ok(Some(NOT_FOUND))).unwrap());
    }

    #[test]
    fn a_key_only_the_search_list_finds_is_an_error_not_a_missing_key() {
        let error = found(Some(NOT_FOUND), || Ok(Some(0))).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Store);
        assert_eq!(
            error.to_string(),
            "the sealing key is in a keychain other than the default one"
        );
    }

    #[test]
    fn a_locked_or_dismissed_keychain_is_an_error_at_either_step() {
        for locked in [Some(36), Some(128), None] {
            assert_eq!(found(locked, never).unwrap_err().kind(), ErrorKind::Store);
            let error = found(Some(NOT_FOUND), || Ok(locked)).unwrap_err();
            assert_eq!(error.to_string(), "the keychain could not be used");
        }
    }

    #[test]
    fn the_default_keychain_is_the_quoted_absolute_path() {
        let output = b"    \"/Users/alex/Library/Keychains/login.keychain-db\"\n";
        assert_eq!(
            default_keychain(output).unwrap(),
            "/Users/alex/Library/Keychains/login.keychain-db"
        );
        for other in [
            &b""[..],
            b"/Users/alex/login.keychain-db\n",
            b"\"login.keychain-db\"\n",
            b"\"/a\"\n\"/b\"\n",
            b"\"/Users/\xff/login.keychain-db\"\n",
        ] {
            assert!(default_keychain(other).is_err());
        }
    }

    #[test]
    fn a_path_that_is_not_one_word_is_never_put_on_an_interactive_line() {
        assert_eq!(
            one_word("/Users/alex/k.keychain-db").unwrap(),
            "/Users/alex/k.keychain-db"
        );
        for path in [
            "/Users/a b/k",
            "/Users/a\"b/k",
            "/Users/a'b/k",
            "/Users/a\\b/k",
        ] {
            assert_eq!(one_word(path).unwrap_err().kind(), ErrorKind::Store);
        }
    }
}
