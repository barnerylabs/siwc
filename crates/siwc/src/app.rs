//! The app's own name, as its users see it when they sign in.

mod reserved;

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, ErrorKind};

/// Longest accepted name, in characters. The provider documents no limit;
/// this one keeps the name readable on a consent screen.
const MAX_CHARS: usize = 64;

/// The name the app registers under and the user sees in the browser.
///
/// A first sign-in sends it as the registration's name hint; the user reads
/// it on the consent screen, can edit it there, and later finds the app under
/// it in their ChatGPT settings. Use the product name from the app's own
/// window title or `--help` output, and use the same one everywhere.
///
/// There is no default and no way to sign in without one, so an app cannot
/// end up registered under a placeholder.
///
/// ```
/// let name = siwc::AppName::new("Paste Perfect")?;
/// assert_eq!(name.as_str(), "Paste Perfect");
///
/// // Not the app's own name:
/// assert!(siwc::AppName::new("ChatGPT").is_err());
/// assert!(siwc::AppName::new("  ").is_err());
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AppName(String);

impl AppName {
    /// Checks and keeps the app's name; surrounding whitespace is dropped.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when the name is empty, longer than 64
    /// characters, contains control, invisible or text-direction characters,
    /// or is a name of the provider or of this library, however it is
    /// spaced, cased or punctuated. A fold for the reserved words covers
    /// full-width ASCII, mathematical and enclosed letters, small and
    /// modifier capitals, selected Cyrillic, Greek, Cherokee and Lisu
    /// look-alikes, and strips combining marks in U+0300–U+036F,
    /// U+1AB0–U+1AFF, U+1DC0–U+1DFF, U+20D0–U+20FF, U+2DE0–U+2DFF and U+FE20–U+FE2F,
    /// Hangul fillers and selected zero-width format characters. After folding,
    /// a non-ASCII letter can stand in for one letter of a reserved name,
    /// or two if the name has at least seven letters. The other positions
    /// must match exactly in ASCII. A name is also reserved if dropping
    /// every remaining non-ASCII character leaves a whole reserved word.
    /// The zero-width joiner and non-joiner
    /// (`U+200D`, `U+200C`) are allowed, since scripts and emoji need them.
    pub fn new(name: &str) -> Result<Self, Error> {
        let name = checked_name(name)?;
        if reserved::new_name(name) {
            return Err(invalid(
                "the app name is a name of the provider or of this library",
            ));
        }
        Ok(Self(name.to_owned()))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stored names describe registrations that already exist. Keep accepting
/// names written before the additional look-alike check was introduced.
pub(crate) fn is_stored_name(name: &str) -> bool {
    checked_name(name).is_ok_and(|trimmed| trimmed == name && !reserved::stored_name(name))
}

fn checked_name(name: &str) -> Result<&str, Error> {
    let name = name.trim();
    if name.is_empty() {
        return Err(invalid("the app name is empty"));
    }
    if name.chars().count() > MAX_CHARS {
        return Err(invalid("the app name is longer than 64 characters"));
    }
    if has_disallowed_chars(name) {
        return Err(invalid(
            "the app name contains a control, invisible or text-direction character",
        ));
    }
    Ok(name)
}

impl fmt::Display for AppName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for AppName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for AppName {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

/// Whether `text` contains a control, invisible or text-direction character
/// that could spoof or break how a display string is rendered. The
/// zero-width joiner and non-joiner are allowed; see `is_invisible`.
pub(crate) fn has_disallowed_chars(text: &str) -> bool {
    text.chars()
        .any(|c| c.is_control() || is_invisible(c) || changes_text_direction(c))
}

/// Bidirectional marks, embeddings, overrides and isolates: they can make a
/// name read differently from what it is.
fn changes_text_direction(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Characters that take no space and join nothing: soft hyphen, zero-width
/// space, word joiner, byte order mark, and the line and paragraph
/// separators. The zero-width joiners stay allowed; scripts and emoji need
/// them.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}' | '\u{200B}' | '\u{2028}' | '\u{2029}' | '\u{2060}' | '\u{FEFF}'
    )
}

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surrounding_whitespace_is_dropped() {
        assert_eq!(
            AppName::new("  Paste Perfect\n").unwrap().as_str(),
            "Paste Perfect"
        );
    }

    #[test]
    fn a_name_of_64_characters_fits_and_65_do_not() {
        assert!(AppName::new(&"ä".repeat(64)).is_ok());
        assert!(AppName::new(&"ä".repeat(65)).is_err());
    }

    #[test]
    fn control_invisible_and_direction_characters_are_refused() {
        for name in [
            "Paste\tPerfect",
            "Paste\nPerfect",
            "Paste\u{202E}tcefreP",
            "\u{2066}Paste",
            "Paste\u{200F}Perfect",
            "Paste\u{200B}Perfect",
            "Paste\u{FEFF}Perfect",
        ] {
            assert!(AppName::new(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn provider_and_library_names_are_refused_in_any_case() {
        for name in reserved::NAMES {
            assert!(AppName::new(name).is_err(), "{name}");
            assert!(AppName::new(&name.to_uppercase()).is_err(), "{name}");
        }
        // Only the whole name is reserved; one that contains it is the app's own.
        assert!(AppName::new("SIWC Helper").is_ok());
    }

    #[test]
    fn spacing_and_punctuation_do_not_hide_a_reserved_name() {
        for name in [
            "Chat GPT",
            "chat-gpt",
            "Open AI",
            "Chat\u{200D}GPT",
            "S.I.W.C.",
        ] {
            assert!(AppName::new(name).is_err(), "{name:?}");
        }
        // A joiner inside a name of the app's own is fine.
        assert!(AppName::new("می\u{200C}خواهم").is_ok());
    }

    #[test]
    fn fullwidth_and_lookalike_letters_do_not_hide_a_reserved_name() {
        for name in [
            "ＣｈａｔＧＰＴ",
            "ChatGРТ",
            "ОpenАI",
            "ΟΡΕΝΑΙ",
            "Сοdех",
            "Ｓ.І.Ԝ.Ϲ.",
        ] {
            assert_eq!(
                AppName::new(name).unwrap_err().kind(),
                ErrorKind::InvalidInput,
                "{name}"
            );
        }
        for name in ["Ουρανός", "Заметки", "Ｃｈａｔ Ｎｏｔｅｓ"] {
            assert_eq!(AppName::new(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn mathematical_letters_do_not_hide_a_reserved_name() {
        for name in ["𝐂𝐡𝐚𝐭𝐆𝐏𝐓", "𝖮𝗉𝖾𝗇𝖠𝖨", "ℂ𝕠𝕕𝕖𝕩", "𝙎𝙄𝙒𝘾", "𝚶𝚸𝚬𝚴𝚨𝚰"]
        {
            assert_eq!(
                AppName::new(name).unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn enclosed_letters_do_not_hide_a_reserved_name() {
        for name in ["ⓒⓞⓓⓔⓧ", "ⒸⓗⓐⓣⒼⓅⓉ", "⒪⒫⒠⒩⒜⒤", "🄢🄘🄦🄒"]
        {
            assert_eq!(
                AppName::new(name).unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn small_capitals_and_cherokee_do_not_hide_a_reserved_name() {
        for name in [
            "ᴏᴘᴇɴᴀɪ",
            "ꜱɪᴡᴄ",
            "ᏟᎻᎪᎢᏀᏢᎢ",
            "ᏟᎻᎪᎢᏀᏢᎢ".to_lowercase().as_str(),
        ] {
            assert_eq!(
                AppName::new(name).unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
        }
        for name in ["ᴏᴘᴇɴ Notes", "ᏣᎳᎩ", "ⓒⓞⓓⓔ Notes", "𝐂𝐡𝐚𝐭 𝐍𝐨𝐭𝐞𝐬"]
        {
            assert_eq!(AppName::new(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn combining_marks_and_dotted_i_do_not_hide_a_reserved_name() {
        for name in ["SİWC", "C\u{0345}odex", "C\u{0301}hatGPT"] {
            assert_eq!(
                AppName::new(name).unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
        }
        assert!(is_stored_name("SİWC"));
        assert!(is_stored_name("𝐂𝐡𝐚𝐭𝐆𝐏𝐓"));
    }
}
