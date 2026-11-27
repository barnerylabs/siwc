//! The scopes the provider granted.

use std::fmt;

use super::PLAN_USE_SCOPE;

const MAX_SCOPES: usize = 64;
const MAX_SCOPE_LEN: usize = 128;

/// The scopes granted with a token set, read from the token response.
///
/// `Display` writes the space-separated scope list. Use [`Self::contains`]
/// or [`Self::iter`] to inspect individual grants.
/// The request always asks for the full set; what counts is what came back.
/// Signing in and being allowed to use the ChatGPT plan are separate grants.
///
/// ```
/// # fn show(credentials: &siwc::protocol::Credentials) {
/// if !credentials.scopes().grants_plan_use() {
///     println!("Signed in. ChatGPT plan use is not enabled.");
/// }
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scopes(Vec<String>);

impl Scopes {
    /// Reads a space-separated scope string. Tokens the grammar of RFC 6749
    /// does not allow are dropped rather than trusted.
    pub(crate) fn parse(text: &str) -> Self {
        let mut scopes: Vec<String> = Vec::new();
        for scope in text.split_ascii_whitespace() {
            let well_formed = scope.len() <= MAX_SCOPE_LEN
                && scope
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\');
            if well_formed && scopes.len() < MAX_SCOPES && !scopes.iter().any(|s| s == scope) {
                scopes.push(scope.to_owned());
            }
        }
        Self(scopes)
    }

    /// Whether `scope` was granted.
    #[must_use]
    pub fn contains(&self, scope: &str) -> bool {
        self.0.iter().any(|granted| granted == scope)
    }

    /// Whether the user allowed the app to use their ChatGPT plan.
    ///
    /// Without it the user is signed in with plan use off: show that state
    /// and do not send API requests on this path.
    #[must_use]
    pub fn grants_plan_use(&self) -> bool {
        self.contains(PLAN_USE_SCOPE)
    }

    /// Number of granted scopes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no scopes were granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The granted scopes in the order the provider listed them.
    pub fn iter(&self) -> ScopeIter<'_> {
        ScopeIter(self.0.iter())
    }
}

/// Borrowed scope names in grant order.
///
/// ```
/// use siwc::protocol::{ScopeIter, Scopes};
///
/// let grants = Scopes::default();
/// let mut names: ScopeIter<'_> = grants.iter();
/// assert_eq!(names.len(), 0);
/// assert_eq!(names.next_back(), None);
/// ```
#[must_use = "iterators are lazy and do nothing unless consumed"]
#[derive(Debug, Clone)]
pub struct ScopeIter<'a>(std::slice::Iter<'a, String>);

impl<'a> Iterator for ScopeIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(String::as_str)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl DoubleEndedIterator for ScopeIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(String::as_str)
    }
}
impl ExactSizeIterator for ScopeIter<'_> {}
impl std::iter::FusedIterator for ScopeIter<'_> {}

impl<'a> IntoIterator for &'a Scopes {
    type Item = &'a str;
    type IntoIter = ScopeIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Display for Scopes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_split_deduplicated_and_kept_in_order() {
        let empty = Scopes::parse("   ");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let scopes = Scopes::parse("openid  email openid\tchatgpt.tokens.use.direct");
        assert!(!scopes.is_empty());
        assert_eq!(scopes.len(), 3);
        let collected: Vec<&str> = (&scopes).into_iter().collect();
        assert_eq!(collected, ["openid", "email", "chatgpt.tokens.use.direct"]);
        let mut names: ScopeIter<'_> = scopes.iter();
        assert_eq!(names.next_back(), Some("chatgpt.tokens.use.direct"));
        assert_eq!(names.len(), 2);
        assert_eq!(scopes.to_string(), "openid email chatgpt.tokens.use.direct");
        assert!(scopes.grants_plan_use());
    }

    #[test]
    fn identity_scopes_alone_do_not_grant_plan_use() {
        let scopes = Scopes::parse("openid profile email offline_access resource.invoke");
        assert!(scopes.contains("offline_access"));
        assert!(!scopes.grants_plan_use());
    }

    #[test]
    fn malformed_scopes_are_dropped() {
        let long = "x".repeat(MAX_SCOPE_LEN + 1);
        let scopes = Scopes::parse(&format!("openid sc\"ope b\\s caf\u{e9} {long}"));
        assert_eq!(scopes.to_string(), "openid");
    }
}
