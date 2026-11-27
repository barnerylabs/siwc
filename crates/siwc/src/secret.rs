//! Secret values: wiped when dropped, never printed, never serialised.
//!
//! None of these types implements `Display` or `Serialize`, so a secret
//! cannot reach a log line or a config file by formatting it. `Debug` prints
//! a fixed placeholder.

use std::fmt;

use zeroize::Zeroizing;

/// Secret text.
#[derive(Clone)]
pub(crate) struct SecretString(Zeroizing<String>);

impl SecretString {
    pub(crate) fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Secret bytes, such as a request body that carries a token.
pub(crate) struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted; {} bytes]", self.0.len())
    }
}

/// The bearer token for the OpenAI API, valid for about an hour.
///
/// This is the one secret an app handles itself: it goes into the
/// `Authorization` header of the app's API requests and nowhere else.
///
/// ```
/// # fn send(token: &siwc::AccessToken) -> String {
/// format!("Bearer {}", token.expose())
/// # }
/// ```
#[derive(Clone)]
pub struct AccessToken(SecretString);

impl AccessToken {
    pub(crate) fn new(text: String) -> Self {
        Self(SecretString::new(text))
    }

    /// The token text, for the `Authorization: Bearer` header.
    ///
    /// Do not log it, store it or pass it to another process on a command
    /// line or in the environment.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken([redacted])")
    }
}

/// Declares a crate-internal secret with its own type.
macro_rules! internal_secret {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub(crate) struct $name(SecretString);

        impl $name {
            pub(crate) fn new(text: String) -> Self {
                Self(SecretString::new(text))
            }

            pub(crate) fn expose(&self) -> &str {
                self.0.expose()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

internal_secret!(
    /// The rotating token that renews the session for 30 days.
    RefreshToken
);
internal_secret!(
    /// The signed ID token, kept as an account hint for later sign-ins.
    IdToken
);
internal_secret!(
    /// The one-use code from the browser callback.
    AuthorizationCode
);
internal_secret!(
    /// The PKCE verifier that binds the code exchange to this attempt.
    PkceVerifier
);
