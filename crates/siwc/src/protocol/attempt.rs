//! One sign-in attempt, from the authorization URL to the accepted callback.

use std::fmt;

use ring::{digest, hmac};
use zeroize::Zeroizing;

use crate::app::AppName;
use crate::entropy::{Entropy, OsEntropy};
use crate::error::{Error, ErrorKind};
use crate::host::HostId;
use crate::secret::{AuthorizationCode, PkceVerifier, SecretString};

use super::client_id::IssuedClientId;
use super::credentials::Credentials;
use super::exchange::Exchange;
use super::identity::Identity;
use super::{
    AUTHORIZE_URL, CALLBACK_PATH, DYNAMIC_CLIENT, ISSUER, REQUESTED_SCOPE, RESOURCE, base64url,
    form, provider_error,
};

/// Longest authorization code accepted from a callback, in bytes.
const MAX_CODE_LEN: usize = 4096;

/// Longest text accepted as a pasted redirect, surrounding whitespace
/// removed, in bytes.
const MAX_REDIRECT_LEN: usize = 8 * 1024;

/// Which registration a sign-in uses.
///
/// The provider may add kinds of registration, so a `match` outside this
/// crate needs a wildcard arm.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Registration<'a> {
    /// The first sign-in for an account: the provider registers the app
    /// under this name, which the user sees and can edit in the browser.
    New(&'a AppName),
    /// A later sign-in with the client ID issued the first time. The name is
    /// not sent again; the registration keeps the one it has.
    Saved(Returning<'a>),
}

/// A sign-in with a saved registration.
///
/// A registration belongs to one account. Which constructor fits depends on
/// what is stored for that account. None sends a hint unless the caller
/// opts in with [`with_hints`](Self::with_hints).
///
/// ```
/// # use siwc::protocol::{Credentials, Identity, IssuedClientId, Returning};
/// # fn build(client_id: &IssuedClientId, identity: &Identity, credentials: &Credentials) {
/// // Tokens are stored for a known account.
/// let returning = Returning::signed_in(identity, credentials);
/// // The account signed out: its tokens are gone, its identity is known.
/// let returning = Returning::signed_out(client_id, identity);
/// // The first sign-in never completed: only the client ID is stored.
/// let returning = Returning::unfinished(client_id);
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Returning<'a> {
    client_id: &'a IssuedClientId,
    account: Option<&'a Identity>,
    credentials: Option<&'a Credentials>,
    consent: bool,
    hints: bool,
}

impl<'a> Returning<'a> {
    /// Completes a registration whose first sign-in did not finish: the
    /// issued client ID is stored, but no account has signed in with it.
    /// The account that completes this sign-in becomes the registration's
    /// account.
    #[must_use]
    pub fn unfinished(client_id: &'a IssuedClientId) -> Self {
        Self {
            client_id,
            account: None,
            credentials: None,
            consent: false,
            hints: false,
        }
    }

    /// Signs in again to an account whose tokens are gone, for example after
    /// a sign-out. A sign-in that ends in any other account is rejected.
    #[must_use]
    pub fn signed_out(client_id: &'a IssuedClientId, identity: &'a Identity) -> Self {
        Self {
            client_id,
            account: Some(identity),
            credentials: None,
            consent: false,
            hints: false,
        }
    }

    /// Signs in again to an account whose credentials are stored.
    /// A sign-in that ends in any other account is rejected.
    ///
    /// `identity` and `credentials` have to belong to the same account:
    /// [`Attempt::start`] refuses a pair that does not.
    #[must_use]
    pub fn signed_in(identity: &'a Identity, credentials: &'a Credentials) -> Self {
        Self {
            client_id: credentials.client_id(),
            account: Some(identity),
            credentials: Some(credentials),
            consent: false,
            hints: false,
        }
    }

    /// Asks the provider to show the consent screen again. Use it only when
    /// the user asked to enable ChatGPT plan use, never on a routine sign-in.
    #[must_use]
    pub fn ask_consent(mut self) -> Self {
        self.consent = true;
        self
    }

    /// Sends the retained ID token and e-mail address as hints when they
    /// are available, so the provider can select the account. They become
    /// part of the authorization URL. Keep that URL out of logs and command
    /// lines, and do not put it behind a start link anyone else can open.
    /// The browser keeps the URL in its history, which some browsers sync to
    /// their vendor. The ID token hint names the account (subject, and name
    /// and e-mail address when the token holds them) but grants nothing: it
    /// cannot be exchanged for tokens or used against the API, and the
    /// provider reads it only to select the account, even once it expired.
    #[must_use]
    pub fn with_hints(mut self) -> Self {
        self.hints = true;
        self
    }

    /// Sends neither the retained ID token nor the e-mail address, the
    /// default for all constructors. Use it
    /// when the authorization URL is shown to the user to open elsewhere,
    /// as for a sign-in completed with [`Attempt::accept_redirect`]: the
    /// URL then carries no token and no personal data. The provider shows
    /// its account chooser, and a sign-in completed with a different account
    /// is still rejected.
    ///
    /// ```
    /// # use siwc::protocol::{Attempt, Credentials, Identity, Registration, Returning};
    /// # fn build(identity: &Identity, credentials: &Credentials, host: &siwc::HostId) -> Result<(), siwc::Error> {
    /// let returning = Returning::signed_in(identity, credentials).without_hints();
    /// let attempt = Attempt::start(Registration::Saved(returning), Some(host), 53124, &siwc::OsEntropy)?;
    /// assert!(!attempt.authorization_url().contains("login_hint"));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn without_hints(mut self) -> Self {
        self.hints = false;
        self
    }
}

/// One sign-in attempt: fresh `state`, `nonce` and PKCE verifier, bound to
/// one redirect URI, usable for one callback.
///
/// Bind the loopback listener first and pass its real port; then show or open
/// [`authorization_url`](Self::authorization_url).
///
/// ```
/// use siwc::protocol::{Attempt, Registration};
///
/// let app = siwc::AppName::new("Paste Perfect")?;
/// let host = siwc::HostId::generate(&siwc::OsEntropy)?;
/// let attempt = Attempt::start(Registration::New(&app), Some(&host), 53124, &siwc::OsEntropy)?;
///
/// assert!(attempt.authorization_url().contains("agent_name_hint=Paste%20Perfect"));
/// assert_eq!(attempt.redirect_uri(), "http://127.0.0.1:53124/auth/callback");
/// # Ok::<(), siwc::Error>(())
/// ```
#[must_use = "accept the callback or redirect with `Attempt::accept` or `Attempt::accept_redirect`"]
pub struct Attempt {
    url: SecretString,
    redirect_uri: String,
    // Boxed: the key is most of this value, which moves through `accept`.
    state_key: Box<hmac::Key>,
    state_tag: hmac::Tag,
    nonce: SecretString,
    verifier: PkceVerifier,
    client: PendingClient,
    account: Option<String>,
}

enum PendingClient {
    /// A first registration; the callback has to bring the issued ID.
    New,
    /// A saved registration; the callback must not name another one.
    Saved(IssuedClientId),
}

impl Attempt {
    /// Starts an attempt whose callback arrives at
    /// `http://127.0.0.1:<port>/auth/callback`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] for port 0 and for a
    /// [`Returning::signed_in`] whose identity and credentials belong to
    /// different accounts; [`ErrorKind::Randomness`] when `entropy` fails.
    pub fn start(
        registration: Registration<'_>,
        host: Option<&HostId>,
        port: u16,
        entropy: &OsEntropy,
    ) -> Result<Self, Error> {
        Self::start_inner(registration, host, port, entropy)
    }

    /// Starts an attempt with a test entropy source.
    ///
    /// ```
    /// # fn example(source: &dyn siwc::Entropy) -> Result<(), siwc::Error> {
    /// let app = siwc::AppName::new("Example")?;
    /// let attempt = siwc::protocol::Attempt::start_with_entropy(
    ///     siwc::protocol::Registration::New(&app), None, 53124, source,
    /// )?;
    /// assert!(attempt.redirect_uri().contains(":53124/"));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The same errors as [`Self::start`].
    #[cfg(feature = "testing")]
    #[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
    pub fn start_with_entropy(
        registration: Registration<'_>,
        host: Option<&HostId>,
        port: u16,
        entropy: &dyn Entropy,
    ) -> Result<Self, Error> {
        Self::start_inner(registration, host, port, entropy)
    }

    pub(crate) fn start_inner(
        registration: Registration<'_>,
        host: Option<&HostId>,
        port: u16,
        entropy: &dyn Entropy,
    ) -> Result<Self, Error> {
        if port == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "the callback port is zero",
            ));
        }
        if let Registration::Saved(returning) = registration {
            let subject = returning.account.map(Identity::subject);
            if returning
                .credentials
                .is_some_and(|credentials| Some(credentials.subject()) != subject)
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "the identity and the credentials belong to different accounts",
                ));
            }
        }
        let state = random_text(entropy)?;
        let nonce = random_text(entropy)?;
        let verifier = random_text(entropy)?;
        let mut key = Zeroizing::new([0u8; 32]);
        entropy.fill(key.as_mut_slice())?;
        let state_key = Box::new(hmac::Key::new(hmac::HMAC_SHA256, key.as_slice()));
        let state_tag = hmac::sign(&state_key, state.as_bytes());
        let challenge =
            base64url::encode(digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref());
        let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");

        let mut fields: Vec<(&str, &str)> = Vec::with_capacity(14);
        let (client, account) = match registration {
            Registration::New(app) => {
                fields.push(("client_id", DYNAMIC_CLIENT));
                fields.push(("agent_name_hint", app.as_str()));
                (PendingClient::New, None)
            }
            Registration::Saved(returning) => {
                fields.push(("client_id", returning.client_id.as_str()));
                (
                    PendingClient::Saved(returning.client_id.clone()),
                    returning.account,
                )
            }
        };
        if let Some(host) = host {
            fields.push(("ext_agent_host_id", host.as_str()));
        }
        fields.extend([
            ("response_type", "code"),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", REQUESTED_SCOPE),
            ("resource", RESOURCE),
            ("state", state.as_str()),
            ("nonce", nonce.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ]);
        if let Registration::Saved(returning) = registration {
            let hinted = returning.hints.then_some(returning);
            if let Some(id_token) = hinted
                .and_then(|returning| returning.credentials)
                .and_then(Credentials::id_token)
            {
                fields.push(("id_token_hint", id_token.expose()));
            }
            if let Some(email) = hinted
                .and_then(|returning| returning.account)
                .and_then(Identity::email)
            {
                fields.push(("login_hint", email));
            }
            if returning.consent {
                fields.push(("prompt", "consent"));
            }
        }
        let query = Zeroizing::new(form::encode(&fields));
        let mut url = String::with_capacity(AUTHORIZE_URL.len() + 1 + query.len());
        url.push_str(AUTHORIZE_URL);
        url.push('?');
        url.push_str(&query);

        Ok(Self {
            url: SecretString::new(url),
            redirect_uri,
            state_key,
            state_tag,
            nonce: SecretString::new((*nonce).clone()),
            verifier: PkceVerifier::new((*verifier).clone()),
            client,
            account: account.map(|identity| identity.subject().to_owned()),
        })
    }

    /// The URL for the user's browser.
    ///
    /// Show it or open it, and nothing else: it holds this attempt's `state`
    /// and, if explicitly enabled with [`Returning::with_hints`], the
    /// account's ID token or e-mail address. Keep it out of logs, crash
    /// reports and analytics.
    #[must_use]
    pub fn authorization_url(&self) -> &str {
        self.url.expose()
    }

    /// The redirect URI of this attempt.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Offers the query of a request to the callback path to this attempt.
    ///
    /// A malformed query or one without this attempt's `state` exactly once is
    /// [`Callback::Unrelated`]: the attempt comes back unchanged, so other
    /// local programs and web pages cannot use it up. The `state` is checked
    /// through an HMAC under a key of this attempt, whose fixed-length tag is
    /// compared in constant time; computing the HMAC takes longer for a
    /// longer `state`.
    ///
    /// Any other query ends the attempt as [`Callback::Final`]. On success
    /// the result holds the [`Exchange`] for the authorization code; a first
    /// registration wraps it in a [`NewRegistration`], whose issued client ID
    /// has to be stored before the exchange. The errors are:
    ///
    /// - [`ErrorKind::AccessDenied`]: the user declined; nothing to exchange.
    /// - [`ErrorKind::ClientRejected`]: the provider refused the app's
    ///   registration (`unauthorized_client` or `invalid_client`, kept as
    ///   [`Error::provider_code`]). The callback is not an authenticated
    ///   answer: it does not confirm that a stored registration has been
    ///   revoked, and the error has no [`Error::http_status`]. Only the token
    ///   endpoint's answer to the exchange or a renewal confirms it.
    /// - [`ErrorKind::AuthorizationFailed`]: the provider reported another
    ///   error, available as [`Error::provider_code`].
    /// - [`ErrorKind::CallbackRejected`]: the query repeats a parameter,
    ///   has both code and error, lacks a valid code or required issued client
    ///   ID, or names a different client or issuer.
    pub fn accept(self, query: &str) -> Callback {
        let Some(pairs) = form::parse(query) else {
            return Callback::Unrelated(self);
        };
        let mut states = pairs
            .iter()
            .filter(|(name, _)| name.as_str() == "state")
            .map(|(_, state)| state.as_str());
        match (states.next(), states.next()) {
            (Some(state), None) if self.owns(state) => Callback::Final(self.finish(&pairs)),
            _ => Callback::Unrelated(self),
        }
    }

    /// Offers text the user pasted to this attempt: the address the browser
    /// was sent to, copied from its address bar, for an app that runs on
    /// another machine than the browser, where the redirect cannot reach a
    /// listener.
    ///
    /// Surrounding whitespace is ignored and a `#fragment` is dropped. Text
    /// longer than 8 KiB, text with a character no URL holds, and text that
    /// does not start with exactly this attempt's
    /// [`redirect_uri`](Self::redirect_uri) followed by `?` (allowing a
    /// browser to omit the default HTTP port 80) are
    /// [`Callback::Unrelated`], as is a query without this attempt's
    /// `state`: the attempt comes back unchanged and the user can paste
    /// again. The query of the attempt's own redirect is judged as
    /// [`accept`](Self::accept) judges a callback.
    ///
    /// ```
    /// use siwc::protocol::{Attempt, Callback, Registration};
    ///
    /// let app = siwc::AppName::new("Paste Perfect")?;
    /// let host = siwc::HostId::generate(&siwc::OsEntropy)?;
    /// let attempt = Attempt::start(Registration::New(&app), Some(&host), 53124, &siwc::OsEntropy)?;
    ///
    /// let pasted = "http://127.0.0.1:53124/auth/callback?code=abc&state=forged";
    /// assert!(matches!(attempt.accept_redirect(pasted), Callback::Unrelated(_)));
    /// # Ok::<(), siwc::Error>(())
    /// ```
    pub fn accept_redirect(self, pasted: &str) -> Callback {
        let text = pasted.trim();
        if text.len() > MAX_REDIRECT_LEN || !text.bytes().all(is_url_byte) {
            return Callback::Unrelated(self);
        }
        let Some(rest) = text
            .strip_prefix(self.redirect_uri.as_str())
            .or_else(|| {
                self.redirect_uri
                    .starts_with("http://127.0.0.1:80/")
                    .then(|| text.strip_prefix("http://127.0.0.1/auth/callback"))
                    .flatten()
            })
            .and_then(|rest| rest.strip_prefix('?'))
        else {
            return Callback::Unrelated(self);
        };
        let query = rest.split_once('#').map_or(rest, |(query, _)| query);
        self.accept(query)
    }

    /// Checks a callback that carries this attempt's `state`.
    fn finish(self, pairs: &[form::Pair]) -> Result<Accepted, Error> {
        let repeated = pairs
            .iter()
            .enumerate()
            .any(|(index, (name, _))| pairs.iter().skip(index + 1).any(|(other, _)| other == name));
        if repeated {
            return Err(rejected("the callback repeats a parameter"));
        }
        let value = |name| {
            pairs
                .iter()
                .find(|(key, _)| key.as_str() == name)
                .map(|(_, value)| value.as_str())
        };

        if value("iss").is_some_and(|issuer| issuer != ISSUER) {
            return Err(rejected("the callback names another issuer"));
        }
        if let Some(error) = value("error") {
            if value("code").is_some() {
                return Err(rejected("the callback carries both a code and an error"));
            }
            if error == "access_denied" {
                return Err(Error::new(
                    ErrorKind::AccessDenied,
                    "the user declined the request",
                ));
            }
            // RFC 6749, section 4.1.2.1, and `invalid_client`, which some
            // providers send in its place: the client itself is refused, not
            // this attempt.
            let failed = if matches!(error, "unauthorized_client" | "invalid_client") {
                Error::new(
                    ErrorKind::ClientRejected,
                    "the provider refused the app's registration in the browser",
                )
            } else {
                Error::new(
                    ErrorKind::AuthorizationFailed,
                    "the provider ended the authorization with an error",
                )
            };
            return Err(failed.with_code(
                provider_error::sanitize(error)
                    .filter(|code| value("state").is_none_or(|state| !code.contains(state))),
            ));
        }
        let code = value("code")
            .filter(|code| !code.is_empty() && code.len() <= MAX_CODE_LEN)
            .ok_or_else(|| rejected("the callback carries no authorization code"))?;
        let code = AuthorizationCode::new(code.to_owned());

        let exchange = |client_id| Exchange {
            client_id,
            code,
            verifier: self.verifier,
            redirect_uri: self.redirect_uri,
            nonce: self.nonce,
            account: self.account,
        };
        match (self.client, value("client_id")) {
            (PendingClient::New, issued) => {
                let client_id = issued
                    .and_then(|issued| IssuedClientId::parse(issued).ok())
                    .ok_or_else(|| rejected("the callback carries no issued client ID"))?;
                Ok(Accepted::NewRegistration(NewRegistration(exchange(
                    client_id,
                ))))
            }
            (PendingClient::Saved(saved), Some(named)) if named != saved.as_str() => {
                Err(rejected("the callback names a different client"))
            }
            (PendingClient::Saved(saved), _) => Ok(Accepted::Returning(exchange(saved))),
        }
    }

    fn owns(&self, state: &str) -> bool {
        hmac::verify(&self.state_key, state.as_bytes(), self.state_tag.as_ref()).is_ok()
    }
}

impl fmt::Debug for Attempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attempt")
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

/// What a request to the callback path did to an attempt.
///
/// These two outcomes are all there are: a request either belongs to the
/// attempt or it does not, so the enum stays exhaustive and a `match`
/// needs no wildcard arm.
///
/// ```no_run
/// # use siwc::protocol::{Accepted, Attempt, Callback};
/// # fn next_query() -> String { todo!() }
/// # fn wait(mut attempt: Attempt) -> Result<Accepted, siwc::Error> {
/// loop {
///     attempt = match attempt.accept(&next_query()) {
///         Callback::Unrelated(open) => open, // answer 404 and keep waiting
///         Callback::Final(result) => return result,
///     };
/// }
/// # }
/// ```
#[derive(Debug)]
#[must_use = "an unrelated request hands the attempt back"]
pub enum Callback {
    /// The request does not carry this attempt's `state`: another local
    /// program, a web page or a browser preload sent it. It says nothing
    /// about the sign-in, so the attempt is handed back and stays open.
    Unrelated(Attempt),
    /// The request was this attempt's callback. The attempt is over,
    /// whatever the result says.
    Final(Result<Accepted, Error>),
}

/// A callback that passed every check.
///
/// A later version may know more ways a sign-in can go on, so a `match`
/// outside this crate needs a wildcard arm; an app that meets a variant it
/// does not know ends the sign-in with an error.
#[derive(Debug)]
#[must_use = "the authorization code is still to be exchanged"]
#[non_exhaustive]
pub enum Accepted {
    /// The provider registered the app and issued a client ID.
    NewRegistration(NewRegistration),
    /// The saved registration was used.
    Returning(Exchange),
}

/// A fresh registration whose client ID is not stored yet.
///
/// The exchange is only handed out by [`saved`](Self::saved): if the code
/// exchange then fails, the next attempt reuses the stored ID instead of
/// registering the app a second time, and the user keeps a single entry for
/// the app in their ChatGPT settings.
///
/// ```no_run
/// # use siwc::protocol::{Accepted, Exchange, IssuedClientId};
/// # fn store(_: &IssuedClientId) -> std::io::Result<()> { todo!() }
/// # fn next(accepted: Accepted) -> std::io::Result<Exchange> {
/// let exchange = match accepted {
///     Accepted::NewRegistration(registration) => {
///         store(registration.client_id())?;
///         registration.saved()
///     }
///     Accepted::Returning(exchange) => exchange,
///     // A way to go on that this version of the app does not know.
///     _ => return Err(std::io::ErrorKind::Unsupported.into()),
/// };
/// # Ok(exchange)
/// # }
/// ```
#[derive(Debug)]
#[must_use = "store the issued client ID, then call saved()"]
pub struct NewRegistration(Exchange);

impl NewRegistration {
    /// The client ID to store for this account.
    #[must_use]
    pub fn client_id(&self) -> &IssuedClientId {
        self.0.client_id()
    }

    /// Continues to the code exchange. Call it once the client ID is stored.
    pub fn saved(self) -> Exchange {
        self.0
    }
}

/// 256 random bits as 43 base64url characters.
fn random_text(entropy: &dyn Entropy) -> Result<Zeroizing<String>, Error> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    entropy.fill(bytes.as_mut_slice())?;
    Ok(Zeroizing::new(base64url::encode(bytes.as_slice())))
}

/// A byte that can stand in a URL as RFC 3986 writes it: unreserved,
/// reserved, or the `%` of an escape.
fn is_url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&byte)
}

fn rejected(message: &'static str) -> Error {
    Error::new(ErrorKind::CallbackRejected, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_always_accepts_os_entropy() {
        type Start =
            fn(Registration<'_>, Option<&HostId>, u16, &crate::OsEntropy) -> Result<Attempt, Error>;
        let _: Start = Attempt::start;
    }
}
