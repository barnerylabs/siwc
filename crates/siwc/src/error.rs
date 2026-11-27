//! The crate's one error type and the categories an app can act on.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

use crate::protocol::HttpResponse;

mod cause;

pub use cause::ErrorCause;

/// Owned provider text that can contain an echoed token.
pub(crate) type DiagnosticText = Zeroizing<Box<str>>;

/// What went wrong, as a category an app can act on.
///
/// # Acting on errors
///
/// - **A later attempt may succeed ([`Error::is_temporary`]):**
///   [`Self::Temporary`] and [`Self::StoreBusy`]. These categories do not
///   say whether a plan POST was sent or accepted. Do not use them to
///   replay the request automatically. The client already handles eligible
///   HTTP refusals (see [`ResponseStream`](crate::ResponseStream)).
/// - **Renew once for an HTTP `401` before output:** for an app driving
///   its own requests, [`Self::TokenRejected`] with that status can be handled
///   with [`Client::access_token_after_rejection`](crate::Client::access_token_after_rejection)
///   if the app has not tried renewal yet. `Client::call` and the built-in
///   plan streams already handle this. A token rejection after output
///   from a plan stream is final.
/// - **Ask the user to act on the account:** [`Self::SignInRequired`] →
///   [`Client::sign_in_again`](crate::Client::sign_in_again);
///   [`Self::PlanUseNotGranted`] →
///   [`Client::enable_plan_use`](crate::Client::enable_plan_use);
///   [`Self::ClientRejected`] → [`Client::forget`](crate::Client::forget) and
///   [`Client::add_account`](crate::Client::add_account), or for an
///   unfinished registration a new `add_account`. When the refusal came
///   from the browser callback ([`Error::http_status`] is `None`), nothing
///   was recorded and an existing account keeps its session until the
///   provider confirms the refusal;
///   [`Self::UsageLimit`] → pause plan requests for this account and link
///   [`MANAGE_USAGE_URL`](crate::plan::MANAGE_USAGE_URL).
/// - **Sign-in did not complete (a pending registration may remain):**
///   [`Self::AccessDenied`], [`Self::TimedOut`], [`Self::Cancelled`],
///   [`Self::AccountMismatch`], [`Self::CallbackRejected`],
///   [`Self::IdentityRejected`], [`Self::AuthorizationFailed`] and
///   [`Self::Loopback`].
/// - **Show the link instead:** when
///   [`SignIn::open_browser`](crate::SignIn::open_browser) returns
///   [`Self::BrowserUnavailable`], show
///   [`SignIn::start_link`](crate::SignIn::start_link) and keep waiting.
/// - **Local environment or bundle errors:** [`Self::BundleRejected`] (check
///   the passphrase or bundle file), [`Self::Store`], [`Self::StoreNotPrivate`],
///   [`Self::StoreCorrupt`] and [`Self::Randomness`].
/// - **Ask the user before discarding data:** [`Self::SealingKeyMissing`]
///   (check the keychain and retry, or start over with
///   `store::Keychain::start_over` and sign in again). For [`Self::StoreUnsupported`],
///   keep the entry and open it with a compatible release.
/// - **Do not repeat unchanged:** [`Self::NotPermitted`], [`Self::Rejected`],
///   [`Self::Incomplete`],
///   [`Self::InvalidResponse`], [`Self::UnknownAccount`],
///   [`Self::AccountLimit`], [`Self::SignInInProgress`] and
///   [`Self::InvalidInput`].
///
/// New categories may be added; match with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A value handed to the crate breaks one of its rules, such as an empty
    /// app name. A programming error in the app, not something a user can fix.
    InvalidInput,
    /// The operating system returned no random bytes. The operation stopped
    /// there; requests made before that point may have been sent.
    Randomness,
    /// The user declined the request in the browser.
    AccessDenied,
    /// The provider ended the authorization with an error other than a
    /// refusal by the user.
    AuthorizationFailed,
    /// The browser callback did not match the sign-in attempt it claims to
    /// answer.
    CallbackRejected,
    /// The provider answered with something this flow does not define.
    InvalidResponse,
    /// The ID token did not prove an identity for this app and attempt.
    IdentityRejected,
    /// The browser sign-in ended in a different account than the one the app
    /// asked to sign in again.
    AccountMismatch,
    /// The stored credentials can no longer be renewed; the user has to sign
    /// in again.
    SignInRequired,
    /// The provider no longer accepts the issued client ID, for example
    /// because the user removed the app in their ChatGPT settings. For an
    /// account of a [`Client`](crate::Client), signing in again cannot work:
    /// forget the account and add it again.
    ///
    /// The refusal arrives in one of two ways, and the recovery is the same:
    ///
    /// - **The token endpoint** answers a renewal or a code exchange with
    ///   `invalid_client`. The error carries the answer's
    ///   [`Error::http_status`]. This authenticated answer is the only one a
    ///   `Client` records: the account becomes
    ///   [`AccountState::RegistrationRejected`](crate::AccountState::RegistrationRejected)
    ///   and an unfinished registration is cleared.
    /// - **The browser callback** of a sign-in reports `unauthorized_client`
    ///   or `invalid_client`. It has no HTTP status. The redirect passes
    ///   through the browser unauthenticated, so it changes nothing stored: an
    ///   existing account keeps its state and session, and an unfinished
    ///   registration stays until `add_account` replaces it or
    ///   [`Client::discard_unfinished_registration`](crate::Client::discard_unfinished_registration)
    ///   drops it.
    ClientRejected,
    /// The provider refused the request for a reason this crate does not
    /// classify; repeating the same request will not help.
    Rejected,
    /// The provider or the network is unavailable for now. Credentials are
    /// kept; a later attempt can succeed, except after a lost refresh answer
    /// (see [`Client::access_token`](crate::Client::access_token)).
    /// The plan client already retries eligible HTTP `429` and `5xx`
    /// refusals, unless
    /// [`ClientBuilder::resend_after_server_error`](crate::ClientBuilder::resend_after_server_error)
    /// turned that off for a `5xx` without one of the provider's
    /// unavailable codes. [`Error::http_status`] gives the status when
    /// available. This category alone cannot tell the app whether a plan
    /// POST was sent or accepted, or whether any output arrived. Do not use
    /// it to resend the request automatically; an app that turned the
    /// retries off decides by [`Error::http_status`] and
    /// [`Error::provider_code`].
    Temporary,
    /// The loopback listener could not be bound or served.
    Loopback,
    /// Nobody completed the sign-in in the browser in time.
    TimedOut,
    /// The app cancelled the operation through a [`Canceller`](crate::Canceller):
    /// a sign-in's wait for the browser, a call's retry or a streamed answer.
    Cancelled,
    /// The system browser could not be opened; show the start link instead.
    BrowserUnavailable,
    /// The account reached a usage limit for plan requests. Pause plan
    /// requests for this account and offer
    /// [`MANAGE_USAGE_URL`](crate::plan::MANAGE_USAGE_URL) as the main action.
    /// The limit may be plan-wide or set for this app; no reset time can be
    /// inferred.
    UsageLimit,
    /// The user, the workspace or a policy does not allow plan use. Explain
    /// it; do not start a new sign-in and do not repeat the request.
    NotPermitted,
    /// The sign-in does not cover plan use. Offer to enable it.
    PlanUseNotGranted,
    /// The API did not accept the access token. Renew and retry only for
    /// an HTTP `401` before any output and if renewal has not already
    /// been tried. `Client::call` and the built-in plan streams do this
    /// themselves. A token rejection after output from a plan stream is
    /// final. If renewal gives [`ErrorKind::SignInRequired`], ask the user
    /// to sign in again.
    TokenRejected,
    /// The store could not read, write or lock an entry.
    Store,
    /// Another thread or process held the entry's lock for longer than the
    /// caller was willing to wait.
    StoreBusy,
    /// The store's directory or one of its files is not private: other users
    /// can reach it, it belongs to another user, or it is a link or not a
    /// regular file or directory. The operation did not read or write that
    /// file.
    StoreNotPrivate,
    /// No account with this ID exists in this installation. Drop the ID; it
    /// was forgotten or belongs to another installation.
    UnknownAccount,
    /// The installation already holds 32 accounts. Ask the user to forget
    /// one before adding another.
    AccountLimit,
    /// This client already has a sign-in waiting for the browser, or another
    /// sign-in completed the same registration first. Finish, cancel or drop
    /// the other sign-in, then start again.
    SignInInProgress,
    /// What the store returned cannot be read or does not belong to the
    /// account it was read for; nothing from it was used and it was not
    /// overwritten. An operation over several entries, such as
    /// `Sealed::seal_existing`, keeps the entries it finished before. For an
    /// account's credentials, sign the account out, which deletes them
    /// unused, and sign in again. An unreadable installation record has to be
    /// repaired or removed outside the crate. After a keychain service
    /// rotation, an older release that cannot open an entry and does not
    /// recognise the recorded service reports [`Self::InvalidInput`].
    /// Restart with the release that uses the new service before signing
    /// out or repairing the store.
    StoreCorrupt,
    /// The stored format has an unsupported version. Keep the entry and open it
    /// with a compatible release before changing the account.
    StoreUnsupported,
    /// The sealing key is missing from its source while the store holds
    /// entries sealed under a key. The system keychain may have been reset,
    /// or the key may sit where the source does not look, such as a macOS
    /// keychain outside the search list. A locked keychain gives
    /// [`Self::Store`] with the built-in `Keychain`, not this kind. Nothing
    /// was changed. Ask the user to check the keychain and retry; if the key is
    /// gone, `store::Keychain::start_over` (feature `keychain`) discards
    /// only sealed entries that no readable active or retired key opens,
    /// after the user agrees. Check that previous service names are listed
    /// with `Keychain::with_retired`, especially for stores predating the
    /// service marker.
    SealingKeyMissing,
    /// An account bundle handed to
    /// [`Client::import_account`](crate::Client::import_account) is damaged,
    /// does not open under the passphrase or has no verifiable ID token.
    /// The store was not accessed.
    BundleRejected,
    /// A streamed answer stopped before the model finished it, for example at
    /// an output limit or a content filter
    /// ([`Client::stream_response`](crate::Client::stream_response)). The text
    /// received so far is usable but unfinished; [`Error::provider_code`]
    /// holds the provider's reason when it is one of the two it documents,
    /// `max_output_tokens` and `content_filter`. The built-in streams return
    /// this error in place of the event. With [`SseDecoder`](crate::plan::SseDecoder),
    /// read the filtered [`StreamEvent::Incomplete`](crate::plan::StreamEvent::Incomplete)
    /// reason or the original [`ResponseEvent::json`](crate::plan::ResponseEvent::json).
    /// Sending the same request again is likely to stop at the same place.
    Incomplete,
}

impl ErrorKind {
    /// Short identifier used in [`Diagnosis`](crate::Diagnosis) output.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::Randomness => "randomness",
            Self::AccessDenied => "access_denied",
            Self::AuthorizationFailed => "authorization_failed",
            Self::CallbackRejected => "callback_rejected",
            Self::InvalidResponse => "invalid_response",
            Self::IdentityRejected => "identity_rejected",
            Self::AccountMismatch => "account_mismatch",
            Self::SignInRequired => "sign_in_required",
            Self::ClientRejected => "client_rejected",
            Self::Rejected => "rejected",
            Self::Temporary => "temporary",
            Self::Loopback => "loopback",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::BrowserUnavailable => "browser_unavailable",
            Self::UsageLimit => "usage_limit",
            Self::NotPermitted => "not_permitted",
            Self::PlanUseNotGranted => "plan_use_not_granted",
            Self::TokenRejected => "token_rejected",
            Self::Store => "store",
            Self::StoreBusy => "store_busy",
            Self::StoreNotPrivate => "store_not_private",
            Self::UnknownAccount => "unknown_account",
            Self::AccountLimit => "account_limit",
            Self::SignInInProgress => "sign_in_in_progress",
            Self::StoreUnsupported => "store_unsupported",
            Self::StoreCorrupt => "store_corrupt",
            Self::SealingKeyMissing => "sealing_key_missing",
            Self::BundleRejected => "bundle_rejected",
            Self::Incomplete => "incomplete",
        }
    }
}

/// The error type of every fallible operation in this crate.
///
/// It carries a category and a fixed message. An error made from a
/// provider's error response also carries the provider's error code, the
/// HTTP status and the request ID, and an API refusal
/// ([`Refusal`](crate::plan::Refusal)) adds the request member the provider
/// named. Local input errors and an unreadable JWKS body after HTTP 200 have
/// no provider diagnostics. A malformed event on an accepted response
/// stream is `InvalidResponse` and retains the stream's checked request ID
/// when available. It has no error HTTP status. Keep the status, request
/// ID and request member for support requests. The provider's values are
/// kept only when they look like identifiers; they are still the provider's
/// text and could contain sensitive identifiers. Review them before logging.
/// `Display` and `Debug` redact provider text. Their wording may change.
/// [`source`](StdError::source) and [`Error::cause`] give the crate's own
/// [`ErrorCause`] where it knows why a connection or read failed, and never
/// another crate's error.
///
/// ```
/// let error = siwc::AppName::new("").unwrap_err();
/// assert_eq!(error.kind(), siwc::ErrorKind::InvalidInput);
/// assert!(!error.is_temporary());
/// ```
#[derive(Clone)]
pub struct Error {
    kind: ErrorKind,
    message: &'static str,
    #[cfg(feature = "keychain")]
    pub(crate) keychain_timeout: Option<KeychainTimeout>,
    code: Option<DiagnosticText>,
    /// Boxed, so an error stays small where the provider said nothing more.
    answer: Option<Box<Answer>>,
    /// `false` when recording what the provider's refusal means failed.
    state_saved: bool,
    cause: Option<ErrorCause>,
}

/// What the provider's HTTP answer said beyond its error code. Every text
/// was checked to be made of safe characters before it got here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Answer {
    pub(crate) status: Option<u16>,
    pub(crate) request_id: Option<Box<str>>,
    pub(crate) param: Option<DiagnosticText>,
    pub(crate) retry_after: Option<Duration>,
}

#[cfg(feature = "keychain")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeychainTimeout {
    Reset,
    WriteLock,
}

#[cfg(feature = "keychain")]
impl From<KeychainTimeout> for Error {
    fn from(timeout: KeychainTimeout) -> Self {
        let message = match timeout {
            KeychainTimeout::Reset => "the sealing key reset timed out",
            KeychainTimeout::WriteLock => "the sealing key write lock timed out",
        };
        let mut error = Self::new(ErrorKind::Store, message).with_cause(ErrorCause::TimedOut);
        error.keychain_timeout = Some(timeout);
        error
    }
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            #[cfg(feature = "keychain")]
            keychain_timeout: None,
            code: None,
            answer: None,
            state_saved: true,
            cause: None,
        }
    }

    pub(crate) fn with_cause(mut self, cause: ErrorCause) -> Self {
        self.cause = Some(cause);
        self
    }

    /// The provider's terminal refusal stays the error the app sees; a
    /// failure to record it locally only clears [`Self::state_saved`].
    pub(crate) fn after_recording(mut self, recorded: Result<(), Error>) -> Self {
        self.state_saved &= recorded.is_ok();
        self
    }

    /// A cancellation that wins over `displaced` keeps its report that
    /// the state it called for was not saved.
    pub(crate) fn displacing<T>(mut self, displaced: &Result<T, Self>) -> Self {
        if let Err(error) = displaced {
            self.state_saved &= error.state_saved;
        }
        self
    }

    pub(crate) fn with_code(self, code: Option<String>) -> Self {
        self.with_owned_code(code.map(|value| Zeroizing::new(value.into_boxed_str())))
    }

    pub(crate) fn with_owned_code(mut self, code: Option<DiagnosticText>) -> Self {
        self.code = code;
        self
    }

    /// Adds the status and request ID of the HTTP answer this error is
    /// about.
    pub(crate) fn with_response(self, response: &HttpResponse) -> Self {
        if !(100..=599).contains(&response.status()) {
            return Self::invalid_status();
        }
        self.with_answer(Answer {
            status: Some(response.status()),
            request_id: response.request_id().map(Box::from),
            ..Answer::default()
        })
    }

    pub(crate) fn invalid_status() -> Self {
        Self::new(
            ErrorKind::InvalidResponse,
            "the response has an invalid HTTP status",
        )
    }

    pub(crate) fn with_answer(mut self, answer: Answer) -> Self {
        self.answer = (answer != Answer::default()).then(|| Box::new(answer));
        self
    }

    /// Drops the provider code, request ID and parameter for which
    /// `unwanted` holds: values the provider sent that the caller knows to
    /// be something else than they claim, such as an echoed token.
    pub(crate) fn without(mut self, unwanted: impl Fn(&str) -> bool) -> Self {
        let discard = |value: &mut Box<str>| wipe_if_unwanted(value, &unwanted);
        self.code.take_if(|value| unwanted(value));
        if let Some(mut answer) = self.answer.take() {
            answer.request_id.take_if(discard);
            answer.param.take_if(|value| unwanted(value));
            self = self.with_answer(*answer);
        }
        self
    }

    /// The random source could not provide bytes.
    #[must_use]
    pub fn entropy_unavailable() -> Self {
        Self::new(ErrorKind::Randomness, "no random bytes are available")
    }

    /// The error a [`Transport`](crate::Transport) implementation returns
    /// when no answer arrived: no connection, a failed TLS handshake, a
    /// deadline or a response above its size limit.
    #[must_use]
    pub fn transport_unavailable() -> Self {
        Self::new(ErrorKind::Temporary, "the provider could not be reached")
    }

    /// The error a [`Store`](crate::store::Store) implementation returns
    /// when it cannot read, write or lock an entry.
    #[must_use]
    pub fn store_failed() -> Self {
        Self::new(
            ErrorKind::Store,
            "the store could not read, write or lock an entry",
        )
    }

    /// The error a [`Store`](crate::store::Store) implementation returns
    /// when the entry's lock could not be taken within the time the caller
    /// allowed.
    #[must_use]
    pub fn store_busy() -> Self {
        Self::new(
            ErrorKind::StoreBusy,
            "another thread or process holds the entry's lock",
        )
    }

    /// The store's permissions would expose an entry to other users.
    #[must_use]
    pub fn store_not_private() -> Self {
        Self::new(ErrorKind::StoreNotPrivate, "the store is not private")
    }

    /// A stored entry is damaged or inconsistent.
    #[must_use]
    pub fn store_corrupt() -> Self {
        Self::corrupt_entry("an entry in the store is corrupt")
    }

    pub(crate) fn unsupported_format() -> Self {
        Self::new(
            ErrorKind::StoreUnsupported,
            "the stored format version is unsupported",
        )
    }

    /// What the store returned cannot be used.
    pub(crate) fn corrupt_entry(message: &'static str) -> Self {
        Self::new(ErrorKind::StoreCorrupt, message)
    }

    /// The category to act on.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The error code the provider sent, such as `invalid_grant`.
    ///
    /// Only codes made of letters, digits, `_`, `-` and `.` are kept, so the
    /// value holds no markup or line breaks. What it says is still the
    /// provider's choice: `Display` and `Debug` of the error name a code
    /// only when it is one the crate knows from OAuth, OpenID Connect or
    /// the provider's documentation. This accessor also returns unrecognised
    /// codes. Sign-in and renewal omit codes that echo the code, verifier
    /// or tokens associated with the failed step.
    /// Review a code before writing it to a log.
    #[must_use]
    pub fn provider_code(&self) -> Option<&str> {
        self.code.as_ref().map(AsRef::as_ref)
    }

    /// The HTTP status of the provider's answer the error was made from.
    #[must_use]
    pub fn http_status(&self) -> Option<u16> {
        self.answer.as_ref()?.status
    }

    /// The checked request ID for diagnosis and support. It comes from the
    /// `x-request-id` header or [`Refusal::with_request_id`]. An accepted
    /// stream keeps its ID if an event later proves malformed. Sign-in and
    /// renewal omit IDs that echo their secrets. OpenAI asks apps
    /// to keep the ID, notably for `subscription_sharing_invalid_user`.
    ///
    /// [`Refusal::with_request_id`]: crate::plan::Refusal::with_request_id
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.answer.as_ref()?.request_id.as_deref()
    }

    /// The request member the provider named, such as `tools[0].type`.
    #[must_use]
    pub fn param(&self) -> Option<&str> {
        self.answer.as_ref()?.param.as_ref().map(AsRef::as_ref)
    }

    /// How long the provider asked to wait before the request is sent
    /// again: the `Retry-After` header of the refusal this error was made
    /// from, when it named a number of seconds.
    ///
    /// [`Client::stream_response`](crate::Client::stream_response) and
    /// [`Client::call`](crate::Client::call) wait out up to 30 seconds
    /// themselves only for eligible retries. A terminal refusal or exhausted
    /// retry budget may carry any numeric wait. The delay alone does not
    /// make replay safe; OAuth and JWKS errors do not expose this header.
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use siwc::plan::Refusal;
    ///
    /// let body = br#"{"error":{"code":"subscription_sharing_usage_unavailable"}}"#;
    /// let refusal = Refusal::from_response(503, body).unwrap();
    /// let error = siwc::Error::from(refusal.with_retry_after(Some("90")));
    /// assert_eq!(error.retry_after(), Some(Duration::from_secs(90)));
    /// ```
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        self.answer.as_ref()?.retry_after
    }

    /// The safe underlying cause, when the crate knows one; the same value
    /// [`source`](StdError::source) returns. See [`ErrorCause`] for where it
    /// is set and where it is deliberately absent.
    ///
    /// ```
    /// let error = siwc::Error::transport_unavailable();
    /// assert_eq!(error.cause(), None);
    /// ```
    #[must_use]
    pub fn cause(&self) -> Option<ErrorCause> {
        self.cause
    }

    /// Whether the local state this error calls for was written.
    ///
    /// `false` only when the provider ended a session or refused the
    /// registration ([`ErrorKind::SignInRequired`] or
    /// [`ErrorKind::ClientRejected`] from the token endpoint), or a session
    /// without a refresh token ran out (`SignInRequired`), and the client
    /// could not record it in the store: the account may still be listed
    /// as signed in, or an unfinished registration may still be offered.
    /// The kind still decides what the user does next; act on it as usual.
    ///
    /// An account that holds tokens keeps them until the state is written,
    /// so the next renewal meets the same refusal, returns the same kind
    /// and tries the recording again. An account without tokens, one that
    /// was signed out or already needed a sign-in, has nothing a renewal
    /// could send: it keeps reporting `SignInRequired`, and the next sign-in
    /// that meets the refusal records it. A store that keeps failing shows
    /// up in later calls as a storage error.
    ///
    /// A cancellation the app asked for still wins over such an error: the
    /// result is [`ErrorKind::Cancelled`], and it carries `false` too.
    ///
    /// `true` for every other error, including errors that do not concern
    /// stored state, and a refusal for an account that was forgotten
    /// meanwhile, which leaves nothing to record.
    ///
    /// ```
    /// let error = siwc::AppName::new("").unwrap_err();
    /// assert!(error.state_saved());
    /// ```
    #[must_use]
    pub fn state_saved(&self) -> bool {
        self.state_saved
    }

    /// Whether the error is [`ErrorKind::Temporary`] or [`ErrorKind::StoreBusy`].
    /// A later attempt may succeed, but this does not establish that
    /// repeating a plan POST is safe. See [`ErrorKind::Temporary`].
    #[must_use]
    pub fn is_temporary(&self) -> bool {
        matches!(self.kind, ErrorKind::Temporary | ErrorKind::StoreBusy)
    }
}

/// Called on the owned bytes immediately before the field is dropped.
fn wipe_if_unwanted(value: &mut str, unwanted: &impl Fn(&str) -> bool) -> bool {
    if unwanted(value) {
        value.zeroize();
        true
    } else {
        false
    }
}

/// The error codes the crate names in what it prints: those of OAuth 2.0
/// and OpenID Connect, and those the provider gives for a session that
/// cannot be renewed.
const KNOWN_CODES: [&str; 19] = [
    "access_denied",
    "account_selection_required",
    "consent_required",
    "interaction_required",
    "invalid_client",
    "invalid_grant",
    "invalid_refresh_token",
    "invalid_request",
    "invalid_scope",
    "invalid_token",
    "login_required",
    "refresh_token_expired",
    "refresh_token_invalidated",
    "refresh_token_reused",
    "server_error",
    "temporarily_unavailable",
    "token_expired",
    "unauthorized_client",
    "unsupported_grant_type",
];

/// Whether the crate knows `code` as one a standard or the provider's
/// documentation defines. Only such a code is printed: any other is text
/// the answering server chose freely.
fn is_known_code(code: &str) -> bool {
    KNOWN_CODES.contains(&code)
        || crate::plan::is_documented_code(code)
        || crate::plan::known_incomplete_reason(code).is_some()
}

/// The message, and the provider's code when it is one the crate knows.
/// Any other code is read with [`Error::provider_code`].
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)?;
        match self.provider_code() {
            Some(code) if is_known_code(code) => write!(f, " ({code})"),
            _ => Ok(()),
        }
    }
}

/// Shows what the crate itself knows: kind, message, HTTP status, a known
/// code, and of every other value the provider sent only its length. Those
/// values are read with the accessors, by code that means to.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Error");
        debug
            .field("kind", &self.kind)
            .field("message", &self.message);
        match self.provider_code() {
            Some(code) if is_known_code(code) => debug.field("provider_code", &code),
            Some(code) => debug.field("provider_code_len", &code.len()),
            None => &mut debug,
        };
        if let Some(answer) = &self.answer {
            debug
                .field("http_status", &answer.status)
                .field("request_id_len", &self.request_id().map(str::len))
                .field("param_len", &self.param().map(str::len));
        }
        if !self.state_saved {
            debug.field("state_saved", &false);
        }
        if let Some(cause) = &self.cause {
            debug.field("cause", cause);
        }
        debug.finish()
    }
}

/// The source is the crate's own [`ErrorCause`], never another crate's
/// error.
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| cause as &(dyn StdError + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discarding_an_echo_wipes_the_owned_diagnostic_in_place() {
        let mut id = String::from("req-rt-synthetic");
        assert!(wipe_if_unwanted(&mut id, &|id| id.contains("rt-synthetic")));
        assert!(id.as_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn every_error_kind_has_a_distinct_snake_case_name() {
        let all = [
            ErrorKind::InvalidInput,
            ErrorKind::Randomness,
            ErrorKind::AccessDenied,
            ErrorKind::AuthorizationFailed,
            ErrorKind::CallbackRejected,
            ErrorKind::InvalidResponse,
            ErrorKind::IdentityRejected,
            ErrorKind::AccountMismatch,
            ErrorKind::SignInRequired,
            ErrorKind::ClientRejected,
            ErrorKind::Rejected,
            ErrorKind::Temporary,
            ErrorKind::Loopback,
            ErrorKind::TimedOut,
            ErrorKind::Cancelled,
            ErrorKind::BrowserUnavailable,
            ErrorKind::UsageLimit,
            ErrorKind::NotPermitted,
            ErrorKind::PlanUseNotGranted,
            ErrorKind::TokenRejected,
            ErrorKind::Store,
            ErrorKind::StoreBusy,
            ErrorKind::StoreNotPrivate,
            ErrorKind::UnknownAccount,
            ErrorKind::AccountLimit,
            ErrorKind::SignInInProgress,
            ErrorKind::StoreUnsupported,
            ErrorKind::StoreCorrupt,
            ErrorKind::SealingKeyMissing,
            ErrorKind::BundleRejected,
            ErrorKind::Incomplete,
        ];
        for (idx, kind) in all.iter().enumerate() {
            let name = kind.name();
            assert!(!name.is_empty());
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{name}"
            );
            for other in &all[idx + 1..] {
                assert_ne!(name, other.name());
            }
        }
    }
}
