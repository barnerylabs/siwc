//! Who signed in, as proven by a verified ID token.

use std::fmt;

use serde_json::{Map, Value};

use super::id_token::{is_display_text, is_picture_url, is_subject};
use super::json;

/// The verified identity of the signed-in user.
///
/// Sign-in verifies the ID token's signature, issuer, audience, expiry,
/// nonce and subject. Bundle import verifies the signed identity again
/// without requiring a current expiry or a new nonce. A stored installation
/// record keeps the identity from the last verification. The subject
/// identifies the account for this registration; the other fields are for
/// display and can be missing.
///
/// A subject is 1 to 255 printable ASCII characters (OpenID Connect Core,
/// section 2); a token with any other subject is refused. A `name` or
/// `email` claim with control, invisible or text-direction characters and a
/// `picture` that is not an `https://` URL are dropped from a fresh token,
/// and make a stored installation record
/// [`StoreCorrupt`](crate::ErrorKind::StoreCorrupt).
///
/// `Debug` shows none of the personal fields, so an identity that ends up in
/// a log line or a panic message names nobody.
///
/// ```
/// # fn greet(identity: &siwc::protocol::Identity) -> String {
/// match identity.name().or(identity.email()) {
///     Some(label) => format!("Signed in as {label}"),
///     None => "Signed in".to_owned(),
/// }
/// # }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    pub(crate) subject: String,
    pub(crate) email: Option<String>,
    pub(crate) email_verified: bool,
    pub(crate) name: Option<String>,
    pub(crate) picture: Option<String>,
}

impl Identity {
    /// The provider's stable identifier for the account. Together with the
    /// issued client ID it is the key of a profile; never show it as a name.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The account's e-mail address, as a display hint. It does not identify
    /// a workspace, and two registrations can share it.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Whether the provider states that the e-mail address is verified.
    /// `false` when the claim is absent.
    #[must_use]
    pub fn email_verified(&self) -> bool {
        self.email_verified
    }

    /// The user's display name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// HTTPS URL of the user's profile picture.
    #[must_use]
    pub fn picture(&self) -> Option<&str> {
        self.picture.as_deref()
    }
}

/// The members of a stored identity, all of them always present.
const RECORD_MEMBERS: [&str; 5] = ["subject", "email", "email_verified", "name", "picture"];

impl Identity {
    /// The identity as the JSON object the client keeps in its installation
    /// record. Absent display values are `null`.
    pub(crate) fn to_record(&self) -> Value {
        let text = |value: &Option<String>| value.clone().map_or(Value::Null, Value::String);
        let mut object = Map::new();
        object.insert("subject".to_owned(), Value::String(self.subject.clone()));
        object.insert("email".to_owned(), text(&self.email));
        object.insert(
            "email_verified".to_owned(),
            Value::Bool(self.email_verified),
        );
        object.insert("name".to_owned(), text(&self.name));
        object.insert("picture".to_owned(), text(&self.picture));
        Value::Object(object)
    }

    /// Reads back what [`to_record`](Self::to_record) wrote. `None` when a
    /// member is missing, unknown, of another type or rejected by the ID
    /// token parser's display rules.
    pub(crate) fn from_record(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        if !json::exact(object, &RECORD_MEMBERS) {
            return None;
        }
        let display = |name: &str, valid: fn(&str) -> bool| match object.get(name)? {
            Value::Null => Some(None),
            Value::String(text) if valid(text) => Some(Some(text.clone())),
            _ => None,
        };
        let subject = object
            .get("subject")?
            .as_str()
            .filter(|subject| is_subject(subject))?;
        Some(Self {
            subject: subject.to_owned(),
            email: display("email", is_display_text)?,
            email_verified: object.get("email_verified")?.as_bool()?,
            name: display("name", is_display_text)?,
            picture: display("picture", is_picture_url)?,
        })
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("email_verified", &self.email_verified)
            .finish_non_exhaustive()
    }
}
