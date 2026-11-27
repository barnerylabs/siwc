//! The explicit export of credentials for a store, and its strict reader.

use serde_json::{Map, Value};

use crate::error::Error;
use crate::protocol::client_id::IssuedClientId;
use crate::protocol::http::is_b64token;
use crate::protocol::id_token::is_subject;
use crate::protocol::json;
use crate::protocol::scope::Scopes;
use crate::protocol::token_response::{MAX_EARLIEST_REFRESH_LEN, MAX_TOKEN_LEN};
use crate::secret::{AccessToken, IdToken, RefreshToken};
use crate::store::Stored;
use crate::time::UnixTime;

use super::Credentials;

/// The format version this code writes and the only one it reads.
const VERSION: u64 = 1;

/// Room for everything in the export that is not a text: ten member names
/// with their quotes, colons and commas, three numbers, the braces.
const FIXED_LEN: usize = 256;

/// Every member of the stored object; each one is always written, absent
/// values as `null`.
const MEMBERS: [&str; 10] = [
    "v",
    "client_id",
    "subject",
    "access_token",
    "expires_at",
    "renew_at",
    "refresh_token",
    "id_token",
    "scope",
    "earliest_refresh_at",
];

impl Credentials {
    /// The credentials as bytes for a [`Store`](crate::store::Store): a
    /// versioned JSON object with the tokens, the granted scopes, the expiry
    /// and the client ID and subject they were issued for.
    ///
    /// This is the one way credentials leave the crate as a whole. The
    /// result holds the refresh token: give it to a store and nothing else.
    ///
    /// ```no_run
    /// # fn keep(credentials: &siwc::protocol::Credentials) -> Result<(), siwc::Error> {
    /// use siwc::protocol::Credentials;
    ///
    /// let stored = credentials.to_stored();
    /// let read_back = Credentials::from_stored(stored.expose())?;
    /// assert_eq!(read_back.client_id(), credentials.client_id());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn to_stored(&self) -> Stored {
        let secret = |text: Option<&str>| text.map_or(Value::Null, |text| text.to_owned().into());
        let mut object = Map::new();
        object.insert("v".to_owned(), VERSION.into());
        object.insert("client_id".to_owned(), self.client_id.as_str().into());
        object.insert("subject".to_owned(), self.subject.as_str().into());
        object.insert(
            "access_token".to_owned(),
            self.access.expose().to_owned().into(),
        );
        object.insert("expires_at".to_owned(), self.expires_at.as_secs().into());
        object.insert("renew_at".to_owned(), self.renew_at.as_secs().into());
        object.insert(
            "refresh_token".to_owned(),
            secret(self.refresh.as_ref().map(RefreshToken::expose)),
        );
        object.insert(
            "id_token".to_owned(),
            secret(self.id_token.as_ref().map(IdToken::expose)),
        );
        object.insert("scope".to_owned(), self.scopes.to_string().into());
        object.insert(
            "earliest_refresh_at".to_owned(),
            secret(self.earliest_refresh_at.as_deref()),
        );
        let mut value = Value::Object(object);
        // The full size up front: a buffer that never grows leaves no
        // partial copies of the tokens behind.
        let mut bytes = Vec::with_capacity(self.stored_len_limit());
        // A value with text keys always serialises, and a `Vec` takes every
        // write; an empty entry would be refused when it is read.
        if serde_json::to_writer(&mut bytes, &value).is_err() {
            bytes.clear();
        }
        json::wipe(&mut value);
        Stored::new(bytes)
    }

    /// An upper bound for the length of the export: every byte of a text
    /// can take six when it is escaped, and the member names, punctuation
    /// and numbers fit in the fixed part.
    fn stored_len_limit(&self) -> usize {
        let optional = |text: Option<&str>| text.map_or(0, str::len);
        let texts = self.client_id.as_str().len()
            + self.subject.len()
            + self.access.expose().len()
            + optional(self.refresh.as_ref().map(RefreshToken::expose))
            + optional(self.id_token.as_ref().map(IdToken::expose))
            + self.scopes.to_string().len()
            + optional(self.earliest_refresh_at.as_deref());
        FIXED_LEN + 6 * texts
    }

    /// Reads credentials back from what [`to_stored`](Self::to_stored)
    /// wrote.
    ///
    /// Nothing is guessed: every member has to be present with its type, no
    /// other member may be, the version has to be the one this crate writes,
    /// and every text has to fit the limits the token parser applies.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::StoreCorrupt`](crate::ErrorKind::StoreCorrupt) for
    /// malformed entries. An unknown integer version returns
    /// [`ErrorKind::StoreUnsupported`](crate::ErrorKind::StoreUnsupported).
    pub fn from_stored(bytes: &[u8]) -> Result<Self, Error> {
        let corrupt = || Error::corrupt_entry("the stored credentials cannot be read");
        let mut document = json::Document(json::object(bytes).ok_or_else(corrupt)?);
        let object = &mut document.0;
        match object.get("v").and_then(Value::as_u64) {
            Some(VERSION) => {}
            Some(_) => return Err(Error::unsupported_format()),
            None => return Err(corrupt()),
        }
        if !json::exact(object, &MEMBERS) {
            return Err(corrupt());
        }
        let mut token =
            |name| json::take_text(object, name, MAX_TOKEN_LEN).map_err(|json::Unusable| corrupt());
        let access = token("access_token")?
            .map(AccessToken::new)
            .filter(|access| is_b64token(access.expose()))
            .ok_or_else(corrupt)?;
        let refresh = token("refresh_token")?.map(RefreshToken::new);
        let id_token = token("id_token")?.map(IdToken::new);

        let client_id = json::string(object, "client_id")
            .and_then(|text| IssuedClientId::parse(text).ok())
            .ok_or_else(corrupt)?;
        let subject = json::string(object, "subject")
            .filter(|subject| is_subject(subject))
            .ok_or_else(corrupt)?
            .to_owned();
        let time = |name| {
            object
                .get(name)
                .and_then(Value::as_u64)
                .map(UnixTime::from_secs)
        };
        let expires_at = time("expires_at").ok_or_else(corrupt)?;
        let renew_at = time("renew_at")
            .filter(|renew_at| *renew_at <= expires_at)
            .ok_or_else(corrupt)?;
        let scopes = json::string(object, "scope")
            .map(|text| (text, Scopes::parse(text)))
            .filter(|(text, scopes)| scopes.to_string() == *text)
            .ok_or_else(corrupt)?
            .1;
        let earliest_refresh_at = match object.get("earliest_refresh_at") {
            Some(Value::Null) => None,
            Some(Value::String(text))
                if !text.is_empty() && text.len() <= MAX_EARLIEST_REFRESH_LEN =>
            {
                Some(text.clone())
            }
            _ => return Err(corrupt()),
        };
        Ok(Self {
            client_id,
            subject,
            access,
            expires_at,
            renew_at,
            refresh,
            id_token,
            scopes,
            earliest_refresh_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Credentials whose every free text is `len` times `filler`.
    fn credentials(filler: char, len: usize) -> Credentials {
        let text = || filler.to_string().repeat(len);
        Credentials {
            client_id: IssuedClientId::parse("app_issued0001").unwrap(),
            subject: text(),
            access: AccessToken::new(text()),
            expires_at: UnixTime::from_secs(u64::MAX),
            renew_at: UnixTime::from_secs(u64::MAX),
            refresh: Some(RefreshToken::new(text())),
            id_token: Some(IdToken::new(text())),
            scopes: Scopes::parse("openid profile email offline_access"),
            earliest_refresh_at: Some(text()),
        }
    }

    #[test]
    fn the_export_fits_the_buffer_reserved_for_it_whatever_the_texts_hold() {
        // Escaped, a control character takes six bytes and a quote two.
        for filler in ['\u{1}', '"', 'a', '\u{e4}'] {
            for len in [1, 300, 4000] {
                let credentials = credentials(filler, len);
                let stored = credentials.to_stored();
                assert!(stored.expose().len() > 5 * len, "{filler:?} {len}");
                assert!(
                    stored.expose().len() <= credentials.stored_len_limit(),
                    "{filler:?} {len}"
                );
            }
        }
    }
}
