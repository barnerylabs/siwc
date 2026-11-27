//! The models one account may use, read from the model list endpoint.

use serde_json::Value;

use crate::error::{Error, ErrorKind};
use crate::protocol::json;
use crate::protocol::{HttpRequest, HttpResponse};
use crate::secret::AccessToken;

use super::{MODELS_URL, Refusal};

/// Largest model list answer that is read.
const MAX_BODY_LEN: usize = 1024 * 1024;

/// Most models kept from one answer; later entries are ignored.
const MAX_MODELS: usize = 256;

/// Longest model identifier or display name, in characters.
const MAX_TEXT_CHARS: usize = 128;

/// The models one account may use, in the provider's order.
///
/// The list belongs to the account whose access token fetched it. Fetch it
/// again after switching accounts, and pass the chosen [`Model::id`] as
/// the `model` of an API request.
///
/// ```
/// use siwc::plan::Models;
/// use siwc::protocol::HttpResponse;
///
/// let body = br#"{"models":[
///     {"slug":"example-large","display_name":"Example Large","visibility":"list"},
///     {"slug":"example-internal","display_name":"Internal","visibility":"hide"}
/// ]}"#;
/// let models = Models::from_response(&HttpResponse::new(200, body.to_vec()))?;
/// let names: Vec<_> = models.iter().map(|model| model.display_name()).collect();
/// assert_eq!(names, ["Example Large"]);
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Models(Vec<Model>);

/// One model an account may use.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Model {
    id: Box<str>,
    display_name: Box<str>,
}

impl Models {
    /// `GET https://api.openai.com/v1/models` with the account's access
    /// token as `authorization: Bearer`.
    ///
    /// ```no_run
    /// # fn send(_: siwc::protocol::HttpRequest) -> siwc::protocol::HttpResponse { todo!() }
    /// # fn token() -> siwc::AccessToken { todo!() }
    /// use siwc::plan::Models;
    ///
    /// let models = Models::from_response(&send(Models::request(&token())))?;
    /// # Ok::<(), siwc::Error>(())
    /// ```
    #[must_use]
    pub fn request(token: &AccessToken) -> HttpRequest {
        HttpRequest::get_with_bearer(MODELS_URL, token)
    }

    /// Reads the model list from the API's answer.
    ///
    /// Only entries marked for listing are kept, in the order received, and
    /// at most the first 256 of them. An entry without a usable identifier
    /// (`slug`) is skipped, and one without a usable display name shows its
    /// identifier instead.
    ///
    /// # Errors
    ///
    /// For a status other than `200`, the error of the [`Refusal`] the
    /// answer carries, such as [`ErrorKind::UsageLimit`] or
    /// [`ErrorKind::TokenRejected`]; [`ErrorKind::InvalidResponse`] when a
    /// `200` carries no model list, its body is larger than 1 MiB, or another
    /// success status arrives.
    pub fn from_response(response: &HttpResponse) -> Result<Self, Error> {
        let invalid = || Error::new(ErrorKind::InvalidResponse, "the model list is malformed");
        if response.status() != 200 {
            let refusal = Refusal::from_response(response.status(), response.body())
                .ok_or_else(invalid)?
                .with_request_id(response.request_id())
                .with_retry_after(response.retry_after());
            return Err(refusal.into());
        }
        let body = response.body();
        if body.len() > MAX_BODY_LEN {
            return Err(invalid());
        }
        let document = json::Document(json::object(body).ok_or_else(invalid)?);
        let Some(Value::Array(entries)) = document.0.get("models") else {
            return Err(invalid());
        };
        let models = entries
            .iter()
            .filter_map(listed_model)
            .take(MAX_MODELS)
            .collect();
        Ok(Self(models))
    }

    /// The models as a slice in the provider's order.
    #[must_use]
    pub fn as_slice(&self) -> &[Model] {
        &self.0
    }

    /// The models in the provider's order.
    pub fn iter(&self) -> std::slice::Iter<'_, Model> {
        self.0.iter()
    }

    /// Whether the account may use no model at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many models the account may use.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl IntoIterator for Models {
    type Item = Model;
    type IntoIter = std::vec::IntoIter<Model>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Models {
    type Item = &'a Model;
    type IntoIter = std::slice::Iter<'a, Model>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl Model {
    /// The identifier to send as the `model` of an API request.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The name to show the user; the identifier when the provider sent none.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

fn listed_model(entry: &Value) -> Option<Model> {
    let entry = entry.as_object()?;
    if json::string(entry, "visibility") != Some("list") {
        return None;
    }
    let id = json::string(entry, "slug").filter(|id| {
        (1..=MAX_TEXT_CHARS).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
    })?;
    let display_name = json::string(entry, "display_name")
        .filter(|name| usable(name))
        .unwrap_or(id);
    Some(Model {
        id: id.into(),
        display_name: display_name.into(),
    })
}

/// Text of 1 to [`MAX_TEXT_CHARS`] characters without control characters.
fn usable(text: &str) -> bool {
    let chars = text.chars().take(MAX_TEXT_CHARS + 1).count();
    (1..=MAX_TEXT_CHARS).contains(&chars) && !crate::app::has_disallowed_chars(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usable_text_is_counted_in_characters_not_bytes() {
        assert!(usable(&"\u{e4}".repeat(MAX_TEXT_CHARS)));
        assert!(!usable(&"\u{e4}".repeat(MAX_TEXT_CHARS + 1)));
        assert!(!usable(""));
        assert!(!usable("tab\there"));
        assert!(!usable("model\u{202e}name"));
    }
}
