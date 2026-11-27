//! The body of a plan request to `/v1/responses`, checked before it is sent.

use std::fmt;
use std::sync::Arc;

use serde_json::{Value, json};

use crate::error::{Error, ErrorKind};
use crate::protocol::{HttpRequest, json as strict};
use crate::secret::{AccessToken, SecretBytes};

use super::RESPONSES_URL;

/// Largest request body: 32 MiB, which leaves room for images sent inline.
pub(crate) const MAX_LEN: usize = 32 * 1024 * 1024;

/// One request to the Responses API on the user's plan: the JSON body the
/// app wrote, with the two members this route insists on.
///
/// The provider serves plan requests only stateless and streamed, so the
/// body always says `"store": false` and `"stream": true`: a body without
/// them gets them, and a body that says otherwise is refused here, before
/// anything is sent. Everything else in the body is the app's and goes out
/// unchanged; the crate does not model the Responses schema. A member this
/// route does not support comes back from the provider as
/// [`Reason::Unsupported`](super::Reason::Unsupported) with
/// [`Refusal::param`](super::Refusal::param) naming it.
///
/// The body can hold the user's prompt and files. It is wiped when the
/// last clone is dropped, `Debug` prints none of it, and no error quotes it.
/// Clones share one buffer.
///
/// The HTTP request with the access token is built inside the crate, by
/// [`Client::stream_response`](crate::Client::stream_response), and only
/// for a token whose credentials grant plan use. An app cannot build it
/// around that check:
///
/// ```compile_fail,E0624
/// # fn example(request: &siwc::plan::ResponseRequest, token: &siwc::AccessToken) {
/// let unchecked = request.http_request(token);
/// # drop(unchecked);
/// # }
/// ```
///
/// ```
/// use siwc::plan::ResponseRequest;
///
/// let request = ResponseRequest::from_json(
///     r#"{
///         "model": "example-large",
///         "instructions": "Answer in one sentence.",
///         "input": [{"role": "user", "content": "Why is the sky blue?"}]
///     }"#,
/// )?;
/// # drop(request);
///
/// let contradicting = ResponseRequest::from_json(
///     r#"{"model": "example-large", "input": [], "stream": false}"#,
/// );
/// assert_eq!(contradicting.unwrap_err().kind(), siwc::ErrorKind::InvalidInput);
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Clone)]
pub struct ResponseRequest {
    body: Arc<SecretBytes>,
}

impl ResponseRequest {
    /// Takes a Responses request body as JSON text.
    ///
    /// `"store": false` and `"stream": true` are added when the body leaves
    /// them out; the rest of the text is kept byte for byte.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when the text
    ///
    /// - is not one JSON object, repeats a member name or is larger than
    ///   32 MiB before or after adding the required members;
    /// - has no nonempty `"model"` string;
    /// - has no `"input"` array (the route takes its context as an array,
    ///   not as a string);
    /// - sets `"store"` to anything but `false` or `"stream"` to anything
    ///   but `true`.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        if json.len() > MAX_LEN {
            return Err(invalid("the request body is larger than 32 MiB"));
        }
        let object = strict::object_within(json.as_bytes(), MAX_LEN).ok_or_else(|| {
            invalid("the request body is not one JSON object without repeated members")
        })?;
        let document = strict::Document(object);
        let members = &document.0;
        if !matches!(members.get("model"), Some(Value::String(model)) if !model.is_empty()) {
            return Err(invalid("the request body names no model"));
        }
        if !matches!(members.get("input"), Some(Value::Array(_))) {
            return Err(invalid("the request body has no input array"));
        }
        let store = match members.get("store") {
            None => r#""store":false,"#,
            Some(Value::Bool(false)) => "",
            Some(_) => return Err(invalid("a plan request has to say \"store\": false")),
        };
        let stream = match members.get("stream") {
            None => r#""stream":true,"#,
            Some(Value::Bool(true)) => "",
            Some(_) => return Err(invalid("a plan request has to say \"stream\": true")),
        };
        // The object has members, so what is added in front of them needs
        // its comma and nothing else changes.
        let opening = json
            .find('{')
            .ok_or_else(|| invalid("the request body is not one JSON object"))?;
        let (head, members) = json.split_at(opening + 1);
        // The limit is on what is sent, the added members included.
        let len = json.len() + store.len() + stream.len();
        if len > MAX_LEN {
            return Err(invalid("the request body is larger than 32 MiB"));
        }
        let mut body = Vec::with_capacity(len);
        for part in [head, store, stream, members] {
            body.extend_from_slice(part.as_bytes());
        }
        Ok(Self {
            body: Arc::new(SecretBytes::new(body)),
        })
    }

    /// A request that sends `input` as one user message to `model`, the
    /// [`Model::id`](super::Model::id) the user picked.
    ///
    /// ```
    /// use siwc::plan::ResponseRequest;
    ///
    /// let request = ResponseRequest::text("example-large", "Say \"hello\".")?;
    /// # drop(request);
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when `model` is empty or the body would
    /// be larger than 32 MiB.
    pub fn text(model: &str, input: &str) -> Result<Self, Error> {
        Self::message(model, None, input)
    }

    /// Like [`text`](Self::text), with `instructions` for the model: what a
    /// chat API calls the system prompt. The route takes them as the
    /// `instructions` member and refuses input items with a system role.
    ///
    /// ```
    /// use siwc::plan::ResponseRequest;
    ///
    /// let request = ResponseRequest::text_with_instructions(
    ///     "example-large",
    ///     "Answer in one sentence.",
    ///     "Why is the sky blue?",
    /// )?;
    /// # drop(request);
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`text`](Self::text).
    pub fn text_with_instructions(
        model: &str,
        instructions: &str,
        input: &str,
    ) -> Result<Self, Error> {
        Self::message(model, Some(instructions), input)
    }

    /// One user message, with instructions if there are any.
    fn message(model: &str, instructions: Option<&str>, input: &str) -> Result<Self, Error> {
        if model.is_empty() {
            return Err(invalid("the request body names no model"));
        }
        let document = |model: &str, instructions: Option<&str>, input: &str| {
            let mut value = json!({
                "model": model,
                "input": [{ "role": "user", "content": input }],
                "store": false,
                "stream": true,
            });
            if let (Some(text), Some(members)) = (instructions, value.as_object_mut()) {
                members.insert("instructions".to_owned(), Value::String(text.to_owned()));
            }
            value
        };
        // The size of the body is known before it is built: the document
        // around the texts, and each text as JSON writes it. The count
        // runs down from the limit and stops where that is used up, so no
        // sum grows past what a `usize` holds, on any target.
        let around = document("", instructions.map(|_| ""), "").to_string().len();
        let left = [Some(model), instructions, Some(input)]
            .into_iter()
            .flatten()
            .try_fold(MAX_LEN.saturating_sub(around), left_after);
        let Some(left) = left else {
            return Err(invalid("the request body is larger than 32 MiB"));
        };
        let len = MAX_LEN - left;
        let mut value = document(model, instructions, input);
        let mut body = Vec::with_capacity(len);
        let written = serde_json::to_writer(&mut body, &value);
        strict::wipe(&mut value);
        let request = Self {
            body: Arc::new(SecretBytes::new(body)),
        };
        if written.is_err() || request.body.expose().len() != len {
            return Err(invalid("the request body could not be written"));
        }
        Ok(request)
    }

    /// `POST https://api.openai.com/v1/responses` with this body, the
    /// account's access token as `authorization: Bearer` and
    /// `accept: text/event-stream`.
    ///
    /// Crate-internal: [`Client::stream_response`](crate::Client::stream_response)
    /// builds this request only for a token whose credentials grant plan
    /// use, a check a request handed out to the app would skip.
    pub(crate) fn http_request(&self, token: &AccessToken) -> HttpRequest {
        HttpRequest::post_json_with_bearer(RESPONSES_URL, token, Arc::clone(&self.body))
    }

    /// Fails unless the body is what every request has to be. For
    /// cargo-fuzz harnesses only.
    #[cfg(fuzzing)]
    pub(super) fn assert_sendable(&self, message: Option<(&str, &str, Option<&str>)>) {
        let body = self.body.expose();
        assert!(body.len() <= MAX_LEN, "a body above the limit");
        let object = strict::object_within(body, MAX_LEN);
        let object = object.as_ref();
        assert!(object.is_some(), "a body that is not one strict object");
        let member = |name| object.and_then(|object| object.get(name));
        assert_eq!(member("store"), Some(&Value::Bool(false)));
        assert_eq!(member("stream"), Some(&Value::Bool(true)));
        assert!(matches!(member("model"), Some(Value::String(model)) if !model.is_empty()));
        assert!(matches!(member("input"), Some(Value::Array(_))));
        if let Some((model, input, instructions)) = message {
            assert_eq!(member("model").and_then(Value::as_str), Some(model));
            assert_eq!(
                member("input"),
                Some(&json!([{"role": "user", "content": input}]))
            );
            assert_eq!(member("instructions").and_then(Value::as_str), instructions);
        }
    }
}

/// What is left of `budget` bytes once `text` stands inside a JSON string
/// as `serde_json` writes it: two bytes for a quote, a backslash and the
/// control characters with a short escape, six for any other control
/// character. `None` as soon as the budget is used up.
fn left_after(budget: usize, text: &str) -> Option<usize> {
    text.bytes().try_fold(budget, |left, byte| {
        left.checked_sub(match byte {
            b'"' | b'\\' | 0x08 | 0x09 | 0x0a | 0x0c | 0x0d => 2,
            0x00..=0x1f => 6,
            _ => 1,
        })
    })
}

impl fmt::Debug for ResponseRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseRequest").finish_non_exhaustive()
    }
}

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_attempt_borrows_the_checked_request_body() {
        let request = ResponseRequest::text("example", "Hello").unwrap();
        let token = AccessToken::new("at-synthetic".to_owned());
        let first = request.http_request(&token);
        let retry = request.http_request(&token);
        let body = request.body.expose();
        assert!(std::ptr::eq(body, first.body()));
        assert!(std::ptr::eq(body, retry.body()));
        drop(request);
        assert_eq!(first.body(), retry.body());
    }

    fn body(request: &ResponseRequest) -> &str {
        std::str::from_utf8(request.body.expose()).unwrap()
    }

    #[test]
    fn missing_members_are_added_in_front_and_the_rest_is_kept_byte_for_byte() {
        let cases = [
            (
                r#"{"model":"m","input":[]}"#,
                r#"{"store":false,"stream":true,"model":"m","input":[]}"#,
            ),
            (
                "  \n{ \"model\" : \"m\",\n \"input\" : [ ] , \"store\":false }\n",
                "  \n{\"stream\":true, \"model\" : \"m\",\n \"input\" : [ ] , \"store\":false }\n",
            ),
            (
                r#"{"stream":true,"model":"m","input":[{"content":"{ \"store\": true }"}]}"#,
                r#"{"store":false,"stream":true,"model":"m","input":[{"content":"{ \"store\": true }"}]}"#,
            ),
            (
                r#"{"model":"m","input":[],"stream":true,"store":false}"#,
                r#"{"model":"m","input":[],"stream":true,"store":false}"#,
            ),
        ];
        for (given, sent) in cases {
            let request = ResponseRequest::from_json(given).unwrap();
            assert_eq!(body(&request), sent);
            // What goes out is still one object, with both members set.
            let parsed = strict::object(request.body.expose()).unwrap();
            assert_eq!(parsed.get("store"), Some(&Value::Bool(false)));
            assert_eq!(parsed.get("stream"), Some(&Value::Bool(true)));
        }
    }

    #[test]
    fn a_body_that_contradicts_the_route_or_cannot_be_read_is_refused() {
        for json in [
            r#"{"model":"m","input":[],"store":true}"#,
            r#"{"model":"m","input":[],"store":null}"#,
            r#"{"model":"m","input":[],"store":"false"}"#,
            r#"{"model":"m","input":[],"stream":false}"#,
            r#"{"model":"m","input":[],"stream":1}"#,
            r#"{"model":"m","input":"just text"}"#,
            r#"{"model":"m"}"#,
            r#"{"input":[]}"#,
            r#"{"model":"","input":[]}"#,
            r#"{"model":7,"input":[]}"#,
            r#"{"model":"m","input":[],"input":[]}"#,
            r#"{"model":"m","input":[]"#,
            r#"[{"model":"m","input":[]}]"#,
            r#""text""#,
            "",
        ] {
            let error = ResponseRequest::from_json(json).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{json}");
        }
    }

    #[test]
    fn a_text_request_escapes_its_input_and_sets_both_members() {
        let request = ResponseRequest::text("example-large", "say \"hi\"\n{\u{1f600}}").unwrap();
        let parsed = strict::object(request.body.expose()).unwrap();
        assert_eq!(parsed.get("model"), Some(&json!("example-large")));
        assert_eq!(
            parsed.get("input"),
            Some(&json!([{ "role": "user", "content": "say \"hi\"\n{\u{1f600}}" }]))
        );
        assert_eq!(parsed.get("store"), Some(&Value::Bool(false)));
        assert_eq!(parsed.get("stream"), Some(&Value::Bool(true)));
        assert_eq!(
            ResponseRequest::text("", "hi").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn an_oversized_body_is_refused_and_one_at_the_limit_is_taken() {
        let frame = r#"{"model":"m","store":false,"stream":true,"input":[""]}"#;
        let fill = |len: usize| frame.replace("\"\"", &format!("\"{}\"", "a".repeat(len)));
        let fits = fill(MAX_LEN - frame.len());
        assert_eq!(fits.len(), MAX_LEN);
        assert!(ResponseRequest::from_json(&fits).is_ok());
        let over = fill(MAX_LEN - frame.len() + 1);
        let error = ResponseRequest::from_json(&over).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let error = ResponseRequest::text("m", &"a".repeat(MAX_LEN)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn debug_and_errors_show_nothing_of_the_body() {
        let request = ResponseRequest::text("example-large", "secret-prompt").unwrap();
        assert_eq!(format!("{request:?}"), "ResponseRequest { .. }");
        let refused =
            ResponseRequest::from_json(r#"{"model":"m","input":"secret-prompt"}"#).unwrap_err();
        for text in [format!("{refused:?}"), refused.to_string()] {
            assert!(!text.contains("secret-prompt"), "{text}");
        }
    }

    #[test]
    fn the_http_request_posts_the_body_with_the_token_in_a_header_only() {
        let request = ResponseRequest::text("example-large", "Hello").unwrap();
        let http = request.http_request(&AccessToken::new("at-synthetic".to_owned()));
        assert_eq!(http.method().as_str(), "POST");
        assert_eq!(http.url(), RESPONSES_URL);
        let headers: Vec<_> = http.headers().collect();
        assert_eq!(
            headers,
            [
                ("accept", "text/event-stream"),
                ("content-type", "application/json"),
                ("authorization", "Bearer at-synthetic"),
            ]
        );
        assert_eq!(http.body(), request.body.expose());
        assert!(!body(&request).contains("at-synthetic"));
        assert!(!format!("{http:?}").contains("at-synthetic"));
    }

    #[test]
    fn the_limit_is_on_the_body_that_is_sent_with_its_added_members() {
        // 28 bytes are added to a body that names neither member.
        let added = r#""store":false,"stream":true,"#.len();
        let frame = r#"{"model":"m","input":[""]}"#;
        let fill = |len: usize| frame.replace("\"\"", &format!("\"{}\"", "a".repeat(len)));
        let fits = fill(MAX_LEN - frame.len() - added);
        let request = ResponseRequest::from_json(&fits).unwrap();
        assert_eq!(request.body.expose().len(), MAX_LEN);
        for over in [1, added, added + 1] {
            let json = fill(MAX_LEN - frame.len() - added + over);
            assert!(json.len() <= MAX_LEN + 1);
            let error = ResponseRequest::from_json(&json).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{over} over");
        }
    }

    #[test]
    fn a_text_request_is_measured_as_json_writes_it_before_it_is_built() {
        // Every kind of character JSON writes longer than it is.
        let awkward = "q\"b\\n\nt\tr\rf\u{c}b\u{8}z\u{0}e\u{1f}d\u{7f}\u{e4}\u{1f600}";
        let request = ResponseRequest::text(awkward, awkward).unwrap();
        let around = ResponseRequest::text("m", "").unwrap().body.expose().len() - 1;
        let written = 1000 - left_after(1000, awkward).unwrap();
        assert_eq!(request.body.expose().len(), around + 2 * written);

        // At the limit to the byte, with input that doubles when written.
        let room = MAX_LEN - around - 1;
        let quotes = "\"".repeat(room / 2);
        let pad = "a".repeat(room % 2);
        let fits = ResponseRequest::text("m", &format!("{quotes}{pad}")).unwrap();
        assert_eq!(fits.body.expose().len(), MAX_LEN);
        let over = ResponseRequest::text("m", &format!("{quotes}{pad}a")).unwrap_err();
        assert_eq!(over.kind(), ErrorKind::InvalidInput);
        // Far above it nothing is built: this would be 192 MiB of JSON.
        let controls = "\u{0}".repeat(MAX_LEN);
        assert_eq!(
            ResponseRequest::text("m", &controls).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn the_count_of_written_bytes_stops_where_its_budget_is_used_up() {
        // One byte each, two for a short escape, six for a control byte.
        assert_eq!(left_after(10, "ab"), Some(8));
        assert_eq!(left_after(10, "a\"\n"), Some(5));
        assert_eq!(left_after(10, "\u{1}"), Some(4));
        assert_eq!(left_after(6, "\u{1}"), Some(0));
        // Never below zero, and never a sum that could wrap: a text that
        // does not fit ends the count at the byte that crosses the budget.
        assert_eq!(left_after(5, "\u{1}"), None);
        assert_eq!(left_after(2, "abc"), None);
        assert_eq!(left_after(0, ""), Some(0));
        assert_eq!(left_after(usize::MAX, "\u{1}\u{1}"), Some(usize::MAX - 12));
    }

    #[test]
    fn escaped_instructions_fit_exactly_at_the_serialized_limit() {
        let overhead = ResponseRequest::text_with_instructions("m", "", "")
            .unwrap()
            .body
            .expose()
            .len();
        let room = MAX_LEN - overhead;
        let mut instructions = "\"".repeat(room / 2);
        instructions.push_str(&"a".repeat(room % 2));
        let exact = ResponseRequest::text_with_instructions("m", &instructions, "").unwrap();
        assert_eq!(exact.body.expose().len(), MAX_LEN);
        instructions.push('a');
        assert_eq!(
            ResponseRequest::text_with_instructions("m", &instructions, "")
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn instructions_go_into_their_own_member_under_the_same_rules() {
        let request =
            ResponseRequest::text_with_instructions("example-large", "Be \"brief\".", "Hi")
                .unwrap();
        let parsed = strict::object(request.body.expose()).unwrap();
        assert_eq!(parsed.get("instructions"), Some(&json!("Be \"brief\".")));
        assert_eq!(
            parsed.get("input"),
            Some(&json!([{ "role": "user", "content": "Hi" }]))
        );
        assert_eq!(parsed.get("store"), Some(&Value::Bool(false)));
        assert_eq!(parsed.get("stream"), Some(&Value::Bool(true)));
        // A plain text request has no such member.
        let plain = ResponseRequest::text("example-large", "Hi").unwrap();
        assert!(!body(&plain).contains("instructions"));

        for refused in [
            ResponseRequest::text_with_instructions("", "Be brief.", "Hi"),
            ResponseRequest::text_with_instructions("m", &"a".repeat(MAX_LEN), "Hi"),
        ] {
            assert_eq!(refused.unwrap_err().kind(), ErrorKind::InvalidInput);
        }
        let debug = format!(
            "{:?}",
            ResponseRequest::text_with_instructions("m", "secret-instructions", "Hi").unwrap()
        );
        assert!(!debug.contains("secret-instructions"));
    }
}
