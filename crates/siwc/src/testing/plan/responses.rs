//! The fake provider's /v1/responses route and its scripted replies.

use std::collections::VecDeque;

use serde_json::Value;

use crate::protocol::{HttpRequest, HttpResponse, json};
use crate::testing::{FakeResponse, oauth::OAuth};

use super::{api_error, require_plan};

pub(in crate::testing) const RESPONSES_URL: &str = "https://api.openai.com/v1/responses";

#[derive(Default)]
pub(in crate::testing) struct Responses {
    scripted: VecDeque<FakeResponse>,
    requests: Vec<String>,
}

impl Responses {
    pub(in crate::testing) fn push(&mut self, response: FakeResponse) {
        self.scripted.push_back(response);
    }

    pub(in crate::testing) fn requests(&self) -> Vec<String> {
        self.requests.clone()
    }

    /// Counts arrivals before validation or injected HTTP refusals.
    pub(in crate::testing) fn record(&mut self, body: &[u8]) {
        self.requests
            .push(String::from_utf8_lossy(body).into_owned());
    }

    pub(in crate::testing) fn answer(
        &mut self,
        oauth: &OAuth,
        request: &HttpRequest,
        now: u64,
    ) -> Result<FakeResponse, HttpResponse> {
        require_plan(oauth, request, now)?;
        // A plan request can be far larger than a buffered API answer.
        let stateless_stream = json::object_within(request.body(), crate::plan::MAX_REQUEST_LEN)
            .is_some_and(|object| {
                object.get("store") == Some(&Value::Bool(false))
                    && object.get("stream") == Some(&Value::Bool(true))
            });
        if !stateless_stream {
            return Err(api_error(400, "invalid_request_error"));
        }
        Ok(self
            .scripted
            .pop_front()
            .unwrap_or_else(|| FakeResponse::text(&["Hello from the fake provider."])))
    }
}
