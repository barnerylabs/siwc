//! Request routing and shared state for the in-memory provider.

use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::cancel::Canceller;
use crate::error::Error;
use crate::protocol::{HttpRequest, HttpResponse, Method, StreamingResponse};
use crate::time::Clock;

use super::oauth::{JWKS_URL, OAuth, REVOKE_URL, TOKEN_URL, oauth_error};
use super::plan::{MODELS_URL, Models, RESPONSES_URL, Responses};
use super::responses::FakeResponse;
use super::user::FakeUser;

/// What the provider answers: a whole response, or a scripted plan answer
/// with the request ID it goes out under.
enum Answer {
    Whole(HttpResponse),
    Scripted(FakeResponse, String),
}

pub(super) struct ProviderCore {
    clock: Box<dyn Clock>,
    state: Mutex<State>,
}

struct State {
    oauth: OAuth,
    models: Models,
    responses: Responses,
    fail_next: Option<(u16, Vec<u8>)>,
    requests: u64,
}

impl ProviderCore {
    pub(super) fn new(instance: u64, clock: Box<dyn Clock>) -> Self {
        Self {
            clock,
            state: Mutex::new(State {
                oauth: OAuth::new(instance),
                models: Models::new(),
                responses: Responses::default(),
                fail_next: None,
                requests: 0,
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn authorize(
        &self,
        authorization_url: &str,
        user: FakeUser,
    ) -> Result<(String, String), Error> {
        self.state().oauth.authorize(authorization_url, user)
    }

    pub(super) fn fail_authorization(
        &self,
        authorization_url: &str,
        error_code: &str,
    ) -> Result<(String, String), Error> {
        OAuth::fail_authorization(authorization_url, error_code)
    }

    pub(super) fn revoke_refresh_tokens(&self) {
        self.state().oauth.revoke_refresh_tokens();
    }

    pub(super) fn reject_registrations(&self) {
        self.state().oauth.reject_registrations();
    }

    pub(super) fn fail_next_request(&self, status: u16, body: Vec<u8>) {
        self.state().fail_next = Some((status, body));
    }

    pub(super) fn refuse_next_models(&self, status: u16, body: Vec<u8>) {
        self.state().models.refuse_next(status, body);
    }

    pub(super) fn set_models(&self, models: &[(&str, &str)]) {
        self.state().models.set(models);
    }

    pub(super) fn push_response(&self, response: FakeResponse) {
        self.state().responses.push(response);
    }

    pub(super) fn plan_requests(&self) -> Vec<String> {
        self.state().responses.requests()
    }

    /// Answers `request` with a whole body.
    pub(super) fn handle(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        match self.answer(request)? {
            Answer::Whole(response) => Ok(response),
            Answer::Scripted(scripted, request_id) => scripted.into_whole(&request_id),
        }
    }

    /// Answers `request` with a body that is read piece by piece.
    pub(super) fn handle_streaming(
        &self,
        request: &HttpRequest,
        canceller: &Canceller,
    ) -> Result<StreamingResponse, Error> {
        match self.answer(request)? {
            Answer::Whole(response) => Ok(response.into()),
            Answer::Scripted(scripted, request_id) => {
                Ok(scripted.into_streaming(&request_id, canceller))
            }
        }
    }

    fn answer(&self, request: &HttpRequest) -> Result<Answer, Error> {
        let now = self.clock.now().as_secs();
        let mut guard = self.state();
        let state = &mut *guard;
        state.requests += 1;
        let req_id = format!("req_fake_{:04}", state.requests);

        let failure = state.fail_next.take();
        if matches!(failure, Some((0, _))) {
            // The request never reached the provider.
            return Err(Error::transport_unavailable());
        }
        let route = (request.method(), request.url());
        if route == (Method::Post, RESPONSES_URL) {
            state.responses.record(request.body());
        }
        if let Some((status, body)) = failure {
            let response = HttpResponse::new(status, body).with_request_id(Some(&req_id));
            return Ok(Answer::Whole(response));
        }

        let response = match route {
            (Method::Get, JWKS_URL) => state.oauth.jwks(),
            (Method::Post, TOKEN_URL) => state.oauth.token(request.body(), now),
            (Method::Post, REVOKE_URL) => state.oauth.revoke(request.body()),
            (Method::Get, MODELS_URL) => state.models.answer(&state.oauth, request, now),
            (Method::Post, RESPONSES_URL) => {
                match state.responses.answer(&state.oauth, request, now) {
                    Ok(scripted) => return Ok(Answer::Scripted(scripted, req_id)),
                    Err(refused) => refused,
                }
            }
            _ => oauth_error(404, "not_found"),
        };
        Ok(Answer::Whole(response.with_request_id(Some(&req_id))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transport;
    use crate::testing::FakeProvider;

    #[test]
    fn rejects_malformed_requests_and_unknown_routes() {
        let transport = FakeProvider::new().transport();
        assert_eq!(
            transport
                .send(&HttpRequest::get("https://api.openai.com/v1/unknown"))
                .unwrap()
                .status(),
            404
        );
        assert_eq!(
            transport
                .send(&HttpRequest::get(MODELS_URL))
                .unwrap()
                .status(),
            401
        );
        assert_eq!(
            transport
                .send(&HttpRequest::post_form(TOKEN_URL, &[("x", "1")]))
                .unwrap()
                .status(),
            400
        );
        assert_eq!(
            transport
                .send(&HttpRequest::post_form(REVOKE_URL, &[("x", "1")]))
                .unwrap()
                .status(),
            400
        );
    }
}
