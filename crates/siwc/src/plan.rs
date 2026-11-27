//! Using the ChatGPT plan once signed in: the models an account may use,
//! what the API's refusals mean, and the interface wording the provider asks
//! for.
//!
//! Like [`protocol`](crate::protocol), nothing in this module performs I/O;
//! the methods on [`Client`](crate::Client) that send its requests are
//! named below.
//!
//! # Sending requests on the user's plan
//!
//! 1. Call [`Account::check_plan_use`](crate::Account::check_plan_use) (or
//!    inspect [`Account::plan_use`](crate::Account::plan_use)) first; when plan
//!    use was not granted, offer
//!    [`Client::enable_plan_use`](crate::Client::enable_plan_use) instead of
//!    sending a plan request.
//! 2. Let the user pick from [`Client::models`](crate::Client::models) and
//!    pass [`Model::id`] in the request body.
//! 3. Put the request body into a [`ResponseRequest`] and send it with
//!    [`Client::stream_response`](crate::Client::stream_response) (or
//!    [`stream_response_async`](crate::Client::stream_response_async)). The
//!    answer comes back as a [`ResponseStream`](crate::ResponseStream) of
//!    [`ResponseEvent`]s, which ends without an error only when the answer
//!    is complete.
//! 4. Show [`wording::WELCOME`] once when
//!    [`Completed::plan_use_started`](crate::Completed::plan_use_started) is
//!    `true`, show [`wording::USING_PLAN`] beside a [`wording::MANAGE_USAGE`]
//!    link to [`MANAGE_USAGE_URL`] while requests use the plan, and make that
//!    link the main action on [`ErrorKind::UsageLimit`](crate::ErrorKind::UsageLimit).
//!
//! ```no_run
//! use siwc::ErrorKind;
//! use siwc::plan::{MANAGE_USAGE_URL, ResponseRequest, wording};
//!
//! # fn show(_: &str) {}
//! # fn example(client: &siwc::Client, id: &siwc::AccountId) -> Result<(), siwc::Error> {
//! let models = client.models(id)?;
//! // An account may be offered no model at all.
//! let Some(model) = models.as_slice().first() else {
//!     return Ok(());
//! };
//! let request = ResponseRequest::text(model.id(), "Why is the sky blue?")?;
//! let answer = client.stream_response(id, &request).and_then(|stream| {
//!     for event in stream {
//!         if let Some(text) = event?.text_delta() {
//!             show(text);
//!         }
//!     }
//!     Ok(())
//! });
//! match answer {
//!     // The loop ended without an error: the answer is complete.
//!     Ok(()) => {}
//!     Err(error) if error.kind() == ErrorKind::UsageLimit => {
//!         println!("{}: {MANAGE_USAGE_URL}", wording::MANAGE_USAGE);
//!     }
//!     Err(error) => return Err(error),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The stream takes care of the route's rules: it sends the token only for
//! an account with plan use, sets `"store": false` and `"stream": true`,
//! renews a token refused with `401` once, and waits out a `429` or `5xx`
//! that says "not now" (a `5xx` without one of the provider's unavailable
//! codes only while
//! [`ClientBuilder::resend_after_server_error`](crate::ClientBuilder::resend_after_server_error)
//! allows it). Once the API accepts the POST, a failure event ends
//! the stream without sending again, even before output reaches the app.
//! It takes an answer for complete only when `response.completed`
//! arrived and the HTTP body behind it ended as announced.
//! [`ErrorKind`](crate::ErrorKind) says what to do about each ending.
//! [`ResponseRequest::text_with_instructions`] adds a system text to the
//! smallest request, and [`ResponseRequest::from_json`] takes any body the
//! route accepts.
//!
//! For a whole answer of at most 16 MiB, collect the untouched stream:
//!
//! ```no_run
//! # fn answer(client: &siwc::Client, id: &siwc::AccountId, request: &siwc::plan::ResponseRequest) -> Result<String, siwc::Error> {
//! client.stream_response(id, request)?.into_text()
//! # }
//! ```
//!
//! # With an HTTP client of your own
//!
//! An app that already has an HTTP client, or needs a route this crate does
//! not send to, keeps the pieces in its own hands:
//!
//! 1. Send plan requests to [`RESPONSES_URL`] (`POST`) with
//!    `Authorization: Bearer <token>`, `"store": false` and `"stream": true`
//!    (the provider documents stateless streaming responses for plan use).
//!    Wrap the request in [`Client::call`](crate::Client::call) or
//!    [`Client::call_async`](crate::Client::call_async). They decide by
//!    the HTTP status of a refusal: a token refused with `401` is renewed
//!    once, a `429` or `5xx` that says "not now" is sent again with
//!    bounded backoff (a `5xx` without one of the provider's unavailable
//!    codes only while
//!    [`ClientBuilder::resend_after_server_error`](crate::ClientBuilder::resend_after_server_error)
//!    allows it), and no other status is sent again, whatever code
//!    its body carries. A failure the app reads from an accepted stream
//!    has no refusal status and ends the call, because the provider may
//!    already have counted the POST.
//! 2. Pass non-`2xx` responses to [`Refusal::from_response`] (adding the
//!    response's `x-request-id` and `retry-after` headers with
//!    [`Refusal::with_request_id`] and [`Refusal::with_retry_after`]), and
//!    decode chunked `text/event-stream` bodies with [`SseDecoder::feed`],
//!    which returns each event as a [`ResponseEvent`] (or classify
//!    individual failure frames with [`Refusal::from_event`] and
//!    [`Refusal::from_code`]). [`Refusal`]'s conversion into
//!    [`Error`](crate::Error) gives the [`ErrorKind`](crate::ErrorKind) to
//!    act on.
//! 3. Take an answer for complete only when all of this holds: the HTTP
//!    client read the body to its end without an error, and
//!    [`SseDecoder::finish`], called after that, returned `Ok`. It does so
//!    only for a stream whose last event was `response.completed`
//!    ([`StreamEvent::Completed`]); after `response.incomplete`, after a
//!    failure event and after a stream that just stopped it returns the
//!    error of that ending. Text received before any error is a partial
//!    answer.
//! 4. For the model list, send [`Models::request`] and read the response
//!    with [`Models::from_response`].
//!
//! ```
//! use siwc::ErrorKind;
//! use siwc::plan::SseDecoder;
//!
//! /// Show each delta of a body the HTTP client read without error.
//! fn answer<'a>(
//!     body: impl IntoIterator<Item = &'a [u8]>,
//!     mut show: impl FnMut(&str),
//! ) -> Result<(), siwc::Error> {
//!     let mut decoder = SseDecoder::new();
//!     for piece in body {
//!         for event in decoder.feed(piece)? {
//!             if let Some(text) = event.text_delta() {
//!                 show(text);
//!             }
//!         }
//!     }
//!     // The three endings part here: only `response.completed` is `Ok`.
//!     decoder.finish()?;
//!     Ok(())
//! }
//!
//! let delta = &br#"data: {"type":"response.output_text.delta","delta":"Blue."}"#[..];
//! let show = |text: &str| print!("{text}");
//! let ending = |last: &str| answer([delta, b"\n\n", last.as_bytes(), b"\n\n"], show);
//!
//! ending(r#"data: {"type":"response.completed"}"#)?;
//! let stopped = ending(r#"data: {"type":"response.incomplete"}"#);
//! assert_eq!(stopped.unwrap_err().kind(), ErrorKind::Incomplete);
//! let failed = ending(
//!     r#"data: {"type":"response.failed","response":{"error":{"code":"subscription_sharing_usage_limit_exceeded"}}}"#,
//! );
//! assert_eq!(failed.unwrap_err().kind(), ErrorKind::UsageLimit);
//! // The connection ended after the text, without any of the three.
//! assert_eq!(answer([delta, b"\n\n"], show).unwrap_err().kind(), ErrorKind::Temporary);
//!
//! // An accepted stream can fail after the app has displayed a delta.
//! // Returning that error through `call` must not send the request again.
//! # #[cfg(feature = "testing")] {
//! # use siwc::{AppName, Client, store::MemoryStore, testing::{FakeProvider, FakeUser}};
//! # let provider = FakeProvider::new();
//! # let client = Client::new(AppName::new("Example")?, MemoryStore::new(), provider.clone());
//! # let mut sign_in = client.add_account_manually()?;
//! # let redirect = provider.approve_manual(&sign_in, FakeUser::new("sample@example.invalid"))?;
//! # let id = sign_in.finish(&redirect)?.into_account().id().clone();
//! let mut requests = 0;
//! let mut shown = Vec::new();
//! let result: Result<(), siwc::Error> = client.call(&id, |_| {
//!     requests += 1;
//!     let failure = br#"data: {"type":"error","code":"subscription_sharing_usage_unavailable"}"#;
//!     answer([delta, b"\n\n", failure, b"\n\n"], |text| shown.push(text.to_owned()))?;
//!     Ok(Ok(()))
//! });
//! assert_eq!(result.unwrap_err().kind(), ErrorKind::Temporary);
//! assert_eq!(shown, ["Blue."]);
//! assert_eq!(requests, 1);
//! # }
//!
//! # Ok::<(), siwc::Error>(())
//! ```
//!
//! ```
//! use siwc::ErrorKind;
//! use siwc::plan::{MANAGE_USAGE_URL, Refusal, wording};
//!
//! let body = br#"{"error":{"code":"subscription_sharing_usage_limit_exceeded"}}"#;
//! let error = siwc::Error::from(Refusal::from_response(429, body).unwrap());
//! assert_eq!(error.kind(), ErrorKind::UsageLimit);
//! let action = (wording::MANAGE_USAGE, MANAGE_USAGE_URL);
//! # assert_eq!(action.0, "Manage usage");
//! ```

mod event;
#[cfg(fuzzing)]
mod fuzzing;
mod models;
mod refusal;
mod request;
mod response_event;
mod sse;
mod stream_event;
pub mod wording;

#[cfg(fuzzing)]
#[doc(hidden)]
pub use fuzzing::{fuzz_event, fuzz_request};
pub use models::{Model, Models};
pub use refusal::{Reason, Refusal};
pub(crate) use refusal::{delta_seconds, is_documented_code};
#[cfg(feature = "testing")]
pub(crate) use request::MAX_LEN as MAX_REQUEST_LEN;
pub use request::ResponseRequest;
pub use response_event::ResponseEvent;
pub use sse::SseDecoder;
pub use stream_event::StreamEvent;
pub(crate) use stream_event::known_incomplete_reason;

/// Endpoint for listing the models an account may use (`GET`).
pub const MODELS_URL: &str = "https://api.openai.com/v1/models";

/// Endpoint for sending streamed, stateless plan inference requests (`POST`).
pub const RESPONSES_URL: &str = "https://api.openai.com/v1/responses";

/// Where a user manages how apps use their ChatGPT plan.
///
/// Link it as [`wording::MANAGE_USAGE`] next to [`wording::USING_PLAN`], and
/// make it the main action when a request ends in
/// [`ErrorKind::UsageLimit`](crate::ErrorKind::UsageLimit).
pub const MANAGE_USAGE_URL: &str = "https://chatgpt.com/settings/usage";
