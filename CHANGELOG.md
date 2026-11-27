# Changelog

All notable changes to `siwc` are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0, a
minor release may break the API.

## [Unreleased]

## [0.1.0] - 2026-11-27

First release.

### Added

- Browser sign-in with PKCE through a one-shot listener on `127.0.0.1`: `Client::add_account`, `sign_in_again`, `enable_plan_use`.
- The installation's host ID in the authorization request, sent by default: `HostId`, `ClientBuilder::send_host_id`.
- Sign-in without a local browser: `add_account_manually`, `ClientBuilder::callback_port`.
- An interrupted first registration can be resumed or discarded: `resume_unfinished_registration`, `discard_unfinished_registration`.
- The browser tab's answer page in the app's words and look: `ClientBuilder::page_texts`, `page_style`.
- Several accounts side by side, each named by its `AccountId`: `accounts`, `select_account`.
- Token renewal under a per-account lock that holds across processes: `access_token`.
- Signing out and removing an account: `sign_out`, `forget`.
- Moving an account to another machine as a passphrase-sealed bundle: `export_account_to`, `import_account`.
- Account changes made by other processes: `Client::changes`.
- A support report without tokens or personal data: `Client::diagnose`.
- The models the user's plan allows: `Client::models`.
- Streamed plan requests: `Client::stream_response`, `ResponseRequest`, `ResponseStream`.
- Plan requests through the app's own HTTP client: `Client::call`, `plan::SseDecoder`, `plan::Refusal`.
- Bounded retries after a `429` or `5xx`, the `5xx` ones optional: `ClientBuilder::resend_after_server_error`.
- Cancellation from another thread: `Canceller`.
- Async calls that need no particular runtime: the `*_async` methods, `AsyncResponseStream`, `ClientBuilder::spawner`.
- Stores: `MemoryStore`, `PrivateFiles`, `Sealed`, and `store::Keychain` with the `keychain` feature; `store::conformance::check` with the `testing` feature tests an app's own `Store`.
- Transports: the `Transport` trait, and `Https` and `Ureq` with the `https` and `ureq` features.
- Errors with a stable kind, the HTTP status, the provider's code and the request ID: `Error`, `ErrorKind`.
- The labels OpenAI's interface guidelines ask for: `plan::wording`.
- Offline tests with the `testing` feature: `FakeProvider`, `FakeClock`, `FakeUser`, `FakeResponse`.
- The whole flow as data without I/O, for apps that drive it themselves: `protocol`.

[Unreleased]: https://github.com/barnerylabs/siwc/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/barnerylabs/siwc/releases/tag/v0.1.0
