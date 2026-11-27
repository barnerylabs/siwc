# Contributing to siwc

Bug reports, documentation fixes and pull requests are welcome. `siwc`
handles sign-in and tokens, so every change is reviewed for what it does to
a user's account.

## Security vulnerabilities

Do not open an issue or a pull request for a vulnerability. Report it
privately as described in [`SECURITY.md`](SECURITY.md).

## Issues

Use one of the issue forms: bug report, documentation or feature request.

- Replace every token, authorization code, client ID, account ID and e-mail
  address with a placeholder. A fault never needs a real one to show: the
  `testing` feature provides an in-memory provider, and a failing test
  against it is the best bug report.
- `siwc` follows what OpenAI documents for local apps. A feature that needs
  an undocumented endpoint or parameter waits until OpenAI documents it.
- For a larger change, open an issue first so the approach can be agreed
  before you write the code.

## Pull requests

- One topic per pull request. Refactoring that the change does not need
  goes into a pull request of its own.
- Tests cover the behaviour you change and run offline: no network, no real
  account, no real keychain and no `sleep`. Use `FakeProvider`, `FakeClock`
  and `FakeUser` from the `testing` feature. Never weaken or delete a test to
  make a change pass.
- Run before you push:

  ```sh
  cargo fmt --all --check
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo test --workspace --all-features
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
  ```

  CI also checks the minimum supported Rust version (1.89), the lowest
  allowed dependency versions, Windows and macOS, and runs the fuzz targets.
- The crate is `#![forbid(unsafe_code)]`, and cryptography comes from `ring`
  and `rustls`, never from code written here. A new dependency needs a reason
  in the pull request: what it replaces, how many packages it adds, and
  whether it has a build script.
- Tokens and other secrets never reach `Debug` or `Display` output, error
  messages, the crate's own logging, command lines or the environment, and
  their buffers are wiped when dropped. ureq's debug logging under the `ureq`
  feature is the one exception, which `SECURITY.md` names. A change to how a
  secret is held or passed says so in the pull request.
- A change users notice gets an entry under `[Unreleased]` in
  [`CHANGELOG.md`](CHANGELOG.md).
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
  `fix(store): keep the lock while a write is retried`. A change that breaks
  the public API is marked with `!` and explains the break in a
  `BREAKING CHANGE:` footer. Before 1.0, such a change lands in the next
  minor release.
- `siwc` is an independent implementation of OpenAI's public protocol
  documentation. Do not copy code or longer text from OpenAI's Sign in with
  ChatGPT DevKit or from any other source whose licence is not compatible
  with MIT OR Apache-2.0.

## AI tools

You may use AI coding assistants and agents. A person is responsible for
everything they produce.

An agent does not open issues, pull requests, reviews or comments on its
own. A person reads the result, checks it and submits it.

You have read every line of the change, can explain it in your own words,
and have run the tests yourself. For a bug or security report, you have
reproduced the problem against the real code.

Every commit that an AI tool helped write carries a trailer with the tool
and the exact model:

```text
Assisted-by: <tool>:<model>
```

For example `Assisted-by: ExampleAgent:example-model-2`. Issues and pull
requests name the tool and model in their form, or say `none`. Only people
are authors: do not list an AI tool as author or in `Co-authored-by`, and
remove such trailers if your tool adds them.

Issue texts, pull request descriptions and replies are in your own words.
Tool output you want to show goes into a quote block and says where it came
from.

A contribution without the disclosure or the confirmation gets one request
to add it. If it does not follow, or if the person who submitted it cannot
explain the change, it is closed. False disclosure or invented reports lead
to a block from the repository.

## Licence

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under MIT OR Apache-2.0, without any
additional terms or conditions. There is no contributor licence agreement.
