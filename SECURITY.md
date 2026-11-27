# Security policy

`siwc` handles sign-in and tokens for local apps, so a fault in it can expose
a user's ChatGPT account to other programs. Reports are welcome.

## Reporting a vulnerability

Report it privately through
[GitHub Private Vulnerability Reporting](https://github.com/barnerylabs/siwc/security/advisories/new)
(**Security → Report a vulnerability**), or by e-mail to `oss@barnery.com` if
the form is unavailable. Do not open a public issue or pull request for it.

A useful report names the version or commit, the platform, what an attacker
needs (another local program, a web page in the user's browser, a malicious
server response, the same OS user), and the steps or a test that shows the
fault. Use synthetic accounts and tokens in the report; never send a real
token, refresh token or ID token.

AI tools may help find or describe a fault, but a person reproduces it
against the real code, writes or checks the report and sends it. Name the
tool and model that helped, or say none. A report that describes code `siwc`
does not contain or behaviour nobody reproduced is closed, and an invented
one leads to a block.

## Supported versions

Before 1.0, fixes go into the latest minor release only. Upgrade to it to
receive them.

## Scope

### In scope

Faults in the crate's security guarantees are in scope, including:

- a callback, start link or request to the loopback listener that another
  local program or a web page can use to complete, hijack or disturb a
  sign-in, beyond the [known limits](#known-limits);
- a token, code, verifier or ID token that reaches a log, `Debug` output, a
  panic message, a command line or the environment;
- a token, client ID or identity of one account used for another;
- an ID token, callback or provider response accepted although it should be
  refused, or a refresh that loses or reuses a rotated token;
- store files that other users can read beyond the
  [known limits](#known-limits), or a
  sealed entry or account bundle accepted after tampering or under the wrong
  entry/context;
- `Https` sending request data or tokens to the provider before TLS 1.3
  verification succeeds (the `CONNECT` exchange with a configured proxy and
  the TLS handshake come first by design), following a redirect, connecting
  to a host other than the documented provider hosts, or mishandling
  `CONNECT` proxy framing or custom root certificates;
- `Ureq` sending request data or tokens before the server's certificate is
  verified, following a redirect, connecting to a host other than the
  documented provider hosts, or trusting a root that `Https` does not, beyond
  the [known limits](#known-limits);
- a dependency of the crate with a known vulnerability that affects it.

### Out of scope

An attacker who already controls the same OS user (through a debugger, the
user's files or keychain) or root is out of scope. Faults in OpenAI's service
itself belong to OpenAI, not here.

### Known limits

The API docs describe these limits as well:

- The browser opener receives the start link on its command line. Another
  local user who reads it while the sign-in waits can end the attempt or,
  when an account is being added, complete it with an account of their own.
  Signing an existing account in again rejects a different user, and the app
  should show the identity a new account signed in with. An app that shows
  `start_link()` for the user to copy, instead of calling `open_browser`,
  avoids the command line.
- `Client` and `protocol::Returning` default to no account hints. An app
  that calls `Returning::with_hints()` can put the ID token or e-mail address
  in the authorization URL, which anyone who opens its local start link can
  read. An app that drives the listener itself should leave hints disabled.
- `Ureq` is built on ureq, which behaves differently from `Https` in three
  respects this crate does not control. It accepts TLS 1.2 as well as
  TLS 1.3. With a logger installed and `TRACE` enabled for the `ureq` or
  `ureq_proto` targets, it logs request and response data, tokens included,
  and `DEBUG` logs selected headers; an app must leave both levels off while
  real accounts are in use. A cancellation or a deadline can wait for a blocked socket read to
  time out.
- `PrivateFiles` enforces owner-only permission bits on Unix but does not
  check macOS ACLs or Windows DACLs; `Sealed` with a keychain key keeps entry
  contents unreadable either way.
- `Sealed` proves that an entry was sealed under the store's key for that
  entry name, not that it is current or that the app wrote it. Anyone who can
  write the store directory can put back an older sealed entry, and
  `Keychain::open_sealed` seals every plain `installation` and `account-*`
  entry it finds on each open (`Sealed::seal_existing`), so a plain value
  written into the directory is sealed and then trusted. Such a writer
  already has the user's files and is [out of scope](#out-of-scope).

## Disclosure

A confirmed fault is fixed in a new release, then published as a security
advisory on the repository and in the RustSec advisory database, with credit
to the reporter if they want it.
