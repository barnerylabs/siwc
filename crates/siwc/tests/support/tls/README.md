# Test certificates for the HTTPS transport

Synthetic certificates for the end-to-end tests in `crates/siwc/src/https.rs`
and `crates/siwc/src/https/stream_tests.rs`.
They are trusted by those tests only, never by the transport itself, and their
keys protect nothing.

| File | What it is |
| --- | --- |
| `ca.pem` | A test CA, `CN=siwc test CA`. The direct TLS tests' root. |
| `server.key` | The ECDSA P-256 key of the server and proxy certificates (PKCS#8). |
| `server.pem` | `auth.openai.com`, issued by the test CA. |
| `wrong-name.pem` | `other.example`, issued by the test CA. |
| `unknown-issuer.pem` | `auth.openai.com`, issued by a second CA that is not checked in. |
| `proxy-ca.pem` | A second test CA, `CN=siwc test proxy CA`, for `https://` forward proxy tests. |
| `proxy.pem` | `proxy.example.invalid`, `proxy.homelab.invalid` and `127.0.0.1`, issued by `proxy-ca.pem` using `server.key`. |
| `self-signed-leaf.pem` | Self-signed `auth.openai.com` leaf (`CA:FALSE`), signed with `server.key`. |
| `self-signed-api-leaf.pem` | Self-signed `api.openai.com` leaf (`CA:FALSE`), signed with `server.key`, for the streamed plan requests in `crates/siwc/src/https/stream_tests.rs`. |
| `self-signed-ca-leaf.pem` | Self-signed `auth.openai.com` certificate with `CA:TRUE`, to verify WebPKI rejects a CA certificate used as a server leaf. |

The fixtures are valid from 1 January 2024 through 1 January 2076. The CA
private keys are not checked in. If replacing the shared server key, regenerate
all leaf fixtures in the table with ECDSA P-256 and the same names, issuing
CAs, and `BasicConstraints` values. Keep the unknown issuer's CA outside the
repository and discard all CA private keys after signing.
