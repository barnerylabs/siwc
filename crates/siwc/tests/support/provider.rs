//! An in-memory stand-in for the provider, written from the public protocol
//! description. It plays the browser side of authorization and answers the
//! token, revocation and key requests; it panics when a request breaks the
//! documented contract, so every test also checks the request shapes.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use serde_json::{Map, Value, json};
use siwc::Transport;
use siwc::protocol::{HttpRequest, HttpResponse};

use super::keys::{SigningKey, jwt};
use super::wire::{base64url, form_decode, form_encode, only, optional, sha256};

pub const ISSUER: &str = "https://auth.openai.com";
pub const AUTHORIZE_URL: &str = "https://auth.openai.com/api/accounts/authorize";
pub const TOKEN_URL: &str = "https://auth.openai.com/api/accounts/oauth/token";
pub const REVOKE_URL: &str = "https://auth.openai.com/api/accounts/oauth/revoke";
pub const JWKS_URL: &str = "https://auth.openai.com/.well-known/jwks.json";
pub const RESOURCE: &str = "https://api.openai.com/v1";
pub const FULL_SCOPE: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
pub const IDENTITY_SCOPE: &str = "openid profile email offline_access";
pub const MODELS_URL: &str = "https://api.openai.com/v1/models";

/// What the model list endpoint sends every account with plan use: two
/// listed models, one listed without a display name, and entries the client
/// has to drop.
pub fn model_list() -> Value {
    json!({ "models": [
        { "slug": "example-large", "display_name": "Example Large", "visibility": "list",
          "context_window": 1000 },
        { "slug": "example-preview", "display_name": "Example Preview", "visibility": "hide" },
        { "slug": "example-small", "display_name": "Example Small", "visibility": "list" },
        { "display_name": "No Slug", "visibility": "list" },
        { "slug": "example-mini", "visibility": "list" },
    ] })
}

/// A synthetic account and what it grants when asked.
#[derive(Clone)]
pub struct User {
    pub subject: &'static str,
    pub email: Option<&'static str>,
    pub name: Option<&'static str>,
    pub grant: &'static str,
}

impl User {
    pub fn alex() -> Self {
        Self {
            subject: "user-alex-0001",
            email: Some("alex@example.com"),
            name: Some("Alex Example"),
            grant: FULL_SCOPE,
        }
    }

    pub fn sam() -> Self {
        Self {
            subject: "user-sam-0002",
            email: Some("sam@example.com"),
            name: Some("Sam Example"),
            grant: FULL_SCOPE,
        }
    }

    pub fn kim() -> Self {
        Self {
            subject: "user-kim-0003",
            email: Some("kim@example.com"),
            name: Some("Kim Example"),
            grant: FULL_SCOPE,
        }
    }

    pub fn jo() -> Self {
        Self {
            subject: "user-jo-0004",
            email: Some("jo@example.com"),
            name: Some("Jo Example"),
            grant: FULL_SCOPE,
        }
    }

    pub fn without_plan_use(mut self) -> Self {
        self.grant = IDENTITY_SCOPE;
        self
    }
}

/// An ID token before signing; a test alters it to forge a token.
pub struct Draft {
    pub header: Map<String, Value>,
    pub claims: Map<String, Value>,
    pub signer: Signer,
}

pub enum Signer {
    /// The published key.
    Provider,
    /// A key that is not published, under the published key's ID.
    Other,
    /// No signature at all.
    Unsigned,
    /// HS256 keyed with the published public key.
    HmacWithPublicKey,
}

/// A request as any transport carries it: what the provider reads.
pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body: &'a [u8],
}

impl<'a> Request<'a> {
    pub fn of(request: &'a HttpRequest) -> Self {
        Self {
            method: request.method().as_str(),
            url: request.url(),
            headers: request.headers().collect(),
            body: request.body(),
        }
    }
}

/// The provider's answer: status, body and the synthetic request ID it
/// assigned, `req_synthetic_<n>`.
pub struct Answer {
    pub status: u16,
    pub body: Vec<u8>,
    pub request_id: String,
}

/// One request the provider saw, decoded.
#[derive(Clone)]
pub struct Seen {
    pub fields: Vec<(String, String)>,
}

impl Seen {
    pub fn field(&self, name: &str) -> Option<&str> {
        optional(&self.fields, name)
    }
}

type AlterToken = Box<dyn FnOnce(&mut Draft) + Send>;
type AlterResponse = Box<dyn FnOnce(&mut Map<String, Value>) + Send>;

struct Code {
    client_id: String,
    challenge: String,
    redirect_uri: String,
    nonce: String,
    user: User,
}

#[derive(Clone)]
struct Session {
    client_id: String,
    user: User,
}

#[derive(Default)]
struct State {
    now: u64,
    counter: u64,
    /// Issued client IDs with the name each was registered under.
    clients: Vec<(String, String)>,
    codes: HashMap<String, Code>,
    /// Refresh tokens ever issued; `None` once used or revoked.
    refresh_tokens: HashMap<String, Option<Session>>,
    seen: Vec<Seen>,
    fail_next: Option<(u16, String)>,
    /// Access tokens ever issued, with their expiry, grant and client.
    access_tokens: HashMap<String, (u64, &'static str, String)>,
    refuse_next_api: Option<(u16, String)>,
    /// Answers given so far; the latest one's request ID ends in it.
    answered: u64,
    alter_id_token: Option<AlterToken>,
    alter_response: Option<AlterResponse>,
    callback_names_saved_client: bool,
    callback_omits_issued_client: bool,
}

pub struct FakeProvider {
    key: SigningKey,
    other_key: SigningKey,
    state: Mutex<State>,
}

impl FakeProvider {
    pub fn new(now: u64) -> Self {
        Self {
            key: SigningKey::provider(),
            other_key: SigningKey::other(),
            state: Mutex::new(State {
                now,
                ..State::default()
            }),
        }
    }

    pub fn set_now(&self, now: u64) {
        self.state.lock().unwrap().now = now;
    }

    /// The next token, revocation or key request fails with this answer.
    pub fn fail_next(&self, status: u16, body: &str) {
        self.state.lock().unwrap().fail_next = Some((status, body.to_owned()));
    }

    /// The next API request is refused with this answer.
    pub fn refuse_next_api_request(&self, status: u16, body: &str) {
        self.state.lock().unwrap().refuse_next_api = Some((status, body.to_owned()));
    }

    /// Alters the next ID token before it is signed.
    pub fn alter_next_id_token(&self, alter: impl FnOnce(&mut Draft) + Send + 'static) {
        self.state.lock().unwrap().alter_id_token = Some(Box::new(alter));
    }

    /// Alters the next successful token response before it is sent.
    pub fn alter_next_response(
        &self,
        alter: impl FnOnce(&mut Map<String, Value>) + Send + 'static,
    ) {
        self.state.lock().unwrap().alter_response = Some(Box::new(alter));
    }

    /// Returning callbacks repeat the client ID, which the protocol allows.
    pub fn name_saved_client_in_callbacks(&self) {
        self.state.lock().unwrap().callback_names_saved_client = true;
    }

    /// First-registration callbacks leave the issued client ID out.
    pub fn omit_issued_client_in_callbacks(&self) {
        self.state.lock().unwrap().callback_omits_issued_client = true;
    }

    /// Every request seen so far, authorization requests included.
    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    pub fn last_seen(&self) -> Seen {
        self.seen().pop().expect("a request")
    }

    /// The names the app registered under, one per registration.
    pub fn registered_names(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .clients
            .iter()
            .map(|(_, name)| name.clone())
            .collect()
    }

    /// The client IDs issued so far, oldest first.
    pub fn issued_clients(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .clients
            .iter()
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// The client an access token was issued to; `None` for a token the
    /// provider never issued.
    pub fn owner_of(&self, access_token: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap()
            .access_tokens
            .get(access_token)
            .map(|(_, _, client_id)| client_id.clone())
    }

    /// The user opens `url` in the browser and approves as `user`. Returns
    /// the query of the redirect to the app's callback.
    pub fn authorize(&self, url: &str, user: &User) -> String {
        let params = self.authorization_request(url);
        let mut state = self.state.lock().unwrap();
        let requested = only(&params, "client_id");
        let (client_id, newly_issued) = if requested == "dynamic_agent_client" {
            let name = only(&params, "agent_name_hint");
            assert!(
                !name.trim().is_empty(),
                "a registration needs the app's name"
            );
            state.counter += 1;
            let issued = format!("app_issued{:04}", state.counter);
            state.clients.push((issued.clone(), name.to_owned()));
            (issued, true)
        } else {
            assert!(
                state.clients.iter().any(|(id, _)| id == requested),
                "unknown client {requested}"
            );
            assert!(
                optional(&params, "agent_name_hint").is_none(),
                "a saved registration keeps its name"
            );
            (requested.to_owned(), false)
        };
        state.counter += 1;
        let code = format!("code-{:04}", state.counter);
        state.codes.insert(
            code.clone(),
            Code {
                client_id: client_id.clone(),
                challenge: only(&params, "code_challenge").to_owned(),
                redirect_uri: only(&params, "redirect_uri").to_owned(),
                nonce: only(&params, "nonce").to_owned(),
                user: user.clone(),
            },
        );
        let mut answer = vec![("code", code.as_str()), ("state", only(&params, "state"))];
        let names_client = if newly_issued {
            !state.callback_omits_issued_client
        } else {
            state.callback_names_saved_client
        };
        if names_client {
            answer.push(("client_id", &client_id));
        }
        answer.push(("scope", user.grant));
        form_encode(&answer)
    }

    /// The user opens `url` and declines.
    pub fn deny(&self, url: &str) -> String {
        let params = self.authorization_request(url);
        form_encode(&[
            ("error", "access_denied"),
            ("state", only(&params, "state")),
        ])
    }

    /// Checks an authorization URL against the documented request and
    /// records it.
    fn authorization_request(&self, url: &str) -> Vec<(String, String)> {
        let (endpoint, query) = url.split_once('?').expect("a query");
        assert_eq!(endpoint, AUTHORIZE_URL);
        let params = form_decode(query);
        assert_eq!(only(&params, "response_type"), "code");
        assert_eq!(only(&params, "scope"), FULL_SCOPE);
        assert_eq!(only(&params, "resource"), RESOURCE);
        assert_eq!(only(&params, "code_challenge_method"), "S256");
        assert_eq!(only(&params, "code_challenge").len(), 43);
        assert!(
            only(&params, "state").len() >= 43,
            "state carries at least 256 bits"
        );
        assert!(
            only(&params, "nonce").len() >= 43,
            "nonce carries at least 256 bits"
        );
        // Sent unless the client is built with `send_host_id(false)`.
        if let Some(host) = params.iter().find(|(name, _)| name == "ext_agent_host_id") {
            assert!(host.1.starts_with("urn:uuid:"));
        }
        let redirect = only(&params, "redirect_uri");
        let port = redirect
            .strip_prefix("http://127.0.0.1:")
            .and_then(|rest| rest.strip_suffix("/auth/callback"))
            .expect("a loopback redirect uri");
        assert!(port.parse::<u16>().is_ok_and(|port| port > 0));
        self.state.lock().unwrap().seen.push(Seen {
            fields: params.clone(),
        });
        params
    }

    /// Answers a token, revocation, key or API request.
    pub fn send(&self, request: &HttpRequest) -> HttpResponse {
        let answer = self.answer(&Request::of(request));
        HttpResponse::new(answer.status, answer.body).with_request_id(Some(&answer.request_id))
    }

    /// Answers a request that arrived as its parts, for example from
    /// another process, under a request ID of its own.
    pub fn answer(&self, request: &Request<'_>) -> Answer {
        let mut answer = self.respond(request);
        let mut state = self.state.lock().unwrap();
        state.answered += 1;
        answer.request_id = format!("req_synthetic_{}", state.answered);
        answer
    }

    /// The request ID of the latest answer.
    pub fn last_request_id(&self) -> String {
        format!("req_synthetic_{}", self.state.lock().unwrap().answered)
    }

    fn respond(&self, request: &Request<'_>) -> Answer {
        if request.url.starts_with(RESOURCE) {
            return self.api(request);
        }
        let fields = form_decode(std::str::from_utf8(request.body).expect("a text body"));
        let mut state = self.state.lock().unwrap();
        state.seen.push(Seen {
            fields: fields.clone(),
        });
        if let Some((status, body)) = state.fail_next.take() {
            return Answer {
                status,
                body: body.into_bytes(),
                request_id: String::new(),
            };
        }
        let headers: Vec<_> = request.headers.clone();
        assert!(headers.contains(&("accept", "application/json")));
        match (request.method, request.url) {
            ("GET", JWKS_URL) => ok(&json!({ "keys": [self.key.jwk()] })),
            ("POST", TOKEN_URL) => {
                assert!(headers.contains(&("content-type", "application/x-www-form-urlencoded")));
                assert_eq!(only(&fields, "resource"), RESOURCE);
                match only(&fields, "grant_type") {
                    "authorization_code" => self.exchange(&mut state, &fields),
                    "refresh_token" => self.refresh(&mut state, &fields),
                    other => panic!("unsupported grant {other}"),
                }
            }
            ("POST", REVOKE_URL) => {
                assert_eq!(only(&fields, "token_type_hint"), "refresh_token");
                only(&fields, "client_id");
                if let Some(session) = state.refresh_tokens.get_mut(only(&fields, "token")) {
                    *session = None;
                }
                Answer {
                    status: 200,
                    body: Vec::new(),
                    request_id: String::new(),
                }
            }
            (method, url) => panic!("unexpected request {method} {url}"),
        }
    }

    /// Answers a request to the API, which takes the access token as a
    /// bearer header and nothing in the URL or body.
    fn api(&self, request: &Request<'_>) -> Answer {
        let mut state = self.state.lock().unwrap();
        assert!(!request.url.contains('?'), "the API takes no query");
        assert!(request.body.is_empty(), "a GET has no body");
        if let Some((status, body)) = state.refuse_next_api.take() {
            return Answer {
                status,
                body: body.into_bytes(),
                request_id: String::new(),
            };
        }
        let headers: Vec<_> = request.headers.clone();
        assert!(headers.contains(&("accept", "application/json")));
        let bearers: Vec<_> = headers
            .iter()
            .filter(|(name, _)| *name == "authorization")
            .map(|(_, value)| value.strip_prefix("Bearer ").expect("a bearer token"))
            .collect();
        let [token] = bearers[..] else {
            panic!("an API request carries exactly one authorization header");
        };
        let grant = match state.access_tokens.get(token) {
            Some(&(expires, grant, _)) if expires > state.now => grant,
            _ => {
                let body = json!({ "error": {
                    "code": "subscription_sharing_invalid_user",
                    "message": "synthetic: the token is unknown or expired",
                } });
                return error(401, &body);
            }
        };
        if !grant.contains("chatgpt.tokens.use.direct") {
            let body = json!({ "error": { "code": "chatpass_v2_scope_not_authorized" } });
            return error(403, &body);
        }
        match (request.method, request.url) {
            ("GET", MODELS_URL) => ok(&model_list()),
            (method, url) => panic!("unexpected API request {method} {url}"),
        }
    }

    fn exchange(&self, state: &mut State, fields: &[(String, String)]) -> Answer {
        let Some(code) = state.codes.remove(only(fields, "code")) else {
            return error(400, &json!({ "error": "invalid_grant" }));
        };
        let challenge = base64url(&sha256(only(fields, "code_verifier").as_bytes()));
        let matches = code.client_id == only(fields, "client_id")
            && code.redirect_uri == only(fields, "redirect_uri")
            && code.challenge == challenge;
        if !matches {
            return error(400, &json!({ "error": "invalid_grant" }));
        }
        let session = Session {
            client_id: code.client_id,
            user: code.user,
        };
        self.issue(state, session, Some(&code.nonce))
    }

    fn refresh(&self, state: &mut State, fields: &[(String, String)]) -> Answer {
        assert!(
            optional(fields, "scope").is_none(),
            "a refresh keeps the grant"
        );
        let session = match state.refresh_tokens.get_mut(only(fields, "refresh_token")) {
            None => return error(400, &json!({ "error": "invalid_grant" })),
            Some(used) => used.take(),
        };
        let Some(session) = session else {
            let body = json!({ "error": { "code": "refresh_token_reused", "message": "used" } });
            return error(400, &body);
        };
        if session.client_id != only(fields, "client_id") {
            return error(401, &json!({ "error": "invalid_client" }));
        }
        self.issue(state, session, None)
    }

    fn issue(&self, state: &mut State, session: Session, nonce: Option<&str>) -> Answer {
        state.counter += 1;
        let access = format!("access-{:04}", state.counter);
        let refresh = format!("refresh-{:04}", state.counter);
        let user = session.user.clone();

        let mut claims = Map::new();
        claims.insert("iss".into(), json!(ISSUER));
        claims.insert("aud".into(), json!(session.client_id));
        claims.insert("sub".into(), json!(user.subject));
        claims.insert("iat".into(), json!(state.now));
        claims.insert("exp".into(), json!(state.now + 3600));
        claims.insert("sid".into(), json!("session-0001"));
        claims.insert("email_verified".into(), json!(user.email.is_some()));
        for (name, value) in [("nonce", nonce), ("email", user.email), ("name", user.name)] {
            if let Some(value) = value {
                claims.insert(name.into(), json!(value));
            }
        }
        let mut header = Map::new();
        header.insert("alg".into(), json!("RS256"));
        header.insert("typ".into(), json!("JWT"));
        header.insert("kid".into(), json!(self.key.id));
        let mut draft = Draft {
            header,
            claims,
            signer: Signer::Provider,
        };
        if let Some(alter) = state.alter_id_token.take() {
            alter(&mut draft);
        }
        let id_token = jwt(
            &Value::Object(draft.header),
            &Value::Object(draft.claims),
            |signed| match draft.signer {
                Signer::Provider => self.key.sign(signed),
                Signer::Other => self.other_key.sign(signed),
                Signer::Unsigned => Vec::new(),
                Signer::HmacWithPublicKey => self.key.hmac_with_public_key(signed),
            },
        );

        state.access_tokens.insert(
            access.clone(),
            (state.now + 3600, user.grant, session.client_id.clone()),
        );
        state.refresh_tokens.insert(refresh.clone(), Some(session));
        let mut body = Map::new();
        body.insert("access_token".into(), json!(access));
        body.insert("refresh_token".into(), json!(refresh));
        body.insert("id_token".into(), json!(id_token));
        body.insert("token_type".into(), json!("Bearer"));
        body.insert("expires_in".into(), json!(3600));
        body.insert("scope".into(), json!(user.grant));
        body.insert("earliest_refresh_at".into(), json!("synthetic-earliest"));
        if let Some(alter) = state.alter_response.take() {
            alter(&mut body);
        }
        ok(&Value::Object(body))
    }
}

fn ok(body: &Value) -> Answer {
    Answer {
        status: 200,
        body: body.to_string().into_bytes(),
        request_id: String::new(),
    }
}

fn error(status: u16, body: &Value) -> Answer {
    Answer {
        status,
        body: body.to_string().into_bytes(),
        request_id: String::new(),
    }
}

/// The provider as the network: every request is answered in memory.
impl Transport for FakeProvider {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, siwc::Error> {
        Ok(FakeProvider::send(self, request))
    }
}

impl fmt::Debug for FakeProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FakeProvider")
    }
}
