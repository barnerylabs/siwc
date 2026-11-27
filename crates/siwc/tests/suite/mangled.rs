//! Answers and stored data with random damage: whatever arrives, nothing
//! panics, and no damage changes who is signed in.
//!
//! The curated cases live with their subjects; these tests add what nobody
//! thought of. Every run makes the same edits.

use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};
use siwc::protocol::{Attempt, Exchange, HttpResponse, Jwks, Registration, SignedIn};
use siwc::{Error, ErrorKind};

use crate::support::keys::SigningKey;
use crate::support::provider::User;
use crate::support::random::{Generator, Seeded};
use crate::support::rig::Rig;
use crate::support::{PORT, World, answered, saved};

/// Characters that mean something in JSON, to insert where they hurt.
const JSON: &[u8] = b"{}[]\",:0\\nu ";

/// One sign-in that can be played again: the same attempt as often as it is
/// asked for, and the callback, token answer and keys that belong to it.
struct Replay {
    world: World,
    query: String,
    answer: Map<String, Value>,
    keys: Jwks,
}

impl Replay {
    const SEED: u64 = 99;

    fn new() -> Self {
        let world = World::new();
        let attempt = Self::attempt(&world);
        let query = world
            .provider
            .authorize(attempt.authorization_url(), &User::alex());
        let exchange = saved(answered(attempt.accept(&query)).unwrap());
        let answer = next_answer(&world, || {
            drop(world.provider.send(&exchange.request()));
        });
        let keys = world.keys();
        Self {
            world,
            query,
            answer,
            keys,
        }
    }

    /// The same entropy every time, so the same `state`, nonce and verifier.
    fn attempt(world: &World) -> Attempt {
        Attempt::start_with_entropy(
            Registration::New(&world.app),
            Some(&world.host),
            PORT,
            &Seeded::new(Self::SEED),
        )
        .unwrap()
    }

    fn exchange(&self) -> Exchange {
        saved(answered(Self::attempt(&self.world).accept(&self.query)).unwrap())
    }

    /// Reads `body` as the token answer and verifies it with `keys`.
    fn finish(&self, body: Vec<u8>, keys: &Jwks) -> Result<SignedIn, Error> {
        self.exchange()
            .response(HttpResponse::new(200, body), self.world.now())?
            .verify(keys, self.world.now())
    }

    fn answer_bytes(&self) -> Vec<u8> {
        Value::Object(self.answer.clone()).to_string().into_bytes()
    }
}

/// The body of the next successful token answer the provider sends while
/// `request` runs.
fn next_answer(world: &World, request: impl FnOnce()) -> Map<String, Value> {
    let seen = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&seen);
    world
        .provider
        .alter_next_response(move |body| *slot.lock().unwrap() = Some(body.clone()));
    request();
    seen.lock().unwrap().take().unwrap()
}

#[test]
fn a_replayed_sign_in_verifies_so_the_tests_below_start_from_a_valid_one() {
    let replay = Replay::new();
    for _ in 0..2 {
        let signed_in = replay.finish(replay.answer_bytes(), &replay.keys).unwrap();
        assert_eq!(signed_in.identity().subject(), User::alex().subject);
    }
}

#[test]
fn a_damaged_token_answer_never_panics_and_never_changes_who_signed_in() {
    let replay = Replay::new();
    let valid = replay.answer_bytes();
    let mut generator = Generator::new(51);
    let (mut signed_in, mut refused) = (0, 0);
    for _ in 0..600 {
        match replay.finish(generator.mangle(&valid, JSON), &replay.keys) {
            Ok(done) => {
                assert_eq!(done.identity().subject(), User::alex().subject);
                assert_eq!(done.credentials().subject(), User::alex().subject);
                signed_in += 1;
            }
            Err(error) => {
                assert!(
                    matches!(
                        error.kind(),
                        ErrorKind::InvalidResponse | ErrorKind::IdentityRejected
                    ),
                    "{error:?}"
                );
                refused += 1;
            }
        }
    }
    // Damage to a member nobody reads leaves a valid answer.
    assert!(signed_in > 0 && refused > 0, "{signed_in} / {refused}");
}

#[test]
fn every_changed_character_of_an_id_token_is_refused() {
    let replay = Replay::new();
    let token = replay.answer["id_token"].as_str().unwrap().to_owned();
    assert_eq!(token.matches('.').count(), 2);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for at in 0..token.len() {
        let mut changed = token.clone().into_bytes();
        // The neighbour that differs in the lowest bit: at the end of a
        // segment that bit is beyond the last byte, where a lenient decoder
        // would not look.
        changed[at] = match alphabet.iter().position(|&c| c == changed[at]) {
            Some(index) => alphabet[index ^ 1],
            None => b'A',
        };
        let mut answer = replay.answer.clone();
        answer.insert(
            "id_token".to_owned(),
            json!(String::from_utf8(changed).unwrap()),
        );
        let body = Value::Object(answer).to_string().into_bytes();

        let error = replay.finish(body, &replay.keys).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::IdentityRejected, "character {at}");
    }
}

#[test]
fn a_damaged_key_set_never_panics_and_never_verifies_another_identity() {
    let replay = Replay::new();
    let valid = json!({ "keys": [SigningKey::provider().jwk()] })
        .to_string()
        .into_bytes();
    let mut generator = Generator::new(52);
    let (mut usable, mut unusable) = (0, 0);
    for _ in 0..600 {
        let body = generator.mangle(&valid, JSON);
        let Ok(keys) = Jwks::from_response(&HttpResponse::new(200, body)) else {
            unusable += 1;
            continue;
        };
        match replay.finish(replay.answer_bytes(), &keys) {
            Ok(done) => {
                assert_eq!(done.identity().subject(), User::alex().subject);
                usable += 1;
            }
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::IdentityRejected, "{error:?}");
                unusable += 1;
            }
        }
    }
    assert!(usable > 0 && unusable > 0, "{usable} / {unusable}");
}

#[test]
fn a_damaged_refresh_answer_never_panics_and_keeps_the_account_it_is_for() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex());
    let credentials = signed_in.credentials();
    let request = credentials.refresh_request().unwrap();
    let valid = Value::Object(next_answer(&world, || {
        drop(world.provider.send(&request));
    }))
    .to_string()
    .into_bytes();

    let mut generator = Generator::new(53);
    let (mut renewed, mut refused) = (0, 0);
    for _ in 0..600 {
        let body = generator.mangle(&valid, JSON);
        match credentials.refreshed(HttpResponse::new(200, body), world.now()) {
            Ok(successor) => {
                assert_eq!(successor.subject(), credentials.subject());
                assert_eq!(successor.client_id(), credentials.client_id());
                renewed += 1;
            }
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::InvalidResponse, "{error:?}");
                refused += 1;
            }
        }
    }
    assert!(renewed > 0 && refused > 0, "{renewed} / {refused}");

    // A refusal's body is read for its code and nothing else.
    for status in [400, 401, 403, 429, 500, 503] {
        for _ in 0..100 {
            let body = generator.mangle(
                br#"{"error":"invalid_grant","error_description":"x"}"#,
                JSON,
            );
            let response = HttpResponse::new(status, body.clone());
            assert!(credentials.refreshed(response, world.now()).is_err());
            let response = HttpResponse::new(status, body);
            assert!(credentials.revocation_confirmed(&response).is_err());
        }
    }
}

#[test]
fn a_damaged_installation_record_never_panics_and_is_never_rewritten_or_sent() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let valid = rig.store.bytes("installation").unwrap();
    let mut generator = Generator::new(54);
    let (mut readable, mut corrupt) = (0, 0);
    for _ in 0..400 {
        let damaged = generator.mangle(&valid, JSON);
        rig.store.put("installation", &damaged);
        rig.journal.clear();

        let client = &rig.client;
        let kinds = [
            client.accounts().err(),
            client.account(alex.id()).err(),
            client.access_token(alex.id()).err(),
        ]
        .map(|error| error.map(|error| error.kind()));
        if kinds.contains(&Some(ErrorKind::StoreCorrupt)) {
            corrupt += 1;
        } else {
            readable += 1;
        }
        for kind in kinds.into_iter().flatten() {
            assert!(
                matches!(
                    kind,
                    ErrorKind::StoreCorrupt | ErrorKind::UnknownAccount | ErrorKind::SignInRequired
                ),
                "{kind:?}"
            );
        }
        assert_eq!(rig.store.bytes("installation").unwrap(), damaged);
        assert!(rig.journal.about("write").is_empty());
        assert!(rig.journal.about("send").is_empty());
    }
    assert!(readable > 0 && corrupt > 0, "{readable} / {corrupt}");
}
