//! ID token verification: every way a token can fail to prove the identity.

use serde_json::{Value, json};
use siwc::protocol::{HttpResponse, Jwks, Registration, Returning};
use siwc::{Error, ErrorKind};

use crate::support::keys::SigningKey;
use crate::support::provider::{Draft, Signer, User};
use crate::support::wire::{base64url, base64url_decode};
use crate::support::{NOW, World, answered, saved};

/// Signs in with an ID token the test altered before it was signed.
fn sign_in_with(alter: impl FnOnce(&mut Draft) + Send + 'static) -> Result<String, Error> {
    let world = World::new();
    world.provider.alter_next_id_token(alter);
    let exchange = world.authorized(&User::alex());
    world
        .finish(exchange)
        .map(|signed_in| signed_in.identity().subject().to_owned())
}

fn rejection(alter: impl FnOnce(&mut Draft) + Send + 'static) -> String {
    let error = sign_in_with(alter).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::IdentityRejected, "{error}");
    error.to_string()
}

fn claim(name: &'static str, value: Value) -> impl FnOnce(&mut Draft) + Send + 'static {
    move |draft| drop(draft.claims.insert(name.to_owned(), value))
}

fn without(name: &'static str) -> impl FnOnce(&mut Draft) + Send + 'static {
    move |draft| drop(draft.claims.remove(name))
}

#[test]
fn claims_changed_after_signing_are_rejected() {
    let world = World::new();
    world.provider.alter_next_response(|body| {
        let token = body["id_token"].as_str().unwrap().to_owned();
        let mut segments: Vec<&str> = token.split('.').collect();
        let mut claims: Value = serde_json::from_slice(&base64url_decode(segments[1])).unwrap();
        claims["sub"] = json!("user-sam-0002");
        let forged = base64url(claims.to_string().as_bytes());
        segments[1] = &forged;
        body.insert("id_token".into(), json!(segments.join(".")));
    });
    let exchange = world.authorized(&User::alex());

    let error = world.finish(exchange).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::IdentityRejected);
    assert_eq!(error.to_string(), "the ID token signature is invalid");
}

#[test]
fn a_token_signed_with_an_unpublished_key_is_rejected() {
    assert_eq!(
        rejection(|draft| draft.signer = Signer::Other),
        "the ID token signature is invalid"
    );
}

#[test]
fn a_token_naming_an_unpublished_key_is_rejected() {
    let message = rejection(|draft| {
        draft.signer = Signer::Other;
        draft.header.insert("kid".into(), json!("other-key-1"));
    });
    assert_eq!(message, "no published key matches the ID token");
}

#[test]
fn only_rs256_is_accepted() {
    let unsigned = rejection(|draft| {
        draft.signer = Signer::Unsigned;
        draft.header.insert("alg".into(), json!("none"));
    });
    assert_eq!(unsigned, "the ID token is not signed with RS256");

    let confused = rejection(|draft| {
        draft.signer = Signer::HmacWithPublicKey;
        draft.header.insert("alg".into(), json!("HS256"));
    });
    assert_eq!(confused, "the ID token is not signed with RS256");

    for alg in [
        json!("RS384"),
        json!("rs256"),
        json!(null),
        json!(["RS256"]),
    ] {
        let message = rejection(move |draft| drop(draft.header.insert("alg".into(), alg)));
        assert_eq!(message, "the ID token is not signed with RS256");
    }
}

#[test]
fn an_rs256_header_does_not_make_another_signature_valid() {
    for signer in [Signer::Unsigned, Signer::HmacWithPublicKey] {
        assert_eq!(
            rejection(move |draft| draft.signer = signer),
            "the ID token signature is invalid"
        );
    }
}

#[test]
fn a_critical_extension_is_rejected() {
    let message = rejection(|draft| drop(draft.header.insert("crit".into(), json!(["exp"]))));
    assert_eq!(message, "the ID token requires an unknown extension");
}

#[test]
fn another_issuer_is_rejected() {
    for issuer in [
        "https://auth.example.com",
        "https://auth.openai.com/",
        "http://auth.openai.com",
    ] {
        assert_eq!(
            rejection(claim("iss", json!(issuer))),
            "the ID token comes from another issuer"
        );
    }
    assert_eq!(
        rejection(without("iss")),
        "the ID token comes from another issuer"
    );
}

#[test]
fn a_token_for_another_client_is_rejected() {
    let other = "the ID token was issued to another client";
    assert_eq!(rejection(claim("aud", json!("app_issued9999"))), other);
    assert_eq!(rejection(claim("aud", json!(["app_issued9999"]))), other);
    assert_eq!(
        rejection(claim("aud", json!(["app_issued0001", "app_issued9999"]))),
        other
    );
    assert_eq!(rejection(claim("azp", json!("app_issued9999"))), other);
    assert_eq!(rejection(claim("aud", json!(17))), other);
    assert_eq!(rejection(without("aud")), other);
}

#[test]
fn the_client_has_to_be_the_only_audience_and_the_authorized_party() {
    assert!(sign_in_with(claim("aud", json!(["app_issued0001"]))).is_ok());
    assert!(sign_in_with(claim("azp", json!("app_issued0001"))).is_ok());

    let another_client = "the ID token was issued to another client";
    assert_eq!(
        rejection(|draft| {
            draft
                .claims
                .insert("aud".into(), json!(["app_issued0001", "app_issued9999"]));
            draft.claims.insert("azp".into(), json!("app_issued0001"));
        }),
        another_client
    );
    for azp in [
        json!("app_issued9999"),
        json!(["app_issued0001"]),
        json!(null),
    ] {
        assert_eq!(rejection(claim("azp", azp)), another_client);
    }
    assert_eq!(rejection(claim("aud", json!([]))), another_client);
}

#[test]
fn an_expired_token_is_rejected_beyond_a_minute_of_clock_skew() {
    assert_eq!(
        rejection(claim("exp", json!(NOW - 60))),
        "the ID token has expired"
    );
    assert!(sign_in_with(claim("exp", json!(NOW - 59))).is_ok());
    assert!(sign_in_with(claim("exp", json!(NOW as f64 + 0.5))).is_ok());
}

#[test]
fn a_token_from_the_future_is_rejected_beyond_a_minute_of_clock_skew() {
    assert_eq!(
        rejection(claim("iat", json!(NOW + 61))),
        "the ID token is not valid yet"
    );
    assert_eq!(
        rejection(claim("nbf", json!(NOW + 61))),
        "the ID token is not valid yet"
    );
    assert!(sign_in_with(claim("iat", json!(NOW + 60))).is_ok());
    assert!(sign_in_with(claim("nbf", json!(NOW + 60))).is_ok());
}

#[test]
fn missing_or_mistyped_dates_are_rejected() {
    let malformed = "the ID token is malformed";
    assert_eq!(rejection(without("exp")), malformed);
    assert_eq!(rejection(without("iat")), malformed);
    assert_eq!(rejection(claim("exp", json!("tomorrow"))), malformed);
    assert_eq!(rejection(claim("exp", json!(-5))), malformed);
    assert_eq!(rejection(claim("exp", json!(1.0e300))), malformed);
    assert_eq!(rejection(claim("nbf", json!("yesterday"))), malformed);
    assert_eq!(rejection(claim("nbf", json!(-5))), malformed);
}

#[test]
fn a_token_for_another_attempt_is_rejected() {
    let another = "the ID token belongs to another sign-in attempt";
    assert_eq!(
        rejection(claim("nonce", json!("a-nonce-from-elsewhere"))),
        another
    );
    assert_eq!(rejection(without("nonce")), another);
}

#[test]
fn a_token_without_a_subject_is_rejected() {
    let nameless = "the ID token names no subject";
    assert_eq!(rejection(claim("sub", json!(""))), nameless);
    assert_eq!(rejection(claim("sub", json!(42))), nameless);
    assert_eq!(rejection(claim("sub", json!("s".repeat(256)))), nameless);
    assert_eq!(rejection(without("sub")), nameless);
}

#[test]
fn a_subject_of_other_than_255_printable_ascii_characters_at_most_is_rejected() {
    let nameless = "the ID token names no subject";
    for subject in [
        "\u{e4}".repeat(100),
        "user\nalex".to_owned(),
        "user\u{7f}".to_owned(),
    ] {
        assert_eq!(
            rejection(claim("sub", json!(subject))),
            nameless,
            "{subject:?}"
        );
    }
    assert!(sign_in_with(claim("sub", json!("s".repeat(255)))).is_ok());
}

#[test]
fn an_empty_session_id_is_rejected_and_a_missing_one_is_fine() {
    assert_eq!(
        rejection(claim("sid", json!(""))),
        "the ID token is malformed"
    );
    assert_eq!(
        rejection(claim("sid", json!(7))),
        "the ID token is malformed"
    );
    assert!(sign_in_with(without("sid")).is_ok());
}

#[test]
fn text_that_is_no_signed_jwt_is_rejected() {
    let world = World::new();
    for (token, message) in [
        ("only.two".to_owned(), "the ID token is not a signed JWT"),
        ("a.b.c.d".to_owned(), "the ID token is not a signed JWT"),
        ("!.!.!".to_owned(), "the ID token is malformed"),
        (
            format!("{}.e30.c2ln", base64url(b"[]")),
            "the ID token is malformed",
        ),
    ] {
        world
            .provider
            .alter_next_response(move |body| drop(body.insert("id_token".into(), json!(token))));
        let exchange = world.authorized(&User::alex());

        let error = world.finish(exchange).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::IdentityRejected);
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn display_claims_are_optional_and_bounded() {
    let world = World::new();
    world.provider.alter_next_id_token(|draft| {
        draft.claims.remove("email");
        draft.claims.remove("email_verified");
        draft.claims.insert("name".into(), json!("n".repeat(513)));
        draft
            .claims
            .insert("picture".into(), json!("https://example.com/alex.png"));
    });
    let signed_in = world.sign_in(&User::alex());

    let identity = signed_in.identity();
    assert_eq!(identity.email(), None);
    assert!(!identity.email_verified());
    assert_eq!(identity.name(), None);
    assert_eq!(identity.picture(), Some("https://example.com/alex.png"));
}

#[test]
fn display_claims_with_disallowed_characters_or_non_https_pictures_are_dropped() {
    let world = World::new();
    for bad in [
        "Alex\nExample",
        "Alex\u{202E}elpmaxE",
        "Alex\u{200B}Example",
        "\u{FEFF}Alex",
    ] {
        world.provider.alter_next_id_token(move |draft| {
            draft.claims.insert("name".into(), json!(bad));
            draft.claims.insert("email".into(), json!(bad));
        });
        let signed_in = world.sign_in(&User::alex());
        assert_eq!(signed_in.identity().name(), None, "{bad:?}");
        assert_eq!(signed_in.identity().email(), None, "{bad:?}");
    }

    for bad_url in [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "http://example.com/alex.png",
        "data:image/png;base64,AAAA",
        "https://",
        "https://example.com/alex .png",
        "https://example.com/alex\n.png",
        "https://example.com/\u{202E}gnp.xela",
    ] {
        world.provider.alter_next_id_token(move |draft| {
            draft.claims.insert("picture".into(), json!(bad_url));
        });
        let signed_in = world.sign_in(&User::alex());
        assert_eq!(signed_in.identity().picture(), None, "{bad_url:?}");
    }
}

#[test]
fn signing_in_again_to_an_account_rejects_any_other_account() {
    let world = World::new();
    let alex = world.sign_in(&User::alex());

    let returning = Returning::signed_out(alex.client_id(), alex.identity());
    let attempt = world.attempt(Registration::Saved(returning));
    let query = world
        .provider
        .authorize(attempt.authorization_url(), &User::sam());
    let error = world
        .finish(saved(answered(attempt.accept(&query)).unwrap()))
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::AccountMismatch);
    assert_eq!(
        error.to_string(),
        "the browser signed in to a different account"
    );
}

#[test]
fn signing_in_again_to_the_same_account_succeeds() {
    let world = World::new();
    let alex = world.sign_in(&User::alex());

    let returning = Returning::signed_out(alex.client_id(), alex.identity());
    let attempt = world.attempt(Registration::Saved(returning));
    let query = world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());
    let again = world
        .finish(saved(answered(attempt.accept(&query)).unwrap()))
        .unwrap();

    assert_eq!(again.identity(), alex.identity());
    assert_eq!(again.client_id(), alex.client_id());
}

fn key_set(keys: &Value) -> Jwks {
    Jwks::from_response(&HttpResponse::new(200, keys.to_string().into_bytes())).unwrap()
}

/// Verifies a normal sign-in against `keys` instead of the provider's set.
fn verified_against(
    keys: &Jwks,
    alter: impl FnOnce(&mut Draft) + Send + 'static,
) -> Result<(), Error> {
    let world = World::new();
    world.provider.alter_next_id_token(alter);
    let exchange = world.authorized(&User::alex());
    let response = world.provider.send(&exchange.request());
    exchange
        .response(response, world.now())?
        .verify(keys, world.now())
        .map(drop)
}

#[test]
fn keys_that_cannot_sign_rs256_are_skipped() {
    let provider = SigningKey::provider().jwk();
    let mut encryption = provider.clone();
    encryption["use"] = json!("enc");
    let mut other_algorithm = provider.clone();
    other_algorithm["alg"] = json!("RS512");
    let mut elliptic = provider.clone();
    elliptic["kty"] = json!("EC");
    let mut broken = provider.clone();
    broken["n"] = json!("not base64url!");

    let unusable = key_set(&json!({ "keys": [encryption, other_algorithm, elliptic, broken, 7] }));
    let error = verified_against(&unusable, |_| {}).unwrap_err();
    assert_eq!(error.to_string(), "no published key matches the ID token");
    assert!(verified_against(&key_set(&json!({ "keys": [provider] })), |_| {}).is_ok());
}

#[test]
fn keys_that_cannot_sign_do_not_crowd_out_the_one_that_can() {
    let mut elliptic = SigningKey::provider().jwk();
    elliptic["kty"] = json!("EC");
    let mut keys = vec![elliptic; 40];
    keys.push(SigningKey::provider().jwk());

    assert!(verified_against(&key_set(&json!({ "keys": keys })), |_| {}).is_ok());
}

#[test]
fn a_token_without_a_key_id_needs_a_set_with_one_key() {
    let provider = SigningKey::provider().jwk();
    let other = SigningKey::other().jwk();
    let drop_key_id = |draft: &mut Draft| drop(draft.header.remove("kid"));

    assert!(verified_against(&key_set(&json!({ "keys": [provider] })), drop_key_id).is_ok());
    for invalid in [json!(42), json!(null), json!("")] {
        let error = verified_against(&key_set(&json!({ "keys": [provider] })), |draft| {
            drop(draft.header.insert("kid".into(), invalid));
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "the ID token is malformed");
    }
    let error =
        verified_against(&key_set(&json!({ "keys": [other, provider] })), drop_key_id).unwrap_err();
    assert_eq!(error.to_string(), "no published key matches the ID token");
}

#[test]
fn a_key_with_a_leading_zero_byte_still_verifies() {
    let mut padded = SigningKey::provider().jwk();
    let mut modulus = vec![0u8];
    modulus.extend(base64url_decode(padded["n"].as_str().unwrap()));
    padded["n"] = json!(base64url(&modulus));

    assert!(verified_against(&key_set(&json!({ "keys": [padded] })), |_| {}).is_ok());
}

#[test]
fn a_matching_key_after_an_earlier_key_with_the_same_id_still_verifies() {
    let valid = SigningKey::provider().jwk();
    let mut stale = SigningKey::other().jwk();
    stale["kid"] = valid["kid"].clone();

    assert!(verified_against(&key_set(&json!({ "keys": [stale.clone(), valid] })), |_| {}).is_ok());
    let error = verified_against(&key_set(&json!({ "keys": [stale] })), |_| {}).unwrap_err();
    assert_eq!(error.to_string(), "the ID token signature is invalid");
}

#[test]
fn an_answer_that_is_no_key_set_is_reported() {
    for (status, body, kind) in [
        (503, "", ErrorKind::Temporary),
        (429, "", ErrorKind::Temporary),
        (404, "{}", ErrorKind::InvalidResponse),
        (200, "<html>", ErrorKind::InvalidResponse),
        (200, "{}", ErrorKind::InvalidResponse),
        (200, r#"{"keys":{}}"#, ErrorKind::InvalidResponse),
    ] {
        let error = Jwks::from_response(&HttpResponse::new(status, body.into())).unwrap_err();
        assert_eq!(error.kind(), kind, "{status} {body}");
    }
}
