//! The authorization request: what the browser is sent to the provider with.

use siwc::protocol::{Attempt, Registration, Returning};
use siwc::{AppName, Entropy, Error, ErrorKind};

use crate::support::provider::User;
use crate::support::{PORT, World};

#[test]
fn a_first_sign_in_registers_the_app_under_its_own_name() {
    let world = World::new();
    let attempt = world.attempt(Registration::New(&world.app));
    world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());

    let request = world.provider.last_seen();
    assert_eq!(request.field("client_id"), Some("dynamic_agent_client"));
    assert_eq!(request.field("agent_name_hint"), Some("Paste Perfect"));
    assert_eq!(
        request.field("ext_agent_host_id"),
        Some(world.host.as_str())
    );
    assert_eq!(
        request.field("redirect_uri"),
        Some("http://127.0.0.1:53124/auth/callback")
    );
    assert_eq!(
        attempt.redirect_uri(),
        "http://127.0.0.1:53124/auth/callback"
    );
    assert_eq!(world.provider.registered_names(), ["Paste Perfect"]);
}

#[test]
fn a_name_with_reserved_characters_reaches_the_provider_unchanged() {
    let mut world = World::new();
    world.app = AppName::new("Müller & Söhne: Notizen+ 100%").unwrap();
    let attempt = world.attempt(Registration::New(&world.app));
    world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());

    assert_eq!(
        world.provider.registered_names(),
        ["Müller & Söhne: Notizen+ 100%"]
    );
}

#[test]
fn a_later_sign_in_sends_the_saved_client_and_no_name() {
    let world = World::new();
    let first = world.sign_in(&User::alex());

    let returning = Returning::unfinished(first.client_id());
    let attempt = world.attempt(Registration::Saved(returning));
    world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());

    let request = world.provider.last_seen();
    assert_eq!(request.field("client_id"), Some(first.client_id().as_str()));
    assert_eq!(
        request.field("ext_agent_host_id"),
        Some(world.host.as_str())
    );
    for absent in ["agent_name_hint", "id_token_hint", "login_hint", "prompt"] {
        assert_eq!(request.field(absent), None, "{absent}");
    }
    assert_eq!(
        world.provider.registered_names().len(),
        1,
        "no second registration"
    );
}

#[test]
fn opting_in_to_hints_sends_both_for_a_signed_in_account() {
    let world = World::new();
    let first = world.sign_in(&User::alex());

    let returning = Returning::signed_in(first.identity(), first.credentials()).with_hints();
    let attempt = world.attempt(Registration::Saved(returning));
    world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());

    let request = world.provider.last_seen();
    assert_eq!(request.field("client_id"), Some(first.client_id().as_str()));
    assert_eq!(request.field("login_hint"), Some("alex@example.com"));
    assert_eq!(
        request
            .field("id_token_hint")
            .map(|token| token.split('.').count()),
        Some(3)
    );
}

#[test]
fn opting_in_to_hints_for_a_signed_out_account_sends_only_its_login_hint() {
    let world = World::new();
    let first = world.sign_in(&User::alex());

    let returning = Returning::signed_out(first.client_id(), first.identity()).with_hints();
    let attempt = world.attempt(Registration::Saved(returning));
    world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());

    let request = world.provider.last_seen();
    assert_eq!(request.field("login_hint"), Some("alex@example.com"));
    assert_eq!(request.field("id_token_hint"), None);
}

#[test]
fn a_returning_sign_in_sends_no_hints_by_default() {
    let world = World::new();
    let first = world.sign_in(&User::alex());
    for returning in [
        Returning::signed_in(first.identity(), first.credentials()),
        Returning::signed_out(first.client_id(), first.identity()),
        Returning::unfinished(first.client_id()),
    ] {
        let attempt = world.attempt(Registration::Saved(returning));
        world
            .provider
            .authorize(attempt.authorization_url(), &User::alex());
        let seen = world.provider.last_seen();
        assert_eq!(seen.field("id_token_hint"), None);
        assert_eq!(seen.field("login_hint"), None);
    }
}

#[test]
fn a_returning_sign_in_without_hints_sends_no_id_token_and_no_email() {
    let world = World::new();
    let first = world.sign_in(&User::alex());

    for returning in [
        Returning::signed_in(first.identity(), first.credentials()),
        Returning::signed_out(first.client_id(), first.identity()),
    ] {
        let attempt = world.attempt(Registration::Saved(
            returning.with_hints().without_hints().ask_consent(),
        ));
        world
            .provider
            .authorize(attempt.authorization_url(), &User::alex());

        let request = world.provider.last_seen();
        assert_eq!(request.field("client_id"), Some(first.client_id().as_str()));
        assert_eq!(request.field("id_token_hint"), None);
        assert_eq!(request.field("login_hint"), None);
        assert!(!attempt.authorization_url().contains("alex"));
        assert_eq!(request.field("prompt"), Some("consent"));
    }
}

#[test]
fn the_hints_of_two_accounts_cannot_be_combined() {
    let world = World::new();
    let alex = world.sign_in(&User::alex());
    let sam = world.sign_in(&User::sam());

    let mixed = Returning::signed_in(alex.identity(), sam.credentials());
    let error = Attempt::start_with_entropy(
        Registration::Saved(mixed),
        Some(&world.host),
        PORT,
        &world.entropy,
    )
    .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(
        error.to_string(),
        "the identity and the credentials belong to different accounts"
    );
}

#[test]
fn consent_is_only_asked_for_on_request() {
    let world = World::new();
    let first = world.sign_in(&User::alex().without_plan_use());

    let returning = Returning::signed_out(first.client_id(), first.identity()).ask_consent();
    let attempt = world.attempt(Registration::Saved(returning));
    world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());

    assert_eq!(world.provider.last_seen().field("prompt"), Some("consent"));
}

#[test]
fn every_attempt_has_its_own_state_nonce_and_challenge() {
    let world = World::new();
    for _ in 0..2 {
        let attempt = world.attempt(Registration::New(&world.app));
        world
            .provider
            .authorize(attempt.authorization_url(), &User::alex());
    }

    let seen = world.provider.seen();
    let mut values = Vec::new();
    for request in &seen {
        for name in ["state", "nonce", "code_challenge"] {
            values.push(request.field(name).unwrap().to_owned());
        }
    }
    let total = values.len();
    values.sort();
    values.dedup();
    assert_eq!(values.len(), total, "a value was used twice");
}

#[test]
fn port_zero_is_refused() {
    let world = World::new();
    let error = Attempt::start_with_entropy(
        Registration::New(&world.app),
        Some(&world.host),
        0,
        &world.entropy,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

#[test]
fn without_random_bytes_no_attempt_starts() {
    struct Dry;
    impl Entropy for Dry {
        fn fill(&self, _: &mut [u8]) -> Result<(), Error> {
            Err(Error::entropy_unavailable())
        }
    }

    let world = World::new();
    let error =
        Attempt::start_with_entropy(Registration::New(&world.app), Some(&world.host), PORT, &Dry)
            .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Randomness);
}
