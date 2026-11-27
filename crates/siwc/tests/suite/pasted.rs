//! A pasted redirect: which text the user copies from the address bar
//! ends an attempt, and how.

use siwc::ErrorKind;
use siwc::protocol::{Accepted, Attempt, Callback, Registration};

use crate::support::provider::User;
use crate::support::wire::{form_decode, form_encode, only};
use crate::support::{PORT, World, answered};

/// The attempt's redirect address as the browser shows it.
const REDIRECT: &str = "http://127.0.0.1:53124/auth/callback";

/// An attempt and the address the provider sends the browser to after
/// approval.
fn approved(world: &World) -> (Attempt, String) {
    let attempt = world.attempt(Registration::New(&world.app));
    let query = world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());
    (attempt, format!("{REDIRECT}?{query}"))
}

fn kept(attempt: Attempt, pasted: &str) -> Attempt {
    match attempt.accept_redirect(pasted) {
        Callback::Unrelated(open) => open,
        Callback::Final(result) => panic!("{pasted:?} ended the attempt: {result:?}"),
    }
}

#[test]
fn the_redirect_address_with_surrounding_whitespace_and_a_fragment_completes_the_attempt() {
    let world = World::new();
    assert_eq!(
        world.attempt(Registration::New(&world.app)).redirect_uri(),
        REDIRECT
    );
    for dressed in ["{}", "  {}\r\n", "\t{}#", "{}#&state=elsewhere"] {
        let (attempt, address) = approved(&world);
        let pasted = dressed.replace("{}", &address);
        let accepted = answered(attempt.accept_redirect(&pasted)).unwrap();
        assert!(
            matches!(accepted, Accepted::NewRegistration(_)),
            "{dressed}"
        );
    }
}

#[test]
fn the_browser_can_omit_the_default_port_from_pasted_redirects() {
    let world = World::new();
    let attempt =
        Attempt::start(Registration::New(&world.app), None, 80, &siwc::OsEntropy).unwrap();
    let query = world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());
    let address = format!("http://127.0.0.1/auth/callback?{query}");
    assert!(answered(attempt.accept_redirect(&address)).is_ok());
}

#[test]
fn text_that_is_not_this_attempts_redirect_leaves_the_attempt_open() {
    let world = World::new();
    let (mut attempt, address) = approved(&world);
    let (_, address_of_another_attempt) = approved(&world);
    let query = address.split_once('?').unwrap().1;
    let without_state: String = query
        .split('&')
        .filter(|pair| !pair.starts_with("state="))
        .collect::<Vec<_>>()
        .join("&");
    let other_port = PORT + 1;

    for foreign in [
        String::new(),
        query.to_owned(),
        format!("?{query}"),
        REDIRECT.to_owned(),
        format!("{REDIRECT}{query}"),
        format!("{REDIRECT}/?{query}"),
        format!("{REDIRECT}x?{query}"),
        format!("http://127.0.0.1:{other_port}/auth/callback?{query}"),
        format!("http://127.0.0.1:5312/auth/callback?{query}"),
        format!("http://localhost:{PORT}/auth/callback?{query}"),
        format!("https://127.0.0.1:{PORT}/auth/callback?{query}"),
        format!("http://127.0.0.1:{PORT}/other?{query}"),
        format!("HTTP://127.0.0.1:{PORT}/auth/callback?{query}"),
        format!("x{address}"),
        format!("{address} {address}"),
        format!("{address}\"x"),
        format!("{REDIRECT}?{without_state}"),
        format!("{REDIRECT}?#{query}"),
        address_of_another_attempt,
    ] {
        attempt = kept(attempt, &foreign);
    }

    // None of them used the attempt up: its own redirect still completes it.
    assert!(answered(attempt.accept_redirect(&address)).is_ok());
}

#[test]
fn text_longer_than_eight_kibibytes_is_not_a_redirect() {
    let world = World::new();
    let limit = 8 * 1024;
    let padded = |address: &str, length: usize| {
        let padding = "a".repeat(length - address.len() - "&pad=".len());
        format!("{address}&pad={padding}")
    };

    let (attempt, address) = approved(&world);
    let attempt = kept(attempt, &padded(&address, limit + 1));
    let at_the_limit = format!("  {}  ", padded(&address, limit));
    assert!(answered(attempt.accept_redirect(&at_the_limit)).is_ok());
}

#[test]
fn a_pasted_decline_or_provider_error_ends_the_attempt() {
    let world = World::new();

    let attempt = world.attempt(Registration::New(&world.app));
    let query = world.provider.deny(attempt.authorization_url());
    let error = answered(attempt.accept_redirect(&format!("{REDIRECT}?{query}"))).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AccessDenied);

    let attempt = world.attempt(Registration::New(&world.app));
    let (_, request) = attempt.authorization_url().split_once('?').unwrap();
    let state = only(&form_decode(request), "state").to_owned();
    let failed = form_encode(&[("error", "server_error"), ("state", &state)]);
    let error = answered(attempt.accept_redirect(&format!("{REDIRECT}?{failed}"))).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthorizationFailed);
    assert_eq!(error.provider_code(), Some("server_error"));
}
