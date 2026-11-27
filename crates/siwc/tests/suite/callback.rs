//! Callback validation: which redirects end an attempt, and how.

use siwc::ErrorKind;
use siwc::protocol::{Accepted, Attempt, Callback, Registration, Returning};

use crate::support::provider::User;
use crate::support::random::Generator;
use crate::support::wire::{form_decode, only};
use crate::support::{World, answered, saved};

/// An attempt and the query the provider redirects with after approval.
fn approved(world: &World) -> (Attempt, String) {
    let attempt = world.attempt(Registration::New(&world.app));
    let query = world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());
    (attempt, query)
}

fn state_of(attempt: &Attempt) -> String {
    let (_, query) = attempt.authorization_url().split_once('?').unwrap();
    only(&form_decode(query), "state").to_owned()
}

fn rejection(attempt: Attempt, query: &str) -> String {
    let error = answered(attempt.accept(query)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CallbackRejected, "{error}");
    error.to_string()
}

#[test]
fn a_request_without_this_attempts_state_leaves_the_attempt_open() {
    let world = World::new();
    let (mut attempt, query) = approved(&world);
    let (_, callback_of_another_attempt) = approved(&world);
    let state = state_of(&attempt);

    for foreign in [
        String::new(),
        "state=".to_owned(),
        "code=x".to_owned(),
        "state=%zz".to_owned(),
        callback_of_another_attempt,
        format!("state={state}x"),
        format!("state={}", &state[1..]),
        format!("state={state}&state={state}"),
        format!("state={state}&code=%zz"),
    ] {
        attempt = match attempt.accept(&foreign) {
            Callback::Unrelated(open) => open,
            Callback::Final(result) => panic!("{foreign:?} ended the attempt: {result:?}"),
        };
    }

    // None of them used the attempt up: its own callback still completes it.
    assert!(answered(attempt.accept(&query)).is_ok());
}

#[test]
fn an_approved_first_sign_in_yields_the_issued_client_id() {
    let world = World::new();
    let (attempt, query) = approved(&world);

    let Accepted::NewRegistration(registration) = answered(attempt.accept(&query)).unwrap() else {
        panic!("a first sign-in registers the app");
    };
    assert!(registration.client_id().as_str().starts_with("app_issued"));
    assert_eq!(
        registration.client_id().clone(),
        *registration.saved().client_id()
    );
}

#[test]
fn a_repeated_parameter_is_rejected() {
    let world = World::new();
    for repeated in ["code=another", "client_id=app_other", "scope=openid"] {
        let (attempt, query) = approved(&world);
        assert_eq!(
            rejection(attempt, &format!("{query}&{repeated}")),
            "the callback repeats a parameter"
        );
    }
}

#[test]
fn declining_ends_the_attempt_as_access_denied() {
    let world = World::new();
    let attempt = world.attempt(Registration::New(&world.app));
    let query = world.provider.deny(attempt.authorization_url());

    let error = answered(attempt.accept(&query)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AccessDenied);
    assert_eq!(error.to_string(), "the user declined the request");
}

#[test]
fn another_provider_error_is_reported_with_its_code() {
    let world = World::new();
    let (attempt, _) = approved(&world);
    let query = format!(
        "error=server_error&error_description=down&state={}",
        state_of(&attempt)
    );

    let error = answered(attempt.accept(&query)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthorizationFailed);
    assert_eq!(error.provider_code(), Some("server_error"));
    assert_eq!(
        error.to_string(),
        "the provider ended the authorization with an error (server_error)"
    );
}

#[test]
fn a_registration_refusal_is_client_rejected_without_an_http_status() {
    for code in ["unauthorized_client", "invalid_client"] {
        let world = World::new();
        let (attempt, _) = approved(&world);
        let query = format!("error={code}&state={}", state_of(&attempt));

        let error = answered(attempt.accept(&query)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ClientRejected, "{code}");
        assert_eq!(error.provider_code(), Some(code));
        assert_eq!(error.http_status(), None);
        assert_eq!(
            error.to_string(),
            format!("the provider refused the app's registration in the browser ({code})")
        );
    }
}

#[test]
fn an_error_value_that_is_no_code_is_not_repeated() {
    let world = World::new();
    let (attempt, _) = approved(&world);
    let query = format!(
        "error=%3Cscript%3Ealert(1)%3C%2Fscript%3E&state={}",
        state_of(&attempt)
    );

    let error = answered(attempt.accept(&query)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthorizationFailed);
    assert_eq!(error.provider_code(), None);
    assert!(!format!("{error} {error:?}").contains("script"));
}

#[test]
fn a_code_together_with_an_error_is_rejected() {
    let world = World::new();
    let (attempt, query) = approved(&world);
    assert_eq!(
        rejection(attempt, &format!("{query}&error=access_denied")),
        "the callback carries both a code and an error"
    );
}

#[test]
fn a_first_registration_needs_an_issued_client_id() {
    let world = World::new();
    world.provider.omit_issued_client_in_callbacks();
    let (attempt, query) = approved(&world);
    assert_eq!(
        rejection(attempt, &query),
        "the callback carries no issued client ID"
    );

    for not_issued in [
        "client_id=dynamic_agent_client",
        "client_id=",
        "client_id=two%20words",
    ] {
        let attempt = world.attempt(Registration::New(&world.app));
        let query = format!("code=c&state={}&{not_issued}", state_of(&attempt));
        assert_eq!(
            rejection(attempt, &query),
            "the callback carries no issued client ID"
        );
    }
}

#[test]
fn a_returning_callback_may_omit_or_repeat_the_client_id() {
    let world = World::new();
    let first = world.sign_in(&User::alex());

    for names_client in [false, true] {
        if names_client {
            world.provider.name_saved_client_in_callbacks();
        }
        let returning = Returning::signed_out(first.client_id(), first.identity());
        let attempt = world.attempt(Registration::Saved(returning));
        let query = world
            .provider
            .authorize(attempt.authorization_url(), &User::alex());
        assert_eq!(query.contains("client_id="), names_client);

        let Accepted::Returning(exchange) = answered(attempt.accept(&query)).unwrap() else {
            panic!("a saved registration is not registered again");
        };
        assert_eq!(exchange.client_id(), first.client_id());
    }
}

#[test]
fn a_returning_callback_naming_another_client_is_rejected() {
    let world = World::new();
    let first = world.sign_in(&User::alex());
    let returning = Returning::signed_out(first.client_id(), first.identity());
    let attempt = world.attempt(Registration::Saved(returning));
    let query = world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());

    assert_eq!(
        rejection(attempt, &format!("{query}&client_id=app_issued9999")),
        "the callback names a different client"
    );
}

#[test]
fn a_callback_naming_another_issuer_is_rejected() {
    let world = World::new();
    let (attempt, query) = approved(&world);
    assert_eq!(
        rejection(
            attempt,
            &format!("{query}&iss=https%3A%2F%2Fauth.example.com")
        ),
        "the callback names another issuer"
    );

    let (attempt, query) = approved(&world);
    let named = format!("{query}&iss=https%3A%2F%2Fauth.openai.com");
    assert!(answered(attempt.accept(&named)).is_ok());
}

#[test]
fn a_callback_without_a_code_is_rejected() {
    let world = World::new();
    for code in ["", "&code="] {
        let (attempt, _) = approved(&world);
        let query = format!(
            "state={}{code}&client_id=app_issued0001",
            state_of(&attempt)
        );
        assert_eq!(
            rejection(attempt, &query),
            "the callback carries no authorization code"
        );
    }
}

/// Starts from a valid callback and applies random edits: dropped, repeated
/// and renamed parameters, broken escapes, foreign values.
#[test]
fn edited_callbacks_never_panic_and_only_this_attempts_state_ends_it() {
    let world = World::new();
    let mut generator = Generator::new(2026);
    let (mut accepted, mut refused, mut unrelated) = (0, 0, 0);
    for _ in 0..1500 {
        let attempt = world.attempt(Registration::New(&world.app));
        let state = state_of(&attempt);
        let names = [
            "state",
            "code",
            "client_id",
            "error",
            "iss",
            "scope",
            "",
            "%",
            "x",
        ];
        let values = [
            state.as_str(),
            "abc",
            "app_issued0001",
            "access_denied",
            "https://auth.openai.com",
            "",
            "%2",
            "%C3",
            "a+b%20c",
            "\u{e4}\0",
        ];
        let mut pairs = vec![
            ("state", state.as_str()),
            ("code", "abc"),
            ("client_id", "app_issued0001"),
        ];
        for _ in 0..generator.below(4) {
            let index = generator.below(pairs.len().max(1));
            match generator.below(6) {
                0 if !pairs.is_empty() => drop(pairs.remove(index)),
                1 if !pairs.is_empty() => pairs.push(pairs[index]),
                2 if !pairs.is_empty() => pairs[index].1 = generator.pick(&values),
                3 if !pairs.is_empty() => pairs[index].0 = generator.pick(&names),
                4 => pairs.push((generator.pick(&names), generator.pick(&values))),
                _ => pairs.reverse(),
            }
        }
        let query: Vec<String> = pairs
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        let query = query.join("&");

        let states: Vec<&str> = pairs
            .iter()
            .filter(|(name, _)| *name == "state")
            .map(|(_, value)| *value)
            .collect();
        let readable = pairs
            .iter()
            .all(|(name, value)| *name != "%" && !["%2", "%C3"].contains(value));
        let is_callback = readable && states == [state.as_str()];
        match attempt.accept(&query) {
            Callback::Unrelated(_) => {
                assert!(!is_callback, "{query:?} was not taken as the callback");
                unrelated += 1;
            }
            Callback::Final(result) => {
                assert!(is_callback, "{query:?} ended an attempt it does not name");
                match result {
                    Ok(callback) => {
                        let client_id = saved(callback).client_id().clone();
                        assert!(values.contains(&client_id.as_str()));
                        accepted += 1;
                    }
                    Err(_) => refused += 1,
                }
            }
        }
    }
    assert!(
        accepted > 100 && refused > 100 && unrelated > 100,
        "{accepted} accepted, {refused} refused, {unrelated} unrelated"
    );
}

#[test]
fn authorization_errors_do_not_return_the_attempt_state() {
    let world = World::new();
    let (attempt, _) = approved(&world);
    let state = state_of(&attempt);
    let error = answered(attempt.accept(&format!("error={state}&state={state}"))).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthorizationFailed);
    assert_eq!(error.provider_code(), None);
    assert!(!format!("{error:?} {error}").contains(&state));
}
