//! Secrets stay out of `Debug` output and error messages.

use siwc::protocol::{Jwks, Registration, Returning};

use crate::support::provider::User;
use crate::support::recording::Failure;
use crate::support::rig::Rig;
use crate::support::wire::{form_decode, only};
use crate::support::{World, answered, saved};

#[test]
fn debug_output_shows_no_secret() {
    let world = World::new();
    let mut printed = Vec::new();
    let mut secrets = Vec::new();

    let attempt = world.attempt(Registration::New(&world.app));
    let (_, query) = attempt.authorization_url().split_once('?').unwrap();
    let request = form_decode(query);
    for name in ["state", "nonce", "code_challenge"] {
        secrets.push(only(&request, name).to_owned());
    }
    printed.push(format!("{attempt:?}"));

    let callback = world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());
    secrets.push(only(&form_decode(&callback), "code").to_owned());
    let accepted = answered(attempt.accept(&callback)).unwrap();
    printed.push(format!("{accepted:?}"));

    let exchange = saved(accepted);
    let token_request = exchange.request();
    printed.push(format!("{exchange:?} {token_request:?}"));
    let response = world.provider.send(&token_request);
    let sent = world.provider.last_seen();
    secrets.push(sent.field("code_verifier").unwrap().to_owned());
    printed.push(format!("{response:?}"));

    let unverified = exchange.response(response, world.now()).unwrap();
    printed.push(format!("{unverified:?}"));
    let keys = Jwks::from_response(&world.provider.send(&Jwks::request())).unwrap();
    assert!(!format!("{keys:?}").contains("provider-key-1"));
    printed.push(format!("{keys:?}"));
    let signed_in = unverified.verify(&keys, world.now()).unwrap();
    secrets.push(signed_in.credentials().access_token().expose().to_owned());
    printed.push(format!(
        "{signed_in:?} {:?}",
        signed_in.credentials().access_token()
    ));
    let returning = Returning::signed_in(signed_in.identity(), signed_in.credentials());
    printed.push(format!("{:?}", Registration::Saved(returning)));
    let identity = signed_in.identity();
    secrets.extend(
        [
            identity.subject(),
            identity.email().unwrap(),
            identity.name().unwrap(),
        ]
        .map(str::to_owned),
    );

    let refresh = signed_in.credentials().refresh_request().unwrap();
    printed.push(format!("{refresh:?}"));
    world.provider.send(&refresh);
    secrets.push(
        world
            .provider
            .last_seen()
            .field("refresh_token")
            .unwrap()
            .to_owned(),
    );

    let printed = printed.join("\n");
    for secret in &secrets {
        assert!(secret.len() >= 9, "{secret} is too short to search for");
        assert!(
            !printed.contains(secret.as_str()),
            "{secret} appears in {printed}"
        );
    }
    assert!(printed.contains("AccessToken([redacted])"));
    assert!(printed.contains("Identity { email_verified: true, .. }"));
    assert!(!printed.contains("eyJ"), "a JWT appears in {printed}");
}

#[test]
fn client_debug_output_shows_no_token_link_address_name_or_subject() {
    let rig = Rig::new();
    let user = User::alex();
    let mut printed = vec![
        format!("{:?}", rig.builder("Paste Perfect")),
        format!("{:?}", rig.client),
    ];

    let sign_in = rig.client.add_account().unwrap();
    let link = sign_in.start_link().to_owned();
    printed.push(format!("{sign_in:?}"));
    let (completed, _) = rig.approve(sign_in, &user);
    let completed = completed.unwrap();
    printed.push(format!("{completed:?}"));
    let id = completed.account().id().clone();
    rig.client.set_label(&id, Some("Alex at work")).unwrap();
    let account = rig.client.account(&id).unwrap();
    printed.push(format!("{account:?} {:?}", rig.client.accounts().unwrap()));
    let again = rig.client.sign_in_again(&id).unwrap();
    printed.push(format!("{again:?}"));
    drop(again);
    let token = rig.token(&id);
    let signed_out = rig.client.sign_out(&id).unwrap();
    printed.push(format!("{signed_out:?}"));

    let printed = printed.join("\n");
    for secret in [
        token.as_str(),
        link.as_str(),
        link.rsplit('/').next().unwrap(),
        user.email.unwrap(),
        user.name.unwrap(),
        user.subject,
        "Alex at work",
    ] {
        assert!(!printed.contains(secret), "{secret} appears in {printed}");
    }
    assert!(printed.contains(id.as_str()));
    assert!(!printed.contains("eyJ"), "a JWT appears in {printed}");
}

#[test]
fn an_unrecorded_refusal_shows_no_secret() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let token = rig.token(alex.id());
    rig.at(3540);
    rig.transport.fail(
        "refresh",
        1,
        Failure::Status(400, r#"{"error":"invalid_grant"}"#),
    );
    rig.store.fail_writes_to("installation");

    let error = rig.client.access_token(alex.id()).unwrap_err();
    assert!(!error.state_saved());
    let source = std::error::Error::source(&error).map(ToString::to_string);
    let printed = format!("{error} {error:?} {source:?}");
    assert!(printed.contains("state_saved: false"), "{printed}");
    assert!(
        !printed.contains(&token),
        "the access token appears in {printed}"
    );
    assert!(!printed.contains("refresh-"), "{printed}");
}

#[test]
fn a_request_carries_its_secrets_only_in_the_body() {
    let world = World::new();
    let exchange = world.authorized(&User::alex());
    let request = exchange.request();

    assert!(!request.url().contains('?'));
    assert!(request.headers().all(|(_, value)| !value.contains("code-")));
    assert!(
        std::str::from_utf8(request.body())
            .unwrap()
            .contains("code=code-")
    );
}

#[test]
fn client_formatting_omits_the_store() {
    let rig = Rig::new();
    let builder = rig.builder("Synthetic");
    assert!(!format!("{builder:?}").contains("RecordingStore"));
    assert!(!format!("{:?}", builder.build()).contains("RecordingStore"));
}
