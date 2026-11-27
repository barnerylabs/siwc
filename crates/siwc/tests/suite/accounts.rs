//! Several accounts side by side: each has its own registration, and the
//! parts of two accounts never meet in one request.

use siwc::ErrorKind;
use siwc::protocol::{Credentials, Registration, Returning};

use crate::support::World;
use crate::support::provider::User;

fn renew(world: &World, credentials: &Credentials) -> Result<Credentials, siwc::Error> {
    let request = credentials.refresh_request().unwrap();
    credentials.refreshed(world.provider.send(&request), world.now())
}

#[test]
fn every_account_registers_the_app_under_the_same_name_and_host() {
    let world = World::new();
    let alex = world.sign_in(&User::alex());
    let sam = world.sign_in(&User::sam());

    assert_ne!(alex.client_id(), sam.client_id());
    assert_eq!(
        world.provider.registered_names(),
        ["Paste Perfect", "Paste Perfect"]
    );
    let hosts: Vec<String> = world
        .provider
        .seen()
        .iter()
        .filter_map(|request| request.field("ext_agent_host_id").map(str::to_owned))
        .collect();
    assert_eq!(hosts, [world.host.as_str(), world.host.as_str()]);
}

#[test]
fn credentials_name_the_registration_and_account_they_belong_to() {
    let world = World::new();
    let alex = world.sign_in(&User::alex());
    let sam = world.sign_in(&User::sam());

    for (signed_in, subject) in [(&alex, "user-alex-0001"), (&sam, "user-sam-0002")] {
        let credentials = signed_in.credentials();
        assert_eq!(credentials.client_id(), signed_in.client_id());
        assert_eq!(credentials.subject(), subject);
        assert_eq!(credentials.subject(), signed_in.identity().subject());

        let renewed = renew(&world, credentials).unwrap();
        let sent = world.provider.last_seen();
        assert_eq!(
            sent.field("client_id"),
            Some(signed_in.client_id().as_str())
        );
        assert_eq!(renewed.client_id(), signed_in.client_id());
        assert_eq!(renewed.subject(), subject);
    }
}

#[test]
fn signing_one_account_out_leaves_the_others_signed_in() {
    let world = World::new();
    let alex = world.sign_in(&User::alex());
    let sam = world.sign_in(&User::sam());

    let revocation = alex.credentials().revoke_request().unwrap();
    assert_eq!(world.provider.send(&revocation).status(), 200);
    assert_eq!(
        world.provider.last_seen().field("client_id"),
        Some(alex.client_id().as_str())
    );

    let error = renew(&world, alex.credentials()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::SignInRequired);
    assert!(renew(&world, sam.credentials()).is_ok());
}

#[test]
fn one_login_can_hold_two_registrations_that_stay_apart() {
    let world = World::new();
    let personal = world.sign_in(&User::alex());
    let team = world.sign_in(&User::alex());

    assert_eq!(personal.identity(), team.identity());
    assert_ne!(personal.client_id(), team.client_id());

    // The credentials decide which registration signs in again.
    let returning = Returning::signed_in(personal.identity(), team.credentials());
    let attempt = world.attempt(Registration::Saved(returning));
    world
        .provider
        .authorize(attempt.authorization_url(), &User::alex());
    assert_eq!(
        world.provider.last_seen().field("client_id"),
        Some(team.client_id().as_str())
    );
}
