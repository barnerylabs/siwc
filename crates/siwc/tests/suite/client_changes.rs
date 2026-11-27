//! `Client::changes`: what changed in the accounts between two polls.

use siwc::{AccountState, Change};

use crate::support::provider::User;
use crate::support::recording::Failure;
use crate::support::rig::Rig;

/// Seconds after sign-in from which a token is due.
const DUE: u64 = 3540;

const SPENT: Failure = Failure::Status(400, r#"{"error":"invalid_grant"}"#);

#[test]
fn a_poll_without_changes_is_empty() {
    let rig = Rig::new();
    rig.add(&User::alex());
    let mut changes = rig.client.changes().unwrap();
    rig.token(rig.client.accounts().unwrap()[0].id());

    assert_eq!(changes.poll().unwrap(), []);
    assert_eq!(changes.poll().unwrap(), []);
}

#[test]
fn an_account_another_client_adds_is_added_once() {
    let rig = Rig::new();
    let mut changes = rig.another_client().changes().unwrap();

    let alex = rig.add(&User::alex());
    assert_eq!(changes.poll().unwrap(), [Change::Added(alex)]);
    assert_eq!(changes.poll().unwrap(), []);
}

#[test]
fn a_sign_out_changes_the_state() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let mut changes = rig.client.changes().unwrap();

    assert!(
        rig.client
            .sign_out(alex.id())
            .unwrap()
            .revocation_confirmed()
    );
    let after = rig.client.account(alex.id()).unwrap();
    assert_eq!(after.state(), AccountState::SignedOut);
    assert_eq!(changes.poll().unwrap(), [Change::Changed(after)]);
}

#[test]
fn a_renewal_that_ends_the_session_changes_the_state() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let mut changes = rig.client.changes().unwrap();
    rig.at(DUE);
    rig.transport.fail("refresh", 1, SPENT);

    rig.client.access_token(alex.id()).unwrap_err();
    let after = rig.client.account(alex.id()).unwrap();
    assert_eq!(after.state(), AccountState::SignInRequired);
    assert_eq!(changes.poll().unwrap(), [Change::Changed(after)]);
}

#[test]
fn a_new_label_is_a_change() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let mut changes = rig.client.changes().unwrap();

    rig.client.set_label(alex.id(), Some("Work")).unwrap();
    let after = rig.client.account(alex.id()).unwrap();
    assert_eq!(after.label(), Some("Work"));
    assert_eq!(changes.poll().unwrap(), [Change::Changed(after)]);
}

#[test]
fn plan_use_granted_later_is_a_change() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex().without_plan_use());
    let mut changes = rig.client.changes().unwrap();

    let (enabled, _) = rig.approve(
        rig.client.enable_plan_use(alex.id()).unwrap(),
        &User::alex(),
    );
    let after = enabled.unwrap().into_account();
    assert!(after.plan_use());
    assert_eq!(changes.poll().unwrap(), [Change::Changed(after)]);
}

#[test]
fn a_forgotten_account_is_removed_with_its_last_snapshot() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.client.set_label(alex.id(), Some("Work")).unwrap();
    let before = rig.client.account(alex.id()).unwrap();
    let mut changes = rig.client.changes().unwrap();

    assert!(rig.client.forget(alex.id()).unwrap().revocation_confirmed());
    assert_eq!(changes.poll().unwrap(), [Change::Removed(before)]);
    assert_eq!(changes.poll().unwrap(), []);
}

#[test]
fn several_changes_come_in_one_poll_in_list_order_then_the_removed() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.add(&User::sam());
    let kim = rig.add(&User::kim());
    let mut changes = rig.client.changes().unwrap();

    assert!(rig.client.forget(alex.id()).unwrap().revocation_confirmed());
    let jo = rig.add(&User::jo());
    rig.client.set_label(kim.id(), Some("Team")).unwrap();
    let kim = rig.client.account(kim.id()).unwrap();

    assert_eq!(
        changes.poll().unwrap(),
        [
            Change::Changed(kim),
            Change::Added(jo),
            Change::Removed(alex),
        ]
    );
}

#[test]
fn a_change_prints_no_label_address_or_name() {
    let rig = Rig::new();
    let mut changes = rig.client.changes().unwrap();
    let alex = rig.add(&User::alex());
    rig.client.set_label(alex.id(), Some("Work")).unwrap();

    let printed = format!("{:?}", changes.poll().unwrap());
    assert!(printed.contains(alex.id().as_str()), "{printed}");
    for personal in ["Work", "alex@example.com", "Alex Example", "user-alex"] {
        assert!(!printed.contains(personal), "{printed}");
    }
}
