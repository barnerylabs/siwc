//! `Client` accounts: signing out, forgetting, labels, listing, and the
//! whole life of four accounts side by side.

use siwc::{AccountState, ErrorKind};

use crate::support::provider::User;
use crate::support::recording::{Failure, Journal};
use crate::support::rig::Rig;

fn authorization_request_fields(rig: &Rig) -> Vec<(String, String)> {
    rig.provider
        .seen()
        .into_iter()
        .rfind(|seen| seen.field("response_type").is_some())
        .unwrap()
        .fields
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

#[test]
fn signing_out_revokes_deletes_the_tokens_and_leaves_the_others_signed_in() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sam = rig.add(&User::sam());
    let client = rig.provider.issued_clients()[0].clone();
    let entry = format!("account-{}", alex.id());
    rig.journal.clear();

    let signed_out = rig.client.sign_out(alex.id()).unwrap();
    assert!(signed_out.revocation_confirmed());
    assert_eq!(signed_out.registered_as(), "Paste Perfect");
    assert_eq!(
        rig.journal.events(),
        [
            format!("lock {entry}"),
            "send revoke".to_owned(),
            format!("remove {entry}"),
            "lock installation".to_owned(),
            "write installation".to_owned(),
            "unlock installation".to_owned(),
            format!("unlock {entry}"),
        ]
    );
    assert_eq!(
        rig.provider.last_seen().field("client_id"),
        Some(client.as_str())
    );
    assert!(rig.credentials_of(alex.id()).is_none());
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedOut
    );
    assert!(rig.provider.owner_of(&rig.token(sam.id())).is_some());
}

#[test]
fn a_revocation_is_sent_once_more_after_a_temporary_failure() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.transport.fail("revoke", 1, Failure::Unreachable);

    assert!(
        rig.client
            .sign_out(alex.id())
            .unwrap()
            .revocation_confirmed()
    );
    assert_eq!(rig.journal.count("send revoke"), 2);
}

#[test]
fn a_revocation_is_sent_once_more_only_after_a_second() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.transport.fail("revoke", 1, Failure::Unreachable);

    drop(rig.client.sign_out(alex.id()).unwrap());
    assert_eq!(rig.clock.waits(), [std::time::Duration::from_secs(1)]);
}

#[test]
fn an_unconfirmed_revocation_is_reported_and_the_tokens_are_deleted_anyway() {
    for (failure, sent) in [
        (Failure::Status(503, "{}"), 2),
        (
            Failure::Status(400, r#"{"error":"unsupported_token_type"}"#),
            1,
        ),
    ] {
        let rig = Rig::new();
        let alex = rig.add(&User::alex());
        rig.transport.fail("revoke", 2, failure);

        let signed_out = rig.client.sign_out(alex.id()).unwrap();
        assert!(!signed_out.revocation_confirmed());
        assert_eq!(rig.journal.count("send revoke"), sent);
        assert!(rig.credentials_of(alex.id()).is_none());
        assert_eq!(
            rig.client.account(alex.id()).unwrap().state(),
            AccountState::SignedOut
        );
    }
}

#[test]
fn a_rejected_registration_is_cleaned_up_locally_on_sign_out_or_forget() {
    for forget in [false, true] {
        let rig = Rig::new();
        let alex = rig.add(&User::alex());
        let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
        rig.store.fail_removes();
        rig.transport.fail(
            "exchange",
            1,
            Failure::Status(401, r#"{"error":"invalid_client"}"#),
        );
        let (result, _) = rig.approve(sign_in, &User::alex());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::ClientRejected);
        assert!(rig.credentials_of(alex.id()).is_some());

        rig.store.heal();
        rig.journal.clear();
        let removed = if forget {
            rig.client.forget(alex.id())
        } else {
            rig.client.sign_out(alex.id())
        }
        .unwrap();
        assert!(rig.journal.about("send").is_empty());
        assert!(!removed.revocation_confirmed());
        assert!(rig.credentials_of(alex.id()).is_none());
    }
}

#[test]
fn after_a_sign_out_signing_in_again_keeps_the_registration_and_sends_no_hint() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let client = rig.provider.issued_clients()[0].clone();
    let _ = rig.client.sign_out(alex.id()).unwrap();

    let (result, _) = rig.approve(rig.client.sign_in_again(alex.id()).unwrap(), &User::alex());
    let account = result.unwrap().into_account();
    let fields = authorization_request_fields(&rig);
    assert_eq!(field(&fields, "client_id"), Some(client.as_str()));
    assert_eq!(field(&fields, "login_hint"), None);
    assert_eq!(field(&fields, "id_token_hint"), None);
    assert_eq!(account.id(), alex.id());
    assert_eq!(account.state(), AccountState::SignedIn);
    assert_eq!(rig.provider.registered_names().len(), 1);
    assert_eq!(rig.provider.owner_of(&rig.token(alex.id())), Some(client));
}

#[test]
fn forgetting_signs_out_and_removes_the_account_whose_id_is_unknown_afterwards() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sam = rig.add(&User::sam());

    let forgotten = rig.client.forget(alex.id()).unwrap();
    assert!(forgotten.revocation_confirmed());
    assert_eq!(forgotten.registered_as(), "Paste Perfect");
    assert!(rig.credentials_of(alex.id()).is_none());
    assert_eq!(
        rig.client.account(alex.id()).unwrap_err().kind(),
        ErrorKind::UnknownAccount
    );
    let ids: Vec<_> = rig
        .client
        .accounts()
        .unwrap()
        .iter()
        .map(|a| a.id().clone())
        .collect();
    assert_eq!(ids, [sam.id().clone()]);
    assert!(rig.client.access_token(sam.id()).is_ok());
}

#[test]
fn forgetting_a_signed_out_account_sends_no_request() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let _ = rig.client.sign_out(alex.id()).unwrap();
    rig.journal.clear();

    let forgotten = rig.client.forget(alex.id()).unwrap();
    assert!(!forgotten.revocation_confirmed());
    assert!(rig.journal.about("send").is_empty());
    assert!(rig.client.accounts().unwrap().is_empty());
}

#[test]
fn a_label_is_1_to_64_characters_without_control_characters_or_none() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let longest = "\u{e4}".repeat(64);
    for label in ["W", "Work account", longest.as_str()] {
        rig.client.set_label(alex.id(), Some(label)).unwrap();
        assert_eq!(rig.client.account(alex.id()).unwrap().label(), Some(label));
    }

    let too_long = "\u{e4}".repeat(65);
    for label in ["", too_long.as_str(), "line\nbreak", "tab\there", "nul\0"] {
        let error = rig.client.set_label(alex.id(), Some(label)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{label:?}");
    }
    assert_eq!(
        rig.client.account(alex.id()).unwrap().label(),
        Some(longest.as_str())
    );

    rig.client.set_label(alex.id(), None).unwrap();
    assert_eq!(rig.client.account(alex.id()).unwrap().label(), None);
}

#[test]
fn an_empty_store_lists_no_accounts_and_writes_nothing() {
    let rig = Rig::new();
    assert!(rig.client.accounts().unwrap().is_empty());
    assert!(rig.journal.events().is_empty());
    assert!(rig.store.snapshot().is_empty());
}

#[test]
fn accounts_are_listed_in_the_order_they_were_added() {
    let rig = Rig::new();
    let added: Vec<_> = [User::sam(), User::alex(), User::kim()]
        .iter()
        .map(|user| rig.add(user).id().clone())
        .collect();
    let listed: Vec<_> = rig
        .another_client()
        .accounts()
        .unwrap()
        .iter()
        .map(|account| account.id().clone())
        .collect();
    assert_eq!(listed, added);
}

// The whole life of four accounts side by side.

#[test]
fn four_accounts_live_side_by_side_from_sign_in_to_forgetting() {
    let rig = Rig::new();
    let users = [User::alex(), User::sam(), User::kim(), User::jo()];
    let mut clients = Vec::new();
    let mut ids = Vec::new();
    for user in &users {
        let account = rig.add(user);
        assert_eq!(account.identity().subject(), user.subject);
        clients.push(rig.provider.issued_clients().last().unwrap().clone());
        ids.push(account.id().clone());
    }
    let owner = |index: usize| rig.provider.owner_of(&rig.token(&ids[index]));

    // Use each.
    for index in 0..4 {
        assert_eq!(owner(index).as_ref(), Some(&clients[index]));
        assert_eq!(rig.client.models(&ids[index]).unwrap().len(), 3);
    }

    // Refresh one.
    let token = rig.client.access_token(&ids[0]).unwrap();
    let renewed = rig
        .client
        .access_token_after_rejection(&ids[0], &token)
        .unwrap();
    assert_ne!(renewed.expose(), token.expose());
    assert_eq!(rig.journal.count("send refresh"), 1);

    // Sign one out, forget another.
    assert!(rig.client.sign_out(&ids[1]).unwrap().revocation_confirmed());
    assert!(rig.client.forget(&ids[2]).unwrap().revocation_confirmed());
    assert_eq!(
        rig.client.access_token(&ids[1]).unwrap_err().kind(),
        ErrorKind::SignInRequired
    );
    assert_eq!(
        rig.client.access_token(&ids[2]).unwrap_err().kind(),
        ErrorKind::UnknownAccount
    );

    // Sign the signed-out one in again.
    let (result, _) = rig.approve(rig.client.sign_in_again(&ids[1]).unwrap(), &users[1]);
    assert_eq!(result.unwrap().account().state(), AccountState::SignedIn);

    let states: Vec<_> = rig
        .client
        .accounts()
        .unwrap()
        .iter()
        .map(|account| (account.id().clone(), account.state()))
        .collect();
    assert_eq!(
        states,
        [
            (ids[0].clone(), AccountState::SignedIn),
            (ids[1].clone(), AccountState::SignedIn),
            (ids[3].clone(), AccountState::SignedIn),
        ]
    );
    for index in [0, 1, 3] {
        assert_eq!(owner(index).as_ref(), Some(&clients[index]));
    }
    assert_eq!(owner(0), rig.provider.owner_of(renewed.expose()));
    assert_eq!(rig.provider.registered_names().len(), 4);
    rig.journal.assert_lock_rules();
}

/// The paths where something goes wrong take locks and send requests too.
#[test]
fn the_lock_rules_hold_on_the_paths_that_fail_as_well() {
    let rig = Rig::new();
    let invalid = |code: &'static str| Failure::Status(400, code);

    // A sign-in whose exchange fails, then one whose credentials cannot be
    // written and is undone.
    rig.transport.fail("exchange", 1, Failure::Unreachable);
    let (result, _) = rig.approve(rig.client.add_account().unwrap(), &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Temporary);
    let sign_in = rig.client.add_account().unwrap();
    rig.store.fail_writes_to("account-");
    let (result, _) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Store);
    rig.store.heal();

    let alex = rig.add(&User::alex());
    let sam = rig.add(&User::sam());
    let kim = rig.add(&User::kim());
    rig.client.set_label(alex.id(), Some("Work")).unwrap();

    // A sign-in again as another person, and one that asks for plan use.
    let (result, _) = rig.approve(rig.client.sign_in_again(alex.id()).unwrap(), &User::sam());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::AccountMismatch);
    let (result, _) = rig.approve(
        rig.client.enable_plan_use(alex.id()).unwrap(),
        &User::alex(),
    );
    result.unwrap();

    // Renewals: one that works, one that ends the session, one that finds
    // the registration gone, one that cannot be stored.
    rig.at(3540);
    rig.client.access_token(alex.id()).unwrap();
    rig.transport
        .fail("refresh", 1, invalid(r#"{"error":"invalid_grant"}"#));
    assert_eq!(
        rig.client.access_token(sam.id()).unwrap_err().kind(),
        ErrorKind::SignInRequired
    );
    rig.transport
        .fail("refresh", 1, invalid(r#"{"error":"invalid_client"}"#));
    assert_eq!(
        rig.client.access_token(kim.id()).unwrap_err().kind(),
        ErrorKind::ClientRejected
    );
    rig.at(2 * 3540);
    rig.store.fail_writes_to("account-");
    assert_eq!(
        rig.client.access_token(alex.id()).unwrap_err().kind(),
        ErrorKind::Store
    );
    rig.store.heal();

    // Sign-outs whose revocation fails, and removals.
    rig.transport.fail("revoke", 2, Failure::Unreachable);
    assert!(
        !rig.client
            .sign_out(alex.id())
            .unwrap()
            .revocation_confirmed()
    );
    drop(rig.client.sign_out(sam.id()).unwrap());
    drop(rig.client.forget(kim.id()).unwrap());
    drop(rig.client.forget(sam.id()).unwrap());

    assert!(rig.journal.count("send refresh") >= 4);
    rig.journal.assert_lock_rules();
}

#[test]
fn the_check_of_the_lock_rules_refuses_each_way_to_break_them() {
    for events in [
        vec!["lock installation", "send refresh", "unlock installation"],
        vec![
            "lock installation",
            "lock account-a",
            "unlock account-a",
            "unlock installation",
        ],
        vec![
            "lock account-a",
            "lock account-b",
            "unlock account-b",
            "unlock account-a",
        ],
        vec!["lock account-a"],
    ] {
        let journal = Journal::default();
        for event in &events {
            journal.push((*event).to_owned());
        }
        let checked = std::panic::catch_unwind(|| journal.assert_lock_rules());
        assert!(checked.is_err(), "{events:?}");
    }
}

#[test]
fn selected_account_persists_validates_membership_and_clears_when_forgotten() {
    let rig = Rig::new();
    assert_eq!(rig.client.selected_account().unwrap(), None);
    let unknown = siwc::AccountId::parse("00000000000000000000000000000099").unwrap();
    assert_eq!(
        rig.client
            .select_account(Some(&unknown))
            .unwrap_err()
            .kind(),
        ErrorKind::UnknownAccount
    );

    let alex = rig.add(&User::alex());
    alex.check_plan_use().unwrap();
    let identity_only = rig.add(&User::sam().without_plan_use());
    let missing_grant = identity_only.check_plan_use().unwrap_err();
    assert_eq!(missing_grant.kind(), ErrorKind::PlanUseNotGranted);
    assert_eq!(missing_grant.provider_code(), None);
    let _ = rig.client.forget(identity_only.id()).unwrap();

    let sam = rig.add(&User::sam());
    assert_eq!(rig.client.selected_account().unwrap(), None);

    rig.client.select_account(Some(alex.id())).unwrap();
    assert_eq!(
        rig.client.selected_account().unwrap().unwrap().id(),
        alex.id()
    );

    rig.client.select_account(Some(sam.id())).unwrap();
    assert_eq!(
        rig.client.selected_account().unwrap().unwrap().id(),
        sam.id()
    );

    // Signing out keeps the account and its selection; forgetting clears it.
    let _ = rig.client.sign_out(sam.id()).unwrap();
    assert_eq!(
        rig.client.selected_account().unwrap().unwrap().id(),
        sam.id()
    );
    let _ = rig.client.forget(sam.id()).unwrap();
    assert_eq!(rig.client.selected_account().unwrap(), None);

    // Another caller can select a staged account before its credential write
    // reports an error. The account remains listed for later reconciliation.
    let client_for_hook = rig.another_client();
    rig.store.before_next_lock_of("account-", move || {
        let accounts = client_for_hook.accounts().unwrap();
        if let Some(staged) = accounts.last() {
            client_for_hook.select_account(Some(staged.id())).unwrap();
        }
    });
    rig.store.fail_writes_to("account-");
    let sign_in = rig.client.add_account().unwrap();
    let (rolled_back, _) = rig.approve(sign_in, &User::kim());
    assert_eq!(rolled_back.unwrap_err().kind(), ErrorKind::Store);
    rig.store.heal();
    let accounts = rig.client.accounts().unwrap();
    assert_eq!(accounts.len(), 2);
    assert_eq!(
        rig.client.selected_account().unwrap().unwrap().id(),
        accounts[1].id()
    );

    rig.client.select_account(Some(alex.id())).unwrap();
    rig.client.select_account(None).unwrap();
    assert_eq!(rig.client.selected_account().unwrap(), None);
    rig.journal.assert_lock_rules();
}
