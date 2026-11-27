//! `Client` access tokens: renewal under the account's lock, failures that
//! stay with their account, and the model list.

use std::sync::{Arc, Barrier};
use std::thread;

use siwc::plan::{Models, Refusal};
use siwc::{AccountId, AccountState, Client, ErrorKind};

use crate::support::NOW;
use crate::support::provider::{Request, User};
use crate::support::recording::Failure;
use crate::support::rig::Rig;

/// Seconds after sign-in from which a token is due.
const DUE: u64 = 3540;

const SPENT: Failure = Failure::Status(400, r#"{"error":"invalid_grant"}"#);
const UNKNOWN_CLIENT: Failure = Failure::Status(401, r#"{"error":"invalid_client"}"#);

fn kind_of_token_error(client: &Client, id: &AccountId) -> ErrorKind {
    client.access_token(id).unwrap_err().kind()
}

#[test]
fn a_token_that_is_not_due_comes_without_a_request_or_a_lock() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.at(DUE - 1);
    rig.journal.clear();

    let token = rig.token(alex.id());
    assert!(
        rig.journal.events().is_empty(),
        "{:?}",
        rig.journal.events()
    );
    assert_eq!(
        rig.provider.owner_of(&token),
        Some(rig.provider.issued_clients()[0].clone())
    );
}

#[test]
fn a_due_token_is_renewed_under_the_lock_and_stored_before_it_is_returned() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let first = rig.token(alex.id());
    let entry = format!("account-{}", alex.id());
    rig.at(DUE);
    rig.journal.clear();

    let renewed = rig.token(alex.id());
    assert_eq!(
        rig.journal.events(),
        [
            format!("lock {entry}"),
            "send refresh".to_owned(),
            format!("write {entry}"),
            format!("unlock {entry}"),
        ]
    );
    assert_ne!(renewed, first);
    assert!(rig.provider.owner_of(&renewed).is_some());
    // The successor is what is stored now.
    rig.journal.clear();
    assert_eq!(rig.token(alex.id()), renewed);
    assert!(rig.journal.events().is_empty());
}

#[test]
fn a_refresh_that_changes_plan_use_updates_the_stored_account() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    assert!(alex.plan_use());
    rig.at(DUE);
    rig.provider.alter_next_response(|body| {
        body.insert(
            "scope".into(),
            serde_json::json!("openid profile email offline_access"),
        );
    });
    rig.token(alex.id());
    assert!(!rig.client.account(alex.id()).unwrap().plan_use());

    rig.at(DUE * 2);
    rig.provider.alter_next_response(|body| {
        body.insert(
            "scope".into(),
            serde_json::json!(
                "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
            ),
        );
    });
    rig.token(alex.id());
    assert!(rig.client.account(alex.id()).unwrap().plan_use());
}

#[test]
fn a_failed_plan_use_update_is_repaired_by_parallel_token_callers() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let previous = rig.token(alex.id());
    rig.at(DUE);
    rig.provider.alter_next_response(|body| {
        body.insert(
            "scope".into(),
            serde_json::json!("openid profile email offline_access"),
        );
    });
    rig.store.fail_one_write_after(1);

    assert_eq!(
        kind_of_token_error(&rig.client, alex.id()),
        ErrorKind::Store
    );
    assert!(rig.client.account(alex.id()).unwrap().plan_use());
    let stored = rig.credentials_of(alex.id()).unwrap();
    let successor = siwc::protocol::Credentials::from_stored(&stored).unwrap();
    assert!(!successor.scopes().grants_plan_use());
    assert_ne!(successor.access_token().expose(), previous);

    rig.journal.clear();
    let tokens = at_once(vec![rig.client.clone(), rig.another_client()], alex.id());
    assert!(!rig.client.account(alex.id()).unwrap().plan_use());
    assert!(
        tokens
            .iter()
            .all(|token| *token == successor.access_token().expose())
    );
    assert_eq!(rig.journal.count("send refresh"), 0);
    assert_eq!(rig.journal.about("write"), ["write installation"]);
    assert_eq!(rig.credentials_of(alex.id()).unwrap(), stored);
}

#[test]
fn a_failed_plan_use_update_is_repaired_when_retrying_a_rejected_token() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex().without_plan_use());
    let rejected = rig.client.access_token(alex.id()).unwrap();
    rig.provider.alter_next_response(|body| {
        body.insert(
            "scope".into(),
            serde_json::json!(
                "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
            ),
        );
    });
    rig.store.fail_one_write_after(1);

    let retry = || {
        rig.client
            .access_token_after_rejection(alex.id(), &rejected)
    };
    assert_eq!(retry().unwrap_err().kind(), ErrorKind::Store);
    assert!(!rig.client.account(alex.id()).unwrap().plan_use());
    let stored = rig.credentials_of(alex.id()).unwrap();
    let successor = siwc::protocol::Credentials::from_stored(&stored).unwrap();
    assert!(successor.scopes().grants_plan_use());
    assert_ne!(successor.access_token().expose(), rejected.expose());

    rig.journal.clear();
    assert_eq!(retry().unwrap().expose(), successor.access_token().expose());
    assert!(rig.client.account(alex.id()).unwrap().plan_use());
    assert_eq!(rig.journal.count("send refresh"), 0);
    assert_eq!(rig.journal.about("write"), ["write installation"]);
    assert_eq!(rig.credentials_of(alex.id()).unwrap(), stored);
    rig.journal.assert_lock_rules();

    rig.journal.clear();
    assert_eq!(rig.token(alex.id()), successor.access_token().expose());
    assert!(rig.journal.events().is_empty());
}

/// Asks for the token of `id` from each client at the same time.
fn at_once(clients: Vec<Client>, id: &AccountId) -> Vec<String> {
    let barrier = Arc::new(Barrier::new(clients.len()));
    let askers: Vec<_> = clients
        .into_iter()
        .map(|client| {
            let barrier = Arc::clone(&barrier);
            let id = id.clone();
            thread::spawn(move || {
                barrier.wait();
                client.access_token(&id).unwrap().expose().to_owned()
            })
        })
        .collect();
    askers
        .into_iter()
        .map(|asker| asker.join().unwrap())
        .collect()
}

#[test]
fn two_threads_asking_for_a_due_token_cause_one_refresh() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.at(DUE);
    rig.journal.clear();

    let tokens = at_once(vec![rig.client.clone(), rig.client.clone()], alex.id());
    assert_eq!(rig.journal.count("send refresh"), 1);
    assert_eq!(tokens[0], tokens[1]);
}

#[test]
fn two_clients_on_one_store_asking_for_a_due_token_cause_one_refresh() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.at(DUE);
    rig.journal.clear();

    let tokens = at_once(
        vec![
            rig.client.clone(),
            rig.another_client(),
            rig.another_client(),
        ],
        alex.id(),
    );
    assert_eq!(rig.journal.count("send refresh"), 1);
    assert!(tokens.iter().all(|token| *token == tokens[0]));
}

#[test]
fn a_spent_session_requires_a_sign_in_for_its_account_alone() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sam = rig.add(&User::sam());
    rig.at(DUE);
    rig.transport.fail("refresh", 1, SPENT);

    let error = rig.client.access_token(alex.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::SignInRequired);
    assert_eq!(error.provider_code(), Some("invalid_grant"));
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignInRequired
    );

    rig.journal.clear();
    assert_eq!(
        kind_of_token_error(&rig.client, alex.id()),
        ErrorKind::SignInRequired
    );
    assert!(rig.journal.about("send").is_empty());
    assert!(rig.provider.owner_of(&rig.token(sam.id())).is_some());
    assert_eq!(
        rig.client.account(sam.id()).unwrap().state(),
        AccountState::SignedIn
    );
}

#[test]
fn a_spent_session_deletes_the_tokens_and_keeps_the_registration() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.at(DUE);
    rig.transport.fail("refresh", 1, SPENT);
    rig.client.access_token(alex.id()).unwrap_err();

    assert!(rig.credentials_of(alex.id()).is_none());
    let listed = rig.client.accounts().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state(), AccountState::SignInRequired);
    let diagnosis = rig.client.diagnose().to_string();
    assert!(diagnosis.contains("credentials: missing"), "{diagnosis}");
    assert_eq!(
        rig.client
            .export_account_to(
                alex.id(),
                b"synthetic passphrase",
                env!("CARGO_TARGET_TMPDIR")
            )
            .unwrap_err()
            .kind(),
        ErrorKind::SignInRequired
    );

    // Signing in again uses the same registration and works.
    rig.journal.clear();
    let again = rig.client.sign_in_again(alex.id()).unwrap();
    let (result, _) = rig.approve(again, &User::alex());
    assert_eq!(result.unwrap().account().state(), AccountState::SignedIn);
    assert_eq!(rig.provider.registered_names().len(), 1);
    assert!(rig.provider.owner_of(&rig.token(alex.id())).is_some());

    // With the session ended again, sign-out and forget need no tokens.
    rig.at(DUE * 2);
    rig.transport.fail("refresh", 1, SPENT);
    rig.client.access_token(alex.id()).unwrap_err();
    rig.journal.clear();
    let signed_out = rig.client.sign_out(alex.id()).unwrap();
    assert!(!signed_out.revocation_confirmed());
    drop(rig.client.forget(alex.id()).unwrap());
    assert!(rig.journal.about("send").is_empty());
    assert!(rig.client.accounts().unwrap().is_empty());
}

#[test]
fn a_spent_session_retries_credential_removal_on_token_calls() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.at(DUE);
    rig.store.fail_removes();
    rig.transport.fail("refresh", 1, SPENT);

    let error = rig.client.access_token(alex.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::SignInRequired);
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignInRequired
    );
    assert!(rig.credentials_of(alex.id()).is_some());

    rig.store.heal();
    rig.journal.clear();
    assert_eq!(
        kind_of_token_error(&rig.another_client(), alex.id()),
        ErrorKind::SignInRequired
    );
    assert!(rig.credentials_of(alex.id()).is_none());
    assert!(rig.journal.about("send").is_empty());
    assert!(rig.journal.about("write").is_empty());
}

#[test]
fn a_call_never_sends_a_token_whose_credentials_do_not_grant_plan_use() {
    let rig = Rig::new();
    let off = rig.add(&User::sam().without_plan_use());
    let sent = std::cell::Cell::new(0);
    let error = rig
        .client
        .call(off.id(), api_call(&rig, &sent))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PlanUseNotGranted);
    assert_eq!(sent.get(), 0);
}

#[test]
fn a_call_stops_when_the_renewal_of_a_refused_token_drops_plan_use() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.provider
        .refuse_next_api_request(401, r#"{"error":{"code":"invalid_api_key"}}"#);
    rig.provider.alter_next_response(|body| {
        body.insert(
            "scope".into(),
            serde_json::json!("openid profile email offline_access"),
        );
    });
    let sent = std::cell::Cell::new(0);
    let error = rig
        .client
        .call(alex.id(), api_call(&rig, &sent))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PlanUseNotGranted);
    assert_eq!(sent.get(), 1);
    assert_eq!(rig.journal.count("send refresh"), 1);
}

#[test]
fn after_a_rejection_a_newer_token_without_a_refresh_token_is_used_until_it_expires() {
    let rig = Rig::new();
    let without_refresh = || {
        rig.provider
            .alter_next_response(|body| drop(body.remove("refresh_token")));
    };
    without_refresh();
    let alex = rig.add(&User::alex());
    let rejected = rig.client.access_token(alex.id()).unwrap();
    // Another sign-in stored a newer token, which is due but still valid.
    without_refresh();
    let again = rig.client.sign_in_again(alex.id()).unwrap();
    rig.approve(again, &User::alex()).0.unwrap();
    let newer = rig.token(alex.id());
    assert_ne!(newer, rejected.expose());
    rig.at(DUE);
    rig.journal.clear();

    let token = rig
        .client
        .access_token_after_rejection(alex.id(), &rejected)
        .unwrap();
    assert_eq!(token.expose(), newer);
    assert!(rig.journal.about("send").is_empty());
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedIn
    );
}

#[test]
fn a_renewal_whose_access_token_has_already_expired_is_stored_but_not_returned() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let before = rig.credentials_of(alex.id()).unwrap();
    rig.at(DUE);
    rig.provider
        .alter_next_response(|body| drop(body.insert("expires_in".into(), serde_json::json!(0))));

    let error = rig.client.access_token(alex.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidResponse);
    // The rotated refresh token is kept, so the next call can renew.
    assert_ne!(rig.credentials_of(alex.id()).unwrap(), before);
    rig.journal.clear();
    assert!(rig.provider.owner_of(&rig.token(alex.id())).is_some());
    assert_eq!(rig.journal.count("send refresh"), 1);
}

#[test]
fn a_rejected_registration_stays_rejected_and_is_not_sent_to_the_browser() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sam = rig.add(&User::sam());
    rig.at(DUE);
    rig.transport.fail("refresh", 1, UNKNOWN_CLIENT);

    assert_eq!(
        kind_of_token_error(&rig.client, alex.id()),
        ErrorKind::ClientRejected
    );
    let state = |id| rig.client.account(id).unwrap().state();
    assert_eq!(state(alex.id()), AccountState::RegistrationRejected);
    assert!(rig.credentials_of(alex.id()).is_none());
    assert_eq!(state(sam.id()), AccountState::SignedIn);

    // Every later call says the same without a request, and a sign-in for
    // the same registration is not started.
    rig.journal.clear();
    assert_eq!(
        kind_of_token_error(&rig.client, alex.id()),
        ErrorKind::ClientRejected
    );
    for refused in [
        rig.client.sign_in_again(alex.id()),
        rig.client.enable_plan_use(alex.id()),
    ] {
        assert_eq!(refused.unwrap_err().kind(), ErrorKind::ClientRejected);
    }
    assert!(rig.journal.about("send").is_empty());
    assert!(rig.journal.about("remove").is_empty());
    assert!(rig.journal.about("write").is_empty());
    assert!(rig.client.access_token(sam.id()).is_ok());

    // A sign-out deletes the tokens and keeps what is known.
    drop(rig.client.sign_out(alex.id()).unwrap());
    assert!(rig.credentials_of(alex.id()).is_none());
    assert_eq!(state(alex.id()), AccountState::RegistrationRejected);

    // The way out: forget the account and add it again, which registers
    // anew.
    drop(rig.client.forget(alex.id()).unwrap());
    let added = rig.add(&User::alex());
    assert_eq!(added.state(), AccountState::SignedIn);
    assert_eq!(rig.provider.registered_names().len(), 3);
}

#[test]
fn a_rejected_registration_retries_credential_removal_on_token_calls() {
    for force_renewal in [false, true] {
        let rig = Rig::new();
        let alex = rig.add(&User::alex());
        let first = rig.client.access_token(alex.id()).unwrap();
        rig.at(DUE);
        rig.store.fail_removes();
        rig.transport.fail("refresh", 1, UNKNOWN_CLIENT);

        let error = rig.client.access_token(alex.id()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ClientRejected);
        assert_eq!(error.provider_code(), Some("invalid_client"));
        assert_eq!(
            rig.client.account(alex.id()).unwrap().state(),
            AccountState::RegistrationRejected
        );
        assert!(rig.credentials_of(alex.id()).is_some());

        rig.store.heal();
        rig.journal.clear();
        let other = rig.another_client();
        let error = if force_renewal {
            other.access_token_after_rejection(alex.id(), &first)
        } else {
            other.access_token(alex.id())
        }
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ClientRejected);
        assert!(rig.credentials_of(alex.id()).is_none());
        assert!(rig.journal.about("send").is_empty());
        assert!(rig.journal.about("write").is_empty());
    }
}

#[test]
fn a_temporary_failure_returns_its_error_and_changes_nothing() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.at(DUE);
    let before = rig.store.snapshot();
    for failure in [
        Failure::Unreachable,
        Failure::Status(503, r#"{"error":"invalid_client"}"#),
        Failure::Status(429, r#"{"error":"invalid_grant"}"#),
    ] {
        rig.transport.fail("refresh", 1, failure);
        assert_eq!(
            kind_of_token_error(&rig.client, alex.id()),
            ErrorKind::Temporary
        );
        assert_eq!(rig.store.snapshot(), before);
    }
    assert!(rig.client.access_token(alex.id()).is_ok());
}

#[test]
fn an_unreadable_answer_returns_its_error_and_changes_nothing() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.at(DUE);
    let before = rig.store.snapshot();
    rig.transport.fail(
        "refresh",
        1,
        Failure::Status(200, r#"{"token_type":"Bearer"}"#),
    );

    assert_eq!(
        kind_of_token_error(&rig.client, alex.id()),
        ErrorKind::InvalidResponse
    );
    assert_eq!(rig.store.snapshot(), before);
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedIn
    );
}

#[test]
fn a_successor_that_cannot_be_stored_gives_a_store_error_and_no_token() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.at(DUE);
    rig.store.fail_writes_to(&format!("account-{}", alex.id()));

    let error = rig.client.access_token(alex.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Store);
    assert_eq!(rig.journal.count("send refresh"), 1);
}

#[test]
fn a_terminal_refusal_stays_the_error_when_recording_it_fails() {
    for (refusal, kind, code) in [
        (SPENT, ErrorKind::SignInRequired, "invalid_grant"),
        (UNKNOWN_CLIENT, ErrorKind::ClientRejected, "invalid_client"),
    ] {
        let rig = Rig::new();
        let alex = rig.add(&User::alex());
        rig.at(DUE);
        rig.transport.fail("refresh", 2, refusal);
        rig.store.fail_writes_to("installation");

        let error = rig.client.access_token(alex.id()).unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(error.provider_code(), Some(code));
        assert!(error.http_status().is_some());
        assert!(!error.state_saved(), "{kind:?}");
        assert!(format!("{error:?}").contains("state_saved: false"));
        assert_eq!(
            rig.client.account(alex.id()).unwrap().state(),
            AccountState::SignedIn,
            "nothing was recorded"
        );
    }
}

#[test]
fn an_ended_session_that_could_not_be_recorded_is_recorded_by_the_next_renewal() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.at(DUE);
    rig.transport.fail("refresh", 2, SPENT);
    rig.store.fail_writes_to("installation");
    assert!(
        !rig.client
            .access_token(alex.id())
            .unwrap_err()
            .state_saved()
    );

    rig.store.heal();
    let error = rig.client.access_token(alex.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::SignInRequired);
    assert!(error.state_saved());
    assert_eq!(rig.journal.count("send refresh"), 2);
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignInRequired
    );
}

#[test]
fn a_rejected_registration_keeps_its_tokens_until_the_rejection_is_recorded() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.at(DUE);
    rig.transport.fail("refresh", 3, UNKNOWN_CLIENT);
    rig.store.fail_writes_to("installation");
    assert!(
        !rig.client
            .access_token(alex.id())
            .unwrap_err()
            .state_saved()
    );
    assert!(rig.credentials_of(alex.id()).is_some());

    // The next renewal meets the refusal again instead of asking for a
    // sign-in that cannot work, and retries the recording.
    let error = rig.client.access_token(alex.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ClientRejected);
    assert!(!error.state_saved());
    assert!(rig.credentials_of(alex.id()).is_some());

    rig.store.heal();
    let error = rig.client.access_token(alex.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ClientRejected);
    assert!(error.state_saved());
    assert_eq!(rig.journal.count("send refresh"), 3);
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::RegistrationRejected
    );
    assert!(rig.credentials_of(alex.id()).is_none());
}

#[test]
fn a_cancellation_that_wins_over_an_unrecorded_refusal_reports_the_state_unsaved() {
    for (refusal, code) in [(SPENT, "invalid_grant"), (UNKNOWN_CLIENT, "invalid_client")] {
        let rig = Rig::new();
        let alex = rig.add(&User::alex());
        rig.at(DUE);
        rig.transport.fail("refresh", 1, refusal);
        rig.store.fail_writes_to("installation");
        let stop = siwc::Canceller::new();
        let trigger = stop.clone();
        rig.store
            .before_next_lock_of("installation", move || trigger.cancel());

        let sent = std::cell::Cell::new(0);
        let error = rig
            .client
            .call_cancellable(alex.id(), &stop, api_call(&rig, &sent))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Cancelled, "{code}");
        assert!(!error.state_saved(), "{code}");
        assert_eq!(rig.journal.count("send refresh"), 1);
        assert_eq!(sent.get(), 0);
    }
}

#[test]
fn an_expired_session_without_a_refresh_token_stays_sign_in_required_when_recording_fails() {
    let rig = Rig::new();
    rig.provider
        .alter_next_response(|body| drop(body.remove("refresh_token")));
    let alex = rig.add(&User::alex());
    rig.at(7200);
    rig.store.fail_writes_to("installation");

    let error = rig.client.access_token(alex.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::SignInRequired);
    assert!(!error.state_saved());
    assert!(rig.credentials_of(alex.id()).is_some());

    rig.store.heal();
    let error = rig.client.access_token(alex.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::SignInRequired);
    assert!(error.state_saved());
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignInRequired
    );
    assert!(rig.credentials_of(alex.id()).is_none());
}

#[test]
fn a_cancellation_that_stops_recording_an_ended_session_reports_the_state_unsaved() {
    let rig = Rig::new();
    rig.provider
        .alter_next_response(|body| drop(body.remove("refresh_token")));
    let alex = rig.add(&User::alex());
    rig.at(7200);
    let stop = siwc::Canceller::new();
    let trigger = stop.clone();
    rig.store
        .before_next_lock_of("installation", move || trigger.cancel());

    let sent = std::cell::Cell::new(0);
    let error = rig
        .client
        .call_cancellable(alex.id(), &stop, api_call(&rig, &sent))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(!error.state_saved());
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedIn
    );
    assert!(rig.credentials_of(alex.id()).is_some());
    assert_eq!(sent.get(), 0);
}

#[test]
fn signed_out_and_sign_in_required_accounts_get_sign_in_required() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sam = rig.add(&User::sam());
    let jo = rig.add(&User::jo());
    let rejected = rig.client.access_token(jo.id()).unwrap();
    let signed_out = rig.client.sign_out(alex.id()).unwrap();
    assert!(signed_out.revocation_confirmed());
    rig.at(DUE);
    rig.transport.fail("refresh", 1, SPENT);
    rig.client.access_token(sam.id()).unwrap_err();

    rig.journal.clear();
    for id in [alex.id(), sam.id()] {
        assert_eq!(
            kind_of_token_error(&rig.client, id),
            ErrorKind::SignInRequired
        );
        let error = rig
            .client
            .access_token_after_rejection(id, &rejected)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SignInRequired);
    }
    assert!(rig.journal.about("send").is_empty());
}

#[test]
fn each_of_four_accounts_gets_the_token_issued_for_its_own_client() {
    let rig = Rig::new();
    let mut accounts = Vec::new();
    for user in [User::alex(), User::sam(), User::kim(), User::alex()] {
        let account = rig.add(&user);
        let client = rig.provider.issued_clients().last().unwrap().clone();
        accounts.push((account.id().clone(), client));
    }
    let check = |accounts: &[(AccountId, String)]| {
        for (id, client) in accounts {
            let token = rig.token(id);
            assert_eq!(rig.provider.owner_of(&token).as_ref(), Some(client), "{id}");
        }
    };
    check(&accounts);

    // Right after another account was refreshed.
    let (first, _) = &accounts[0];
    let token = rig.client.access_token(first).unwrap();
    rig.client
        .access_token_after_rejection(first, &token)
        .unwrap();
    check(&accounts);

    // Right after another account was signed out, and one forgotten.
    let (signed_out, _) = accounts.remove(1);
    let _ = rig.client.sign_out(&signed_out).unwrap();
    check(&accounts);
    let (forgotten, _) = accounts.remove(1);
    let _ = rig.client.forget(&forgotten).unwrap();
    check(&accounts);

    // And once all of them are due.
    rig.at(DUE);
    check(&accounts);
    assert_eq!(rig.journal.count("send refresh"), 1 + accounts.len());
}

#[test]
fn swapped_credentials_entries_fail_for_both_accounts_without_a_request() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sam = rig.add(&User::sam());
    let alex_entry = rig.credentials_of(alex.id()).unwrap();
    let sam_entry = rig.credentials_of(sam.id()).unwrap();
    rig.store.put(&format!("account-{}", alex.id()), &sam_entry);
    rig.store.put(&format!("account-{}", sam.id()), &alex_entry);
    rig.at(DUE);
    rig.journal.clear();

    for id in [alex.id(), sam.id()] {
        assert_eq!(
            kind_of_token_error(&rig.client, id),
            ErrorKind::StoreCorrupt
        );
        assert_eq!(
            rig.client.sign_in_again(id).unwrap_err().kind(),
            ErrorKind::StoreCorrupt
        );
    }
    assert!(rig.journal.about("send").is_empty());
    assert!(rig.journal.about("write").is_empty());
}

#[test]
fn credentials_of_the_same_person_in_another_registrations_slot_are_refused() {
    let rig = Rig::new();
    let personal = rig.add(&User::alex());
    let team = rig.add(&User::alex());
    let team_entry = rig.credentials_of(team.id()).unwrap();
    rig.store
        .put(&format!("account-{}", personal.id()), &team_entry);

    assert_eq!(
        kind_of_token_error(&rig.client, personal.id()),
        ErrorKind::StoreCorrupt
    );
    assert!(rig.client.access_token(team.id()).is_ok());
}

#[test]
fn stored_credentials_for_the_right_client_but_another_subject_are_refused() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let mut credentials: serde_json::Value =
        serde_json::from_slice(&rig.credentials_of(account.id()).unwrap()).unwrap();
    credentials["subject"] = serde_json::json!("user-synthetic-other");
    rig.store.put(
        &format!("account-{}", account.id()),
        &serde_json::to_vec(&credentials).unwrap(),
    );
    rig.at(DUE);
    rig.journal.clear();

    assert_eq!(
        kind_of_token_error(&rig.client, account.id()),
        ErrorKind::StoreCorrupt
    );
    assert!(rig.journal.about("send").is_empty());
}

#[test]
fn after_a_rejection_a_token_someone_else_renewed_comes_without_a_request() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let rejected = rig.client.access_token(alex.id()).unwrap();
    let other = rig.another_client();
    let renewed = other
        .access_token_after_rejection(alex.id(), &rejected)
        .unwrap();
    assert_ne!(renewed.expose(), rejected.expose());

    rig.journal.clear();
    let again = rig
        .client
        .access_token_after_rejection(alex.id(), &rejected)
        .unwrap();
    assert_eq!(again.expose(), renewed.expose());
    assert_eq!(rig.journal.about("send"), Vec::<String>::new());
}

#[test]
fn after_a_rejection_a_token_someone_else_renewed_that_is_due_itself_is_renewed() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let rejected = rig.client.access_token(alex.id()).unwrap();
    let other = rig.another_client();
    let renewed = other
        .access_token_after_rejection(alex.id(), &rejected)
        .unwrap();

    // Much later the first process comes back with the token it still
    // holds; the stored one is another, and due.
    rig.at(DUE);
    rig.journal.clear();
    let again = rig
        .client
        .access_token_after_rejection(alex.id(), &rejected)
        .unwrap();
    assert_eq!(rig.journal.count("send refresh"), 1);
    assert_ne!(again.expose(), renewed.expose());
    assert_eq!(rig.token(alex.id()), again.expose());
}

#[test]
fn after_a_rejection_the_same_token_is_renewed_although_it_is_not_due() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let rejected = rig.client.access_token(alex.id()).unwrap();
    rig.journal.clear();

    let renewed = rig
        .client
        .access_token_after_rejection(alex.id(), &rejected)
        .unwrap();
    assert_ne!(renewed.expose(), rejected.expose());
    assert_eq!(rig.journal.count("send refresh"), 1);
    assert_eq!(rig.token(alex.id()), renewed.expose());
}

#[test]
fn models_are_read_with_the_accounts_token() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let models = rig.client.models(alex.id()).unwrap();
    let slugs: Vec<_> = models.iter().map(|model| model.id()).collect();
    assert_eq!(slugs, ["example-large", "example-small", "example-mini"]);
}

#[test]
fn a_rejected_token_is_renewed_once_and_the_models_asked_again() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    // The provider's clock is past the token's expiry; the client's is not.
    rig.provider.set_now(NOW + 4000);
    rig.journal.clear();

    assert_eq!(rig.client.models(alex.id()).unwrap().len(), 3);
    assert_eq!(
        rig.journal.about("send"),
        ["send models", "send refresh", "send models"]
    );
}

#[test]
fn a_token_rejected_again_after_its_renewal_is_returned_as_the_error() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let rejected = r#"{"error":{"code":"subscription_sharing_invalid_user"}}"#;
    rig.transport
        .fail("models", 2, Failure::Status(401, rejected));
    rig.journal.clear();

    let error = rig.client.models(alex.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TokenRejected);
    assert_eq!(
        rig.journal.about("send"),
        ["send models", "send refresh", "send models"]
    );
}

#[test]
fn other_refusals_are_returned_without_a_renewal() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let limit = r#"{"error":{"code":"subscription_sharing_usage_limit_exceeded"}}"#;
    rig.provider.refuse_next_api_request(429, limit);
    rig.journal.clear();

    assert_eq!(
        rig.client.models(alex.id()).unwrap_err().kind(),
        ErrorKind::UsageLimit
    );
    assert_eq!(rig.journal.about("send"), ["send models"]);

    let off = rig.add(&User::sam().without_plan_use());
    assert_eq!(
        rig.client.models(off.id()).unwrap_err().kind(),
        ErrorKind::PlanUseNotGranted
    );
}

// `Client::call`

/// One API request as an app sends it through `call`: the models endpoint
/// of the fake provider stands for any API request.
fn api_call(
    rig: &Rig,
    sent: &std::cell::Cell<u32>,
) -> impl FnMut(&siwc::AccessToken) -> Result<Result<String, Refusal>, siwc::Error> {
    move |token| {
        sent.set(sent.get() + 1);
        let answer = rig.provider.answer(&Request::of(&Models::request(token)));
        Ok(match Refusal::from_response(answer.status, &answer.body) {
            Some(refusal) => Err(refusal.with_request_id(Some(&answer.request_id))),
            None => Ok(String::from_utf8(answer.body).unwrap()),
        })
    }
}

#[test]
fn a_call_sends_the_request_once_with_the_accounts_token() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sent = std::cell::Cell::new(0);
    let body = rig.client.call(alex.id(), api_call(&rig, &sent)).unwrap();
    assert!(body.contains("\"models\""), "{body}");
    assert_eq!(sent.get(), 1);
}

#[test]
fn a_refused_token_is_renewed_once_and_the_request_sent_again() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let first = rig.token(alex.id());
    rig.provider
        .refuse_next_api_request(401, r#"{"error":{"code":"invalid_api_key"}}"#);
    let sent = std::cell::Cell::new(0);
    rig.client.call(alex.id(), api_call(&rig, &sent)).unwrap();
    assert_eq!(sent.get(), 2);
    assert_ne!(rig.token(alex.id()), first);
    assert_eq!(
        rig.provider.last_seen().field("grant_type"),
        Some("refresh_token")
    );
}

#[test]
fn a_refusal_becomes_the_error_with_its_status_code_and_request_id() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.provider.refuse_next_api_request(
        429,
        r#"{"error":{"code":"subscription_sharing_usage_limit_exceeded","message":"synthetic"}}"#,
    );
    let sent = std::cell::Cell::new(0);
    let error = rig
        .client
        .call(alex.id(), api_call(&rig, &sent))
        .unwrap_err();
    assert_eq!(sent.get(), 1, "only a refused token is worth a second try");
    assert_eq!(error.kind(), ErrorKind::UsageLimit);
    assert_eq!(
        error.provider_code(),
        Some("subscription_sharing_usage_limit_exceeded")
    );
    assert_eq!(error.http_status(), Some(429));
    assert_eq!(
        error.request_id(),
        Some(rig.provider.last_request_id().as_str())
    );
    assert!(!format!("{error} {error:?}").contains("synthetic\""));
}

#[test]
fn an_error_of_the_apps_own_passes_through_unchanged() {
    #[derive(Debug, PartialEq)]
    enum AppError {
        Offline,
        Siwc(ErrorKind),
    }
    impl From<siwc::Error> for AppError {
        fn from(error: siwc::Error) -> Self {
            Self::Siwc(error.kind())
        }
    }
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let result: Result<(), AppError> = rig.client.call(alex.id(), |_| Err(AppError::Offline));
    assert_eq!(result, Err(AppError::Offline));
    let unknown = AccountId::parse("00000000000000000000000000000abc").unwrap();
    let result: Result<(), AppError> = rig.client.call(&unknown, |_| Ok(Ok(())));
    assert_eq!(result, Err(AppError::Siwc(ErrorKind::UnknownAccount)));
}

#[test]
fn a_token_endpoint_error_keeps_its_status_and_request_id() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.at(DUE);
    rig.transport.fail("refresh", 1, SPENT);
    let error = rig.client.access_token(alex.id()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::SignInRequired);
    assert_eq!(error.http_status(), Some(400));
}

/// An app's request that the API refuses with `status` and `body` the first
/// `unserved` times and serves after that.
fn unserved_first<'a>(
    unserved: u32,
    status: u16,
    body: &'static str,
    retry_after: Option<&'static str>,
    sent: &'a std::cell::Cell<u32>,
) -> impl FnMut(&siwc::AccessToken) -> Result<Result<&'static str, Refusal>, siwc::Error> + 'a {
    move |_token| {
        sent.set(sent.get() + 1);
        Ok(if sent.get() <= unserved {
            Err(Refusal::from_response(status, body.as_bytes())
                .unwrap()
                .with_retry_after(retry_after))
        } else {
            Ok("served")
        })
    }
}

#[test]
fn a_request_the_api_cannot_serve_for_now_is_sent_again_after_growing_waits() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sent = std::cell::Cell::new(0);
    let served = rig
        .client
        .call(alex.id(), unserved_first(2, 503, "{}", None, &sent))
        .unwrap();
    assert_eq!(served, "served");
    assert_eq!(sent.get(), 3);
    let waits = rig.clock.waits();
    assert_eq!(waits.len(), 2, "{waits:?}");
    let second = std::time::Duration::from_secs(1);
    assert!(second / 2 <= waits[0] && waits[0] <= second, "{waits:?}");
    assert!(second <= waits[1] && waits[1] <= second * 2, "{waits:?}");
}

#[test]
fn after_three_attempts_the_last_refusal_is_the_error() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sent = std::cell::Cell::new(0);
    // A 429 without a usage-limit code is the API's own rate limit.
    let error = rig
        .client
        .call(alex.id(), unserved_first(u32::MAX, 429, "{}", None, &sent))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert_eq!(error.http_status(), Some(429));
    assert_eq!(sent.get(), 3);
    assert_eq!(rig.clock.waits().len(), 2);
}

#[test]
fn a_usage_limit_is_never_sent_again() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sent = std::cell::Cell::new(0);
    let usage_limit = r#"{"error":{"code":"subscription_sharing_usage_limit_exceeded"}}"#;
    let error = rig
        .client
        .call(
            alex.id(),
            unserved_first(1, 429, usage_limit, Some("1"), &sent),
        )
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UsageLimit);
    assert_eq!(sent.get(), 1);
    assert_eq!(rig.clock.waits(), []);
}

#[test]
fn the_wait_the_api_asks_for_is_taken_up_to_thirty_seconds() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sent = std::cell::Cell::new(0);
    rig.client
        .call(alex.id(), unserved_first(1, 503, "{}", Some("30"), &sent))
        .unwrap();
    assert_eq!(rig.clock.waits(), [std::time::Duration::from_secs(30)]);

    sent.set(0);
    let error = rig
        .client
        .call(alex.id(), unserved_first(1, 503, "{}", Some("31"), &sent))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Temporary);
    assert_eq!(sent.get(), 1, "a longer wait is the app's to decide");
    assert_eq!(rig.clock.waits().len(), 1);
}

#[test]
fn a_cancelled_call_stops_before_sending_or_retrying() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.journal.clear();

    let pre_cancelled = siwc::Canceller::new();
    pre_cancelled.cancel();
    let sent = std::cell::Cell::new(0);
    let error = rig
        .client
        .call_cancellable(alex.id(), &pre_cancelled, api_call(&rig, &sent))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(sent.get(), 0);
    assert!(rig.journal.about("send").is_empty());

    // Cancelling while a request is in flight stops before renewing a refused token or sleeping.
    let during_send = siwc::Canceller::new();
    let trigger = during_send.clone();
    let attempts = std::cell::Cell::new(0);
    let error = rig
        .client
        .call_cancellable(
            alex.id(),
            &during_send,
            |_token| -> Result<Result<(), Refusal>, siwc::Error> {
                attempts.set(attempts.get() + 1);
                trigger.cancel();
                Ok(Err(Refusal::from_response(401, b"{}").unwrap()))
            },
        )
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(attempts.get(), 1);
    assert!(rig.journal.about("send").is_empty());
}

#[test]
fn cancelling_wakes_a_long_retry_wait_at_once() {
    #[derive(Debug)]
    struct NotifyingClock(std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>);

    impl siwc::Clock for NotifyingClock {
        fn now(&self) -> siwc::UnixTime {
            siwc::UnixTime::from_secs(NOW)
        }

        fn sleep_cancellable(
            &self,
            wait: std::time::Duration,
            canceller: &siwc::Canceller,
        ) -> bool {
            if let Some(entered) = self.0.lock().unwrap().take() {
                entered.send(()).unwrap();
            }
            siwc::SystemClock.sleep_cancellable(wait, canceller)
        }
    }

    let (entered_sleep, sleeping) = std::sync::mpsc::channel();
    let provider = std::sync::Arc::new(crate::support::provider::FakeProvider::new(NOW));
    let client = siwc::Client::builder(
        siwc::AppName::new("Paste Perfect").unwrap(),
        siwc::store::MemoryStore::new(),
        std::sync::Arc::clone(&provider),
    )
    .clock(NotifyingClock(std::sync::Mutex::new(Some(entered_sleep))))
    .build();
    let mut manual = client.add_account_manually().unwrap();
    let query = provider.authorize(manual.authorization_link(), &User::alex());
    let redirect_uri = manual
        .authorization_link()
        .split('&')
        .find_map(|part| part.strip_prefix("redirect_uri="))
        .unwrap()
        .replace("%3A", ":")
        .replace("%2F", "/");
    let alex = manual
        .finish(&format!("{redirect_uri}?{query}"))
        .unwrap()
        .into_account();

    let canceller = siwc::Canceller::default();
    let stop = canceller.clone();
    let started = std::time::Instant::now();
    let worker_client = client.clone();
    let id = alex.id().clone();
    let handle = std::thread::spawn(move || {
        worker_client.call_cancellable(
            &id,
            &canceller,
            |_token| -> Result<Result<(), Refusal>, siwc::Error> {
                Ok(Err(Refusal::from_response(503, b"{}")
                    .unwrap()
                    .with_retry_after(Some("30"))))
            },
        )
    });

    sleeping
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    stop.cancel();
    let error = handle.join().unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "woke immediately out of a 30s Retry-After wait"
    );
}

#[test]
fn cancelling_after_refresh_still_commits_the_new_plan_grant() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let old = rig.token(account.id());
    let stop = siwc::Canceller::new();
    let during_refresh = stop.clone();
    rig.provider.alter_next_response(move |body| {
        during_refresh.cancel();
        body.insert(
            "scope".into(),
            serde_json::json!("openid profile email offline_access"),
        );
    });
    rig.at(DUE);
    let result: Result<(), siwc::Error> = rig.client.call_cancellable(account.id(), &stop, |_| {
        panic!("a cancelled request must not send the renewed token")
    });
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    assert!(!rig.client.account(account.id()).unwrap().plan_use());
    assert_ne!(rig.token(account.id()), old);
}
