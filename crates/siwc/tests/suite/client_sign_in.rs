//! `Client` sign-ins over real loopback sockets: adding accounts, signing
//! them in again and enabling plan use.

use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use siwc::loopback::{Listener, Text, Texts};
use siwc::{AccountId, AccountState, ErrorKind, SignIn};

use crate::support::browser::{Browser, PATIENCE, Response};
use crate::support::provider::{Seen, User};
use crate::support::recording::Failure;
use crate::support::rig::Rig;

/// The authorization requests the provider saw, oldest first.
fn authorization_requests(rig: &Rig) -> Vec<Seen> {
    rig.provider
        .seen()
        .into_iter()
        .filter(|seen| seen.field("response_type").is_some())
        .collect()
}

fn last_authorization_request(rig: &Rig) -> Seen {
    authorization_requests(rig).pop().unwrap()
}

/// Where in the journal `event` happened first and last.
fn first(events: &[String], event: &str) -> usize {
    events
        .iter()
        .position(|seen| seen == event)
        .unwrap_or_else(|| panic!("{event} not in {events:?}"))
}

fn last(events: &[String], event: &str) -> usize {
    events
        .iter()
        .rposition(|seen| seen == event)
        .unwrap_or_else(|| panic!("{event} not in {events:?}"))
}

/// Adds `count` accounts: one real sign-in, the rest copied into the
/// installation record with IDs and client IDs of their own.
fn fill(rig: &Rig, count: usize) {
    rig.add(&User::alex());
    let mut record: Value =
        serde_json::from_slice(&rig.store.bytes("installation").unwrap()).unwrap();
    let template = record["accounts"][0].clone();
    for index in 1..count {
        let mut copy = template.clone();
        copy["id"] = json!(format!("{index:032x}"));
        copy["client_id"] = json!(format!("app_filler{index:04}"));
        record["accounts"].as_array_mut().unwrap().push(copy);
    }
    rig.store.put("installation", record.to_string().as_bytes());
    assert_eq!(rig.client.accounts().unwrap().len(), count);
}

fn signed_in_page(page: &Response) {
    assert_eq!(page.status, 200);
    assert_eq!(page.heading(), "Signed in to Paste Perfect");
}

fn failed_page(page: &Response) {
    assert_eq!(page.status, 200);
    assert_eq!(page.heading(), "Sign-in did not complete");
}

#[test]
fn adding_an_account_beyond_32_is_refused_with_account_limit() {
    let rig = Rig::new();
    fill(&rig, 32);
    assert_eq!(
        rig.client.add_account().unwrap_err().kind(),
        ErrorKind::AccountLimit
    );
}

#[test]
fn a_second_sign_in_of_one_client_waits_until_the_first_is_dropped() {
    let rig = Rig::new();
    let first = rig.client.add_account().unwrap();
    for refused in [rig.client.add_account(), rig.client.clone().add_account()] {
        assert_eq!(refused.unwrap_err().kind(), ErrorKind::SignInInProgress);
    }
    // Another client, standing in for another process, is not held up.
    drop(rig.another_client().add_account().unwrap());

    drop(first);
    let account = rig.add(&User::alex());
    assert_eq!(account.state(), AccountState::SignedIn);
}

#[test]
fn signing_in_again_shares_the_one_sign_in_slot_of_the_client() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let adding = rig.client.add_account().unwrap();
    assert_eq!(
        rig.client.sign_in_again(alex.id()).unwrap_err().kind(),
        ErrorKind::SignInInProgress
    );
    drop(adding);
    let again = rig.client.sign_in_again(alex.id()).unwrap();
    assert_eq!(
        rig.client.add_account().unwrap_err().kind(),
        ErrorKind::SignInInProgress
    );
    drop(again);
}

#[test]
fn adding_an_account_registers_anew_without_a_hint_on_the_listeners_port() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    let port = Browser::new(sign_in.start_link()).port;
    let (result, page) = rig.approve(sign_in, &User::alex());
    result.unwrap();
    signed_in_page(&page);

    let request = last_authorization_request(&rig);
    assert_eq!(request.field("client_id"), Some("dynamic_agent_client"));
    assert_eq!(request.field("agent_name_hint"), Some("Paste Perfect"));
    assert_eq!(
        request.field("redirect_uri"),
        Some(format!("http://127.0.0.1:{port}/auth/callback").as_str())
    );
    for hint in ["login_hint", "id_token_hint", "prompt"] {
        assert_eq!(request.field(hint), None, "{hint}");
    }
}

#[test]
fn the_answer_page_shows_the_configured_texts_under_the_apps_name() {
    let rig = Rig::new();
    let mut texts = Texts::default();
    texts.lang = "de".to_owned();
    texts.signed_in = Text::new("Angemeldet bei {app}", "Du kannst diesen Tab schließen.");
    let client = rig.builder("Paste Perfect").page_texts(texts).build();

    let (result, page) = rig.approve(client.add_account().unwrap(), &User::alex());
    result.unwrap();
    assert_eq!(page.heading(), "Angemeldet bei Paste Perfect");
    assert!(page.body.contains("<html lang=\"de\">"));
}

#[test]
fn a_configured_callback_port_is_the_one_the_sign_in_listens_on() {
    let rig = Rig::new();
    let port = Listener::bind().unwrap().port();
    let client = rig.builder("Paste Perfect").callback_port(port).build();

    let sign_in = client.add_account().unwrap();
    assert!(
        sign_in
            .start_link()
            .starts_with(&format!("http://127.0.0.1:{port}/start/"))
    );
    let (result, _) = rig.approve(sign_in, &User::alex());
    result.unwrap();
    assert!(
        last_authorization_request(&rig)
            .field("redirect_uri")
            .unwrap()
            .contains(&format!(":{port}/"))
    );
}

#[test]
fn the_issued_client_id_is_stored_before_the_code_exchange_is_sent() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    rig.journal.clear();
    let (result, _) = rig.approve(sign_in, &User::alex());
    result.unwrap();

    let events = rig.journal.events();
    assert!(first(&events, "write installation") < first(&events, "send exchange"));
    assert!(first(&events, "send exchange") < first(&events, "send keys"));
}

#[test]
fn a_failed_exchange_keeps_the_registration_to_resume() {
    let rig = Rig::new();
    rig.transport
        .fail("exchange", 1, Failure::Status(503, "{}"));
    let (result, page) = rig.approve(rig.client.add_account().unwrap(), &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Temporary);
    failed_page(&page);
    assert!(rig.client.accounts().unwrap().is_empty());
    assert_eq!(
        rig.client.unfinished_registration().unwrap().as_deref(),
        Some("Paste Perfect")
    );

    let issued = rig.provider.issued_clients();
    let account = resume(&rig, &User::alex());
    let resumed = last_authorization_request(&rig);
    assert_eq!(resumed.field("client_id"), Some(issued[0].as_str()));
    assert_eq!(resumed.field("agent_name_hint"), None);
    assert_eq!(rig.provider.registered_names(), ["Paste Perfect"]);
    assert_eq!(account.registered_as(), "Paste Perfect");
    assert_eq!(
        rig.provider.owner_of(&rig.token(account.id())),
        Some(issued[0].clone())
    );
}

#[test]
fn a_failed_key_fetch_revokes_the_new_session_and_keeps_the_registration() {
    let rig = Rig::new();
    rig.transport.fail("keys", 1, Failure::Unreachable);
    let (result, _) = rig.approve(rig.client.add_account().unwrap(), &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Temporary);
    assert_eq!(
        rig.journal.about("send"),
        ["send exchange", "send keys", "send revoke"]
    );
    assert!(rig.client.accounts().unwrap().is_empty());

    resume(&rig, &User::alex());
    assert_eq!(rig.provider.registered_names().len(), 1);
}

/// A first attempt whose exchange gets no answer, so its registration is
/// pending.
fn with_pending_registration(rig: &Rig) {
    rig.transport.fail("exchange", 1, Failure::Unreachable);
    let (result, _) = rig.approve(rig.client.add_account().unwrap(), &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Temporary);
    assert_eq!(
        pending_client(rig),
        Some(rig.provider.issued_clients()[0].clone())
    );
}

/// The pending registration's client ID in the installation record.
fn pending_client(rig: &Rig) -> Option<String> {
    let record: Value = serde_json::from_slice(&rig.store.bytes("installation").unwrap()).unwrap();
    record["pending"]["client_id"].as_str().map(str::to_owned)
}

/// Resumes the unfinished registration as `user`; returns the account.
fn resume(rig: &Rig, user: &User) -> siwc::Account {
    let sign_in = rig.client.resume_unfinished_registration().unwrap();
    let (result, page) = rig.approve(sign_in, user);
    assert_eq!(page.status, 200);
    result.unwrap().into_account()
}

fn next_attempt_registers_anew(rig: &Rig) {
    assert_eq!(pending_client(rig), None);
    rig.add(&User::alex());
    assert_eq!(
        last_authorization_request(rig).field("client_id"),
        Some("dynamic_agent_client")
    );
    assert_eq!(rig.provider.registered_names().len(), 2);
}

#[test]
fn a_resumed_registration_the_provider_rejects_is_cleared() {
    let rig = Rig::new();
    with_pending_registration(&rig);
    rig.transport.fail(
        "exchange",
        1,
        Failure::Status(401, r#"{"error":"invalid_client"}"#),
    );
    let resumed = rig.client.resume_unfinished_registration().unwrap();
    let (result, page) = rig.approve(resumed, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::ClientRejected);
    failed_page(&page);
    assert_eq!(
        last_authorization_request(&rig).field("client_id"),
        Some(rig.provider.issued_clients()[0].as_str())
    );

    next_attempt_registers_anew(&rig);
}

#[test]
fn a_resumed_registration_the_provider_rejects_stays_the_error_when_clearing_it_fails() {
    let rig = Rig::new();
    with_pending_registration(&rig);
    let issued = rig.provider.issued_clients();
    rig.transport.fail(
        "exchange",
        1,
        Failure::Status(401, r#"{"error":"invalid_client"}"#),
    );
    rig.store.fail_writes_to("installation");
    let resumed = rig.client.resume_unfinished_registration().unwrap();
    let (result, _) = rig.approve(resumed, &User::alex());
    let error = result.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ClientRejected);
    assert!(!error.state_saved());
    assert_eq!(pending_client(&rig), Some(issued[0].clone()));
}

#[test]
fn a_fresh_registration_the_provider_rejects_at_its_first_exchange_is_cleared() {
    let rig = Rig::new();
    rig.transport.fail(
        "exchange",
        1,
        Failure::Status(401, r#"{"error":"invalid_client"}"#),
    );
    let (result, page) = rig.approve(rig.client.add_account().unwrap(), &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::ClientRejected);
    failed_page(&page);

    next_attempt_registers_anew(&rig);
}

#[test]
fn a_registration_refusal_in_the_browser_is_client_rejected_and_keeps_the_pending_registration() {
    for code in ["unauthorized_client", "invalid_client"] {
        let rig = Rig::new();
        with_pending_registration(&rig);
        let issued = rig.provider.issued_clients();
        let resumed = rig.client.resume_unfinished_registration().unwrap();
        let (result, page) = rig.browse(resumed, move |browser, _| browser.fail(code));
        let error = result.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ClientRejected, "{code}");
        assert_eq!(error.provider_code(), Some(code));
        assert_eq!(error.http_status(), None, "no token endpoint answer");
        failed_page(&page);
        assert_eq!(pending_client(&rig), Some(issued[0].clone()), "{code}");

        // The recovery for `ClientRejected`: adding the account registers
        // anew and replaces the unfinished registration.
        rig.add(&User::alex());
        assert_eq!(pending_client(&rig), None, "{code}");
        assert_eq!(rig.provider.registered_names().len(), 2, "{code}");
    }
}

#[test]
fn a_registration_refusal_in_the_browser_for_a_new_registration_stores_nothing() {
    let rig = Rig::new();
    let (result, page) = rig.browse(rig.client.add_account().unwrap(), |browser, _| {
        browser.fail("invalid_client")
    });
    let error = result.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ClientRejected);
    failed_page(&page);
    assert_eq!(pending_client(&rig), None);
    assert!(rig.client.accounts().unwrap().is_empty());
}

#[test]
fn a_resumed_registration_is_kept_when_the_provider_says_try_again_later() {
    for code in ["server_error", "temporarily_unavailable"] {
        let rig = Rig::new();
        with_pending_registration(&rig);
        let issued = rig.provider.issued_clients();
        let resumed = rig.client.resume_unfinished_registration().unwrap();
        let (result, _) = rig.browse(resumed, move |browser, _| browser.fail(code));
        let error = result.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AuthorizationFailed, "{code}");
        assert_eq!(error.provider_code(), Some(code));
        assert_eq!(pending_client(&rig), Some(issued[0].clone()), "{code}");

        // Resuming again completes the same registration.
        resume(&rig, &User::alex());
        assert_eq!(
            last_authorization_request(&rig).field("client_id"),
            Some(issued[0].as_str())
        );
        assert_eq!(rig.provider.registered_names(), ["Paste Perfect"]);
    }
}

#[test]
fn a_resumed_registration_is_kept_when_the_authorization_error_concerns_only_the_attempt() {
    for code in [
        "login_required",
        "interaction_required",
        "consent_required",
        "account_selection_required",
        "invalid_request",
        "invalid_scope",
    ] {
        let rig = Rig::new();
        with_pending_registration(&rig);
        let issued = rig.provider.issued_clients();
        let resumed = rig.client.resume_unfinished_registration().unwrap();
        let (result, _) = rig.browse(resumed, move |browser, _| browser.fail(code));
        let error = result.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AuthorizationFailed, "{code}");
        assert_eq!(pending_client(&rig), Some(issued[0].clone()), "{code}");
    }
}

#[test]
fn adding_an_account_beside_an_unfinished_registration_registers_anew_and_replaces_it() {
    let rig = Rig::new();
    with_pending_registration(&rig);
    let unfinished = rig.provider.issued_clients()[0].clone();

    let account = rig.add(&User::alex());

    let request = last_authorization_request(&rig);
    assert_eq!(request.field("client_id"), Some("dynamic_agent_client"));
    assert_eq!(request.field("agent_name_hint"), Some("Paste Perfect"));
    let issued = rig.provider.issued_clients();
    assert_eq!(issued.len(), 2);
    assert_eq!(
        rig.provider.owner_of(&rig.token(account.id())),
        Some(issued[1].clone())
    );
    assert_ne!(issued[1], unfinished);
    assert_eq!(pending_client(&rig), None);
    assert_eq!(rig.client.unfinished_registration().unwrap(), None);
}

#[test]
fn resuming_without_an_unfinished_registration_is_invalid_input() {
    let rig = Rig::new();
    rig.add(&User::alex());

    let error = rig.client.resume_unfinished_registration().unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(rig.client.unfinished_registration().unwrap(), None);
}

#[test]
fn a_discarded_registration_is_named_and_the_next_account_registers_anew() {
    let rig = Rig::new();
    with_pending_registration(&rig);

    let discarded = rig.client.discard_unfinished_registration().unwrap();

    assert_eq!(discarded.as_deref(), Some("Paste Perfect"));
    next_attempt_registers_anew(&rig);
}

#[test]
fn a_discard_without_an_unfinished_registration_returns_none_and_writes_nothing() {
    let rig = Rig::new();
    rig.add(&User::alex());
    rig.journal.clear();

    assert_eq!(rig.client.discard_unfinished_registration().unwrap(), None);
    assert!(
        !rig.journal
            .events()
            .iter()
            .any(|event| event.starts_with("write")),
        "{:?}",
        rig.journal.events()
    );
    assert_eq!(rig.client.accounts().unwrap().len(), 1);
}

#[test]
fn a_discard_while_a_sign_in_waits_is_refused_and_keeps_the_registration() {
    let rig = Rig::new();
    with_pending_registration(&rig);
    let issued = rig.provider.issued_clients();
    let waiting = rig.client.add_account().unwrap();

    let error = rig.client.discard_unfinished_registration().unwrap_err();

    assert_eq!(error.kind(), ErrorKind::SignInInProgress);
    assert_eq!(pending_client(&rig), Some(issued[0].clone()));
    drop(waiting);
}

#[test]
fn a_new_account_is_listed_then_given_its_credentials_then_marked_signed_in() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    rig.journal.clear();
    let (result, _) = rig.approve(sign_in, &User::alex());
    let alex = result.unwrap().into_account();

    // The registration, the listed account, the signed-in account.
    let events = rig.journal.events();
    let records: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, event)| *event == "write installation")
        .map(|(index, _)| index)
        .collect();
    let [registered, listed, signed_in] = records[..] else {
        panic!("{events:?}");
    };
    let credentials = first(&events, &format!("write account-{}", alex.id()));
    assert!(registered < first(&events, "send exchange"));
    assert!(first(&events, "send exchange") < listed);
    assert!(listed < credentials && credentials < signed_in);
    assert!(rig.credentials_of(alex.id()).is_some());
    assert_eq!(alex.state(), AccountState::SignedIn);

    let sam = rig.add(&User::sam());
    assert_ne!(alex.id(), sam.id());
    assert_eq!(AccountId::parse(sam.id().as_str()).unwrap(), *sam.id());
    // The pending registration went with the stored account.
    assert_eq!(
        last_authorization_request(&rig).field("client_id"),
        Some("dynamic_agent_client")
    );
}

/// The names of the credentials entries in the store, without `account-`.
fn credentials_entries(rig: &Rig) -> Vec<String> {
    rig.store
        .snapshot()
        .into_iter()
        .filter_map(|(name, _)| name.strip_prefix("account-").map(str::to_owned))
        .collect()
}

#[test]
fn a_sign_in_cut_off_before_its_credentials_leaves_an_account_to_sign_in_again() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    // The registration and the listed account are written, nothing after.
    rig.store.cut_off_after(2);
    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Store);
    failed_page(&page);
    rig.store.heal();

    let [account] = &rig.client.accounts().unwrap()[..] else {
        panic!("one account is listed");
    };
    assert_eq!(account.state(), AccountState::SignInRequired);
    assert!(credentials_entries(&rig).is_empty(), "no tokens were kept");
    assert_eq!(
        rig.client.access_token(account.id()).unwrap_err().kind(),
        ErrorKind::SignInRequired
    );

    // The user signs the account in again under the same registration.
    let again = rig.client.sign_in_again(account.id()).unwrap();
    let (result, _) = rig.approve(again, &User::alex());
    assert_eq!(result.unwrap().account().state(), AccountState::SignedIn);
    assert_eq!(rig.provider.registered_names(), ["Paste Perfect"]);
}

#[test]
fn a_sign_in_cut_off_after_its_credentials_leaves_no_tokens_without_an_account() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    // The credentials are written too; the account is not marked signed in.
    rig.store.cut_off_after(3);
    let (result, _) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Store);
    rig.store.heal();

    let [account] = &rig.client.accounts().unwrap()[..] else {
        panic!("one account is listed");
    };
    assert_eq!(account.state(), AccountState::SignInRequired);
    assert_eq!(credentials_entries(&rig), [account.id().to_string()]);

    let again = rig.client.sign_in_again(account.id()).unwrap();
    let (result, _) = rig.approve(again, &User::alex());
    assert_eq!(result.unwrap().account().state(), AccountState::SignedIn);
    assert_eq!(credentials_entries(&rig), [account.id().to_string()]);
}

#[test]
fn a_credentials_write_error_keeps_the_staged_account_for_retry() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    rig.store.fail_writes_to("account-");
    rig.journal.clear();
    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Store);
    failed_page(&page);
    rig.store.heal();

    let [account] = &rig.client.accounts().unwrap()[..] else {
        panic!("the staged account remains listed");
    };
    assert_eq!(account.state(), AccountState::SignInRequired);
    assert!(credentials_entries(&rig).is_empty());
    assert_eq!(rig.journal.count("send revoke"), 1);
    let issued = rig.provider.issued_clients();
    assert_eq!(pending_client(&rig), None);

    // Resuming completes the same registration.
    let again = rig.client.sign_in_again(account.id()).unwrap();
    let (result, _) = rig.approve(again, &User::alex());
    assert_eq!(result.unwrap().account().state(), AccountState::SignedIn);
    assert_eq!(
        last_authorization_request(&rig).field("client_id"),
        Some(issued[0].as_str())
    );
    assert_eq!(rig.provider.registered_names(), ["Paste Perfect"]);
}

/// The account every credentials entry belongs to is listed.
fn every_credentials_entry_has_a_listed_owner(rig: &Rig) {
    let listed: Vec<String> = rig
        .client
        .accounts()
        .unwrap()
        .iter()
        .map(|account| account.id().to_string())
        .collect();
    for owner in credentials_entries(rig) {
        assert!(listed.contains(&owner), "tokens without an account");
    }
}

#[test]
fn a_failed_installation_update_before_publication_revokes_the_new_session() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    // The registration, the listed account and the credentials are
    // written; marking the account fails, and so does taking the
    // credentials back only after confirming that publication did not happen.
    rig.store.fail_one_write_after(3);
    rig.journal.clear();
    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Store);
    failed_page(&page);
    rig.store.heal();
    assert_eq!(rig.journal.about("failed write installation").len(), 1);
    assert_eq!(rig.journal.about("remove account-").len(), 1);

    let [account] = &rig.client.accounts().unwrap()[..] else {
        panic!("the account stays listed");
    };
    assert_eq!(account.state(), AccountState::SignInRequired);
    assert!(credentials_entries(&rig).is_empty());
    every_credentials_entry_has_a_listed_owner(&rig);
    assert_eq!(pending_client(&rig), None);
    assert_eq!(rig.journal.count("send revoke"), 1);

    // Forgetting the account takes its entry along.
    drop(rig.client.forget(account.id()).unwrap());
    assert!(credentials_entries(&rig).is_empty());
}

#[test]
fn an_account_lock_that_cannot_be_taken_leaves_the_account_to_sign_in_again() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    rig.store.fail_locks_of("account-");
    rig.journal.clear();
    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::StoreBusy);
    failed_page(&page);
    rig.store.heal();

    // Nothing was written for the account, so nothing is taken back.
    let [account] = &rig.client.accounts().unwrap()[..] else {
        panic!("the account stays listed");
    };
    assert_eq!(account.state(), AccountState::SignInRequired);
    assert!(credentials_entries(&rig).is_empty());
    assert!(rig.journal.about("remove").is_empty());
    assert_eq!(rig.journal.count("send revoke"), 1);

    let again = rig.client.sign_in_again(account.id()).unwrap();
    let (result, _) = rig.approve(again, &User::alex());
    assert_eq!(result.unwrap().account().state(), AccountState::SignedIn);
    assert_eq!(rig.provider.registered_names(), ["Paste Perfect"]);
}

#[test]
fn a_sign_out_between_the_listing_and_the_lock_stands() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    let other = rig.another_client();
    rig.store.before_next_lock_of("account-", move || {
        let [listed] = &other.accounts().unwrap()[..] else {
            panic!("the new account is listed");
        };
        drop(other.sign_out(listed.id()).unwrap());
    });
    rig.journal.clear();
    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::SignInRequired);
    failed_page(&page);

    let [account] = &rig.client.accounts().unwrap()[..] else {
        panic!("the account stays listed");
    };
    assert_eq!(account.state(), AccountState::SignedOut);
    assert!(rig.journal.about("write account-").is_empty());
    assert!(credentials_entries(&rig).is_empty());
    assert_eq!(rig.journal.count("send revoke"), 1);
}

#[test]
fn a_removal_between_the_listing_and_the_lock_stands() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    let other = rig.another_client();
    rig.store.before_next_lock_of("account-", move || {
        let [listed] = &other.accounts().unwrap()[..] else {
            panic!("the new account is listed");
        };
        drop(other.forget(listed.id()).unwrap());
    });
    rig.journal.clear();
    let (result, _) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::UnknownAccount);

    assert!(rig.client.accounts().unwrap().is_empty());
    assert!(rig.journal.about("write account-").is_empty());
    assert!(credentials_entries(&rig).is_empty());
    assert_eq!(pending_client(&rig), None);
    assert_eq!(rig.journal.count("send revoke"), 1);
}

#[test]
fn the_limit_is_checked_again_when_the_account_is_stored() {
    let rig = Rig::new();
    fill(&rig, 31);
    let waiting = rig.client.add_account().unwrap();
    // Another process adds the 32nd account meanwhile.
    let other = rig.another_client();
    let (result, _) = rig.approve(other.add_account().unwrap(), &User::sam());
    result.unwrap();

    rig.journal.clear();
    let (result, page) = rig.approve(waiting, &User::kim());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::AccountLimit);
    failed_page(&page);
    assert_eq!(rig.client.accounts().unwrap().len(), 32);
    // Nothing was written for the refused account, and its session is
    // revoked.
    assert!(rig.journal.about("write account-").is_empty());
    assert_eq!(rig.journal.count("send revoke"), 1);
}

#[test]
fn the_tab_shows_signed_in_only_once_the_account_is_stored() {
    let rig = Rig::new();
    let journal = rig.journal.clone();
    let (result, page) = rig.browse(
        rig.client.add_account().unwrap(),
        move |browser, provider| {
            let page = browser.approve(provider, &User::alex());
            journal.push("page arrived".to_owned());
            page
        },
    );
    result.unwrap();
    signed_in_page(&page);
    let events = rig.journal.events();
    assert!(last(&events, "write installation") < first(&events, "page arrived"));
}

#[test]
fn the_tab_says_plan_use_is_off_when_the_grant_does_not_cover_it() {
    let rig = Rig::new();
    let (result, page) = rig.approve(
        rig.client.add_account().unwrap(),
        &User::alex().without_plan_use(),
    );
    assert!(!result.unwrap().account().plan_use());
    assert_eq!(page.heading(), "Signed in to Paste Perfect");
    assert!(
        page.body
            .contains("ChatGPT plan use is not enabled for Paste Perfect.")
    );
}

#[test]
fn a_declined_sign_in_answers_declined_and_returns_access_denied() {
    let rig = Rig::new();
    let (result, page) = rig.browse(rig.client.add_account().unwrap(), |browser, provider| {
        browser.decline(provider)
    });
    assert_eq!(result.unwrap_err().kind(), ErrorKind::AccessDenied);
    assert_eq!(page.heading(), "Sign-in cancelled");
    assert!(rig.client.accounts().unwrap().is_empty());
}

#[test]
fn a_store_failure_answers_failed_and_returns_the_store_error() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    rig.store.fail_writes_to("installation");
    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Store);
    failed_page(&page);
    // Nothing was exchanged without the client ID stored first.
    assert_eq!(rig.journal.count("send exchange"), 0);
}

#[test]
fn a_refused_code_answers_failed_and_returns_the_same_error() {
    let rig = Rig::new();
    rig.transport.fail(
        "exchange",
        1,
        Failure::Status(400, r#"{"error":"invalid_grant"}"#),
    );
    let (result, page) = rig.approve(rig.client.add_account().unwrap(), &User::alex());
    let error = result.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Rejected);
    assert_eq!(error.provider_code(), Some("invalid_grant"));
    failed_page(&page);
}

#[test]
fn plan_use_started_is_true_the_first_time_plan_use_is_granted_and_never_again() {
    let rig = Rig::new();
    let (alex, _) = rig.approve(rig.client.add_account().unwrap(), &User::alex());
    let alex = alex.unwrap();
    assert!(alex.plan_use_started());
    let (again, _) = rig.approve(
        rig.client.sign_in_again(alex.account().id()).unwrap(),
        &User::alex(),
    );
    assert!(!again.unwrap().plan_use_started());

    let off = User::sam().without_plan_use();
    let (sam, _) = rig.approve(rig.client.add_account().unwrap(), &off);
    let sam = sam.unwrap();
    assert!(!sam.plan_use_started());
    let id = sam.account().id().clone();
    let (still_off, _) = rig.approve(rig.client.sign_in_again(&id).unwrap(), &off);
    assert!(!still_off.unwrap().plan_use_started());
    let (enabled, page) = rig.approve(rig.client.enable_plan_use(&id).unwrap(), &User::sam());
    let enabled = enabled.unwrap();
    assert!(enabled.plan_use_started() && enabled.account().plan_use());
    signed_in_page(&page);
    let (enabled_again, _) = rig.approve(rig.client.enable_plan_use(&id).unwrap(), &User::sam());
    assert!(!enabled_again.unwrap().plan_use_started());
}

#[test]
fn a_second_account_of_the_same_person_is_kept_apart_and_named_as_sharing_the_login() {
    let rig = Rig::new();
    let personal = rig.add(&User::alex());
    let team = rig.add(&User::alex());
    let sam = rig.add(&User::sam());

    let clients = rig.provider.issued_clients();
    assert_eq!(clients.len(), 3);
    assert_ne!(personal.id(), team.id());
    assert_eq!(
        rig.provider.owner_of(&rig.token(personal.id())),
        Some(clients[0].clone())
    );
    assert_eq!(
        rig.provider.owner_of(&rig.token(team.id())),
        Some(clients[1].clone())
    );

    let personal = rig.client.account(personal.id()).unwrap();
    let team = rig.client.account(team.id()).unwrap();
    assert_eq!(personal.shares_login_with(), [team.id().clone()]);
    assert_eq!(team.shares_login_with(), [personal.id().clone()]);
    assert!(
        rig.client
            .account(sam.id())
            .unwrap()
            .shares_login_with()
            .is_empty()
    );
}

#[test]
fn a_sign_in_that_times_out_stores_nothing() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    rig.journal.clear();
    let error = sign_in.finish(Duration::ZERO).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert!(rig.journal.about("write").is_empty());
    assert!(rig.client.accounts().unwrap().is_empty());
}

#[test]
fn a_cancelled_sign_in_stores_nothing() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let before = rig.store.snapshot();
    let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
    sign_in.canceller().cancel();
    assert_eq!(
        sign_in.open_browser().unwrap_err().kind(),
        ErrorKind::Cancelled
    );
    assert_eq!(
        sign_in.finish(PATIENCE).unwrap_err().kind(),
        ErrorKind::Cancelled
    );
    assert_eq!(rig.store.snapshot(), before);
}

#[test]
fn cancelling_after_the_callback_arrives_stores_no_account_and_revokes_the_session() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    let canceller = sign_in.canceller();
    rig.store
        .before_next_lock_of("account-", move || canceller.cancel());
    rig.journal.clear();
    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    failed_page(&page);
    assert!(rig.client.accounts().unwrap().is_empty());
    assert!(credentials_entries(&rig).is_empty());
    assert_eq!(rig.journal.count("send revoke"), 1);

    let alex = rig.add(&User::alex().without_plan_use());
    let before = rig.store.snapshot();
    let again = rig.client.enable_plan_use(alex.id()).unwrap();
    let canceller = again.canceller();
    rig.store
        .before_next_lock_of("account-", move || canceller.cancel());
    let (result, page) = rig.approve(again, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    failed_page(&page);
    assert_eq!(rig.store.snapshot(), before);
}

#[test]
fn cancelling_before_the_final_installation_lock_rolls_back_the_new_account() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    let canceller = sign_in.canceller();
    let store = rig.store.clone();
    rig.store.before_next_lock_of("account-", move || {
        store.before_next_lock_of("installation", move || canceller.cancel());
    });

    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    failed_page(&page);
    assert!(rig.client.accounts().unwrap().is_empty());
    assert!(credentials_entries(&rig).is_empty());
    assert_eq!(pending_client(&rig), rig.provider.issued_clients().pop());
    assert_eq!(rig.journal.count("send revoke"), 1);
    rig.journal.assert_lock_rules();
}

#[test]
fn cancelling_during_exchange_takes_precedence_over_a_failed_key_request() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    let canceller = sign_in.canceller();
    rig.provider
        .alter_next_response(move |_| canceller.cancel());
    rig.transport.fail("keys", 1, Failure::Unreachable);

    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    failed_page(&page);
    assert_eq!(rig.journal.count("send keys"), 1);
    assert!(rig.client.accounts().unwrap().is_empty());
    assert!(credentials_entries(&rig).is_empty());
}

#[test]
fn cancelling_during_a_successful_exchange_revokes_before_staging_the_account() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account().unwrap();
    let stop = sign_in.canceller();
    rig.provider.alter_next_response(move |_| stop.cancel());

    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    failed_page(&page);
    assert!(rig.client.accounts().unwrap().is_empty());
    assert_eq!(rig.journal.count("write installation"), 2); // host and pending registration
    assert_eq!(
        rig.journal.about("send"),
        ["send exchange", "send keys", "send revoke"]
    );
}

#[test]
fn cancelling_during_reauthentication_keeps_the_current_session_after_a_failed_key_request() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let token = rig.token(account.id());
    let before = rig.store.snapshot();
    let again = rig.client.sign_in_again(account.id()).unwrap();
    let canceller = again.canceller();
    rig.provider
        .alter_next_response(move |_| canceller.cancel());
    rig.transport.fail("keys", 1, Failure::Unreachable);

    let (result, page) = rig.approve(again, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    failed_page(&page);
    assert_eq!(rig.store.snapshot(), before);
    assert_eq!(rig.token(account.id()), token);
    assert_eq!(rig.journal.count("send revoke"), 1);
}

#[test]
fn cancelling_after_an_existing_accounts_credential_write_keeps_the_new_session() {
    let rig = Rig::new();
    let account = rig.add(&User::alex().without_plan_use());
    let previous = rig.token(account.id());
    let again = rig.client.enable_plan_use(account.id()).unwrap();
    let canceller = again.canceller();
    rig.store
        .before_next_lock_of("installation", move || canceller.cancel());

    let (result, page) = rig.approve(again, &User::alex());
    assert!(result.unwrap().account().plan_use());
    signed_in_page(&page);
    assert_ne!(rig.token(account.id()), previous);
    assert_eq!(rig.journal.count("send revoke"), 0);
}

#[test]
fn a_sign_in_can_finish_on_another_thread() {
    fn sendable<T: Send>(value: T) -> T {
        value
    }
    let rig = Rig::new();
    let sign_in: SignIn = sendable(rig.client.add_account().unwrap());
    let browser = Browser::new(sign_in.start_link());
    let finishing = thread::spawn(move || sign_in.finish(PATIENCE));
    let page = browser.approve(&rig.provider, &User::alex());
    signed_in_page(&page);
    assert!(finishing.join().unwrap().is_ok());
}

#[test]
fn signing_in_again_with_stored_credentials_uses_its_registration_and_sends_no_hint() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let client = rig.provider.issued_clients()[0].clone();
    let (result, _) = rig.approve(rig.client.sign_in_again(alex.id()).unwrap(), &User::alex());
    result.unwrap();

    let request = last_authorization_request(&rig);
    assert_eq!(request.field("client_id"), Some(client.as_str()));
    assert_eq!(request.field("id_token_hint"), None);
    assert_eq!(request.field("login_hint"), None);
    assert_eq!(request.field("agent_name_hint"), None);
    assert_eq!(request.field("prompt"), None);
    assert_eq!(rig.provider.registered_names().len(), 1);
}

#[test]
fn enabling_plan_use_asks_for_consent_again() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex().without_plan_use());
    let (result, _) = rig.approve(
        rig.client.enable_plan_use(alex.id()).unwrap(),
        &User::alex(),
    );
    assert!(result.unwrap().account().plan_use());

    let request = last_authorization_request(&rig);
    assert_eq!(request.field("prompt"), Some("consent"));
    assert_eq!(request.field("id_token_hint"), None);
    assert_eq!(request.field("login_hint"), None);
}

#[test]
fn signing_in_again_as_another_person_revokes_the_new_session_and_keeps_the_old_one() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.client.set_label(alex.id(), Some("Work")).unwrap();
    let before = rig.store.snapshot();
    rig.journal.clear();

    let (result, page) = rig.approve(rig.client.sign_in_again(alex.id()).unwrap(), &User::sam());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::AccountMismatch);
    failed_page(&page);
    assert_eq!(rig.store.snapshot(), before);
    assert_eq!(
        rig.journal.about("send"),
        ["send exchange", "send keys", "send revoke"]
    );
}

#[test]
fn an_unavailable_account_lock_revokes_the_new_session_on_sign_in_again() {
    for signed_in in [true, false] {
        let rig = Rig::new();
        let account = rig.add(&User::alex());
        if !signed_in {
            let _signed_out = rig.client.sign_out(account.id()).unwrap();
        }
        let before = rig.store.snapshot();
        let again = rig.client.sign_in_again(account.id()).unwrap();
        rig.store.fail_locks_of("account-");
        rig.journal.clear();

        let (result, page) = rig.approve(again, &User::alex());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::StoreBusy);
        failed_page(&page);
        assert_eq!(rig.store.snapshot(), before);
        assert_eq!(
            rig.journal.about("send"),
            ["send exchange", "send keys", "send revoke"]
        );
    }
}

#[test]
fn signing_in_again_rechecks_the_registration_after_taking_the_account_lock() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let old_credentials = rig.credentials_of(account.id()).unwrap();
    let again = rig.client.sign_in_again(account.id()).unwrap();
    let store = rig.store.clone();
    rig.store.before_next_lock_of("account-", move || {
        let mut installation: Value =
            serde_json::from_slice(&store.bytes("installation").unwrap()).unwrap();
        installation["accounts"][0]["client_id"] = json!("app_synthetic_replacement");
        store.put("installation", &serde_json::to_vec(&installation).unwrap());
    });

    let (result, page) = rig.approve(again, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::AccountMismatch);
    failed_page(&page);
    assert_eq!(rig.credentials_of(account.id()).unwrap(), old_credentials);
    assert_eq!(rig.journal.count("send revoke"), 1);
}

#[test]
fn signing_in_again_replaces_the_credentials_under_the_account_lock() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex().without_plan_use());
    rig.client.set_label(alex.id(), Some("Work")).unwrap();
    let old = rig.credentials_of(alex.id()).unwrap();
    let renamed = User {
        name: Some("Alex Renamed"),
        ..User::alex()
    };

    let sign_in = rig.client.enable_plan_use(alex.id()).unwrap();
    rig.journal.clear();
    let (result, _) = rig.approve(sign_in, &renamed);
    let account = result.unwrap().into_account();

    let entry = format!("account-{}", alex.id());
    let events = rig.journal.events();
    let locked = first(&events, &format!("lock {entry}"));
    let written = first(&events, &format!("write {entry}"));
    let recorded = last(&events, "write installation");
    let unlocked = last(&events, &format!("unlock {entry}"));
    assert!(locked < written && written < recorded && recorded < unlocked);
    assert_ne!(rig.credentials_of(alex.id()).unwrap(), old);

    assert_eq!(account.id(), alex.id());
    assert_eq!(account.label(), Some("Work"));
    assert_eq!(account.registered_as(), "Paste Perfect");
    assert_eq!(account.state(), AccountState::SignedIn);
    assert!(account.plan_use());
    assert_eq!(account.identity().name(), Some("Alex Renamed"));
    assert_eq!(
        rig.client.account(alex.id()).unwrap().identity().name(),
        Some("Alex Renamed")
    );
}

#[test]
fn a_sign_in_again_write_error_checks_what_was_published() {
    // The credentials write can fail before publication, or the later
    // installation write can fail after credentials were stored.
    for writes_before_the_failure in [0, 1] {
        let rig = Rig::new();
        let alex = rig.add(&User::alex());
        drop(rig.client.sign_out(alex.id()).unwrap());
        let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
        rig.store.fail_one_write_after(writes_before_the_failure);
        rig.journal.clear();
        let (result, page) = rig.approve(sign_in, &User::alex());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Store);
        failed_page(&page);

        let account = rig.client.account(alex.id()).unwrap();
        assert_eq!(account.state(), AccountState::SignedOut);
        assert!(rig.credentials_of(alex.id()).is_none());
        assert_eq!(rig.journal.count("send revoke"), 1);
    }
}

#[test]
fn a_sign_in_again_that_cannot_be_stored_leaves_a_signed_in_account_its_session() {
    // The credentials cannot be written: the old session goes on.
    let rig = Rig::new();
    let alex = rig.add(&User::alex().without_plan_use());
    let old = rig.credentials_of(alex.id()).unwrap();
    let sign_in = rig.client.enable_plan_use(alex.id()).unwrap();
    rig.store.fail_one_write_after(0);
    rig.journal.clear();
    let (result, _) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Store);
    assert_eq!(rig.credentials_of(alex.id()).unwrap(), old);
    assert_eq!(rig.journal.count("send revoke"), 1);
    assert!(rig.provider.owner_of(&rig.token(alex.id())).is_some());

    // The account cannot be marked: the session just stored goes on.
    let sign_in = rig.client.enable_plan_use(alex.id()).unwrap();
    rig.store.fail_one_write_after(1);
    rig.journal.clear();
    let (result, _) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Store);
    assert_ne!(rig.credentials_of(alex.id()).unwrap(), old);
    assert!(rig.journal.about("send revoke").is_empty());
    assert!(rig.journal.about("remove").is_empty());
    assert_eq!(rig.journal.about("failed write installation").len(), 1);
    let account = rig.client.account(alex.id()).unwrap();
    assert_eq!(account.state(), AccountState::SignedIn);
    assert!(rig.provider.owner_of(&rig.token(alex.id())).is_some());
}

#[test]
fn a_registration_the_provider_gave_up_during_a_sign_in_again_marks_the_account() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    assert!(rig.credentials_of(alex.id()).is_some());
    rig.transport.fail(
        "exchange",
        1,
        Failure::Status(401, r#"{"error":"invalid_client"}"#),
    );
    let (result, page) = rig.approve(
        rig.client.enable_plan_use(alex.id()).unwrap(),
        &User::alex(),
    );
    assert_eq!(result.unwrap_err().kind(), ErrorKind::ClientRejected);
    failed_page(&page);

    let account = rig.client.account(alex.id()).unwrap();
    assert_eq!(account.state(), AccountState::RegistrationRejected);
    assert!(rig.credentials_of(alex.id()).is_none());
    assert_eq!(
        rig.client.sign_in_again(alex.id()).unwrap_err().kind(),
        ErrorKind::ClientRejected
    );
}

#[test]
fn a_registration_refusal_in_the_browser_during_a_sign_in_again_leaves_the_account_as_it_was() {
    for code in ["unauthorized_client", "invalid_client"] {
        let rig = Rig::new();
        let alex = rig.add(&User::alex());
        let before = rig.store.snapshot();
        rig.journal.clear();
        let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
        let (result, page) = rig.browse(sign_in, move |browser, _| browser.fail(code));
        let error = result.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ClientRejected, "{code}");
        assert_eq!(error.http_status(), None);
        failed_page(&page);

        // Only the token endpoint's answer marks the registration.
        assert_eq!(rig.store.snapshot(), before, "{code}");
        assert!(rig.journal.about("write").is_empty(), "{code}");
        assert!(rig.journal.about("send").is_empty(), "{code}");
        assert_eq!(
            rig.client.account(alex.id()).unwrap().state(),
            AccountState::SignedIn
        );
        assert!(rig.client.access_token(alex.id()).is_ok());
    }
}

#[test]
fn a_transient_authorization_error_during_a_sign_in_again_keeps_the_account_usable() {
    for code in ["temporarily_unavailable", "server_error", "login_required"] {
        let rig = Rig::new();
        let alex = rig.add(&User::alex());
        let before = rig.store.snapshot();
        let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
        let (result, _) = rig.browse(sign_in, move |browser, _| browser.fail(code));
        let error = result.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AuthorizationFailed, "{code}");
        assert_eq!(error.provider_code(), Some(code));
        assert_eq!(rig.store.snapshot(), before, "{code}");

        let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
        let (result, _) = rig.approve(sign_in, &User::alex());
        assert_eq!(result.unwrap().account().state(), AccountState::SignedIn);
    }
}

#[test]
fn a_registration_rejected_during_a_sign_in_again_stays_the_error_when_recording_it_fails() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.transport.fail(
        "exchange",
        1,
        Failure::Status(401, r#"{"error":"invalid_client"}"#),
    );
    rig.store.fail_writes_to("installation");
    let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
    let (result, page) = rig.approve(sign_in, &User::alex());
    let error = result.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ClientRejected);
    assert_eq!(error.http_status(), Some(401));
    assert!(!error.state_saved());
    failed_page(&page);
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedIn
    );
    // The tokens stay until the rejection is recorded, so the next renewal
    // meets the refusal again rather than reporting `SignInRequired`.
    assert!(rig.credentials_of(alex.id()).is_some());
}

#[test]
fn an_unrecorded_rejection_on_a_signed_out_account_is_recorded_by_the_next_sign_in_again() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    drop(rig.client.sign_out(alex.id()).unwrap());
    let invalid_client = || {
        rig.transport.fail(
            "exchange",
            1,
            Failure::Status(401, r#"{"error":"invalid_client"}"#),
        );
    };
    invalid_client();
    rig.store.fail_writes_to("installation");
    let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
    let error = rig.approve(sign_in, &User::alex()).0.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ClientRejected);
    assert!(!error.state_saved());

    // No tokens are stored, so no renewal can meet the refusal again; the
    // account still asks for a sign-in, and that sign-in records it.
    rig.store.heal();
    let state = || rig.client.account(alex.id()).unwrap().state();
    assert_eq!(state(), AccountState::SignedOut);
    assert_eq!(
        rig.client.access_token(alex.id()).unwrap_err().kind(),
        ErrorKind::SignInRequired
    );
    invalid_client();
    let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
    let error = rig.approve(sign_in, &User::alex()).0.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ClientRejected);
    assert!(error.state_saved());
    assert_eq!(state(), AccountState::RegistrationRejected);
}

#[test]
fn a_cancellation_that_wins_over_an_unrecorded_rejection_reports_the_state_unsaved() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.transport.fail(
        "exchange",
        1,
        Failure::Status(401, r#"{"error":"invalid_client"}"#),
    );
    rig.store.fail_writes_to("installation");
    let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
    let canceller = sign_in.canceller();
    rig.store
        .before_next_lock_of("account-", move || canceller.cancel());
    rig.journal.clear();
    let error = rig.approve(sign_in, &User::alex()).0.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(!error.state_saved());
    assert_eq!(rig.journal.count("send exchange"), 1);
}

#[test]
fn a_rejection_for_an_account_forgotten_during_its_sign_in_again_leaves_nothing_to_record() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.transport.fail(
        "exchange",
        1,
        Failure::Status(401, r#"{"error":"invalid_client"}"#),
    );
    let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
    drop(rig.client.forget(alex.id()).unwrap());
    let error = rig.approve(sign_in, &User::alex()).0.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ClientRejected);
    assert!(error.state_saved());
    assert_eq!(
        rig.client.account(alex.id()).unwrap_err().kind(),
        ErrorKind::UnknownAccount
    );
}

#[test]
fn a_rejected_registration_retries_credential_removal_on_sign_in_again() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.store.fail_removes();
    rig.transport.fail(
        "exchange",
        1,
        Failure::Status(401, r#"{"error":"invalid_client"}"#),
    );
    let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::ClientRejected);
    failed_page(&page);
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::RegistrationRejected
    );
    assert!(rig.credentials_of(alex.id()).is_some());

    assert_eq!(
        rig.client.sign_in_again(alex.id()).unwrap_err().kind(),
        ErrorKind::ClientRejected
    );
    rig.store.heal();
    rig.journal.clear();
    assert_eq!(
        rig.another_client()
            .sign_in_again(alex.id())
            .unwrap_err()
            .kind(),
        ErrorKind::ClientRejected
    );
    assert!(rig.credentials_of(alex.id()).is_none());
    assert!(rig.journal.about("send").is_empty());
    assert!(rig.journal.about("write").is_empty());
}

#[test]
fn a_sign_out_while_signing_in_again_stands_even_across_a_completed_cycle() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex().without_plan_use());
    let sign_in = rig.client.enable_plan_use(alex.id()).unwrap();
    let other = rig.another_client();
    drop(other.sign_out(alex.id()).unwrap());

    rig.journal.clear();
    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::SignInRequired);
    failed_page(&page);
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedOut
    );
    assert!(rig.credentials_of(alex.id()).is_none());
    assert_eq!(rig.journal.count("send revoke"), 1);

    // Starting from `SignedOut` and cycling `SignedIn -> SignedOut` in
    // another client while the browser is open still leaves it signed out.
    let stale = rig.client.sign_in_again(alex.id()).unwrap();
    let (cycled, _) = rig.approve(other.sign_in_again(alex.id()).unwrap(), &User::alex());
    assert_eq!(cycled.unwrap().account().state(), AccountState::SignedIn);
    drop(other.sign_out(alex.id()).unwrap());

    rig.journal.clear();
    let (result, page) = rig.approve(stale, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::SignInRequired);
    failed_page(&page);
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedOut
    );
    assert!(rig.credentials_of(alex.id()).is_none());
    assert_eq!(rig.journal.count("send revoke"), 1);
}

#[test]
fn forgetting_or_rejecting_an_account_while_signing_in_again_keeps_that_outcome() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let sign_in = rig.client.sign_in_again(alex.id()).unwrap();
    let other = rig.another_client();
    drop(other.forget(alex.id()).unwrap());

    rig.journal.clear();
    let (result, page) = rig.approve(sign_in, &User::alex());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::UnknownAccount);
    failed_page(&page);
    assert!(rig.client.accounts().unwrap().is_empty());
    assert!(
        rig.journal
            .about(&format!("lock account-{}", alex.id()))
            .is_empty(),
        "forgetting does not recreate an account lock"
    );
    assert_eq!(rig.journal.count("send revoke"), 1);

    let sam = rig.add(&User::sam().without_plan_use());
    let sign_in = rig.client.enable_plan_use(sam.id()).unwrap();
    rig.at(3540);
    rig.transport.fail(
        "refresh",
        1,
        Failure::Status(401, r#"{"error":"invalid_client"}"#),
    );
    assert_eq!(
        other.access_token(sam.id()).unwrap_err().kind(),
        ErrorKind::ClientRejected
    );

    let (result, page) = rig.approve(sign_in, &User::sam());
    assert_eq!(result.unwrap_err().kind(), ErrorKind::ClientRejected);
    failed_page(&page);
    assert_eq!(
        rig.client.account(sam.id()).unwrap().state(),
        AccountState::RegistrationRejected
    );
    assert!(rig.credentials_of(sam.id()).is_none());
}

#[test]
fn an_account_keeps_the_name_it_registered_under_after_the_app_is_renamed() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let renamed = rig.client_named("Paste Perfect Pro");

    let (again, _) = rig.approve(renamed.sign_in_again(alex.id()).unwrap(), &User::alex());
    assert_eq!(again.unwrap().account().registered_as(), "Paste Perfect");
    let (added, _) = rig.approve(renamed.add_account().unwrap(), &User::sam());
    assert_eq!(
        added.unwrap().account().registered_as(),
        "Paste Perfect Pro"
    );
    assert_eq!(
        rig.provider.registered_names(),
        ["Paste Perfect", "Paste Perfect Pro"]
    );
}

#[test]
fn an_unknown_id_is_refused_by_every_method() {
    let rig = Rig::new();
    let unknown = AccountId::parse("ffffffffffffffffffffffffffffffff").unwrap();
    let client = &rig.client;
    let unknown_on_empty_store = [
        client.account(&unknown).err(),
        client.access_token(&unknown).err(),
        client.sign_out(&unknown).err(),
    ];
    for error in unknown_on_empty_store {
        assert_eq!(error.unwrap().kind(), ErrorKind::UnknownAccount);
    }

    let alex = rig.add(&User::alex());
    let token = client.access_token(alex.id()).unwrap();
    let errors = [
        client.account(&unknown).err(),
        client.set_label(&unknown, Some("Work")).err(),
        client.sign_in_again(&unknown).err(),
        client.enable_plan_use(&unknown).err(),
        client.access_token(&unknown).err(),
        client.access_token_after_rejection(&unknown, &token).err(),
        client.models(&unknown).err(),
        client.sign_out(&unknown).err(),
        client.forget(&unknown).err(),
    ];
    for (index, error) in errors.into_iter().enumerate() {
        assert_eq!(error.unwrap().kind(), ErrorKind::UnknownAccount, "{index}");
    }
    // No lock or entry was made for the unknown ID.
    assert!(rig.journal.about(unknown.as_str()).is_empty());
}

#[test]
fn the_host_id_reaches_the_provider_unless_the_app_turns_it_off() {
    let rig = Rig::new();
    rig.add(&User::alex());
    let silent = rig.builder("Paste Perfect").send_host_id(false).build();
    let (result, page) = rig.approve(silent.add_account().unwrap(), &User::sam());
    assert_eq!(page.status, 200);
    result.unwrap();

    let hosts: Vec<Option<String>> = authorization_requests(&rig)
        .iter()
        .map(|request| request.field("ext_agent_host_id").map(str::to_owned))
        .collect();
    assert_eq!(hosts.len(), 2);
    assert!(
        hosts[0]
            .as_deref()
            .is_some_and(|host| host.starts_with("urn:uuid:")),
        "sent by default: {hosts:?}"
    );
    assert_eq!(hosts[1], None, "left out when turned off");
}
