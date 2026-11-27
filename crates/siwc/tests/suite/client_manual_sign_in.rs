//! `Client` sign-ins completed by pasting the redirect address, for an app
//! whose browser runs on another machine.

use std::net::{Ipv4Addr, TcpStream};

use siwc::{AccountState, ErrorKind, ManualSignIn};

use crate::support::provider::{AUTHORIZE_URL, User};
use crate::support::recording::Failure;
use crate::support::rig::Rig;
use crate::support::wire::{form_decode, form_encode, only, optional};

#[path = "client_manual_sign_in/rejected.rs"]
mod rejected;

/// The parameters of the sign-in's authorization link.
fn link_fields(sign_in: &ManualSignIn) -> Vec<(String, String)> {
    let (endpoint, query) = sign_in.authorization_link().split_once('?').unwrap();
    assert_eq!(endpoint, AUTHORIZE_URL);
    form_decode(query)
}

/// The address the browser is sent to once `user` approves, as the user
/// copies it from the address bar.
fn approved_address(rig: &Rig, sign_in: &ManualSignIn, user: &User) -> String {
    let redirect = only(&link_fields(sign_in), "redirect_uri").to_owned();
    let query = rig.provider.authorize(sign_in.authorization_link(), user);
    format!("{redirect}?{query}")
}

#[test]
fn adding_an_account_manually_stores_it_signed_in() {
    let rig = Rig::new();
    let mut sign_in = rig.client.add_account_manually().unwrap();
    assert_eq!(
        optional(&link_fields(&sign_in), "agent_name_hint"),
        Some("Paste Perfect")
    );

    let address = approved_address(&rig, &sign_in, &User::alex());
    let completed = sign_in.finish(&format!("{address}\n")).unwrap();

    let account = completed.account();
    assert_eq!(account.state(), AccountState::SignedIn);
    assert_eq!(account.identity().email(), Some("alex@example.com"));
    assert!(completed.plan_use_started());
    assert_eq!(
        rig.client.accounts().unwrap(),
        std::slice::from_ref(account)
    );
    assert!(rig.token(account.id()).starts_with("access-"));
}

#[test]
fn a_wrong_paste_is_refused_and_the_right_one_still_completes_the_sign_in() {
    let rig = Rig::new();
    let mut sign_in = rig.client.add_account_manually().unwrap();
    let address = approved_address(&rig, &sign_in, &User::alex());
    let (redirect, query) = address.split_once('?').unwrap();
    let port: u16 = redirect
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.strip_suffix("/auth/callback"))
        .unwrap()
        .parse()
        .unwrap();

    for wrong in [
        String::new(),
        "I signed in".to_owned(),
        query.to_owned(),
        format!("http://127.0.0.1:{}/auth/callback?{query}", port ^ 1),
        format!("{redirect}?code=code-9999&state=forged"),
    ] {
        let error = sign_in.finish(&wrong).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CallbackRejected, "{wrong:?}");
        assert!(sign_in.is_open(), "{wrong:?}");
    }
    assert_eq!(
        rig.client.add_account().unwrap_err().kind(),
        ErrorKind::SignInInProgress,
        "the sign-in is still open"
    );

    let completed = sign_in.finish(&address).unwrap();
    assert_eq!(completed.account().state(), AccountState::SignedIn);
    assert!(!sign_in.is_open());
}

#[test]
fn a_redirect_of_this_sign_in_that_breaks_a_callback_rule_ends_it() {
    let rig = Rig::new();
    let mut sign_in = rig.client.add_account_manually().unwrap();
    let address = approved_address(&rig, &sign_in, &User::alex());

    let error = sign_in
        .finish(&format!("{address}&code=code-9999"))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CallbackRejected);
    assert!(!sign_in.is_open(), "the attempt is spent");
    assert_eq!(
        sign_in.finish(&address).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert!(rig.client.accounts().unwrap().is_empty());
}

#[test]
fn signing_in_again_manually_sends_no_hint_and_refuses_another_person() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let before = rig.store.snapshot();

    let mut sign_in = rig.client.sign_in_again_manually(alex.id()).unwrap();
    let fields = link_fields(&sign_in);
    assert_eq!(optional(&fields, "login_hint"), None);
    assert_eq!(optional(&fields, "id_token_hint"), None);
    assert_eq!(optional(&fields, "prompt"), None);

    let address = approved_address(&rig, &sign_in, &User::sam());
    let error = sign_in.finish(&address).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AccountMismatch);
    assert_eq!(rig.store.snapshot(), before);
}

#[test]
fn enabling_plan_use_manually_asks_for_consent_without_hints() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex().without_plan_use());

    let mut sign_in = rig.client.enable_plan_use_manually(alex.id()).unwrap();
    let fields = link_fields(&sign_in);
    assert_eq!(optional(&fields, "prompt"), Some("consent"));
    assert_eq!(optional(&fields, "login_hint"), None);
    assert_eq!(optional(&fields, "id_token_hint"), None);

    let address = approved_address(&rig, &sign_in, &User::alex());
    let completed = sign_in.finish(&address).unwrap();
    assert_eq!(completed.account().id(), alex.id());
    assert!(completed.account().plan_use());
}

#[test]
fn a_sign_in_that_has_ended_refuses_another_paste_and_frees_the_client() {
    let rig = Rig::new();
    let mut sign_in = rig.client.add_account_manually().unwrap();
    let redirect = only(&link_fields(&sign_in), "redirect_uri").to_owned();
    let declined = rig.provider.deny(sign_in.authorization_link());

    let error = sign_in
        .finish(&format!("{redirect}?{declined}"))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AccessDenied);
    let again = sign_in
        .finish(&format!("{redirect}?{declined}"))
        .unwrap_err();
    assert_eq!(again.kind(), ErrorKind::InvalidInput);

    // The client is free while the ended sign-in is still around.
    let mut next = rig.client.add_account_manually().unwrap();
    let address = approved_address(&rig, &next, &User::alex());
    next.finish(&address).unwrap();
    assert_eq!(
        next.finish(&address).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    drop(sign_in);
}

/// The address the browser is sent to when the provider ends the
/// authorization with the error `code`.
fn failed_address(sign_in: &ManualSignIn, code: &str) -> String {
    let fields = link_fields(sign_in);
    let query = form_encode(&[("error", code), ("state", only(&fields, "state"))]);
    format!("{}?{query}", only(&fields, "redirect_uri"))
}

/// The installation record's unfinished registration.
fn pending_client(rig: &Rig) -> Option<String> {
    let record: serde_json::Value =
        serde_json::from_slice(&rig.store.bytes("installation").unwrap()).unwrap();
    record["pending"]["client_id"].as_str().map(str::to_owned)
}

#[test]
fn a_pasted_registration_refusal_is_client_rejected_and_keeps_the_pending_registration() {
    let rig = Rig::new();
    rig.transport.fail("exchange", 1, Failure::Unreachable);
    let mut first = rig.client.add_account_manually().unwrap();
    let address = approved_address(&rig, &first, &User::alex());
    assert_eq!(
        first.finish(&address).unwrap_err().kind(),
        ErrorKind::Temporary
    );
    let issued = rig.provider.issued_clients();
    assert_eq!(pending_client(&rig), Some(issued[0].clone()));
    let before = rig.store.snapshot();

    let mut resumed = rig
        .client
        .resume_unfinished_registration_manually()
        .unwrap();
    let error = resumed
        .finish(&failed_address(&resumed, "invalid_client"))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ClientRejected);
    assert_eq!(error.provider_code(), Some("invalid_client"));
    assert_eq!(error.http_status(), None);
    assert!(!resumed.is_open());
    assert_eq!(rig.store.snapshot(), before);
}

#[test]
fn a_pasted_registration_refusal_during_a_sign_in_again_leaves_the_account_as_it_was() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let before = rig.store.snapshot();
    rig.journal.clear();

    let mut sign_in = rig.client.sign_in_again_manually(alex.id()).unwrap();
    let error = sign_in
        .finish(&failed_address(&sign_in, "unauthorized_client"))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ClientRejected);
    assert_eq!(rig.store.snapshot(), before);
    assert!(rig.journal.about("send").is_empty());
    assert_eq!(
        rig.client.account(alex.id()).unwrap().state(),
        AccountState::SignedIn
    );
    assert!(rig.client.access_token(alex.id()).is_ok());
}

#[test]
fn a_pasted_transient_authorization_error_keeps_the_account_usable() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let before = rig.store.snapshot();

    let mut sign_in = rig.client.sign_in_again_manually(alex.id()).unwrap();
    let error = sign_in
        .finish(&failed_address(&sign_in, "temporarily_unavailable"))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthorizationFailed);
    assert_eq!(rig.store.snapshot(), before);
    assert!(rig.client.access_token(alex.id()).is_ok());
}

#[test]
fn a_manual_sign_in_holds_the_one_sign_in_of_the_client_until_dropped() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let manual = rig.client.add_account_manually().unwrap();
    assert_eq!(
        rig.client.add_account().unwrap_err().kind(),
        ErrorKind::SignInInProgress
    );
    assert_eq!(
        rig.client
            .sign_in_again_manually(alex.id())
            .unwrap_err()
            .kind(),
        ErrorKind::SignInInProgress
    );
    drop(manual);
    drop(rig.client.sign_in_again_manually(alex.id()).unwrap());
}

#[test]
fn neither_debug_output_nor_an_error_shows_the_link_or_the_code() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let mut sign_in = rig.client.sign_in_again_manually(alex.id()).unwrap();
    let address = approved_address(&rig, &sign_in, &User::sam());
    let code = only(&form_decode(address.split_once('?').unwrap().1), "code").to_owned();
    let state = only(&link_fields(&sign_in), "state").to_owned();

    let mut printed = vec![format!("{sign_in:?}")];
    let refused = sign_in.finish(&format!("{address}x\"")).unwrap_err();
    printed.push(format!("{refused} {refused:?}"));
    let mismatch = sign_in.finish(&address).unwrap_err();
    assert_eq!(mismatch.kind(), ErrorKind::AccountMismatch);
    printed.push(format!("{mismatch} {mismatch:?} {sign_in:?}"));

    for text in printed {
        for secret in [
            code.as_str(),
            state.as_str(),
            "auth.openai.com",
            "127.0.0.1",
        ] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
    }
}

#[test]
fn nothing_listens_on_the_redirect_port() {
    let rig = Rig::new();
    let sign_in = rig.client.add_account_manually().unwrap();
    let redirect = only(&link_fields(&sign_in), "redirect_uri").to_owned();
    let port: u16 = redirect
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.strip_suffix("/auth/callback"))
        .unwrap()
        .parse()
        .unwrap();
    assert_ne!(port, 0);
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
}
