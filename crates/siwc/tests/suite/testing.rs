//! End-to-end tests of `siwc::testing` as an external application uses it.

use std::time::Duration;

use siwc::plan::{Reason, Refusal};
use siwc::store::MemoryStore;
use siwc::testing::{FakeClock, FakeProvider, FakeUser};
use siwc::{AccountState, AppName, Client, Clock, ErrorKind, UnixTime};

#[test]
fn fake_provider_and_clock_drive_sign_in_refresh_revocation_and_refusals_without_threads_in_caller()
{
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    provider.set_models(&[("gpt-synthetic", "GPT Synthetic")]);

    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        MemoryStore::new(),
        provider.transport(),
    )
    .clock(clock.clone())
    .build();

    // 1. Declined browser sign-in.
    let declined = client.add_account().unwrap();
    provider.decline(&declined);
    assert_eq!(
        declined.finish(Duration::from_secs(5)).unwrap_err().kind(),
        ErrorKind::AccessDenied
    );

    // 2. Identity-only sign-in followed by explicit consent to enable plan use.
    let first = client.add_account().unwrap();
    provider.approve(
        &first,
        FakeUser::new("owner@example.invalid")
            .name("Alex Owner")
            .without_plan_use(),
    );
    let completed = first.finish(Duration::from_secs(5)).unwrap();
    assert!(!completed.account().plan_use());
    assert!(!completed.plan_use_started());
    assert_eq!(
        client.models(completed.account().id()).unwrap_err().kind(),
        ErrorKind::PlanUseNotGranted
    );

    let enable = client.enable_plan_use(completed.account().id()).unwrap();
    provider.approve(
        &enable,
        FakeUser::new("owner@example.invalid")
            .name("Alex Owner")
            .without_plan_use(),
    );
    let upgraded = enable.finish(Duration::from_secs(5)).unwrap();
    assert!(upgraded.account().plan_use());
    assert!(upgraded.plan_use_started());
    let models = client.models(upgraded.account().id()).unwrap();
    assert_eq!(models.len(), 1);
    assert_eq!(models.iter().next().unwrap().id(), "gpt-synthetic");

    // 3. Second account via manual sign-in.
    let mut second = client.add_account_manually().unwrap();
    let redirect = provider
        .approve_manual(&second, FakeUser::new("team@example.invalid"))
        .unwrap();
    let second_acc = second.finish(&redirect).unwrap().into_account();
    assert_eq!(client.accounts().unwrap().len(), 2);

    // 4. Token expiry + automatic rotation under FakeClock.
    let initial_token = client.access_token(upgraded.account().id()).unwrap();
    clock.advance(Duration::from_secs(3600));
    let rotated_token = client.access_token(upgraded.account().id()).unwrap();
    assert_ne!(rotated_token.expose(), initial_token.expose());

    // 5. Provider revokes refresh tokens -> next refresh reports SignInRequired.
    provider.revoke_refresh_tokens();
    clock.advance(Duration::from_secs(3600));
    assert_eq!(
        client
            .access_token(upgraded.account().id())
            .unwrap_err()
            .kind(),
        ErrorKind::SignInRequired
    );
    assert_eq!(
        client.account(upgraded.account().id()).unwrap().state(),
        AccountState::SignInRequired
    );

    // Re-sign in to recover the first account.
    let again = client.sign_in_again(upgraded.account().id()).unwrap();
    provider.approve(
        &again,
        FakeUser::new("owner@example.invalid").name("Alex Owner"),
    );
    assert_eq!(
        again
            .finish(Duration::from_secs(5))
            .unwrap()
            .account()
            .state(),
        AccountState::SignedIn
    );

    // 6. Structured refusal & SSE failure event helpers + retry sleep recording.
    provider.refuse_next_models(429, "subscription_sharing_usage_limit_exceeded");
    assert_eq!(
        client.models(upgraded.account().id()).unwrap_err().kind(),
        ErrorKind::UsageLimit
    );

    let sse = FakeProvider::failure_event(
        "subscription_sharing_unsupported_capability",
        Some("tools[0].type"),
    );
    let refusal = Refusal::from_event(&sse).unwrap();
    assert_eq!(refusal.reason(), Reason::Unsupported);
    assert_eq!(refusal.param(), Some("tools[0].type"));

    let mut tries = 0;
    let body = FakeProvider::refusal_body("subscription_sharing_usage_unavailable", None);
    let answer = client
        .call(
            upgraded.account().id(),
            |_token| -> Result<_, siwc::Error> {
                tries += 1;
                if tries == 1 {
                    Ok(Err(Refusal::from_response(503, &body)
                        .unwrap()
                        .with_retry_after(Some("4"))))
                } else {
                    Ok(Ok("completed"))
                }
            },
        )
        .unwrap();
    assert_eq!(answer, "completed");
    assert_eq!(clock.sleeps(), [Duration::from_secs(4)]);

    // 7. Rejected registrations -> ClientRejected on both refresh and re-sign-in.
    provider.reject_registrations();
    clock.advance(Duration::from_secs(3600));
    assert_eq!(
        client.access_token(second_acc.id()).unwrap_err().kind(),
        ErrorKind::ClientRejected
    );
    assert_eq!(
        client.account(second_acc.id()).unwrap().state(),
        AccountState::RegistrationRejected
    );

    let third_reauth = client.sign_in_again(upgraded.account().id()).unwrap();
    provider.approve(&third_reauth, FakeUser::new("owner@example.invalid"));
    assert_eq!(
        third_reauth
            .finish(Duration::from_secs(5))
            .unwrap_err()
            .kind(),
        ErrorKind::ClientRejected
    );
    assert_eq!(
        client.account(upgraded.account().id()).unwrap().state(),
        AccountState::RegistrationRejected
    );

    // Resuming an unfinished registration on a brand-new empty store fails with
    // InvalidInput without writing an installation record.
    let empty_store = std::sync::Arc::new(MemoryStore::new());
    let fresh_client = Client::new(
        AppName::new("Paste Perfect").unwrap(),
        std::sync::Arc::clone(&empty_store),
        provider.transport(),
    );
    assert_eq!(
        fresh_client
            .resume_unfinished_registration()
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput
    );
    assert!(
        siwc::store::Store::read(
            &*empty_store,
            &siwc::store::EntryName::new("installation").unwrap()
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn fake_user_claims_and_manual_or_transport_error_injections_behave_as_configured() {
    let clock = FakeClock::new(UnixTime::from_secs(1_790_000_000));
    clock.set(UnixTime::from_secs(1_800_000_000));
    clock.advance(Duration::from_millis(250));
    assert_eq!(clock.now(), UnixTime::from_secs(1_800_000_001));

    let default_provider = FakeProvider::default();
    assert_eq!(format!("{default_provider:?}"), "FakeProvider { .. }");

    let provider = FakeProvider::with_clock(&clock);
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        MemoryStore::new(),
        provider.transport(),
    )
    .clock(clock.clone())
    .build();

    // Transport error injection on `/oauth/token`: network drop (status 0) and HTTP 503.
    let mut drop_attempt = client.add_account_manually().unwrap();
    let drop_redirect = provider
        .approve_manual(&drop_attempt, FakeUser::new("drop@example.invalid"))
        .unwrap();
    provider.fail_next_request(0, None);
    assert_eq!(
        drop_attempt.finish(&drop_redirect).unwrap_err().kind(),
        ErrorKind::Temporary
    );

    let mut unavailable_attempt = client.add_account_manually().unwrap();
    let unavailable_redirect = provider
        .approve_manual(
            &unavailable_attempt,
            FakeUser::new("unavail@example.invalid"),
        )
        .unwrap();
    provider.fail_next_request(503, Some("temporarily_unavailable"));
    assert_eq!(
        unavailable_attempt
            .finish(&unavailable_redirect)
            .unwrap_err()
            .kind(),
        ErrorKind::Temporary
    );

    // Manual decline and explicit provider failure.
    let mut declined = client.add_account_manually().unwrap();
    let redirect = provider.decline_manual(&declined).unwrap();
    assert_eq!(
        declined.finish(&redirect).unwrap_err().kind(),
        ErrorKind::AccessDenied
    );

    let mut failed = client.add_account_manually().unwrap();
    let redirect = provider.fail_manual(&failed, "server_error").unwrap();
    assert_eq!(
        failed.finish(&redirect).unwrap_err().kind(),
        ErrorKind::AuthorizationFailed
    );

    // Loopback explicit authorization failure.
    let loopback_failed = client.add_account().unwrap();
    provider.fail_authorization(&loopback_failed, "server_error");
    assert_eq!(
        loopback_failed
            .finish(Duration::from_secs(5))
            .unwrap_err()
            .kind(),
        ErrorKind::AuthorizationFailed
    );

    // Custom FakeUser claims: custom subject, unverified email, picture, non-renewable.
    let mut custom = client.add_account_manually().unwrap();
    let redirect = provider
        .approve_manual(
            &custom,
            FakeUser::new("sso@example.invalid")
                .subject("user-enterprise-sso-42")
                .unverified_email()
                .picture("https://auth.openai.com/avatar.png")
                .without_refresh_token(),
        )
        .unwrap();
    let account = custom.finish(&redirect).unwrap().into_account();
    assert_eq!(account.identity().subject(), "user-enterprise-sso-42");
    assert_eq!(account.identity().email(), Some("sso@example.invalid"));
    assert!(!account.identity().email_verified());
    assert_eq!(
        account.identity().picture(),
        Some("https://auth.openai.com/avatar.png")
    );
    clock.advance(Duration::from_secs(3600));
    assert_eq!(
        client.access_token(account.id()).unwrap_err().kind(),
        ErrorKind::SignInRequired
    );

    // User without email claim at all and empty-input subject fallback, plus
    // revocation on sign-out, identity-only non-renewable scope combination,
    // and direct transport error branches (`404`, missing/expired bearer).
    let mut no_email = client.add_account_manually().unwrap();
    let redirect = provider
        .approve_manual(&no_email, FakeUser::new("").without_email())
        .unwrap();
    let no_email_acc = no_email.finish(&redirect).unwrap().into_account();
    assert_eq!(no_email_acc.identity().subject(), "user-synthetic-default");
    assert_eq!(no_email_acc.identity().email(), None);
    assert!(
        client
            .sign_out(no_email_acc.id())
            .unwrap()
            .revocation_confirmed()
    );

    let mut minimal = client.add_account_manually().unwrap();
    let redirect = provider
        .approve_manual(
            &minimal,
            FakeUser::new("minimal@example.invalid")
                .without_plan_use()
                .without_refresh_token(),
        )
        .unwrap();
    let minimal_acc = minimal.finish(&redirect).unwrap().into_account();
    assert!(!minimal_acc.plan_use());

    let minimal_token = client.access_token(minimal_acc.id()).unwrap();
    clock.advance(Duration::from_secs(3600));
    let transport = provider.transport();
    let expired_models = siwc::plan::Models::request(&minimal_token);
    assert_eq!(
        siwc::Transport::send(&transport, &expired_models)
            .unwrap()
            .status(),
        401
    );
}
