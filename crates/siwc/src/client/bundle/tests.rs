//! Import requires verified identity before the first store operation.

#![expect(
    clippy::unwrap_used,
    reason = "helpers use only known synthetic fixtures and fail the test if setup fails"
)]

use std::time::Duration;

use serde_json::{Value, json};

use crate::store::{EntryName, Lock, MemoryStore, Store, Stored};
use crate::testing::{FakeClock, FakeProvider, FakeUser};
use crate::{Account, AccountState, AppName, Client, OsEntropy, UnixTime};

use super::*;

const PASSPHRASE: &[u8] = b"synthetic-transfer-passphrase";

struct Source {
    clock: FakeClock,
    provider: FakeProvider,
    client: Client,
    account: Account,
}

impl Source {
    fn new() -> Self {
        let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
        let provider = FakeProvider::with_clock(&clock);
        let client = Self::client(&clock, &provider, MemoryStore::new());
        let account = Self::sign_in(
            &client,
            &provider,
            FakeUser::new("owner@example.invalid")
                .unverified_email()
                .name("Synthetic Owner")
                .picture("https://example.invalid/owner.png"),
        );
        Self {
            clock,
            provider,
            client,
            account,
        }
    }

    fn client(clock: &FakeClock, provider: &FakeProvider, store: impl Store + 'static) -> Client {
        Client::builder(
            AppName::new("Synthetic Notes").unwrap(),
            store,
            provider.transport(),
        )
        .clock(clock.clone())
        .build()
    }

    fn sign_in(client: &Client, provider: &FakeProvider, user: FakeUser) -> Account {
        let mut flow = client.add_account_manually().unwrap();
        let redirect = provider.approve_manual(&flow, user).unwrap();
        flow.finish(&redirect).unwrap().into_account()
    }

    fn target(&self, store: impl Store + 'static) -> Client {
        Self::client(&self.clock, &self.provider, store)
    }

    fn payload(&self, account: &Account) -> (AccountRecord, Credentials) {
        let (_, record) = self.client.inner.record(account.id(), None).unwrap();
        let credentials = self
            .client
            .inner
            .credentials(&record, None)
            .unwrap()
            .unwrap();
        (record, credentials)
    }
}

#[derive(Debug)]
struct UntouchedStore;

impl Store for UntouchedStore {
    fn read(&self, _: &EntryName) -> Result<Option<Stored>, Error> {
        Err(Error::store_failed())
    }

    fn write(&self, _: &EntryName, _: &[u8]) -> Result<(), Error> {
        Err(Error::store_failed())
    }

    fn remove(&self, _: &EntryName) -> Result<(), Error> {
        Err(Error::store_failed())
    }

    fn lock(&self, _: &EntryName, _: Duration) -> Result<Lock<'_>, Error> {
        Err(Error::store_failed())
    }
}

fn stored(credentials: &Credentials) -> Value {
    serde_json::from_slice(credentials.to_stored().expose()).unwrap()
}

fn with_id_token(credentials: &Credentials, token: Value) -> Credentials {
    let mut value = stored(credentials);
    value["id_token"] = token;
    Credentials::from_stored(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn sealed(record: &AccountRecord, credentials: &Credentials) -> AccountBundle {
    seal(record, credentials, PASSPHRASE, &OsEntropy).unwrap()
}

#[test]
fn import_requires_an_id_token_before_touching_the_store() {
    let source = Source::new();
    let (record, credentials) = source.payload(&source.account);
    let bundle = sealed(&record, &with_id_token(&credentials, Value::Null));
    let error = source
        .target(UntouchedStore)
        .import_account(bundle.as_bytes(), PASSPHRASE)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BundleRejected);
}

#[test]
fn export_without_an_id_token_leaves_the_source_session_in_place() {
    let source = Source::new();
    let (_, credentials) = source.payload(&source.account);
    let without_id_token = with_id_token(&credentials, Value::Null);
    source
        .client
        .inner
        .write_credentials(source.account.id(), &without_id_token)
        .unwrap();
    let path = std::env::temp_dir();
    let result = source
        .client
        .export_account_to(source.account.id(), PASSPHRASE, path);
    assert_eq!(result.unwrap_err().kind(), ErrorKind::SignInRequired);
    assert_eq!(
        source.client.account(source.account.id()).unwrap(),
        source.account
    );
    assert_eq!(
        source.payload(&source.account).1.to_stored().expose(),
        without_id_token.to_stored().expose()
    );
}

#[test]
fn an_invalid_signature_cannot_replace_an_existing_account() {
    let source = Source::new();
    let (record, credentials) = source.payload(&source.account);
    let token = credentials.id_token().unwrap().expose();
    let (signed, signature) = token.rsplit_once('.').unwrap();
    let mut signature = base64url::decode(signature).unwrap();
    signature[0] ^= 1;
    let changed = format!("{signed}.{}", base64url::encode(&signature));
    let bundle = sealed(&record, &with_id_token(&credentials, json!(changed)));
    let previous = credentials.to_stored();

    let error = source
        .client
        .import_account(bundle.as_bytes(), PASSPHRASE)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BundleRejected);
    assert_eq!(
        source.client.account(source.account.id()).unwrap(),
        source.account
    );
    assert_eq!(
        source.payload(&source.account).1.to_stored().expose(),
        previous.expose()
    );
}

#[test]
fn an_id_token_for_another_registration_is_rejected_before_touching_the_store() {
    let source = Source::new();
    let other = Source::sign_in(
        &source.client,
        &source.provider,
        FakeUser::new("owner@example.invalid"),
    );
    let other = stored(&source.payload(&other).1);
    let (record, credentials) = source.payload(&source.account);
    let bundle = sealed(
        &record,
        &with_id_token(&credentials, other["id_token"].clone()),
    );
    let error = source
        .target(UntouchedStore)
        .import_account(bundle.as_bytes(), PASSPHRASE)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BundleRejected);
}

#[test]
fn an_id_token_for_another_subject_is_rejected_before_touching_the_store() {
    let source = Source::new();
    let (mut record, credentials) = source.payload(&source.account);
    let mut identity = record.identity.to_record();
    identity["subject"] = json!("synthetic-unrelated-subject");
    record.identity = Identity::from_record(&identity).unwrap();
    let mut credentials = stored(&credentials);
    credentials["subject"] = identity["subject"].clone();
    let credentials = Credentials::from_stored(&serde_json::to_vec(&credentials).unwrap()).unwrap();
    let bundle = sealed(&record, &credentials);

    let error = source
        .target(UntouchedStore)
        .import_account(bundle.as_bytes(), PASSPHRASE)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BundleRejected);
}

#[test]
fn import_uses_the_signed_identity_even_after_the_id_token_expires() {
    let source = Source::new();
    let (mut record, credentials) = source.payload(&source.account);
    let mut identity = record.identity.to_record();
    identity["email"] = json!("other@example.invalid");
    identity["email_verified"] = json!(true);
    identity["name"] = json!("Other User");
    identity["picture"] = json!("https://example.invalid/other.png");
    record.identity = Identity::from_record(&identity).unwrap();
    let bundle = sealed(&record, &credentials);
    source.clock.advance(Duration::from_secs(7_200));

    for target in [source.target(MemoryStore::new()), source.client.clone()] {
        let imported = target
            .import_account(bundle.as_bytes(), PASSPHRASE)
            .unwrap();
        assert_eq!(imported.state(), AccountState::SignedIn);
        assert_eq!(imported.identity(), source.account.identity());
    }
}

#[test]
fn import_reports_the_jwks_transport_error_before_touching_the_store() {
    let source = Source::new();
    let (record, credentials) = source.payload(&source.account);
    let bundle = sealed(&record, &credentials);
    source.provider.fail_next_request(0, None);

    let error = source
        .target(UntouchedStore)
        .import_account(bundle.as_bytes(), PASSPHRASE)
        .unwrap_err();
    let expected = Error::transport_unavailable();
    assert_eq!(error.kind(), expected.kind());
    assert_eq!(error.to_string(), expected.to_string());
}

#[test]
fn an_exact_reimport_repairs_legacy_identity_without_overwriting_local_edits() {
    let source = Source::new();
    let (mut record, credentials) = source.payload(&source.account);
    record.label = Some("Bundle label".to_owned());
    let bundle = sealed(&record, &credentials);
    let target = source.target(MemoryStore::new());
    let imported = target
        .import_account(bundle.as_bytes(), PASSPHRASE)
        .unwrap();
    target.set_label(imported.id(), None).unwrap();

    let mut identity = record.identity.to_record();
    identity["email_verified"] = json!(true);
    target
        .inner
        .change_installation(|installation| {
            let account = installation
                .as_mut()
                .unwrap()
                .account_mut(imported.id())
                .unwrap();
            account.identity = Identity::from_record(&identity).unwrap();
            Ok(())
        })
        .unwrap();

    let repeated = target
        .import_account(bundle.as_bytes(), PASSPHRASE)
        .unwrap();
    assert_eq!(repeated.label(), None);
    assert_eq!(repeated.identity(), source.account.identity());
}

#[test]
fn bundle_debug_only_shows_the_encrypted_length() {
    let source = Source::new();
    let (record, credentials) = source.payload(&source.account);
    let bundle = sealed(&record, &credentials);
    assert_eq!(
        format!("{bundle:?}"),
        format!(
            "AccountBundle([redacted; {} bytes])",
            bundle.as_bytes().len()
        )
    );
}
