//! What the client keeps in the store: corrupt entries are refused and
//! never overwritten, and stored credentials read back exactly.

use serde_json::{Value, json};
use siwc::protocol::{Credentials, Registration, Returning};
use siwc::protocol::{HttpRequest, HttpResponse};
use siwc::store::{EntryName, Lock, MemoryStore, Store, Stored};
use siwc::testing::{FakeProvider, FakeUser};
use siwc::{AppName, Client, Error, ErrorKind, Transport, UnixTime};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use crate::support::provider::User;
use crate::support::random::Generator;
use crate::support::rig::Rig;
use crate::support::wire::{form_decode, optional};
use crate::support::{NOW, World};

#[derive(Debug)]
struct PublishThenError {
    inner: Arc<MemoryStore>,
    fail_once: AtomicBool,
    removals: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct PublishInstallationThenError {
    inner: Arc<MemoryStore>,
    after_credentials: AtomicBool,
}

impl Store for PublishInstallationThenError {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        self.inner.read(entry)
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        self.inner.write(entry, value)?;
        if entry.as_str().starts_with("account-") {
            self.after_credentials.store(true, Ordering::SeqCst);
        }
        if entry.as_str() == "installation" && self.after_credentials.swap(false, Ordering::SeqCst)
        {
            return Err(Error::store_failed());
        }
        Ok(())
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        self.inner.remove(entry)
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        self.inner.lock(entry, patience)
    }
}

impl Store for PublishThenError {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        self.inner.read(entry)
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        self.inner.write(entry, value)?;
        if entry.as_str().starts_with("account-") && self.fail_once.swap(false, Ordering::SeqCst) {
            return Err(Error::store_failed());
        }
        Ok(())
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        self.removals.fetch_add(1, Ordering::SeqCst);
        self.inner.remove(entry)
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        self.inner.lock(entry, patience)
    }
}

#[derive(Debug)]
struct CountRevocations {
    provider: FakeProvider,
    revocations: Arc<AtomicUsize>,
}

impl Transport for CountRevocations {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        if request.url().ends_with("/revoke") {
            self.revocations.fetch_add(1, Ordering::SeqCst);
        }
        self.provider.send(request)
    }
}

#[test]
fn a_post_publication_credentials_write_error_does_not_remove_or_revoke_the_session() {
    let inner = Arc::new(MemoryStore::new());
    let removals = Arc::new(AtomicUsize::new(0));
    let revocations = Arc::new(AtomicUsize::new(0));
    let provider = FakeProvider::new();
    let client = Client::new(
        AppName::new("Offline Test App").unwrap(),
        PublishThenError {
            inner: Arc::clone(&inner),
            fail_once: AtomicBool::new(true),
            removals: Arc::clone(&removals),
        },
        CountRevocations {
            provider: provider.clone(),
            revocations: Arc::clone(&revocations),
        },
    );
    let mut sign_in = client.add_account_manually().unwrap();
    let redirect = provider
        .approve_manual(&sign_in, FakeUser::new("sample@example.invalid"))
        .unwrap();
    assert_eq!(
        sign_in.finish(&redirect).unwrap_err().kind(),
        ErrorKind::Store
    );
    let account = client.accounts().unwrap().pop().unwrap();
    let entry = EntryName::new(&format!("account-{}", account.id())).unwrap();
    assert!(inner.read(&entry).unwrap().is_some());
    assert_eq!(removals.load(Ordering::SeqCst), 0);
    assert_eq!(revocations.load(Ordering::SeqCst), 0);
}

#[test]
fn a_post_publication_installation_write_error_keeps_the_signed_in_session() {
    let inner = Arc::new(MemoryStore::new());
    let revocations = Arc::new(AtomicUsize::new(0));
    let provider = FakeProvider::new();
    let client = Client::new(
        AppName::new("Offline Test App").unwrap(),
        PublishInstallationThenError {
            inner: Arc::clone(&inner),
            after_credentials: AtomicBool::new(false),
        },
        CountRevocations {
            provider: provider.clone(),
            revocations: Arc::clone(&revocations),
        },
    );
    let mut sign_in = client.add_account_manually().unwrap();
    let redirect = provider
        .approve_manual(&sign_in, FakeUser::new("sample@example.invalid"))
        .unwrap();
    assert_eq!(
        sign_in.finish(&redirect).unwrap_err().kind(),
        ErrorKind::Store
    );
    let account = client.accounts().unwrap().pop().unwrap();
    assert_eq!(account.state(), siwc::AccountState::SignedIn);
    assert!(client.access_token(account.id()).is_ok());
    assert_eq!(revocations.load(Ordering::SeqCst), 0);
}

/// Bytes a store might hand back for an entry of the client: not JSON,
/// JSON of another shape, another version, a member of the wrong type.
fn corruptions(valid: &[u8]) -> Vec<Vec<u8>> {
    let valid: Value = serde_json::from_slice(valid).unwrap();
    let mut versioned = valid.clone();
    versioned["v"] = json!("unknown");
    let mut mistyped = valid.clone();
    let first = valid
        .as_object()
        .unwrap()
        .keys()
        .find(|key| *key != "v")
        .unwrap()
        .clone();
    mistyped[first.as_str()] = json!({});
    let mut extended = valid;
    extended["unknown"] = json!(true);
    vec![
        b"not json".to_vec(),
        b"[]".to_vec(),
        Vec::new(),
        versioned.to_string().into_bytes(),
        mistyped.to_string().into_bytes(),
        extended.to_string().into_bytes(),
    ]
}

#[test]
fn an_unreadable_installation_record_is_store_corrupt_and_never_overwritten() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let valid = rig.store.bytes("installation").unwrap();
    for corrupt in corruptions(&valid) {
        rig.store.put("installation", &corrupt);
        rig.journal.clear();
        let client = &rig.client;
        let errors = [
            client.accounts().err(),
            client.account(alex.id()).err(),
            client.set_label(alex.id(), Some("Work")).err(),
            client.access_token(alex.id()).err(),
            client.add_account().err(),
            client.sign_in_again(alex.id()).err(),
            client.sign_out(alex.id()).err(),
        ];
        for (index, error) in errors.into_iter().enumerate() {
            assert_eq!(error.unwrap().kind(), ErrorKind::StoreCorrupt, "{index}");
        }
        assert_eq!(rig.store.bytes("installation").unwrap(), corrupt);
        assert!(rig.journal.about("write").is_empty());
        assert!(rig.journal.about("send").is_empty());
    }
}

#[test]
fn a_registration_with_an_old_lookalike_name_stays_readable() {
    let rig = Rig::new();
    let account = rig.add(&User::alex());
    let mut record: Value =
        serde_json::from_slice(&rig.store.bytes("installation").unwrap()).unwrap();
    record["accounts"][0]["registered_as"] = json!("ChatGРТ");
    rig.store
        .put("installation", &serde_json::to_vec(&record).unwrap());

    assert_eq!(
        rig.client.account(account.id()).unwrap().registered_as(),
        "ChatGРТ"
    );
    assert!(rig.client.access_token(account.id()).is_ok());
}

#[test]
fn a_stored_identity_with_disallowed_display_claims_or_picture_url_is_store_corrupt() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let valid: Value = serde_json::from_slice(&rig.store.bytes("installation").unwrap()).unwrap();

    for (field, bad) in [
        ("name", "Alex\nExample"),
        ("name", "Alex\u{202E}elpmaxE"),
        ("email", "alex\u{200B}@example.com"),
        ("picture", "javascript:alert(1)"),
        ("picture", "http://example.com/alex.png"),
        ("picture", "https://example.com/alex .png"),
    ] {
        let mut tampered = valid.clone();
        tampered["accounts"][0]["identity"][field] = json!(bad);
        let bytes = tampered.to_string().into_bytes();
        rig.store.put("installation", &bytes);
        assert_eq!(
            rig.client.account(alex.id()).unwrap_err().kind(),
            ErrorKind::StoreCorrupt,
            "{field}: {bad:?}"
        );
    }
}

#[test]
fn a_stored_subject_that_is_not_printable_ascii_is_store_corrupt() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let installation: Value =
        serde_json::from_slice(&rig.store.bytes("installation").unwrap()).unwrap();
    let credentials: Value =
        serde_json::from_slice(&rig.credentials_of(alex.id()).unwrap()).unwrap();

    for subject in ["user-\u{e4}lex", "user\nalex"] {
        let mut tampered = installation.clone();
        tampered["accounts"][0]["identity"]["subject"] = json!(subject);
        rig.store
            .put("installation", tampered.to_string().as_bytes());
        assert_eq!(
            rig.client.account(alex.id()).unwrap_err().kind(),
            ErrorKind::StoreCorrupt,
            "{subject:?}"
        );

        let mut tampered = credentials.clone();
        tampered["subject"] = json!(subject);
        let error = Credentials::from_stored(tampered.to_string().as_bytes()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::StoreCorrupt, "{subject:?}");
    }
}

#[test]
fn a_stored_access_token_that_could_not_be_a_bearer_header_is_store_corrupt() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let credentials: Value =
        serde_json::from_slice(&rig.credentials_of(alex.id()).unwrap()).unwrap();

    for access in [
        "access token",
        "access\r\nx-injected: 1",
        "access=token",
        "=",
    ] {
        let mut tampered = credentials.clone();
        tampered["access_token"] = json!(access);
        let error = Credentials::from_stored(tampered.to_string().as_bytes()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::StoreCorrupt, "{access:?}");
    }
    let mut padded = credentials;
    padded["access_token"] = json!("access-0001+/_.~==");
    assert!(Credentials::from_stored(padded.to_string().as_bytes()).is_ok());
}

#[test]
fn an_unreadable_credentials_entry_is_store_corrupt_and_never_overwritten() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    let entry = format!("account-{}", alex.id());
    let valid = rig.store.bytes(&entry).unwrap();
    rig.at(3600);
    for corrupt in corruptions(&valid) {
        rig.store.put(&entry, &corrupt);
        rig.journal.clear();
        for error in [
            rig.client.access_token(alex.id()).err(),
            rig.client.models(alex.id()).err(),
            rig.client.sign_in_again(alex.id()).err(),
        ] {
            assert_eq!(error.unwrap().kind(), ErrorKind::StoreCorrupt);
        }
        assert_eq!(rig.store.bytes(&entry).unwrap(), corrupt);
        assert!(rig.journal.about("write").is_empty());
        assert!(rig.journal.about("send").is_empty());
    }
}

#[test]
fn signing_out_clears_unreadable_credentials_without_sending_anything_from_them() {
    let rig = Rig::new();
    let alex = rig.add(&User::alex());
    rig.store
        .put(&format!("account-{}", alex.id()), b"not json");
    rig.journal.clear();

    let signed_out = rig.client.sign_out(alex.id()).unwrap();
    assert!(!signed_out.revocation_confirmed());
    assert!(rig.journal.about("send").is_empty());
    assert!(rig.credentials_of(alex.id()).is_none());
    let (result, _) = rig.approve(rig.client.sign_in_again(alex.id()).unwrap(), &User::alex());
    assert!(result.is_ok());
}

fn body(request: Option<siwc::protocol::HttpRequest>) -> Vec<u8> {
    request.unwrap().body().to_vec()
}

#[test]
fn stored_credentials_read_back_every_member() {
    let world = World::new();
    let signed_in = world.sign_in(&User::alex().without_plan_use());
    let original = signed_in.credentials();
    let stored = original.to_stored();
    let read = Credentials::from_stored(stored.expose()).unwrap();

    assert_eq!(read.client_id(), original.client_id());
    assert_eq!(read.subject(), original.subject());
    assert_eq!(
        read.access_token().expose(),
        original.access_token().expose()
    );
    assert_eq!(read.expires_at(), original.expires_at());
    for offset in [0, 3539, 3540, 3600] {
        let now = UnixTime::from_secs(NOW + offset);
        assert_eq!(
            read.needs_refresh(now),
            original.needs_refresh(now),
            "{offset}"
        );
    }
    assert_eq!(read.scopes(), original.scopes());
    assert_eq!(read.earliest_refresh_at(), original.earliest_refresh_at());
    assert_eq!(
        body(read.refresh_request()),
        body(original.refresh_request())
    );
    assert_eq!(body(read.revoke_request()), body(original.revoke_request()));
    // The ID token kept as the hint for a later sign-in is the same one.
    let hint = |credentials: &Credentials| {
        let returning = Returning::signed_in(signed_in.identity(), credentials).with_hints();
        let attempt = world.attempt(Registration::Saved(returning));
        let (_, query) = attempt.authorization_url().split_once('?').unwrap();
        optional(&form_decode(query), "id_token_hint").map(str::to_owned)
    };
    assert_eq!(hint(&read), hint(original));
    assert!(hint(&read).is_some());
    // Exporting again gives the same bytes.
    assert_eq!(read.to_stored().expose(), stored.expose());
}

#[test]
fn credentials_without_a_refresh_token_read_back_without_one() {
    let world = World::new();
    world.provider.alter_next_response(|body| {
        body.remove("refresh_token");
        body.remove("earliest_refresh_at");
    });
    let signed_in = world.sign_in(&User::alex());
    let stored = signed_in.credentials().to_stored();
    let read = Credentials::from_stored(stored.expose()).unwrap();
    assert!(read.refresh_request().is_none());
    assert!(read.earliest_refresh_at().is_none());
    assert_eq!(read.to_stored().expose(), stored.expose());
}

#[test]
fn mutated_stored_credentials_never_panic_and_are_store_corrupt_when_refused() {
    let world = World::new();
    let stored = world.sign_in(&User::alex()).credentials().to_stored();
    let original = stored.expose().to_vec();
    let mut generator = Generator::new(30);
    let check = |bytes: &[u8]| {
        if let Err(error) = Credentials::from_stored(bytes) {
            let version = serde_json::from_slice::<Value>(bytes)
                .ok()
                .and_then(|obj| obj["v"].as_u64());
            if error.kind() == ErrorKind::StoreUnsupported {
                assert!(version.is_some_and(|v| v != 1));
            } else {
                assert_eq!(error.kind(), ErrorKind::StoreCorrupt);
                assert_eq!(error.to_string(), "the stored credentials cannot be read");
            }
        }
    };

    // Byte-level edits.
    for _ in 0..300 {
        check(&generator.mangle(&original, b"{}[]\",:0\\nu "));
    }

    // Every member replaced by every kind of value.
    let document: Value = serde_json::from_slice(&original).unwrap();
    let long = "x".repeat(17 * 1024);
    let replacements = [
        json!(null),
        json!(true),
        json!(0),
        json!(-1),
        json!(1.5),
        json!(u64::MAX),
        json!(""),
        json!("x"),
        json!(long),
        json!("dynamic_agent_client"),
        json!("openid \"quoted\""),
        json!([]),
        json!({}),
    ];
    for name in document.as_object().unwrap().keys() {
        for replacement in &replacements {
            let mut edited = document.clone();
            edited[name.as_str()] = replacement.clone();
            check(edited.to_string().as_bytes());
        }
    }
    // A renewal time after the expiry is refused.
    let mut late = document.clone();
    late["renew_at"] = json!(document["expires_at"].as_u64().unwrap() + 1);
    assert!(Credentials::from_stored(late.to_string().as_bytes()).is_err());
}

#[test]
fn unknown_store_versions_survive_sign_out_and_forget() {
    for installation in [false, true] {
        let rig = Rig::new();
        let account = rig.add(&User::alex());
        let id = account.id();
        let entry = if installation {
            "installation".to_owned()
        } else {
            format!("account-{id}")
        };
        rig.store.put(&entry, br#"{"v":2,"future":true}"#);
        let before = rig.store.snapshot();
        for action in [siwc::Client::sign_out, siwc::Client::forget] {
            assert_eq!(
                action(&rig.client, id).unwrap_err().kind(),
                ErrorKind::StoreUnsupported
            );
            assert_eq!(rig.store.snapshot(), before);
        }
        assert_eq!(rig.journal.count("send revoke"), 0);
    }
}

#[test]
fn rejected_registration_cleanup_skips_unreadable_credentials() {
    for action in [siwc::Client::sign_out, siwc::Client::forget] {
        let rig = Rig::new();
        let account = rig.add(&User::alex());
        let id = account.id();
        let mut record: Value =
            serde_json::from_slice(&rig.store.bytes("installation").unwrap()).unwrap();
        record["accounts"][0]["state"] = json!("registration_rejected");
        rig.store.put("installation", record.to_string().as_bytes());
        // A credential read would return StoreUnsupported.
        let entry = format!("account-{id}");
        rig.store.put(&entry, br#"{"v":2}"#);
        assert!(!action(&rig.client, id).unwrap().revocation_confirmed());
        assert!(rig.store.bytes(&entry).is_none());
        assert_eq!(rig.journal.count("send revoke"), 0);
    }
}
