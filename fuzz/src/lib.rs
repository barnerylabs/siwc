//! Fixtures for the fuzz targets: an attempt with a fixed state, the
//! exchange its callback leads to, the fake provider's key set, stored
//! credentials and a fixed sealing key. All values are synthetic.

use siwc::protocol::{
    Accepted, Attempt, Callback, Credentials, Exchange, HttpResponse, Jwks, Registration,
};
use siwc::store::{KEY_LEN, KeyGeneration, RetiredKeys, SealingKey};
use siwc::{AppName, Entropy, Error, HostId, UnixTime};

/// The time every target runs at.
pub const NOW: UnixTime = UnixTime::from_secs(1_800_000_000);

/// The same bytes every time, so the state of every attempt is the same
/// and a target can answer it.
struct Fixed;

impl Entropy for Fixed {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.fill(0x5a);
        Ok(())
    }
}

/// A new registration's attempt and the `state` its callback must carry.
///
/// # Panics
///
/// When the fixed values are refused, which a target must not hide.
pub fn attempt() -> (Attempt, String) {
    let app = AppName::new("Paste Perfect").expect("a valid app name");
    let host =
        HostId::parse("urn:uuid:00000000-0000-4000-8000-000000000000").expect("a valid host ID");
    let attempt = Attempt::start_with_entropy(Registration::New(&app), Some(&host), 8765, &Fixed)
        .expect("an attempt with fixed entropy");
    let state = attempt
        .authorization_url()
        .split(['?', '&'])
        .find_map(|pair| pair.strip_prefix("state="))
        .expect("a state in the authorization url")
        .to_owned();
    (attempt, state)
}

/// The exchange after a callback that passed every check.
///
/// # Panics
///
/// When the attempt refuses its own callback.
pub fn exchange() -> Exchange {
    let (attempt, state) = attempt();
    let query = format!("state={state}&code=fuzz-code&client_id=app_fuzz0001");
    match attempt.accept(&query) {
        Callback::Final(Ok(Accepted::NewRegistration(registration))) => registration.saved(),
        other => panic!("the attempt refused its own callback: {other:?}"),
    }
}

/// The fake provider's published keys, which the ID tokens are checked
/// against.
///
/// # Panics
///
/// When the key set in `key_set.json` is refused.
#[must_use]
pub fn keys() -> Jwks {
    let body = include_bytes!("key_set.json").to_vec();
    Jwks::from_response(&HttpResponse::new(200, body)).expect("the fixed key set")
}

/// Two bytes of big-endian status followed by the response body.
pub fn response(data: &[u8]) -> Option<HttpResponse> {
    let (status, body) = data.split_first_chunk::<2>()?;
    Some(HttpResponse::new(
        u16::from_be_bytes(*status),
        body.to_vec(),
    ))
}

/// The credentials that obtain the renewal in the refresh response target.
///
/// # Panics
///
/// When the synthetic stored credentials are refused.
pub fn credentials() -> Credentials {
    Credentials::from_stored(include_bytes!("../seeds/token_response/stored-credentials"))
        .expect("the fixed credentials")
}

/// The sealing key `0x5a` repeated, under which the seed of `sealed_entry`
/// was sealed.
#[derive(Debug)]
pub struct FixedKey;

impl SealingKey for FixedKey {
    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(KeyGeneration::new(0, None))
    }

    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        key.fill(0x5a);
        Ok(())
    }

    fn fill_retired(&self, _keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        Ok(())
    }
}
