//! Renewing a refused token while another process of the app holds the
//! account's lock: the stream waits its turn like every other renewal.
//!
//! The test works in a directory of its own under `CARGO_TARGET_TMPDIR`
//! and starts this program a second time to hold the lock.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::time::Duration;

use siwc::store::{EntryName, PrivateFiles, Store};
use siwc::testing::{FakeClock, FakeProvider, FakeResponse, FakeUser};
use siwc::{AppName, Client, ErrorKind, UnixTime};

use crate::support::random::Seeded;

use super::{INVALID_USER, request, sign_in};

/// The marker the child below prints once it holds the lock.
const LOCK_HELD: &str = "siwc-test-account-lock-held";

/// The variables that name the store directory and the locked entry for
/// the child below.
const LOCK_DIR: &str = "SIWC_TEST_RESPONSES_LOCK_DIR";
const LOCK_ENTRY: &str = "SIWC_TEST_RESPONSES_LOCK_ENTRY";

/// A store directory of the test's own, removed when the test ends.
pub(super) struct Scratch(pub(super) PathBuf);

impl Scratch {
    pub(super) fn new(test: &str) -> Self {
        let name = format!("responses-{test}-{}", process::id());
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        // Left behind by a run that was killed.
        let _ = fs::remove_dir_all(&path);
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Not a rule of its own: the other process of the next test. Without the
/// variables it does nothing.
#[test]
fn the_other_process_of_the_renewal_test() {
    let (Some(dir), Ok(entry)) = (std::env::var_os(LOCK_DIR), std::env::var(LOCK_ENTRY)) else {
        return;
    };
    let store = PrivateFiles::open(dir).unwrap();
    let entry = EntryName::new(&entry).unwrap();
    let _held = store.lock(&entry, Duration::ZERO).unwrap();
    // Written to the real output, past the test harness's capture.
    let mut output = std::io::stdout();
    writeln!(output, "{LOCK_HELD}").unwrap();
    output.flush().unwrap();
    // Holds the lock until the test closes this process's input.
    let mut rest = String::new();
    std::io::stdin().read_to_string(&mut rest).unwrap();
}

#[test]
fn a_refused_token_is_renewed_only_once_another_process_releases_the_account() {
    let scratch = Scratch::new("processes");
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        PrivateFiles::open(&scratch.0).unwrap(),
        provider.transport(),
    )
    .clock(clock.clone())
    .entropy(Seeded::new(11))
    // Waited out once below.
    .lock_patience(Duration::from_millis(60))
    .build();
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    let first = client.access_token(&id).unwrap().expose().to_owned();

    // This test program again, running only the test above: another
    // process of the app that is busy with the same account.
    let mut other = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "responses::processes::the_other_process_of_the_renewal_test",
        ])
        .env(LOCK_DIR, &scratch.0)
        .env(LOCK_ENTRY, format!("account-{id}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(other.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok);
    let holds = output.by_ref().any(|line| line.contains(LOCK_HELD));
    assert!(holds, "the other process took the account's lock");

    // The API refuses the token. Renewing it needs the account's lock,
    // which the other process holds: the stream gives up after its
    // patience instead of renewing beside that process.
    provider.push_response(FakeResponse::refusal(401, INVALID_USER));
    let error = client.stream_response(&id, &request()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::StoreBusy);
    assert_eq!(provider.plan_requests().len(), 1);

    drop(other.stdin.take());
    // Read to the end, so the other process can finish what it prints.
    output.for_each(drop);
    assert!(other.wait().unwrap().success());

    // With the account released, the same refusal is answered by a
    // renewal and a second request.
    let lasting = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        PrivateFiles::open(&scratch.0).unwrap(),
        provider.transport(),
    )
    .clock(clock.clone())
    .entropy(Seeded::new(12))
    // A process another test starts may hold a copy of the lock file,
    // and the lock with it, until it executes.
    .lock_patience(Duration::from_secs(30))
    .build();
    provider.push_response(FakeResponse::refusal(401, INVALID_USER));
    provider.push_response(FakeResponse::text(&["Hello"]));
    let stream = lasting.stream_response(&id, &request()).unwrap();
    assert_eq!(stream.into_text().unwrap(), "Hello");
    assert_eq!(provider.plan_requests().len(), 3);
    let renewed = lasting.access_token(&id).unwrap().expose().to_owned();
    assert_ne!(renewed, first, "the token was renewed");
    // The first client reads the renewed credentials from the shared store.
    assert_eq!(client.access_token(&id).unwrap().expose(), renewed);
}
