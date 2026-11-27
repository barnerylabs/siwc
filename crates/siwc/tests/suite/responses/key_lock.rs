//! A cold Keychain store while another process holds its sealing-key lock.

use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{self, Sender};
use std::task::{Context, Waker};
use std::thread;
use std::time::{Duration, Instant};

use siwc::store::{KEY_LEN, KeyGeneration, Keychain, PrivateFiles, Sealed, SealingKey};
use siwc::testing::{FakeProvider, FakeUser};
use siwc::{AccountId, AppName, Canceller, Client, Error, ErrorKind};

use super::async_end::report_thread_end;
use super::processes::Scratch;
use super::{request, sign_in};

const GUARD: Duration = Duration::from_secs(3);
const DIR: &str = "SIWC_TEST_SEALING_LOCK_DIR";
const ID: &str = "SIWC_TEST_SEALING_LOCK_ACCOUNT";
const LOOKUP_SOCKET: &str = "SIWC_TEST_KEYCHAIN_LOOKUP_SOCKET";
const LOOKUP_EXE: &str = "SIWC_TEST_KEYCHAIN_LOOKUP_EXE";

struct Fixed;

impl SealingKey for Fixed {
    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(KeyGeneration::new(0, None))
    }

    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        key.fill(0x42);
        Ok(())
    }

    fn fill_retired(&self, _keys: &mut siwc::store::RetiredKeys<'_>) -> Result<(), Error> {
        Ok(())
    }
}

struct WatchedKey(Keychain, Sender<()>);

impl SealingKey for WatchedKey {
    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        self.0.lock_generation()
    }

    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        report_thread_end(&self.1);
        self.0.fill(key)
    }

    fn fill_retired(&self, keys: &mut siwc::store::RetiredKeys<'_>) -> Result<(), Error> {
        self.0.fill_retired(keys)
    }
}

/// The holder is a different process. A descriptor here belongs to the
/// reader inside the lock wait, even if the test thread ran first.
fn wait_for_lock_attempt(path: &Path) {
    let start = Instant::now();
    while !fs::read_dir("/proc/self/fd")
        .unwrap()
        .flatten()
        .any(|fd| fs::read_link(fd.path()).is_ok_and(|link| link == path))
    {
        assert!(
            start.elapsed() < GUARD,
            "the reader never tried the key lock"
        );
        thread::yield_now();
    }
}

fn cancel_reader(dir: &Path, id: AccountId, asynchronous: bool) {
    let files = PrivateFiles::open(dir).unwrap();
    let key = Keychain::new("com.example.siwc-lock-test", &files).unwrap();
    let (ended, ends) = mpsc::channel();
    let provider = FakeProvider::new();
    let client = Client::new(
        AppName::new("Paste Perfect").unwrap(),
        Sealed::new(files, WatchedKey(key, ended)),
        provider.clone(),
    );
    let lock_path = dir.join(".sealing-key.lock");
    if asynchronous {
        let request = request();
        let mut opening = Box::pin(client.stream_response_async(&id, &request));
        assert!(
            opening
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        wait_for_lock_attempt(&lock_path);
        drop(opening);
        ends.recv_timeout(GUARD)
            .expect("the dropped future left its reader at the key lock");
    } else {
        let stop = Canceller::new();
        let worker_stop = stop.clone();
        let sync = thread::spawn(move || {
            client
                .stream_response_cancellable(&id, &request(), &worker_stop)
                .unwrap_err()
                .kind()
        });
        wait_for_lock_attempt(&lock_path);
        stop.cancel();
        ends.recv_timeout(GUARD)
            .expect("the synchronous caller still waits for the key lock");
        assert_eq!(sync.join().unwrap(), ErrorKind::Cancelled);
    }
    assert!(provider.plan_requests().is_empty());
}

#[test]
fn cancellation_releases_a_cold_keychain_reader_while_the_key_lock_is_still_held() {
    if let Some(dir) = std::env::var_os(DIR) {
        let id = AccountId::parse(&std::env::var(ID).unwrap()).unwrap();
        let dir = Path::new(&dir);
        cancel_reader(dir, id.clone(), false);
        return cancel_reader(dir, id, true);
    }
    let scratch = Scratch::new("sealing-key");
    let files = PrivateFiles::open(&scratch.0).unwrap();
    let provider = FakeProvider::new();
    let client = Client::new(
        AppName::new("Paste Perfect").unwrap(),
        Sealed::new(files, Fixed),
        provider.clone(),
    );
    let id = sign_in(&client, &provider, FakeUser::new("owner@example.invalid"));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(scratch.0.join(".sealing-key.lock"))
        .unwrap();
    lock.lock().unwrap();
    // Keep the lock until the reader process exits, including on a failed
    // assertion. No reader needs access to the user's system keychain.
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("responses::key_lock::cancellation_releases_a_cold_keychain_reader_while_the_key_lock_is_still_held")
        .env(DIR, &scratch.0)
        .env(ID, id.as_str())
        .env("PATH", "")
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_keychain_helper_for_the_lookup_test() {
    let Some(socket) = std::env::var_os(LOOKUP_SOCKET) else {
        return;
    };
    let mut peer = UnixStream::connect(socket).unwrap();
    peer.write_all(&std::process::id().to_ne_bytes()).unwrap();
    // Stay inside the lookup until killed, or until the test closes the
    // gate to clean up a reader that failed to cancel.
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

fn accept_lookup(listener: &UnixListener) -> UnixStream {
    let start = Instant::now();
    loop {
        match listener.accept() {
            Ok((peer, _)) => return peer,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(start.elapsed() < GUARD, "the keychain lookup never began");
                thread::yield_now();
            }
            Err(error) => panic!("could not accept the keychain helper: {error}"),
        }
    }
}

fn cancel_running_lookup(dir: &Path, id: AccountId, asynchronous: bool) {
    let files = PrivateFiles::open(dir).unwrap();
    let key = Keychain::new("com.example.siwc-lookup-test", &files).unwrap();
    let (ended, ends) = mpsc::channel();
    let provider = FakeProvider::new();
    let client = Client::new(
        AppName::new("Paste Perfect").unwrap(),
        Sealed::new(files, WatchedKey(key, ended)),
        provider.clone(),
    );
    let listener = UnixListener::bind(std::env::var_os(LOOKUP_SOCKET).unwrap()).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Canceller::new();
    let request = request();
    let mut opening = Box::pin(client.stream_response_async(&id, &request));
    let worker = if asynchronous {
        assert!(
            opening
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        None
    } else {
        let (client, id, request, stop) =
            (client.clone(), id.clone(), request.clone(), stop.clone());
        Some(thread::spawn(move || {
            client
                .stream_response_cancellable(&id, &request, &stop)
                .unwrap_err()
                .kind()
        }))
    };

    let mut peer = accept_lookup(&listener);
    peer.set_read_timeout(Some(GUARD)).unwrap();
    let mut pid = [0; 4];
    peer.read_exact(&mut pid).unwrap();
    let process = Path::new("/proc").join(u32::from_ne_bytes(pid).to_string());
    let lock = fs::File::open(dir.join(".sealing-key.lock")).unwrap();
    let held_during_lookup = lock.try_lock();
    drop(opening);
    stop.cancel();
    let finished_in_time = ends.recv_timeout(GUARD);
    let released_while_gate_closed = lock.try_lock();
    let reaped_while_gate_closed = !process.exists();
    drop(peer);

    if let Some(worker) = worker {
        assert_eq!(worker.join().unwrap(), ErrorKind::Cancelled);
    }
    assert!(matches!(
        held_during_lookup,
        Err(fs::TryLockError::WouldBlock)
    ));
    finished_in_time.expect("the reader waited for the cancelled keychain lookup");
    assert!(
        reaped_while_gate_closed,
        "the keychain helper was not reaped"
    );
    released_while_gate_closed.expect("the keychain lookup kept the key lock");
    assert!(provider.plan_requests().is_empty());
}

fn with_synthetic_lookup(test: &str, asynchronous: bool) {
    if let Some(dir) = std::env::var_os(DIR) {
        let id = AccountId::parse(&std::env::var(ID).unwrap()).unwrap();
        return cancel_running_lookup(Path::new(&dir), id, asynchronous);
    }
    let scratch = Scratch::new(if asynchronous {
        "lookup-async"
    } else {
        "lookup-sync"
    });
    fs::create_dir(&scratch.0).unwrap();
    let dir = scratch.0.join("store");
    let provider = FakeProvider::new();
    let client = Client::new(
        AppName::new("Paste Perfect").unwrap(),
        Sealed::new(PrivateFiles::open(&dir).unwrap(), Fixed),
        provider.clone(),
    );
    let id = sign_in(&client, &provider, FakeUser::new("sample@example.invalid"));
    // Linked rather than written, so no forked test can hold it open for
    // writing when it starts (ETXTBSY).
    symlink(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/suite/responses/lookup-secret-tool.sh"
        ),
        scratch.0.join("secret-tool"),
    )
    .unwrap();
    let executable = std::env::current_exe().unwrap();
    let output = Command::new(&executable)
        .args(["--exact", test])
        .env(DIR, dir)
        .env(ID, id.as_str())
        .env(LOOKUP_SOCKET, scratch.0.join("gate"))
        .env(LOOKUP_EXE, executable)
        .env("PATH", &scratch.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cancellation_kills_and_reaps_a_running_keychain_lookup() {
    with_synthetic_lookup(
        "responses::key_lock::cancellation_kills_and_reaps_a_running_keychain_lookup",
        false,
    );
}

#[test]
fn dropping_async_opening_kills_and_reaps_a_running_keychain_lookup() {
    with_synthetic_lookup(
        "responses::key_lock::dropping_async_opening_kills_and_reaps_a_running_keychain_lookup",
        true,
    );
}
