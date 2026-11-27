//! Keychain commands stalled behind a test-owned socket, with a fake clock.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::ErrorKind;
use crate::store::keychain::{KEY_LOCK_FILE, KEY_PATIENCE, Keychain, key_text};
use crate::store::{KEY_LEN, PrivateFiles};

use super::Tool;

const GATE: &str = "SIWC_TEST_KEYCHAIN_HELPER_DEADLINE_GATE";
const GUARD: Duration = Duration::from_secs(3);

struct Scratch(PathBuf);

impl Scratch {
    fn new(stall: &str) -> Self {
        let path = env::temp_dir().join(format!("siwc-helper-{stall}-{}", process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn helper(&self, stall: &str) -> PathBuf {
        let executable = self.0.join("secret-tool");
        fs::write(self.0.join("stall"), format!("{stall}\n")).unwrap();
        fs::write(
            self.0.join("runner"),
            format!("{}\n", env::current_exe().unwrap().display()),
        )
        .unwrap();
        // Linked rather than written, so no forked test can hold it open for
        // writing when it starts (ETXTBSY).
        symlink(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/suite/store/keychain_fixture/stalling-secret-tool.sh"
            ),
            &executable,
        )
        .unwrap();
        executable
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_stalled_keychain_helper() {
    let Some(gate) = env::var_os(GATE) else {
        return;
    };
    let mut peer = UnixStream::connect(gate).unwrap();
    peer.write_all(&process::id().to_ne_bytes()).unwrap();
    // Only the test closing the gate or the library killing the helper ends this.
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

fn accept(listener: &UnixListener) -> UnixStream {
    let started = Instant::now();
    loop {
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    started.elapsed() < GUARD,
                    "the keychain helper did not start"
                );
                thread::yield_now();
            }
            accepted => {
                return accepted
                    .expect("could not accept the synthetic keychain helper")
                    .0;
            }
        }
    }
}

fn stall_helper(stall: &str) {
    let scratch = Scratch::new(stall);
    let helper = scratch.helper(stall);
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let keychain = Keychain::new("com.example.siwc-deadline", &files).unwrap();
    let item = scratch.0.join("item");
    if stall == "lookup" {
        fs::write(&item, format!("{}\n", "ab".repeat(KEY_LEN))).unwrap();
    }

    let expired = AtomicBool::new(false);
    thread::scope(|scope| {
        let listener = UnixListener::bind(scratch.0.join("gate")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (done, returned) = mpsc::channel();
        let (keychain, helper, expired) = (&keychain, &helper, &expired);
        let worker = scope.spawn(move || {
            let elapsed = |start: &Instant| {
                if expired.load(Ordering::Acquire) {
                    KEY_PATIENCE
                } else {
                    start.elapsed()
                }
            };
            let tool = Tool {
                program: helper.as_os_str(),
                elapsed: &elapsed,
            };
            let mut key = [0; KEY_LEN];
            done.send((keychain.fill_using(&tool, &mut key), key))
                .unwrap();
        });

        let mut peer = accept(&listener);
        peer.set_read_timeout(Some(GUARD)).unwrap();
        let mut pid = [0; 4];
        peer.read_exact(&mut pid).unwrap();
        let proc = Path::new("/proc").join(u32::from_ne_bytes(pid).to_string());
        let held = files
            .lock_file(KEY_LOCK_FILE, Duration::ZERO, None)
            .map(drop);
        expired.store(true, Ordering::Release);
        let result = returned.recv_timeout(GUARD);
        let reaped = !proc.exists();
        let released = files
            .lock_file(KEY_LOCK_FILE, Duration::ZERO, None)
            .map(drop);
        drop(peer);
        worker.join().unwrap();

        assert_eq!(held.unwrap_err().kind(), ErrorKind::StoreBusy);
        let (result, key) = result.expect("the helper did not stop at the deadline");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Store);
        assert_eq!(error.to_string(), "the keychain helper timed out");
        assert_eq!(error.cause(), Some(crate::ErrorCause::TimedOut));
        assert_eq!(key, [0; KEY_LEN]);
        assert!(reaped, "the keychain helper was not reaped");
        released.expect("the timed-out helper kept the keychain lock");
    });

    fs::remove_file(scratch.0.join("stall")).unwrap();
    let mut stored = [0; KEY_LEN];
    assert!(key_text::decode(&fs::read(item).unwrap(), &mut stored));
    let mut key = [0; KEY_LEN];
    keychain
        .fill_using(&Tool::new(helper.as_os_str()), &mut key)
        .unwrap();
    assert!(key == stored);
    let writes = scratch.0.join("writes");
    if stall == "store" {
        assert_eq!(fs::read(writes).unwrap(), b"store\n");
    } else {
        assert!(!writes.exists());
    }
}

#[test]
fn a_stalled_lookup_times_out_and_releases_the_key_lock() {
    stall_helper("lookup");
}

#[test]
fn a_stalled_creation_times_out_and_the_next_lookup_reads_the_stored_key() {
    stall_helper("store");
}
