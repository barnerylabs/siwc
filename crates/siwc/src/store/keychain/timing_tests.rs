//! Refreshes overlapping a real file lock and a gated synthetic helper.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::protocol::{HttpRequest, HttpResponse};
use crate::store::{EntryName, KEY_LEN, KeyGeneration, RetiredKeys, SealingKey, Store};
use crate::testing::{FakeProvider, FakeUser};
use crate::{AccessToken, AccountId, AppName, Client, Error, ErrorKind, Transport};

use super::{Keychain, PrivateFiles, Sealed};

const OLD: &str = "com.example.renewal.v1";
const NEW: &str = "com.example.renewal.v2";
const MISSING: &str = "com.example.renewal.missing";
const GUARD: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(super) struct Timing {
    pub(super) program: PathBuf,
    pub(super) patience: Duration,
    pub(super) elapsed: Option<Arc<AtomicU64>>,
    pub(super) contended: Option<mpsc::SyncSender<()>>,
    pub(super) write_elapsed: Option<Arc<AtomicU64>>,
    pub(super) expire_after_reset_keys: Option<Arc<AtomicU64>>,
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("siwc-renewal-{label}-{}", process::id()));
        fs::create_dir(&path).unwrap();
        // A link, not a copy: writing an executable in a process whose other
        // tests fork can leave it busy (ETXTBSY) when the helper starts.
        symlink(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/suite/store/keychain_fixture/secret-tool.sh"
            ),
            path.join("secret-tool"),
        )
        .unwrap();
        Self(path)
    }

    fn source(&self, files: &PrivateFiles, service: &str, patience: Duration) -> Keychain {
        let mut keychain = Keychain::new(service, files).unwrap();
        keychain.timing = Some(Timing {
            program: self.0.join("secret-tool"),
            patience,
            elapsed: None,
            write_elapsed: None,
            contended: None,
            expire_after_reset_keys: None,
        });
        keychain
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct PausedHelper {
    gate: File,
    started: PathBuf,
    released: bool,
}

impl PausedHelper {
    fn new(dir: &Path, operation: &str, service: &str) -> Self {
        let name = format!("{operation}-{service}");
        let path = dir.join(format!("pause-{name}"));
        assert!(
            Command::new("/bin/mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        Self {
            gate: OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap(),
            started: dir.join(format!("{name}-started")),
            released: false,
        }
    }

    fn wait(&self) {
        let started = Instant::now();
        while !self.started.exists() {
            assert!(
                started.elapsed() < GUARD,
                "the synthetic helper did not start"
            );
            thread::yield_now();
        }
    }

    fn release(&mut self) {
        if !self.released {
            let _ = self.gate.write_all(b"\n");
            self.released = true;
        }
    }
}

impl Drop for PausedHelper {
    fn drop(&mut self) {
        self.release();
    }
}

struct PauseAfterRefresh {
    provider: FakeProvider,
    spent: mpsc::Sender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl fmt::Debug for PauseAfterRefresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PauseAfterRefresh")
    }
}

impl Transport for PauseAfterRefresh {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        let response = self.provider.send(request)?;
        if request.body().starts_with(b"grant_type=refresh_token") {
            self.spent.send(()).unwrap();
            self.resume.lock().unwrap().recv_timeout(GUARD).unwrap();
        }
        Ok(response)
    }
}

struct Session {
    provider: FakeProvider,
    id: AccountId,
    old: Client,
    first: AccessToken,
    spent: mpsc::Receiver<()>,
    resume: mpsc::Sender<()>,
}

impl Session {
    fn new(scratch: &Scratch, files: &PrivateFiles) -> Self {
        let source = scratch.source(files, OLD, Duration::ZERO);
        Self::with_source(files, source)
    }

    fn watching_contention(scratch: &Scratch, files: &PrivateFiles) -> (Self, mpsc::Receiver<()>) {
        let (signal, contended) = mpsc::sync_channel(1);
        let mut source = scratch.source(files, OLD, Duration::ZERO);
        source.timing.as_mut().unwrap().contended = Some(signal);
        (Self::with_source(files, source), contended)
    }

    fn with_source(files: &PrivateFiles, source: Keychain) -> Self {
        let provider = FakeProvider::new();
        let (spent, wait_spent) = mpsc::channel();
        let (resume, wait_resume) = mpsc::channel();
        let old = Client::new(
            AppName::new("Offline Test App").unwrap(),
            Sealed::new(files.clone(), source),
            PauseAfterRefresh {
                provider: provider.clone(),
                spent,
                resume: Mutex::new(wait_resume),
            },
        );
        let mut sign_in = old.add_account_manually().unwrap();
        let redirect = provider
            .approve_manual(&sign_in, FakeUser::new("sample@example.invalid"))
            .unwrap();
        let id = sign_in.finish(&redirect).unwrap().account().id().clone();
        let first = old.access_token(&id).unwrap();
        Self {
            provider,
            id,
            old,
            first,
            spent: wait_spent,
            resume,
        }
    }

    fn start_renewal(&self) -> mpsc::Receiver<Result<AccessToken, Error>> {
        let (done, returned) = mpsc::channel();
        let (old, id, first) = (self.old.clone(), self.id.clone(), self.first.clone());
        thread::spawn(move || {
            let result = old.access_token_after_rejection(&id, &first);
            let _ = done.send(result);
        });
        self.spent.recv_timeout(GUARD).unwrap();
        returned
    }

    fn renew_with_v2(&self, files: PrivateFiles, keychain: Keychain, successor: &AccessToken) {
        let client = Client::new(
            AppName::new("Offline Test App").unwrap(),
            Sealed::new(files, keychain),
            self.provider.clone(),
        );
        assert_eq!(
            client.access_token(&self.id).unwrap().expose(),
            successor.expose()
        );
        let renewed = client
            .access_token_after_rejection(&self.id, successor)
            .unwrap();
        assert_ne!(renewed.expose(), successor.expose());
    }
}

#[test]
fn a_held_reset_lock_without_a_generation_change_does_not_block_a_successor() {
    let scratch = Scratch::new("reset-lock");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let session = Session::new(&scratch, &files);
    let held = files
        .lock_file(super::RESET_LOCK_FILE, Duration::ZERO, None)
        .unwrap();
    let returned = session.start_renewal();
    session.resume.send(()).unwrap();
    let result = returned.recv_timeout(Duration::from_secs(1));
    drop(held);
    let successor = result
        .expect("a write with an unchanged generation must not wait")
        .unwrap();
    let rotating = scratch
        .source(&files, NEW, GUARD)
        .with_retired(OLD)
        .unwrap();
    session.renew_with_v2(files, rotating, &successor);
}

#[test]
fn a_successor_stops_waiting_for_a_stuck_reset_at_the_write_deadline() {
    let scratch = Scratch::new("stuck-reset");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let elapsed = Arc::new(AtomicU64::new(0));
    let mut source = scratch.source(&files, OLD, Duration::ZERO);
    source.timing.as_mut().unwrap().write_elapsed = Some(Arc::clone(&elapsed));
    let session = Session::with_source(&files, source);
    let returned = session.start_renewal();
    let mut lookup = PausedHelper::new(&scratch.0, "lookup", OLD);
    let resetting = scratch.source(&files, OLD, GUARD);
    let reset = thread::spawn(move || resetting.start_over());
    lookup.wait();
    elapsed.store(180, Ordering::Release);
    session.resume.send(()).unwrap();
    let result = returned.recv_timeout(Duration::from_secs(1));
    lookup.release();
    assert!(!reset.join().unwrap().unwrap());
    assert_write_timeout(result);
}

#[test]
fn a_successor_stops_waiting_for_the_key_lock_after_a_clear_at_the_write_deadline() {
    let scratch = Scratch::new("stuck-key");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let elapsed = Arc::new(AtomicU64::new(0));
    let mut source = scratch.source(&files, OLD, Duration::ZERO);
    source.timing.as_mut().unwrap().write_elapsed = Some(Arc::clone(&elapsed));
    let session = Session::with_source(&files, source);
    let returned = session.start_renewal();
    fs::remove_file(scratch.0.join(OLD)).unwrap();
    assert!(scratch.source(&files, OLD, GUARD).start_over().unwrap());
    let held = files
        .lock_file(super::KEY_LOCK_FILE, Duration::ZERO, None)
        .unwrap();
    elapsed.store(180, Ordering::Release);
    session.resume.send(()).unwrap();
    let result = returned.recv_timeout(Duration::from_secs(1));
    drop(held);
    assert_write_timeout(result);
}

fn assert_write_timeout(result: Result<Result<AccessToken, Error>, mpsc::RecvTimeoutError>) {
    let error = result
        .expect("the virtual three-minute deadline was ignored")
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Store);
    assert_eq!(error.to_string(), "the sealing key write lock timed out");
    assert_eq!(error.cause(), Some(crate::ErrorCause::TimedOut));
}

#[test]
fn a_slow_key_creation_does_not_strand_a_successor() {
    let scratch = Scratch::new("activation");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let (session, contended) = Session::watching_contention(&scratch, &files);
    let mut add = PausedHelper::new(&scratch.0, "store", NEW);
    let rotating = scratch
        .source(&files, NEW, GUARD)
        .with_retired(OLD)
        .unwrap();
    let returned = session.start_renewal();
    let new_store = Sealed::new(files.clone(), rotating.clone());
    let activating = thread::spawn(move || {
        new_store
            .read(&EntryName::new("installation").unwrap())
            .map(|entry| entry.is_some())
    });
    add.wait();
    // The crossing write waits for the key lock while the add is gated.
    session.resume.send(()).unwrap();
    contended.recv_timeout(GUARD).unwrap();
    assert!(matches!(
        returned.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    add.release();
    assert!(activating.join().unwrap().unwrap());
    let successor = returned
        .recv_timeout(GUARD)
        .unwrap()
        .expect("slow activation must not lose the refresh successor");
    session.renew_with_v2(files, rotating, &successor);
}

#[test]
fn a_slow_reset_keeps_the_retained_accounts_successor_and_removes_nothing() {
    let scratch = Scratch::new("reset");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let (session, contended) = Session::watching_contention(&scratch, &files);
    let rotating = scratch
        .source(&files, NEW, GUARD)
        .with_retired(OLD)
        .unwrap();
    let unrelated = EntryName::new("unrelated-v2-entry").unwrap();
    Sealed::new(files.clone(), rotating.clone())
        .write(&unrelated, b"synthetic")
        .unwrap();
    let saved = scratch.0.join("saved-v2-key");
    fs::rename(scratch.0.join(NEW), &saved).unwrap();

    let elapsed = Arc::new(AtomicU64::new(0));
    let mut resetting = scratch
        .source(&files, NEW, GUARD)
        .with_retired(MISSING)
        .unwrap()
        .with_retired(OLD)
        .unwrap();
    resetting.timing.as_mut().unwrap().elapsed = Some(Arc::clone(&elapsed));
    let returned = session.start_renewal();
    let mut first = PausedHelper::new(&scratch.0, "lookup", MISSING);
    let mut second = PausedHelper::new(&scratch.0, "lookup", OLD);
    let reset = thread::spawn(move || resetting.start_over());
    first.wait();
    elapsed.store(20, Ordering::Release);
    first.release();
    second.wait();
    session.resume.send(()).unwrap();
    contended.recv_timeout(GUARD).unwrap();
    assert!(matches!(
        returned.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    // Each lookup is within its individual 60 s. Together they exhaust
    // the reset's budget before the scan can remove the unreadable entry.
    elapsed.store(40, Ordering::Release);
    second.release();
    let reset = reset.join().unwrap();
    let successor = returned
        .recv_timeout(GUARD)
        .unwrap()
        .expect("slow reset must not lose the refresh successor");
    let error = reset.expect_err("the total reset deadline must expire");
    assert_eq!(error.kind(), ErrorKind::Store);
    assert_eq!(error.to_string(), "the sealing key reset timed out");
    assert_eq!(error.cause(), Some(crate::ErrorCause::TimedOut));
    assert!(files.read(&unrelated).unwrap().is_some());

    let _ = fs::remove_file(scratch.0.join(format!("pause-lookup-{OLD}")));
    fs::rename(saved, scratch.0.join(NEW)).unwrap();
    session.renew_with_v2(files, rotating, &successor);
}

#[test]
fn a_completed_reset_lets_a_retained_account_keep_its_cached_key() {
    let scratch = Scratch::new("retained");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let session = Session::new(&scratch, &files);
    let rotating = scratch
        .source(&files, NEW, GUARD)
        .with_retired(OLD)
        .unwrap();
    let unrelated = EntryName::new("unrelated-v2-entry").unwrap();
    Sealed::new(files.clone(), rotating.clone())
        .write(&unrelated, b"synthetic")
        .unwrap();
    let saved = scratch.0.join("saved-v2-key");
    fs::rename(scratch.0.join(NEW), &saved).unwrap();

    let returned = session.start_renewal();
    assert!(rotating.start_over().unwrap());
    assert!(files.read(&unrelated).unwrap().is_none());
    let unavailable = scratch.0.join(format!("{OLD}.missing"));
    fs::write(&unavailable, []).unwrap();
    session.resume.send(()).unwrap();
    let successor = returned.recv_timeout(GUARD).unwrap().unwrap();

    fs::remove_file(unavailable).unwrap();
    fs::rename(saved, scratch.0.join(NEW)).unwrap();
    session.renew_with_v2(files, rotating, &successor);
}

#[test]
fn an_aborted_reset_after_key_inventory_keeps_the_crossing_successor() {
    let scratch = Scratch::new("abort-after-keys");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let session = Session::new(&scratch, &files);
    let returned = session.start_renewal();
    let saved = scratch.0.join("saved-old-key");
    fs::rename(scratch.0.join(OLD), &saved).unwrap();
    let elapsed = Arc::new(AtomicU64::new(0));
    let mut resetting = scratch.source(&files, OLD, GUARD);
    resetting.timing.as_mut().unwrap().elapsed = Some(Arc::clone(&elapsed));
    resetting.timing.as_mut().unwrap().expire_after_reset_keys = Some(elapsed);
    let error = resetting.start_over().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Store);
    assert_eq!(error.to_string(), "the sealing key reset timed out");
    assert!(
        files
            .read(&EntryName::new("installation").unwrap())
            .unwrap()
            .is_some()
    );
    session.resume.send(()).unwrap();
    let successor = returned.recv_timeout(GUARD).unwrap().unwrap();
    fs::rename(saved, scratch.0.join(OLD)).unwrap();
    let cold_key = scratch.source(&files, OLD, GUARD);
    session.renew_with_v2(files, cold_key, &successor);
}

#[test]
fn a_cleanly_aborted_reset_keeps_a_retired_entry_successor_while_keychain_is_locked() {
    struct OtherKey;
    impl SealingKey for OtherKey {
        fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
            key.fill(0x5a);
            Ok(())
        }
        fn fill_retired(&self, _: &mut RetiredKeys<'_>) -> Result<(), Error> {
            Ok(())
        }
        fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
            Ok(KeyGeneration::new(0, None))
        }
    }

    let scratch = Scratch::new("abort-retired-locked");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let original = Session::new(&scratch, &files);
    let rotating = scratch
        .source(&files, NEW, GUARD)
        .with_retired(OLD)
        .unwrap();
    let (spent, wait_spent) = mpsc::channel();
    let (resume, wait_resume) = mpsc::channel();
    let current = Client::new(
        AppName::new("Offline Test App").unwrap(),
        Sealed::new(files.clone(), rotating.clone()),
        PauseAfterRefresh {
            provider: original.provider.clone(),
            spent,
            resume: Mutex::new(wait_resume),
        },
    );
    let first = current.access_token(&original.id).unwrap();
    Sealed::new(files.clone(), OtherKey)
        .write(&EntryName::new("unreadable-orphan").unwrap(), b"synthetic")
        .unwrap();
    let (id, client, token) = (original.id.clone(), current.clone(), first.clone());
    let worker = thread::spawn(move || client.access_token_after_rejection(&id, &token));
    wait_spent.recv_timeout(GUARD).unwrap();

    let elapsed = Arc::new(AtomicU64::new(0));
    let mut resetting = scratch
        .source(&files, NEW, GUARD)
        .with_retired(OLD)
        .unwrap();
    resetting.timing.as_mut().unwrap().elapsed = Some(Arc::clone(&elapsed));
    resetting.timing.as_mut().unwrap().expire_after_reset_keys = Some(elapsed);
    let error = resetting.start_over().unwrap_err();
    assert_eq!(error.to_string(), "the sealing key reset timed out");
    assert!(
        files
            .read(&EntryName::new("unreadable-orphan").unwrap())
            .unwrap()
            .is_some()
    );
    fs::write(scratch.0.join("locked"), []).unwrap();
    resume.send(()).unwrap();
    let successor = worker.join().unwrap().unwrap();
    fs::remove_file(scratch.0.join("locked")).unwrap();
    original.renew_with_v2(files, rotating, &successor);
}

#[test]
fn an_aborted_key_inventory_cannot_erase_the_last_completed_clear() {
    let scratch = Scratch::new("aborted-inventory-history");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let keychain = scratch.source(&files, OLD, GUARD);
    let mut first = keychain.begin_reset().unwrap();
    keychain
        .record_reset_keys(&first, std::iter::empty())
        .unwrap();
    first.completed = first.started;
    keychain.record_reset(&first).unwrap();

    let key = [0x42; crate::store::KEY_LEN];
    let aborted = keychain.begin_reset().unwrap();
    keychain.record_reset_keys(&aborted, [&key]).unwrap();

    let mut last = keychain.begin_reset().unwrap();
    keychain.record_reset_keys(&last, [&key]).unwrap();
    last.completed = last.started;
    keychain.record_reset(&last).unwrap();
    let reset = keychain.reset_since(0).unwrap();
    assert!(matches!(reset, super::ResetSince::Checked(_)));
    if let super::ResetSince::Checked(readable) = reset {
        assert!(!readable.kept(&key, 0));
    }
}

#[test]
fn a_clean_abort_after_an_unfinished_reset_preserves_its_inventory() {
    let scratch = Scratch::new("abort-after-unfinished");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let mut keychain = scratch.source(&files, OLD, GUARD);
    let key = [0x42; KEY_LEN];
    let mut completed = keychain.begin_reset().unwrap();
    keychain.record_reset_keys(&completed, [&key]).unwrap();
    completed.completed = completed.started;
    keychain.record_reset(&completed).unwrap();

    let unfinished = keychain.begin_reset().unwrap();
    keychain
        .record_reset_keys(&unfinished, std::iter::empty())
        .unwrap();
    let elapsed = Arc::new(AtomicU64::new(31));
    keychain.timing.as_mut().unwrap().elapsed = Some(elapsed);
    assert_eq!(
        keychain.start_over().unwrap_err().to_string(),
        "the sealing key reset timed out"
    );
    let reset = keychain.reset_since(0).unwrap();
    let provisional = match reset {
        super::ResetSince::Unrecorded { provisional, .. } => provisional,
        _ => None,
    };
    assert!(
        !provisional.unwrap().kept(&key, 0),
        "the earlier unfinished inventory must still prohibit the key"
    );
}

#[test]
fn a_reset_that_cannot_record_its_abort_still_reports_the_timeout() {
    let scratch = Scratch::new("abort-unrecorded");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let entry = EntryName::new("synthetic-entry").unwrap();
    Sealed::new(files.clone(), scratch.source(&files, OLD, GUARD))
        .write(&entry, b"synthetic")
        .unwrap();

    let elapsed = Arc::new(AtomicU64::new(0));
    let mut resetting = scratch.source(&files, OLD, GUARD);
    resetting.timing.as_mut().unwrap().elapsed = Some(Arc::clone(&elapsed));
    let mut lookup = PausedHelper::new(&scratch.0, "lookup", OLD);
    let reset = thread::spawn(move || resetting.start_over());
    lookup.wait();
    // The budget runs out during the key lookup, and the reset history can
    // no longer be replaced when the reset records its abort.
    elapsed.store(31, Ordering::Release);
    let history = scratch.0.join("store").join(".sealing-key.resets");
    fs::remove_file(&history).unwrap();
    fs::create_dir(&history).unwrap();
    lookup.release();

    let error = reset.join().unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Store);
    assert_eq!(error.to_string(), "the sealing key reset timed out");
    assert_eq!(error.cause(), Some(crate::ErrorCause::TimedOut));
    assert!(files.read(&entry).unwrap().is_some());
}

#[test]
fn a_clean_abort_after_an_unfinished_reset_does_not_strand_a_successor() {
    let scratch = Scratch::new("abort-after-unfinished-successor");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let original = Session::new(&scratch, &files);
    let mut keychain = scratch
        .source(&files, NEW, GUARD)
        .with_retired(OLD)
        .unwrap();
    let (spent, wait_spent) = mpsc::channel();
    let (resume, wait_resume) = mpsc::channel();
    let current = Client::new(
        AppName::new("Offline Test App").unwrap(),
        Sealed::new(files.clone(), keychain.clone()),
        PauseAfterRefresh {
            provider: original.provider.clone(),
            spent,
            resume: Mutex::new(wait_resume),
        },
    );
    let first = current.access_token(&original.id).unwrap();
    let (returned, result) = mpsc::channel();
    let id = original.id.clone();
    thread::spawn(move || {
        let _ = returned.send(current.access_token_after_rejection(&id, &first));
    });
    wait_spent.recv_timeout(GUARD).unwrap();

    let mut old = [0; KEY_LEN];
    scratch.source(&files, OLD, GUARD).fill(&mut old).unwrap();
    let mut active = [0; KEY_LEN];
    keychain.fill(&mut active).unwrap();
    let mut completed = keychain.begin_reset().unwrap();
    keychain
        .record_reset_keys(&completed, [&old, &active])
        .unwrap();
    completed.completed = completed.started;
    keychain.record_reset(&completed).unwrap();

    fs::remove_file(scratch.0.join(NEW)).unwrap();
    let unfinished = keychain.begin_reset().unwrap();
    keychain.record_reset_keys(&unfinished, [&old]).unwrap();
    keychain.timing.as_mut().unwrap().elapsed = Some(Arc::new(AtomicU64::new(31)));
    assert_eq!(
        keychain.start_over().unwrap_err().to_string(),
        "the sealing key reset timed out"
    );

    resume.send(()).unwrap();
    let successor = result.recv_timeout(GUARD).unwrap().unwrap();
    let cold = Client::new(
        AppName::new("Offline Test App").unwrap(),
        Sealed::new(files, keychain),
        original.provider,
    );
    assert_eq!(
        cold.access_token(&original.id).unwrap().expose(),
        successor.expose()
    );
}

#[test]
fn a_later_activation_cannot_restore_fallback_to_a_key_cleared_by_reset() {
    let scratch = Scratch::new("cleared");
    let files = PrivateFiles::open(scratch.0.join("store")).unwrap();
    let session = Session::new(&scratch, &files);
    let returned = session.start_renewal();
    fs::remove_file(scratch.0.join(OLD)).unwrap();
    let resetting = scratch.source(&files, OLD, GUARD);
    assert!(resetting.start_over().unwrap());

    let rotating = scratch
        .source(&files, NEW, GUARD)
        .with_retired(OLD)
        .unwrap();
    Sealed::new(files.clone(), rotating)
        .write(&EntryName::new("new-service-entry").unwrap(), b"synthetic")
        .unwrap();
    session.resume.send(()).unwrap();
    let error = returned.recv_timeout(GUARD).unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let credentials = EntryName::new(&format!("account-{}", session.id)).unwrap();
    assert!(files.read(&credentials).unwrap().is_none());
}
