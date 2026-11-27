//! Stores: the behaviour every store shares, run against `MemoryStore` and
//! `PrivateFiles`, and the file rules of `PrivateFiles`.
//!
//! `PrivateFiles` tests work in a directory of their own under
//! `CARGO_TARGET_TMPDIR` and remove it when they end.

#[cfg(all(target_os = "linux", feature = "keychain"))]
#[path = "store/keychain_fixture.rs"]
mod keychain_fixture;

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use siwc::ErrorKind;
use siwc::store::{EntryName, MemoryStore, PrivateFiles, Store};

/// Upper bound for anything a test waits for; reached only when a test
/// fails.
const PATIENCE: Duration = Duration::from_secs(30);

/// A path of its own for one test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Self {
        let path =
            Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("store-{test}-{}", process::id()));
        remove(&path);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn open(&self) -> PrivateFiles {
        PrivateFiles::open(&self.0).unwrap()
    }

    /// The names in the directory, sorted.
    fn listing(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.0)
            .unwrap()
            .map(|item| item.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

fn remove(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path).unwrap(),
        Ok(_) => fs::remove_file(path).unwrap(),
        Err(_) => {}
    }
}

/// Runs `check` against a `MemoryStore` and against `PrivateFiles` in a
/// fresh directory.
fn each_store(test: &str, check: impl Fn(&dyn Store)) {
    check(&MemoryStore::new());
    let scratch = Scratch::new(test);
    check(&scratch.open());
}

fn name(text: &str) -> EntryName {
    EntryName::new(text).unwrap()
}

fn read(store: &dyn Store, entry: &EntryName) -> Option<Vec<u8>> {
    store
        .read(entry)
        .unwrap()
        .map(|stored| stored.expose().to_vec())
}

fn kind<T: std::fmt::Debug>(result: Result<T, siwc::Error>) -> ErrorKind {
    result.unwrap_err().kind()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

// Every store

#[test]
fn an_entry_reads_back_what_was_written_until_it_is_removed() {
    each_store("reads-back", |store| {
        let entry = name("account-1");
        assert_eq!(read(store, &entry), None, "{store:?}");

        let first = [0, 1, 2, 255, b'\n', 0];
        store.write(&entry, &first).unwrap();
        assert_eq!(
            read(store, &entry).as_deref(),
            Some(&first[..]),
            "{store:?}"
        );

        store.write(&entry, b"second").unwrap();
        assert_eq!(
            read(store, &entry).as_deref(),
            Some(&b"second"[..]),
            "{store:?}"
        );

        store.remove(&entry).unwrap();
        assert_eq!(read(store, &entry), None, "{store:?}");
        store.remove(&entry).unwrap();
    });
}

/// A write either fails with the old value in place or succeeds with the
/// new one visible; a directory sync that fails after the rename does not
/// turn the second into an error.
#[cfg(unix)]
#[test]
fn a_replacement_that_readers_see_is_no_error_even_when_the_directory_cannot_be_synced() {
    let scratch = Scratch::new("unsynced");
    let store = scratch.open();
    let entry = name("account-1");
    store.write(&entry, b"old").unwrap();
    // Without read permission the directory cannot be opened for its sync,
    // while files in it can still be created and renamed. (Root ignores
    // the mode, so there the sync works and the test proves less.)
    set_mode(scratch.path(), 0o300);
    let written = store.write(&entry, b"new");
    set_mode(scratch.path(), 0o700);
    written.unwrap();
    assert_eq!(read(&store, &entry).as_deref(), Some(&b"new"[..]));
}

#[test]
fn an_empty_value_is_an_entry_and_not_a_missing_one() {
    each_store("empty-value", |store| {
        let entry = name("installation");
        store.write(&entry, b"").unwrap();
        assert_eq!(read(store, &entry), Some(Vec::new()), "{store:?}");
    });
}

#[test]
fn entries_are_independent_of_each_other() {
    each_store("independent", |store| {
        let (one, two) = (name("account-1"), name("account-2"));
        store.write(&one, b"one").unwrap();
        store.write(&two, b"two").unwrap();

        store.write(&one, b"one again").unwrap();
        assert_eq!(read(store, &two).as_deref(), Some(&b"two"[..]), "{store:?}");

        store.remove(&one).unwrap();
        assert_eq!(read(store, &two).as_deref(), Some(&b"two"[..]), "{store:?}");
        assert_eq!(read(store, &one), None, "{store:?}");
    });
}

#[test]
fn a_held_lock_turns_away_a_second_taker_until_it_is_dropped() {
    each_store("lock-busy", |store| {
        let (entry, other) = (name("account-1"), name("account-2"));
        let held = store.lock(&entry, Duration::ZERO).unwrap();

        assert_eq!(
            kind(store.lock(&entry, Duration::ZERO)),
            ErrorKind::StoreBusy,
            "{store:?}"
        );
        let unrelated = store.lock(&other, Duration::ZERO).unwrap();

        drop(held);
        // Not at once: a process another test starts at this moment holds a
        // copy of the lock file until it executes, and the lock with it.
        drop(store.lock(&entry, PATIENCE).unwrap());
        drop(unrelated);
    });
}

#[test]
fn a_busy_lock_is_a_temporary_error() {
    each_store("lock-temporary", |store| {
        let entry = name("account-1");
        let _held = store.lock(&entry, Duration::ZERO).unwrap();
        assert!(
            store
                .lock(&entry, Duration::ZERO)
                .unwrap_err()
                .is_temporary()
        );
    });
}

#[test]
fn a_taker_waits_as_long_as_its_patience_and_no_longer() {
    each_store("patience", |store| {
        let entry = name("account-1");
        let held = store.lock(&entry, Duration::ZERO).unwrap();
        let patience = Duration::from_millis(60);
        thread::scope(|scope| {
            // On a thread of its own: the lock is taken there too.
            let waited = scope
                .spawn(|| {
                    let started = Instant::now();
                    let result = store.lock(&entry, patience).map(drop);
                    (result, started.elapsed())
                })
                .join()
                .unwrap();
            assert_eq!(kind(waited.0), ErrorKind::StoreBusy);
            assert!(waited.1 >= patience, "{:?}", waited.1);
            assert!(waited.1 < PATIENCE, "{:?}", waited.1);
        });
        drop(held);
    });
}

#[test]
fn a_patient_taker_gets_the_lock_once_the_holder_drops_it() {
    each_store("lock-wait", |store| {
        let entry = name("account-1");
        let held = store.lock(&entry, Duration::ZERO).unwrap();
        let (ready, is_ready) = mpsc::channel();

        thread::scope(|scope| {
            let taker = scope.spawn(|| {
                let busy = store.lock(&entry, Duration::ZERO).map(drop);
                ready.send(()).unwrap();
                let taken = store.lock(&entry, PATIENCE).map(drop);
                (busy, taken)
            });
            is_ready.recv().unwrap();
            drop(held);
            let (busy, taken) = taker.join().unwrap();
            assert_eq!(kind(busy), ErrorKind::StoreBusy, "{store:?}");
            taken.unwrap();
        });
    });
}

#[test]
fn reading_writing_and_removing_neither_need_nor_take_the_lock() {
    each_store("lock-free-access", |store| {
        let entry = name("account-1");
        let held = store.lock(&entry, Duration::ZERO).unwrap();

        thread::scope(|scope| {
            scope
                .spawn(|| {
                    store.write(&entry, b"value").unwrap();
                    assert_eq!(read(store, &entry).as_deref(), Some(&b"value"[..]));
                    store.remove(&entry).unwrap();
                })
                .join()
                .unwrap();
        });
        assert_eq!(
            kind(store.lock(&entry, Duration::ZERO)),
            ErrorKind::StoreBusy,
            "{store:?}"
        );

        drop(held);
        store.write(&entry, b"value").unwrap();
        read(store, &entry);
        store.remove(&entry).unwrap();
        // With patience: a process another test starts may hold a copy of
        // the lock file, and the lock with it, until it executes.
        drop(store.lock(&entry, PATIENCE).unwrap());
    });
}

#[test]
fn an_entry_name_outside_the_rule_is_refused() {
    for good in ["a", "0", "account-1", "a-b-c", &"a".repeat(64)] {
        assert_eq!(EntryName::new(good).unwrap().as_str(), good);
    }
    for bad in [
        "",
        &"a".repeat(65),
        "Account",
        "account.1",
        "a/b",
        "a\\b",
        "..",
        "a b",
        "a\0b",
        "-account",
        "account-",
        "kont\u{f6}",
        "\u{430}ccount",
    ] {
        assert_eq!(
            kind(EntryName::new(bad)),
            ErrorKind::InvalidInput,
            "{bad:?}"
        );
    }
}

#[test]
fn a_device_name_of_windows_is_refused_on_every_platform() {
    for device in ["con", "prn", "aux", "nul", "com1", "com9", "lpt0", "lpt1"] {
        assert_eq!(
            kind(EntryName::new(device)),
            ErrorKind::InvalidInput,
            "{device}"
        );
    }
    for fine in ["console", "nul-1", "com10", "com", "lpt", "account-nul"] {
        assert_eq!(EntryName::new(fine).unwrap().as_str(), fine);
    }
}

#[test]
fn a_name_cannot_point_at_a_lock_a_temporary_file_or_another_directory() {
    for bad in ["x.lock", "x.1-2.new", "../x", "/x", "x/../y", ".x"] {
        assert_eq!(
            kind(EntryName::new(bad)),
            ErrorKind::InvalidInput,
            "{bad:?}"
        );
    }
}

#[test]
fn debug_output_shows_no_stored_byte() {
    let value = b"synthetic-stored-value-7f3a";
    let entry = name("account-1");

    let memory = MemoryStore::new();
    memory.write(&entry, value).unwrap();
    let stored = memory.read(&entry).unwrap().unwrap();
    assert_eq!(format!("{memory:?}"), "MemoryStore { .. }");
    assert_eq!(format!("{stored:?}"), "Stored([redacted; 27 bytes])");

    let scratch = Scratch::new("debug");
    let files = scratch.open();
    files.write(&entry, value).unwrap();
    let stored = files.read(&entry).unwrap().unwrap();
    let lock = files.lock(&entry, Duration::ZERO).unwrap();
    assert_eq!(format!("{files:?}"), "PrivateFiles");
    assert_eq!(format!("{stored:?}"), "Stored([redacted; 27 bytes])");
    assert_eq!(format!("{lock:?}"), "Lock");
}

// PrivateFiles

#[test]
fn opening_needs_an_absolute_path() {
    assert_eq!(
        kind(PrivateFiles::open("relative/store")),
        ErrorKind::InvalidInput
    );
}

#[test]
fn opening_creates_a_missing_directory_owner_only() {
    let scratch = Scratch::new("creates");
    scratch.open();
    assert!(scratch.path().is_dir());
    #[cfg(unix)]
    assert_eq!(mode(scratch.path()), 0o700);
}

#[test]
fn opening_under_a_missing_parent_fails_and_creates_nothing() {
    let scratch = Scratch::new("missing-parent");
    let deep = scratch.join("store");
    assert_eq!(kind(PrivateFiles::open(&deep)), ErrorKind::Store);
    assert!(!scratch.path().exists());
}

#[test]
fn opening_leaves_no_probe_or_other_file_behind() {
    let scratch = Scratch::new("no-probe");
    scratch.open();
    scratch.open();
    assert!(scratch.listing().is_empty());
}

#[test]
fn opening_refuses_a_path_that_is_not_a_directory() {
    let scratch = Scratch::new("not-a-directory");
    fs::write(scratch.path(), b"").unwrap();
    assert_eq!(
        kind(PrivateFiles::open(scratch.path())),
        ErrorKind::StoreNotPrivate
    );
}

#[cfg(unix)]
#[test]
fn opening_refuses_a_symbolic_link() {
    let target = Scratch::new("link-target");
    target.open();
    let link = Scratch::new("link");
    std::os::unix::fs::symlink(target.path(), link.path()).unwrap();
    assert_eq!(
        kind(PrivateFiles::open(link.path())),
        ErrorKind::StoreNotPrivate
    );
    // Trailing `/` and `/.` must not resolve through the final symlink on POSIX.
    assert_eq!(
        kind(PrivateFiles::open(format!("{}/", link.path().display()))),
        ErrorKind::StoreNotPrivate
    );
    assert_eq!(
        kind(PrivateFiles::open(link.path().join("."))),
        ErrorKind::StoreNotPrivate
    );
    assert_eq!(
        kind(PrivateFiles::open(link.path().join("..").join("escaped"))),
        ErrorKind::InvalidInput
    );
}

#[cfg(unix)]
#[test]
fn opening_refuses_a_directory_others_can_access() {
    let scratch = Scratch::new("shared-directory");
    scratch.open();
    for shared in [0o740, 0o720, 0o710, 0o704, 0o702, 0o701] {
        set_mode(scratch.path(), shared);
        assert_eq!(
            kind(PrivateFiles::open(scratch.path())),
            ErrorKind::StoreNotPrivate,
            "{shared:o}"
        );
    }
    set_mode(scratch.path(), 0o700);
    scratch.open();
}

#[test]
fn an_entry_is_a_file_named_after_it_with_no_temporary_file_left() {
    let scratch = Scratch::new("entry-file");
    let store = scratch.open();
    store.write(&name("account-1"), b"value").unwrap();
    store.write(&name("account-1"), b"newer").unwrap();
    assert_eq!(scratch.listing(), ["account-1"]);
    assert_eq!(fs::read(scratch.join("account-1")).unwrap(), b"newer");
    #[cfg(unix)]
    assert_eq!(mode(&scratch.join("account-1")), 0o600);
}

#[test]
fn a_failed_write_removes_its_temporary_file() {
    let scratch = Scratch::new("failed-write");
    let store = scratch.open();
    fs::create_dir(scratch.join("account-1")).unwrap();
    fs::write(scratch.join("account-1").join("inside"), b"").unwrap();

    assert_eq!(
        kind(store.write(&name("account-1"), b"value")),
        ErrorKind::Store
    );
    assert_eq!(scratch.listing(), ["account-1"]);
}

#[test]
fn a_value_over_the_limit_is_not_written_and_the_previous_one_stays() {
    let scratch = Scratch::new("too-large-write");
    let store = scratch.open();
    let entry = name("account-1");
    store.write(&entry, b"previous").unwrap();

    let large = vec![7; 256 * 1024 + 1];
    assert_eq!(kind(store.write(&entry, &large)), ErrorKind::Store);
    assert_eq!(read(&store, &entry).as_deref(), Some(&b"previous"[..]));
    assert_eq!(scratch.listing(), ["account-1"]);

    store.write(&entry, &large[1..]).unwrap();
    assert_eq!(
        read(&store, &entry).map(|value| value.len()),
        Some(256 * 1024)
    );
}

#[test]
fn reading_refuses_an_entry_over_the_limit() {
    let scratch = Scratch::new("too-large-read");
    let store = scratch.open();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(scratch.join("account-1")).unwrap();
    file.write_all(&vec![7; 256 * 1024 + 1]).unwrap();
    drop(file);

    assert_eq!(kind(store.read(&name("account-1"))), ErrorKind::Store);
}

#[test]
fn reading_refuses_an_entry_that_is_not_a_regular_file() {
    let scratch = Scratch::new("not-a-file");
    let store = scratch.open();
    fs::create_dir(scratch.join("account-1")).unwrap();
    assert_eq!(
        kind(store.read(&name("account-1"))),
        ErrorKind::StoreNotPrivate
    );
}

#[cfg(unix)]
#[test]
fn reading_refuses_a_symbolic_link_even_to_a_private_file() {
    let scratch = Scratch::new("entry-link");
    let store = scratch.open();
    store.write(&name("target"), b"value").unwrap();
    std::os::unix::fs::symlink(scratch.join("target"), scratch.join("account-1")).unwrap();
    assert_eq!(
        kind(store.read(&name("account-1"))),
        ErrorKind::StoreNotPrivate
    );
}

#[cfg(unix)]
#[test]
fn reading_refuses_an_entry_others_can_access() {
    let scratch = Scratch::new("shared-entry");
    let store = scratch.open();
    let entry = name("account-1");
    store.write(&entry, b"value").unwrap();
    for shared in [0o640, 0o620, 0o604, 0o602] {
        set_mode(&scratch.join("account-1"), shared);
        assert_eq!(
            kind(store.read(&entry)),
            ErrorKind::StoreNotPrivate,
            "{shared:o}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_write_puts_a_new_file_in_place_and_never_changes_the_old_one() {
    use std::os::unix::fs::MetadataExt;

    let scratch = Scratch::new("replace");
    let store = scratch.open();
    let entry = name("account-1");
    store.write(&entry, b"the first value").unwrap();
    // A reader that opened the entry before the next write.
    let mut reader = File::open(scratch.join("account-1")).unwrap();
    let first_file = reader.metadata().unwrap().ino();

    store.write(&entry, b"second").unwrap();

    let mut seen = Vec::new();
    reader.read_to_end(&mut seen).unwrap();
    assert_eq!(seen, b"the first value", "the old file was not touched");
    let second_file = fs::metadata(scratch.join("account-1")).unwrap().ino();
    assert_ne!(first_file, second_file);
    assert_eq!(read(&store, &entry).unwrap(), b"second");
}

#[cfg(unix)]
#[test]
fn every_operation_refuses_a_directory_that_was_opened_to_others_since() {
    let scratch = Scratch::new("shared-later");
    let store = scratch.open();
    let entry = name("account-1");
    store.write(&entry, b"value").unwrap();

    set_mode(scratch.path(), 0o750);
    assert_eq!(kind(store.read(&entry)), ErrorKind::StoreNotPrivate);
    assert_eq!(
        kind(store.write(&entry, b"other")),
        ErrorKind::StoreNotPrivate
    );
    assert_eq!(kind(store.remove(&entry)), ErrorKind::StoreNotPrivate);
    assert_eq!(
        kind(store.lock(&entry, Duration::ZERO)),
        ErrorKind::StoreNotPrivate
    );

    set_mode(scratch.path(), 0o700);
    assert_eq!(read(&store, &entry).unwrap(), b"value");
    assert_eq!(scratch.listing(), ["account-1"]);
}

#[cfg(unix)]
#[test]
fn every_operation_refuses_a_directory_that_was_replaced_by_a_link() {
    let scratch = Scratch::new("linked-later");
    let elsewhere = Scratch::new("linked-later-target");
    let store = scratch.open();
    let entry = name("account-1");
    store.write(&entry, b"value").unwrap();

    fs::rename(scratch.path(), elsewhere.path()).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), scratch.path()).unwrap();
    assert_eq!(kind(store.read(&entry)), ErrorKind::StoreNotPrivate);
    assert_eq!(
        kind(store.write(&entry, b"other")),
        ErrorKind::StoreNotPrivate
    );
    assert_eq!(kind(store.remove(&entry)), ErrorKind::StoreNotPrivate);
    assert_eq!(
        kind(store.lock(&entry, Duration::ZERO)),
        ErrorKind::StoreNotPrivate
    );
    assert_eq!(fs::read(elsewhere.join(entry.as_str())).unwrap(), b"value");
    assert!(!elsewhere.join("account-1.lock").exists());
}

/// The marker the child below prints once it holds the lock.
const LOCK_HELD: &str = "siwc-test-lock-held";

/// The variable that names the store directory for the child below.
const LOCK_DIR: &str = "SIWC_TEST_LOCK_DIR";

/// Not a rule of its own: the other process of the next test. Without the
/// variable it does nothing.
#[test]
fn the_other_process_of_the_lock_test() {
    let Some(dir) = std::env::var_os(LOCK_DIR) else {
        return;
    };
    let store = PrivateFiles::open(dir).unwrap();
    let _held = store.lock(&name("account-1"), Duration::ZERO).unwrap();
    // Written to the real output, past the test harness's capture.
    let mut output = std::io::stdout();
    writeln!(output, "{LOCK_HELD}").unwrap();
    output.flush().unwrap();
    // Holds the lock until the test closes this process's input.
    let mut rest = String::new();
    std::io::stdin().read_to_string(&mut rest).unwrap();
}

#[test]
fn a_lock_keeps_another_process_out_until_it_is_released() {
    let scratch = Scratch::new("lock-processes");
    let store = scratch.open();
    let entry = name("account-1");

    // This test program again, running only the test above.
    let mut other = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "store::the_other_process_of_the_lock_test"])
        .env(LOCK_DIR, scratch.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(other.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok);
    let holds = output.by_ref().any(|line| line.contains(LOCK_HELD));
    assert!(holds, "the other process took the lock");

    assert_eq!(
        kind(store.lock(&entry, Duration::ZERO)),
        ErrorKind::StoreBusy
    );
    drop(other.stdin.take());
    // Read to the end, so the other process can finish what it prints.
    output.for_each(drop);
    assert!(other.wait().unwrap().success());
    // With patience: a process another test starts may hold a copy of
    // the lock file, and the lock with it, until it executes.
    drop(store.lock(&entry, PATIENCE).unwrap());
}

#[test]
fn a_lock_file_stays_after_the_lock_is_released() {
    let scratch = Scratch::new("lock-file");
    let store = scratch.open();
    drop(store.lock(&name("account-1"), Duration::ZERO).unwrap());
    assert_eq!(scratch.listing(), ["account-1.lock"]);
    #[cfg(unix)]
    assert_eq!(mode(&scratch.join("account-1.lock")), 0o600);
    // With patience: a process another test starts may hold a copy of
    // the lock file, and the lock with it, until it executes.
    drop(store.lock(&name("account-1"), PATIENCE).unwrap());
}

#[test]
fn locking_refuses_a_lock_path_that_is_not_a_regular_file() {
    let scratch = Scratch::new("lock-not-a-file");
    let store = scratch.open();
    fs::create_dir(scratch.join("account-1.lock")).unwrap();
    assert_eq!(
        kind(store.lock(&name("account-1"), Duration::ZERO)),
        ErrorKind::StoreNotPrivate
    );
}

#[cfg(unix)]
#[test]
fn locking_refuses_a_symbolic_link_or_a_lock_file_others_can_access() {
    let scratch = Scratch::new("lock-privacy");
    let outside = Scratch::new("lock-outside");
    outside.open();
    let store = scratch.open();
    let entry = name("account-1");

    let target = outside.join("redirected.lock");
    std::os::unix::fs::symlink(&target, scratch.join("account-1.lock")).unwrap();
    assert_eq!(
        kind(store.lock(&entry, Duration::ZERO)),
        ErrorKind::StoreNotPrivate
    );
    assert!(!target.exists(), "the symlink target was never created");

    fs::remove_file(scratch.join("account-1.lock")).unwrap();
    drop(store.lock(&entry, Duration::ZERO).unwrap());
    for shared in [0o640, 0o620, 0o604, 0o602] {
        set_mode(&scratch.join("account-1.lock"), shared);
        assert_eq!(
            kind(store.lock(&entry, Duration::ZERO)),
            ErrorKind::StoreNotPrivate,
            "{shared:o}"
        );
    }
}

#[test]
fn two_stores_on_one_directory_exclude_each_other() {
    let scratch = Scratch::new("two-stores");
    let (first, second) = (scratch.open(), scratch.open());
    let entry = name("account-1");

    let held = first.lock(&entry, Duration::ZERO).unwrap();
    assert_eq!(
        kind(second.lock(&entry, Duration::ZERO)),
        ErrorKind::StoreBusy
    );

    let (ready, is_ready) = mpsc::channel();
    thread::scope(|scope| {
        let taker = scope.spawn(|| {
            ready.send(()).unwrap();
            second.lock(&entry, PATIENCE).map(drop)
        });
        is_ready.recv().unwrap();
        drop(held);
        taker.join().unwrap().unwrap();
    });
}

#[test]
fn opening_removes_only_stale_leftovers() {
    let scratch = Scratch::new("leftovers");
    scratch.open();
    let old = SystemTime::now() - Duration::from_secs(2 * 60 * 60);
    let recent = SystemTime::now() - Duration::from_secs(30 * 60);
    let files = [
        ("account-1.4242-7.new", old),
        ("account-1.4242-8.new", recent),
        ("account-1.lock", old),
        ("notes.txt", old),
        ("notes.1-2.new.txt", old),
    ];
    for (name, modified) in files {
        let file = File::create(scratch.join(name)).unwrap();
        file.set_modified(modified).unwrap();
    }

    scratch.open();
    assert_eq!(
        scratch.listing(),
        [
            "account-1.4242-8.new",
            "account-1.lock",
            "notes.1-2.new.txt",
            "notes.txt"
        ]
    );
}

#[test]
fn files_that_are_not_the_stores_are_left_alone() {
    let scratch = Scratch::new("foreign-files");
    let store = scratch.open();
    fs::write(scratch.join("notes.txt"), b"notes").unwrap();
    fs::write(scratch.join("account-1.bak"), b"backup").unwrap();

    let entry = name("account-1");
    let lock = store.lock(&entry, Duration::ZERO).unwrap();
    store.write(&entry, b"value").unwrap();
    read(&store, &entry);
    store.remove(&entry).unwrap();
    drop(lock);
    scratch.open();

    assert_eq!(
        scratch.listing(),
        ["account-1.bak", "account-1.lock", "notes.txt"]
    );
    assert_eq!(fs::read(scratch.join("notes.txt")).unwrap(), b"notes");
    assert_eq!(fs::read(scratch.join("account-1.bak")).unwrap(), b"backup");
}

#[test]
fn a_shared_store_is_a_store_and_its_users_exclude_each_other() {
    let shared = Arc::new(MemoryStore::new());
    let first: Box<dyn Store> = Box::new(Arc::clone(&shared));
    let second: Box<dyn Store> = Box::new(shared);
    let entry = EntryName::new("account-1").unwrap();

    first.write(&entry, b"synthetic").unwrap();
    assert_eq!(second.read(&entry).unwrap().unwrap().expose(), b"synthetic");

    let held = first.lock(&entry, Duration::ZERO).unwrap();
    let error = second.lock(&entry, Duration::ZERO).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::StoreBusy);
    drop(held);
    assert!(second.lock(&entry, Duration::ZERO).is_ok());
}

#[cfg(feature = "testing")]
mod conformance_suite {
    use std::fmt;
    use std::time::Duration;

    use siwc::store::{
        EntryName, KEY_LEN, KeyGeneration, Lock, MemoryStore, Sealed, SealingKey, Store, Stored,
        conformance,
    };
    use siwc::{Error, ErrorKind};

    use super::{Scratch, kind};

    #[derive(Debug)]
    struct FixedKey;

    impl SealingKey for FixedKey {
        fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
            Ok(KeyGeneration::new(0, None))
        }

        fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
            *key = [0x42; KEY_LEN];
            Ok(())
        }

        fn fill_retired(&self, _keys: &mut siwc::store::RetiredKeys<'_>) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn built_in_stores_pass_the_conformance_suite() {
        let memory = MemoryStore::new();
        let existing = EntryName::new("conformance-a").unwrap();
        memory.write(&existing, b"existing entry").unwrap();
        conformance::check(&memory).unwrap();
        assert_eq!(
            memory.read(&existing).unwrap().unwrap().expose(),
            b"existing entry"
        );

        let scratch_files = Scratch::new("conformance-files");
        conformance::check(&scratch_files.open()).unwrap();

        let scratch_sealed = Scratch::new("conformance-sealed");
        let sealed = Sealed::new(scratch_sealed.open(), FixedKey);
        conformance::check(&sealed).unwrap();
    }

    #[derive(Clone, Copy)]
    enum Defect {
        MissingNotNone,
        NonTruncatingWrite,
        LeakyDebug,
        DecimalDebug,
        HexDebug,
        StickyRemove,
        NonExclusiveLock,
        ImpatientLock,
    }

    struct BrokenStore {
        inner: MemoryStore,
        defect: Defect,
        last_written: std::sync::Mutex<Option<EntryName>>,
    }

    impl BrokenStore {
        fn new(defect: Defect) -> Self {
            Self {
                inner: MemoryStore::new(),
                defect,
                last_written: std::sync::Mutex::new(None),
            }
        }
    }

    impl fmt::Debug for BrokenStore {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let last = self.last_written.lock().unwrap().clone();
            let Some(Ok(Some(stored))) = last.map(|entry| self.inner.read(&entry)) else {
                return f.write_str("BrokenStore");
            };
            match self.defect {
                Defect::LeakyDebug => write!(
                    f,
                    "BrokenStore({:?})",
                    String::from_utf8_lossy(stored.expose())
                ),
                // What a derived `Debug` over a `Vec<u8>` prints.
                Defect::DecimalDebug => write!(f, "BrokenStore {{ last: {:?} }}", stored.expose()),
                Defect::HexDebug => {
                    let hex: String = stored.expose().iter().map(|b| format!("{b:02x}")).collect();
                    write!(f, "BrokenStore({hex})")
                }
                _ => f.write_str("BrokenStore"),
            }
        }
    }

    impl Store for BrokenStore {
        fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
            if matches!(self.defect, Defect::MissingNotNone) && entry.as_str().ends_with("-missing")
            {
                return Ok(Some(Stored::new(Vec::new())));
            }
            self.inner.read(entry)
        }

        fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
            *self.last_written.lock().unwrap() = Some(entry.clone());
            if matches!(self.defect, Defect::NonTruncatingWrite)
                && let Some(prev) = self.inner.read(entry)?
                && prev.expose().len() > value.len()
            {
                let mut merged = prev.expose().to_vec();
                merged[..value.len()].copy_from_slice(value);
                return self.inner.write(entry, &merged);
            }
            self.inner.write(entry, value)
        }

        fn remove(&self, entry: &EntryName) -> Result<(), Error> {
            if matches!(self.defect, Defect::StickyRemove) && entry.as_str().ends_with("-a") {
                return Ok(());
            }
            self.inner.remove(entry)
        }

        fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
            match self.defect {
                Defect::NonExclusiveLock => Ok(Lock::new(())),
                Defect::ImpatientLock => self.inner.lock(entry, Duration::ZERO),
                _ => self.inner.lock(entry, patience),
            }
        }
    }

    #[test]
    fn conformance_suite_rejects_broken_store_adapters() {
        for defect in [
            Defect::MissingNotNone,
            Defect::NonTruncatingWrite,
            Defect::LeakyDebug,
            Defect::DecimalDebug,
            Defect::HexDebug,
            Defect::StickyRemove,
            Defect::NonExclusiveLock,
            Defect::ImpatientLock,
        ] {
            let store = BrokenStore::new(defect);
            assert_eq!(kind(conformance::check(&store)), ErrorKind::StoreCorrupt);
        }
    }
}

#[test]
fn open_app_dir_validates_names_before_touching_the_filesystem() {
    for bad in ["", "../escape", "sub/dir", "sub\\dir", "con", ".hidden"] {
        assert_eq!(
            kind(PrivateFiles::open_app_dir(bad)),
            ErrorKind::InvalidInput,
            "{bad}"
        );
    }
}
