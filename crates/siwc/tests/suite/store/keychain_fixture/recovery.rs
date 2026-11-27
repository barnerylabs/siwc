//! Recovery through independent sealed stores using the fake keychain.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use siwc::Error;
use siwc::store::{EntryName, Lock, SealingKey, Stored};

use super::*;

#[test]
fn a_forgetful_keychain_does_not_keep_creating_keys() {
    with_fake_tool(
        "recovery::a_forgetful_keychain_does_not_keep_creating_keys",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            let source = Keychain::new(SERVICE, &files).unwrap();
            fs::write(dir.join(format!("{SERVICE}.forget")), []).unwrap();

            let error = Sealed::new(files.clone(), source)
                .write(&entry, VALUE)
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Store);
            assert_eq!(
                error.to_string(),
                "the sealing key generation keeps changing"
            );
            let attempts = fs::read_to_string(dir.join("attempts")).unwrap();
            assert!((1..=3).contains(&attempts.trim().parse::<usize>().unwrap()));
            assert!(files.read(&entry).unwrap().is_none());
        },
    );
}

struct InterceptWrite<F> {
    files: PrivateFiles,
    once: Mutex<Option<F>>,
}

impl<F> std::fmt::Debug for InterceptWrite<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InterceptWrite")
    }
}

impl<F> Store for InterceptWrite<F>
where
    F: FnOnce(&PrivateFiles, &EntryName, &[u8]) -> Result<(), Error> + Send,
{
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        self.files.read(entry)
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        let hook = self.once.lock().unwrap().take();
        match hook {
            Some(hook) => hook(&self.files, entry, value),
            None => self.files.write(entry, value),
        }
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        self.files.remove(entry)
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        self.files.lock(entry, patience)
    }

    fn shared_across_processes(&self) -> bool {
        self.files.shared_across_processes()
    }
}

#[test]
fn a_write_published_after_a_crossing_reset_is_resealed() {
    with_fake_tool(
        "recovery::a_write_published_after_a_crossing_reset_is_resealed",
        |dir| {
            let store_dir = dir.join("store");
            let files = PrivateFiles::open(&store_dir).unwrap();
            let source = Keychain::new(SERVICE, &files).unwrap();
            let previous = name("account-1");
            let successor = name("account-2");
            let inner = Arc::new(InterceptWrite {
                files: files.clone(),
                once: Mutex::new(None),
            });
            let store = Sealed::new(Arc::clone(&inner), source.clone());
            store.write(&previous, VALUE).unwrap();
            fs::remove_file(dir.join(SERVICE)).unwrap();
            let resetting = source.clone();
            *inner.once.lock().unwrap() = Some(
                |files: &PrivateFiles, entry: &EntryName, ciphertext: &[u8]| {
                    let lock = fs::File::open(store_dir.join(".sealing-key.lock")).unwrap();
                    lock.try_lock()
                        .expect("publishing a sealed entry must not hold the key lock");
                    lock.unlock().unwrap();
                    assert!(resetting.start_over().unwrap());
                    assert!(!dir.join(SERVICE).exists());
                    files.write(entry, ciphertext)?;
                    let unrelated_reader = Sealed::new(files.clone(), resetting);
                    assert_eq!(
                        unrelated_reader.read(entry).unwrap_err().kind(),
                        ErrorKind::SealingKeyMissing
                    );
                    Ok(())
                },
            );

            // The reset leaves no replacement key and completes before
            // the old ciphertext reaches disk. A retry must not mistake
            // that ciphertext for an entry the user never agreed to lose.
            store.write(&successor, b"renewed session").unwrap();
            assert!(files.read(&previous).unwrap().is_none());
            let cold = Sealed::new(files, source);
            assert_eq!(
                cold.read(&successor).unwrap().unwrap().expose(),
                b"renewed session"
            );
        },
    );
}

#[test]
fn a_write_during_the_reset_lookup_is_resealed() {
    with_fake_tool(
        "recovery::a_write_during_the_reset_lookup_is_resealed",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let source = Keychain::new(SERVICE, &files).unwrap();
            let entry = name("account-1");
            let inner = Arc::new(InterceptWrite {
                files: files.clone(),
                once: Mutex::new(None),
            });
            let store = Sealed::new(Arc::clone(&inner), source.clone());
            store.write(&entry, VALUE).unwrap();
            fs::remove_file(dir.join(SERVICE)).unwrap();

            let generation = source.lock_generation().unwrap().number();
            let resetting = source.clone();
            *inner.once.lock().unwrap() = Some(
                |files: &PrivateFiles, entry: &EntryName, ciphertext: &[u8]| {
                    let gate = dir.join("pause-lookup");
                    let started = dir.join("lookup-started");
                    assert!(
                        Command::new("/bin/mkfifo")
                            .arg(&gate)
                            .status()
                            .unwrap()
                            .success()
                    );
                    let mut resume = fs::File::options()
                        .read(true)
                        .write(true)
                        .open(gate)
                        .unwrap();
                    let reset = thread::spawn(move || resetting.start_over());
                    let waiting_since = Instant::now();
                    while !started.exists() {
                        assert!(
                            !reset.is_finished()
                                && waiting_since.elapsed() < super::super::PATIENCE,
                            "the reset lookup did not start"
                        );
                        thread::yield_now();
                    }

                    // The first ciphertext uses the cached key. Publish it while
                    // reset is still looking up keys, then let reset remove it.
                    let during_lookup = source.lock_generation();
                    let published = files.write(entry, ciphertext);
                    resume.write_all(b"\n").unwrap();
                    assert!(reset.join().unwrap().unwrap());
                    assert!(files.read(entry).unwrap().is_none());
                    assert_ne!(
                        during_lookup?.number(),
                        generation,
                        "reset must invalidate caches before lookup"
                    );
                    published
                },
            );

            store.write(&entry, b"renewed during reset").unwrap();
            let cold = Sealed::new(files, source);
            assert_eq!(
                cold.read(&entry).unwrap().unwrap().expose(),
                b"renewed during reset"
            );
        },
    );
}

#[test]
fn warm_stores_pick_up_the_new_key_after_starting_over() {
    with_fake_tool(
        "recovery::warm_stores_pick_up_the_new_key_after_starting_over",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let shared_source = Arc::new(Keychain::new(SERVICE, &files).unwrap());
            let first = Sealed::new(files.clone(), Arc::clone(&shared_source));
            let second = Sealed::new(files.clone(), Arc::clone(&shared_source));
            let independent = Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap());
            let entry = name("account-1");
            first.write(&entry, VALUE).unwrap();
            assert_eq!(second.read(&entry).unwrap().unwrap().expose(), VALUE);
            assert_eq!(independent.read(&entry).unwrap().unwrap().expose(), VALUE);
            fs::remove_file(dir.join(SERVICE)).unwrap();

            let recovery = Keychain::new(SERVICE, &files).unwrap();
            let cold = Sealed::new(files.clone(), recovery.clone());
            assert_eq!(
                cold.read(&entry).unwrap_err().kind(),
                ErrorKind::SealingKeyMissing
            );
            assert!(recovery.start_over().unwrap());
            first.write(&entry, b"first new session").unwrap();
            assert_eq!(
                cold.read(&entry).unwrap().unwrap().expose(),
                b"first new session"
            );
            assert_eq!(
                independent.read(&entry).unwrap().unwrap().expose(),
                b"first new session"
            );
            second.write(&entry, b"second new session").unwrap();
            let reopened = Sealed::new(files, recovery);
            assert_eq!(
                reopened.read(&entry).unwrap().unwrap().expose(),
                b"second new session"
            );
        },
    );
}

#[test]
fn losing_the_active_key_after_rotation_does_not_create_another_one() {
    with_fake_tool(
        "recovery::losing_the_active_key_after_rotation_does_not_create_another_one",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap())
                .write(&entry, VALUE)
                .unwrap();
            let keychain = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(SERVICE)
                .unwrap();
            Sealed::new(files.clone(), keychain.clone())
                .reseal(Duration::ZERO)
                .unwrap();
            fs::remove_file(dir.join(ROTATED)).unwrap();
            let ciphertext = files.read(&entry).unwrap().unwrap();

            let cold = Sealed::new(files.clone(), keychain.clone());
            assert_eq!(
                cold.read(&entry).unwrap_err().kind(),
                ErrorKind::SealingKeyMissing
            );
            assert!(!dir.join(ROTATED).exists());
            assert_eq!(
                files.read(&entry).unwrap().unwrap().expose(),
                ciphertext.expose()
            );
            assert!(keychain.start_over().unwrap());
            assert!(cold.read(&entry).unwrap().is_none());
            cold.write(&entry, b"new session").unwrap();
            assert_eq!(cold.read(&entry).unwrap().unwrap().expose(), b"new session");
        },
    );
}

#[test]
fn starting_over_keeps_only_the_entries_that_are_plain_or_still_open() {
    with_fake_tool(
        "recovery::starting_over_keeps_only_the_entries_that_are_plain_or_still_open",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let retired = name("account-retired");
            let active = name("account-active");
            let unreadable = name("account-unreadable");
            let plain = name("plain");
            Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap())
                .write(&retired, VALUE)
                .unwrap();
            let keychain = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(SERVICE)
                .unwrap();
            let store = Sealed::new(files.clone(), keychain.clone());
            store.write(&active, VALUE).unwrap();
            store.write(&unreadable, VALUE).unwrap();
            let mut damaged = files.read(&unreadable).unwrap().unwrap().expose().to_vec();
            *damaged.last_mut().unwrap() ^= 1;
            files.write(&unreadable, &damaged).unwrap();
            files.write(&plain, VALUE).unwrap();

            assert!(keychain.start_over().unwrap());
            assert!(files.read(&unreadable).unwrap().is_none());
            assert_eq!(store.read(&retired).unwrap().unwrap().expose(), VALUE);
            assert_eq!(store.read(&active).unwrap().unwrap().expose(), VALUE);
            assert_eq!(files.read(&plain).unwrap().unwrap().expose(), VALUE);
            assert!(!keychain.start_over().unwrap());
        },
    );
}

#[test]
fn a_changed_service_requires_the_recorded_service_to_be_listed_as_retired() {
    with_fake_tool(
        "recovery::a_changed_service_requires_the_recorded_service_to_be_listed_as_retired",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            let original = Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap());
            original.write(&entry, VALUE).unwrap();
            let changed = Keychain::new(ROTATED, &files).unwrap();
            let mismatched = Sealed::new(files.clone(), changed.clone());

            let read_error = mismatched.read(&entry).unwrap_err();
            let reset_error = changed.start_over().err();
            assert_eq!(read_error.kind(), ErrorKind::InvalidInput);
            assert!(read_error.to_string().contains("with_retired"));
            let reset_error = reset_error.expect("a mismatched service must not discard entries");
            assert_eq!(reset_error.kind(), ErrorKind::InvalidInput);
            assert!(reset_error.to_string().contains("with_retired"));
            assert_eq!(original.read(&entry).unwrap().unwrap().expose(), VALUE);
            assert!(!dir.join(ROTATED).exists());

            // Data written before service markers has only its sealed entries.
            let legacy_files = PrivateFiles::open(dir.join("legacy")).unwrap();
            let ciphertext = files.read(&entry).unwrap().unwrap();
            legacy_files.write(&entry, ciphertext.expose()).unwrap();
            let legacy = Sealed::new(
                legacy_files.clone(),
                Keychain::new(ROTATED, &legacy_files).unwrap(),
            );
            assert_eq!(
                legacy.read(&entry).unwrap_err().kind(),
                ErrorKind::SealingKeyMissing
            );

            let rotating = changed.with_retired(SERVICE).unwrap();
            Sealed::new(files.clone(), rotating)
                .reseal(Duration::ZERO)
                .unwrap();
            let only_active = Sealed::new(files.clone(), Keychain::new(ROTATED, &files).unwrap());
            assert_eq!(only_active.read(&entry).unwrap().unwrap().expose(), VALUE);
        },
    );
}

#[test]
fn future_envelopes_block_key_creation_and_reset() {
    with_fake_tool(
        "recovery::future_envelopes_block_key_creation_and_reset",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("custom-entry");
            files.write(&entry, &[3; 64]).unwrap();
            let key = Keychain::new(SERVICE, &files).unwrap();
            assert_eq!(
                key.fill(&mut [0; 32]).unwrap_err().kind(),
                ErrorKind::StoreUnsupported
            );
            assert!(!dir.join(SERVICE).exists());
            assert_eq!(
                key.start_over().unwrap_err().kind(),
                ErrorKind::StoreUnsupported
            );
            assert_eq!(files.read(&entry).unwrap().unwrap().expose(), &[3; 64]);
        },
    );
}

#[test]
fn foreign_files_survive_migration_key_creation_rotation_and_reset() {
    with_fake_tool(
        "recovery::foreign_files_survive_migration_key_creation_rotation_and_reset",
        |dir| {
            let path = dir.join("store");
            let files = PrivateFiles::open(&path).unwrap();
            for (file, bytes) in [
                ("notes", b"{}".as_slice()),
                ("Preferences", b"{}"),
                ("history", b"text"),
            ] {
                fs::write(path.join(file), bytes).unwrap();
            }
            fs::create_dir(path.join("cache")).unwrap();
            let account = name("account-example");
            files.write(&account, b"{}").unwrap();
            let first = Keychain::new(SERVICE, &files).unwrap();
            let store = Sealed::new(files.clone(), first);
            store.seal_existing(Duration::ZERO).unwrap();
            assert_eq!(files.read(&account).unwrap().unwrap().expose()[0], 2);
            let custom = name("custom");
            store.write(&custom, VALUE).unwrap();
            let rotated = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(SERVICE)
                .unwrap();
            Sealed::new(files.clone(), rotated.clone())
                .reseal(Duration::ZERO)
                .unwrap();
            assert!(!rotated.start_over().unwrap());
            let fresh = Sealed::new(files.clone(), Keychain::new(ROTATED, &files).unwrap());
            assert_eq!(fresh.read(&custom).unwrap().unwrap().expose(), VALUE);
            assert_eq!(fresh.read(&account).unwrap().unwrap().expose(), b"{}");
            for (file, bytes) in [
                ("notes", b"{}".as_slice()),
                ("Preferences", b"{}"),
                ("history", b"text"),
            ] {
                assert_eq!(fs::read(path.join(file)).unwrap(), bytes);
                assert!(!path.join(format!("{file}.lock")).exists());
            }
            assert!(path.join("cache").is_dir());
        },
    );
}

#[test]
fn service_markers_follow_case_only_renames_for_active_and_retired_keys() {
    with_fake_tool(
        "recovery::service_markers_follow_case_only_renames_for_active_and_retired_keys",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-one");
            let original = Keychain::new(SERVICE, &files).unwrap();
            Sealed::new(files.clone(), original)
                .write(&entry, VALUE)
                .unwrap();
            // Model a keychain that resolves either spelling to the same item.
            let renamed = SERVICE.to_ascii_uppercase();
            fs::hard_link(dir.join(SERVICE), dir.join(&renamed)).unwrap();
            let active = Keychain::new(&renamed, &files).unwrap();
            assert!(!active.start_over().unwrap());
            assert_eq!(
                Sealed::new(files.clone(), active)
                    .read(&entry)
                    .unwrap()
                    .unwrap()
                    .expose(),
                VALUE
            );
            let rotated = Keychain::new(ROTATED, &files)
                .unwrap()
                .with_retired(&renamed)
                .unwrap();
            Sealed::new(files.clone(), rotated)
                .reseal(Duration::ZERO)
                .unwrap();
            assert_eq!(
                fs::read_to_string(dir.join("store").join(MARKER)).unwrap(),
                ROTATED
            );
        },
    );
}
