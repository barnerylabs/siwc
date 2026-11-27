//! A locked collection answers `lookup` exactly as for a missing item; only
//! a search that lists nothing proves the key is gone.

use super::*;

fn writes(dir: &Path) -> String {
    fs::read_to_string(dir.join("writes")).unwrap_or_default()
}

#[test]
fn a_locked_key_over_sealed_entries_fails_without_being_reported_missing() {
    with_fake_tool(
        "locked::a_locked_key_over_sealed_entries_fails_without_being_reported_missing",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            let keychain = Keychain::new(SERVICE, &files).unwrap();
            Sealed::new(files.clone(), keychain.clone())
                .write(&entry, VALUE)
                .unwrap();
            fs::write(dir.join("locked"), []).unwrap();

            let error = Sealed::new(files, keychain).read(&entry).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Store);
            assert_eq!(error.to_string(), "the keychain is locked");
        },
    );
}

#[test]
fn a_locked_key_is_not_replaced_when_the_directory_has_no_sealed_entries() {
    with_fake_tool(
        "locked::a_locked_key_is_not_replaced_when_the_directory_has_no_sealed_entries",
        |dir| {
            let key = b"synthetic-locked-key\n";
            fs::write(dir.join(SERVICE), key).unwrap();
            fs::write(dir.join("locked"), []).unwrap();
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let store = Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap());

            let error = store.write(&name("account-1"), VALUE).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Store);
            assert_eq!(writes(dir), "");
            assert_eq!(fs::read(dir.join(SERVICE)).unwrap(), key);
        },
    );
}

#[test]
fn an_approved_start_over_over_a_locked_key_deletes_nothing() {
    with_fake_tool(
        "locked::an_approved_start_over_over_a_locked_key_deletes_nothing",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            let keychain = Keychain::new(SERVICE, &files).unwrap();
            Sealed::new(files.clone(), keychain.clone())
                .write(&entry, VALUE)
                .unwrap();
            let sealed = files.read(&entry).unwrap().unwrap();
            let key = fs::read(dir.join(SERVICE)).unwrap();
            fs::write(dir.join("locked"), []).unwrap();

            assert_eq!(keychain.start_over().unwrap_err().kind(), ErrorKind::Store);
            assert_eq!(
                files.read(&entry).unwrap().unwrap().expose(),
                sealed.expose()
            );
            assert_eq!(fs::read(dir.join(SERVICE)).unwrap(), key);
            assert_eq!(writes(dir), format!("{SERVICE}\n"));

            fs::remove_file(dir.join("locked")).unwrap();
            let reopened = Sealed::new(files, keychain);
            assert_eq!(reopened.read(&entry).unwrap().unwrap().expose(), VALUE);
        },
    );
}

#[test]
fn a_failing_search_is_not_read_as_a_missing_key() {
    with_fake_tool(
        "locked::a_failing_search_is_not_read_as_a_missing_key",
        |dir| {
            let files = PrivateFiles::open(dir.join("store")).unwrap();
            let entry = name("account-1");
            files.write(&entry, VALUE).unwrap();
            fs::write(dir.join(format!("{SERVICE}.fail-search")), []).unwrap();
            let store = Sealed::new(files.clone(), Keychain::new(SERVICE, &files).unwrap());

            let error = store.seal_existing(Duration::ZERO).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Store);
            assert_eq!(error.to_string(), "the keychain could not be used");
            assert_eq!(writes(dir), "");
        },
    );
}
