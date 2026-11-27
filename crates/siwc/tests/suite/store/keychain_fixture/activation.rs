//! When an active service can be recorded in an existing store directory.

use super::*;

#[test]
fn a_failed_key_creation_leaves_the_original_service_usable() {
    with_fake_tool(
        "activation::a_failed_key_creation_leaves_the_original_service_usable",
        |dir| {
            for failure in ["fail-store", "fail-readback"] {
                let store_dir = dir.join(failure);
                let files = PrivateFiles::open(&store_dir).unwrap();
                let entry = name("account-1");
                let new_service = format!("{ROTATED}.{failure}");
                let original = Keychain::new(SERVICE, &files).unwrap();
                Sealed::new(files.clone(), original.clone())
                    .write(&entry, VALUE)
                    .unwrap();
                let ciphertext = files.read(&entry).unwrap().unwrap();
                let fault = dir.join(format!("{new_service}.{failure}"));
                fs::write(&fault, []).unwrap();
                let rotating = Keychain::new(&new_service, &files)
                    .unwrap()
                    .with_retired(SERVICE)
                    .unwrap();
                let rotated = Sealed::new(files.clone(), rotating);

                assert_eq!(
                    rotated.read(&entry).unwrap_err().kind(),
                    ErrorKind::Store,
                    "{failure}"
                );
                let reopened = Sealed::new(files.clone(), original.clone());
                let read = reopened.read(&entry);
                assert!(
                    read.is_ok(),
                    "the original service must still work after {failure}: {read:?}"
                );
                assert_eq!(read.unwrap().unwrap().expose(), VALUE);
                assert_eq!(fs::read_to_string(store_dir.join(MARKER)).unwrap(), SERVICE);
                assert!(!original.start_over().unwrap());
                assert_eq!(
                    files.read(&entry).unwrap().unwrap().expose(),
                    ciphertext.expose()
                );

                fs::remove_file(fault).unwrap();
                rotated.reseal(Duration::ZERO).unwrap();
                assert_eq!(
                    fs::read_to_string(store_dir.join(MARKER)).unwrap(),
                    new_service
                );
            }
        },
    );
}

#[test]
fn an_existing_key_records_its_service_in_a_recreated_directory() {
    with_fake_tool(
        "activation::an_existing_key_records_its_service_in_a_recreated_directory",
        |dir| {
            let store_dir = dir.join("store");
            let entry = name("account-1");
            let write = || {
                let files = PrivateFiles::open(&store_dir).unwrap();
                let source = Keychain::new(SERVICE, &files).unwrap();
                Sealed::new(files, source).write(&entry, VALUE).unwrap();
            };
            write();
            fs::remove_dir_all(&store_dir).unwrap();
            write();
            assert_eq!(
                fs::read_to_string(dir.join("writes")).unwrap(),
                format!("{SERVICE}\n")
            );
            let files = PrivateFiles::open(&store_dir).unwrap();
            let renamed = Keychain::new(ROTATED, &files).unwrap();

            assert_eq!(
                Sealed::new(files.clone(), renamed.clone())
                    .read(&entry)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidInput
            );
            assert_eq!(
                renamed.start_over().unwrap_err().kind(),
                ErrorKind::InvalidInput
            );
            assert_eq!(fs::read_to_string(store_dir.join(MARKER)).unwrap(), SERVICE);
            let original = Keychain::new(SERVICE, &files).unwrap();
            assert_eq!(
                Sealed::new(files, original)
                    .read(&entry)
                    .unwrap()
                    .unwrap()
                    .expose(),
                VALUE
            );
        },
    );
}

#[test]
fn an_existing_key_marks_a_legacy_directory_only_if_it_opens_an_entry() {
    with_fake_tool(
        "activation::an_existing_key_marks_a_legacy_directory_only_if_it_opens_an_entry",
        |dir| {
            let store_dir = dir.join("legacy");
            let files = PrivateFiles::open(&store_dir).unwrap();
            let entry = name("account-1");
            let original = Keychain::new(SERVICE, &files).unwrap();
            Sealed::new(files.clone(), original.clone())
                .write(&entry, VALUE)
                .unwrap();
            fs::remove_file(store_dir.join(MARKER)).unwrap();
            fs::write(dir.join(ROTATED), "23".repeat(32)).unwrap();

            let wrong = Keychain::new(ROTATED, &files).unwrap();
            assert_eq!(
                Sealed::new(files.clone(), wrong)
                    .read(&entry)
                    .unwrap_err()
                    .kind(),
                ErrorKind::StoreCorrupt
            );
            assert!(!store_dir.join(MARKER).exists());

            assert_eq!(
                Sealed::new(files, original)
                    .read(&entry)
                    .unwrap()
                    .unwrap()
                    .expose(),
                VALUE
            );
            assert_eq!(fs::read_to_string(store_dir.join(MARKER)).unwrap(), SERVICE);
        },
    );
}
