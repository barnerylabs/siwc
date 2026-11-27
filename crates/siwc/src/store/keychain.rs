//! A sealing key kept in the system keychain.

mod activation;
mod coordination;
mod deadline;
#[cfg(unix)]
mod helper;
mod key_text;
mod material;
mod reset_keys;
#[cfg(any(target_os = "macos", test))]
mod security_scope;
mod service;
mod start_over;
mod state;
#[cfg(test)]
#[cfg(all(target_os = "linux", feature = "testing"))]
mod timing_tests;

#[cfg(target_os = "macos")]
#[path = "keychain/security.rs"]
mod platform;

#[cfg(all(unix, not(target_os = "macos")))]
#[path = "keychain/secret_tool.rs"]
mod platform;

#[cfg(windows)]
#[path = "keychain/credential_manager.rs"]
mod platform;

#[cfg(not(any(unix, windows)))]
#[path = "keychain/unsupported.rs"]
mod platform;

use std::time::Duration;

use crate::cancel::Canceller;
use crate::error::{Error, ErrorKind};

#[cfg(unix)]
use super::reading;
use super::{MAX_RETIRED_KEYS, PrivateFiles, Sealed};

use material::Backend;
use service::ServiceName;

pub(in crate::store) use coordination::ValidatedResetLock;
pub(in crate::store) use reset_keys::ResetKeys;
pub(super) use reset_keys::ResetSince;

/// The account the key is stored under, beside the app's service name.
const ACCOUNT: &str = "sealing-key";

/// The lock file in the store's directory that lets one process create the key
/// when two meet its first use at once. Prefixed with `.` so it never collides
/// with a caller's [`EntryName`].
const KEY_LOCK_FILE: &str = ".sealing-key.lock";

/// Excludes an approved reset from publishing a renewal's successor.
const RESET_LOCK_FILE: &str = ".sealing-key.reset.lock";

/// How long a process waits for the key lock or for one keychain helper,
/// including time for the user to unlock the keychain.
const KEY_PATIENCE: Duration = Duration::from_secs(60);

/// Default lock patience used by [`Keychain::open_sealed`] when sealing plain
/// entries already in the directory.
const SEAL_EXISTING_PATIENCE: Duration = Duration::from_secs(10);

/// A [`SealingKey`](super::SealingKey) in the system keychain: a random key, made on first use
/// and stored as 64 hex digits under the app's service name and the
/// account `sealing-key`.
///
/// It needs the `keychain` feature. The keychain is the platform's own:
///
/// - **macOS:** the user's default keychain, through `/usr/bin/security`
///   with that keychain's path, so a key is read from the keychain it was
///   added to. An item that only another keychain in the search list holds
///   fails the call with [`ErrorKind::Store`] instead of counting as
///   missing; a keychain outside the search list is not looked at. A
///   default keychain whose path contains whitespace, quotes or a
///   backslash cannot take a new key. The item trusts that program rather
///   than the app, so a rebuilt or updated app reads it without a prompt
///   while the keychain is unlocked, as it is in a desktop session. When
///   the keychain is locked, as is common over SSH, the call fails without
///   asking.
/// - **Linux and other Unix systems:** the Secret Service of GNOME Keyring
///   or KWallet, through `secret-tool` from libsecret. A desktop session
///   unlocks it at login; without a Secret Service the call fails. An item
///   in a collection that stays locked fails the call with
///   [`ErrorKind::Store`] (`the keychain is locked`) instead of counting
///   as missing.
/// - **Windows:** the Credential Manager, as a generic credential named
///   `sealing-key.<service>` that stays on this computer and does not roam
///   with the profile. Reading it never asks the user.
///
/// The key goes to the tools on their standard input, never on a command
/// line. A key that was read is checked to be 64 hex digits; anything else
/// in the item fails the call and is left as it is, since replacing it
/// could lose the accounts sealed under it. A new key is read back before
/// it is used, so a keychain that reports success without storing cannot
/// leave values sealed under a key nobody has.
///
/// On Unix each helper invocation has 60 seconds. On expiry it is killed
/// and reaped, and the call returns [`ErrorKind::Store`]. No key is used
/// after a timed-out creation; the next call looks it up again.
/// [`start_over`](Self::start_over) uses a shorter, shared deadline.
///
/// The item counts as missing only when the keychain shows it absent: on
/// Linux a search of the Secret Service lists no item, on macOS neither the
/// default keychain nor the search list has one. This holds for the active
/// and the retired keys, for key creation and for
/// [`start_over`](Self::start_over).
///
/// If the keychain reports the item missing and the directory holds sealed
/// entries, a new key is created only if a retired key opens at least one
/// sealed entry. Otherwise the call fails with
/// [`ErrorKind::SealingKeyMissing`] and leaves the keychain and the entries
/// alone; [`start_over`](Self::start_over) is the way out once the user
/// agrees that the key is gone. A write crossing an approved reset can
/// also create a replacement if the reset cleared all sealed entries
/// and its previous key opens every sealed entry left by in-flight writes.
/// If the active item exists but neither it nor a retired key opens an
/// entry, that read normally fails with [`ErrorKind::StoreCorrupt`]. If
/// the recorded service is neither the one configured nor a retired one,
/// the read returns [`ErrorKind::InvalidInput`] and the old release cannot
/// sign the account out.
///
/// The store directory records a new service once its key is read back.
/// A directory without a marker records an existing key's service if it
/// has no sealed entries or if the key opens one.
/// Over sealed entries, creating a key for a different service or starting
/// over under that service requires listing the recorded service with
/// [`with_retired`](Self::with_retired); otherwise the call returns
/// [`ErrorKind::InvalidInput`]. An older release can still read entries that
/// open under its own key. Keep its service in the new release's retired
/// list until the old processes have stopped and their entries are resealed.
///
/// A generation file invalidates cached keys across processes before a
/// reset looks up any keys. A key load first checks that the reset lock
/// file is private, without taking the lock. When the generation is
/// unchanged, cached writes touch neither the key lock nor the reset lock.
/// A crossing write waits for a concurrent key replacement within the
/// three-minute write budget, then reads its replacement. It can use the
/// cached key when that lookup fails or the budget expires without a reset
/// clearing it. After a reset that checked the keys, the
/// cached key must have been readable and a readable key must still open
/// the entry; otherwise the write reloads. An earlier read or client
/// operation can still hold a copy of an entry from before the reset.
/// A clean timeout before removal records an abort if the previous reset was
/// settled. An incomplete reset without an inventory can keep the cached
/// active key when the entry still opens under any cached active or retired
/// key; earlier completed clears still apply. An inventory that found the
/// active key missing requires a reload, even after a later reset times out.
///
/// The locks needed by a crossing write share a three-minute wait limit.
/// This gives a running reset time beyond its 30-second planning budget
/// to finish removing entries. Expiry returns [`ErrorKind::Store`] with
/// `the sealing key write lock timed out`. A holder that exceeds the limit
/// can still prevent storing a successor after its refresh token was spent.
/// The limit is for lock contention; synchronous filesystem calls and
/// the keychain lookup itself have their own timing.
///
/// Any program that runs as the same user can read the item, as it can
/// read the files.
///
/// ```no_run
/// use siwc::store::{Keychain, PrivateFiles, Sealed};
///
/// let files = PrivateFiles::open("/Users/alex/Library/Application Support/paste-perfect")?;
/// let key = Keychain::new("com.example.paste-perfect", &files)?;
/// let store = Sealed::new(files, key);
/// # Ok::<(), siwc::Error>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "keychain")))]
#[derive(Clone)]
pub struct Keychain {
    service: ServiceName,
    retired: Vec<ServiceName>,
    /// The store's directory, where the key lock and sealed entries live.
    files: PrivateFiles,
    #[cfg(all(test, target_os = "linux", feature = "testing"))]
    timing: Option<timing_tests::Timing>,
}

impl std::fmt::Debug for Keychain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keychain")
            .field("service", &self.service.as_str())
            .field("retired_count", &self.retired.len())
            .finish_non_exhaustive()
    }
}

impl Keychain {
    fn key_lock(&self, stop: Option<&Canceller>) -> Result<super::Lock<'_>, Error> {
        let patience = KEY_PATIENCE;
        #[cfg(all(test, target_os = "linux", feature = "testing"))]
        let patience = self
            .timing
            .as_ref()
            .map_or(patience, |timing| timing.patience);
        self.files.lock_file(KEY_LOCK_FILE, patience, stop)
    }

    /// The key stored under `service`, created on first use if the store
    /// directory has no sealed entries, while its `.sealing-key.lock` is
    /// held. Pass the directory that will hold the sealed entries so they
    /// can be checked before key creation. On a plan request's
    /// thread, cancellation ends the wait for this lock and, on Unix, a
    /// read-only lookup stops and reaps its helper before releasing the lock.
    /// Cancellation leaves a key creation that has begun to finish and
    /// read its result back, subject to the per-helper deadline. Nothing
    /// is read when the key source is built.
    ///
    /// `service` names the keychain item: 1 to 128 ASCII letters, digits,
    /// `.`, `_` and `-`, starting with a letter or digit, such as the app's
    /// bundle identifier. It has to stay the same across releases, unless the
    /// app rotates to a new service name and lists the previous one with
    /// [`with_retired`](Self::with_retired).
    /// All processes opening a given service must use the same lock
    /// directory. Give each profile its own service, distinct even ignoring ASCII case.
    ///
    /// ```no_run
    /// let files = siwc::store::PrivateFiles::open_app_dir("example-desktop")?;
    /// let key = siwc::store::Keychain::new("com.example.desktop", &files)?;
    /// let store = siwc::store::Sealed::new(files, key);
    /// # drop(store);
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when `service` breaks the rule.
    pub fn new(service: &str, files: &PrivateFiles) -> Result<Self, Error> {
        Ok(Self {
            service: ServiceName::new(service)?,
            retired: Vec::new(),
            files: files.clone(),
            #[cfg(all(test, target_os = "linux", feature = "testing"))]
            timing: None,
        })
    }

    /// Opens [`PrivateFiles::open_app_dir`]`(app_dir)` wrapped in [`Sealed`]
    /// with a sealing key stored in the OS keychain under `service`, sealing
    /// plain `installation` and `account-*` entries already in the directory
    /// ([`Sealed::seal_existing`]).
    ///
    /// This is the recommended one-line store setup for desktop and local CLI
    /// applications when the `keychain` feature is enabled.
    ///
    /// Because every open seals plain client entries, a plain account
    /// entry that someone writes into the directory is sealed on the next
    /// open and then read like any other. An older sealed entry copied back
    /// into the directory opens too. The keychain key keeps entries
    /// unreadable to others; it does not tell the app who wrote an entry or
    /// whether it is current.
    /// [`SECURITY.md`](https://github.com/barnerylabs/siwc/blob/v0.1.0/SECURITY.md)
    /// places a writer to the user's files out of scope.
    ///
    /// ```no_run
    /// use siwc::store::Keychain;
    ///
    /// let store = Keychain::open_sealed("com.example.paste-perfect", "paste-perfect")?;
    /// # drop(store);
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when `service` or `app_dir` breaks its
    /// naming rule, plus the errors of [`PrivateFiles::open_app_dir`] and
    /// [`Sealed::seal_existing`].
    #[cfg_attr(docsrs, doc(cfg(feature = "keychain")))]
    pub fn open_sealed(service: &str, app_dir: &str) -> Result<Sealed<PrivateFiles, Self>, Error> {
        let service = ServiceName::new(service)?;
        let files = PrivateFiles::open_app_dir(app_dir)?;
        let keychain = Self {
            service,
            retired: Vec::new(),
            files: files.clone(),
            #[cfg(all(test, target_os = "linux", feature = "testing"))]
            timing: None,
        };
        let sealed = Sealed::new(files, keychain);
        sealed.seal_existing(SEAL_EXISTING_PATIENCE)?;
        Ok(sealed)
    }

    /// Accepts a previous `service` name as a retired key for opening entries
    /// before or during [`Sealed::reseal`](super::Sealed::reseal).
    /// Active and retired service names must differ even when ASCII case is ignored.
    /// Use distinct names under the same rule for separate Windows profiles.
    /// Keep it listed until processes using it have stopped and their entries
    /// have been resealed.
    ///
    /// A retired item is only read, never created: when it is absent from the
    /// keychain it is skipped, and when it holds text that is no key the read
    /// fails instead of ignoring it. At most [`MAX_RETIRED_KEYS`] retired
    /// services may be listed. When there are sealed entries, a missing
    /// active key is created only if a retired key opens at least one
    /// sealed entry under the same keychain lock.
    ///
    /// ```no_run
    /// use std::time::Duration;
    ///
    /// use siwc::store::{Keychain, PrivateFiles, Sealed};
    ///
    /// let files = PrivateFiles::open("/Users/alex/Library/Application Support/paste-perfect")?;
    /// let key = Keychain::new("com.example.paste-perfect.v2", &files)?
    ///     .with_retired("com.example.paste-perfect")?;
    /// let store = Sealed::new(files, key);
    /// store.reseal(Duration::from_secs(10))?;
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when `service` breaks the service-name
    /// rule, repeats the active or an already listed retired service, or
    /// exceeds [`MAX_RETIRED_KEYS`].
    pub fn with_retired(mut self, service: &str) -> Result<Self, Error> {
        if self.retired.len() >= MAX_RETIRED_KEYS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "too many retired sealing keys",
            ));
        }
        let retired = ServiceName::new(service)?;
        if retired == self.service || self.retired.contains(&retired) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "a retired keychain service repeats an existing service",
            ));
        }
        self.retired.push(retired);
        Ok(self)
    }
    #[cfg(unix)]
    fn platform_tool(&self) -> helper::Tool<'_> {
        let program = platform::PROGRAM.as_ref();
        #[cfg(all(test, target_os = "linux", feature = "testing"))]
        let program = self
            .timing
            .as_ref()
            .map_or(program, |timing| timing.program.as_os_str());
        helper::Tool::new(program)
    }

    #[cfg(not(unix))]
    fn platform_tool(&self) -> platform::Tool {
        platform::Tool
    }
}

/// A keychain tool that could not be started or failed.
fn tool_failed() -> Error {
    Error::new(ErrorKind::Store, "the keychain could not be used")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use zeroize::Zeroizing;

    use crate::entropy::Entropy;
    use crate::store::{KEY_LEN, RetiredKeys, reading};

    use super::material::{Lookup, fill_from, fill_retired_from};
    use super::*;

    /// A keychain in memory that can be told to lose what it is given.
    #[derive(Default)]
    struct Fake {
        item: Mutex<Option<Vec<u8>>>,
        forgets: bool,
        adds: Mutex<usize>,
        cancel_on_add: Option<Canceller>,
    }

    impl Backend for Fake {
        fn find(
            &self,
            _: &ServiceName,
            lookup: Lookup<'_>,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
            if lookup.stop.is_some_and(Canceller::is_cancelled) {
                return Err(reading::cancelled());
            }
            Ok(self.item.lock().unwrap().clone().map(Zeroizing::new))
        }

        fn add(&self, _: &ServiceName, text: &[u8]) -> Result<(), Error> {
            *self.adds.lock().unwrap() += 1;
            if !self.forgets {
                *self.item.lock().unwrap() = Some(text.to_vec());
            }
            if let Some(stop) = &self.cancel_on_add {
                stop.cancel();
            }
            Ok(())
        }
    }

    /// Entropy that fills every byte with one value.
    struct Repeated(u8);

    impl Entropy for Repeated {
        fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
            bytes.fill(self.0);
            Ok(())
        }
    }

    fn service() -> ServiceName {
        ServiceName::new("com.example.paste-perfect").unwrap()
    }

    #[test]
    fn a_missing_key_is_created_stored_and_then_read_on_every_later_fill() {
        let keychain = Fake::default();
        let mut first = [0; KEY_LEN];
        fill_from(
            &keychain,
            &service(),
            &Repeated(1),
            None,
            &mut first,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(first, [1; KEY_LEN]);
        assert_eq!(
            keychain.item.lock().unwrap().as_deref(),
            Some(key_text::encode(&first).as_slice())
        );

        let mut second = [0; KEY_LEN];
        fill_from(
            &keychain,
            &service(),
            &Repeated(2),
            None,
            &mut second,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(second, first);
        assert_eq!(*keychain.adds.lock().unwrap(), 1);
    }

    #[test]
    fn a_cancelled_lookup_does_not_start_creating_a_missing_key() {
        struct CancelOnFill(Canceller);

        impl Entropy for CancelOnFill {
            fn fill(&self, bytes: &mut [u8]) -> Result<(), Error> {
                bytes.fill(1);
                self.0.cancel();
                Ok(())
            }
        }

        let keychain = Fake::default();
        let stop = Canceller::new();
        let mut key = [0; KEY_LEN];
        let error = fill_from(
            &keychain,
            &service(),
            &CancelOnFill(stop.clone()),
            Some(&stop),
            &mut key,
            || Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert_eq!(*keychain.adds.lock().unwrap(), 0);
        assert_eq!(key, [0; KEY_LEN]);
    }

    #[test]
    fn a_started_key_creation_is_verified_even_if_cancelled() {
        let stop = Canceller::new();
        let keychain = Fake {
            cancel_on_add: Some(stop.clone()),
            ..Fake::default()
        };
        let mut key = [0; KEY_LEN];
        fill_from(
            &keychain,
            &service(),
            &Repeated(1),
            Some(&stop),
            &mut key,
            || Ok(()),
        )
        .unwrap();
        assert!(stop.is_cancelled());
        assert_eq!(*keychain.adds.lock().unwrap(), 1);
        assert_eq!(key, [1; KEY_LEN]);
    }

    #[test]
    fn an_item_that_is_no_key_fails_and_is_left_as_it_is() {
        let keychain = Fake {
            item: Mutex::new(Some(b"not a key".to_vec())),
            ..Fake::default()
        };
        let mut key = [0; KEY_LEN];
        let error = fill_from(&keychain, &service(), &Repeated(1), None, &mut key, || {
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Store);
        assert_eq!(
            keychain.item.lock().unwrap().as_deref(),
            Some(b"not a key".as_slice())
        );
        assert_eq!(*keychain.adds.lock().unwrap(), 0);
    }

    #[test]
    fn a_keychain_that_does_not_keep_the_new_key_fails_the_fill() {
        let keychain = Fake {
            forgets: true,
            ..Fake::default()
        };
        let mut key = [0; KEY_LEN];
        let error = fill_from(&keychain, &service(), &Repeated(1), None, &mut key, || {
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Store);
    }

    #[test]
    fn retired_services_read_existing_keys_skip_missing_ones_and_refuse_invalid_items() {
        use std::collections::HashMap;

        #[derive(Default)]
        struct Multi(Mutex<HashMap<String, Vec<u8>>>);

        impl Backend for Multi {
            fn find(
                &self,
                service: &ServiceName,
                _: Lookup<'_>,
            ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
                Ok(self
                    .0
                    .lock()
                    .unwrap()
                    .get(service.as_str())
                    .cloned()
                    .map(Zeroizing::new))
            }

            fn add(&self, service: &ServiceName, text: &[u8]) -> Result<(), Error> {
                self.0
                    .lock()
                    .unwrap()
                    .insert(service.as_str().to_owned(), text.to_vec());
                Ok(())
            }
        }

        let backend = Multi::default();
        let old = ServiceName::new("com.example.old").unwrap();
        let gone = ServiceName::new("com.example.gone").unwrap();
        let mut created = [0; KEY_LEN];
        fill_from(&backend, &old, &Repeated(0x3a), None, &mut created, || {
            Ok(())
        })
        .unwrap();

        let mut loaded = Vec::new();
        fill_retired_from(
            &backend,
            &[gone, old.clone()],
            Lookup::default(),
            &mut RetiredKeys::new(&mut loaded),
        )
        .unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(*loaded[0], [0x3a; KEY_LEN]);

        backend
            .0
            .lock()
            .unwrap()
            .insert(old.as_str().to_owned(), b"corrupt".to_vec());
        let mut broken = Vec::new();
        let error = fill_retired_from(
            &backend,
            &[old],
            Lookup::default(),
            &mut RetiredKeys::new(&mut broken),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Store);
        assert!(broken.is_empty());
    }

    #[test]
    fn retired_service_names_must_be_distinct_valid_and_bounded() {
        let dir = std::env::temp_dir().join(format!("siwc-kc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let files = PrivateFiles::open(&dir).unwrap();

        for retired in ["COM.EXAMPLE.APP", "COM.EXAMPLE.OLD"] {
            let error = Keychain::new("com.example.app", &files)
                .unwrap()
                .with_retired("com.example.old")
                .unwrap()
                .with_retired(retired)
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }

        let duplicate_active = Keychain::new("com.example.app", &files)
            .unwrap()
            .with_retired("com.example.app")
            .unwrap_err();
        assert_eq!(duplicate_active.kind(), ErrorKind::InvalidInput);

        let duplicate_retired = Keychain::new("com.example.app.v2", &files)
            .unwrap()
            .with_retired("com.example.app")
            .unwrap()
            .with_retired("com.example.app")
            .unwrap_err();
        assert_eq!(duplicate_retired.kind(), ErrorKind::InvalidInput);

        let bad_name = Keychain::new("com.example.app.v2", &files)
            .unwrap()
            .with_retired("-flag")
            .unwrap_err();
        assert_eq!(bad_name.kind(), ErrorKind::InvalidInput);

        let mut full = Keychain::new("com.example.active", &files).unwrap();
        assert!(format!("{full:?}").contains("com.example.active"));
        for index in 0..MAX_RETIRED_KEYS {
            full = full
                .with_retired(&format!("com.example.old.{index}"))
                .unwrap();
        }
        assert_eq!(
            full.with_retired("com.example.extra").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            Keychain::open_sealed("", "demo").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            Keychain::open_sealed("com.example.demo", "../bad")
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
