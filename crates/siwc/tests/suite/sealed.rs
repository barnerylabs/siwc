//! `Sealed`: values reach the inner store encrypted for their entry, and
//! anything that was not sealed for that entry under that key is refused.
//! The inner store is a `MemoryStore` behind an `Arc`, so a test can read
//! and change what it holds.

#[path = "sealed/retired_wait.rs"]
mod retired_wait;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use siwc::store::{
    EntryName, KEY_LEN, KeyGeneration, MAX_RETIRED_KEYS, MemoryStore, RetiredKeys, Sealed,
    SealingKey, Store,
};
use siwc::{Error, ErrorKind};

/// A synthetic value, long enough that a stray copy would be found.
const VALUE: &[u8] = b"synthetic-refresh-token-5c1e9b0d";

/// A version byte, a 12-byte nonce and a 16-byte tag.
const OVERHEAD: usize = 1 + 12 + 16;

/// A key of one repeated byte that counts how often it was fetched, and
/// fails while `failing` is set.
#[derive(Default)]
struct Key {
    byte: u8,
    fetched: AtomicUsize,
    failing: AtomicBool,
}

impl Key {
    fn of(byte: u8) -> Self {
        Self {
            byte,
            ..Self::default()
        }
    }
}

impl SealingKey for Key {
    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(KeyGeneration::new(0, None))
    }

    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        self.fetched.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            return Err(Error::store_failed());
        }
        key.fill(self.byte);
        Ok(())
    }

    fn fill_retired(&self, _keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        Ok(())
    }
}

/// A borrowed key, so a test can count its fetches.
impl SealingKey for &Key {
    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(KeyGeneration::new(0, None))
    }

    fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        (**self).fill(key)
    }

    fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        (**self).fill_retired(keys)
    }
}

/// A sealed store over a memory store the test can reach.
fn sealed_store(byte: u8) -> (Sealed<Arc<MemoryStore>, Key>, Arc<MemoryStore>) {
    let inner = Arc::new(MemoryStore::new());
    (Sealed::new(Arc::clone(&inner), Key::of(byte)), inner)
}

fn name(text: &str) -> EntryName {
    EntryName::new(text).unwrap()
}

fn raw(store: &MemoryStore, entry: &EntryName) -> Vec<u8> {
    store.read(entry).unwrap().unwrap().expose().to_vec()
}

fn kind<T: std::fmt::Debug>(result: Result<T, Error>) -> ErrorKind {
    result.unwrap_err().kind()
}

#[test]
fn a_sealed_value_reads_back_until_it_is_removed() {
    let (store, _) = sealed_store(1);
    let entry = name("account-1");
    assert!(store.read(&entry).unwrap().is_none());

    for value in [VALUE, b"".as_slice()] {
        store.write(&entry, value).unwrap();
        assert_eq!(store.read(&entry).unwrap().unwrap().expose(), value);
    }
    store.remove(&entry).unwrap();
    assert!(store.read(&entry).unwrap().is_none());
}

#[test]
fn a_value_in_the_documented_format_opens() {
    // Version 1, the nonce 01..0c, then VALUE sealed with ChaCha20-Poly1305
    // under the key 0x5a * 32 with the associated data b"\x01account-1",
    // made with another implementation of the cipher.
    let sealed = "010102030405060708090a0b0c\
                  c19164c7ebec28bb8076be47cac53813f1e8aa10ec963c844487094eede51267\
                  573b433a306b1a1506b79363272c6c61";
    let bytes: Vec<u8> = (0..sealed.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&sealed[at..at + 2], 16).unwrap())
        .collect();
    let (store, inner) = sealed_store(0x5a);
    let entry = name("account-1");
    inner.write(&entry, &bytes).unwrap();

    assert_eq!(store.read(&entry).unwrap().unwrap().expose(), VALUE);
}

#[test]
fn the_inner_store_holds_the_value_sealed_and_never_in_plain() {
    let (store, inner) = sealed_store(1);
    let entry = name("account-1");
    store.write(&entry, VALUE).unwrap();

    let held = raw(&inner, &entry);
    assert_eq!(held.len(), VALUE.len() + OVERHEAD);
    assert_eq!(held[0], 1, "the format version comes first");
    // Not even eight bytes of the value appear in what the inner store holds.
    for part in VALUE.windows(8) {
        assert!(!held.windows(8).any(|window| window == part));
    }
}

#[test]
fn two_writes_of_the_same_value_differ() {
    let (store, inner) = sealed_store(1);
    let entry = name("account-1");
    store.write(&entry, VALUE).unwrap();
    let first = raw(&inner, &entry);
    store.write(&entry, VALUE).unwrap();
    let second = raw(&inner, &entry);

    assert_ne!(first[1..13], second[1..13], "each write draws a new nonce");
    assert_ne!(first[13..], second[13..]);
}

#[test]
fn a_changed_byte_anywhere_is_store_corrupt() {
    let (store, inner) = sealed_store(1);
    let entry = name("account-1");
    store.write(&entry, VALUE).unwrap();
    let held = raw(&inner, &entry);

    // The version byte, the nonce, the encrypted value and the tag.
    for at in 0..held.len() {
        let mut changed = held.clone();
        changed[at] ^= 0x01;
        inner.write(&entry, &changed).unwrap();
        assert_eq!(
            kind(store.read(&entry)),
            ErrorKind::StoreCorrupt,
            "byte {at}"
        );
    }
}

#[test]
fn a_value_copied_to_another_entry_does_not_open_there() {
    let (store, inner) = sealed_store(1);
    let first = name("account-1");
    let second = name("account-2");
    store.write(&first, VALUE).unwrap();
    inner.write(&second, &raw(&inner, &first)).unwrap();

    assert_eq!(kind(store.read(&second)), ErrorKind::StoreCorrupt);
    assert_eq!(store.read(&first).unwrap().unwrap().expose(), VALUE);
}

#[test]
fn a_value_sealed_under_another_key_does_not_open() {
    let inner = Arc::new(MemoryStore::new());
    let entry = name("account-1");
    Sealed::new(Arc::clone(&inner), Key::of(1))
        .write(&entry, VALUE)
        .unwrap();

    let other = Sealed::new(Arc::clone(&inner), Key::of(2));
    assert_eq!(kind(other.read(&entry)), ErrorKind::StoreCorrupt);
}

#[test]
fn a_value_of_an_unknown_version_does_not_open() {
    let (store, inner) = sealed_store(1);
    let entry = name("account-1");
    store.write(&entry, VALUE).unwrap();
    let mut held = raw(&inner, &entry);

    for (version, expected) in [
        (0, ErrorKind::StoreCorrupt),
        (3, ErrorKind::StoreUnsupported),
        (9, ErrorKind::StoreCorrupt),
        (0xff, ErrorKind::StoreCorrupt),
    ] {
        held[0] = version;
        inner.write(&entry, &held).unwrap();
        let error = store.read(&entry).unwrap_err();
        assert_eq!(error.kind(), expected);
    }
}

#[test]
fn a_coordinated_version_requires_keychain_generation_before_decryption() {
    let (store, inner) = sealed_store(1);
    let entry = name("account-1");
    store.write(&entry, VALUE).unwrap();
    let mut held = raw(&inner, &entry);
    held[0] = 2;
    inner.write(&entry, &held).unwrap();
    assert_eq!(kind(store.read(&entry)), ErrorKind::InvalidInput);
    inner.write(&entry, &[2]).unwrap();
    assert_eq!(kind(store.read(&entry)), ErrorKind::StoreCorrupt);
}

#[test]
fn a_value_too_short_to_be_sealed_does_not_open() {
    let (store, inner) = sealed_store(1);
    let entry = name("account-1");
    store.write(&entry, b"").unwrap();
    let held = raw(&inner, &entry);
    assert_eq!(held.len(), OVERHEAD);

    for len in 0..OVERHEAD {
        inner.write(&entry, &held[..len]).unwrap();
        assert_eq!(
            kind(store.read(&entry)),
            ErrorKind::StoreCorrupt,
            "{len} bytes"
        );
    }
}

#[test]
fn the_key_is_fetched_once_and_not_for_a_missing_entry() {
    let key = Key::of(1);
    let store = Sealed::new(MemoryStore::new(), &key);
    let entry = name("account-1");
    let _lock = store.lock(&entry, Duration::ZERO).unwrap();
    assert!(store.read(&entry).unwrap().is_none());
    store.remove(&entry).unwrap();
    assert_eq!(key.fetched.load(Ordering::SeqCst), 0);

    store.write(&entry, VALUE).unwrap();
    store.read(&entry).unwrap();
    store.write(&entry, VALUE).unwrap();
    assert_eq!(key.fetched.load(Ordering::SeqCst), 1);
}

#[test]
fn a_key_that_cannot_be_fetched_fails_the_call_and_is_asked_for_again() {
    let key = Key::of(1);
    key.failing.store(true, Ordering::SeqCst);
    let inner = Arc::new(MemoryStore::new());
    let store = Sealed::new(Arc::clone(&inner), &key);
    let entry = name("account-1");

    assert_eq!(kind(store.write(&entry, VALUE)), ErrorKind::Store);
    assert!(inner.read(&entry).unwrap().is_none(), "nothing was written");

    key.failing.store(false, Ordering::SeqCst);
    store.write(&entry, VALUE).unwrap();
    assert_eq!(key.fetched.load(Ordering::SeqCst), 2);
}

struct UnfilledKey;

impl SealingKey for UnfilledKey {
    fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
        Ok(KeyGeneration::new(0, None))
    }

    fn fill(&self, _: &mut [u8; KEY_LEN]) -> Result<(), Error> {
        Ok(())
    }

    fn fill_retired(&self, _keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
        Ok(())
    }
}

fn assert_zero_key_error(error: Error) {
    assert_eq!(error.kind(), ErrorKind::Store);
    assert_eq!(error.to_string(), "an all-zero sealing key is not allowed");
}

#[test]
fn an_unfilled_active_key_cannot_seal_an_entry() {
    let inner = Arc::new(MemoryStore::new());
    let store = Sealed::new(Arc::clone(&inner), UnfilledKey);
    let entry = name("account-1");

    assert_zero_key_error(store.write(&entry, VALUE).unwrap_err());
    assert!(inner.read(&entry).unwrap().is_none());
}

#[test]
fn an_unfilled_active_key_cannot_open_an_entry() {
    let (writer, inner) = sealed_store(1);
    let entry = name("account-1");
    writer.write(&entry, VALUE).unwrap();

    let reader = Sealed::new(inner, UnfilledKey);
    assert_zero_key_error(reader.read(&entry).unwrap_err());
}

#[test]
fn an_unfilled_retired_key_fails_the_read_before_any_retired_key_is_used() {
    struct RotatingKey;

    impl SealingKey for RotatingKey {
        fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
            Ok(KeyGeneration::new(0, None))
        }

        fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
            key.fill(2);
            Ok(())
        }

        fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
            keys.add(|_| Ok(()))?;
            keys.add(|old| {
                old.fill(1);
                Ok(())
            })
        }
    }

    let (writer, inner) = sealed_store(1);
    let entry = name("account-1");
    writer.write(&entry, VALUE).unwrap();

    let reader = Sealed::new(inner, RotatingKey);
    assert_zero_key_error(reader.read(&entry).unwrap_err());
}

#[test]
fn locks_and_sharing_are_the_inner_stores() {
    let (store, inner) = sealed_store(1);
    let entry = name("account-1");

    let held = inner.lock(&entry, Duration::ZERO).unwrap();
    assert_eq!(
        kind(store.lock(&entry, Duration::ZERO)),
        ErrorKind::StoreBusy
    );
    drop(held);
    assert!(store.lock(&entry, Duration::ZERO).is_ok());
    assert!(
        !store.shared_across_processes(),
        "a MemoryStore is not shared"
    );
}

#[test]
fn debug_output_shows_neither_key_nor_value() {
    let (store, _) = sealed_store(0x7a);
    let entry = name("account-1");
    store.write(&entry, VALUE).unwrap();
    let stored = store.read(&entry).unwrap().unwrap();

    assert_eq!(format!("{store:?}"), "Sealed { .. }");
    assert_eq!(format!("{stored:?}"), "Stored([redacted; 32 bytes])");
}

#[test]
fn retired_keys_open_existing_entries_without_being_asked_when_the_active_key_works() {
    struct Ring {
        active: u8,
        retired: Vec<u8>,
        retired_fetches: AtomicUsize,
    }

    impl SealingKey for &Ring {
        fn lock_generation(&self) -> Result<KeyGeneration<'_>, Error> {
            Ok(KeyGeneration::new(0, None))
        }

        fn fill(&self, key: &mut [u8; KEY_LEN]) -> Result<(), Error> {
            key.fill(self.active);
            Ok(())
        }

        fn fill_retired(&self, keys: &mut RetiredKeys<'_>) -> Result<(), Error> {
            self.retired_fetches.fetch_add(1, Ordering::SeqCst);
            for &byte in &self.retired {
                keys.add(|slot| {
                    slot.fill(byte);
                    Ok(())
                })?;
            }
            Ok(())
        }
    }

    let inner = Arc::new(MemoryStore::new());
    let old_entry = name("account-1");
    let new_entry = name("account-2");
    Sealed::new(Arc::clone(&inner), Key::of(0x11))
        .write(&old_entry, VALUE)
        .unwrap();

    let ring = Ring {
        active: 0x22,
        retired: vec![0x33, 0x11],
        retired_fetches: AtomicUsize::new(0),
    };
    let rotated = Sealed::new(Arc::clone(&inner), &ring);
    rotated.write(&new_entry, b"fresh").unwrap();
    assert_eq!(
        rotated.read(&new_entry).unwrap().unwrap().expose(),
        b"fresh"
    );
    assert_eq!(
        ring.retired_fetches.load(Ordering::SeqCst),
        0,
        "retired keys are untouched while the active key opens every read"
    );

    assert_eq!(rotated.read(&old_entry).unwrap().unwrap().expose(), VALUE);
    assert_eq!(ring.retired_fetches.load(Ordering::SeqCst), 1);

    // An unknown version never asks for retired keys.
    let fresh_ring = Ring {
        active: 0x22,
        retired: vec![0x11],
        retired_fetches: AtomicUsize::new(0),
    };
    let mut bad_version = raw(&inner, &new_entry);
    bad_version[0] = 3;
    inner.write(&new_entry, &bad_version).unwrap();
    assert_eq!(
        kind(Sealed::new(Arc::clone(&inner), &fresh_ring).read(&new_entry)),
        ErrorKind::StoreUnsupported
    );
    assert_eq!(fresh_ring.retired_fetches.load(Ordering::SeqCst), 0);

    // Adding more than MAX_RETIRED_KEYS fails with InvalidInput.
    let overflow = Ring {
        active: 0x22,
        retired: (1..=u8::try_from(MAX_RETIRED_KEYS + 1).unwrap()).collect(),
        retired_fetches: AtomicUsize::new(0),
    };
    assert_eq!(
        kind(Sealed::new(Arc::clone(&inner), &overflow).read(&old_entry)),
        ErrorKind::InvalidInput
    );
}
