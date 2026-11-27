//! A value a sealed store reads back, which anyone who can write the inner
//! store chose: it opens only as a value sealed for its entry.
#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use siwc::store::{EntryName, MemoryStore, Sealed, Store};
use siwc_fuzz::FixedKey;

/// A version byte, a 12-byte nonce and a 16-byte tag.
const OVERHEAD: usize = 1 + 12 + 16;

fuzz_target!(|held: &[u8]| {
    let inner = Arc::new(MemoryStore::new());
    let store = Sealed::new(Arc::clone(&inner), FixedKey);
    let entry = EntryName::new("account-1").expect("a valid entry name");
    inner
        .write(&entry, held)
        .expect("a memory store takes any value");
    if let Ok(Some(value)) = store.read(&entry) {
        assert_eq!(value.expose().len() + OVERHEAD, held.len());
        let other = EntryName::new("account-2").expect("a valid entry name");
        inner
            .write(&other, held)
            .expect("a memory store takes any value");
        assert_eq!(
            store.read(&other).unwrap_err().kind(),
            siwc::ErrorKind::StoreCorrupt
        );
    }
});
