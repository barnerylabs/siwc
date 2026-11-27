//! Identifying store files in an app directory shared with other data.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read};

use zeroize::Zeroizing;

use super::{EntryName, Error, ErrorKind, PrivateFiles, failed};
use crate::store::sealed::envelope;

impl PrivateFiles {
    pub(in crate::store) fn entries(&self) -> Result<Vec<EntryName>, Error> {
        self.entries_checking(&|| Ok(()))
    }

    pub(in crate::store) fn entries_checking(
        &self,
        check: &impl Fn() -> Result<(), Error>,
    ) -> Result<Vec<EntryName>, Error> {
        check()?;
        self.check_dir()?;
        let listing = fs::read_dir(&self.dir).map_err(list_error)?;
        let mut canonical = HashSet::new();
        let mut variants = Vec::new();
        let mut entries = Vec::new();
        for item in listing {
            check()?;
            let item = item.map_err(list_error)?;
            let name = item.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(entry) = EntryName::new(&name.to_ascii_lowercase()) else {
                continue;
            };
            if name == entry.as_str() {
                canonical.insert(entry.clone());
                if is_store_file(&entry, &item)? {
                    entries.push(entry);
                }
            } else {
                variants.push((entry, item));
            }
        }
        for (variant, item) in variants {
            check()?;
            // A listed lowercase spelling is a distinct directory entry. Only
            // inspect the variant if the filesystem resolves a lowercase lookup.
            if !canonical.contains(&variant)
                && self.path(&variant).try_exists().map_err(list_error)?
                && is_store_file(&variant, &item)?
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "a store entry needs its canonical lowercase name",
                ));
            }
        }
        Ok(entries)
    }
}

fn is_store_file(entry: &EntryName, item: &fs::DirEntry) -> Result<bool, Error> {
    let kind = item.file_type().map_err(list_error)?;
    if entry.is_client_entry() {
        return Ok(!kind.is_dir());
    }
    Ok(kind.is_file() && has_envelope(item)?)
}

// Inspect only the format prefix. Unrelated files may be larger or have
// different permissions than store entries. The full store read checks both.
fn has_envelope(item: &fs::DirEntry) -> Result<bool, Error> {
    let mut file = match File::open(item.path()) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(list_error(error)),
    };
    let mut prefix = Zeroizing::new([0; envelope::MIN_ENVELOPE_LEN]);
    let mut used = 0;
    while used < prefix.len() {
        match file.read(&mut prefix[used..]) {
            Ok(0) => break,
            Ok(n) => used += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(list_error(error)),
        }
    }
    let prefix = &prefix[..used];
    Ok(envelope::is_sealed(prefix) || envelope::is_reserved(prefix))
}

fn list_error(_: io::Error) -> Error {
    failed("the store directory could not be read")
}
