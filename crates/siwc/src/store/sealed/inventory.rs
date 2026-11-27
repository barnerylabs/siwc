//! Finding sealed entries and checking whether a key still opens them.

use crate::error::Error;
use crate::store::{EntryName, PrivateFiles, Store, Stored};

use super::{KEY_LEN, envelope};

pub(in crate::store) fn entries(
    files: &PrivateFiles,
) -> Result<impl Iterator<Item = Result<(EntryName, Stored), Error>> + '_, Error> {
    entries_checking(files, || Ok(()))
}

pub(in crate::store) fn entries_checking(
    files: &PrivateFiles,
    check: impl Fn() -> Result<(), Error>,
) -> Result<impl Iterator<Item = Result<(EntryName, Stored), Error>>, Error> {
    Ok(files
        .entries_checking(&check)?
        .into_iter()
        .filter_map(move |entry| {
            if let Err(error) = check() {
                return Some(Err(error));
            }
            match files.read(&entry) {
                Ok(Some(stored)) => match envelope::check_version(stored.expose()) {
                    Err(error) => Some(Err(error)),
                    Ok(()) if envelope::is_sealed(stored.expose()) => Some(Ok((entry, stored))),
                    Ok(()) => None,
                },
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            }
        }))
}

pub(in crate::store) fn opens_with_any<'a>(
    entry: &EntryName,
    stored: &Stored,
    keys: impl IntoIterator<Item = &'a [u8; KEY_LEN]>,
) -> Result<bool, Error> {
    for key in keys {
        match envelope::open_checked(key, entry, stored.expose()) {
            Ok(_) => return Ok(true),
            Err(envelope::OpenFailure::WrongKey) => {}
            Err(envelope::OpenFailure::UnknownFormat) => return Ok(false),
            Err(failure) => return Err(failure.into_error()),
        }
    }
    Ok(false)
}
