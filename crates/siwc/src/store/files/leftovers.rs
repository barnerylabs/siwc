//! Temporary files that an interrupted write left behind.

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::error::{Error, ErrorKind};
use crate::store::name;

/// A temporary file older than this belongs to a write that is over. Long
/// enough for a writer that hangs in a sync on a slow file system or was
/// suspended in the middle; a leftover costs nothing but its bytes.
const LEFTOVER_AGE: Duration = Duration::from_secs(60 * 60);

/// Removes leftovers in `dir` that were last modified more than
/// [`LEFTOVER_AGE`] ago. Every other file stays untouched.
pub(super) fn sweep(dir: &Path) -> Result<(), Error> {
    let listing = fs::read_dir(dir)
        .map_err(|_| Error::new(ErrorKind::Store, "the store directory could not be listed"))?;
    let now = SystemTime::now();
    for item in listing.flatten() {
        let Some(name) = item.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_leftover(&name) {
            continue;
        }
        // `DirEntry::metadata` does not follow links; only plain files go.
        let Ok(metadata) = item.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        if metadata
            .modified()
            .is_ok_and(|modified| is_stale(modified, now))
        {
            // Best effort: a leftover that cannot go now is tried again on
            // the next open.
            let _ = fs::remove_file(item.path());
        }
    }
    Ok(())
}

/// Whether `name` has the shape `<entry>.<pid>-<counter>.new`.
fn is_leftover(name: &str) -> bool {
    let Some((stem, tag)) = name
        .strip_suffix(".new")
        .and_then(|rest| rest.split_once('.'))
    else {
        return false;
    };
    let number = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    name::is_valid(stem)
        && tag
            .split_once('-')
            .is_some_and(|(pid, n)| number(pid) && number(n))
}

/// Whether a file last modified at `modified` is old enough to be a
/// leftover. A time in the future is not.
fn is_stale(modified: SystemTime, now: SystemTime) -> bool {
    now.duration_since(modified)
        .is_ok_and(|age| age > LEFTOVER_AGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_files_named_like_a_temporary_entry_are_leftovers() {
        assert!(is_leftover("account-1.4242-7.new"));
        assert!(is_leftover("owner-probe.1-0.new"));
        for name in [
            "account-1",
            "account-1.lock",
            "account-1.new",
            "account-1.4242.new",
            "account-1.4242-.new",
            "account-1.-7.new",
            "account-1.42a-7.new",
            "Account.1-2.new",
            ".1-2.new",
            "notes.1-2.new.txt",
            "a.b.1-2.new",
        ] {
            assert!(!is_leftover(name), "{name}");
        }
    }

    #[test]
    fn a_leftover_is_stale_only_after_an_hour() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_000_000);
        assert!(!is_stale(now, now));
        assert!(!is_stale(now - LEFTOVER_AGE, now));
        assert!(is_stale(now - LEFTOVER_AGE - Duration::from_secs(1), now));
        assert!(!is_stale(now + Duration::from_secs(5), now));
    }
}
