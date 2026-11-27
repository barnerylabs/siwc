//! Writing private files, with atomic replacement for store entries.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime};

use crate::error::{Error, ErrorKind};

use super::privacy;

/// Numbers this process's temporary files, so two writes never share one.
static TEMPORARY: AtomicU64 = AtomicU64::new(0);

/// The time of the first write, so a process that comes back under the
/// same ID does not repeat the names of the one before it.
static FIRST_NUMBER: OnceLock<u64> = OnceLock::new();

/// Names tried before the write gives up on existing temporary files.
pub(super) const TEMPORARY_TRIES: usize = 16;

/// How long a replacement waits for a program that holds the destination.
const HELD_PATIENCE: Duration = Duration::from_secs(1);

/// The pause between two attempts while the destination is held.
const HELD_PAUSE: Duration = Duration::from_millis(20);

/// A `<dir>/<stem>.<pid>-<number>.new` no write of this process used before.
pub(super) fn temporary(dir: &Path, stem: &str) -> PathBuf {
    let first = *FIRST_NUMBER.get_or_init(|| {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|since| u64::try_from(since.as_nanos()).ok())
            .unwrap_or(0)
    });
    let number = first.wrapping_add(TEMPORARY.fetch_add(1, Ordering::Relaxed));
    dir.join(format!("{stem}.{}-{number}.new", process::id()))
}

/// Creates a file under the first free name from `next`, with owner-only
/// mode bits on Unix and inherited permissions on Windows.
pub(super) fn create_fresh(mut next: impl FnMut() -> PathBuf) -> io::Result<(File, PathBuf)> {
    let options = private_create_options();
    let mut taken = io::Error::from(io::ErrorKind::AlreadyExists);
    for _ in 0..TEMPORARY_TRIES {
        let path = next();
        match options.open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => taken = error,
            Err(error) => return Err(error),
        }
    }
    Err(taken)
}

fn private_create_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    privacy::owner_only(&mut options);
    options
}

fn write_temporary(dir: &Path, stem: &str, value: &[u8]) -> io::Result<PathBuf> {
    let (mut file, path) = create_fresh(|| temporary(dir, stem))?;
    let saved = file.write_all(value).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = saved {
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    Ok(path)
}

/// Replaces a file after syncing its bytes. The caller handles directory sync.
pub(super) fn replace(dir: &Path, stem: &str, path: &Path, value: &[u8]) -> io::Result<()> {
    let temporary = write_temporary(dir, stem, value)?;
    let renamed = retry_while_held(
        || fs::rename(&temporary, path),
        held_elsewhere,
        thread::sleep,
    );
    if let Err(error) = renamed {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

/// Whether the rename failed because another program holds the destination.
///
/// Windows refuses to replace a file that is open without delete sharing,
/// as backup, sync and scanning tools sometimes keep one for a moment, with
/// `ERROR_ACCESS_DENIED` (5) or `ERROR_SHARING_VIOLATION` (32). Readers in
/// this crate open files through the standard library, which shares delete.
fn held_elsewhere(error: &io::Error) -> bool {
    cfg!(windows) && matches!(error.raw_os_error(), Some(5 | 32))
}

/// Runs `attempt` until it succeeds, fails another way or `HELD_PATIENCE`
/// has passed in pauses of `HELD_PAUSE`.
fn retry_while_held(
    mut attempt: impl FnMut() -> io::Result<()>,
    held: impl Fn(&io::Error) -> bool,
    mut pause: impl FnMut(Duration),
) -> io::Result<()> {
    let mut waited = Duration::ZERO;
    loop {
        match attempt() {
            Err(error) if held(&error) && waited < HELD_PATIENCE => {
                pause(HELD_PAUSE);
                waited += HELD_PAUSE;
            }
            result => return result,
        }
    }
}

/// Creates and syncs a file without replacing an existing destination.
pub(crate) fn write_new_file(path: &Path, value: &[u8]) -> Result<(), Error> {
    path.file_name()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "the destination must name a file"))?;
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = private_create_options().open(path).map_err(|error| {
        // Some platforms report another error for an existing directory.
        if error.kind() == io::ErrorKind::AlreadyExists || fs::symlink_metadata(path).is_ok() {
            Error::new(ErrorKind::InvalidInput, "the destination already exists")
        } else {
            Error::new(ErrorKind::Store, "the new file could not be written")
        }
    })?;
    let saved = file
        .write_all(value)
        .and_then(|()| file.sync_all())
        .map_err(|_| Error::new(ErrorKind::Store, "the new file could not be written"));
    drop(file);
    let synced = saved.and_then(|()| {
        privacy::sync_dir_if_supported(dir).map_err(|_| {
            Error::new(
                ErrorKind::Store,
                "the new file's directory could not be synced",
            )
        })
    });
    if synced.is_err() {
        let _ = fs::remove_file(path);
    }
    synced
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied() -> io::Error {
        io::Error::from(io::ErrorKind::PermissionDenied)
    }

    fn is_denied(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::PermissionDenied
    }

    #[test]
    fn a_replacement_waits_for_a_destination_held_for_a_moment() {
        let mut failures = 3;
        let mut paused = Vec::new();
        let result = retry_while_held(
            || {
                if failures == 0 {
                    return Ok(());
                }
                failures -= 1;
                Err(denied())
            },
            is_denied,
            |pause| paused.push(pause),
        );
        assert!(result.is_ok());
        assert_eq!(paused, [HELD_PAUSE; 3]);
    }

    #[test]
    fn a_replacement_gives_up_on_a_destination_held_for_good() {
        let mut attempts = 0;
        let mut waited = Duration::ZERO;
        let result = retry_while_held(
            || {
                attempts += 1;
                Err(denied())
            },
            is_denied,
            |pause| waited += pause,
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(waited, HELD_PATIENCE);
        assert_eq!(
            attempts,
            HELD_PATIENCE.as_millis() / HELD_PAUSE.as_millis() + 1
        );
    }

    #[test]
    fn a_replacement_does_not_retry_other_errors() {
        let mut attempts = 0;
        let mut paused = Vec::new();
        let result = retry_while_held(
            || {
                attempts += 1;
                Err(io::Error::from(io::ErrorKind::NotFound))
            },
            is_denied,
            |pause| paused.push(pause),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(attempts, 1);
        assert!(paused.is_empty());
    }

    #[test]
    fn only_windows_reads_a_rename_error_as_a_held_destination() {
        let access_denied = io::Error::from_raw_os_error(5);
        let sharing_violation = io::Error::from_raw_os_error(32);
        assert_eq!(held_elsewhere(&access_denied), cfg!(windows));
        assert_eq!(held_elsewhere(&sharing_violation), cfg!(windows));
        assert!(!held_elsewhere(&io::Error::from_raw_os_error(2)));
    }
}
