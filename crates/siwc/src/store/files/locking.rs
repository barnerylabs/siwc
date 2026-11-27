//! File locks for both entries and keychain coordination.

use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::cancel::Canceller;
use crate::error::Error;
use crate::store::{Lock, reading};

use super::{PrivateFiles, failed, privacy};

/// How long to wait between tries while another holder keeps the lock.
const LOCK_RETRY: Duration = Duration::from_millis(20);

impl PrivateFiles {
    /// Checks or creates a private lock file without waiting for its holder.
    #[cfg(feature = "keychain")]
    pub(in crate::store) fn check_lock_file(&self, file_name: &str) -> Result<(), Error> {
        self.open_lock_file(&self.dir.join(file_name)).map(drop)
    }

    #[cfg(feature = "keychain")]
    pub(in crate::store) fn checked_lock_handle(&self, file_name: &str) -> Result<File, Error> {
        self.open_lock_file(&self.dir.join(file_name))
            .map(|(file, _)| file)
    }

    /// Takes an exclusive lock on `file_name` inside the store directory, used
    /// both by [`Store::lock`](crate::store::Store::lock) and by crate-internal
    /// coordination locks whose names sit outside [`EntryName`](crate::store::EntryName).
    pub(in crate::store) fn lock_file(
        &self,
        file_name: &str,
        patience: Duration,
        stop: Option<&Canceller>,
    ) -> Result<Lock<'_>, Error> {
        self.lock_file_with(file_name, patience, stop, File::try_lock)
    }

    pub(super) fn lock_file_with(
        &self,
        file_name: &str,
        patience: Duration,
        stop: Option<&Canceller>,
        try_lock: impl Fn(&File) -> Result<(), TryLockError>,
    ) -> Result<Lock<'_>, Error> {
        let start = Instant::now();
        self.lock_file_polling(file_name, patience, stop, try_lock, || start.elapsed())
    }

    #[cfg(feature = "keychain")]
    pub(in crate::store) fn lock_file_timed(
        &self,
        file_name: &str,
        patience: Duration,
        stop: Option<&Canceller>,
        elapsed: impl Fn() -> Duration,
    ) -> Result<Lock<'_>, Error> {
        self.lock_file_polling(file_name, patience, stop, File::try_lock, elapsed)
    }

    fn lock_file_polling(
        &self,
        file_name: &str,
        patience: Duration,
        stop: Option<&Canceller>,
        try_lock: impl Fn(&File) -> Result<(), TryLockError>,
        elapsed: impl Fn() -> Duration,
    ) -> Result<Lock<'_>, Error> {
        let path = self.dir.join(file_name);
        loop {
            let (file, metadata) = self.open_lock_file(&path)?;
            loop {
                let taken = try_lock(&file);
                // A key fetch can enter the OS keychain as soon as we return.
                // Check after the attempt, including if it just became free.
                let cancelled = stop.is_some_and(Canceller::is_cancelled);
                match taken {
                    Ok(()) => {
                        let held = HeldFile(file);
                        if cancelled {
                            return Err(reading::cancelled());
                        }
                        if self.names_locked_file(&path, &metadata)? {
                            return Ok(Lock::new(held));
                        }
                        // Drop the old lock before opening its replacement.
                        break;
                    }
                    Err(_) if cancelled => return Err(reading::cancelled()),
                    Err(TryLockError::WouldBlock) => {}
                    Err(TryLockError::Error(_)) => {
                        return Err(failed("the entry could not be locked"));
                    }
                }
                let waited = elapsed();
                if waited >= patience {
                    return Err(Error::store_busy());
                }
                let delay = LOCK_RETRY.min(patience.saturating_sub(waited));
                match stop {
                    Some(stop) => {
                        stop.wait(delay);
                    }
                    None => thread::sleep(delay),
                }
            }
            if elapsed() >= patience {
                return Err(Error::store_busy());
            }
        }
    }

    fn open_lock_file(&self, path: &Path) -> Result<(File, Metadata), Error> {
        self.check_dir()?;
        // Checked before opening, so a link or a pipe is never opened.
        match fs::symlink_metadata(path) {
            Ok(metadata) => privacy::check_entry(&metadata, &self.owner)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(failed("the entry could not be locked")),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        privacy::owner_only(&mut options);
        deny_delete_sharing(&mut options);
        let file = options
            .open(path)
            .map_err(|_| failed("the entry could not be locked"))?;
        let metadata = file
            .metadata()
            .map_err(|_| failed("the entry could not be locked"))?;
        privacy::check_entry(&metadata, &self.owner)?;
        Ok((file, metadata))
    }

    fn names_locked_file(&self, path: &Path, locked: &Metadata) -> Result<bool, Error> {
        self.check_dir()?;
        let named = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(failed("the entry could not be locked")),
        };
        privacy::check_entry(&named, &self.owner)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            Ok(named.dev() == locked.dev() && named.ino() == locked.ino())
        }
        #[cfg(not(unix))]
        {
            // Stable std exposes no volume and file ID pair on Windows, but
            // the open handle denies delete sharing, so the name cannot have
            // moved to another file since it was opened.
            let _ = locked;
            Ok(true)
        }
    }
}

/// On Windows, keeps other programs from renaming or deleting a lock file
/// while it is open here; reads and writes stay shared, so other
/// processes can still open it to wait for the lock.
fn deny_delete_sharing(options: &mut OpenOptions) {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_SHARE_READ: u32 = 0x1;
        const FILE_SHARE_WRITE: u32 = 0x2;
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    #[cfg(not(windows))]
    let _ = options;
}

struct HeldFile(File);

impl Drop for HeldFile {
    fn drop(&mut self) {
        // An unrelated child can briefly inherit the descriptor between
        // fork and exec. Unlock even if closing this copy would leave it held.
        let _unlocked = self.0.unlock();
    }
}
