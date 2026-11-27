//! A store that keeps each entry as a private file.

mod app_dir;
mod atomic;
mod inventory;
mod leftovers;
mod locking;
#[cfg(feature = "keychain")]
mod metadata;
mod privacy;

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind};

use super::{EntryName, Lock, Store, Stored};

pub(crate) use atomic::write_new_file;
use atomic::{create_fresh, temporary};

/// The largest entry `read` accepts and `write` produces. Under `Sealed`
/// this is the sealed value, so 29 bytes of envelope leave 262,115 bytes of
/// plaintext.
const MAX_ENTRY_BYTES: usize = 256 * 1024;

/// Keeps each entry as a plain file in a directory the app names, created
/// owner-only on Unix. For desktop applications use a private local
/// directory and prefer keychain-sealed storage; this store does not audit ACLs.
///
/// Other files may share the directory. Plaintext migration owns only
/// `installation` and `account-*`; use a dedicated subdirectory such as
/// `paste-perfect/sign-in` to avoid name and envelope-format collisions.
///
/// An entry lives in `<dir>/<entry>` and is replaced through a temporary
/// file and a rename, so a reader sees the old or the new value and a crash
/// never leaves half a value behind. On Windows, while another program holds
/// the entry open without delete sharing, as backup, sync and scanning tools
/// sometimes do, a write retries for up to a second before it fails. An entry's lock is the file
/// `<dir>/<entry>.lock`, locked with the operating system's file lock, so it
/// also excludes other processes; lock files stay in place. On Unix, after
/// locking a file the store checks it still has that name and retries if
/// the file was removed or replaced while it was being locked. On Windows,
/// no program can rename or delete a lock file while a process has it open.
///
/// # What it relies on
///
/// On Unix, everything is created owner-only (`0700` and `0600`).
/// [`open`](Self::open) and every later operation refuse a directory whose
/// permission bits let other users in, that is a symbolic link or that
/// belongs to someone else, and [`read`](Store::read) and [`lock`](Store::lock) refuse
/// such a file. Place the store under ancestors that untrusted users cannot
/// rename or replace, since each operation resolves the path again.
///
/// Access control lists are not checked, because the standard library
/// cannot read them:
///
/// - On macOS an ACL is evaluated before the permission bits, so an entry
///   such as `everyone allow read` on the directory, or inherited from its
///   parent, lets other users read files whose mode is `0600`.
/// - On Windows nothing but the file type is checked. The directory and
///   every entry inherit the access control list of the directory's
///   parent.
///
/// On both, the app places the directory in the user's own data directory,
/// `~/Library/Application Support` or `%LOCALAPPDATA%`, whose default
/// permissions keep other users out, and never in a shared folder. On Linux
/// the mode bits already bound a POSIX ACL: `0700` and `0600` leave its mask
/// empty, so its extra entries grant nothing.
///
/// # What it does not protect against
///
/// Any program that runs as the same user can read what is stored, and so
/// can any backup or sync tool that copies the directory. On a desktop,
/// wrap it in [`Sealed`](super::Sealed) with a key from the system
/// keychain, so a copy of the directory reveals no entry's content, only
/// entry names and sizes, even when an ACL has opened it to other users.
/// Plain entries written before sealing, and their backups, stay readable
/// until they are deleted. Plain, it is for machines without a keychain,
/// such as a server or a container.
/// A program running as the same user can also unlink a lock file after
/// its holder verified it, so all users of the store must leave locks in place.
///
/// ```no_run
/// use std::time::Duration;
///
/// use siwc::store::{EntryName, PrivateFiles, Store};
///
/// let store = PrivateFiles::open("/home/alex/.local/share/paste-perfect/sign-in")?;
/// let entry = EntryName::new("account-1")?;
///
/// let lock = store.lock(&entry, Duration::from_secs(10))?;
/// store.write(&entry, b"synthetic credentials")?;
/// drop(lock);
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Clone)]
pub struct PrivateFiles {
    dir: PathBuf,
    owner: privacy::Owner,
}

impl PrivateFiles {
    /// Opens the store in `dir`, creating the directory when only its last
    /// component is missing.
    ///
    /// Opening also removes temporary files that an interrupted write left
    /// behind more than an hour ago.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::InvalidInput`] when `dir` is not an absolute path or
    ///   contains a `..` component.
    /// - [`ErrorKind::StoreNotPrivate`] when `dir` is not a directory, or, on
    ///   Unix, is a symbolic link, has permission bits open to other users or
    ///   belongs to another user.
    /// - [`ErrorKind::Store`] when the parent of `dir` does not exist or the
    ///   directory cannot be created, inspected or written.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, Error> {
        let raw_dir = dir.as_ref();
        if !raw_dir.is_absolute()
            || raw_dir
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "the store directory must be an absolute path without `..` components",
            ));
        }
        // Strip trailing `/` and `.` components so `symlink_metadata` inspects
        // a final symlink instead of resolving through it on POSIX.
        let dir: PathBuf = raw_dir.components().collect();
        match fs::symlink_metadata(&dir) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => create_dir(&dir)?,
            Err(_) => return Err(failed("the store directory could not be inspected")),
        }
        let metadata = fs::symlink_metadata(&dir)
            .map_err(|_| failed("the store directory could not be inspected"))?;
        privacy::check_dir(&metadata)?;
        let (probe, probe_path) = create_fresh(|| temporary(&dir, "owner-probe"))
            .map_err(|_| failed("the store directory could not be written"))?;
        let owner = privacy::check_owner(&metadata, probe, &probe_path)?;
        leftovers::sweep(&dir)?;
        Ok(Self { dir, owner })
    }

    fn path(&self, entry: &EntryName) -> PathBuf {
        self.dir.join(entry.as_str())
    }

    /// Checks the directory again, as [`open`](Self::open) did: it may have
    /// been replaced or opened to others since.
    fn check_dir(&self) -> Result<(), Error> {
        let metadata = fs::symlink_metadata(&self.dir)
            .map_err(|_| failed("the store directory could not be inspected"))?;
        privacy::check_dir(&metadata)?;
        privacy::check_dir_owner(&metadata, &self.owner)
    }
}

fn create_dir(dir: &Path) -> Result<(), Error> {
    match privacy::create_dir(dir) {
        Ok(()) => Ok(()),
        // Someone else created it first; it is checked like any other.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(failed("the parent of the store directory does not exist"))
        }
        Err(_) => Err(failed("the store directory could not be created")),
    }
}

fn failed(message: &'static str) -> Error {
    Error::new(ErrorKind::Store, message)
}

fn too_large() -> Error {
    failed("the entry is larger than the store allows")
}

impl PrivateFiles {
    fn read_file(&self, path: &Path, limit: usize) -> Result<Option<Stored>, Error> {
        self.check_dir()?;
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(failed("the entry could not be read")),
        };
        // Checked before opening, so a link or a pipe is never opened.
        privacy::check_entry(&metadata, &self.owner)?;
        let mut file = match File::open(path) {
            Ok(file) => file,
            // Removed since it was inspected.
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(failed("the entry could not be read")),
        };
        // A rename may have put another file in place since the first look.
        let metadata = file
            .metadata()
            .map_err(|_| failed("the entry could not be read"))?;
        privacy::check_entry(&metadata, &self.owner)?;
        let len = usize::try_from(metadata.len())
            .ok()
            .filter(|&len| len <= limit)
            .ok_or_else(too_large)?;
        // The buffer has its final size from the start: one that grows
        // leaves copies of the entry behind that nothing wipes. The byte
        // beyond the length shows a file that is longer than it said.
        let mut bytes = Zeroizing::new(vec![0_u8; len.saturating_add(1)]);
        let mut filled = 0_usize;
        loop {
            let spare = bytes.get_mut(filled..).unwrap_or_default();
            if spare.is_empty() {
                break;
            }
            match file.read(spare) {
                Ok(0) => break,
                Ok(read) => filled = filled.saturating_add(read),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(failed("the entry could not be read")),
            }
        }
        if filled > len {
            return Err(failed("the entry changed while it was read"));
        }
        bytes.truncate(filled);
        Ok(Some(Stored::new(std::mem::take(&mut *bytes))))
    }

    pub(super) fn remove_entry(&self, entry: &EntryName) -> Result<bool, Error> {
        self.check_dir()?;
        match fs::remove_file(self.path(entry)) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(failed("the entry could not be removed")),
        }
    }
}

impl Store for PrivateFiles {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        self.read_file(&self.path(entry), MAX_ENTRY_BYTES)
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        if value.len() > MAX_ENTRY_BYTES {
            return Err(too_large());
        }
        self.check_dir()?;
        atomic::replace(&self.dir, entry.as_str(), &self.path(entry), value)
            .map_err(|_| failed("the entry could not be written"))?;
        // Once readers see the new value, the Store contract reports success.
        let _synced = privacy::sync_dir(&self.dir);
        Ok(())
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        self.remove_entry(entry)?;
        Ok(())
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        self.lock_file(&format!("{}.lock", entry.as_str()), patience, None)
    }
}

impl fmt::Debug for PrivateFiles {
    /// Only the type name: the directory path can contain a user name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateFiles")
    }
}

#[cfg(test)]
mod tests {
    use std::process;

    use super::atomic::TEMPORARY_TRIES;
    use super::*;

    /// A private directory of its own under the system's temporary one,
    /// removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(test: &str) -> Self {
            let path = std::env::temp_dir().join(format!("siwc-files-{test}-{}", process::id()));
            let _ = fs::remove_dir_all(&path);
            privacy::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_held_lock_file_cannot_be_renamed_or_deleted() {
        let scratch = Scratch::new("held-lock-name");
        let store = PrivateFiles::open(&scratch.0).unwrap();
        let entry = EntryName::new("account-1").unwrap();
        let path = scratch.0.join("account-1.lock");
        let held = store.lock(&entry, Duration::ZERO).unwrap();
        assert!(fs::rename(&path, scratch.0.join("account-1.moved")).is_err());
        assert!(fs::remove_file(&path).is_err());
        drop(held);
        assert!(fs::remove_file(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_taker_reopens_a_lock_replaced_before_it_returns() {
        let scratch = Scratch::new("replaced-lock");
        let store = PrivateFiles::open(&scratch.0).unwrap();
        let entry = EntryName::new("account-1").unwrap();
        let name = "account-1.lock";
        let path = scratch.0.join(name);
        let replaced = std::cell::Cell::new(false);
        let held = store
            .lock_file_with(name, Duration::from_secs(5), None, |file| {
                file.try_lock()?;
                if !replaced.replace(true) {
                    fs::remove_file(&path).unwrap();
                    drop(store.lock(&entry, Duration::ZERO).unwrap());
                }
                Ok(())
            })
            .unwrap();

        assert_eq!(
            store.lock(&entry, Duration::ZERO).unwrap_err().kind(),
            ErrorKind::StoreBusy
        );
        drop(held);
        assert!(store.lock(&entry, Duration::ZERO).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn dropping_a_lock_releases_it_even_while_another_descriptor_is_open() {
        let scratch = Scratch::new("duplicated-lock");
        let store = PrivateFiles::open(&scratch.0).unwrap();
        let entry = EntryName::new("account-1").unwrap();
        let duplicate = std::cell::RefCell::new(None);
        let held = store
            .lock_file_with("account-1.lock", Duration::ZERO, None, |file| {
                file.try_lock()?;
                // Simulate a child that has inherited the descriptor but
                // has not yet closed it on exec.
                duplicate.replace(Some(file.try_clone().unwrap()));
                Ok(())
            })
            .unwrap();
        let _inherited = duplicate.into_inner().unwrap();
        drop(held);

        let _reacquired = store.lock(&entry, Duration::ZERO).unwrap();
    }

    #[test]
    fn a_name_a_leftover_holds_is_skipped_for_the_next_one() {
        let scratch = Scratch::new("skip");
        let names = [
            "account-1.7-0.new",
            "account-1.7-1.new",
            "account-1.7-2.new",
        ];
        for taken in names.iter().take(2) {
            File::create(scratch.0.join(taken)).unwrap();
        }
        let mut next = names.iter().map(|name| scratch.0.join(name));
        let (_, path) = create_fresh(|| next.next().unwrap()).unwrap();
        assert_eq!(path, scratch.0.join("account-1.7-2.new"));
    }

    #[test]
    fn a_write_gives_up_after_a_bounded_number_of_taken_names() {
        let scratch = Scratch::new("bounded");
        let taken = scratch.0.join("account-1.7-0.new");
        File::create(&taken).unwrap();
        let mut asked = 0;
        let error = create_fresh(|| {
            asked += 1;
            taken.clone()
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(asked, TEMPORARY_TRIES);
    }

    #[test]
    fn creating_a_new_file_cannot_replace_an_existing_destination() {
        let scratch = Scratch::new("create-new");
        let destination = scratch.0.join("bundle");
        fs::write(&destination, b"earlier bundle").unwrap();

        let error = atomic::write_new_file(&destination, b"new bundle").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(fs::read(destination).unwrap(), b"earlier bundle");
    }

    #[test]
    fn temporary_names_differ_and_start_at_the_time_of_the_first_write() {
        let dir = Path::new("/store");
        let (first, second) = (temporary(dir, "account-1"), temporary(dir, "account-1"));
        assert_ne!(first, second);
        let number = |path: &Path| -> u64 {
            let name = path.file_name().unwrap().to_str().unwrap();
            let tag = name
                .strip_prefix(&format!("account-1.{}-", process::id()))
                .unwrap();
            tag.strip_suffix(".new").unwrap().parse().unwrap()
        };
        // Far beyond what a counter from zero reaches: nanoseconds since 1970.
        assert!(number(&first) > 1_000_000_000_000_000_000);
    }
}
