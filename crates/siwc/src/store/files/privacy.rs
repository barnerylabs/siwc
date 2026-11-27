//! What keeps a store's directory and files away from other users on this
//! platform.
//!
//! Unix has permission bits and owners the standard library can read. Access
//! control lists, the macOS ones on Unix and all of Windows, would need
//! platform calls the crate does not make; there the app places the
//! directory inside the user's own data directory (see `PrivateFiles`).

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

use crate::error::{Error, ErrorKind};

fn not_private(message: &'static str) -> Error {
    Error::new(ErrorKind::StoreNotPrivate, message)
}

fn failed(message: &'static str) -> Error {
    Error::new(ErrorKind::Store, message)
}

/// Permission bits for the group and for others.
#[cfg(unix)]
const SHARED_BITS: u32 = 0o077;

/// Creates one directory, owner-only on Unix.
pub(super) fn create_dir(dir: &Path) -> io::Result<()> {
    let builder = &mut fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(builder, 0o700);
    builder.create(dir)
}

/// Makes a file that `options` creates owner-only on Unix.
pub(super) fn owner_only(options: &mut OpenOptions) {
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(options, 0o600);
    #[cfg(not(unix))]
    let _ = options;
}

/// Refuses a store directory others could reach, from metadata that does
/// not follow links.
pub(super) fn check_dir(metadata: &Metadata) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.file_type().is_symlink() {
            return Err(not_private("the store directory is a symbolic link"));
        }
        if !metadata.is_dir() {
            return Err(not_private("the store path is not a directory"));
        }
        if metadata.permissions().mode() & SHARED_BITS != 0 {
            return Err(not_private(
                "other users have access to the store directory",
            ));
        }
    }
    #[cfg(not(unix))]
    if !metadata.is_dir() {
        return Err(not_private("the store path is not a directory"));
    }
    Ok(())
}

/// The user a store's directory and entries have to belong to: the one this
/// process creates files as. Elsewhere than on Unix there is nothing to
/// compare.
#[derive(Debug, Clone, Copy)]
pub(super) struct Owner {
    #[cfg(unix)]
    uid: u32,
}

/// Refuses a store directory that belongs to another user and returns the
/// user it belongs to.
///
/// The standard library has no safe way to ask for the effective user, so
/// the owner of `probe`, a file the caller just created at `probe_path`
/// inside the directory, is compared with the directory's. The probe is
/// removed here.
pub(super) fn check_owner(dir: &Metadata, probe: File, probe_path: &Path) -> Result<Owner, Error> {
    let inspected = probe
        .metadata()
        .map_err(|_| failed("the store directory could not be written"));
    // Close the handle before unlinking so non-NTFS Windows volumes without
    // POSIX delete semantics never reject `remove_file` with a sharing violation.
    drop(probe);
    let removed = fs::remove_file(probe_path);
    let probe = inspected?;
    removed.map_err(|_| failed("the store directory could not be written"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let owner = Owner { uid: probe.uid() };
        check_dir_owner(dir, &owner)?;
        Ok(owner)
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, probe);
        Ok(Owner {})
    }
}

/// Refuses a store directory that does not belong to `owner`.
pub(super) fn check_dir_owner(dir: &Metadata, owner: &Owner) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if dir.uid() != owner.uid {
            return Err(not_private("the store directory belongs to another user"));
        }
    }
    #[cfg(not(unix))]
    let _ = (dir, owner);
    Ok(())
}

/// Refuses an entry that is not a regular file or, on Unix, that others
/// could read or that does not belong to `owner`.
pub(super) fn check_entry(metadata: &Metadata, owner: &Owner) -> Result<(), Error> {
    if !metadata.is_file() {
        return Err(not_private("the entry is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.permissions().mode() & SHARED_BITS != 0 {
            return Err(not_private("other users have access to the entry"));
        }
        if metadata.uid() != owner.uid {
            return Err(not_private("the entry belongs to another user"));
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    Ok(())
}

/// Pre-checks an ancestor directory that already exists before creating any
/// child directory or probe file inside it: must be a directory (following
/// symlinks) and, on Unix, not world-writable (`0o002`).
pub(super) fn precheck_existing_ancestor(dir: &Path) -> Result<(), Error> {
    let metadata = match fs::metadata(dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(failed(
                "the local app-data directory could not be inspected",
            ));
        }
    };
    if !metadata.is_dir() {
        return Err(failed(
            "an ancestor of the store directory is not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o002 != 0 {
            return Err(not_private(
                "the local app-data directory is writable by other users",
            ));
        }
    }
    Ok(())
}

/// Refuses a local app-data ancestor directory that is not a directory or, on
/// Unix, belongs to another user (checking both symlink and target) or is
/// world-writable (such as `/tmp`).
pub(super) fn check_ancestor_dir(dir: &Path, owner: &Owner) -> Result<(), Error> {
    let link_meta = fs::symlink_metadata(dir)
        .map_err(|_| failed("the local app-data directory could not be inspected"))?;
    let metadata = fs::metadata(dir)
        .map_err(|_| failed("the local app-data directory could not be inspected"))?;
    if !metadata.is_dir() {
        return Err(failed(
            "an ancestor of the store directory is not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if link_meta.uid() != owner.uid || metadata.uid() != owner.uid {
            return Err(not_private(
                "the local app-data directory belongs to another user",
            ));
        }
        if metadata.permissions().mode() & 0o002 != 0 {
            return Err(not_private(
                "the local app-data directory is writable by other users",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = (link_meta, owner);
    Ok(())
}

/// Syncs a directory after publishing a file. On Unix this confirms the
/// directory update; elsewhere the store only syncs the file itself.
pub(super) fn sync_dir(dir: &Path) -> io::Result<()> {
    sync_directory(dir, Err)
}

/// Syncs a directory when the file system supports it. Only errors from
/// the sync itself can be ignored.
pub(super) fn sync_dir_if_supported(dir: &Path) -> io::Result<()> {
    sync_directory(dir, ignore_unsupported_directory_sync)
}

fn sync_directory(
    dir: &Path,
    on_sync_error: impl FnOnce(io::Error) -> io::Result<()>,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all().or_else(on_sync_error)
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, on_sync_error);
        Ok(())
    }
}

fn ignore_unsupported_directory_sync(error: io::Error) -> io::Result<()> {
    // Unix std maps EINVAL, EOPNOTSUPP and ENOSYS to these kinds. Some
    // systems have a distinct ENOTSUP that std may leave uncategorized.
    let unsupported = error.kind() == io::ErrorKind::Unsupported
        || (cfg!(unix) && error.kind() == io::ErrorKind::InvalidInput)
        || distinct_enotsup(error.raw_os_error());
    if unsupported { Ok(()) } else { Err(error) }
}

fn distinct_enotsup(errno: Option<i32>) -> bool {
    (cfg!(target_vendor = "apple") && errno == Some(45))
        || (cfg!(target_os = "netbsd") && errno == Some(86))
        || (cfg!(any(target_os = "illumos", target_os = "solaris")) && errno == Some(48))
        || (cfg!(target_os = "aix") && errno == Some(124))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_sync_ignores_only_unsupported_errors() {
        assert!(ignore_unsupported_directory_sync(io::ErrorKind::Unsupported.into()).is_ok());
        #[cfg(unix)]
        assert!(ignore_unsupported_directory_sync(io::ErrorKind::InvalidInput.into()).is_ok());
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        for errno in [22, 38, 95] {
            // EINVAL, ENOSYS, ENOTSUP / EOPNOTSUPP
            assert!(ignore_unsupported_directory_sync(io::Error::from_raw_os_error(errno)).is_ok());
        }
        #[cfg(target_vendor = "apple")]
        for errno in [22, 45, 78, 102] {
            // EINVAL, ENOTSUP, ENOSYS, EOPNOTSUPP
            assert!(ignore_unsupported_directory_sync(io::Error::from_raw_os_error(errno)).is_ok());
        }
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotFound,
            io::ErrorKind::StorageFull,
            io::ErrorKind::Other,
        ] {
            assert_eq!(
                ignore_unsupported_directory_sync(kind.into())
                    .unwrap_err()
                    .kind(),
                kind
            );
        }
    }
}
