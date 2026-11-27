//! Opening [`PrivateFiles`] in the platform's per-user local app-data folder.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, PathBuf};

use crate::error::{Error, ErrorKind};

use super::super::name::is_device;
use super::{PrivateFiles, failed, privacy};

/// Longest app directory name, in bytes.
const MAX_APP_DIR_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Windows,
    MacOs,
    Unix,
    Unsupported,
}

impl Platform {
    const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(unix) {
            Self::Unix
        } else {
            Self::Unsupported
        }
    }
}

impl PrivateFiles {
    /// Opens a private store in `<local-app-data>/<app_dir>`, creating missing
    /// standard local-data parent folders (`~/.local/share` or
    /// `~/Library/Application Support`) when needed, with mode `0700` on Unix:
    ///
    /// - **Windows:** `%LOCALAPPDATA%\<app_dir>`
    /// - **macOS:** `$HOME/Library/Application Support/<app_dir>`
    /// - **Linux and other Unix systems:** `$XDG_DATA_HOME/<app_dir>` when
    ///   `XDG_DATA_HOME` is an absolute path without `..` components, or
    ///   `$HOME/.local/share/<app_dir>` otherwise
    ///
    /// Other files may share the directory. Only `installation` and `account-*`
    /// are migrated from plaintext. Prefer a store-specific directory name.
    ///
    /// A CLI and a desktop app sharing a login must resolve the same local
    /// directory, including its spelling. The parent of a custom
    /// `XDG_DATA_HOME` must exist. Use [`Self::open`] with a trusted absolute
    /// path when the launcher supplies different environment variables.
    ///
    /// `app_dir` must be a single directory name of 1 to 64 ASCII letters,
    /// digits, `.`, `_` and `-`, starting with an ASCII letter or digit and
    /// not ending with `.` or `-`, and not a Windows device name such as
    /// `con` or `nul.txt` on any platform (for example `"paste-perfect"` or
    /// `"com.example.paste-perfect"`).
    ///
    /// ```no_run
    /// use siwc::store::PrivateFiles;
    ///
    /// let store = PrivateFiles::open_app_dir("paste-perfect-sign-in")?;
    /// # drop(store);
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::InvalidInput`] when `app_dir` breaks the naming rule.
    /// - [`ErrorKind::Store`] when `LOCALAPPDATA` on Windows or `HOME`
    ///   elsewhere (on Linux only when `XDG_DATA_HOME` is not an absolute
    ///   path without `..` components) is unset, not absolute or has a `..`
    ///   component, or the directory cannot be created.
    /// - [`ErrorKind::StoreNotPrivate`] when the store directory or, on
    ///   Unix, `$HOME` or a local app-data folder below it belongs to another
    ///   user or is writable by everyone, plus the privacy errors of
    ///   [`open`](Self::open).
    pub fn open_app_dir(app_dir: &str) -> Result<Self, Error> {
        Self::open_app_dir_with(Platform::current(), app_dir, |key| std::env::var_os(key))
    }

    fn open_app_dir_with(
        platform: Platform,
        app_dir: &str,
        var: impl Fn(&str) -> Option<OsString>,
    ) -> Result<Self, Error> {
        validate_app_dir(app_dir)?;
        let (base_ancestors, to_create, dir) = resolve_app_dir(platform, app_dir, var)?;
        for ancestor in base_ancestors.iter().chain(&to_create) {
            privacy::precheck_existing_ancestor(ancestor)?;
        }
        let mut created_steps = Vec::new();
        for step in &to_create {
            if ensure_parent_dir(step)? {
                created_steps.push(step.clone());
            }
        }
        let existed = fs::symlink_metadata(&dir).is_ok();
        let store = match Self::open(&dir) {
            Ok(store) => store,
            Err(err) => {
                for step in created_steps.iter().rev() {
                    let _ = fs::remove_dir(step);
                }
                return Err(err);
            }
        };
        for ancestor in base_ancestors
            .iter()
            .chain(&to_create)
            .map(PathBuf::as_path)
            .chain(dir.parent())
        {
            if let Err(err) = privacy::check_ancestor_dir(ancestor, &store.owner) {
                if !existed {
                    let _ = fs::remove_dir(&store.dir);
                }
                for step in created_steps.iter().rev() {
                    let _ = fs::remove_dir(step);
                }
                return Err(err);
            }
        }
        Ok(store)
    }
}

fn validate_app_dir(name: &str) -> Result<(), Error> {
    let valid = (1..=MAX_APP_DIR_LEN).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && !name.ends_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    let stem = name.split('.').next().unwrap_or(name).to_ascii_lowercase();
    if !valid || is_device(&stem) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the app directory name must be 1 to 64 ASCII letters, digits, '.', '_' or '-', starting with a letter or digit, not ending with '.' or '-', and not a reserved device name",
        ));
    }
    Ok(())
}

/// Returns `(base_ancestors_to_verify, intermediate_dirs_to_ensure, final_store_dir)`.
fn resolve_app_dir(
    platform: Platform,
    app_dir: &str,
    var: impl Fn(&str) -> Option<OsString>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>, PathBuf), Error> {
    let clean_abs = |name: &str| {
        var(name)
            .map(PathBuf::from)
            .filter(|path| {
                path.is_absolute()
                    && !path
                        .components()
                        .any(|part| matches!(part, Component::ParentDir))
            })
            .map(|path| path.components().collect::<PathBuf>())
    };

    match platform {
        Platform::Windows => {
            let base = clean_abs("LOCALAPPDATA").ok_or_else(|| {
                failed("LOCALAPPDATA is not set to an absolute path without .. components")
            })?;
            let store_dir = base.join(app_dir);
            Ok((vec![base], Vec::new(), store_dir))
        }
        Platform::MacOs => {
            let home = clean_abs("HOME").ok_or_else(|| {
                failed("HOME is not set to an absolute path without .. components")
            })?;
            let library = home.join("Library");
            let support = library.join("Application Support");
            let store_dir = support.join(app_dir);
            Ok((vec![home], vec![library, support], store_dir))
        }
        Platform::Unix => {
            if let Some(xdg) = clean_abs("XDG_DATA_HOME") {
                let mut bases = Vec::new();
                if fs::symlink_metadata(&xdg).is_err()
                    && let Some(parent) = xdg.parent()
                {
                    bases.push(parent.to_path_buf());
                }
                let store_dir = xdg.join(app_dir);
                return Ok((bases, vec![xdg], store_dir));
            }
            let home = clean_abs("HOME").ok_or_else(|| {
                failed("HOME is not set to an absolute path without .. components")
            })?;
            let dot_local = home.join(".local");
            let share = dot_local.join("share");
            let store_dir = share.join(app_dir);
            Ok((vec![home], vec![dot_local, share], store_dir))
        }
        Platform::Unsupported => Err(failed(
            "this platform defines no standard local app-data directory",
        )),
    }
}

/// Ensures `dir` exists as a directory, returning `Ok(true)` if this call
/// created it.
fn ensure_parent_dir(dir: &PathBuf) -> Result<bool, Error> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => Ok(false),
        // An existing symlink to a directory (for example a symlinked ~/.local/share
        // in a dotfile setup) is allowed on an ancestor, though never on the store
        // directory itself.
        Ok(_) if fs::metadata(dir).is_ok_and(|target| target.is_dir()) => Ok(false),
        Ok(_) => Err(failed(
            "an ancestor of the store directory is not a directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => match privacy::create_dir(dir) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(_) => Err(failed("the local app-data directory could not be created")),
        },
        Err(_) => Err(failed(
            "the local app-data directory could not be inspected",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_dir_accepts_bundle_ids_and_slugs_and_refuses_paths_or_devices() {
        for good in [
            "siwc",
            "paste-perfect",
            "com.example.paste_perfect",
            "App01",
            &"a".repeat(MAX_APP_DIR_LEN),
        ] {
            validate_app_dir(good).expect(good);
        }
        for bad in [
            "",
            ".hidden",
            "-leading",
            "trailing.",
            "trailing-",
            "../escape",
            "nested/dir",
            "nested\\dir",
            "with space",
            "con",
            "NUL",
            "com1.app",
            "lpt9",
            &"a".repeat(MAX_APP_DIR_LEN + 1),
        ] {
            assert_eq!(
                validate_app_dir(bad).unwrap_err().kind(),
                ErrorKind::InvalidInput,
                "{bad}"
            );
        }
    }

    #[test]
    fn resolves_platform_local_data_paths_and_rejects_relative_env() {
        let base = std::env::temp_dir();
        let xdg_dir = base.join("xdg");
        let home_dir = base.join("home");
        let mac_home = base.join("mac-home");
        let win_local = base.join("localappdata");
        let parent_escape = base.join("sub").join("..").join("escape");

        let env_map = |pairs: &[(&str, OsString)]| {
            let owned: Vec<(String, OsString)> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect();
            move |key: &str| owned.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
        };

        let (_, _, unix_xdg) = resolve_app_dir(
            Platform::Unix,
            "my-app",
            env_map(&[
                ("XDG_DATA_HOME", xdg_dir.clone().into_os_string()),
                ("HOME", home_dir.clone().into_os_string()),
            ]),
        )
        .unwrap();
        assert_eq!(unix_xdg, xdg_dir.join("my-app"));

        // Trailing `/` or `/.` in `HOME` is stripped so POSIX `symlink_metadata`
        // inspects any final symlink rather than resolving through it.
        let mut home_with_slash = home_dir.clone().into_os_string();
        home_with_slash.push("/.");
        let (bases, steps, unix_home) = resolve_app_dir(
            Platform::Unix,
            "my-app",
            env_map(&[
                ("XDG_DATA_HOME", OsString::from("relative/xdg")),
                ("HOME", home_with_slash),
            ]),
        )
        .unwrap();
        assert_eq!(bases, vec![home_dir.clone()]);
        assert_eq!(
            steps,
            vec![
                home_dir.join(".local"),
                home_dir.join(".local").join("share")
            ]
        );
        assert_eq!(
            unix_home,
            home_dir.join(".local").join("share").join("my-app")
        );

        let (mac_bases, _, mac) = resolve_app_dir(
            Platform::MacOs,
            "my-app",
            env_map(&[("HOME", mac_home.clone().into_os_string())]),
        )
        .unwrap();
        assert_eq!(mac_bases, vec![mac_home.clone()]);
        assert_eq!(
            mac,
            mac_home
                .join("Library")
                .join("Application Support")
                .join("my-app")
        );

        assert!(resolve_app_dir(Platform::Unix, "my-app", env_map(&[])).is_err());
        assert!(
            resolve_app_dir(
                Platform::Unix,
                "my-app",
                env_map(&[("HOME", parent_escape.into_os_string())]),
            )
            .is_err()
        );

        let (win_bases, _, win) = resolve_app_dir(
            Platform::Windows,
            "my-app",
            env_map(&[("LOCALAPPDATA", win_local.clone().into_os_string())]),
        )
        .unwrap();
        assert_eq!(win_bases, vec![win_local.clone()]);
        assert_eq!(win, win_local.join("my-app"));
        assert!(resolve_app_dir(Platform::Windows, "my-app", env_map(&[])).is_err());
        assert!(resolve_app_dir(Platform::MacOs, "my-app", env_map(&[])).is_err());
        assert!(resolve_app_dir(Platform::Unsupported, "my-app", env_map(&[])).is_err());
    }

    #[test]
    fn open_app_dir_creates_missing_parents_and_rejects_file_or_shared_ancestors() {
        let root = std::env::temp_dir().join(format!("siwc-appdir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        privacy::create_dir(&root).unwrap();

        let root_os = root.clone().into_os_string();
        let store = PrivateFiles::open_app_dir_with(Platform::Unix, "demo-app", |key| {
            (key == "HOME").then(|| root_os.clone())
        })
        .unwrap();
        assert!(root.join(".local").join("share").join("demo-app").is_dir());
        // Opening a second time reuses the existing `.local/share` hierarchy.
        let _again = PrivateFiles::open_app_dir_with(Platform::Unix, "demo-app", |key| {
            (key == "HOME").then(|| root_os.clone())
        })
        .unwrap();
        drop(store);

        // A regular file where an ancestor directory is expected fails cleanly.
        let bad_home = root.join("file-home");
        privacy::create_dir(&bad_home).unwrap();
        fs::write(bad_home.join(".local"), b"not a dir").unwrap();
        let bad_os = bad_home.into_os_string();
        let err = PrivateFiles::open_app_dir_with(Platform::Unix, "demo-app", |key| {
            (key == "HOME").then(|| bad_os.clone())
        })
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Store);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // A world-writable `XDG_DATA_HOME` or `HOME` (such as `/tmp`) is
            // refused as `StoreNotPrivate` before creating subdirectories inside it.
            let shared_xdg = root.join("world-writable-xdg");
            privacy::create_dir(&shared_xdg).unwrap();
            fs::set_permissions(&shared_xdg, fs::Permissions::from_mode(0o777)).unwrap();
            let shared_os = shared_xdg.clone().into_os_string();
            let err = PrivateFiles::open_app_dir_with(Platform::Unix, "demo-app", |key| {
                (key == "XDG_DATA_HOME").then(|| shared_os.clone())
            })
            .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::StoreNotPrivate);
            assert!(!shared_xdg.join("demo-app").exists());

            let shared_home = root.join("world-writable-home");
            privacy::create_dir(&shared_home).unwrap();
            fs::set_permissions(&shared_home, fs::Permissions::from_mode(0o777)).unwrap();
            let shared_home_os = shared_home.clone().into_os_string();
            let err = PrivateFiles::open_app_dir_with(Platform::Unix, "demo-app", |key| {
                (key == "HOME").then(|| shared_home_os.clone())
            })
            .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::StoreNotPrivate);
            assert!(!shared_home.join(".local").exists());
        }

        let _ = fs::remove_dir_all(&root);
    }
}
