//! Implementing [`Store`] directly over the macOS or Linux keychain, with
//! cross-process locks in a [`PrivateFiles`] folder that holds no secret.
//!
//! This example waits for the system helper without a timeout. Run it off
//! the UI thread; the built-in keychain store bounds helper operations.
//!
//! Most desktop apps prefer [`Sealed<PrivateFiles, Keychain>`](siwc::store::Sealed)
//! (`examples/keychain.rs`), which asks the keychain once per store for a
//! single 32-byte key and keeps entries in files: up to 262,144 sealed bytes,
//! which leaves 262,115 bytes of plaintext. An app whose policy keeps
//! every entry in the keychain itself implements [`Store`] like `KeychainStore`
//! below and checks its adapter with [`siwc::store::conformance::check`],
//! which covers the store contract within one process; cross-process
//! locking comes from the `PrivateFiles` lock folder:
//!
//! ```text
//! cargo run -p siwc --features https,testing --example keychain_store -- \
//!     "$HOME/.local/share/siwc-keychain-store-locks" check
//! ```
//!
//! How the adapter meets the contract, and where it stops:
//!
//! - A write replaces the whole entry. It hex-encodes the bytes, so binary
//!   values and the empty slice `b""` survive text-oriented keychain tools
//!   unchanged, and updates the item under `<service>` / `<entry>` in one
//!   step (`security add-generic-password -U` on macOS, `secret-tool store`
//!   on Linux).
//! - On macOS a value is limited to about 2,000 bytes. `security -i` reads
//!   at most 4,095 bytes per command line and runs a longer one in pieces,
//!   so `put` refuses any `add-generic-password` line longer than that
//!   before running anything; the hex encoding and the command around it
//!   take the rest. A larger write fails with a store error and leaves the
//!   old value in place. The conformance suite writes a 3 KiB value, so
//!   `check` on macOS reports that step as failing; use
//!   `Sealed<PrivateFiles, Keychain>` for larger entries.
//! - Keychains offer no cross-process lock, so `Store::lock` delegates to a
//!   [`PrivateFiles`] directory that holds only `<entry>.lock` files and
//!   never receives `read` or `write` calls.
//! - Windows is not covered: the Credential Manager limits a generic
//!   credential to 2,560 bytes, which a token set of several kilobytes
//!   exceeds. Use `Sealed<PrivateFiles, Keychain>` there.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line example talks to its user through the terminal"
)]

use std::env;
use std::fmt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use zeroize::Zeroizing;

use siwc::store::{EntryName, Lock, PrivateFiles, Store, Stored};
use siwc::{AppName, Client, Error, Https};

const APP_NAME: &str = "siwc keychain store example";
const SERVICE: &str = "com.example.siwc-keychain-store";
/// Hex prefix distinguishing an existing empty entry (`"siwc:"`) from an empty
/// stdout of `secret-tool lookup` on a missing item.
const HEX_PREFIX: &[u8] = b"siwc:";
const MAX_ENTRY_LEN: usize = 64 * 1024;

/// Low-level keychain operations over `(service, account)` items.
trait KeychainBackend: Send + Sync {
    fn get(&self, service: &str, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error>;
    fn put(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), Error>;
    fn delete(&self, service: &str, account: &str) -> Result<(), Error>;
}

/// A [`Store`] keeping entries in a `KeychainBackend` and locks in
/// [`PrivateFiles`].
struct KeychainStore<B> {
    service: String,
    locks: PrivateFiles,
    backend: B,
}

impl<B: KeychainBackend> KeychainStore<B> {
    fn new(service: &str, locks: PrivateFiles, backend: B) -> Result<Self, Error> {
        if !is_valid_service(service) {
            return Err(Error::store_failed());
        }
        Ok(Self {
            service: service.to_owned(),
            locks,
            backend,
        })
    }
}

fn is_valid_service(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    name.len() <= 128
        && first.is_ascii_alphanumeric()
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(any(unix, test))]
fn is_safe_token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes[0] != b'-'
        && bytes
            .iter()
            .all(|b| (0x21..=0x7e).contains(b) && !matches!(b, b'"' | b'\'' | b'\\'))
}

impl<B: KeychainBackend> fmt::Debug for KeychainStore<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeychainStore")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

impl<B: KeychainBackend> Store for KeychainStore<B> {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        let Some(encoded) = self.backend.get(&self.service, entry.as_str())? else {
            return Ok(None);
        };
        let mut decoded = decode_hex(encoded.trim_ascii()).ok_or_else(Error::store_failed)?;
        Ok(Some(Stored::new(std::mem::take(&mut *decoded))))
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        if value.len() > MAX_ENTRY_LEN {
            return Err(Error::store_failed());
        }
        let encoded = encode_hex(value);
        self.backend.put(&self.service, entry.as_str(), &encoded)
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        self.backend.delete(&self.service, entry.as_str())
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        self.locks.lock(entry, patience)
    }
}

fn encode_hex(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Zeroizing::new(Vec::with_capacity(HEX_PREFIX.len() + bytes.len() * 2));
    out.extend_from_slice(HEX_PREFIX);
    for &byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)]);
        out.push(DIGITS[usize::from(byte & 0x0f)]);
    }
    out
}

fn decode_hex(encoded: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let hex = encoded.strip_prefix(HEX_PREFIX)?;
    let (pairs, remainder) = hex.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(pairs.len()));
    for &[first, second] in pairs {
        let hi = nibble(first)?;
        let lo = nibble(second)?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn nibble(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        _ => None,
    }
}

/// The most `security -i` reads as one command line, newline included; it
/// splits a longer line and runs the first piece on its own.
#[cfg(any(target_os = "macos", test))]
const SECURITY_LINE_MAX: usize = 4095;

/// The `security -i` command line that stores `secret` under `service` /
/// `account`, or a store error when a part is unsafe or the line would not
/// fit [`SECURITY_LINE_MAX`].
#[cfg(any(target_os = "macos", test))]
fn security_put_line(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !is_safe_token(service.as_bytes())
        || !is_safe_token(account.as_bytes())
        || !is_safe_token(secret)
    {
        return Err(Error::store_failed());
    }
    // `-U` updates an existing item atomically in the login keychain.
    let prefix = format!("add-generic-password -U -s {service} -a {account} -w ");
    let len = prefix.len() + secret.len() + 1;
    if len > SECURITY_LINE_MAX {
        return Err(Error::store_failed());
    }
    let mut line = Zeroizing::new(Vec::with_capacity(len));
    line.extend_from_slice(prefix.as_bytes());
    line.extend_from_slice(secret);
    line.push(b'\n');
    Ok(line)
}

#[cfg(target_os = "macos")]
mod platform {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use zeroize::Zeroizing;

    use super::{Error, KeychainBackend, is_safe_token, security_put_line};

    pub(super) struct SystemKeychain(pub(super) &'static str);

    impl SystemKeychain {
        pub(super) fn new() -> Self {
            Self("/usr/bin/security")
        }
    }

    impl KeychainBackend for SystemKeychain {
        fn get(&self, service: &str, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
            if !is_safe_token(service.as_bytes()) || !is_safe_token(account.as_bytes()) {
                return Err(Error::store_failed());
            }
            let out = Command::new(self.0)
                .args(["find-generic-password", "-s", service, "-a", account, "-w"])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .map_err(|_| Error::store_failed())?;
            let stdout = Zeroizing::new(out.stdout);
            match out.status.code() {
                Some(0) => Ok(Some(stdout)),
                Some(44) => Ok(None),
                _ => Err(Error::store_failed()),
            }
        }

        fn put(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), Error> {
            // `-i` reads the command from stdin; the line is built whole
            // and checked against its buffer before anything runs.
            let line = security_put_line(service, account, secret)?;
            let mut child = Command::new(self.0)
                .arg("-i")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| Error::store_failed())?;
            let written = child.stdin.take().map(|mut s| s.write_all(&line));
            let status = child.wait().map_err(|_| Error::store_failed())?;
            match written {
                Some(Ok(())) if status.success() => Ok(()),
                _ => Err(Error::store_failed()),
            }
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), Error> {
            if !is_safe_token(service.as_bytes()) || !is_safe_token(account.as_bytes()) {
                return Err(Error::store_failed());
            }
            let out = Command::new(self.0)
                .args(["delete-generic-password", "-s", service, "-a", account])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .map_err(|_| Error::store_failed())?;
            match out.status.code() {
                Some(0 | 44) => Ok(()),
                _ => Err(Error::store_failed()),
            }
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use zeroize::Zeroizing;

    use super::{Error, KeychainBackend, is_safe_token};

    pub(super) struct SystemKeychain(pub(super) &'static str);

    impl SystemKeychain {
        pub(super) fn new() -> Self {
            Self("secret-tool")
        }
    }

    impl KeychainBackend for SystemKeychain {
        fn get(&self, service: &str, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
            if !is_safe_token(service.as_bytes()) || !is_safe_token(account.as_bytes()) {
                return Err(Error::store_failed());
            }
            let out = Command::new(self.0)
                .args(["lookup", "service", service, "account", account])
                .stdin(Stdio::null())
                .output()
                .map_err(|_| Error::store_failed())?;
            let stdout = Zeroizing::new(out.stdout);
            if out.status.success() {
                Ok(Some(stdout))
            } else if out.status.code() == Some(1) && stdout.is_empty() && out.stderr.is_empty() {
                Ok(None)
            } else {
                Err(Error::store_failed())
            }
        }

        fn put(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), Error> {
            if !is_safe_token(service.as_bytes())
                || !is_safe_token(account.as_bytes())
                || !is_safe_token(secret)
            {
                return Err(Error::store_failed());
            }
            let mut child = Command::new(self.0)
                .args([
                    "store", "--label", service, "service", service, "account", account,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| Error::store_failed())?;
            let written = child.stdin.take().map(|mut s| s.write_all(secret));
            let status = child.wait().map_err(|_| Error::store_failed())?;
            match written {
                Some(Ok(())) if status.success() => Ok(()),
                _ => Err(Error::store_failed()),
            }
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), Error> {
            if !is_safe_token(service.as_bytes()) || !is_safe_token(account.as_bytes()) {
                return Err(Error::store_failed());
            }
            let out = Command::new(self.0)
                .args(["clear", "service", service, "account", account])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .output()
                .map_err(|_| Error::store_failed())?;
            // Like `lookup`, `clear` may exit with 1 and no message when no
            // item matched; that is a removal of nothing, not a failure.
            if out.status.success() || (out.status.code() == Some(1) && out.stderr.is_empty()) {
                Ok(())
            } else {
                Err(Error::store_failed())
            }
        }
    }
}

#[cfg(not(unix))]
mod platform {
    use zeroize::Zeroizing;

    use super::{Error, KeychainBackend};

    pub(super) struct SystemKeychain;

    impl SystemKeychain {
        pub(super) fn new() -> Self {
            Self
        }
    }

    impl KeychainBackend for SystemKeychain {
        fn get(&self, _service: &str, _account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
            Err(Error::store_failed())
        }

        fn put(&self, _service: &str, _account: &str, _secret: &[u8]) -> Result<(), Error> {
            Err(Error::store_failed())
        }

        fn delete(&self, _service: &str, _account: &str) -> Result<(), Error> {
            Err(Error::store_failed())
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let (lock_dir, check_only) = match args.as_slice() {
        [dir] => (PathBuf::from(dir), false),
        [dir, mode] if mode == "check" => (PathBuf::from(dir), true),
        _ => {
            eprintln!("usage: keychain_store <lock-dir> [check]");
            return ExitCode::from(2);
        }
    };
    let run = || -> Result<(), Error> {
        let locks = PrivateFiles::open(&lock_dir)?;
        let service = if check_only {
            "com.example.siwc-keychain-store-check"
        } else {
            SERVICE
        };
        let store = KeychainStore::new(service, locks, platform::SystemKeychain::new())?;
        if check_only {
            // On macOS the 3 KiB step fails: `security -i` takes at most
            // 4,095 bytes per command line (see the module docs).
            siwc::store::conformance::check(&store)?;
            println!("KeychainStore passed siwc::store::conformance::check.");
            return Ok(());
        }
        let client = Client::new(AppName::new(APP_NAME)?, store, Https::new()?);
        for account in client.accounts()? {
            println!("{}  {:?}", account.id(), account.state());
        }
        Ok(())
    };
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use siwc::ErrorKind;

    use super::*;

    /// In-memory keychain used by the conformance self-check.
    #[derive(Default)]
    struct MemoryKeychain(Mutex<HashMap<(String, String), Vec<u8>>>);

    impl KeychainBackend for MemoryKeychain {
        fn get(&self, service: &str, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(&(service.to_owned(), account.to_owned()))
                .cloned()
                .map(Zeroizing::new))
        }

        fn put(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), Error> {
            self.0
                .lock()
                .unwrap()
                .insert((service.to_owned(), account.to_owned()), secret.to_vec());
            Ok(())
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), Error> {
            self.0
                .lock()
                .unwrap()
                .remove(&(service.to_owned(), account.to_owned()));
            Ok(())
        }
    }

    #[test]
    fn keychain_store_adapter_passes_the_conformance_suite_and_keeps_secrets_off_disk() {
        let dir = env::temp_dir().join(format!("siwc-kc-store-example-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let locks = PrivateFiles::open(&dir).unwrap();
        for invalid in ["", "-flag", "space in name", "bad/slash"] {
            assert_eq!(
                KeychainStore::new(invalid, locks.clone(), MemoryKeychain::default())
                    .unwrap_err()
                    .kind(),
                ErrorKind::Store
            );
        }
        let store = KeychainStore::new(SERVICE, locks, MemoryKeychain::default()).unwrap();

        siwc::store::conformance::check(&store).unwrap();

        let entry = EntryName::new("account-1").unwrap();
        store.write(&entry, b"synthetic-refresh-secret").unwrap();
        assert!(!dir.join("account-1").exists());
        assert_eq!(
            store.read(&entry).unwrap().unwrap().expose(),
            b"synthetic-refresh-secret"
        );
        assert_eq!(
            store
                .write(&entry, &vec![0u8; MAX_ENTRY_LEN + 1])
                .unwrap_err()
                .kind(),
            ErrorKind::Store
        );
        assert!(decode_hex(b"missing-prefix").is_none());
        assert!(decode_hex(b"siwc:abc").is_none());
        assert!(decode_hex(b"siwc:zz").is_none());

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let failing = platform::SystemKeychain("false");
            assert_eq!(failing.get(SERVICE, "a").unwrap(), None);
            assert!(failing.put(SERVICE, "a", b"siwc:00").is_err());
            failing.delete(SERVICE, "a").unwrap();
            assert!(platform::SystemKeychain("ls").delete(SERVICE, "a").is_err());
            assert!(failing.get("-flag", "a").is_err());
            assert!(failing.put(SERVICE, "a", b"bad\nline").is_err());
            assert!(failing.delete("-flag", "a").is_err());

            // `true` can exit before the secret is written to it, which then
            // fails with a broken pipe; this tool reads its input first.
            let succeeding = platform::SystemKeychain(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/suite/store/keychain_fixture/reading-tool.sh"
            ));
            assert_eq!(
                succeeding.get(SERVICE, "a").unwrap().unwrap().as_slice(),
                b""
            );
            succeeding.put(SERVICE, "a", b"siwc:00").unwrap();
            succeeding.delete(SERVICE, "a").unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_security_command_line_never_exceeds_what_security_reads_at_once() {
        let prefix = format!("add-generic-password -U -s {SERVICE} -a account-1 -w ");
        let fits = SECURITY_LINE_MAX - prefix.len() - 1;
        let secret = |len: usize| {
            let mut secret = HEX_PREFIX.to_vec();
            secret.resize(len, b'a');
            secret
        };

        let line = security_put_line(SERVICE, "account-1", &secret(fits)).unwrap();
        assert_eq!(line.len(), SECURITY_LINE_MAX);
        assert!(line.ends_with(b"aaa\n"));
        for too_long in [secret(fits + 1), encode_hex(&[0xa5; 3072]).to_vec()] {
            assert_eq!(
                security_put_line(SERVICE, "account-1", &too_long)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Store
            );
        }
        assert!(security_put_line(SERVICE, "-flag", &secret(8)).is_err());
    }
}
