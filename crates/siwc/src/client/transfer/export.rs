//! Save an account's bundle before leaving its source signed out.

use std::path::Path;

use crate::account::{AccountId, AccountState};
use crate::client::bundle;
use crate::client::entries::{account_mut, registration_rejected, sign_in_required};
use crate::client::{Client, Inner};
use crate::error::Error;
use crate::store::write_new_file;

impl Client {
    /// Creates a new file at `path` without replacing an existing destination,
    /// writes and syncs the passphrase-sealed bundle, and syncs the directory
    /// on Unix when supported. If the file system cannot sync the
    /// directory, a crash can still lose the new path even though the
    /// bundle file was synced. The source credentials are deleted and the
    /// account marked [`AccountState::SignedOut`] once these steps succeed.
    /// The provider session stays valid, so the target can renew it. Import
    /// requires the provider to still publish the key that signed the original
    /// ID token. If the session is old, signing in again before exporting
    /// obtains a fresh proof. Export does not contact the provider.
    ///
    /// Some file systems, including macOS SMB shares that reject
    /// `F_FULLFSYNC`, cannot sync the bundle file itself. Export fails in
    /// that case and leaves the source account signed in. Export to a local
    /// disk and copy the completed bundle to the share.
    ///
    /// Use a directory you control. As with [`PrivateFiles`](crate::store::PrivateFiles),
    /// the Unix file mode is owner-only, and the crate does not check access
    /// control lists. On macOS, choose a directory whose ACL keeps other
    /// users out. On Windows the file inherits the destination directory's
    /// DACL, and the directory is not synced. Anyone who can read the file
    /// through inherited permissions sees only passphrase-sealed ciphertext.
    ///
    /// Use the bundle only after this method succeeds. An output error
    /// attempts to remove the new file. A crash during the write can leave
    /// a truncated file that import rejects with
    /// [`ErrorKind::BundleRejected`](crate::ErrorKind::BundleRejected).
    /// If an error leaves a file at the new path, check the source
    /// account's state before importing it elsewhere. If saving the sign-out
    /// fails, credentials are restored only when the locked read-back still
    /// shows the original signed-in generation. If confirmation fails, the
    /// source can lack credentials even when its record says signed in.
    /// Keep the completed bundle until you can confirm which copy to use.
    ///
    /// ```no_run
    /// # fn example(client: &siwc::Client, id: &siwc::AccountId) -> Result<(), siwc::Error> {
    /// client.export_account_to(id, b"synthetic-passphrase", "account.bundle")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) when
    ///   `passphrase` is outside `8..=1024` bytes, the path does not name a
    ///   file, or the destination exists.
    /// - [`ErrorKind::UnknownAccount`](crate::ErrorKind::UnknownAccount)
    ///   when `id` is not in this installation.
    /// - [`ErrorKind::SignInRequired`](crate::ErrorKind::SignInRequired)
    ///   when the account has no usable session or its credentials carry
    ///   no ID token for the importer to verify.
    /// - [`ErrorKind::ClientRejected`](crate::ErrorKind::ClientRejected)
    ///   for a rejected registration.
    /// - Store and randomness errors, including
    ///   [`ErrorKind::Store`](crate::ErrorKind::Store) if the output cannot
    ///   be created, written or synced, or the session exceeds the 96 KiB bundle
    ///   limit. An oversized session leaves the destination and source untouched.
    ///   Directory sync errors indicating
    ///   lack of support (`EINVAL`, `ENOTSUP`, `EOPNOTSUPP`, `ENOSYS` or
    ///   `io::ErrorKind::Unsupported`) are tolerated. Other output errors
    ///   leave the source credentials in place.
    pub fn export_account_to(
        &self,
        id: &AccountId,
        passphrase: &[u8],
        path: impl AsRef<Path>,
    ) -> Result<(), Error> {
        bundle::check_passphrase(passphrase)?;
        self.inner.export_account_to(id, passphrase, path.as_ref())
    }
}

impl Inner {
    fn export_account_to(
        &self,
        id: &AccountId,
        passphrase: &[u8],
        path: &Path,
    ) -> Result<(), Error> {
        self.record(id, None)?;
        let _lock = self.lock_account(id)?;
        let (_, record) = self.record(id, None)?;
        match record.state {
            AccountState::RegistrationRejected => {
                self.remove_dead_credentials(id, None);
                return Err(registration_rejected());
            }
            AccountState::SignedOut | AccountState::SignInRequired => {
                return Err(sign_in_required());
            }
            AccountState::SignedIn => {}
        }
        let credentials = self
            .credentials(&record, None)?
            .ok_or_else(sign_in_required)?;
        if credentials.id_token().is_none()
            || (!credentials.has_refresh_token() && self.clock.now() >= credentials.expires_at())
        {
            return Err(sign_in_required());
        }

        let next_sign_out = record.next_sign_out()?;
        let sealed = bundle::seal(&record, &credentials, passphrase, self.entropy.as_ref())?;
        write_new_file(path, sealed.as_bytes())?;
        drop(sealed);

        // Remove credentials before marking SignedOut so a signed-out account
        // never keeps stored tokens; increment `sign_outs` so an in-flight
        // `sign_in_again` on this host cannot silently restore `SignedIn`.
        self.remove_credentials(id)?;
        if let Err(error) = self.change_installation(|installation| {
            let record = account_mut(installation, id)?;
            record.sign_outs = next_sign_out;
            if record.state != AccountState::RegistrationRejected {
                record.state = AccountState::SignedOut;
            }
            Ok(())
        }) {
            if self.record(id, None).is_ok_and(|(_, current)| {
                current.state == AccountState::SignedIn && current.sign_outs == record.sign_outs
            }) {
                let _ = self.write_credentials(id, &credentials);
            }
            return Err(error);
        }
        Ok(())
    }
}
