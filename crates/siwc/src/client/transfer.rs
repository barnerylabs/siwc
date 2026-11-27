//! Moving a signed-in account to another installation as a sealed bundle.

mod export;

use ring::digest::{SHA256, digest};

use crate::account::{Account, AccountId, AccountState};
use crate::error::{Error, ErrorKind};
use crate::host::HostId;
use crate::protocol::{Identity, base64url, verify_bundle_identity};

use super::bundle::{self, UnpackedAccount};
use super::entries::{account_mut, registration_rejected, sign_in_required, unknown_account};
use super::records::{AccountRecord, Installation, MAX_ACCOUNTS};
use super::{Client, Inner};

impl Client {
    /// Largest account bundle, in bytes, that
    /// [`export_account_to`](Self::export_account_to) writes and
    /// [`import_account`](Self::import_account) accepts (96 KiB). An app that
    /// reads a bundle file can stop reading one byte past it.
    pub const MAX_BUNDLE_LEN: usize = bundle::MAX_BUNDLE_LEN;

    /// Decrypts `bundle` with `passphrase` and stores the account in this
    /// installation, preserving this installation's own [`HostId`] (or
    /// generating a fresh one when this is its first account).
    ///
    /// Import fetches the provider's current signing keys through the
    /// client's transport. The original ID token proves the subject and
    /// supplies all display claims; its expiry is ignored because it can
    /// be older than the moved session. Import only bundles from a trusted
    /// source: the ID token does not authenticate the other tokens or scopes
    /// in the bundle.
    ///
    /// When an account with the bundle's `IssuedClientId` already exists here
    /// for the same verified subject, its credentials are replaced under its
    /// lock when the bundle carries a different sign-in; the replaced
    /// session is not revoked and stays valid at the provider until it
    /// expires. Re-importing the same sign-in keeps the active credentials,
    /// including rotated tokens.
    /// An exact repeat of the last completed import returns the current
    /// account without applying the bundle again, except to correct an
    /// older import's identity when it still holds the same sign-in. If no
    /// active credentials remain, that repeat returns [`ErrorKind::SignInRequired`].
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::InvalidInput`] when `passphrase` is outside `8..=1024`
    ///   bytes.
    /// - [`ErrorKind::BundleRejected`] when `bundle` is damaged, truncated,
    ///   larger than 96 KiB, does not open under `passphrase`, or lacks an ID
    ///   token that verifies for its issued client ID and subject.
    /// - Transport and signing-key response errors. These, and rejected
    ///   bundles, are reported before accessing the store.
    /// - [`ErrorKind::AccountLimit`] when the installation already holds 32
    ///   other accounts.
    /// - [`ErrorKind::AccountMismatch`] or [`ErrorKind::ClientRejected`] when
    ///   the existing local record for that registration conflicts with the
    ///   bundle or was rejected by the provider.
    /// - [`ErrorKind::SignInRequired`] for a previously imported session that
    ///   has since ended; [`ErrorKind::UnknownAccount`] if the account was
    ///   forgotten before import acquired its lock.
    /// - Store and randomness errors; the bundle's remote session is never
    ///   revoked on a failed import, so the caller can retry with the same
    ///   bundle.
    pub fn import_account(&self, bundle: &[u8], passphrase: &[u8]) -> Result<Account, Error> {
        self.inner.import_account(bundle, passphrase)
    }
}

impl Inner {
    fn import_account(&self, bundle: &[u8], passphrase: &[u8]) -> Result<Account, Error> {
        let unpacked = bundle::open(bundle, passphrase)?;
        let token = unpacked
            .credentials
            .id_token()
            .ok_or_else(unverified_bundle)?;
        let keys = self
            .provider_keys()
            .map_err(|error| unpacked.credentials.without_credential_echo(error))?;
        let identity = verify_bundle_identity(
            token,
            &keys,
            &unpacked.client_id,
            unpacked.credentials.subject(),
            self.clock.now(),
        )
        .map_err(|_| unverified_bundle())?;
        let receipt = base64url::encode(digest(&SHA256, bundle).as_ref());
        if let Some(existing_id) = self.existing_for_client(&unpacked.client_id)? {
            return self.import_into_existing(&existing_id, unpacked, identity, receipt);
        }
        self.import_as_new(unpacked, identity, receipt)
    }

    fn existing_for_client(
        &self,
        client_id: &crate::protocol::IssuedClientId,
    ) -> Result<Option<AccountId>, Error> {
        Ok(self.installation(None)?.and_then(|installation| {
            installation
                .accounts
                .iter()
                .find(|record| record.client_id == *client_id)
                .map(|record| record.id.clone())
        }))
    }

    fn import_into_existing(
        &self,
        id: &AccountId,
        unpacked: UnpackedAccount,
        identity: Identity,
        receipt: String,
    ) -> Result<Account, Error> {
        let _lock = self.lock_account(id)?;
        let (installation, record) = self.record(id, None)?;
        if record.state == AccountState::RegistrationRejected {
            self.remove_dead_credentials(id, None);
            return Err(registration_rejected());
        }
        if record.client_id != unpacked.client_id || record.identity.subject() != identity.subject()
        {
            return Err(Error::new(
                ErrorKind::AccountMismatch,
                "the bundle belongs to a different account than the stored registration",
            ));
        }
        let active = if record.state == AccountState::SignedIn {
            self.credentials(&record, None)?
        } else {
            None
        };
        if record.bundle_receipt.as_deref() == Some(receipt.as_str()) {
            let active = active.ok_or_else(sign_in_required)?;
            if !active.same_sign_in(&unpacked.credentials) || record.identity == identity {
                return Ok(installation.snapshot(&record));
            }
            // An older import may have used display claims from the payload.
            // Repair only those claims, leaving later local edits in place.
            return self.change_installation(|installation| {
                account_mut(installation, id)?.identity = identity;
                installation
                    .as_ref()
                    .and_then(|inst| inst.snapshot_of(id))
                    .ok_or_else(unknown_account)
            });
        }

        let successor = active.filter(|current| current.same_sign_in(&unpacked.credentials));
        if successor.is_none() {
            self.write_credentials(id, &unpacked.credentials)?;
        }
        let plan_use = successor
            .as_ref()
            .unwrap_or(&unpacked.credentials)
            .scopes()
            .grants_plan_use();
        let sign_outs = record.sign_outs;
        self.change_installation(|installation| {
            let record = account_mut(installation, id)?;
            if record.state == AccountState::RegistrationRejected {
                return Err(registration_rejected());
            }
            if record.sign_outs != sign_outs {
                return Err(sign_in_required());
            }
            record.identity = identity;
            if record.label.is_none() {
                record.label = unpacked.label;
            }
            record.state = AccountState::SignedIn;
            record.plan_use = plan_use;
            record.welcomed |= unpacked.welcomed;
            record.bundle_receipt = Some(receipt);
            installation
                .as_ref()
                .and_then(|inst| inst.snapshot_of(id))
                .ok_or_else(unknown_account)
        })
    }

    fn import_as_new(
        &self,
        unpacked: UnpackedAccount,
        identity: Identity,
        receipt: String,
    ) -> Result<Account, Error> {
        let id = AccountId::generate(self.entropy.as_ref())?;
        let plan_use = unpacked.credentials.scopes().grants_plan_use();
        let welcomed = unpacked.welcomed;
        let staged = AccountRecord {
            id: id.clone(),
            client_id: unpacked.client_id.clone(),
            registered_as: unpacked.registered_as.clone(),
            label: unpacked.label.clone(),
            identity: identity.clone(),
            state: AccountState::SignInRequired,
            plan_use: false,
            welcomed: false,
            sign_outs: 0,
            bundle_receipt: None,
        };
        enum Stage {
            Staged,
            Existing(AccountId),
        }
        let lock = self.lock_account(&id)?;
        let outcome = self.change_installation(|installation| {
            let installation = match installation {
                Some(existing) => existing,
                empty => empty.insert(Installation::new(HostId::generate_inner(
                    self.entropy.as_ref(),
                )?)),
            };
            if let Some(other) = installation
                .accounts
                .iter()
                .find(|other| other.client_id == staged.client_id)
            {
                return Ok(Stage::Existing(other.id.clone()));
            }
            if installation.accounts.len() >= MAX_ACCOUNTS {
                return Err(Error::new(
                    ErrorKind::AccountLimit,
                    "the installation already holds 32 accounts",
                ));
            }
            if installation.account(&id).is_some() {
                return Err(Error::new(
                    ErrorKind::Randomness,
                    "the random source repeated an account ID",
                ));
            }
            if installation
                .pending
                .as_ref()
                .is_some_and(|pending| pending.client_id == staged.client_id)
            {
                installation.pending.take();
            }
            installation.accounts.push(staged);
            Ok(Stage::Staged)
        })?;
        match outcome {
            Stage::Staged => {}
            Stage::Existing(existing_id) => {
                drop(lock);
                return self.import_into_existing(&existing_id, unpacked, identity, receipt);
            }
        }

        // The write may have published before reporting an error. Leave the
        // staged account in place until a later read can resolve it.
        self.write_credentials(&id, &unpacked.credentials)?;
        self.change_installation(|installation| {
            let record = account_mut(installation, &id)?;
            if record.state != AccountState::SignInRequired || record.sign_outs != 0 {
                return Err(sign_in_required());
            }
            record.state = AccountState::SignedIn;
            record.plan_use = plan_use;
            record.welcomed = welcomed;
            record.bundle_receipt = Some(receipt);
            installation
                .as_ref()
                .and_then(|inst| inst.snapshot_of(&id))
                .ok_or_else(unknown_account)
        })
    }
}

fn unverified_bundle() -> Error {
    Error::new(
        ErrorKind::BundleRejected,
        "the account bundle has no verifiable ID token; sign in again at the source",
    )
}
