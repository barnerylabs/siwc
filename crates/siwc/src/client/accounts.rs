//! Listing the accounts and labelling them.

use crate::account::{Account, AccountId};
use crate::error::{Error, ErrorKind};

use super::Client;
use super::entries::{account_mut, unknown_account};
use super::records::is_label;

impl Client {
    /// Every account of this installation, in the order they were added.
    /// Reads the store; writes nothing.
    ///
    /// # Errors
    ///
    /// Store errors, among them [`ErrorKind::StoreCorrupt`].
    pub fn accounts(&self) -> Result<Vec<Account>, Error> {
        Ok(self
            .inner
            .installation(None)?
            .map(|installation| {
                installation
                    .accounts
                    .iter()
                    .map(|record| installation.snapshot(record))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// One account.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::UnknownAccount`]; store errors.
    pub fn account(&self, id: &AccountId) -> Result<Account, Error> {
        let (installation, record) = self.inner.record(id, None)?;
        Ok(installation.snapshot(&record))
    }

    /// Gives an account a label, such as "Work", or clears it with `None`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] unless the label is 1 to 64 characters
    /// without control, invisible or text-direction characters;
    /// [`ErrorKind::UnknownAccount`]; store errors.
    pub fn set_label(&self, id: &AccountId, label: Option<&str>) -> Result<(), Error> {
        if label.is_some_and(|label| !is_label(label)) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "a label must be 1 to 64 characters without control, invisible or text-direction characters",
            ));
        }
        self.inner.change_installation(|installation| {
            account_mut(installation, id)?.label = label.map(str::to_owned);
            Ok(())
        })
    }

    /// The account the app marked as selected in its UI or CLI with
    /// [`select_account`](Self::select_account), or `None` when none is
    /// selected.
    ///
    /// Selecting an account is purely a convenience pointer stored in the
    /// installation record so apps need no separate config file for their
    /// active picker state: token and API calls such as
    /// [`access_token`](Self::access_token) and [`call`](Self::call) still
    /// take an explicit [`AccountId`] and never fall back across accounts.
    /// [`forget`](Self::forget) clears the selection automatically when the
    /// selected account is removed.
    ///
    /// # Errors
    ///
    /// Store errors, among them [`ErrorKind::StoreCorrupt`].
    pub fn selected_account(&self) -> Result<Option<Account>, Error> {
        Ok(self.inner.installation(None)?.and_then(|installation| {
            let id = installation.selected.as_ref()?;
            installation.snapshot_of(id)
        }))
    }

    /// Marks `id` as the UI-selected account in the installation record, or
    /// clears the selection with `None`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::UnknownAccount`] when `id` is `Some` and does not belong
    /// to this installation; store errors.
    pub fn select_account(&self, id: Option<&AccountId>) -> Result<(), Error> {
        self.inner.change_installation(|installation| match id {
            Some(id) => {
                let inst = installation.as_mut().ok_or_else(unknown_account)?;
                if inst.account(id).is_none() {
                    return Err(unknown_account());
                }
                inst.selected = Some(id.clone());
                Ok(())
            }
            None => {
                if let Some(inst) = installation.as_mut() {
                    inst.selected = None;
                }
                Ok(())
            }
        })
    }
}
