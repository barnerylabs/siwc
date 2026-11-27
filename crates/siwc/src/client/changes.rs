//! What changed in the accounts since the app last looked.

use crate::account::Account;
use crate::error::Error;

use super::Client;

/// One account's change between two looks at the accounts.
///
/// Each variant carries an account snapshot, which holds no token or other
/// secret; `Debug` shows what [`Account`]'s `Debug` shows.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// An account that was not there before, such as one a sign-in in
    /// another process added.
    Added(Account),
    /// An account whose snapshot differs, with the new snapshot: another
    /// state (signed out, a renewal that ended in
    /// [`AccountState::SignInRequired`](crate::AccountState::SignInRequired)),
    /// plan use, label, verified identity, or the accounts that share its
    /// login.
    Changed(Account),
    /// An account that is gone, with the last snapshot seen of it, so the
    /// app can still name it.
    Removed(Account),
}

/// The accounts as the app last saw them, to compare with the store.
///
/// [`Client::changes`] makes one; [`poll`](Self::poll) reads the accounts
/// again and returns what changed. Nothing here waits or runs on its own:
/// changes made by another process, such as a command-line tool or a second
/// instance of the app sharing the same store, reach this one through the
/// store when the app polls, for example from its window's timer.
#[derive(Debug, Clone)]
#[must_use = "call `Changes::poll` to observe account updates"]
pub struct Changes {
    client: Client,
    accounts: Vec<Account>,
}

impl Client {
    /// Takes a snapshot of the accounts now, to see later what changed.
    ///
    /// ```no_run
    /// use siwc::{Change, Client};
    ///
    /// # fn window_timer(client: &Client) -> Result<(), siwc::Error> {
    /// let mut changes = client.changes()?;
    /// // Each tick of the window's timer:
    /// for change in changes.poll()? {
    ///     match change {
    ///         Change::Added(account) => println!("{} was added", account.id()),
    ///         Change::Changed(account) => println!("{} is {:?}", account.id(), account.state()),
    ///         Change::Removed(account) => println!("{} is gone", account.id()),
    ///         _ => {}
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The errors of [`accounts`](Self::accounts).
    pub fn changes(&self) -> Result<Changes, Error> {
        Ok(Changes {
            client: self.clone(),
            accounts: self.accounts()?,
        })
    }
}

impl Changes {
    /// The latest snapshot of stored accounts (from [`Client::changes`] or the
    /// most recent successful [`poll`](Self::poll)).
    #[must_use]
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Reads the accounts again and returns what changed since the last
    /// snapshot, which the new one then replaces. Empty when nothing
    /// changed.
    ///
    /// The order is stable: added and changed accounts in the order the
    /// accounts are listed, then removed ones in the order they were
    /// listed before.
    ///
    /// # Errors
    ///
    /// The errors of [`Client::accounts`]; the last snapshot is kept, so
    /// the next poll reports the same changes.
    pub fn poll(&mut self) -> Result<Vec<Change>, Error> {
        let accounts = self.client.accounts()?;
        let changes = compare(&self.accounts, &accounts);
        self.accounts = accounts;
        Ok(changes)
    }
}

/// What differs from `before` to `after`.
fn compare(before: &[Account], after: &[Account]) -> Vec<Change> {
    let mut changes: Vec<Change> = after
        .iter()
        .filter_map(
            |account| match before.iter().find(|old| old.id == account.id) {
                None => Some(Change::Added(account.clone())),
                Some(old) if old != account => Some(Change::Changed(account.clone())),
                Some(_) => None,
            },
        )
        .collect();
    changes.extend(
        before
            .iter()
            .filter(|old| after.iter().all(|account| account.id != old.id))
            .cloned()
            .map(Change::Removed),
    );
    changes
}
