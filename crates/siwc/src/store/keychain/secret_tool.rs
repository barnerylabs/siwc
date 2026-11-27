//! The Secret Service, through `secret-tool` from libsecret.

use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind};

use super::material::Lookup;
use super::{ACCOUNT, Backend, ServiceName, helper::Tool, tool_failed};

/// Found through `PATH`: distributions install it in different places.
pub(super) const PROGRAM: &str = "secret-tool";

fn attributes(service: &ServiceName) -> [&str; 4] {
    ["service", service.as_str(), "account", ACCOUNT]
}

impl Backend for Tool<'_> {
    /// `secret-tool lookup` fails silently both for a missing item and for
    /// one in a locked collection whose unlock prompt failed or was
    /// dismissed, and with a message otherwise, for example without a
    /// Secret Service on the session bus. Only a search that lists nothing
    /// proves the item missing.
    fn find(
        &self,
        service: &ServiceName,
        lookup: Lookup<'_>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let mut command = self.command();
        command.arg("lookup").args(attributes(service));
        let (status, text, stderr_empty) = self.output(command, lookup)?;
        if status.success() {
            Ok(Some(text))
        } else if status.code() == Some(1) && text.is_empty() && stderr_empty {
            self.prove_missing(service, lookup)?;
            Ok(None)
        } else {
            Err(tool_failed())
        }
    }

    /// `secret-tool store` reads the secret from its standard input.
    fn add(&self, service: &ServiceName, text: &[u8]) -> Result<(), Error> {
        let mut command = self.command();
        command
            .args(["store", "--label", service.as_str()])
            .args(attributes(service));
        self.store(command, text)
    }
}

impl Tool<'_> {
    /// `secret-tool search --all` lists an item of a locked collection
    /// without its secret and, without `--unlock`, never asks to unlock it.
    /// Its output can hold the secret of an unlocked item, so only whether
    /// it is empty is looked at.
    fn prove_missing(&self, service: &ServiceName, lookup: Lookup<'_>) -> Result<(), Error> {
        let mut command = self.command();
        command.args(["search", "--all"]).args(attributes(service));
        let (status, listed, _) = self.output(command, lookup)?;
        if !status.success() {
            Err(tool_failed())
        } else if listed.is_empty() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Store, "the keychain is locked"))
        }
    }
}
