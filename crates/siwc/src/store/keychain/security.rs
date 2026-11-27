//! The user's default keychain on macOS, through `/usr/bin/security` with
//! that keychain's path, so finding and adding reach the same keychain.

use std::process::Command;

use zeroize::Zeroizing;

use crate::error::Error;

use super::material::Lookup;
use super::security_scope::{default_keychain, found, one_word};
use super::{ACCOUNT, Backend, ServiceName, helper::Tool, tool_failed};

/// The system's own copy, so a program of the same name earlier in `PATH`
/// is never asked.
pub(super) const PROGRAM: &str = "/usr/bin/security";

impl Backend for Tool<'_> {
    /// Looks in the default keychain. A key the default keychain lacks is
    /// missing only if the search list lacks it too; that second lookup
    /// asks only whether an item exists, never for its secret.
    fn find(
        &self,
        service: &ServiceName,
        lookup: Lookup<'_>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let keychain = self.default_keychain(lookup)?;
        let (status, text, _) = self.output(self.find_command(service, Some(&keychain)), lookup)?;
        let found = found(status.code(), || {
            let (status, _attributes, _) = self.output(self.find_command(service, None), lookup)?;
            Ok(status.code())
        })?;
        Ok(found.then_some(text))
    }

    /// `security -i` reads the command from its standard input, so the key
    /// is on no command line. The service name is one word by its rule, and
    /// the keychain path must be one too.
    fn add(&self, service: &ServiceName, text: &[u8]) -> Result<(), Error> {
        let keychain = self.default_keychain(Lookup::default())?;
        let path = one_word(&keychain)?;
        let prefix = format!(
            "add-generic-password -s {} -a {ACCOUNT} -w ",
            service.as_str()
        );
        let mut line = Zeroizing::new(Vec::with_capacity(
            prefix.len() + text.len() + path.len() + 2,
        ));
        line.extend_from_slice(prefix.as_bytes());
        line.extend_from_slice(text);
        line.push(b' ');
        line.extend_from_slice(path.as_bytes());
        line.push(b'\n');
        let mut command = self.command();
        command.arg("-i");
        self.store(command, &line)
    }
}

impl Tool<'_> {
    /// The keychain that `add-generic-password` without a path would write
    /// to, resolved once per call so both commands name it.
    fn default_keychain(&self, lookup: Lookup<'_>) -> Result<String, Error> {
        let mut command = self.command();
        command.args(["default-keychain", "-d", "user"]);
        let (status, output, _) = self.output(command, lookup)?;
        if !status.success() {
            return Err(tool_failed());
        }
        default_keychain(&output).map(str::to_owned)
    }

    /// `find-generic-password` for the key: in `keychain`, printing its
    /// secret, or, without one, across the search list, printing only the
    /// item's attributes.
    fn find_command(&self, service: &ServiceName, keychain: Option<&str>) -> Command {
        let mut command = self.command();
        command
            .args(["find-generic-password", "-s", service.as_str()])
            .args(["-a", ACCOUNT]);
        if let Some(keychain) = keychain {
            command.args(["-w", keychain]);
        }
        command
    }
}
