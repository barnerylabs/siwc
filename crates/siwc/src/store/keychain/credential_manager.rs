//! The Credential Manager of Windows, through `windows-native-keyring-store`.
//!
//! Windows ships no command-line tool that reads a stored secret back
//! (`cmdkey` never prints one), and calling `CredReadW` directly needs the
//! `unsafe` the workspace forbids.

use std::collections::HashMap;

use keyring_core::Entry;
use keyring_core::api::CredentialStoreApi;
use windows_native_keyring_store::Store;
use zeroize::Zeroizing;

use crate::error::Error;

use super::material::Lookup;
use super::{ACCOUNT, Backend, ServiceName, tool_failed};

pub(super) struct Tool;

/// The credential: `Local` keeps it on this computer, where the store's
/// files are, instead of roaming with the user's profile.
fn entry(service: &ServiceName) -> Result<Entry, Error> {
    let store = Store::new().map_err(|_| tool_failed())?;
    let target = service.credential_target();
    let modifiers = HashMap::from([("persistence", "Local"), ("target", target.as_str())]);
    store
        .build(service.as_str(), ACCOUNT, Some(&modifiers))
        .map_err(|_| tool_failed())
}

impl Backend for Tool {
    fn find(
        &self,
        service: &ServiceName,
        _lookup: Lookup<'_>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        match entry(service)?.get_secret() {
            Ok(text) => Ok(Some(Zeroizing::new(text))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(_) => Err(tool_failed()),
        }
    }

    /// The crate copies `text` into buffers it does not wipe.
    fn add(&self, service: &ServiceName, text: &[u8]) -> Result<(), Error> {
        entry(service)?.set_secret(text).map_err(|_| tool_failed())
    }
}
