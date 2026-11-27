//! A platform without a keychain this crate knows.

use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind};

use super::material::Lookup;
use super::{Backend, ServiceName};

pub(super) struct Tool;

fn unsupported() -> Error {
    Error::new(ErrorKind::Store, "this platform has no supported keychain")
}

impl Backend for Tool {
    fn find(&self, _: &ServiceName, _: Lookup<'_>) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        Err(unsupported())
    }

    fn add(&self, _: &ServiceName, _: &[u8]) -> Result<(), Error> {
        Err(unsupported())
    }
}
