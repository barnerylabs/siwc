//! Private metadata whose names are outside the entry namespace.

use crate::error::Error;
use crate::store::Stored;

use super::{PrivateFiles, atomic, failed, privacy};

impl PrivateFiles {
    pub(in crate::store) fn read_metadata(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Option<Stored>, Error> {
        self.read_file(&self.dir.join(name), limit)
    }

    /// Publishes file-synced coordination metadata before a caller changes a
    /// key or deletes entries. The directory is synced where supported.
    pub(in crate::store) fn write_metadata(&self, name: &str, value: &[u8]) -> Result<(), Error> {
        self.check_dir()?;
        atomic::replace(&self.dir, "key-metadata", &self.dir.join(name), value)
            .and_then(|()| privacy::sync_dir_if_supported(&self.dir))
            .map_err(|_| failed("the sealing key metadata could not be written"))
    }
}
