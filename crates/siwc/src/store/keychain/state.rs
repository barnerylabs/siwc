//! Private metadata for key generations, completed resets and services.

use crate::error::{Error, ErrorKind};

use super::{Keychain, ServiceName, service};

const GENERATION_FILE: &str = ".sealing-key.generation";
const RESETS_FILE: &str = ".sealing-key.resets";
const CLEARED_FILE: &str = ".sealing-key.cleared";
const SERVICE_FILE: &str = ".sealing-key.service";

pub(super) struct ClearedReset {
    pub(super) generation: u64,
    pub(super) same_service: bool,
}

/// The latest reset, completed reset, and clean abort before any removal.
/// Activations leave both counters alone, even if several follow a reset.
#[derive(Default)]
pub(super) struct ResetHistory {
    pub(super) started: u64,
    pub(super) aborted: u64,
    pub(super) completed: u64,
    pub(super) prior_unsettled: bool,
}

impl Keychain {
    pub(in crate::store) fn generation(&self) -> Result<u64, Error> {
        let Some(stored) = self.files.read_metadata(GENERATION_FILE, 8)? else {
            return Ok(0);
        };
        let bytes = stored
            .expose()
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Store, "the sealing key generation is invalid"))?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn next_generation(&self) -> Result<u64, Error> {
        self.generation()?
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::Store, "the sealing key generation is exhausted"))
    }

    fn publish_generation(&self, next: u64) -> Result<(), Error> {
        self.files
            .write_metadata(GENERATION_FILE, &next.to_le_bytes())
    }

    pub(super) fn bump_generation(&self) -> Result<(), Error> {
        self.publish_generation(self.next_generation()?)
    }

    pub(super) fn begin_reset(&self) -> Result<ResetHistory, Error> {
        let previous = self.reset_history()?;
        let reset = ResetHistory {
            started: self.next_generation()?,
            aborted: 0,
            prior_unsettled: previous.started > previous.completed
                && previous.aborted != previous.started,
            ..previous
        };
        self.record_reset(&reset)?;
        self.publish_generation(reset.started)?;
        Ok(reset)
    }

    pub(super) fn record_reset(&self, reset: &ResetHistory) -> Result<(), Error> {
        let mut record = [0; 24];
        record[..8].copy_from_slice(&reset.started.to_le_bytes());
        record[8..16].copy_from_slice(&reset.aborted.to_le_bytes());
        record[16..].copy_from_slice(&reset.completed.to_le_bytes());
        self.files.write_metadata(RESETS_FILE, &record)
    }

    pub(super) fn reset_history(&self) -> Result<ResetHistory, Error> {
        let Some(record) = self.files.read_metadata(RESETS_FILE, 24)? else {
            return Ok(ResetHistory::default());
        };
        let invalid = || Error::new(ErrorKind::Store, "the sealing key reset history is invalid");
        let (started, aborted) = record
            .expose()
            .split_first_chunk::<8>()
            .ok_or_else(invalid)?;
        let started = u64::from_le_bytes(*started);
        let (aborted, completed) = aborted.split_first_chunk::<8>().ok_or_else(invalid)?;
        let aborted = u64::from_le_bytes(*aborted);
        let completed = u64::from_le_bytes(completed.try_into().map_err(|_| invalid())?);
        if completed > started || (aborted != 0 && (aborted != started || aborted <= completed)) {
            return Err(invalid());
        }
        Ok(ResetHistory {
            started,
            aborted,
            completed,
            prior_unsettled: false,
        })
    }

    pub(super) fn record_cleared_reset(&self, generation: u64) -> Result<(), Error> {
        let mut record = generation.to_le_bytes().to_vec();
        record.extend_from_slice(self.service.as_str().as_bytes());
        self.files.write_metadata(CLEARED_FILE, &record)
    }

    /// Only the current generation can still have a cleared reset. Any
    /// subsequent activation or reset makes the old record obsolete.
    pub(super) fn cleared_reset(&self) -> Result<Option<ClearedReset>, Error> {
        let Some(record) = self
            .files
            .read_metadata(CLEARED_FILE, 8 + service::MAX_LEN)?
        else {
            return Ok(None);
        };
        let generation = self.generation()?;
        Ok(record
            .expose()
            .strip_prefix(&generation.to_le_bytes())
            .map(|service| ClearedReset {
                generation,
                same_service: service.eq_ignore_ascii_case(self.service.as_str().as_bytes()),
            }))
    }

    pub(super) fn recorded_service(&self) -> Result<Option<ServiceName>, Error> {
        let Some(stored) = self.files.read_metadata(SERVICE_FILE, service::MAX_LEN)? else {
            return Ok(None);
        };
        std::str::from_utf8(stored.expose())
            .ok()
            .and_then(|name| ServiceName::new(name).ok())
            .map(Some)
            .ok_or_else(|| Error::new(ErrorKind::Store, "the recorded keychain service is invalid"))
    }

    pub(super) fn record_service(&self) -> Result<(), Error> {
        self.files
            .write_metadata(SERVICE_FILE, self.service.as_str().as_bytes())
    }

    pub(super) fn require_configured_service(
        &self,
        recorded: Option<&ServiceName>,
        has_sealed_entries: impl FnOnce() -> Result<bool, Error>,
    ) -> Result<(), Error> {
        if recorded.is_some_and(|service| self.unconfigured_service(service))
            && has_sealed_entries()?
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "the store uses a different keychain service that must be listed with with_retired",
            ));
        }
        Ok(())
    }

    pub(in crate::store) fn require_readable_service(&self) -> Result<(), Error> {
        if self
            .recorded_service()?
            .as_ref()
            .is_some_and(|service| self.unconfigured_service(service))
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "another keychain service sealed the store and this release cannot read it",
            ));
        }
        Ok(())
    }

    fn unconfigured_service(&self, service: &ServiceName) -> bool {
        *service != self.service && !self.retired.contains(service)
    }
}
