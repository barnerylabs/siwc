//! Which keys approved resets could read, even when they removed nothing.

use ring::digest::{self, SHA256, SHA256_OUTPUT_LEN};

use crate::error::{Error, ErrorKind};
use crate::store::{KEY_LEN, MAX_RETIRED_KEYS};

use super::Keychain;
use super::state::ResetHistory;

const RESET_KEYS_FILE: &str = ".sealing-key.reset-keys";
const RESET_KEYS_NEXT_FILE: &str = ".sealing-key.reset-keys.next";
const RECORD_LEN: usize = 8 + SHA256_OUTPUT_LEN;
const LIMIT: usize = 8 + (1 + MAX_RETIRED_KEYS) * RECORD_LEN;

pub(in crate::store) enum ResetSince {
    None,
    Unrecorded {
        prior: Option<ResetKeys>,
        provisional: Option<ResetKeys>,
    },
    Checked(ResetKeys),
}

pub(in crate::store) struct ResetKeys {
    generation: u64,
    readable: Vec<ReadableKey>,
    file_name: &'static str,
}

struct ReadableKey {
    fingerprint: [u8; SHA256_OUTPUT_LEN],
    // The latest checked reset that did not read this key.
    last_missing: u64,
}

impl ResetKeys {
    pub(in crate::store) fn kept(&self, key: &[u8; KEY_LEN], generation: u64) -> bool {
        self.last_missing(digest::digest(&SHA256, key).as_ref()) <= generation
    }

    fn last_missing(&self, fingerprint: &[u8]) -> u64 {
        self.readable
            .iter()
            .find(|key| key.fingerprint == fingerprint)
            .map_or(self.generation, |key| key.last_missing)
    }
}

impl Keychain {
    /// Called while holding either coordination lock, after noticing a new
    /// generation. A completed inventory matters even with no deletion.
    pub(in crate::store) fn reset_since(&self, generation: u64) -> Result<ResetSince, Error> {
        let history = self.reset_history()?;
        if history.started <= generation {
            return Ok(ResetSince::None);
        }
        let prior = self
            .reset_keys(history.completed)?
            .filter(|keys| keys.generation > generation);
        if history.started > history.completed {
            if history.aborted != history.started {
                return Ok(ResetSince::Unrecorded {
                    prior,
                    provisional: self.uncompleted_reset_keys(history.completed, history.started)?,
                });
            }
            return Ok(if history.completed > generation {
                prior.map_or(
                    ResetSince::Unrecorded {
                        prior: None,
                        provisional: None,
                    },
                    ResetSince::Checked,
                )
            } else {
                ResetSince::None
            });
        }
        Ok(prior.map_or(
            ResetSince::Unrecorded {
                prior: None,
                provisional: None,
            },
            ResetSince::Checked,
        ))
    }

    /// The record is bounded by the number of configured keys. A key absent
    /// from the latest completed view was last missing in that generation.
    pub(super) fn record_reset_keys<'a>(
        &self,
        reset: &ResetHistory,
        readable: impl IntoIterator<Item = &'a [u8; KEY_LEN]>,
    ) -> Result<(), Error> {
        let previous = self.reset_keys(reset.completed)?;
        let mut record = Vec::with_capacity(LIMIT);
        record.extend_from_slice(&reset.started.to_le_bytes());
        for key in readable {
            let fingerprint = digest::digest(&SHA256, key);
            let last_missing = previous.as_ref().map_or(reset.completed, |previous| {
                previous.last_missing(fingerprint.as_ref())
            });
            record.extend_from_slice(&last_missing.to_le_bytes());
            record.extend_from_slice(fingerprint.as_ref());
        }
        // Keep the last completed view intact until the new reset commits.
        let target = if previous
            .as_ref()
            .is_some_and(|keys| keys.file_name == RESET_KEYS_FILE)
        {
            RESET_KEYS_NEXT_FILE
        } else {
            RESET_KEYS_FILE
        };
        self.files.write_metadata(target, &record)?;
        #[cfg(all(test, target_os = "linux", feature = "testing"))]
        if let Some(elapsed) = self
            .timing
            .as_ref()
            .and_then(|timing| timing.expire_after_reset_keys.as_ref())
        {
            elapsed.store(31, std::sync::atomic::Ordering::Release);
        }
        Ok(())
    }

    fn reset_keys(&self, completed: u64) -> Result<Option<ResetKeys>, Error> {
        let first = self.read_reset_keys(RESET_KEYS_FILE)?;
        let second = self.read_reset_keys(RESET_KEYS_NEXT_FILE)?;
        let first = first.filter(|keys| keys.generation == completed);
        let second = second.filter(|keys| keys.generation == completed);
        match (first, second) {
            (Some(_), Some(_)) => Err(invalid_history()),
            (first, second) => Ok(first.or(second)),
        }
    }

    fn uncompleted_reset_keys(
        &self,
        completed: u64,
        started: u64,
    ) -> Result<Option<ResetKeys>, Error> {
        let first = self.read_reset_keys(RESET_KEYS_FILE)?;
        let second = self.read_reset_keys(RESET_KEYS_NEXT_FILE)?;
        Ok(first
            .into_iter()
            .chain(second)
            .filter(|keys| keys.generation > completed && keys.generation <= started)
            .max_by_key(|keys| keys.generation))
    }

    fn read_reset_keys(&self, file_name: &'static str) -> Result<Option<ResetKeys>, Error> {
        let Some(record) = self.files.read_metadata(file_name, LIMIT)? else {
            return Ok(None);
        };
        let (generation, keys) = record
            .expose()
            .split_first_chunk::<8>()
            .ok_or_else(invalid_history)?;
        let generation = u64::from_le_bytes(*generation);
        let (records, remainder) = keys.as_chunks::<RECORD_LEN>();
        if generation == 0 || !remainder.is_empty() {
            return Err(invalid_history());
        }
        let mut readable = Vec::with_capacity(records.len());
        for record in records {
            let (last_missing, fingerprint) = record
                .split_first_chunk::<8>()
                .ok_or_else(invalid_history)?;
            let last_missing = u64::from_le_bytes(*last_missing);
            if last_missing >= generation {
                return Err(invalid_history());
            }
            let fingerprint = fingerprint.try_into().map_err(|_| invalid_history())?;
            readable.push(ReadableKey {
                fingerprint,
                last_missing,
            });
        }
        Ok(Some(ResetKeys {
            generation,
            readable,
            file_name,
        }))
    }
}

fn invalid_history() -> Error {
    Error::new(ErrorKind::Store, "the sealing key reset history is invalid")
}
