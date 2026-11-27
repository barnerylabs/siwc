//! A store and a transport that write what happens into one journal, and
//! fail on request: the tests read the order of locks, writes and requests
//! from it.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use siwc::protocol::{HttpRequest, HttpResponse};
use siwc::store::{EntryName, Lock, MemoryStore, Store, Stored};
use siwc::{Error, Transport};

use super::provider::{FakeProvider, JWKS_URL, MODELS_URL, REVOKE_URL, TOKEN_URL};
use super::wire::{form_decode, optional};

/// Events in the order they happened, such as `lock account-…`,
/// `send refresh` or `write installation`.
#[derive(Clone, Default)]
pub struct Journal(Arc<Mutex<Vec<String>>>);

impl Journal {
    pub fn push(&self, event: String) {
        self.0.lock().unwrap().push(event);
    }

    pub fn events(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }

    pub fn count(&self, event: &str) -> usize {
        self.events().iter().filter(|seen| *seen == event).count()
    }

    /// The events that name `what`, such as `account-…` or `send`.
    /// Fails unless everything recorded so far kept the lock rules of the
    /// client: no request while the installation lock is held, an account
    /// lock never taken after the installation lock, never two account
    /// locks at once, and every lock released. For a journal that one
    /// thread wrote.
    pub fn assert_lock_rules(&self) {
        let events = self.events();
        let mut installation = false;
        let mut account: Option<&str> = None;
        for (index, event) in events.iter().enumerate() {
            let context = || format!("event {index} of {events:#?}");
            if let Some(name) = event.strip_prefix("lock ") {
                if name == "installation" {
                    assert!(!installation, "{}", context());
                    installation = true;
                } else {
                    assert!(
                        !installation,
                        "an account lock under the installation lock: {}",
                        context()
                    );
                    assert!(
                        account.is_none(),
                        "two account locks at once: {}",
                        context()
                    );
                    account = Some(name);
                }
            } else if let Some(name) = event.strip_prefix("unlock ") {
                if name == "installation" {
                    assert!(installation, "{}", context());
                    installation = false;
                } else {
                    assert_eq!(account, Some(name), "{}", context());
                    account = None;
                }
            } else if event.starts_with("send ") {
                assert!(
                    !installation,
                    "a request under the installation lock: {}",
                    context()
                );
            }
        }
        assert!(
            !installation && account.is_none(),
            "a lock was never released"
        );
    }

    pub fn about(&self, what: &str) -> Vec<String> {
        self.events()
            .into_iter()
            .filter(|event| event.contains(what))
            .collect()
    }
}

/// A [`MemoryStore`] that records writes, removals and locks.
pub struct RecordingStore {
    inner: MemoryStore,
    journal: Journal,
    /// Names ever written, to compare whole snapshots.
    names: Mutex<BTreeSet<String>>,
    failing_writes: Mutex<Vec<(String, Error)>>,
    /// Writes left before the store stops taking changes; `None` for no
    /// limit.
    changes_left: Mutex<Option<usize>>,
    /// Writes left before one write fails; `None` for no such failure.
    writes_before_one_fails: Mutex<Option<usize>>,
    pub fail_after_publish: Mutex<Option<bool>>,
    fail_next_read: Mutex<bool>,
    failing_removes: Mutex<bool>,
    /// A lock of an entry whose name starts with this is busy.
    busy_locks: Mutex<Option<String>>,
    /// Runs once, before the next lock of an entry whose name starts with
    /// the text is taken.
    before_lock: Mutex<Option<(String, Hook)>>,
}

/// What another process does at a moment the test chose.
type Hook = Box<dyn FnOnce() + Send>;

impl RecordingStore {
    pub fn new(journal: Journal) -> Self {
        Self {
            inner: MemoryStore::new(),
            journal,
            names: Mutex::new(BTreeSet::new()),
            failing_writes: Mutex::new(Vec::new()),
            changes_left: Mutex::new(None),
            writes_before_one_fails: Mutex::new(None),
            fail_after_publish: Mutex::default(),
            fail_next_read: Mutex::default(),
            failing_removes: Mutex::new(false),
            busy_locks: Mutex::new(None),
            before_lock: Mutex::new(None),
        }
    }

    /// Writes to `name` fail from now on; a name that ends in `-` stands
    /// for every entry that starts with it.
    pub fn fail_writes_to(&self, name: &str) {
        self.fail_writes_with(name, Error::store_failed());
    }

    pub fn fail_writes_with(&self, name: &str, error: Error) {
        self.failing_writes
            .lock()
            .unwrap()
            .push((name.to_owned(), error));
    }

    /// After `writes` more writes the store takes no change at all, as if
    /// the process had been cut off at that point.
    pub fn cut_off_after(&self, writes: usize) {
        *self.changes_left.lock().unwrap() = Some(writes);
    }

    /// After `writes` more writes, one write fails; the ones after it
    /// succeed again.
    pub fn fail_one_write_after(&self, writes: usize) {
        *self.writes_before_one_fails.lock().unwrap() = Some(writes);
    }

    /// Removals fail from now on.
    pub fn fail_removes(&self) {
        *self.failing_removes.lock().unwrap() = true;
    }

    /// Locks of entries whose name starts with `prefix` are held by
    /// somebody else from now on.
    pub fn fail_locks_of(&self, prefix: &str) {
        *self.busy_locks.lock().unwrap() = Some(prefix.to_owned());
    }

    /// Ends every failure set with the methods above.
    pub fn heal(&self) {
        self.failing_writes.lock().unwrap().clear();
        *self.changes_left.lock().unwrap() = None;
        *self.writes_before_one_fails.lock().unwrap() = None;
        *self.failing_removes.lock().unwrap() = false;
        *self.busy_locks.lock().unwrap() = None;
    }

    /// Runs `hook` once, right before the next lock of an entry whose name
    /// starts with `prefix` is taken: the moment another process gets in.
    pub fn before_next_lock_of(&self, prefix: &str, hook: impl FnOnce() + Send + 'static) {
        *self.before_lock.lock().unwrap() = Some((prefix.to_owned(), Box::new(hook)));
    }

    fn is_cut_off(&self) -> bool {
        *self.changes_left.lock().unwrap() == Some(0)
    }

    /// The bytes of one entry.
    pub fn bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.inner
            .read(&EntryName::new(name).unwrap())
            .unwrap()
            .map(|stored| stored.expose().to_vec())
    }

    /// Writes `bytes` behind the client's back.
    pub fn put(&self, name: &str, bytes: &[u8]) {
        self.names.lock().unwrap().insert(name.to_owned());
        self.inner
            .write(&EntryName::new(name).unwrap(), bytes)
            .unwrap();
    }

    /// Every entry that exists, with its bytes.
    pub fn snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let names = self.names.lock().unwrap().clone();
        names
            .into_iter()
            .filter_map(|name| self.bytes(&name).map(|bytes| (name, bytes)))
            .collect()
    }
}

impl Store for RecordingStore {
    fn read(&self, entry: &EntryName) -> Result<Option<Stored>, Error> {
        if std::mem::take(&mut *self.fail_next_read.lock().unwrap()) {
            return Err(Error::store_failed());
        }
        self.inner.read(entry)
    }

    fn write(&self, entry: &EntryName, value: &[u8]) -> Result<(), Error> {
        let refused = self
            .failing_writes
            .lock()
            .unwrap()
            .iter()
            .find(|(name, _)| {
                name == entry.as_str() || (name.ends_with('-') && entry.as_str().starts_with(name))
            })
            .map(|(_, error)| error.clone());
        let this_one = {
            let mut before = self.writes_before_one_fails.lock().unwrap();
            match *before {
                Some(0) => {
                    *before = None;
                    true
                }
                Some(left) => {
                    *before = Some(left - 1);
                    false
                }
                None => false,
            }
        };
        if refused.is_some() || this_one || self.is_cut_off() {
            self.journal
                .push(format!("failed write {}", entry.as_str()));
            return Err(refused.unwrap_or_else(Error::store_failed));
        }
        if let Some(left) = self.changes_left.lock().unwrap().as_mut() {
            *left -= 1;
        }
        self.names.lock().unwrap().insert(entry.as_str().to_owned());
        self.journal.push(format!("write {}", entry.as_str()));
        self.inner.write(entry, value)?;
        if let Some(unreadable) = self.fail_after_publish.lock().unwrap().take() {
            *self.fail_next_read.lock().unwrap() = unreadable;
            return Err(Error::store_failed());
        }
        Ok(())
    }

    fn remove(&self, entry: &EntryName) -> Result<(), Error> {
        if self.is_cut_off() {
            return Err(Error::store_failed());
        }
        if *self.failing_removes.lock().unwrap() {
            self.journal
                .push(format!("failed remove {}", entry.as_str()));
            return Err(Error::store_failed());
        }
        self.journal.push(format!("remove {}", entry.as_str()));
        self.inner.remove(entry)
    }

    fn lock(&self, entry: &EntryName, patience: Duration) -> Result<Lock<'_>, Error> {
        // Taken out first: the hook uses this store itself.
        let hook = {
            let mut waiting = self.before_lock.lock().unwrap();
            if waiting
                .as_ref()
                .is_some_and(|(prefix, _)| entry.as_str().starts_with(prefix.as_str()))
            {
                waiting.take().map(|(_, hook)| hook)
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            hook();
        }
        if self
            .busy_locks
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|prefix| entry.as_str().starts_with(prefix.as_str()))
        {
            self.journal.push(format!("busy lock {}", entry.as_str()));
            return Err(Error::store_busy());
        }
        let held = self.inner.lock(entry, patience)?;
        self.journal.push(format!("lock {}", entry.as_str()));
        Ok(Lock::new(Unlocking {
            _held: held,
            journal: self.journal.clone(),
            name: entry.as_str().to_owned(),
        }))
    }
}

impl fmt::Debug for RecordingStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordingStore")
    }
}

/// Records the release of a lock before it happens.
struct Unlocking<'a> {
    _held: Lock<'a>,
    journal: Journal,
    name: String,
}

impl Drop for Unlocking<'_> {
    fn drop(&mut self) {
        self.journal.push(format!("unlock {}", self.name));
    }
}

/// How a request the test chose fails.
#[derive(Clone)]
pub enum Failure {
    /// No answer arrives.
    Unreachable,
    /// A transport error carries this synthetic request ID.
    Diagnostic(String),
    /// The provider answers with this status and body.
    Status(u16, &'static str),
}

struct Rule {
    kind: &'static str,
    times: usize,
    failure: Failure,
}

/// The fake provider behind a transport that records each request by
/// kind (`keys`, `exchange`, `refresh`, `revoke`, `models`) and fails the
/// ones the test asks for.
pub struct RecordingTransport {
    provider: Arc<FakeProvider>,
    journal: Journal,
    rules: Mutex<Vec<Rule>>,
}

impl RecordingTransport {
    pub fn new(provider: Arc<FakeProvider>, journal: Journal) -> Self {
        Self {
            provider,
            journal,
            rules: Mutex::new(Vec::new()),
        }
    }

    /// The next `times` requests of `kind` fail with `failure`.
    pub fn fail(&self, kind: &'static str, times: usize, failure: Failure) {
        self.rules.lock().unwrap().push(Rule {
            kind,
            times,
            failure,
        });
    }
}

/// The kind of a request, read from its URL and grant.
pub fn kind_of(request: &HttpRequest) -> &'static str {
    match request.url() {
        JWKS_URL => "keys",
        REVOKE_URL => "revoke",
        MODELS_URL => "models",
        TOKEN_URL => {
            let fields = form_decode(std::str::from_utf8(request.body()).unwrap());
            match optional(&fields, "grant_type") {
                Some("authorization_code") => "exchange",
                Some("refresh_token") => "refresh",
                other => panic!("unexpected grant {other:?}"),
            }
        }
        other => panic!("unexpected url {other}"),
    }
}

impl Transport for RecordingTransport {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        let kind = kind_of(request);
        self.journal.push(format!("send {kind}"));
        let failure = {
            let mut rules = self.rules.lock().unwrap();
            let failure = rules
                .iter_mut()
                .find(|rule| rule.kind == kind && rule.times > 0)
                .map(|rule| {
                    rule.times -= 1;
                    rule.failure.clone()
                });
            rules.retain(|rule| rule.times > 0);
            failure
        };
        match failure {
            None => Ok(FakeProvider::send(&self.provider, request)),
            Some(Failure::Unreachable) => Err(Error::transport_unavailable()),
            Some(Failure::Diagnostic(id)) => Err(siwc::plan::Refusal::from_code("synthetic")
                .with_request_id(Some(&id))
                .into()),
            Some(Failure::Status(status, body)) => {
                Ok(HttpResponse::new(status, body.as_bytes().to_vec()))
            }
        }
    }
}

impl fmt::Debug for RecordingTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordingTransport")
    }
}
