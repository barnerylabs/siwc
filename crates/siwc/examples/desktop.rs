//! The shape of a desktop app around siwc: a window thread that never waits,
//! and a sign-in on a worker thread that the user can cancel.
//!
//! A real app has a window. To keep to the standard library, lines typed on
//! standard input stand in for clicks here, and printed lines for what the
//! window shows:
//!
//! ```text
//! cargo run -p siwc --features https,keychain --example desktop
//! ```
//!
//! Then type `add`, `cancel`, `list`, `token <account>` or `quit`.
//!
//! # What carries over to a real app
//!
//! - Every call to the client can wait: for a file lock, the provider or the
//!   browser. The window's thread hands each call to a worker and gets the
//!   result back as an [`Event`], the way [`Ui::run`] does. With a toolkit,
//!   `run` is its event loop, and the channel is its way of waking that loop
//!   from another thread.
//! - The window shows the start link next to an "Open browser" button, so a
//!   user whose browser did not open can copy it, and a "Cancel" button that
//!   stops the wait; a request or store write already under way finishes
//!   first.
//! - A timer polls [`siwc::Changes`] and the window shows what changed:
//!   an account added or signed out, a session that needs a new sign-in,
//!   including when another instance of the app or a command-line tool on the
//!   same store made the change. Those reach this process through the
//!   store, so the app decides how often to look.
//! - The accounts live in the platform's directory for local app data
//!   ([`PrivateFiles::open_app_dir`]), or in `SIWC_DESKTOP_DIR` when set; the
//!   override must be an absolute path whose parent exists, and the example
//!   creates only its own folder. The override relocates one store, so stop all
//!   instances before changing it. Every instance using the same keychain
//!   service must use the same directory.
//! - Every value is sealed with a key in the system keychain
//!   ([`Keychain`], from the `keychain` feature), so the files reveal no
//!   account data, even when a backup copies them or an access control list
//!   opens them to other users; entry names and sizes stay visible. An
//!   unlocked keychain gives the key without a prompt. A locked one, as over
//!   SSH on macOS, or a Linux session without a Secret Service makes the
//!   first read or write of an account fail, and nothing is written in plain.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "printed lines stand in for the window"
)]

use std::ffi::OsString;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use siwc::protocol::Identity;
use siwc::store::{Keychain, PrivateFiles, Sealed};
use siwc::{
    AccessToken, Account, AccountId, AppName, Canceller, Change, Client, Completed, Error, Https,
};

/// The name the user reads on the consent screen and later finds in their
/// ChatGPT settings. A real app uses its product name.
const APP_NAME: &str = "siwc desktop example";

/// The app's folder inside the platform's directory for app data, and the
/// keychain item's service name. A real app uses its bundle identifier or
/// another name that never changes.
const DIR_NAME: &str = "siwc-desktop-example";

/// Optional environment variable that overrides the store directory with an
/// absolute path.
const OVERRIDE_DIR: &str = "SIWC_DESKTOP_DIR";

/// How long sealing plain entries waits for another instance that holds an
/// entry's lock.
const SEAL_PATIENCE: Duration = Duration::from_secs(10);

/// How long a sign-in waits for the browser.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);

/// How often the window looks for changed accounts.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    let client = match build() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("The accounts could not be opened: {error}");
            return ExitCode::FAILURE;
        }
    };
    Ui::new(client).run();
    ExitCode::SUCCESS
}

/// Builds the client over a file store sealed with a keychain key.
fn build() -> Result<Client, Error> {
    let store = match override_dir(|name| std::env::var_os(name)) {
        Some(dir) => {
            let files = PrivateFiles::open(dir)?;
            let key = Keychain::new(DIR_NAME, &files)?;
            let store = Sealed::new(files, key);
            // As `Keychain::open_sealed` does for the default directory.
            store.seal_existing(SEAL_PATIENCE)?;
            store
        }
        None => Keychain::open_sealed(DIR_NAME, DIR_NAME)?,
    };
    Ok(Client::new(AppName::new(APP_NAME)?, store, Https::new()?))
}

/// The `SIWC_DESKTOP_DIR` override from the environment that `var` reads.
/// A relative path is passed on, so the store refuses it instead of the
/// example quietly opening the default directory.
fn override_dir(var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    var(OVERRIDE_DIR).map(PathBuf::from)
}

/// What reaches the window's thread: the user's clicks and the workers'
/// results.
enum Event {
    /// The user clicked; the text names the button.
    Click(String),
    /// The user closed the window.
    Closed,
    /// A sign-in waits for the browser.
    Waiting {
        start_link: String,
        browser_opened: bool,
        canceller: Canceller,
        ready: Sender<()>,
    },
    /// A sign-in ended: completed, declined, timed out or cancelled.
    SignInEnded(Result<Completed, Error>),
    Accounts(Result<Vec<Account>, Error>),
    /// The timer found changed accounts.
    Changes(Result<Vec<Change>, Error>),
    Token(AccountId, Result<AccessToken, Error>),
}

/// Where the one sign-in a client can have at a time stands.
enum SignIn {
    Idle,
    /// Asked for, not yet waiting for the browser.
    Starting,
    Waiting(Canceller),
}

/// The window's thread and what it shows.
struct Ui {
    client: Client,
    events: Sender<Event>,
    inbox: Receiver<Event>,
    sign_in: SignIn,
    /// Workers started by [`Ui::work`] that may not have finished yet.
    workers: Vec<JoinHandle<()>>,
}

impl Ui {
    fn new(client: Client) -> Self {
        let (events, inbox) = mpsc::channel();
        Self {
            client,
            events,
            inbox,
            sign_in: SignIn::Idle,
            workers: Vec::new(),
        }
    }

    /// The event loop: shows the accounts, then handles one event at a time
    /// until the window closes. Nothing here waits except for the next
    /// event.
    fn run(mut self) {
        let clicks = self.events.clone();
        thread::spawn(move || {
            for line in io::stdin().lock().lines().map_while(Result::ok) {
                if clicks.send(Event::Click(line)).is_err() {
                    return;
                }
            }
            let _closed = clicks.send(Event::Closed);
        });
        self.work(|client, _| Event::Accounts(client.accounts()));
        let (client, timer) = (self.client.clone(), self.events.clone());
        let (stop_timer, stopped) = mpsc::channel();
        thread::spawn(move || watch(&client, &timer, &stopped));

        while let Ok(event) = self.inbox.recv() {
            match event {
                Event::Click(button) => {
                    if !self.click(button.trim()) {
                        break;
                    }
                }
                Event::Closed => break,
                Event::Waiting {
                    start_link,
                    browser_opened,
                    canceller,
                    ready,
                } => {
                    self.sign_in = SignIn::Waiting(canceller);
                    let _ready = ready.send(());
                    if browser_opened {
                        println!(
                            "Continue in the browser. If no browser window opened, open this \
                             link: {start_link}"
                        );
                    } else {
                        println!("Open this link in your browser: {start_link}");
                    }
                }
                Event::SignInEnded(result) => {
                    self.sign_in = SignIn::Idle;
                    signed_in(result);
                }
                Event::Accounts(Ok(accounts)) => show(&accounts),
                Event::Accounts(Err(error)) | Event::Changes(Err(error)) => {
                    println!("The accounts could not be read: {error}");
                }
                Event::Changes(Ok(changes)) => changes.iter().for_each(show_change),
                Event::Token(id, Ok(_token)) => {
                    // A real app sends `token.expose()` as a bearer token to
                    // the API and never shows or logs it.
                    println!("An access token for {id} is ready.");
                }
                Event::Token(id, Err(error)) => println!("No access token for {id}: {error}"),
            }
        }
        drop(stop_timer);
        self.end_sign_in();
        // A worker may be between a token refresh and the store write that
        // keeps the new refresh token; exiting then would lose it.
        for worker in self.workers.drain(..) {
            let _joined = worker.join();
        }
    }

    /// Closing during a sign-in cancels it and waits for its worker, so the
    /// process never exits halfway through storing an account. The cancel
    /// also stops a sign-in past the browser's answer until the account is
    /// listed in the store; from then on the sign-in completes.
    fn end_sign_in(&mut self) {
        if let SignIn::Waiting(canceller) = &self.sign_in {
            canceller.cancel();
        }
        if matches!(self.sign_in, SignIn::Idle) {
            return;
        }
        while let Ok(event) = self.inbox.recv() {
            match event {
                Event::Waiting {
                    canceller, ready, ..
                } => {
                    canceller.cancel();
                    let _ready = ready.send(());
                }
                Event::SignInEnded(result) => return signed_in(result),
                _ => {}
            }
        }
    }

    /// Handles a click; false when the window is to close.
    fn click(&mut self, button: &str) -> bool {
        match button.split_once(' ').unwrap_or((button, "")) {
            ("add", "") => self.add(),
            ("cancel", "") => match &self.sign_in {
                SignIn::Waiting(canceller) => canceller.cancel(),
                SignIn::Starting => println!("The sign-in is still starting."),
                SignIn::Idle => println!("No sign-in to cancel."),
            },
            ("list", "") => self.work(|client, _| Event::Accounts(client.accounts())),
            ("token", id) => match AccountId::parse(id) {
                Ok(id) => self.work(move |client, _| {
                    let token = client.access_token(&id);
                    Event::Token(id, token)
                }),
                Err(_) => println!("`token` takes an account ID that `list` shows."),
            },
            ("quit", "") => return false,
            _ => println!("Buttons: add, cancel, list, token <account>, quit"),
        }
        true
    }

    /// Starts a sign-in on a worker. The worker reports the start link as
    /// soon as the browser can follow it, then waits for the result.
    fn add(&mut self) {
        if !matches!(self.sign_in, SignIn::Idle) {
            println!("A sign-in is already open; finish or cancel it first.");
            return;
        }
        self.sign_in = SignIn::Starting;
        self.work(|client, events| {
            let sign_in = match client.add_account() {
                Ok(sign_in) => sign_in,
                Err(error) => return Event::SignInEnded(Err(error)),
            };
            let (ready, shown) = mpsc::channel();
            let canceller = sign_in.canceller();
            if events
                .send(Event::Waiting {
                    start_link: sign_in.start_link().to_owned(),
                    browser_opened: sign_in.open_browser().is_ok(),
                    canceller: canceller.clone(),
                    ready,
                })
                .is_err()
                || shown.recv().is_err()
            {
                canceller.cancel();
            }
            Event::SignInEnded(sign_in.finish(SIGN_IN_TIMEOUT))
        });
    }

    /// Runs `job` on a worker thread with a clone of the client and posts
    /// its result to the window. Closing the window waits for the worker.
    fn work(&mut self, job: impl FnOnce(&Client, &Sender<Event>) -> Event + Send + 'static) {
        let client = self.client.clone();
        let events = self.events.clone();
        self.workers.retain(|worker| !worker.is_finished());
        self.workers.push(thread::spawn(move || {
            let event = job(&client, &events);
            let _posted = events.send(event);
        }));
    }
}

/// The window's timer: polls the accounts and posts what changed, until
/// the window is gone.
fn watch(client: &Client, events: &Sender<Event>, stopped: &Receiver<()>) {
    let mut changes = match client.changes() {
        Ok(changes) => changes,
        Err(error) => {
            let _posted = events.send(Event::Changes(Err(error)));
            return;
        }
    };
    while stopped.recv_timeout(POLL_INTERVAL) == Err(mpsc::RecvTimeoutError::Timeout) {
        let polled = changes.poll();
        if polled.as_ref().is_ok_and(Vec::is_empty) {
            continue;
        }
        if events.send(Event::Changes(polled)).is_err() {
            return;
        }
    }
}

fn signed_in(result: Result<Completed, Error>) {
    match result {
        Ok(completed) if completed.plan_use_started() => println!(
            "Signed in as {}. {}",
            person(completed.account().identity()),
            siwc::plan::wording::WELCOME
        ),
        Ok(completed) => println!("Signed in as {}.", person(completed.account().identity())),
        Err(error) => println!("The sign-in did not complete: {error}"),
    }
}

fn show(accounts: &[Account]) {
    if accounts.is_empty() {
        println!("No accounts yet. Type `add` to sign in.");
    }
    for account in accounts {
        println!("{}  {}", account.id(), who(account));
    }
}

fn show_change(change: &Change) {
    match change {
        Change::Added(account) => println!("Added {} ({}).", account.id(), who(account)),
        Change::Changed(account) => println!(
            "{} ({}) is now {:?}.",
            account.id(),
            who(account),
            account.state()
        ),
        Change::Removed(account) => println!("Removed {} ({}).", account.id(), who(account)),
        _ => {}
    }
}

/// The name the window shows for an account.
fn who(account: &Account) -> &str {
    account
        .label()
        .unwrap_or_else(|| person(account.identity()))
}

/// The verified e-mail or name of whoever signed in; never the subject or
/// the local account ID, which mean nothing to the user.
fn person(identity: &Identity) -> &str {
    identity
        .email()
        .or(identity.name())
        .unwrap_or("(no e-mail or name)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    #[test]
    fn the_override_is_passed_on_as_set_so_the_store_can_refuse_a_relative_path() {
        let dir = std::env::temp_dir().join("siwc-desktop-override");
        let absolute = dir.to_str().unwrap();
        assert_eq!(
            override_dir(env(&[(OVERRIDE_DIR, absolute)])),
            Some(dir.clone())
        );
        assert_eq!(
            override_dir(env(&[(OVERRIDE_DIR, "relative/dir")])),
            Some(PathBuf::from("relative/dir"))
        );
        assert_eq!(override_dir(env(&[("HOME", absolute)])), None);
        assert!(PrivateFiles::open("relative/dir").is_err());
    }
}
