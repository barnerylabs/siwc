//! Keeps the accounts encrypted with a key from the system keychain.
//!
//! Uses [`Keychain::open_sealed`], which opens a `PrivateFiles` store in the
//! platform's local app-data folder (`~/Library/Application Support`,
//! `%LOCALAPPDATA%`, or `$XDG_DATA_HOME` / `~/.local/share`) and seals every
//! entry with a random 32-byte key stored in the OS keychain:
//!
//! ```text
//! cargo run -p siwc --features https,keychain --example keychain -- add
//! cargo run -p siwc --features https,keychain --example keychain
//! ```
//!
//! `add` signs in one more account; without a command the example lists
//! the accounts.
//!
//! A folder of its own is the better home for the store. Other files of the
//! app may share it: only plain `installation` and `account-*` entries are
//! sealed when the store opens.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool talks to its user through the terminal"
)]

use std::ffi::OsString;
use std::process::ExitCode;
use std::time::Duration;

use siwc::store::Keychain;
use siwc::{AppName, Client, Error, Https};

/// The name the user reads on the consent screen and later finds in their
/// ChatGPT settings. A real app uses its product name.
const APP_NAME: &str = "siwc keychain example";

/// The store's folder, and the keychain item's service name. A real app
/// uses its bundle identifier or another name that never changes.
const NAME: &str = "siwc-keychain-example";

/// How long a sign-in waits for the browser.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = build().and_then(|client| {
        match arguments.as_slice() {
            [] => list(&client),
            [command] if command == "add" => add(&client),
            _ => {
                eprintln!("usage: keychain [add]");
                return Ok(ExitCode::from(2));
            }
        }
        .map(|()| ExitCode::SUCCESS)
    });
    result.unwrap_or_else(|error| {
        eprintln!("{error}");
        ExitCode::FAILURE
    })
}

fn build() -> Result<Client, Error> {
    let store = Keychain::open_sealed(NAME, NAME)?;
    Ok(Client::new(AppName::new(APP_NAME)?, store, Https::new()?))
}

fn list(client: &Client) -> Result<(), Error> {
    let accounts = client.accounts()?;
    if accounts.is_empty() {
        println!("No accounts yet. Run `keychain add` to sign in.");
    }
    for account in accounts {
        println!("{}  {:?}", account.id(), account.state());
    }
    Ok(())
}

fn add(client: &Client) -> Result<(), Error> {
    let sign_in = client.add_account()?;
    if sign_in.open_browser().is_err() {
        println!("Open this link in your browser: {}", sign_in.start_link());
    }
    let completed = sign_in.finish(SIGN_IN_TIMEOUT)?;
    let who = completed.account().identity();
    println!(
        "Signed in as {} ({}).",
        who.email().or(who.name()).unwrap_or("(no e-mail or name)"),
        completed.account().id()
    );
    Ok(())
}
