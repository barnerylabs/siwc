//! Signs in with ChatGPT and streams one answer on the user's plan.
//!
//! ```text
//! cargo run -p siwc --features https,keychain --example quickstart
//! ```
//!
//! The first run opens the browser to sign in. Later runs reuse the stored
//! account, which [`Keychain::open_sealed`] keeps encrypted with a key from
//! the system keychain.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool talks to its user through the terminal"
)]

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use siwc::plan::{MANAGE_USAGE_URL, ResponseRequest, wording};
use siwc::store::Keychain;
use siwc::{Account, AccountState, AppName, Client, Error, ErrorKind, Https};

/// The name the user reads on the consent screen and later finds in their
/// ChatGPT settings.
const APP_NAME: &str = "Commit Helper";

/// The keychain item's service name. A real app uses its bundle identifier
/// or another name that never changes.
const SERVICE: &str = "com.example.commit-helper";

/// The store's folder inside the platform's local app-data folder.
const APP_DIR: &str = "commit-helper";

/// How long a sign-in waits for the browser.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);

const PROMPT: &str = "Write a one-line commit message for: fix a typo in the README";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", explain(&error));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Error> {
    let store = Keychain::open_sealed(SERVICE, APP_DIR)?;
    let client = Client::new(AppName::new(APP_NAME)?, store, Https::new()?);

    // Show who is signed in, so the user notices a wrong account.
    let account = account(&client)?;
    let who = account.identity();
    let shown = who.email().or(who.name()).unwrap_or("(no e-mail or name)");
    println!("Signed in as {shown}.");

    // Stop before sending anything if the user did not allow plan use.
    account.check_plan_use()?;
    println!(
        "{} · {}: {MANAGE_USAGE_URL}",
        wording::USING_PLAN,
        wording::MANAGE_USAGE
    );

    // The models this account's plan allows; an app lets the user pick.
    let models = client.models(account.id())?;
    let Some(model) = models.iter().next() else {
        println!("The plan of this account lists no models.");
        return Ok(());
    };
    for model in models.iter() {
        println!("  {} ({})", model.id(), model.display_name());
    }

    // The stream ends without an error only when the answer is complete.
    println!("\n{} > {PROMPT}", model.id());
    let request = ResponseRequest::text(model.id(), PROMPT)?;
    let mut stdout = std::io::stdout();
    let answer = client
        .stream_response(account.id(), &request)?
        .try_for_each(|event| {
            if let Some(text) = event?.text_delta() {
                print!("{text}");
                // Show the piece now: stdout holds text back until a newline.
                let _ = stdout.flush();
            }
            Ok(())
        });
    println!();
    answer
}

/// The selected account, signed in: the stored one, or the one the user
/// signs in through the browser now.
fn account(client: &Client) -> Result<Account, Error> {
    let (sign_in, again) = match client.selected_account()? {
        Some(account) if account.state() == AccountState::SignedIn => return Ok(account),
        Some(account) if account.state() == AccountState::RegistrationRejected => {
            drop(client.forget(account.id())?);
            (client.add_account()?, None)
        }
        // Signed out, or the session ended: the same account signs in again.
        Some(account) => (client.sign_in_again(account.id())?, Some(account)),
        None if client.unfinished_registration()?.is_some() => {
            (client.resume_unfinished_registration()?, None)
        }
        None => (client.add_account()?, None),
    };
    if sign_in.open_browser().is_err() {
        println!("Open this link to sign in: {}", sign_in.start_link());
    }
    let finished = sign_in.finish(SIGN_IN_TIMEOUT);
    if let (Err(error), Some(account)) = (&finished, &again) {
        // OpenAI no longer accepts this account's registration: forget
        // it, so the next run adds it anew.
        if error.kind() == ErrorKind::ClientRejected {
            drop(client.forget(account.id())?);
        }
    }
    let completed = finished?;
    if completed.plan_use_started() {
        println!("{}", wording::WELCOME);
    }
    client.select_account(Some(completed.account().id()))?;
    Ok(completed.into_account())
}

/// What the user reads when the run stops, by what they can do about it.
fn explain(error: &Error) -> String {
    match error.kind() {
        ErrorKind::UsageLimit => format!(
            "The plan's usage limit is reached. {}: {MANAGE_USAGE_URL}",
            wording::MANAGE_USAGE
        ),
        // An app offers `Client::enable_plan_use` here.
        ErrorKind::PlanUseNotGranted => {
            "This account has not allowed the app to use its ChatGPT plan.".to_owned()
        }
        // The next run signs the account in again.
        ErrorKind::SignInRequired => "The session ended. Run the example again.".to_owned(),
        _ => error.to_string(),
    }
}
