//! Signs accounts in from a terminal, inspects live JWKS connectivity and
//! moves sessions across machines.
//!
//! Accounts are kept as plain, unencrypted files in a directory you name, so
//! they persist across runs. The files are owner-only on Unix; on macOS and
//! Windows the directory's ACLs have to keep other users out (see
//! `PrivateFiles`). A desktop app seals its files instead, as
//! `examples/keychain.rs` does.
//!
//! ```text
//! cargo run -p siwc --features https --example sign_in -- /home/alex/.local/share/siwc-example add
//! cargo run -p siwc --features https --example sign_in -- /home/alex/.local/share/siwc-example list
//! cargo run -p siwc --features https --example sign_in -- /home/alex/.local/share/siwc-example models <account>
//! cargo run -p siwc --features https --example sign_in -- /home/alex/.local/share/siwc-example diagnose
//! cargo run -p siwc --features https --example sign_in -- /home/alex/.local/share/siwc-example check-jwks
//! ```
//!
//! Run `add` once per account; every other account command names its target
//! with the ID printed by `list`.
//!
//! # Corporate proxies and custom root CAs
//!
//! Pass `--proxy <http(s)://host:port>` and repeatable `--ca-cert <pem-file>`
//! before `<store-dir>` to route requests through an explicit `CONNECT` proxy
//! or trust a custom root certificate:
//!
//! ```text
//! cargo run -p siwc --features https --example sign_in -- \
//!     --proxy https://proxy.corp.example:8443 --ca-cert /etc/ssl/certs/enterprise-root-ca.pem \
//!     /home/alex/.local/share/siwc-example check-jwks
//! ```
//!
//! # From a remote shell or another machine
//!
//! Forward one port so the browser on your workstation reaches the callback
//! listener on the remote host:
//!
//! ```text
//! ssh -L 53124:127.0.0.1:53124 devbox
//! cargo run -p siwc --features https --example sign_in -- --port 53124 /home/alex/.local/share/siwc-example add
//! ```
//!
//! Without a forwarded port, either run `add-manually` and paste the
//! `http://127.0.0.1:...` address the browser is sent back to (the page
//! normally fails to load), or move an already signed-in account from your
//! workstation as a passphrase-sealed bundle (`export <account> <file>` on
//! the source machine, `import <file>` on the destination; both read the
//! passphrase from standard input, which a terminal echoes, so pipe it in or
//! use a no-echo prompt in a real app).
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool talks to its user through the terminal"
)]

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use zeroize::Zeroizing;

use siwc::plan::{MANAGE_USAGE_URL, wording};
use siwc::protocol::Jwks;
use siwc::store::PrivateFiles;
use siwc::{
    Account, AccountId, AccountState, AppName, Client, Completed, Error, ErrorKind, Https,
    ManualSignIn, SignIn, SignOut, Transport,
};

/// The name the user reads on the consent screen and later finds in their
/// ChatGPT settings. A real app uses its product name.
const APP_NAME: &str = "siwc example";

/// How long a sign-in waits for the browser.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_PASSPHRASE_LEN: usize = 1024;
/// The most `Https::add_root_certificates_pem` accepts; one byte more is
/// read from a file, so that a larger one is refused rather than cut.
const MAX_PEM_LEN: usize = 4 * 1024 * 1024;
const MAX_PASTED_REDIRECT_LEN: usize = 8 * 1024;

const USAGE: &str = "\
usage: sign_in [--port <port>] [--proxy <url>] [--ca-cert <pem-file>] <store-dir> <command>

  add                        sign in with one more account
  add-manually               the same, by pasting the address the browser ends on
  resume                     finish the registration an earlier `add` left unfinished
  discard                    drop that unfinished registration
  list                       show the accounts
  models <account>           show the models an account may use
  again <account>            sign an account in again
  plan <account>             ask an account for use of its ChatGPT plan
  export <account> <file>    move a signed-in account into a passphrase-sealed bundle
  import <file>              import a sealed bundle (passphrase read on stdin)
  sign-out <account>         revoke an account's session and delete its tokens
  forget <account>           sign an account out and remove it
  diagnose                   print a report to paste into a support request
  check-jwks                 verify TLS 1.3 and JWKS against auth.openai.com

<store-dir> is an absolute path; <account> is an ID that `list` prints.
--port fixes the callback port; --proxy sets an explicit http:// or https://
CONNECT proxy; --ca-cert adds PEM root certificates to Https.";

/// What the user asked for.
#[derive(Debug, PartialEq, Eq)]
enum Command<'a> {
    Add,
    AddManually,
    Resume,
    Discard,
    List,
    Models(AccountId),
    Again(AccountId),
    Plan(AccountId),
    Export(AccountId, &'a Path),
    Import(&'a Path),
    SignOut(AccountId),
    Forget(AccountId),
    Diagnose,
    CheckJwks,
}

/// The arguments after the program's name, taken apart.
#[derive(Debug, PartialEq, Eq)]
struct Invocation<'a> {
    port: Option<u16>,
    proxy: Option<&'a str>,
    ca_certs: Vec<&'a Path>,
    store_dir: &'a Path,
    command: Command<'a>,
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some(invocation) = parse(&args) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match run(invocation) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // An error's text never holds a token, an address or a path.
            eprintln!("error: {error}");
            if error.kind() == ErrorKind::UsageLimit {
                eprintln!("{}: {MANAGE_USAGE_URL}", wording::MANAGE_USAGE);
            } else if let Some(next) = next_step(error.kind()) {
                eprintln!("{next}");
            }
            ExitCode::FAILURE
        }
    }
}

/// Reads the arguments; `None` when they are not one of the commands.
fn parse(args: &[OsString]) -> Option<Invocation<'_>> {
    let mut port = None;
    let mut proxy = None;
    let mut ca_certs = Vec::new();
    let mut rest = args;
    while let [flag, value, tail @ ..] = rest {
        match flag.to_str().unwrap_or_default() {
            "--port" if port.is_none() => port = Some(value.to_str()?.parse().ok()?),
            "--proxy" if proxy.is_none() => proxy = Some(value.to_str()?),
            "--ca-cert" => ca_certs.push(Path::new(value)),
            _ => break,
        }
        rest = tail;
    }
    let (store_dir, command) = match rest {
        [dir, command] => match command.to_str()? {
            "add" => (Path::new(dir), Command::Add),
            "add-manually" => (Path::new(dir), Command::AddManually),
            "resume" => (Path::new(dir), Command::Resume),
            "discard" => (Path::new(dir), Command::Discard),
            "list" => (Path::new(dir), Command::List),
            "diagnose" => (Path::new(dir), Command::Diagnose),
            "check-jwks" => (Path::new(dir), Command::CheckJwks),
            _ => return None,
        },
        [dir, command, arg] if command == "import" => {
            (Path::new(dir), Command::Import(Path::new(arg)))
        }
        [dir, command, account] => {
            let id: AccountId = account.to_str()?.parse().ok()?;
            let command = match command.to_str()? {
                "models" => Command::Models(id),
                "again" => Command::Again(id),
                "plan" => Command::Plan(id),
                "sign-out" => Command::SignOut(id),
                "forget" => Command::Forget(id),
                _ => return None,
            };
            (Path::new(dir), command)
        }
        [dir, command, account, path] if command == "export" => {
            let id: AccountId = account.to_str()?.parse().ok()?;
            (Path::new(dir), Command::Export(id, Path::new(path)))
        }
        _ => return None,
    };
    Some(Invocation {
        port,
        proxy,
        ca_certs,
        store_dir,
        command,
    })
}

fn build_https(invocation: &Invocation<'_>) -> Result<Https, Error> {
    let mut https = Https::builder();
    if let Some(url) = invocation.proxy {
        https = https.proxy(url)?;
    }
    for pem_path in &invocation.ca_certs {
        https = https.add_root_certificates_pem(&read_pem(pem_path)?)?;
    }
    https.build()
}

/// Reads a PEM file, at most one byte past [`MAX_PEM_LEN`].
fn read_pem(path: &Path) -> Result<Vec<u8>, Error> {
    let mut pem = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_PEM_LEN as u64 + 1).read_to_end(&mut pem))
        .map_err(|_| Error::store_failed())?;
    Ok(pem)
}

fn read_passphrase(prompt: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    read_secret_line(&mut io::stdin().lock(), MAX_PASSPHRASE_LEN)
        .map(|line| line.unwrap_or_default())
        .map_err(|_| Error::store_failed())
}

/// Reads one input line without growing a buffer that already holds a secret.
fn read_secret_line(
    input: &mut impl BufRead,
    max_len: usize,
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let limit = max_len + 2;
    let mut line = Zeroizing::new(Vec::with_capacity(limit));
    if (&mut *input)
        .take(limit as u64)
        .read_until(b'\n', &mut line)?
        == 0
    {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    } else if line.len() == limit {
        input.skip_until(b'\n')?;
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.len() > max_len {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(line))
}

fn run(invocation: Invocation<'_>) -> Result<(), Error> {
    let https = build_https(&invocation)?;
    if invocation.command == Command::CheckJwks {
        let jwks = Jwks::from_response(&https.send(&Jwks::request())?)?;
        println!("Verified TLS 1.3 and JWKS from auth.openai.com: {jwks:?}");
        return Ok(());
    }
    let store = PrivateFiles::open(invocation.store_dir)?;
    let mut builder = Client::builder(AppName::new(APP_NAME)?, store, https);
    if let Some(port) = invocation.port {
        builder = builder.callback_port(port);
    }
    let client = builder.build();

    match invocation.command {
        Command::Add => sign_in(client.add_account()?),
        Command::AddManually => sign_in_manually(client.add_account_manually()?),
        Command::Resume => sign_in(client.resume_unfinished_registration()?),
        Command::Discard => {
            match client.discard_unfinished_registration()? {
                Some(name) => println!(
                    "Dropped. \"{name}\" stays in your ChatGPT settings until you remove it there."
                ),
                None => println!("There was no unfinished registration."),
            }
            Ok(())
        }
        Command::Again(id) => sign_in(client.sign_in_again(&id)?),
        Command::Plan(id) => sign_in(client.enable_plan_use(&id)?),
        Command::Export(id, path) => {
            let pass = read_passphrase("Bundle passphrase (8+ bytes): ")?;
            if let Err(error) = client.export_account_to(&id, &pass, path) {
                if error.kind() == ErrorKind::Store {
                    eprintln!(
                        "If a bundle was created, keep it and check the source account before importing it."
                    );
                }
                return Err(error);
            }
            println!(
                "Exported account {id} to {}; local tokens removed.",
                path.display()
            );
            Ok(())
        }
        Command::Import(path) => {
            let mut bytes = Vec::new();
            File::open(path)
                .and_then(|file| {
                    file.take(Client::MAX_BUNDLE_LEN as u64 + 1)
                        .read_to_end(&mut bytes)
                })
                .map_err(|_| Error::store_failed())?;
            let pass = read_passphrase("Bundle passphrase: ")?;
            let account = client.import_account(&bytes, &pass)?;
            show(&account);
            Ok(())
        }
        Command::CheckJwks => Ok(()),
        Command::List => {
            let accounts = client.accounts()?;
            if accounts.is_empty() {
                println!("No account yet. Run `add`.");
            }
            accounts.iter().for_each(show);
            if let Some(name) = client.unfinished_registration()? {
                println!("Unfinished registration \"{name}\": run `resume` or `discard`.");
            }
            Ok(())
        }
        Command::Models(id) => {
            for model in client.models(&id)?.iter() {
                println!("{:<24} {}", model.id(), model.display_name());
            }
            println!(
                "{}. {}: {MANAGE_USAGE_URL}",
                wording::USING_PLAN,
                wording::MANAGE_USAGE
            );
            Ok(())
        }
        Command::Diagnose => {
            // Holds no token, address, name, label or path.
            print!("{}", client.diagnose());
            Ok(())
        }
        Command::SignOut(id) => {
            signed_out("Signed out.", &client.sign_out(&id)?);
            Ok(())
        }
        Command::Forget(id) => {
            let out = client.forget(&id)?;
            signed_out("Signed out and removed.", &out);
            println!(
                "To remove the app on the provider's side too, delete \"{}\" in your ChatGPT settings.",
                out.registered_as()
            );
            Ok(())
        }
    }
}

/// Takes one sign-in through the browser.
fn sign_in(sign_in: SignIn) -> Result<(), Error> {
    // A terminal often has no browser of its own, or the browser is on
    // another machine, so the link is shown whether or not one opens. It is
    // a local link that works until `finish` returns.
    println!("Continue in your browser. If none opens, open this link:");
    println!("  {}", sign_in.start_link());
    if sign_in.open_browser().is_err() {
        println!("(No browser could be started here.)");
    }

    signed_in(&sign_in.finish(SIGN_IN_TIMEOUT)?);
    Ok(())
}

/// Takes one sign-in through a browser anywhere: the user pastes the
/// address the browser was sent to, as often as it takes.
fn sign_in_manually(mut sign_in: ManualSignIn) -> Result<(), Error> {
    // Show the link to the user and keep it out of logs: it carries the
    // values that identify this sign-in attempt.
    println!("Open this link in a browser on any machine and sign in:");
    println!("  {}", sign_in.authorization_link());
    println!("The browser then fails to load a page on 127.0.0.1.");
    println!("Copy the address from its address bar and paste it here:");
    let mut input = io::stdin().lock();
    loop {
        let pasted = match read_secret_line(&mut input, MAX_PASTED_REDIRECT_LEN) {
            Ok(Some(line)) => line,
            Ok(None) => {
                println!("Nothing was pasted; nothing changed.");
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                println!("The address is too long. Paste it again:");
                continue;
            }
            Err(_) => return Err(Error::store_failed()),
        };
        let Ok(address) = std::str::from_utf8(&pasted) else {
            println!("That is not the redirect address. Paste it again:");
            continue;
        };
        match sign_in.finish(address) {
            // Only a refusal leaves the sign-in open; anything else ended it.
            Err(_) if sign_in.is_open() => {
                println!("That is not the redirect address. Paste it again:");
            }
            result => {
                signed_in(&result?);
                return Ok(());
            }
        }
    }
}

/// Shows the account a sign-in stored, and the welcome or the next step.
fn signed_in(completed: &Completed) {
    show(completed.account());
    if completed.plan_use_started() {
        // Shown once per account, the first time its plan is in use.
        println!(
            "{}. {}: {MANAGE_USAGE_URL}",
            wording::WELCOME,
            wording::MANAGE_USAGE
        );
    } else if !completed.account().plan_use() {
        println!(
            "Signed in without use of the ChatGPT plan. Run `plan {}` to ask for it.",
            completed.account().id()
        );
    }
}

/// One line per account: ID, state, who it is, plan use.
fn show(account: &Account) {
    let identity = account.identity();
    let who = identity
        .email()
        .or(identity.name())
        .unwrap_or("(no e-mail address or name)");
    let state = match account.state() {
        AccountState::SignedIn => "signed in",
        AccountState::SignedOut => "signed out",
        AccountState::SignInRequired => "sign-in required",
        AccountState::RegistrationRejected => "registration removed",
        _ => "unknown state",
    };
    let plan = if account.plan_use() {
        "plan use on"
    } else {
        "plan use off"
    };
    println!("{}  {state}, {plan}  {who}", account.id());
    if !account.shares_login_with().is_empty() {
        println!(
            "  the same person as {} other account(s)",
            account.shares_login_with().len()
        );
    }
}

fn signed_out(done: &str, out: &SignOut) {
    println!("{done}");
    if !out.revocation_confirmed() {
        println!(
            "The provider did not confirm that the session is revoked. \
             To be sure, delete \"{}\" in your ChatGPT settings.",
            out.registered_as()
        );
    }
}

/// What the user can do about an error, where there is something.
fn next_step(kind: ErrorKind) -> Option<&'static str> {
    Some(match kind {
        ErrorKind::SignInRequired => "Run `again <account>` to sign the account in again.",
        ErrorKind::PlanUseNotGranted => "Run `plan <account>` to ask for use of the ChatGPT plan.",
        ErrorKind::ClientRejected => {
            "The app was removed for this account. Run `forget <account>`, then `add`."
        }
        ErrorKind::UnknownAccount => "Run `list` to see the accounts.",
        ErrorKind::AccessDenied => "The sign-in was declined in the browser; nothing changed.",
        ErrorKind::TimedOut => "Nobody finished the sign-in in the browser; nothing changed.",
        ErrorKind::Loopback => "The callback port may be taken; try another `--port`.",
        ErrorKind::StoreNotPrivate => {
            "The store directory must belong to you and be closed to other users."
        }
        ErrorKind::Temporary => "Try again in a moment.",
        ErrorKind::BundleRejected => "Check the bundle passphrase and file, then try again.",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn input_lines_keep_the_limit_and_leave_the_next_line_available() {
        let mut input = std::io::Cursor::new(b"abc\r\naaaaaaa\nxyz\n");
        let read = |input: &mut _| super::read_secret_line(input, 3);
        assert_eq!(read(&mut input).unwrap().unwrap().as_slice(), b"abc");
        assert_eq!(
            read(&mut input).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(read(&mut input).unwrap().unwrap().as_slice(), b"xyz");
        assert!(read(&mut input).unwrap().is_none());
    }

    use super::{Command, Invocation, parse};

    #[test]
    fn a_ca_file_over_the_pem_limit_is_read_only_past_the_limit_and_refused() {
        let path = std::env::temp_dir().join(format!("siwc-sign-in-ca-{}.pem", std::process::id()));
        std::fs::write(&path, vec![b' '; super::MAX_PEM_LEN + 4096]).unwrap();
        let read = super::read_pem(&path);
        let built = super::Https::builder().add_root_certificates_pem(read.as_ref().unwrap());
        let _ = std::fs::remove_file(&path);

        assert_eq!(read.unwrap().len(), super::MAX_PEM_LEN + 1);
        assert_eq!(built.unwrap_err().kind(), super::ErrorKind::InvalidInput);
    }

    fn args(words: &[&str]) -> Vec<super::OsString> {
        words.iter().map(|&word| word.into()).collect()
    }

    #[test]
    fn a_command_without_an_account_takes_the_directory_and_its_name() {
        assert_eq!(
            parse(&args(&["/tmp/example", "add"])),
            Some(Invocation {
                port: None,
                proxy: None,
                ca_certs: Vec::new(),
                store_dir: super::Path::new("/tmp/example"),
                command: Command::Add,
            })
        );
    }

    #[test]
    fn adding_manually_is_a_command_of_its_own() {
        assert_eq!(
            parse(&args(&["/tmp/example", "add-manually"])).map(|invocation| invocation.command),
            Some(Command::AddManually)
        );
    }

    #[test]
    fn resuming_and_discarding_the_unfinished_registration_take_no_account() {
        for (word, command) in [
            ("resume", Command::Resume),
            ("discard", Command::Discard),
            ("check-jwks", Command::CheckJwks),
        ] {
            assert_eq!(
                parse(&args(&["/tmp/example", word])).map(|invocation| invocation.command),
                Some(command)
            );
        }
    }

    #[test]
    fn options_come_first_and_export_or_import_take_their_bundle_path() {
        let account = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            parse(&args(&[
                "--port",
                "53124",
                "--proxy",
                "https://127.0.0.1:8443",
                "--ca-cert",
                "/tmp/ca-1.pem",
                "--ca-cert",
                "/tmp/ca-2.pem",
                "/tmp/example",
                "export",
                account,
                "/tmp/account.bundle",
            ])),
            Some(Invocation {
                port: Some(53124),
                proxy: Some("https://127.0.0.1:8443"),
                ca_certs: vec![
                    super::Path::new("/tmp/ca-1.pem"),
                    super::Path::new("/tmp/ca-2.pem")
                ],
                store_dir: super::Path::new("/tmp/example"),
                command: Command::Export(
                    account.parse().unwrap(),
                    super::Path::new("/tmp/account.bundle")
                ),
            })
        );
        assert_eq!(
            parse(&args(&["/tmp/example", "import", "/tmp/account.bundle"]))
                .map(|invocation| invocation.command),
            Some(Command::Import(super::Path::new("/tmp/account.bundle")))
        );
    }

    #[test]
    fn anything_else_is_refused() {
        for words in [
            &[][..],
            &["/tmp/example"],
            &["/tmp/example", "models"],
            &["/tmp/example", "add", "0123456789abcdef0123456789abcdef"],
            &["/tmp/example", "models", "not-an-account"],
            &["--port", "none", "/tmp/example", "add"],
            &["--port", "53124", "--port", "53125", "/tmp/example", "add"],
            &["/tmp/example", "add", "--port", "53124"],
        ] {
            assert_eq!(parse(&args(words)), None, "{words:?}");
        }
    }
}

#[cfg(all(test, unix))]
#[test]
fn non_unicode_paths_survive_argument_parsing() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let path = OsString::from_vec(vec![b'/', 0xff]);
    let arguments = [path.clone(), OsString::from("import"), path.clone()];
    let parsed = parse(&arguments).unwrap();
    assert_eq!(parsed.store_dir, std::path::Path::new(&path));
    assert_eq!(parsed.command, Command::Import(std::path::Path::new(&path)));
}
