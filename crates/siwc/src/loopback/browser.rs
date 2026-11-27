//! Opening the start link in the system browser.

use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Error, ErrorKind};

use super::start::StartLink;

/// Time the opener has to report a failure.
const GRACE: Duration = Duration::from_secs(1);

/// How often the opener is asked whether it has exited.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Runs the platform's URL opener on the start link, without a shell.
///
/// It takes the link as its own type, so the authorization URL cannot be
/// handed to a command line by mistake. An opener that is still running
/// after the grace period is returned for the caller to reap.
pub(super) fn open(link: &StartLink) -> Result<Option<Child>, Error> {
    let (program, args) = opener(link.link());
    let mut command = Command::new(program);
    command.args(args);
    run(command, GRACE)
}

/// Starts `command` and waits up to `grace` for it to exit.
///
/// A helper that exits with success opened the link. One that is still
/// running when `grace` is over counts as success too and is returned:
/// without a desktop environment `xdg-open` runs the browser itself and
/// stays until the browser is closed, and the browser can only load the
/// start link once the caller goes on to serve it.
fn run(mut command: Command, grace: Duration) -> Result<Option<Child>, Error> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| unavailable())?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(None),
            Ok(Some(_)) | Err(_) => return Err(unavailable()),
            Ok(None) => {}
        }
        let Some(left) = grace
            .checked_sub(started.elapsed())
            .filter(|left| !left.is_zero())
        else {
            return Ok(Some(child));
        };
        thread::sleep(left.min(POLL_INTERVAL));
    }
}

/// The program that opens a URL in the default browser, and its arguments.
#[cfg(target_os = "macos")]
fn opener(link: &str) -> (&'static str, Vec<&str>) {
    ("open", vec![link])
}

/// The program that opens a URL in the default browser, and its arguments.
#[cfg(target_os = "windows")]
fn opener(link: &str) -> (&'static str, Vec<&str>) {
    ("rundll32", vec!["url.dll,FileProtocolHandler", link])
}

/// The program that opens a URL in the default browser, and its arguments.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn opener(link: &str) -> (&'static str, Vec<&str>) {
    ("xdg-open", vec![link])
}

fn unavailable() -> Error {
    Error::new(
        ErrorKind::BrowserUnavailable,
        "the system browser could not be opened",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "http://127.0.0.1:53124/start/00112233445566778899aabbccddeeff";

    /// Upper bound for a helper that is expected to exit; reached only
    /// when a test fails.
    const PATIENCE: Duration = Duration::from_secs(30);

    #[cfg(unix)]
    fn shell(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    #[cfg(unix)]
    fn an_opener_that_exits_with_success_opened_the_link() {
        assert!(run(shell("exit 0"), PATIENCE).unwrap().is_none());
    }

    #[test]
    #[cfg(unix)]
    fn an_opener_that_reports_a_failure_is_unavailable() {
        let error = run(shell("exit 3"), PATIENCE).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::BrowserUnavailable);
    }

    #[test]
    fn an_opener_that_does_not_exist_is_unavailable() {
        let error = run(Command::new("siwc-no-such-opener"), PATIENCE).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::BrowserUnavailable);
    }

    #[test]
    #[cfg(unix)]
    fn an_opener_that_stays_in_the_foreground_does_not_hold_the_app_up() {
        // A helper that never exits on its own, like a browser that
        // `xdg-open` runs in the foreground.
        let mut child = run(shell("exec tail -f /dev/null"), Duration::ZERO)
            .unwrap()
            .expect("the helper is still running");
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_opens_the_link_with_open() {
        assert_eq!(opener(LINK), ("open", vec![LINK]));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_opens_the_link_through_the_url_protocol_handler() {
        assert_eq!(
            opener(LINK),
            ("rundll32", vec!["url.dll,FileProtocolHandler", LINK])
        );
    }

    #[test]
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn other_systems_open_the_link_with_xdg_open() {
        assert_eq!(opener(LINK), ("xdg-open", vec![LINK]));
    }
}
