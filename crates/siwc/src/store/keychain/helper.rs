//! Running a keychain helper on Unix and reaping it before returning.

#[cfg(test)]
#[cfg(target_os = "linux")]
mod deadline_tests;

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{Error, ErrorCause, ErrorKind};

use super::material::Lookup;
use super::{KEY_PATIENCE, reading, tool_failed};

const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Most key text taken from a helper. A key is 65 bytes of text; a helper
/// that prints far more is not answering with a key, and the limit keeps it
/// from filling memory with copies nobody wipes.
const MAX_TEXT: usize = 1024;

/// Exit status, captured key text and whether stderr was empty.
type LookupOutput = (ExitStatus, Zeroizing<Vec<u8>>, bool);

pub(super) struct Tool<'a> {
    program: &'a OsStr,
    elapsed: &'a dyn Fn(&Instant) -> Duration,
}

impl<'a> Tool<'a> {
    pub(super) fn new(program: &'a OsStr) -> Self {
        Self {
            program,
            elapsed: &Instant::elapsed,
        }
    }

    pub(super) fn command(&self) -> Command {
        Command::new(self.program)
    }

    pub(super) fn output(
        &self,
        mut command: Command,
        lookup: Lookup<'_>,
    ) -> Result<LookupOutput, Error> {
        let (stdout, out) = capture()?;
        let (stderr, err) = capture()?;
        command.stdin(Stdio::null()).stdout(out).stderr(err);
        self.run(command, lookup, |child, wait| {
            collect(child, stdout, stderr, wait)
        })
    }

    pub(super) fn store(&self, mut command: Command, text: &[u8]) -> Result<(), Error> {
        command
            .stdin(input(text)?)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        self.run(command, Lookup::default(), |child, wait| {
            loop {
                let delay = wait.next_poll()?;
                if let Some(status) = child.try_wait().map_err(|_| tool_failed())? {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(tool_failed())
                    };
                }
                wait.pause(delay);
            }
        })
    }

    fn run<T>(
        &self,
        mut command: Command,
        lookup: Lookup<'_>,
        job: impl FnOnce(&mut Child, &Wait<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let wait = Wait {
            started: Instant::now(),
            elapsed: self.elapsed,
            lookup,
        };
        wait.next_poll()?;
        let mut child = command.spawn().map_err(|_| tool_failed())?;
        drop(command);
        let result = job(&mut child, &wait);
        if result.is_err() {
            // The helper may have exited since the last check. Always wait,
            // so the caller has no child left to reap when releasing the lock.
            let _killed = child.kill();
            let _reaped = child.wait();
        }
        result
    }
}

struct Wait<'a> {
    started: Instant,
    elapsed: &'a dyn Fn(&Instant) -> Duration,
    lookup: Lookup<'a>,
}

impl Wait<'_> {
    fn next_poll(&self) -> Result<Duration, Error> {
        if self
            .lookup
            .stop
            .is_some_and(crate::cancel::Canceller::is_cancelled)
        {
            return Err(reading::cancelled());
        }
        let mut remaining = KEY_PATIENCE.saturating_sub((self.elapsed)(&self.started));
        if let Some(reset) = self.lookup.reset {
            remaining = remaining.min(reset.remaining()?);
        }
        if remaining.is_zero() {
            return Err(
                Error::new(ErrorKind::Store, "the keychain helper timed out")
                    .with_cause(ErrorCause::TimedOut),
            );
        }
        Ok(POLL_INTERVAL.min(remaining))
    }

    fn pause(&self, delay: Duration) {
        if let Some(stop) = self.lookup.stop {
            stop.wait(delay);
        } else {
            thread::sleep(delay);
        }
    }
}

/// Queue the one short command or key before spawning, so a helper that
/// does not read its input cannot hold up a write.
fn input(text: &[u8]) -> Result<Stdio, Error> {
    let (read, mut write) = UnixStream::pair().map_err(|_| tool_failed())?;
    write.set_nonblocking(true).map_err(|_| tool_failed())?;
    write.write_all(text).map_err(|_| tool_failed())?;
    Ok(Stdio::from(OwnedFd::from(read)))
}

/// A nonblocking reader lets us drain both outputs while the helper runs
/// without waiting for a pipe or leaving another thread holding key text.
fn capture() -> Result<(UnixStream, Stdio), Error> {
    let (read, write) = UnixStream::pair().map_err(|_| tool_failed())?;
    read.set_nonblocking(true).map_err(|_| tool_failed())?;
    Ok((read, Stdio::from(OwnedFd::from(write))))
}

fn collect(
    child: &mut Child,
    mut stdout: UnixStream,
    mut stderr: UnixStream,
    wait: &Wait<'_>,
) -> Result<LookupOutput, Error> {
    // Allocated once at its limit, so no reallocation leaves key text behind.
    let mut text = Zeroizing::new(Vec::with_capacity(MAX_TEXT));
    let mut buffer = Zeroizing::new([0; 4096]);
    let mut stderr_empty = true;
    loop {
        let delay = wait.next_poll()?;
        let status = child.try_wait().map_err(|_| tool_failed())?;
        let bytes = read_ready(&mut stdout, buffer.as_mut_slice())?;
        let read_stdout = bytes.is_some();
        let bytes = bytes.unwrap_or_default();
        if text.len() + bytes.len() > MAX_TEXT {
            return Err(tool_failed());
        }
        text.extend_from_slice(bytes);
        let errors = read_ready(&mut stderr, buffer.as_mut_slice())?;
        stderr_empty &= errors.is_none_or(<[u8]>::is_empty);
        if !read_stdout && errors.is_none() {
            if let Some(status) = status {
                return Ok((status, text, stderr_empty));
            }
            wait.pause(delay);
        }
    }
}

fn read_ready<'a>(
    reader: &mut UnixStream,
    buffer: &'a mut [u8],
) -> Result<Option<&'a [u8]>, Error> {
    match reader.read(buffer) {
        Ok(0) => Ok(None),
        Ok(len) => Ok(buffer.get(..len)),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        // Check the deadline and cancellation and retry without treating the
        // interruption as the end of the helper's output.
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(Some(&[])),
        Err(_) => Err(tool_failed()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;

    use crate::cancel::Canceller;

    use super::*;

    #[test]
    fn a_lookup_drains_both_outputs_and_preserves_the_exit_status() {
        let stop = Canceller::new();
        let (done, result) = mpsc::channel();
        let worker = thread::spawn({
            let stop = stop.clone();
            move || {
                let mut command = Command::new("/bin/sh");
                command.args([
                    "-c",
                    "printf '%0262144d' 0 >&2; printf '%s' synthetic-key; exit 18",
                ]);
                let tool = Tool::new("/bin/sh".as_ref());
                done.send(tool.output(command, Lookup::cancellable(Some(&stop))))
                    .unwrap();
            }
        });
        // On macOS a socket pair holds about 8 KiB, so the 256 KiB of stderr
        // arrive in some thirty rounds with a 50 ms pause each. The bound only
        // keeps a hung test from waiting for `KEY_PATIENCE`; a loaded CI runner
        // needs far more than the 1.6 s this takes at best.
        let returned = result.recv_timeout(Duration::from_secs(30));
        stop.cancel();
        worker.join().unwrap();
        let (status, text, stderr_empty) = returned.unwrap().unwrap();
        assert_eq!(status.code(), Some(18));
        assert_eq!(text.as_slice(), b"synthetic-key");
        assert!(!stderr_empty);
    }

    #[test]
    fn a_helper_that_prints_more_than_a_key_fails_and_is_reaped_without_a_canceller() {
        let mut command = Command::new("/bin/sh");
        // Prints past the limit, then would wait: only the kill ends it.
        command.args(["-c", "printf '%01025d' 0; exec sleep 30"]);
        let started = std::time::Instant::now();
        let tool = Tool::new("/bin/sh".as_ref());
        assert!(tool.output(command, Lookup::default()).is_err());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_lookup_without_a_canceller_returns_the_key_text_and_status() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf '%s' synthetic-key; exit 1"]);
        let tool = Tool::new("/bin/sh".as_ref());
        let (status, text, stderr_empty) = tool.output(command, Lookup::default()).unwrap();
        assert_eq!(status.code(), Some(1));
        assert_eq!(text.as_slice(), b"synthetic-key");
        assert!(stderr_empty);
    }
}
