//! A blocking receiver for the browser callback on `127.0.0.1`.
//!
//! The [`Listener`] binds a free port on the IPv4 loopback address before
//! the attempt starts, so the attempt's redirect URI can name that port. The
//! browser is sent to a local start link, which redirects to the
//! authorization URL; the URL itself never reaches a command line. The
//! listener then serves requests until this attempt's callback arrives,
//! answers everything else with a small error, and hands the waiting browser
//! tab to the app as a [`Reply`], so the page it shows can tell how the
//! sign-in really ended.
//!
//! Sockets and HTTP handling use only the standard library. [`Waiting::wait`]
//! blocks the calling thread; run it on a thread of its own and use a
//! [`Canceller`] to stop it.

mod browser;
mod page;
mod request;
mod response;
mod start;
mod style;

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::process::Child;
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::entropy::{Entropy, OsEntropy};
use crate::error::{Error, ErrorKind};
use crate::protocol::{Accepted, Attempt, CALLBACK_PATH, Callback};

use request::{HEAD_DEADLINE, Head, Refusal, Step};
use response::Status;
use start::{START_PREFIX, StartLink};

#[doc(no_inline)]
pub use crate::cancel::Canceller;
pub use page::{Answer, Page, Text, Texts};
pub use response::Reply;
pub use style::{LogoFormat, Style};

/// Reads `data` as one connection's request head, in pieces of the size the
/// first byte names. For cargo-fuzz harnesses only.
#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_request_head(data: &[u8]) {
    /// Hands out at most `size` bytes per read, then the end of the stream.
    struct Pieces<'a> {
        rest: &'a [u8],
        size: usize,
    }

    impl io::Read for Pieces<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.size.min(self.rest.len()).min(buffer.len());
            let (piece, rest) = self.rest.split_at(count);
            buffer[..count].copy_from_slice(piece);
            self.rest = rest;
            Ok(count)
        }
    }

    let Some((&size, rest)) = data.split_first() else {
        return;
    };
    let mut reader = Pieces {
        rest,
        size: usize::from(size.max(1)),
    };
    let mut head = Head::new();
    while matches!(head.read(&mut reader, "127.0.0.1:8765"), Step::Pending) {}
}

/// How often the wait looks for new connections, data, cancellation and
/// its deadline.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Connections served at the same time. A further one is closed at once.
const MAX_CONNECTIONS: usize = 8;

/// Connections taken from the backlog in one turn, so a flood of them
/// cannot keep the wait from checking its deadline.
const ACCEPTS_PER_TURN: usize = 64;

/// Turns in a row in which the socket may fail to accept before the wait
/// gives up: about a second. The machine running out of file descriptors
/// for a moment is no reason to end a sign-in; a dead socket is.
const FAILED_TURNS: u32 = 50;

/// A TCP listener on `127.0.0.1`, normally on a port the operating system
/// chose.
///
/// One listener serves one sign-in attempt:
///
/// ```no_run
/// use std::time::Duration;
///
/// use siwc::ErrorKind;
/// use siwc::loopback::{Answer, Listener, Page};
/// use siwc::protocol::{Attempt, Registration};
///
/// let app = siwc::AppName::new("Paste Perfect")?;
/// let host = siwc::HostId::generate(&siwc::OsEntropy)?; // stored once per installation
///
/// let listener = Listener::bind()?;
/// let attempt = Attempt::start(
///     Registration::New(&app),
///     Some(&host),
///     listener.port(),
///     &siwc::OsEntropy,
/// )?;
/// let waiting = listener.serve(attempt, Page::new(&app), &siwc::OsEntropy)?;
/// if waiting.open_browser().is_err() {
///     println!("To sign in, open {}", waiting.start_link());
/// }
///
/// let received = waiting.wait(Duration::from_secs(300))?;
/// match received.outcome {
///     Ok(accepted) => {
///         // Store the issued client ID, exchange the code, verify the ID
///         // token; then tell the user how it went.
///         # drop(accepted);
///         received.reply.send(Answer::SignedIn);
///     }
///     Err(error) if error.kind() == ErrorKind::AccessDenied => {
///         received.reply.send(Answer::Declined);
///     }
///     Err(_) => received.reply.send(Answer::Failed),
/// }
/// # Ok::<(), siwc::Error>(())
/// ```
pub struct Listener {
    socket: TcpListener,
    port: u16,
}

impl Listener {
    /// Binds `127.0.0.1` on a free port. Never `0.0.0.0` and never IPv6.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Loopback`] when no port can be bound.
    pub fn bind() -> Result<Self, Error> {
        Self::bind_port(0)
    }

    /// Binds `127.0.0.1` on a port the caller chose and fails when that
    /// port is taken.
    ///
    /// For setups that forward one fixed port to this machine, such as
    /// `ssh -L 53124:127.0.0.1:53124` from the machine with the browser:
    /// the start link and the callback both work through the forward.
    /// Everything else uses [`bind`](Self::bind), which cannot collide.
    ///
    /// ```no_run
    /// let listener = siwc::loopback::Listener::bind_port(53124)?;
    /// assert_eq!(listener.port(), 53124);
    /// # Ok::<(), siwc::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Loopback`] when the port cannot be bound.
    pub fn bind_port(port: u16) -> Result<Self, Error> {
        let socket = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .map_err(|_| loopback("the loopback listener could not be bound"))?;
        let port = socket
            .local_addr()
            .map_err(|_| loopback("the loopback listener has no port"))?
            .port();
        Ok(Self { socket, port })
    }

    /// The bound port; pass it to [`Attempt::start`].
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Takes the attempt that was started with [`port`](Self::port) and the
    /// page shown to the user, and draws the start link.
    ///
    /// Anyone who can open the start link can see the attempt's whole
    /// authorization URL. Keep account hints disabled (the default) for a
    /// returning account, since opting in via
    /// [`Returning::with_hints`](crate::protocol::Returning::with_hints)
    /// can put the ID token or e-mail address in that URL.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] when the attempt was started for another
    /// port; [`ErrorKind::Randomness`] when `entropy` fails;
    /// [`ErrorKind::Loopback`] when the socket cannot be switched to
    /// non-blocking mode.
    pub fn serve(
        self,
        attempt: Attempt,
        page: Page,
        entropy: &OsEntropy,
    ) -> Result<Waiting, Error> {
        self.serve_inner(attempt, page, entropy)
    }

    /// Serves an attempt with a caller-supplied source of test randomness.
    ///
    /// ```no_run
    /// use siwc::loopback::{Listener, Page};
    /// use siwc::protocol::{Attempt, Registration};
    ///
    /// # fn example(source: &dyn siwc::Entropy) -> Result<(), siwc::Error> {
    /// let app = siwc::AppName::new("Example")?;
    /// let listener = Listener::bind()?;
    /// let attempt = Attempt::start_with_entropy(Registration::New(&app), None, listener.port(), source)?;
    /// let waiting = listener.serve_with_entropy(attempt, Page::new(&app), source)?;
    /// # drop(waiting);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// The same port, randomness and socket errors as [`serve`](Self::serve).
    #[cfg(feature = "testing")]
    #[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
    pub fn serve_with_entropy(
        self,
        attempt: Attempt,
        page: Page,
        entropy: &dyn Entropy,
    ) -> Result<Waiting, Error> {
        self.serve_inner(attempt, page, entropy)
    }

    pub(crate) fn serve_inner(
        self,
        attempt: Attempt,
        page: Page,
        entropy: &dyn Entropy,
    ) -> Result<Waiting, Error> {
        let redirect_uri = format!("http://127.0.0.1:{}{CALLBACK_PATH}", self.port);
        if attempt.redirect_uri() != redirect_uri {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "the attempt was started for another port",
            ));
        }
        let start = StartLink::draw(entropy, self.port)?;
        self.socket
            .set_nonblocking(true)
            .map_err(|_| loopback("the loopback listener could not be served"))?;
        Ok(Waiting {
            socket: self.socket,
            port: self.port,
            attempt: Some(attempt),
            start,
            page,
            canceller: Canceller::unshared(),
            openers: Mutex::new(Vec::new()),
            head_deadline: HEAD_DEADLINE,
        })
    }
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// A listener that serves one attempt and waits for its callback.
#[must_use = "call `Waiting::wait` to receive the callback; dropping it closes the listener"]
pub struct Waiting {
    socket: TcpListener,
    port: u16,
    attempt: Option<Attempt>,
    start: StartLink,
    page: Page,
    canceller: Canceller,
    /// Openers that were still running when `open_browser` returned.
    openers: Mutex<Vec<Child>>,
    /// Time a connection has to send its request head.
    head_deadline: Duration,
}

impl Waiting {
    /// `http://127.0.0.1:<port>/start/<token>`: a local link that redirects
    /// to the authorization URL.
    ///
    /// Open it with [`open_browser`](Self::open_browser), or show it when the
    /// browser cannot be opened. It works while [`wait`](Self::wait) runs and
    /// is dead once the wait is over.
    #[must_use]
    pub fn start_link(&self) -> &str {
        self.start.link()
    }

    /// Opens the start link in the system browser. Only this link can be
    /// opened.
    ///
    /// Runs `open` on macOS, `rundll32 url.dll,FileProtocolHandler` on
    /// Windows and `xdg-open` elsewhere. The OS resolves the executable name, so
    /// the launcher must supply a trusted search path. No shell handles the
    /// link, but local users with access to process arguments can read it. The opener has a
    /// second to report a failure. Success means the opener did not fail,
    /// not that a browser window appeared: keep
    /// [`start_link`](Self::start_link) within the user's reach either way.
    ///
    /// An opener that takes longer than the second is collected while
    /// [`wait`](Self::wait) runs. One that outlives the wait, such as an
    /// `xdg-open` that runs the browser itself, stays in the process table
    /// until the app exits.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::BrowserUnavailable`] when the opener cannot be started
    /// or reports a failure; show [`start_link`](Self::start_link) instead.
    /// [`ErrorKind::Cancelled`] when the wait was already cancelled.
    pub fn open_browser(&self) -> Result<(), Error> {
        if self.canceller.is_cancelled() {
            return Err(cancelled());
        }
        if let Some(opener) = browser::open(&self.start)? {
            self.openers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(opener);
        }
        Ok(())
    }

    /// A handle that stops [`wait`](Self::wait) from another thread.
    #[must_use]
    pub fn canceller(&self) -> Canceller {
        self.canceller.clone()
    }

    /// Serves requests until this attempt's callback arrives, `timeout`
    /// passes or the wait is cancelled. The socket closes on return. Elapsed
    /// time follows [`std::time::Instant`]; on Linux and macOS, system sleep pauses the wait.
    ///
    /// Up to eight connections are served at once, so a browser's idle
    /// speculative connection does not hold up the real request. Each one
    /// gets two seconds for a `GET` with `Host: 127.0.0.1:<port>`. On port
    /// 80, browsers can omit the port. Other requests get a small error
    /// response or are dropped, and the wait goes on.
    /// A callback without this attempt's `state` gets `404` and leaves the
    /// attempt open.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Cancelled`] after [`Canceller::cancel`], even when the
    /// timeout has passed too; [`ErrorKind::TimedOut`] when `timeout`
    /// passed; [`ErrorKind::Loopback`] when the socket stops accepting
    /// connections. What the callback itself said is in
    /// [`Received::outcome`].
    pub fn wait(self, timeout: Duration) -> Result<Received, Error> {
        let Self {
            socket,
            port,
            mut attempt,
            start,
            page,
            canceller,
            openers,
            head_deadline,
        } = self;
        let host = format!("127.0.0.1:{port}");
        let started = Instant::now();
        let mut openers = openers.into_inner().unwrap_or_else(PoisonError::into_inner);
        let mut failed_turns = 0_u32;
        let mut open: Vec<Connection> = Vec::with_capacity(MAX_CONNECTIONS);
        let mut connections = Vec::with_capacity(MAX_CONNECTIONS);
        loop {
            // An opener that has exited is collected, so it does not stay
            // behind as a defunct process.
            openers.retain_mut(|opener| matches!(opener.try_wait(), Ok(None)));
            if canceller.is_cancelled() {
                return Err(self::cancelled());
            }
            let Some(left) = timeout
                .checked_sub(started.elapsed())
                .filter(|left| !left.is_zero())
            else {
                return Err(Error::new(
                    ErrorKind::TimedOut,
                    "the sign-in was not completed in time",
                ));
            };

            open.retain(|connection| match connection.state {
                ConnectionState::Reading(_) => connection.since.elapsed() < head_deadline,
                ConnectionState::Writing(_) => connection.since.elapsed() < response::WRITE_TIMEOUT,
            });
            let mut busy = match accept_pending(&socket, &mut open) {
                Ok(any) => {
                    failed_turns = 0;
                    any
                }
                Err(()) if failed_turns < FAILED_TURNS => {
                    failed_turns += 1;
                    false
                }
                Err(()) => {
                    return Err(loopback(
                        "the loopback listener stopped accepting connections",
                    ));
                }
            };
            std::mem::swap(&mut open, &mut connections);
            for mut connection in connections.drain(..) {
                if canceller.is_cancelled() {
                    return Err(self::cancelled());
                }
                if started.elapsed() >= timeout {
                    break;
                }
                let response = match &mut connection.state {
                    ConnectionState::Writing(response) => {
                        if connection.since.elapsed() < response::WRITE_TIMEOUT
                            && response.pending(&mut connection.stream)
                        {
                            open.push(connection);
                        }
                        continue;
                    }
                    ConnectionState::Reading(head) => {
                        let mut stream = &connection.stream;
                        let step = head.read(&mut stream, &host);
                        if connection.since.elapsed() >= head_deadline {
                            continue;
                        }
                        match step {
                            Step::Pending => {
                                open.push(connection);
                                continue;
                            }
                            Step::Refused(refusal) => refuse(refusal),
                            Step::Target(request) => {
                                match serve(&mut attempt, &request, &start, &page) {
                                    Ok(outcome) => {
                                        return Ok(Received {
                                            outcome,
                                            reply: Reply::new(connection.stream, page),
                                        });
                                    }
                                    Err(response) => Some(response),
                                }
                            }
                        }
                    }
                };
                if let Some(mut response) = response {
                    busy = true;
                    if response.pending(&mut connection.stream) {
                        connection.since = Instant::now();
                        connection.state = ConnectionState::Writing(response);
                        open.push(connection);
                    }
                }
            }
            if !busy {
                thread::sleep(left.min(POLL_INTERVAL));
            }
        }
    }
}

impl fmt::Debug for Waiting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Waiting")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// This attempt's callback, and the browser tab that sent it.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "handle the callback outcome and answer the browser"]
pub struct Received {
    /// What the callback said, as [`Attempt::accept`] checked it.
    pub outcome: Result<Accepted, Error>,
    /// The browser tab that still waits for its page.
    pub reply: Reply,
}

/// One accepted connection, reading its head or writing a short response.
struct Connection {
    stream: TcpStream,
    since: Instant,
    state: ConnectionState,
}

enum ConnectionState {
    Reading(Head),
    Writing(response::Response),
}

/// Takes every pending connection from the backlog, up to the limits.
/// Returns whether there was any, or `Err` when the socket failed in a way
/// that is not about one connection.
fn accept_pending(socket: &TcpListener, open: &mut Vec<Connection>) -> Result<bool, ()> {
    let mut any = false;
    for _ in 0..ACCEPTS_PER_TURN {
        match socket.accept() {
            Ok((stream, _)) => {
                any = true;
                // Beyond the limit, or not switchable to non-blocking: the
                // connection is closed without a response.
                if open.len() < MAX_CONNECTIONS && stream.set_nonblocking(true).is_ok() {
                    open.push(Connection {
                        stream,
                        since: Instant::now(),
                        state: ConnectionState::Reading(Head::new()),
                    });
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(any),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                ) => {}
            Err(_) => return Err(()),
        }
    }
    Ok(any)
}

fn refuse(refusal: Refusal) -> Option<response::Response> {
    let status = match refusal {
        Refusal::Malformed => Status::BadRequest,
        Refusal::Method => Status::MethodNotAllowed,
        Refusal::TooLarge => Status::HeaderFieldsTooLarge,
        Refusal::Silent => return None,
    };
    Some(response::plain(status))
}

/// An accepted callback ends the wait. Other requests get an immediate response.
fn serve(
    attempt: &mut Option<Attempt>,
    request: &str,
    start: &StartLink,
    page: &Page,
) -> Result<Result<Accepted, Error>, response::Response> {
    let (path, query) = request.split_once('?').unwrap_or((request, ""));
    if path == CALLBACK_PATH {
        let Some(current) = attempt.take() else {
            return Err(response::plain(Status::NotFound));
        };
        return match current.accept(query) {
            Callback::Unrelated(current) => {
                *attempt = Some(current);
                Err(response::plain(Status::NotFound))
            }
            Callback::Final(outcome) => Ok(outcome),
        };
    }
    Err(if start.matches(path) {
        let url = attempt.as_ref().map_or("", Attempt::authorization_url);
        response::redirect(url)
    } else if path.starts_with(START_PREFIX) {
        response::html(Status::NotFound, page, page.link_expired())
    } else {
        response::plain(Status::NotFound)
    })
}

fn loopback(message: &'static str) -> Error {
    Error::new(ErrorKind::Loopback, message)
}

fn cancelled() -> Error {
    Error::new(
        ErrorKind::Cancelled,
        "the app cancelled the wait for the browser",
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    #[test]
    fn serve_always_accepts_os_entropy() {
        let _: fn(Listener, Attempt, Page, &OsEntropy) -> Result<Waiting, Error> = Listener::serve;
    }
    use crate::protocol::Registration;
    use crate::{AppName, HostId};

    use super::*;

    /// Upper bound for a step that is expected to happen; reached only when
    /// a test fails.
    const PATIENCE: Duration = Duration::from_secs(30);

    fn waiting() -> Waiting {
        let app = AppName::new("Paste Perfect").unwrap();
        let host = HostId::generate(&OsEntropy).unwrap();
        let listener = Listener::bind().unwrap();
        let attempt = Attempt::start(
            Registration::New(&app),
            Some(&host),
            listener.port(),
            &OsEntropy,
        )
        .unwrap();
        listener
            .serve(attempt, Page::new(&app), &OsEntropy)
            .unwrap()
    }

    #[test]
    fn the_socket_is_bound_to_the_ipv4_loopback_address_and_no_other() {
        let listener = Listener::bind().unwrap();
        let address = listener.socket.local_addr().unwrap();
        assert_eq!(address.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(address.port(), listener.port());
    }

    #[test]
    fn opening_the_browser_after_a_cancel_is_refused_as_cancelled() {
        let waiting = waiting();
        waiting.canceller().cancel();
        let error = waiting.open_browser().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Cancelled);
    }

    #[test]
    fn a_connection_that_does_not_finish_its_head_in_time_is_closed() {
        let mut waiting = waiting();
        waiting.head_deadline = Duration::from_millis(50);
        let canceller = waiting.canceller();
        let port = waiting.port;
        let wait = thread::spawn(move || waiting.wait(PATIENCE));

        let mut slow = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        slow.write_all(b"GET /auth/callback?state=").unwrap();
        slow.set_read_timeout(Some(PATIENCE)).unwrap();
        // The listener closes the connection without a response while the
        // wait itself goes on.
        let mut answer = Vec::new();
        let closed = slow.read_to_end(&mut answer).map_err(|error| error.kind());
        assert!(
            matches!(closed, Ok(0) | Err(io::ErrorKind::ConnectionReset)),
            "{closed:?}"
        );
        assert!(answer.is_empty());
        assert!(!wait.is_finished(), "the wait goes on");

        canceller.cancel();
        let error = wait.join().unwrap().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Cancelled);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn an_opener_that_exits_during_the_wait_is_collected() {
        let waiting = waiting();
        let mut command = std::process::Command::new("sh");
        command.args(["-c", "exit 0"]);
        let opener = command.spawn().unwrap();
        let listed = format!("/proc/{}", opener.id());
        waiting
            .openers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(opener);

        let error = waiting.wait(Duration::from_millis(200)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        // A collected child has left the process table; a defunct one is
        // still listed there.
        assert!(!std::path::Path::new(&listed).exists());
    }
}
