//! Opening a verified TLS connection to one host: TCP and the handshake,
//! every step bounded by the exchange's deadline. With a canceller, every
//! wait but a TCP connect in progress also ends within about 50 ms of its
//! trigger.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::cancel::Canceller;

use super::deadline::{Deadline, stop_if_cancelled, wait_left};
use super::proxy::{self, Proxy, ProxyScheme};

/// The port every provider request goes to.
pub(super) const PORT: u16 = 443;

/// A TLS connection whose reads and writes end at the deadline.
pub(super) type Stream = StreamOwned<ClientConnection, Carrier>;

/// What carries the provider's TLS records: a direct or `http://`-proxied TCP
/// socket, or an outer TLS 1.3 connection to an `https://` proxy.
pub(super) enum Carrier {
    Tcp(Socket),
    TlsProxy(Box<StreamOwned<ClientConnection, Socket>>),
}

impl Carrier {
    /// The TCP socket underneath, whose reads and writes carry the limits.
    pub(super) fn socket_mut(&mut self) -> &mut Socket {
        match self {
            Self::Tcp(socket) => socket,
            Self::TlsProxy(tls) => &mut tls.sock,
        }
    }
}

impl Read for Carrier {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(socket) => socket.read(buf),
            Self::TlsProxy(tls) => tls.read(buf),
        }
    }
}

impl Write for Carrier {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(socket) => socket.write(buf),
            Self::TlsProxy(tls) => tls.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(socket) => socket.flush(),
            Self::TlsProxy(tls) => tls.flush(),
        }
    }
}

/// Connects to the first of `addresses` that answers within
/// `connect_timeout` and completes a TLS handshake for `host`.
///
/// The handshake is finished before this returns, so nothing of a request
/// is written to a server whose certificate does not verify.
pub(super) fn open(
    config: &Arc<ClientConfig>,
    host: &'static str,
    addresses: &[SocketAddr],
    connect_timeout: Duration,
    deadline: Deadline,
    canceller: Option<&Canceller>,
) -> io::Result<Stream> {
    let tcp = tcp(addresses, connect_timeout, deadline, canceller)?;
    let name = ServerName::try_from(host).map_err(|_| io::ErrorKind::InvalidInput)?;
    let socket = Socket::new(tcp, deadline, canceller);
    handshake(config, name, Carrier::Tcp(socket))
}

/// Connects to `proxy`, completes an outer TLS 1.3 handshake when `proxy` is
/// `https://`, establishes an HTTP `CONNECT <host>:443` tunnel, and completes
/// the inner end-to-end TLS 1.3 handshake for `host` before returning.
pub(super) fn open_via_proxy(
    config: &Arc<ClientConfig>,
    proxy: &Proxy,
    proxy_addresses: &[SocketAddr],
    host: &'static str,
    connect_timeout: Duration,
    deadline: Deadline,
    canceller: Option<&Canceller>,
) -> io::Result<Stream> {
    let tcp = tcp(proxy_addresses, connect_timeout, deadline, canceller)?;
    let socket = Socket::new(tcp, deadline, canceller);
    let mut carrier = match proxy.scheme {
        ProxyScheme::Http => Carrier::Tcp(socket),
        ProxyScheme::Https => {
            let outer = handshake_socket(config, proxy.server_name(), socket)?;
            Carrier::TlsProxy(Box::new(outer))
        }
    };
    proxy::establish_tunnel(&mut carrier, host)?;
    let target = ServerName::try_from(host).map_err(|_| io::ErrorKind::InvalidInput)?;
    handshake(config, target, carrier)
}

fn handshake_socket(
    config: &Arc<ClientConfig>,
    name: ServerName<'static>,
    mut socket: Socket,
) -> io::Result<StreamOwned<ClientConnection, Socket>> {
    let mut connection = ClientConnection::new(Arc::clone(config), name)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket)?;
    }
    Ok(StreamOwned::new(connection, socket))
}

fn handshake(
    config: &Arc<ClientConfig>,
    name: ServerName<'static>,
    mut carrier: Carrier,
) -> io::Result<Stream> {
    let mut connection = ClientConnection::new(Arc::clone(config), name)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    while connection.is_handshaking() {
        connection.complete_io(&mut carrier)?;
    }
    Ok(StreamOwned::new(connection, carrier))
}

/// A connect in progress is the one wait a canceller does not end: the
/// standard library offers no way to interrupt it, so it lasts at most
/// `connect_timeout`. No further address is tried after a cancellation.
fn tcp(
    addresses: &[SocketAddr],
    connect_timeout: Duration,
    deadline: Deadline,
    canceller: Option<&Canceller>,
) -> io::Result<TcpStream> {
    let mut last = io::Error::from(io::ErrorKind::NotFound);
    for address in addresses {
        stop_if_cancelled(canceller)?;
        let timeout = connect_timeout.min(deadline.remaining()?);
        match TcpStream::connect_timeout(address, timeout) {
            Ok(tcp) => {
                tcp.set_nodelay(true)?;
                return Ok(tcp);
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// The socket uses the deadline of the exchange or of the body read in
/// progress. No TLS record or partial socket read extends it.
#[derive(Debug)]
pub(super) struct Socket {
    tcp: TcpStream,
    deadline: Deadline,
    canceller: Option<Canceller>,
    #[cfg(test)]
    pub(super) after_first_byte: Option<Canceller>,
}

impl Socket {
    fn new(tcp: TcpStream, deadline: Deadline, canceller: Option<&Canceller>) -> Self {
        Self {
            tcp,
            deadline,
            canceller: canceller.cloned(),
            #[cfg(test)]
            after_first_byte: None,
        }
    }

    /// A buffered request is about to write its first byte. Keep the total
    /// deadline but let the exchange return the answer to that request.
    pub(super) fn finish_after_cancel(&mut self) {
        self.canceller = None;
    }

    pub(super) fn set_deadline(&mut self, deadline: Deadline) {
        self.deadline = deadline;
    }

    /// Keeps one deadline across all attempts to read the next bytes.
    fn read_with(
        &mut self,
        mut read: impl FnMut(&mut TcpStream) -> io::Result<usize>,
    ) -> io::Result<usize> {
        loop {
            let left = wait_left(self.deadline, self.canceller.as_ref())?;
            self.tcp.set_read_timeout(Some(left))?;
            match read(&mut self.tcp) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    #[cfg(test)]
                    waiting::blocked(waiting::Wait::Read);
                    self.deadline.remaining()?;
                }
                other => return other,
            }
        }
    }
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_with(|tcp| tcp.read(buf))
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let left = wait_left(self.deadline, self.canceller.as_ref())?;
            self.tcp.set_write_timeout(Some(left))?;
            #[cfg(test)]
            if let Some(first) = buf.first()
                && let Some(stop) = self.after_first_byte.take()
            {
                self.tcp.write_all(std::slice::from_ref(first))?;
                stop.cancel();
                return Ok(1);
            }
            match self.tcp.write(buf) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    #[cfg(test)]
                    waiting::blocked(waiting::Wait::Write);
                    self.deadline.remaining()?;
                }
                other => return other,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

#[cfg(test)]
pub(super) mod waiting {
    use std::cell::RefCell;
    use std::sync::mpsc::Sender;

    #[derive(Debug, PartialEq, Eq)]
    pub(in crate::https) enum Wait {
        Read,
        Write,
    }

    thread_local! {
        static WAITS: RefCell<Option<Sender<Wait>>> = const { RefCell::new(None) };
    }

    pub(in crate::https) fn observe(sender: Sender<Wait>) {
        WAITS.set(Some(sender));
    }

    pub(super) fn blocked(wait: Wait) {
        WAITS.with_borrow(|sender| {
            if let Some(sender) = sender {
                let _ = sender.send(wait);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn a_cancelled_exchange_connects_to_no_address() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let deadline = Deadline::after(TEST_TIMEOUT).unwrap();
        let canceller = Canceller::new();
        canceller.cancel();
        let error = tcp(&[address], TEST_TIMEOUT, deadline, Some(&canceller)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        // A connection that was made would be waiting here.
        let nobody = listener.accept().unwrap_err();
        assert_eq!(nobody.kind(), io::ErrorKind::WouldBlock);
        // Without a cancellation the same call connects.
        tcp(&[address], TEST_TIMEOUT, deadline, Some(&Canceller::new())).unwrap();
        listener.accept().unwrap();
    }

    #[test]
    fn a_canceller_ends_a_write_that_the_peer_does_not_take() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let deadline = Deadline::after(TEST_TIMEOUT).unwrap();
        let canceller = Canceller::new();
        let stream = tcp(&[address], TEST_TIMEOUT, deadline, None).unwrap();
        // The peer accepts and then reads nothing.
        let (_peer, _) = listener.accept().unwrap();
        let mut socket = Socket::new(stream, deadline, Some(&canceller));

        let (blocked, waits) = mpsc::channel();
        let writer = thread::spawn(move || {
            waiting::observe(blocked);
            let block = [0_u8; 64 * 1024];
            loop {
                if let Err(error) = socket.write(&block) {
                    return error;
                }
            }
        });
        assert_eq!(
            waits.recv_timeout(TEST_TIMEOUT).unwrap(),
            waiting::Wait::Write
        );
        canceller.cancel();
        assert_eq!(
            writer.join().unwrap().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[test]
    fn interrupted_socket_reads_keep_their_idle_deadline_and_check_for_cancellation() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let deadline = Deadline::after(TEST_TIMEOUT).unwrap();
        let stop = Canceller::new();
        let mut socket = Socket::new(stream, deadline, Some(&stop));
        socket.set_deadline(Deadline::after(Duration::from_millis(20)).unwrap());
        let mut attempts = 0;
        let error = socket
            .read_with(|tcp| {
                attempts += 1;
                assert!(attempts <= 4, "interruptions started a fresh idle deadline");
                // Interrupt a silent read after its socket timeout has elapsed.
                let error = tcp.read(&mut [0]).unwrap_err();
                assert!(matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ));
                Err(io::ErrorKind::Interrupted.into())
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        socket.set_deadline(Deadline::after(TEST_TIMEOUT).unwrap());
        let error = socket
            .read_with(|_| {
                assert!(!stop.is_cancelled(), "a cancelled read was retried");
                stop.cancel();
                Err(io::ErrorKind::Interrupted.into())
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }
}
