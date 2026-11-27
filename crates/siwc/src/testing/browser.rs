//! Driving the loopback start link and callback from a short-lived helper thread.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::provider::ProviderCore;
use super::user::FakeUser;

/// Upper bound on test loopback socket operations so an abandoned `SignIn`
/// never leaves a helper thread waiting indefinitely.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

/// Most bytes read from one listener response, head and page together.
const RESPONSE_LIMIT: usize = 64 * 1024;

pub(super) enum Outcome {
    Approve(FakeUser),
    Error(String),
}

pub(super) fn drive_loopback(core: Arc<ProviderCore>, start_link: &str, outcome: Outcome) {
    let Some((port, start_path)) = split_start_link(start_link) else {
        return;
    };
    let start_path = start_path.to_owned();
    let _spawned = thread::Builder::new()
        .name("siwc-fake-browser".to_owned())
        .spawn(move || {
            let Some(auth_url) = fetch_redirect(port, &start_path) else {
                return;
            };
            let built = match outcome {
                Outcome::Approve(user) => core.authorize(&auth_url, user),
                Outcome::Error(code) => core.fail_authorization(&auth_url, &code),
            };
            if let Ok((_redirect_uri, query)) = built {
                send_callback(port, &query);
            }
        });
}

fn split_start_link(link: &str) -> Option<(u16, &str)> {
    let rest = link.strip_prefix("http://127.0.0.1:")?;
    let slash = rest.find('/')?;
    let port: u16 = rest.get(..slash)?.parse().ok()?;
    let path = rest.get(slash..)?;
    Some((port, path))
}

fn connect_loopback(port: u16) -> Option<TcpStream> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let stream = TcpStream::connect_timeout(&addr, SOCKET_TIMEOUT).ok()?;
    let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
    Some(stream)
}

fn fetch_redirect(port: u16, start_path: &str) -> Option<String> {
    let mut stream = connect_loopback(port)?;
    let request = format!("GET {start_path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let response = read_response(&mut stream);
    let text = String::from_utf8_lossy(&response);
    let (head, _) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    head.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("location")
            .then(|| value.trim().to_owned())
    })
}

fn send_callback(port: u16, query: &str) {
    let Some(mut stream) = connect_loopback(port) else {
        return;
    };
    let request = format!("GET /auth/callback?{query} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return;
    }
    let _page = read_response(&mut stream);
}

/// Reads a listener response until the listener closes, [`RESPONSE_LIMIT`]
/// bytes have arrived or [`SOCKET_TIMEOUT`] has passed in all.
fn read_response(stream: &mut TcpStream) -> Vec<u8> {
    let deadline = Instant::now() + SOCKET_TIMEOUT;
    let mut response = vec![0; RESPONSE_LIMIT];
    let mut filled = 0;
    while let Some(spare) = response.get_mut(filled..).filter(|spare| !spare.is_empty()) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match stream.read(spare) {
            Ok(0) | Err(_) => break,
            Ok(read) => filled += read,
        }
    }
    response.truncate(filled);
    response
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn a_response_that_does_not_end_is_read_only_up_to_the_limit() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            // Fails once the reader has had enough and closes.
            let _sent = connection.write_all(&vec![b'a'; 4 * RESPONSE_LIMIT]);
        });
        let mut stream = connect_loopback(port).unwrap();
        let response = read_response(&mut stream);
        drop(stream);
        server.join().unwrap();
        assert_eq!(response.len(), RESPONSE_LIMIT);
    }
}
