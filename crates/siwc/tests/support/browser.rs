//! A browser played by a `TcpStream` on `127.0.0.1`: it follows the start
//! link, sends callbacks and reads the pages the listener answers with.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::time::Duration;

use super::provider::{FakeProvider, User};
use super::wire::{form_decode, form_encode, only};

/// Upper bound for anything a test waits for; reached only when a test
/// fails.
pub const PATIENCE: Duration = Duration::from_secs(30);

/// The browser side of one sign-in: the listener's port and start link.
pub struct Browser {
    pub port: u16,
    pub link: String,
}

impl Browser {
    /// A browser for the sign-in whose start link is `link`.
    pub fn new(link: &str) -> Self {
        let port = link
            .strip_prefix("http://127.0.0.1:")
            .and_then(|rest| rest.split_once('/'))
            .and_then(|(port, _)| port.parse().ok())
            .expect("a start link on 127.0.0.1");
        Self {
            port,
            link: link.to_owned(),
        }
    }

    pub fn start_path(&self) -> String {
        let prefix = format!("http://127.0.0.1:{}", self.port);
        self.link.strip_prefix(&prefix).unwrap().to_owned()
    }

    pub fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// A browser request for `target`, with the right `Host`.
    pub fn get(&self, target: &str) -> Response {
        let head = format!("GET {target} HTTP/1.1\r\nHost: {}\r\n\r\n", self.host());
        self.raw(head.as_bytes())
    }

    pub fn raw(&self, bytes: &[u8]) -> Response {
        let mut browser = connect(self.port);
        // The listener may close before reading everything it was sent.
        let _ = browser.write_all(bytes);
        read_response(browser)
    }

    /// Follows the start link; returns where it redirects.
    pub fn authorization_url(&self) -> String {
        let response = self.get(&self.start_path());
        assert_eq!(response.status, 302, "{}", response.head);
        response.header("location").unwrap().to_owned()
    }

    /// Sends the callback; the connection stays open for the answer page.
    pub fn callback(&self, query: &str) -> TcpStream {
        let mut browser = connect(self.port);
        let head = format!(
            "GET /auth/callback?{query} HTTP/1.1\r\nHost: {}\r\n\r\n",
            self.host()
        );
        browser.write_all(head.as_bytes()).unwrap();
        browser
    }

    /// The whole browser side: follows the start link, lets `user` approve
    /// at the provider, returns to the app and reads the answer page.
    pub fn approve(&self, provider: &FakeProvider, user: &User) -> Response {
        let query = provider.authorize(&self.authorization_url(), user);
        read_response(self.callback(&query))
    }

    /// Follows the start link, lets the user decline and reads the page.
    pub fn decline(&self, provider: &FakeProvider) -> Response {
        let query = provider.deny(&self.authorization_url());
        read_response(self.callback(&query))
    }

    /// Follows the start link and returns with the provider's error `code`
    /// instead of an approval.
    pub fn fail(&self, code: &str) -> Response {
        let url = self.authorization_url();
        let request = form_decode(url.split_once('?').unwrap().1);
        let query = form_encode(&[("error", code), ("state", only(&request, "state"))]);
        read_response(self.callback(&query))
    }
}

pub fn connect(port: u16) -> TcpStream {
    let browser = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    browser.set_read_timeout(Some(PATIENCE)).unwrap();
    browser
}

/// What the browser read until the listener closed the connection; status
/// 0 when there was no answer at all.
pub struct Response {
    pub status: u16,
    pub head: String,
    pub body: String,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.head.split("\r\n").skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    /// The heading of an answer page.
    pub fn heading(&self) -> &str {
        self.body
            .split_once("<h1>")
            .and_then(|(_, rest)| rest.split_once("</h1>"))
            .map_or("", |(heading, _)| heading)
    }
}

pub fn read_response(mut browser: TcpStream) -> Response {
    let mut bytes = Vec::new();
    // A reset after a refusal still leaves what arrived before it.
    let _ = browser.read_to_end(&mut bytes);
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    Response {
        status,
        head: head.to_owned(),
        body: body.to_owned(),
    }
}

/// A connection the listener has not closed: a read finds nothing yet.
pub fn still_open(browser: &TcpStream) -> bool {
    browser.set_nonblocking(true).unwrap();
    let open = matches!(
        (&*browser).read(&mut [0u8; 1]),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    );
    browser.set_nonblocking(false).unwrap();
    open
}
