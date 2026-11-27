//! Collecting one request head from a browser connection and checking it.

use std::io::{self, Read};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::protocol::is_token;

/// Largest request head read, terminator included.
pub(super) const HEAD_LIMIT: usize = 16 * 1024;

/// Time a connection has from its accept to deliver its whole request head.
pub(super) const HEAD_DEADLINE: Duration = Duration::from_secs(2);

/// Why a request is not served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// The head is not a well-formed HTTP/1.x request for this listener.
    Malformed,
    /// The method is not `GET`.
    Method,
    /// The head does not end within [`HEAD_LIMIT`].
    TooLarge,
    /// The connection closed or failed: there is nobody to answer.
    Silent,
}

/// Where a head stands after a read.
pub(super) enum Step {
    /// The head is not complete yet; read again later.
    Pending,
    /// The head is complete and names this request target.
    Target(Zeroizing<String>),
    /// The connection is over without a request to serve.
    Refused(Refusal),
}

/// The bytes of one connection's head received so far.
pub(super) struct Head {
    bytes: Zeroizing<Vec<u8>>,
}

impl Head {
    pub(super) fn new() -> Self {
        // The full capacity up front: the buffer never moves, so no copy of
        // the query is left behind unwiped.
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(HEAD_LIMIT)),
        }
    }

    /// Makes one read from `reader`, which must not block, and checks the
    /// head once it is complete. `Host` must match `host`; browsers may
    /// omit the port when the listener is on port 80.
    /// Never reads past [`HEAD_LIMIT`]; bytes after the head are dropped.
    pub(super) fn read(&mut self, reader: &mut impl Read, host: &str) -> Step {
        let filled = self.bytes.len();
        let room = HEAD_LIMIT.saturating_sub(filled);
        if room == 0 {
            return Step::Refused(Refusal::TooLarge);
        }
        self.bytes.resize(HEAD_LIMIT, 0);
        let result = match self.bytes.get_mut(filled..) {
            Some(spare) => reader.read(spare),
            None => Ok(0),
        };
        let read = match result {
            Ok(0) => return Step::Refused(Refusal::Silent),
            Ok(read) => read.min(room),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                0
            }
            Err(_) => return Step::Refused(Refusal::Silent),
        };
        self.bytes.truncate(filled + read);
        // The terminator may straddle the previous read.
        match head_end(&self.bytes, filled.saturating_sub(3)) {
            Some(end) => match parse(self.bytes.get(..end).unwrap_or_default(), host) {
                Ok(target) => Step::Target(target),
                Err(refusal) => Step::Refused(refusal),
            },
            None if self.bytes.len() >= HEAD_LIMIT => Step::Refused(Refusal::TooLarge),
            None => Step::Pending,
        }
    }
}

/// The length of the head if `bytes` holds its terminator, searching from
/// `from`.
fn head_end(bytes: &[u8], from: usize) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| from + position + 4)
}

/// Checks a complete head and returns its request target.
fn parse(head: &[u8], host: &str) -> Result<Zeroizing<String>, Refusal> {
    let text = std::str::from_utf8(head).map_err(|_| Refusal::Malformed)?;
    let text = text.strip_suffix("\r\n\r\n").ok_or(Refusal::Malformed)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(Refusal::Malformed)?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refusal::Malformed);
    };
    let well_formed = is_token(method.as_bytes())
        && target.starts_with('/')
        && target.bytes().all(|byte| byte.is_ascii_graphic())
        && matches!(version, "HTTP/1.0" | "HTTP/1.1");
    if !well_formed {
        return Err(Refusal::Malformed);
    }

    let mut hosts = 0;
    let mut host_matches = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(Refusal::Malformed)?;
        // A name with spaces, or a folded continuation line, is malformed.
        if !is_token(name.as_bytes()) {
            return Err(Refusal::Malformed);
        }
        // RFC 9110 section 5.5: no control character but HTAB in a value.
        if value
            .bytes()
            .any(|byte| byte != b'\t' && byte.is_ascii_control())
        {
            return Err(Refusal::Malformed);
        }
        if name.eq_ignore_ascii_case("host") {
            hosts += 1;
            let value = value.trim_matches([' ', '\t']);
            host_matches = value == host || (host == "127.0.0.1:80" && value == "127.0.0.1");
        }
    }
    if method != "GET" {
        return Err(Refusal::Method);
    }
    if hosts != 1 || !host_matches {
        return Err(Refusal::Malformed);
    }
    Ok(Zeroizing::new(target.to_owned()))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    const HOST: &str = "127.0.0.1:53124";

    /// A non-blocking connection, scripted: each read hands out the next
    /// piece, at most as many bytes as fit; an empty script reads as closed.
    struct Script(VecDeque<Result<Vec<u8>, io::ErrorKind>>);

    impl Script {
        fn new(pieces: impl IntoIterator<Item = Result<Vec<u8>, io::ErrorKind>>) -> Self {
            Self(pieces.into_iter().collect())
        }

        fn whole(bytes: impl Into<Vec<u8>>) -> Self {
            Self::new([Ok(bytes.into())])
        }
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.pop_front() {
                None => Ok(0),
                Some(Err(kind)) => Err(kind.into()),
                Some(Ok(mut piece)) => {
                    let count = piece.len().min(buf.len());
                    buf[..count].copy_from_slice(&piece[..count]);
                    let rest = piece.split_off(count);
                    if !rest.is_empty() {
                        self.0.push_front(Ok(rest));
                    }
                    Ok(count)
                }
            }
        }
    }

    /// Reads until the head is complete or refused; returns the outcome and
    /// how many reads came back pending.
    fn drive(script: &mut Script) -> (Result<String, Refusal>, usize) {
        let mut head = Head::new();
        let mut pending = 0;
        loop {
            match head.read(script, HOST) {
                Step::Pending => pending += 1,
                Step::Target(target) => return (Ok(target.to_string()), pending),
                Step::Refused(refusal) => return (Err(refusal), pending),
            }
            assert!(pending < 100, "the head never completed");
        }
    }

    fn request(head: &str) -> Result<String, Refusal> {
        drive(&mut Script::whole(head)).0
    }

    #[test]
    fn a_get_with_the_listeners_host_yields_its_target() {
        let head =
            format!("GET /auth/callback?a=b HTTP/1.1\r\nHost: {HOST}\r\nAccept: */*\r\n\r\n");
        assert_eq!(request(&head).unwrap(), "/auth/callback?a=b");
        let old = format!("GET / HTTP/1.0\r\nhost:{HOST}  \r\n\r\n");
        assert_eq!(request(&old).unwrap(), "/");

        let default_port = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        assert_eq!(*parse(default_port, "127.0.0.1:80").unwrap(), "/");
        assert!(parse(default_port, HOST).is_err());
    }

    #[test]
    fn a_head_that_arrives_in_pieces_between_empty_reads_is_assembled() {
        let mut script = Script::new([
            Err(io::ErrorKind::WouldBlock),
            Ok(b"GET /x HT".to_vec()),
            Err(io::ErrorKind::WouldBlock),
            Ok(format!("TP/1.1\r\nHost: {HOST}\r").into_bytes()),
            Err(io::ErrorKind::Interrupted),
            Ok(b"\n\r".to_vec()),
            Err(io::ErrorKind::WouldBlock),
            Ok(b"\nbody that is never looked at".to_vec()),
        ]);
        let (target, pending) = drive(&mut script);
        assert_eq!(target.unwrap(), "/x");
        assert_eq!(pending, 7);
    }

    #[test]
    fn a_head_of_exactly_the_limit_is_read_and_one_byte_more_is_too_large() {
        let start = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nX-Fill: ");
        let fill = HEAD_LIMIT - start.len() - 4;
        let fits = format!("{start}{}\r\n\r\n", "a".repeat(fill));
        assert_eq!(fits.len(), HEAD_LIMIT);
        assert_eq!(request(&fits).unwrap(), "/");

        let over = format!("{start}{}\r\n\r\n", "a".repeat(fill + 1));
        assert_eq!(request(&over), Err(Refusal::TooLarge));
    }

    #[test]
    fn a_head_that_never_ends_stops_at_the_limit() {
        let mut script = Script::new([Ok(vec![b'a'; 1000]), Ok(vec![b'a'; 3 * HEAD_LIMIT])]);
        assert_eq!(drive(&mut script).0, Err(Refusal::TooLarge));
        let unread: usize = script
            .0
            .iter()
            .map(|piece| piece.as_ref().unwrap().len())
            .sum();
        assert_eq!(
            unread,
            2 * HEAD_LIMIT + 1000,
            "nothing past the limit is read"
        );
    }

    #[test]
    fn an_early_close_and_a_failed_read_are_silent() {
        let partial = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\n").into_bytes();
        let mut closed = Script::new([Ok(partial.clone())]);
        assert_eq!(drive(&mut closed).0, Err(Refusal::Silent));
        let mut reset = Script::new([Ok(partial), Err(io::ErrorKind::ConnectionReset)]);
        assert_eq!(drive(&mut reset).0, Err(Refusal::Silent));
        let mut timed_out = Script::new([Err(io::ErrorKind::TimedOut)]);
        assert_eq!(drive(&mut timed_out).0, Err(Refusal::Silent));
    }

    #[test]
    fn other_methods_are_not_allowed() {
        for method in ["POST", "HEAD", "OPTIONS", "get"] {
            let head = format!("{method} / HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
            assert_eq!(request(&head), Err(Refusal::Method), "{method}");
        }
    }

    #[test]
    fn a_missing_repeated_or_other_host_is_malformed() {
        for headers in [
            String::new(),
            "Host: localhost:53124\r\n".to_owned(),
            "Host: 127.0.0.1\r\n".to_owned(),
            "Host: 127.0.0.1:53125\r\n".to_owned(),
            "Host: attacker.example\r\n".to_owned(),
            "Host: [::1]:53124\r\n".to_owned(),
            format!("Host: {HOST}\r\nHost: {HOST}\r\n"),
            format!("Host: {HOST}\r\nhost: attacker.example\r\n"),
        ] {
            let head = format!("GET / HTTP/1.1\r\n{headers}\r\n");
            assert_eq!(request(&head), Err(Refusal::Malformed), "{headers:?}");
        }
    }

    #[test]
    fn malformed_request_lines_and_headers_are_refused() {
        for head in [
            format!("GET / HTTP/2.0\r\nHost: {HOST}\r\n\r\n"),
            format!("GET / HTTP/1.1 extra\r\nHost: {HOST}\r\n\r\n"),
            format!("GET  / HTTP/1.1\r\nHost: {HOST}\r\n\r\n"),
            format!("GET /a\tb HTTP/1.1\r\nHost: {HOST}\r\n\r\n"),
            format!("GET /\u{e4} HTTP/1.1\r\nHost: {HOST}\r\n\r\n"),
            format!("GET http://{HOST}/ HTTP/1.1\r\nHost: {HOST}\r\n\r\n"),
            format!("GET /\r\nHost: {HOST}\r\n\r\n"),
            format!("\r\nGET / HTTP/1.1\r\nHost: {HOST}\r\n\r\n"),
            format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nNo colon here\r\n\r\n"),
            format!("GET / HTTP/1.1\r\nHost: {HOST}\r\n folded: value\r\n\r\n"),
            format!("GET / HTTP/1.1\r\nHost : {HOST}\r\n\r\n"),
        ] {
            assert_eq!(request(&head), Err(Refusal::Malformed), "{head:?}");
        }
    }

    /// Starts from a valid head and damages it at random; the same edits
    /// on every run.
    #[test]
    fn damaged_heads_never_panic_and_only_a_get_yields_a_target() {
        let valid = format!(
            "GET /auth/callback?code=abc&state=xyz HTTP/1.1\r\nHost: {HOST}\r\nAccept: */*\r\n\r\n"
        )
        .into_bytes();
        let alphabet = b" \r\n\t:/?%.HTPGEost1";
        let mut seed = 0x2026_1123_u64;
        // SplitMix64.
        let mut below = |bound: usize| {
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut mixed = seed;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            usize::try_from((mixed ^ (mixed >> 31)) % bound as u64).unwrap()
        };
        let (mut served, mut refused) = (0, 0);
        for _ in 0..400 {
            let mut bytes = valid.clone();
            for _ in 0..=below(3) {
                if bytes.is_empty() {
                    break;
                }
                let at = below(bytes.len());
                match below(4) {
                    0 => bytes[at] = alphabet[below(alphabet.len())],
                    1 => drop(bytes.remove(at)),
                    2 => bytes.insert(at, alphabet[below(alphabet.len())]),
                    _ => bytes.truncate(at),
                }
            }
            // In pieces, so that the end of the head is found across reads.
            let mut pieces = Vec::new();
            let mut rest = bytes.as_slice();
            while !rest.is_empty() {
                let (piece, tail) = rest.split_at(1 + below(rest.len()));
                pieces.push(Ok(piece.to_vec()));
                rest = tail;
            }
            match drive(&mut Script::new(pieces)).0 {
                Ok(target) => {
                    assert!(bytes.starts_with(b"GET /"), "{bytes:?}");
                    assert!(target.starts_with('/'), "{target:?}");
                    assert!(!target.contains(|c: char| c.is_whitespace() || c.is_control()));
                    served += 1;
                }
                Err(_) => refused += 1,
            }
        }
        assert!(served > 0 && refused > 0, "{served} / {refused}");
    }

    #[test]
    fn header_values_with_control_characters_are_malformed() {
        for value in ["a\0b", "a\rb", "a\nb", "a\x01b", "a\x1fb", "a\x7fb"] {
            for headers in [
                format!("Host: {HOST}\r\nAccept: {value}\r\n"),
                format!("Accept: {value}\r\nHost: {HOST}\r\n"),
                format!("Host: {HOST}{value}\r\n"),
            ] {
                let head = format!("GET / HTTP/1.1\r\n{headers}\r\n");
                assert_eq!(request(&head), Err(Refusal::Malformed), "{headers:?}");
            }
        }
        let tab = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nAccept:\ttext/html\t\r\n\r\n");
        assert_eq!(request(&tab).unwrap(), "/");
    }

    #[test]
    fn a_head_that_is_not_utf_8_is_malformed() {
        let mut head = b"GET /\xff HTTP/1.1\r\nHost: ".to_vec();
        head.extend_from_slice(HOST.as_bytes());
        head.extend_from_slice(b"\r\n\r\n");
        assert_eq!(drive(&mut Script::whole(head)).0, Err(Refusal::Malformed));
    }
}
