//! The loopback listener, driven over real `127.0.0.1` sockets: a
//! `TcpStream` plays the browser, a thread runs the wait.

use std::io::{ErrorKind as IoErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::ops::Deref;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use siwc::loopback::{Answer, Canceller, Listener, LogoFormat, Page, Received, Style};
use siwc::protocol::{Attempt, Registration};
use siwc::{AppName, ErrorKind};

use crate::support::browser::{Browser, PATIENCE, connect, read_response, still_open};
use crate::support::provider::User;
use crate::support::wire::{form_decode, only};
use crate::support::{World, saved};

/// A listener waiting on its own thread for one attempt.
struct Running {
    browser: Browser,
    canceller: Canceller,
    waiting: JoinHandle<Result<Received, siwc::Error>>,
}

fn running(world: &World) -> Running {
    running_with(world, Page::new(&world.app))
}

fn running_with(world: &World, page: Page) -> Running {
    let listener = Listener::bind().unwrap();
    let port = listener.port();
    let attempt = Attempt::start_with_entropy(
        Registration::New(&world.app),
        Some(&world.host),
        port,
        &world.entropy,
    )
    .unwrap();
    let waiting = listener
        .serve_with_entropy(attempt, page, &world.entropy)
        .unwrap();
    let link = waiting.start_link().to_owned();
    let canceller = waiting.canceller();
    let waiting = thread::spawn(move || waiting.wait(PATIENCE));
    Running {
        browser: Browser { port, link },
        canceller,
        waiting,
    }
}

/// The browser requests go to the running listener.
impl Deref for Running {
    type Target = Browser;

    fn deref(&self) -> &Browser {
        &self.browser
    }
}

impl Running {
    /// The provider's redirect after `user` approved, as a callback query.
    fn approved(&self, world: &World, user: &User) -> String {
        world.provider.authorize(&self.authorization_url(), user)
    }

    fn received(self) -> Received {
        self.waiting.join().unwrap().unwrap()
    }

    fn ended(self) -> siwc::Error {
        self.waiting.join().unwrap().unwrap_err()
    }

    /// Cancels the wait and checks that it ended that way.
    fn stop(self) {
        self.canceller.cancel();
        assert_eq!(self.ended().kind(), ErrorKind::Cancelled);
    }
}

#[test]
fn the_listener_binds_127_0_0_1_on_a_port_the_system_chose() {
    let listener = Listener::bind().unwrap();
    assert_ne!(listener.port(), 0);
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, listener.port())).is_ok());
    assert_ne!(Listener::bind().unwrap().port(), listener.port());
}

#[test]
fn a_port_the_app_chose_is_bound_and_a_taken_one_is_refused() {
    let free = Listener::bind().unwrap().port();
    let listener = Listener::bind_port(free).unwrap();
    assert_eq!(listener.port(), free);

    let error = Listener::bind_port(free).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Loopback);
}

#[test]
fn an_attempt_for_another_port_is_refused() {
    let world = World::new();
    let listener = Listener::bind().unwrap();
    let attempt = world.attempt(Registration::New(&world.app));
    assert_ne!(
        attempt.redirect_uri(),
        format!("http://127.0.0.1:{}/auth/callback", listener.port())
    );

    let error = listener
        .serve_with_entropy(attempt, Page::new(&world.app), &world.entropy)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

#[test]
fn the_start_link_redirects_to_the_authorization_url_and_works_twice() {
    let world = World::new();
    let running = running(&world);
    let token = running
        .link
        .strip_prefix(&format!("http://127.0.0.1:{}/start/", running.port))
        .unwrap();
    assert_eq!(token.len(), 32);
    assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let first = running.authorization_url();
    let second = running.authorization_url();
    assert_eq!(first, second);
    assert!(first.starts_with("https://auth.openai.com/api/accounts/authorize?"));
    let redirect_uri = format!("http://127.0.0.1:{}/auth/callback", running.port);
    assert_eq!(
        only(
            &form_decode(first.split_once('?').unwrap().1),
            "redirect_uri"
        ),
        redirect_uri
    );
    running.stop();
}

#[test]
fn a_wrong_start_token_gets_the_expired_page() {
    let world = World::new();
    let running = running(&world);
    let wrong = format!("{}0", running.start_path());

    for target in [
        wrong.as_str(),
        "/start/00112233445566778899aabbccddeeff",
        "/start/",
    ] {
        let response = running.get(target);
        assert_eq!(response.status, 404, "{target}");
        assert!(
            response
                .body
                .contains("<h1>This sign-in link is no longer valid</h1>")
        );
        assert!(
            response
                .body
                .contains("Return to Paste Perfect and start again.")
        );
        assert!(!response.body.contains("00112233") && !response.body.contains("/start/"));
        assert!(response.header("location").is_none());
    }
    running.stop();
}

#[test]
fn a_full_sign_in_answers_the_tab_with_the_signed_in_page() {
    let world = World::new();
    let running = running(&world);
    let query = running.approved(&world, &User::alex());
    let callback = form_decode(&query);
    let (code, state) = (only(&callback, "code"), only(&callback, "state"));

    let browser = running.callback(&query);
    let received = running.received();
    let accepted = received.outcome.unwrap();
    received.reply.send(Answer::SignedIn);
    let page = read_response(browser);

    assert_eq!(page.status, 200);
    assert!(page.body.contains("<h1>Signed in to Paste Perfect</h1>"));
    assert!(
        page.body
            .contains("You can close this tab and return to Paste Perfect.")
    );
    assert!(!page.head.contains(code) && !page.body.contains(code));
    assert!(!page.head.contains(state) && !page.body.contains(state));
    // The accepted callback leads to a real sign-in.
    assert!(world.finish(saved(accepted)).is_ok());
}

#[test]
fn an_app_name_with_markup_arrives_escaped() {
    let mut world = World::new();
    world.app = AppName::new("Tom & \"Jerry\" <b>").unwrap();
    let running = running(&world);
    let query = running.approved(&world, &User::alex());

    let browser = running.callback(&query);
    running.received().reply.send(Answer::SignedIn);
    let page = read_response(browser);

    assert!(
        page.body
            .contains("Signed in to Tom &amp; &quot;Jerry&quot; &lt;b&gt;")
    );
    assert!(!page.body.contains("<b>") && !page.body.contains("\"Jerry\""));
}

#[test]
fn each_answer_shows_a_different_page() {
    let world = World::new();
    let mut pages = Vec::new();
    for (answer, detail) in [
        (
            Answer::SignedIn,
            "You can close this tab and return to Paste Perfect.",
        ),
        (
            Answer::SignedInPlanUseOff,
            "ChatGPT plan use is not enabled for Paste Perfect. You can enable it in Paste Perfect.",
        ),
        (
            Answer::Declined,
            "Nothing was shared with Paste Perfect. You can close this tab.",
        ),
        (Answer::Failed, "Return to Paste Perfect and try again."),
    ] {
        let running = running(&world);
        let browser = running.callback(&running.approved(&world, &User::alex()));
        running.received().reply.send(answer);
        let page = read_response(browser);
        assert_eq!(page.status, 200);
        assert!(
            page.body.contains(&format!("<p>{detail}</p>")),
            "{answer:?}"
        );
        pages.push(page.body);
    }
    for (index, page) in pages.iter().enumerate() {
        assert!(!pages[index + 1..].contains(page));
    }
}

#[test]
fn every_response_carries_the_security_headers() {
    let world = World::new();
    let running = running(&world);
    let mut responses = vec![
        running.get(&running.start_path()),
        running.get("/start/0"),
        running.get("/favicon.ico"),
        running.raw(b"GET / HTTP/1.1\r\nHost: attacker.example\r\n\r\n"),
    ];
    let browser = running.callback(&running.approved(&world, &User::alex()));
    running.received().reply.send(Answer::SignedIn);
    responses.push(read_response(browser));

    for response in &responses {
        let status = response.status;
        assert_ne!(status, 0);
        assert_eq!(
            response.header("cache-control"),
            Some("no-store"),
            "{status}"
        );
        assert_eq!(
            response.header("referrer-policy"),
            Some("no-referrer"),
            "{status}"
        );
        assert_eq!(
            response.header("x-content-type-options"),
            Some("nosniff"),
            "{status}"
        );
        assert_eq!(response.header("connection"), Some("close"), "{status}");
        let length = response
            .header("content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(length, response.body.len(), "{status}");
        let policy = response.header("content-security-policy").unwrap();
        assert!(
            policy.starts_with("default-src 'none'; style-src 'sha256-"),
            "{policy}"
        );
        assert!(
            policy.ends_with("'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
            "{policy}"
        );
    }
    for page in [&responses[1], &responses[4]] {
        assert_eq!(
            page.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        assert!(page.body.starts_with("<!DOCTYPE html>\n<html lang=\"en\">"));
    }
}

#[test]
fn a_styled_page_brings_its_stylesheet_and_logo_under_a_policy_that_allows_exactly_them() {
    let world = World::new();
    let css = "h1{color:#7a1f1f}";
    let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
    let style = Style::default()
        .stylesheet(css)
        .unwrap()
        .logo(LogoFormat::Png, png)
        .unwrap();
    let running = running_with(&world, Page::new(&world.app).with_style(style));
    let expired = running.get("/start/0");
    let browser = running.callback(&running.approved(&world, &User::alex()));
    running.received().reply.send(Answer::SignedIn);
    let signed_in = read_response(browser);

    // printf '%s' 'h1{color:#7a1f1f}' | openssl dgst -sha256 -binary | base64
    let app_hash = "sha256-nnik55ltCekdBKhh4ew8B6q7AGpE+kxR8g0FsGo2R74=";
    for page in [&expired, &signed_in] {
        let policy = page.header("content-security-policy").unwrap();
        assert!(
            policy.starts_with("default-src 'none'; style-src 'sha256-"),
            "{policy}"
        );
        assert!(
            policy.ends_with(&format!(
                "' '{app_hash}'; img-src data:; \
                 base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            )),
            "{policy}"
        );
        assert!(page.body.contains(&format!("<style>{css}</style>")));
        assert!(page.body.contains(
            "<img class=\"logo\" src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==\" alt=\"\">"
        ));
    }
    assert_eq!(signed_in.heading(), "Signed in to Paste Perfect");
}

#[test]
fn unrelated_requests_of_every_kind_do_not_end_the_wait() {
    let world = World::new();
    let running = running(&world);
    let port = running.port;
    let start = running.start_path();
    let mut oversized = format!("GET {start} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Fill: ");
    oversized.push_str(&"a".repeat(17 * 1024));

    for (request, statuses) in [
        (
            format!("POST {start} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes(),
            [405, 405],
        ),
        (
            format!("GET {start} HTTP/1.1\r\n\r\n").into_bytes(),
            [400, 400],
        ),
        (
            format!("GET {start} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").into_bytes(),
            [400, 400],
        ),
        (
            format!("GET {start} HTTP/1.1\r\nHost: attacker.example\r\n\r\n").into_bytes(),
            [400, 400],
        ),
        (
            format!("GET {start} HTTP/2\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes(),
            [400, 400],
        ),
        (
            format!("GET {start}\u{e4} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes(),
            [400, 400],
        ),
        (b"GET /\xff\xfe HTTP/1.1\r\n\r\n".to_vec(), [400, 400]),
        (
            format!("GET /other HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes(),
            [404, 404],
        ),
        // The listener stops reading at its limit; the reset that closing
        // with unread bytes causes may swallow the answer.
        (oversized.into_bytes(), [431, 0]),
        (
            format!("GET {start} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n").into_bytes(),
            [0, 0],
        ),
    ] {
        let mut browser = connect(port);
        let _ = browser.write_all(&request);
        // Ends the request early where the head is incomplete.
        let _ = browser.shutdown(std::net::Shutdown::Write);
        let response = read_response(browser);
        assert!(
            statuses.contains(&response.status),
            "{}",
            String::from_utf8_lossy(&request)
        );
        assert!(response.header("location").is_none());
        assert!(response.body.len() < 64, "{}", response.body);
    }
    drop(connect(port));

    let browser = running.callback(&running.approved(&world, &User::alex()));
    assert!(running.received().outcome.is_ok());
    drop(browser);
}

#[test]
fn a_callback_with_another_state_does_not_end_the_wait() {
    let world = World::new();
    let running = running(&world);
    for target in [
        "/auth/callback",
        "/auth/callback?",
        "/auth/callback?state=forged&code=c&client_id=app_issued9999",
        "/auth/callback?error=access_denied",
    ] {
        let response = running.get(target);
        assert_eq!(response.status, 404, "{target}");
        assert!(!response.body.contains("forged"));
    }

    let browser = running.callback(&running.approved(&world, &User::alex()));
    assert!(running.received().outcome.is_ok());
    drop(browser);
}

#[test]
fn a_declined_sign_in_returns_access_denied_with_a_usable_reply() {
    let world = World::new();
    let running = running(&world);
    let query = world.provider.deny(&running.authorization_url());

    let browser = running.callback(&query);
    let received = running.received();
    assert_eq!(
        received.outcome.unwrap_err().kind(),
        ErrorKind::AccessDenied
    );
    received.reply.send(Answer::Declined);

    let page = read_response(browser);
    assert_eq!(page.status, 200);
    assert!(page.body.contains("<h1>Sign-in cancelled</h1>"));
}

#[test]
fn dropping_the_reply_shows_the_failed_page() {
    let world = World::new();
    let running = running(&world);
    let browser = running.callback(&running.approved(&world, &User::alex()));
    drop(running.received());

    let page = read_response(browser);
    assert_eq!(page.status, 200);
    assert!(page.body.contains("<h1>Sign-in did not complete</h1>"));
    assert_eq!(
        page.body.matches("<html").count(),
        1,
        "the page is written once"
    );
}

#[test]
fn a_zero_timeout_times_out() {
    let world = World::new();
    let listener = Listener::bind().unwrap();
    let port = listener.port();
    let attempt = Attempt::start_with_entropy(
        Registration::New(&world.app),
        Some(&world.host),
        port,
        &world.entropy,
    )
    .unwrap();
    let waiting = listener
        .serve_with_entropy(attempt, Page::new(&world.app), &world.entropy)
        .unwrap();

    let error = waiting.wait(Duration::ZERO).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
}

#[test]
fn cancelling_before_the_wait_wins_over_the_timeout() {
    let world = World::new();
    let listener = Listener::bind().unwrap();
    let port = listener.port();
    let attempt = Attempt::start_with_entropy(
        Registration::New(&world.app),
        Some(&world.host),
        port,
        &world.entropy,
    )
    .unwrap();
    let waiting = listener
        .serve_with_entropy(attempt, Page::new(&world.app), &world.entropy)
        .unwrap();
    waiting.canceller().cancel();

    let error = waiting.wait(Duration::ZERO).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
}

#[test]
fn cancelling_during_the_wait_ends_it_as_cancelled() {
    let world = World::new();
    let running = running(&world);
    let mut idle_browser = connect(running.port);
    // The wait accepted the idle connection before serving this request.
    running.authorization_url();
    assert!(still_open(&idle_browser));
    running.canceller.cancel();

    assert_eq!(running.ended().kind(), ErrorKind::Cancelled);
    // The address can be reused by another test. Check the original connection.
    match idle_browser.read(&mut [0; 1]) {
        Ok(0) => {}
        Err(error) if error.kind() == IoErrorKind::ConnectionReset => {}
        other => panic!("the cancelled wait did not close its connection: {other:?}"),
    }
}

#[test]
fn the_port_refuses_connections_once_the_wait_returned() {
    let world = World::new();
    let running = running(&world);
    let port = running.port;
    let browser = running.callback(&running.approved(&world, &User::alex()));
    let received = running.received();

    // A subprocess another test spawns at this instant may hold an inherited
    // copy of the listener socket for a few milliseconds until `exec` closes it.
    let deadline = Instant::now() + Duration::from_millis(500);
    let refused = loop {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err() {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert!(refused, "the listener port still accepted connections");
    received.reply.send(Answer::SignedIn);
    assert_eq!(read_response(browser).status, 200);
}

#[test]
fn an_idle_connection_does_not_delay_the_callback() {
    let world = World::new();
    let running = running(&world);
    // Speculative connections a browser opens and never uses.
    let idle: Vec<TcpStream> = (0..3).map(|_| connect(running.port)).collect();

    let query = running.approved(&world, &User::alex());
    assert!(
        idle.iter().all(still_open),
        "served while the idle ones were open"
    );
    let browser = running.callback(&query);
    let received = running.received();
    assert!(received.outcome.is_ok());
    received.reply.send(Answer::SignedIn);
    assert_eq!(read_response(browser).status, 200);
    drop(idle);
}

#[test]
fn a_head_that_arrives_in_several_writes_is_served() {
    let world = World::new();
    let running = running(&world);
    let head = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        running.start_path(),
        running.host()
    );
    let (first, rest) = head.split_at(6);
    let (second, third) = rest.split_at(rest.len() - 3);

    let mut browser = connect(running.port);
    for piece in [first, second, third] {
        browser.write_all(piece.as_bytes()).unwrap();
        browser.flush().unwrap();
    }
    assert_eq!(read_response(browser).status, 302);
    running.stop();
}

#[test]
fn a_connection_beyond_eight_at_once_is_closed_without_an_answer() {
    let world = World::new();
    let running = running(&world);
    let idle: Vec<TcpStream> = (0..8).map(|_| connect(running.port)).collect();

    let ninth = read_response(connect(running.port));
    assert_eq!(ninth.status, 0);
    assert!(idle.iter().all(still_open));
    running.stop();
}

#[test]
fn debug_output_shows_no_start_link_or_authorization_url() {
    let world = World::new();
    let listener = Listener::bind().unwrap();
    let port = listener.port();
    let printed_listener = format!("{listener:?}");
    let attempt = Attempt::start_with_entropy(
        Registration::New(&world.app),
        Some(&world.host),
        port,
        &world.entropy,
    )
    .unwrap();
    let url = attempt.authorization_url().to_owned();
    let waiting = listener
        .serve_with_entropy(attempt, Page::new(&world.app), &world.entropy)
        .unwrap();
    let link = waiting.start_link().to_owned();
    let token = link.rsplit('/').next().unwrap().to_owned();

    let printed = format!("{printed_listener} {waiting:?} {:?}", waiting.canceller());
    assert!(printed.contains(&port.to_string()));
    let (_, query) = url.split_once('?').unwrap();
    let state = only(&form_decode(query), "state").to_owned();
    for secret in [&link, &token, &url, &state] {
        assert!(!printed.contains(secret.as_str()), "{printed}");
    }
}
