//! Cancellation on either side of the first write of a buffered request.

use std::cell::Cell;
use std::time::Duration;

use super::tests::{SERVER, complete, finish, loopback, serve, serve_before_answer, token_request};
use crate::{Canceller, Transport};

thread_local! {
    pub(super) static BEFORE_WRITE: Cell<Option<Canceller>> = const { Cell::new(None) };
    pub(super) static AFTER_FIRST_BYTE: Cell<Option<Canceller>> = const { Cell::new(None) };
}

#[test]
fn cancelling_between_refresh_writes_delivers_the_whole_post_and_its_successor() {
    let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nsuccessor";
    let (address, server) = serve(SERVER, answer);
    let stop = Canceller::new();
    AFTER_FIRST_BYTE.set(Some(stop.clone()));
    let request = token_request();
    let result = loopback(address, Duration::from_secs(10)).send_cancellable(&request, &stop);
    let received = finish(address, server).received;
    assert!(stop.is_cancelled());
    assert!(
        received.starts_with(b"POST /oauth/token "),
        "received {} bytes",
        received.len()
    );
    assert!(complete(&received));
    assert!(received.ends_with(request.body()));
    assert_eq!(result.unwrap().body(), b"successor");
}

#[test]
fn the_first_refresh_write_commits_the_exchange() {
    let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nsuccessor";
    for before_write in [false, true] {
        let stop = Canceller::new();
        let during = stop.clone();
        let (address, server) = serve_before_answer(SERVER, answer, move || during.cancel());
        let https = loopback(address, Duration::from_secs(10));
        if before_write {
            BEFORE_WRITE.set(Some(stop.clone()));
        }
        let result = https.send_cancellable(&token_request(), &stop);
        let received = finish(address, server).received;
        assert!(stop.is_cancelled());
        if before_write {
            assert!(received.is_empty(), "no POST may leave after cancellation");
            assert!(result.is_err());
        } else {
            assert!(received.starts_with(b"POST /oauth/token "));
            assert_eq!(result.unwrap().body(), b"successor");
        }
    }
}

#[cfg(feature = "testing")]
#[test]
fn cancelling_a_due_renewal_stops_the_tls_handshake() {
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::{Arc, mpsc};
    use std::thread;

    use super::connect::waiting::{self, Wait};
    use crate::plan::ResponseRequest;
    use crate::protocol::{HttpRequest, HttpResponse};
    use crate::store::MemoryStore;
    use crate::testing::{FakeClock, FakeProvider, FakeUser};
    use crate::{AppName, Client, Error, ErrorKind, Https, UnixTime};

    #[derive(Debug)]
    struct RenewOverTls(FakeProvider, Https);

    impl Transport for RenewOverTls {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
            if request.body().starts_with(b"grant_type=refresh_token&") {
                self.1.send(request)
            } else {
                self.0.send(request)
            }
        }

        fn send_cancellable(
            &self,
            request: &HttpRequest,
            stop: &Canceller,
        ) -> Result<HttpResponse, Error> {
            self.1.send_cancellable(request, stop)
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let https = loopback(listener.local_addr().unwrap(), Duration::from_secs(30));
    let clock = FakeClock::new(UnixTime::from_secs(1_800_000_000));
    let provider = FakeProvider::with_clock(&clock);
    // The override must reach the inner transport through both pointer types.
    let transport = Arc::new(Box::new(RenewOverTls(provider.clone(), https)));
    let client = Client::builder(
        AppName::new("Paste Perfect").unwrap(),
        MemoryStore::new(),
        transport,
    )
    .clock(clock.clone())
    .build();
    let mut sign_in = client.add_account_manually().unwrap();
    let redirect = provider
        .approve_manual(&sign_in, FakeUser::new("owner@example.invalid"))
        .unwrap();
    let id = sign_in.finish(&redirect).unwrap().account().id().clone();
    clock.advance(Duration::from_secs(3600));

    let stop = Canceller::new();
    let client_stop = stop.clone();
    let (done, finished) = mpsc::channel();
    let (blocked, waits) = mpsc::channel();
    let worker = thread::spawn(move || {
        waiting::observe(blocked);
        let request = ResponseRequest::text("example", "Hello").unwrap();
        let reply = client.stream_response_cancellable(&id, &request, &client_stop);
        let _ = done.send(reply);
    });
    let patience = Duration::from_secs(3);
    assert_eq!(
        waits.recv_timeout(patience),
        Ok(Wait::Read),
        "expected the TLS handshake to wait for a read; worker result: {:?}",
        finished.try_recv()
    );
    listener.set_nonblocking(true).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_nonblocking(false).unwrap();
    peer.set_read_timeout(Some(patience)).unwrap();
    let mut prefix = [0; 6];
    peer.read_exact(&mut prefix).unwrap();
    assert_eq!((prefix[0], prefix[5]), (22, 1)); // TLS ClientHello
    stop.cancel();
    // The server has not sent its ServerHello or closed its socket.
    let reply = finished
        .recv_timeout(patience)
        .expect("the handshake must stop");
    assert_eq!(reply.unwrap_err().kind(), ErrorKind::Cancelled);
    assert!(provider.plan_requests().is_empty());
    worker.join().unwrap();
}
