//! When a stream counts as read from and when it has ended: a poll that
//! found nothing has read nothing, and `response.completed` is the last
//! item of the blocking stream as of the async one.

use std::io::{self, Read};
use std::sync::mpsc::{self, Receiver};
use std::task::{Context, Poll, Wake, Waker};

use siwc::protocol::StreamingResponse;
use siwc::testing::FakeResponse;
use siwc::{Canceller, ErrorKind};

use crate::support::executor::{block_on, waker};

use super::answers::{Wired, completed, delta, opening};
use super::{Desk, request};

/// A body whose first byte arrives only when the test opens the gate.
struct Gated {
    gate: Receiver<()>,
    bytes: io::Cursor<Vec<u8>>,
    open: bool,
}

impl Read for Gated {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.open {
            self.gate
                .recv()
                .map_err(|_| io::Error::from(io::ErrorKind::ConnectionReset))?;
            self.open = true;
        }
        self.bytes.read(buffer)
    }
}

#[test]
fn a_poll_that_found_nothing_leaves_the_whole_answer_to_into_text() {
    let (wired, client, id, _clock) = Wired::desk();
    let (open, gate) = mpsc::channel();
    let body = Gated {
        gate,
        bytes: io::Cursor::new([opening(), delta("All of it"), completed()].concat()),
        open: false,
    };
    wired.answer(move |_| StreamingResponse::new(200, body));
    let mut stream = block_on(client.stream_response_async(&id, &request())).unwrap();

    // Nothing has arrived: the poll hands out no item.
    let (waker, _wakes) = waker();
    let polled = stream.poll_next(&mut Context::from_waker(&waker));
    assert!(matches!(polled, Poll::Pending));

    open.send(()).unwrap();
    assert_eq!(block_on(stream.into_text()).unwrap(), "All of it");
}

#[test]
fn completed_is_the_last_item_whatever_happens_after_it() {
    let desk = Desk::new();
    desk.provider.push_response(FakeResponse::text(&["Done."]));
    let canceller = Canceller::new();
    let mut stream = desk
        .client
        .stream_response_cancellable(&desk.id, &request(), &canceller)
        .unwrap();
    let mut last = None;
    for _ in 0..4 {
        last = stream.next();
    }
    let last = last.unwrap().unwrap();
    assert_eq!(last.event_type(), Some("response.completed"));
    assert!(format!("{stream:?}").contains("ended: true"));

    // The answer is complete. A cancellation that comes now changes
    // nothing about it: the stream has ended, and stays so.
    canceller.cancel();
    assert!(stream.next().is_none());
    assert!(stream.next().is_none());

    // The async stream agrees.
    desk.provider.push_response(FakeResponse::text(&["Done."]));
    let canceller = Canceller::new();
    block_on(async {
        let mut stream = desk
            .client
            .stream_response_async_cancellable(&desk.id, &request(), &canceller)
            .await
            .unwrap();
        for _ in 0..4 {
            stream.next().await.unwrap().unwrap();
        }
        canceller.cancel();
        assert!(stream.next().await.is_none());
    });

    // An answer cancelled before its end is the error it always was.
    desk.provider.push_response(FakeResponse::text(&["Done."]));
    let canceller = Canceller::new();
    let mut stream = desk
        .client
        .stream_response_cancellable(&desk.id, &request(), &canceller)
        .unwrap();
    stream.next().unwrap().unwrap();
    canceller.cancel();
    let error = stream.next().unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(stream.next().is_none());
}

/// A body whose second read takes the reading thread down with it.
struct Dying {
    first: Option<Vec<u8>>,
}

impl Read for Dying {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Some(bytes) = self.first.take() else {
            panic!("a synthetic failure of the transport's reader");
        };
        buffer[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
}

#[test]
fn a_reading_thread_that_died_is_an_error_and_never_the_end_of_an_answer() {
    let (wired, client, id, _clock) = Wired::desk();
    for _ in 0..2 {
        let body = Dying {
            first: Some([opening(), delta("Half")].concat()),
        };
        wired.answer(move |_| StreamingResponse::new(200, body));
    }
    block_on(async {
        let mut stream = client.stream_response_async(&id, &request()).await.unwrap();
        let mut last = None;
        while let Some(item) = stream.next().await {
            last = Some(item);
        }
        // Whatever the thread had read is gone; what is left is that the
        // answer did not complete.
        assert_eq!(last.unwrap().unwrap_err().kind(), ErrorKind::Temporary);

        let stream = client.stream_response_async(&id, &request()).await.unwrap();
        let error = stream.into_text().await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Temporary);
    });
}

struct CancelOnDrop {
    stop: Canceller,
    task: Waker,
}

impl Wake for CancelOnDrop {
    fn wake(self: std::sync::Arc<Self>) {
        self.task.wake_by_ref();
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn replace_waker_while_pending(opening: bool) {
    use std::future::Future;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let (wired, client, id, _clock) = Wired::desk();
    let (release, gate) = mpsc::channel();
    wired.answer(move |_| {
        if opening {
            let _ = gate.recv();
            StreamingResponse::new(200, io::empty())
        } else {
            StreamingResponse::new(
                200,
                Gated {
                    gate,
                    bytes: io::Cursor::default(),
                    open: false,
                },
            )
        }
    });
    let (finished, result) = mpsc::channel();
    let poller = thread::spawn(move || {
        let stop = Canceller::new();
        let (task, old_wakes) = waker();
        let old = Waker::from(Arc::new(CancelOnDrop {
            stop: stop.clone(),
            task,
        }));
        let mut first = Context::from_waker(&old);
        let (new, wakes) = waker();
        let mut next = Context::from_waker(&new);
        let request = request();
        let future = client.stream_response_async_cancellable(&id, &request, &stop);
        if opening {
            let mut future = std::pin::pin!(future);
            assert!(future.as_mut().poll(&mut first).is_pending());
            drop(old);
            assert!(future.as_mut().poll(&mut next).is_pending());
            assert!(
                wakes.try_recv().is_ok(),
                "the replacement waker saw cancellation"
            );
        } else {
            let mut stream = block_on(future).unwrap();
            assert!(stream.poll_next(&mut first).is_pending());
            drop(old);
            assert!(stream.poll_next(&mut next).is_pending());
            assert_eq!(
                block_on(stream.next()).unwrap().unwrap_err().kind(),
                ErrorKind::Cancelled
            );
        }
        assert!(stop.is_cancelled());
        assert!(
            old_wakes.try_iter().next().is_none(),
            "the old waker was dropped without waking its task"
        );
        finished.send(()).unwrap();
    });
    result
        .recv_timeout(Duration::from_secs(3))
        .expect("replacing the waker must return even when its destructor cancels");
    drop(release);
    poller.join().unwrap();
}

#[test]
fn replacing_the_opening_waker_can_cancel_from_drop() {
    replace_waker_while_pending(true);
}

#[test]
fn replacing_the_reading_waker_can_cancel_from_drop() {
    replace_waker_while_pending(false);
}
