//! Where the thread that reads an answer and the task that awaits its
//! events meet: the result of opening the stream, then a bounded queue.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;

use crate::cancel::{Canceller, OnCancel};
use crate::error::{Error, ErrorKind};
use crate::plan::ResponseEvent;

/// Most events that wait for the task that reads them. The thread that
/// reads the connection pauses at this number, so a slow reader slows the
/// download instead of filling memory.
const QUEUE: usize = 32;

/// The JSON of waiting events at which the thread pauses as well (16 MiB,
/// the size one event may have), so a few large events count like many
/// small ones.
const QUEUE_BYTES: usize = 16 * 1024 * 1024;

/// How often a thread that waits for room looks at its canceller.
const CANCEL_POLL: Duration = Duration::from_millis(50);

type Item = Result<ResponseEvent, Error>;
type RequestId = Option<Box<str>>;

pub(super) struct Handover {
    state: Mutex<State>,
    /// Signalled when the queue has room again.
    room: Condvar,
}

struct State {
    #[cfg(all(test, feature = "testing"))]
    full: Option<std::sync::mpsc::Sender<()>>,
    /// How opening the stream ended, until the awaiting task takes it.
    opened: Option<Result<RequestId, Error>>,
    queue: VecDeque<Item>,
    /// The JSON of the queued events, in bytes.
    queued_bytes: usize,
    /// The request was cancelled: the queue is empty and stays so. Kept
    /// beside the queue, so a full one has room for it.
    cancelled: bool,
    /// The reading thread has ended; nothing more will be queued.
    ended: bool,
    waker: Option<Waker>,
}

impl State {
    /// Notes a cancellation, if `stop` says so, and drops what waits.
    fn stopped_by(&mut self, stop: &Canceller) -> bool {
        if !self.cancelled && stop.is_cancelled() {
            self.cancelled = true;
            self.clear();
        }
        self.cancelled
    }

    fn has_room(&self) -> bool {
        self.queue.len() < QUEUE && self.queued_bytes < QUEUE_BYTES
    }

    fn put(&mut self, item: Item) {
        self.queued_bytes += json_len(&item);
        self.queue.push_back(item);
    }

    fn take(&mut self) -> Option<Item> {
        let item = self.queue.pop_front()?;
        self.queued_bytes -= json_len(&item);
        Some(item)
    }

    fn clear(&mut self) {
        self.queue.clear();
        self.queued_bytes = 0;
    }
}

/// What an item counts towards [`QUEUE_BYTES`].
fn json_len(item: &Item) -> usize {
    item.as_ref().map_or(0, |event| event.json().len())
}

/// What the awaiting task takes from the queue.
pub(super) enum Taken {
    Item(Item),
    /// The request was cancelled; no event is handed out any more.
    Cancelled,
    /// The reading thread ended and left nothing: never the end of a
    /// complete answer, whose last item is `response.completed`.
    Ended,
}

impl Handover {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                #[cfg(all(test, feature = "testing"))]
                full: None,
                opened: None,
                queue: VecDeque::new(),
                queued_bytes: 0,
                cancelled: false,
                ended: false,
                waker: None,
            }),
            room: Condvar::new(),
        }
    }

    /// A poisoned lock can only come from a panic in this module's few
    /// lines that hold it, which leave the state whole.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes the state and wakes the awaiting task.
    fn update(&self, change: impl FnOnce(&mut State)) {
        let mut state = self.lock();
        change(&mut state);
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Reports how opening the stream ended.
    pub(super) fn opened(&self, result: Result<RequestId, Error>) {
        self.update(|state| state.opened = Some(result));
    }

    /// For a reading thread that never ran: `error` is how opening the
    /// stream ended. A thread that ran has marked its end and is left alone.
    pub(super) fn never_ran(&self, error: Error) {
        self.update(|state| {
            if !state.ended {
                state.opened = Some(Err(error));
                state.ended = true;
            }
        });
    }

    /// The result of opening the stream, once the thread has reported it.
    pub(super) fn poll_opened(&self, context: &mut Context<'_>) -> Poll<Result<RequestId, Error>> {
        let waker = context.waker().clone();
        let mut state = self.lock();
        match state.opened.take() {
            Some(result) => Poll::Ready(result),
            // The thread ended without a result: it panicked.
            None if state.ended => Poll::Ready(Err(broken())),
            None => pending(state, waker),
        }
    }

    /// Waits until fewer than 32 events and less than 16 MiB of their JSON
    /// wait, so that one more event has room. `false` once
    /// `stop` is triggered: nothing more is to be read, and what waited is
    /// dropped.
    pub(super) fn wait_for_room(&self, stop: &Canceller) -> bool {
        let mut state = self.lock();
        loop {
            if state.stopped_by(stop) {
                return false;
            }
            if state.has_room() {
                return true;
            }
            #[cfg(all(test, feature = "testing"))]
            if let Some(signal) = state.full.take() {
                let _ = signal.send(());
            }
            // A cancellation signals this wait through `cancel`, once
            // the handover is registered with the canceller; the interval
            // is the second look that does not depend on that.
            state = self
                .room
                .wait_timeout(state, CANCEL_POLL)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Queues `item` unless `stop` was triggered: a cancelled request
    /// leaves nothing behind to read.
    pub(super) fn push(&self, item: Item, stop: &Canceller) {
        self.update(|state| {
            if !state.stopped_by(stop) {
                state.put(item);
            }
        });
    }

    /// The next queued event. The canceller is read under the queue's
    /// lock, so the end of the reading thread is never seen without the
    /// cancellation that caused it.
    pub(super) fn poll_item(&self, context: &mut Context<'_>, stop: &Canceller) -> Poll<Taken> {
        let waker = context.waker().clone();
        let mut state = self.lock();
        if state.stopped_by(stop) {
            drop(state);
            self.room.notify_all();
            return Poll::Ready(Taken::Cancelled);
        }
        match state.take() {
            Some(item) => {
                drop(state);
                self.room.notify_one();
                Poll::Ready(Taken::Item(item))
            }
            None if state.ended => Poll::Ready(Taken::Ended),
            None => pending(state, waker),
        }
    }

    /// Ends the handover for a cancelled request: drops the events that
    /// wait, takes no more, and lets the waiting thread and the awaiting
    /// task look again.
    pub(super) fn cancel(&self) {
        self.update(|state| {
            state.cancelled = true;
            state.clear();
        });
        self.room.notify_all();
    }

    /// How many events wait for the task.
    pub(super) fn waiting(&self) -> usize {
        self.lock().queue.len()
    }

    /// A guard for the reading thread that marks its end when dropped.
    pub(super) fn closing(&self) -> Closing<'_> {
        Closing(self)
    }
}

/// A waker belongs to the executor. Its destructor can cancel the request
/// and take this lock again, just as a wake can.
fn pending<T>(mut state: MutexGuard<'_, State>, waker: Waker) -> Poll<T> {
    let previous = state.waker.replace(waker);
    drop(state);
    drop(previous);
    Poll::Pending
}

/// Told by the request's canceller, so that the events that wait are
/// dropped at once, also when the reading thread has ended and no task
/// polls.
impl OnCancel for Handover {
    fn cancelled(&self) {
        self.cancel();
    }
}

/// Marks the end of the reading thread, however it ends.
pub(super) struct Closing<'a>(&'a Handover);

impl Drop for Closing<'_> {
    fn drop(&mut self) {
        let panicking = thread::panicking();
        self.0.update(|state| {
            if panicking {
                // Nothing a thread that broke had read is handed out.
                state.clear();
            }
            state.ended = true;
        });
    }
}

pub(super) fn broken() -> Error {
    Error::new(
        ErrorKind::Temporary,
        "the response stream ended before response.completed",
    )
}

#[cfg(test)]
mod tests {
    use std::task::Waker;

    use super::*;

    fn taken(handover: &Handover, stop: &Canceller) -> Poll<Taken> {
        handover.poll_item(&mut Context::from_waker(Waker::noop()), stop)
    }

    #[test]
    fn a_thread_that_ended_with_an_empty_queue_is_never_a_complete_answer() {
        let handover = Handover::new();
        let stop = Canceller::new();
        assert!(matches!(taken(&handover, &stop), Poll::Pending));
        drop(handover.closing());
        assert!(matches!(taken(&handover, &stop), Poll::Ready(Taken::Ended)));
        // The thread ended because of a cancellation the task has not
        // looked at yet: the same lock shows both.
        stop.cancel();
        assert!(matches!(
            taken(&handover, &stop),
            Poll::Ready(Taken::Cancelled)
        ));
    }

    #[test]
    fn cancellation_wipes_queued_and_late_text_deltas_before_free() {
        use crate::plan::SseDecoder;
        use std::cell::Cell;

        thread_local! {
            static WIPED: Cell<usize> = const { Cell::new(0) };
        }
        let make = || {
            let mut events = SseDecoder::new()
                .feed(b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n")
                .unwrap();
            let mut event = events.pop().unwrap();
            event.inspect_delta_before_free = Some(|text| {
                if text.as_bytes() == [0; 5] {
                    WIPED.set(WIPED.get() + 1);
                }
            });
            Ok(event)
        };
        let stop = Canceller::new();
        let handover = Handover::new();
        handover.push(make(), &stop);
        handover.push(make(), &stop);
        stop.cancel();
        handover.cancel();
        handover.push(make(), &stop);
        assert_eq!(WIPED.get(), 3);
        // Moving the decoded event out hands the String to the caller.
        assert_eq!(
            make().unwrap().into_event(),
            crate::plan::StreamEvent::TextDelta {
                text: "hello".into()
            }
        );
    }

    #[test]
    fn large_events_fill_the_queue_by_their_size_before_their_number() {
        use crate::plan::SseDecoder;

        let large = |len: usize| {
            let text = "a".repeat(len);
            let stream = format!(
                "data: {{\"type\":\"response.output_text.delta\",\"delta\":\"{text}\"}}\n\n"
            );
            Ok(SseDecoder::new().feed(stream.as_bytes()).unwrap().remove(0))
        };
        let handover = Handover::new();
        let stop = Canceller::new();
        handover.push(large(QUEUE_BYTES / 2), &stop);
        assert!(handover.lock().has_room());
        handover.push(large(QUEUE_BYTES / 2), &stop);
        assert!(!handover.lock().has_room());
        // Taking one event makes room again, and an empty queue counts nothing.
        assert!(matches!(
            taken(&handover, &stop),
            Poll::Ready(Taken::Item(_))
        ));
        assert!(handover.lock().has_room());
        assert!(matches!(
            taken(&handover, &stop),
            Poll::Ready(Taken::Item(_))
        ));
        assert_eq!(handover.lock().queued_bytes, 0);
    }

    #[cfg(feature = "testing")]
    #[test]
    fn the_response_worker_pauses_at_the_byte_limit_until_an_event_is_taken() {
        use super::super::Worker;
        use crate::testing::{FakeProvider, FakeResponse, FakeUser};
        use crate::{AppName, Client, plan::ResponseRequest, store::MemoryStore};
        use std::sync::{Arc, mpsc};

        let provider = FakeProvider::new();
        let client = Client::new(
            AppName::new("Sample").unwrap(),
            MemoryStore::new(),
            provider.clone(),
        );
        let mut sign_in = client.add_account_manually().unwrap();
        let redirect = provider
            .approve_manual(&sign_in, FakeUser::new("sample@example.invalid"))
            .unwrap();
        let id = sign_in
            .finish(&redirect)
            .unwrap()
            .into_account()
            .id()
            .clone();
        let delta = "x".repeat(QUEUE_BYTES / 2);
        provider.push_response(
            FakeResponse::stream()
                .delta(&delta)
                .delta(&delta)
                .completed(),
        );
        let stop = Canceller::new();
        let handover = Arc::new(Handover::new());
        let (full, notified) = mpsc::channel();
        handover.lock().full = Some(full);
        let worker = Worker {
            client,
            id,
            request: ResponseRequest::text("m", "Hi").unwrap(),
            handover: handover.clone(),
            stop: stop.clone(),
        };
        let reader = thread::spawn(move || worker.run());
        notified.recv_timeout(Duration::from_secs(15)).unwrap();
        assert_eq!(handover.waiting(), 2);
        assert!(matches!(
            taken(&handover, &stop),
            Poll::Ready(Taken::Item(Ok(_)))
        ));
        reader.join().unwrap();
        assert!(
            matches!(taken(&handover, &stop), Poll::Ready(Taken::Item(Ok(event))) if event.text_delta() == Some(delta.as_str()))
        );
        assert!(
            matches!(taken(&handover, &stop), Poll::Ready(Taken::Item(Ok(event))) if event.event() == &crate::plan::StreamEvent::Completed)
        );
    }

    #[test]
    fn a_cancellation_empties_a_full_queue_and_nothing_is_queued_after_it() {
        let handover = Handover::new();
        let stop = Canceller::new();
        for _ in 0..QUEUE {
            assert!(handover.wait_for_room(&stop));
            handover.push(Err(broken()), &stop);
        }
        assert_eq!(handover.waiting(), 32);
        stop.cancel();
        // The reading thread notices first: no poll has happened.
        assert!(!handover.wait_for_room(&stop));
        assert_eq!(handover.waiting(), 0);
        handover.push(Err(broken()), &stop);
        assert_eq!(handover.waiting(), 0);
        assert!(matches!(
            taken(&handover, &stop),
            Poll::Ready(Taken::Cancelled)
        ));
    }
}
