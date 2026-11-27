//! A streamed plan answer for async code: the blocking stream runs on a
//! thread of its own and hands its events over through a bounded queue.

use std::fmt;
use std::future::poll_fn;
use std::io;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::thread;

use crate::account::AccountId;
use crate::cancel::{Canceller, OnCancel};
use crate::error::{Error, ErrorKind};
use crate::plan::{ResponseEvent, ResponseRequest};

use super::Client;
use super::async_call::CancelOnDrop;
use super::call::call_cancelled;
use super::response::is_last;
use super::response::text::{self, Collected};

mod handover;

use handover::{Handover, Taken};

impl Client {
    /// Async counterpart of [`stream_response`](Self::stream_response): the
    /// request is sent and its answer read on a background thread, and the
    /// returned [`AsyncResponseStream`] hands out the events to any
    /// executor.
    ///
    /// Dropping the returned future, or the stream it resolves to, stops
    /// the request. [`SystemClock`](crate::SystemClock) wakes a retry wait at
    /// once. A clock using the default [`Clock::sleep_cancellable`](crate::Clock::sleep_cancellable)
    /// sees the cancellation when its sleep returns. A read ends when the
    /// transport notices the cancellation (within about 50 ms with `Https`).
    ///
    /// ```no_run
    /// use siwc::plan::ResponseRequest;
    ///
    /// # fn show(_: &str) {}
    /// # async fn example(client: &siwc::Client, id: &siwc::AccountId) -> Result<(), siwc::Error> {
    /// let request = ResponseRequest::text("example-large", "Why is the sky blue?")?;
    /// let mut stream = client.stream_response_async(id, &request).await?;
    /// while let Some(event) = stream.next().await {
    ///     if let Some(text) = event?.text_delta() {
    ///         show(text);
    ///     }
    /// }
    /// // The loop ended without an error: the answer is complete.
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`stream_response`](Self::stream_response), and
    /// [`ErrorKind::Temporary`] when the system starts no thread for the
    /// request, in which case nothing was sent.
    pub async fn stream_response_async(
        &self,
        id: &AccountId,
        request: &ResponseRequest,
    ) -> Result<AsyncResponseStream, Error> {
        self.open_async(id, request, CancelOnDrop(Canceller::unshared()))
            .await
    }

    /// Like [`stream_response_async`](Self::stream_response_async), with a
    /// `canceller` that stops the request from anywhere, in addition to
    /// dropping the future or the stream. Once it is triggered the stream
    /// hands out [`ErrorKind::Cancelled`] as its last item, whatever events
    /// were still waiting, and its thread ends without being asked for
    /// another event.
    ///
    /// If cancellation arrives after the worker published an accepted
    /// response but before this future resolves, it still returns the
    /// stream. Its first item is [`ErrorKind::Cancelled`], and
    /// [`AsyncResponseStream::request_id`] keeps the ID of a POST the
    /// provider may already have counted.
    ///
    /// ```no_run
    /// use siwc::Canceller;
    /// use siwc::plan::ResponseRequest;
    ///
    /// # async fn example(client: &siwc::Client, id: &siwc::AccountId, request: &ResponseRequest) -> Result<(), siwc::Error> {
    /// let canceller = Canceller::new();
    /// let stream = client
    ///     .stream_response_async_cancellable(id, request, &canceller)
    ///     .await?;
    /// let answer = stream.into_text().await?;
    /// # drop(answer);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`stream_response_cancellable`](Self::stream_response_cancellable)
    /// and [`stream_response_async`](Self::stream_response_async).
    pub async fn stream_response_async_cancellable(
        &self,
        id: &AccountId,
        request: &ResponseRequest,
        canceller: &Canceller,
    ) -> Result<AsyncResponseStream, Error> {
        self.open_async(id, request, CancelOnDrop(canceller.child()))
            .await
    }

    /// Starts the one thread that sends the request and reads its answer,
    /// then waits until the API has accepted or refused the request.
    async fn open_async(
        &self,
        id: &AccountId,
        request: &ResponseRequest,
        guard: CancelOnDrop,
    ) -> Result<AsyncResponseStream, Error> {
        let handover = Arc::new(Handover::new());
        // The canceller empties the queue itself: a cancelled answer is
        // let go of at once, with or without a thread or a poll.
        let weak = Arc::downgrade(&handover);
        let listener: Weak<dyn OnCancel> = weak;
        guard.0.tell(listener);
        let worker = Worker {
            client: self.clone(),
            id: id.clone(),
            request: request.clone(),
            stop: guard.0.clone(),
            handover: Arc::clone(&handover),
        };
        // The thread exists before anything is sent: a system that starts
        // none leaves an error and no request behind.
        if guard.0.is_cancelled() {
            return Err(call_cancelled());
        }
        worker.start().map_err(|_| {
            if guard.0.is_cancelled() {
                return call_cancelled();
            }
            not_started()
        })?;
        let request_id = poll_fn(|context| handover.poll_opened(context)).await?;
        Ok(AsyncResponseStream {
            handover,
            request_id,
            touched: false,
            finished: false,
            guard,
        })
    }
}

/// What the stream's thread does: send the request, then read the answer
/// one event at a time, each only once the queue has room for it.
struct Worker {
    client: Client,
    id: AccountId,
    request: ResponseRequest,
    stop: Canceller,
    handover: Arc<Handover>,
}

/// Takes the request by value: no further attempt is possible once the
/// stream opens, so the worker's copy is gone before it publishes the
/// stream, whatever the outcome.
fn open(
    client: &Client,
    id: &AccountId,
    request: ResponseRequest,
    stop: &Canceller,
) -> Result<super::response::ResponseStream, Error> {
    client.stream_response_cancellable(id, &request, stop)
}

impl Worker {
    /// Starts the thread that reads the answer.
    fn start(self) -> io::Result<()> {
        #[cfg(all(test, feature = "testing"))]
        if let Some(fail) = start_tests::FAIL_START.take() {
            fail(&self.stop);
            return Err(io::Error::other("the test starts no thread"));
        }
        let client = self.client.clone();
        let Some(spawner) = &client.inner.spawner else {
            return thread::Builder::new()
                .name("siwc-response".to_owned())
                .spawn(move || self.run())
                .map(drop);
        };
        // The app's spawner reports nothing: a job it drops instead of
        // running it says so itself.
        let unrun = NeverRan(Arc::clone(&self.handover));
        spawner(Box::new(move || {
            let _unrun = unrun;
            self.run();
        }));
        Ok(())
    }

    fn run(self) {
        let Self {
            client,
            id,
            request,
            stop,
            handover,
        } = self;
        // Marks the end of this thread however it ends.
        let _closing = handover.closing();
        let opened = open(&client, &id, request, &stop);
        let mut stream = match opened {
            Ok(stream) => stream,
            Err(error) => return handover.opened(Err(error)),
        };
        handover.opened(Ok(stream.request_id().map(Box::from)));
        // Room first, then the read: a reader that stopped asking, or a
        // cancelled request, leaves no event read for nobody.
        while handover.wait_for_room(&stop) {
            let Some(item) = stream.next() else {
                return;
            };
            // With its last item the answer is over: the thread ends
            // without waiting for room it has no use for.
            let last = is_last(&item);
            handover.push(item, &stop);
            if last {
                return;
            }
        }
    }
}

/// Tells the awaiting task that its request was not sent, if the job that
/// held this was dropped before it ran.
struct NeverRan(Arc<Handover>);

impl Drop for NeverRan {
    fn drop(&mut self) {
        self.0.never_ran(not_started());
    }
}

fn not_started() -> Error {
    Error::new(
        ErrorKind::Temporary,
        "no thread could be started for the request; nothing was sent",
    )
}

/// The streamed answer to one plan request for async code, from
/// [`Client::stream_response_async`].
///
/// It hands out the same events under the same rules as
/// [`ResponseStream`](crate::ResponseStream): the answer is complete only
/// if [`next`](Self::next) reaches `None` without an error, and every other
/// ending is an `Err` as the last item, after which `None` follows too.
///
/// The request has been sent by the time a stream exists, and a thread of
/// the stream's own reads the answer whether or not the stream is polled.
/// It needs no particular runtime: the thread wakes the task that awaits
/// the next event. At most 32 events wait in between, fewer once 16 MiB of
/// them wait, and the thread reads no further while they do. Dropping the
/// stream, or triggering its
/// canceller, cancels the request and ends that thread.
///
/// For a `futures::Stream`, wrap [`poll_next`](Self::poll_next):
/// `futures::stream::poll_fn(move |context| stream.poll_next(context))`.
///
/// ```no_run
/// # fn show(_: &str) {}
/// # async fn example(mut stream: siwc::AsyncResponseStream) -> Result<(), siwc::Error> {
/// while let Some(event) = stream.next().await {
///     if let Some(text) = event?.text_delta() {
///         show(text);
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[must_use = "the request was already sent and is being read; read the stream, or drop it to cancel"]
pub struct AsyncResponseStream {
    handover: Arc<Handover>,
    request_id: Option<Box<str>>,
    /// Whether the stream was asked for an item.
    touched: bool,
    /// Whether the last item was handed out.
    finished: bool,
    /// Stops the reading thread when the stream is dropped.
    guard: CancelOnDrop,
}

impl AsyncResponseStream {
    /// The next event; `None` after the last item, which is
    /// `response.completed` for a complete answer and an error otherwise.
    ///
    /// # Errors
    ///
    /// The error the answer ended with, as the last item; see
    /// [`ResponseStream`](crate::ResponseStream).
    pub async fn next(&mut self) -> Option<Result<ResponseEvent, Error>> {
        poll_fn(|context| self.poll_next(context)).await
    }

    /// Polls for the next event, for adapters such as `futures::Stream`:
    /// `Ready(None)` after the last item, `Pending` with the task's waker
    /// registered while no event is there.
    ///
    /// ```no_run
    /// use std::future::poll_fn;
    ///
    /// # async fn example(mut stream: siwc::AsyncResponseStream) {
    /// let first = poll_fn(|context| stream.poll_next(context)).await;
    /// # drop(first);
    /// # }
    /// ```
    pub fn poll_next(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<ResponseEvent, Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        let taken = match self.handover.poll_item(context, &self.guard.0) {
            Poll::Ready(taken) => taken,
            Poll::Pending => return Poll::Pending,
        };
        // An item leaves the stream: only now has it been read from.
        self.touched = true;
        let item = match taken {
            Taken::Item(item) => item,
            // Events that were waiting are not handed out any more.
            Taken::Cancelled => Err(call_cancelled()),
            // The thread is gone and `response.completed` never came.
            Taken::Ended => Err(handover::broken()),
        };
        self.finished = is_last(&item);
        Poll::Ready(Some(item))
    }

    /// The request ID of the accepted response; see
    /// [`ResponseStream::request_id`](crate::ResponseStream::request_id).
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// Reads the stream to its end and returns the whole text of the
    /// answer, at most 16 MiB of it; see
    /// [`ResponseStream::into_text`](crate::ResponseStream::into_text).
    ///
    /// # Errors
    ///
    /// The error the stream ends with; the text read before it is dropped.
    /// [`ErrorKind::InvalidInput`], without reading anything, on a stream
    /// that has already handed out an item.
    /// [`ErrorKind::InvalidResponse`] when the text is longer than 16 MiB or
    /// memory for it could not be allocated, with the current answer's request ID if available.
    pub async fn into_text(mut self) -> Result<String, Error> {
        if self.touched {
            return Err(text::already_read());
        }
        let mut text = Collected::new();
        while let Some(event) = self.next().await {
            text.collect(&event?, self.request_id())?;
        }
        Ok(text.into_string())
    }
}

impl Drop for AsyncResponseStream {
    fn drop(&mut self) {
        // The canceller tells the handover, which drops what waits.
        self.guard.0.cancel();
    }
}

impl fmt::Debug for AsyncResponseStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncResponseStream")
            .field("has_request_id", &self.request_id.is_some())
            .field("waiting_events", &self.handover.waiting())
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "testing"))]
mod start_tests;
