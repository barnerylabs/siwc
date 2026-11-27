//! The client: several accounts side by side, each addressed by its ID.
//!
//! [`Client`] ties the protocol, the loopback listener, the store and the
//! plan helpers together. Every operation that touches tokens names its
//! account; nothing falls back from one account to another.

mod accounts;
mod async_call;
mod bundle;
mod call;
mod changes;
mod diagnose;
mod diagnosis;
mod echo;
mod entries;
mod manual_sign_in;
mod records;
mod response;
mod response_async;
mod sign_in;
mod sign_out;
mod tokens;
mod transfer;
mod unfinished;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::app::AppName;
use crate::background::{self, Background, Job, Spawner};
#[cfg(feature = "testing")]
use crate::entropy::Entropy;
use crate::entropy::OsEntropy;
use crate::loopback::{Style, Texts};
use crate::store::Store;
use crate::time::{Clock, SystemClock};
use crate::transport::Transport;

#[cfg(fuzzing)]
pub(crate) use bundle::fuzz_bundle;
pub use changes::{Change, Changes};
pub use diagnosis::Diagnosis;
pub use manual_sign_in::ManualSignIn;
#[cfg(fuzzing)]
pub(crate) use records::fuzz_installation;
pub use response::ResponseStream;
pub use response_async::AsyncResponseStream;
pub use sign_in::{Completed, SignIn};
pub use sign_out::SignOut;

/// How long an operation waits for an entry's lock by default.
const DEFAULT_LOCK_PATIENCE: Duration = Duration::from_secs(30);

#[cfg(feature = "testing")]
type ClientEntropy = dyn Entropy;
#[cfg(not(feature = "testing"))]
type ClientEntropy = OsEntropy;

/// Signs accounts in, keeps them in a store and hands out their access
/// tokens.
///
/// A store holds up to 32 accounts side by side, however many clients open
/// it. Each account has its own registration with the provider, its own
/// credentials entry in the store and its own lock, and every operation
/// names the account it is for by its [`AccountId`](crate::AccountId). A
/// refresh happens under that account's lock, so two threads, or two
/// processes on the same store, never spend the same refresh token at the
/// same time. If the answer to a refresh is lost or its successor cannot be
/// stored, a later refresh sends the previous token again, and the provider
/// may then ask for a new sign-in.
///
/// The accounts in one store form an *installation*: its installation record
/// lists them and holds the host ID.
///
/// Clones share everything: the store, the transport and the one sign-in a
/// client can have waiting for the browser.
///
/// ```no_run
/// use std::time::Duration;
///
/// use siwc::store::MemoryStore;
/// use siwc::{AppName, Client};
/// # #[derive(Debug)]
/// # struct MyHttpClient;
/// # impl siwc::Transport for MyHttpClient {
/// #     fn send(&self, _: &siwc::protocol::HttpRequest) -> Result<siwc::protocol::HttpResponse, siwc::Error> { todo!() }
/// # }
///
/// // `MyHttpClient` is the app's `Transport`; with the `https` feature,
/// // pass `siwc::Https::new()?` instead.
/// let client = Client::new(AppName::new("Paste Perfect")?, MemoryStore::new(), MyHttpClient);
///
/// let sign_in = client.add_account()?;
/// if sign_in.open_browser().is_err() {
///     println!("To sign in, open {}", sign_in.start_link());
/// }
/// let account = sign_in.finish(Duration::from_secs(300))?.into_account();
///
/// let token = client.access_token(account.id())?;
/// # drop(token);
/// # Ok::<(), siwc::Error>(())
/// ```
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

/// What every clone of a client shares.
struct Inner {
    app: AppName,
    store: Box<dyn Store>,
    transport: Box<dyn Transport>,
    clock: Box<dyn Clock>,
    entropy: Box<ClientEntropy>,
    texts: Texts,
    style: Style,
    /// The callback port; 0 lets the system choose one.
    callback_port: u16,
    /// Whether authorization requests carry the installation's host ID.
    send_host_id: bool,
    lock_patience: Duration,
    /// Whether a plan request refused with a `5xx` is sent again.
    resend_after_server_error: bool,
    /// Where the `*_async` methods run their work; `None` for a thread
    /// of its own each.
    spawner: Option<Box<Spawner>>,
    /// Whether a [`SignIn`] of this client is alive.
    signing_in: Arc<AtomicBool>,
}

impl Client {
    /// A client with the defaults: the system clock, the operating system's
    /// random source, the English answer page, a callback port the system
    /// assigns, 30 seconds of patience for a lock and plan requests sent
    /// again after a `5xx`.
    ///
    /// Every account this client adds registers under `app`.
    #[must_use]
    pub fn new(
        app: AppName,
        store: impl Store + 'static,
        transport: impl Transport + 'static,
    ) -> Self {
        Self::builder(app, store, transport).build()
    }

    /// A builder for a client with other settings.
    ///
    /// ```no_run
    /// use std::time::Duration;
    ///
    /// use siwc::store::PrivateFiles;
    /// use siwc::{AppName, Client};
    /// # #[derive(Debug)]
    /// # struct MyHttpClient;
    /// # impl siwc::Transport for MyHttpClient {
    /// #     fn send(&self, _: &siwc::protocol::HttpRequest) -> Result<siwc::protocol::HttpResponse, siwc::Error> { todo!() }
    /// # }
    ///
    /// let store = PrivateFiles::open("/var/lib/paste-perfect")?;
    /// let client = Client::builder(AppName::new("Paste Perfect")?, store, MyHttpClient)
    ///     .callback_port(53124) // forwarded with `ssh -L 53124:127.0.0.1:53124`
    ///     .lock_patience(Duration::from_secs(10))
    ///     .build();
    /// # drop(client);
    /// # Ok::<(), siwc::Error>(())
    /// ```
    #[must_use]
    pub fn builder(
        app: AppName,
        store: impl Store + 'static,
        transport: impl Transport + 'static,
    ) -> ClientBuilder {
        ClientBuilder {
            app,
            store: Box::new(store),
            transport: Box::new(transport),
            clock: Box::new(SystemClock),
            entropy: Box::new(OsEntropy),
            texts: Texts::default(),
            style: Style::default(),
            callback_port: 0,
            send_host_id: true,
            lock_patience: DEFAULT_LOCK_PATIENCE,
            resend_after_server_error: true,
            spawner: None,
        }
    }
}

impl Client {
    /// Runs `work` where the client's spawner puts it, or on a thread of
    /// its own, and returns a future of its result.
    fn background<T, F>(&self, work: F) -> Result<Background<T>, crate::Error>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        match &self.inner.spawner {
            Some(spawner) => Ok(background::run_on(&**spawner, work)),
            None => background::try_run_with(background::spawn, work),
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("app", &self.inner.app)
            .finish_non_exhaustive()
    }
}

/// Settings for a [`Client`]; [`build`](Self::build) makes the client.
#[cfg_attr(
    not(feature = "testing"),
    doc = "\n```compile_fail,E0599\nfn replace_entropy(builder: siwc::ClientBuilder) {\n    let _ = builder.entropy(siwc::OsEntropy);\n}\n```"
)]
pub struct ClientBuilder {
    app: AppName,
    store: Box<dyn Store>,
    transport: Box<dyn Transport>,
    clock: Box<dyn Clock>,
    entropy: Box<ClientEntropy>,
    texts: Texts,
    style: Style,
    callback_port: u16,
    send_host_id: bool,
    lock_patience: Duration,
    resend_after_server_error: bool,
    spawner: Option<Box<Spawner>>,
}

impl ClientBuilder {
    /// Where the client reads the time. Default: [`SystemClock`].
    #[must_use]
    pub fn clock(mut self, clock: impl Clock + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Replaces the client's random source in tests. The default is
    /// [`OsEntropy`], which is the only source without the `testing` feature.
    #[cfg(feature = "testing")]
    #[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
    #[must_use]
    pub fn entropy(mut self, entropy: impl Entropy + 'static) -> Self {
        self.entropy = Box::new(entropy);
        self
    }

    /// The texts of the page the browser tab shows when a sign-in ends.
    /// Default: English.
    #[must_use]
    pub fn page_texts(mut self, texts: Texts) -> Self {
        self.texts = texts;
        self
    }

    /// The look of that page: a stylesheet and a logo. Default: the plain
    /// default style.
    #[must_use]
    pub fn page_style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// A fixed port for the browser callback, for a setup that forwards it
    /// from another machine. Default: a port the system assigns, which
    /// cannot collide. A sign-in fails with
    /// [`ErrorKind::Loopback`](crate::ErrorKind::Loopback) when the port is
    /// taken.
    #[must_use]
    pub fn callback_port(mut self, port: u16) -> Self {
        self.callback_port = port;
        self
    }

    /// Whether authorization requests carry the installation's host ID as
    /// `ext_agent_host_id`, which OpenAI's sign-in guide lists as required.
    /// Default: `true`. `false` leaves the parameter out, for an
    /// authorization server that does not accept it; the host ID is still
    /// generated and stored, so turning it back on sends the same ID.
    #[must_use]
    pub fn send_host_id(mut self, send: bool) -> Self {
        self.send_host_id = send;
        self
    }

    /// How long an operation waits for an entry's lock held by another
    /// thread or process before it fails with
    /// [`ErrorKind::StoreBusy`](crate::ErrorKind::StoreBusy). Default: 30
    /// seconds.
    #[must_use]
    pub fn lock_patience(mut self, patience: Duration) -> Self {
        self.lock_patience = patience;
        self
    }

    /// Whether a plan request the API refused with a `5xx` is sent again
    /// after a wait, by the rule [`Client::call`] describes. Default:
    /// `true`.
    ///
    /// With `false`, a `5xx` is the error at once
    /// ([`ErrorKind::Temporary`](crate::ErrorKind::Temporary)) and the app
    /// decides whether to send the request again. A `5xx` whose body carries
    /// the provider's own "not now" code (`subscription_sharing_usage_unavailable`
    /// or `subscription_sharing_user_unavailable`) is still waited out, as is a
    /// `429`, because the provider asks for those to be retried. A `401` still
    /// renews the token once.
    #[must_use]
    pub fn resend_after_server_error(mut self, resend: bool) -> Self {
        self.resend_after_server_error = resend;
        self
    }

    /// Where the `*_async` methods run their blocking work. Default: an OS
    /// thread of its own for every call and for every open
    /// [`AsyncResponseStream`].
    ///
    /// An app on an async runtime hands the work to that runtime's pool for
    /// blocking calls instead, which reuses threads and limits their number:
    ///
    /// ```
    /// # use siwc::{AppName, Client, background::Job, store::MemoryStore};
    /// # fn spawn_blocking(job: Job) { std::thread::spawn(job); }
    /// # fn build(transport: impl siwc::Transport + 'static) -> Result<Client, siwc::Error> {
    /// let client = Client::builder(AppName::new("Paste Perfect")?, MemoryStore::new(), transport)
    ///     // With Tokio: `|job| drop(tokio::task::spawn_blocking(job))`.
    ///     .spawner(|job| spawn_blocking(job))
    ///     .build();
    /// # Ok(client)
    /// # }
    /// ```
    ///
    /// The spawner has to run each job, on another thread that may block
    /// for as long as the call lasts: the wait for the browser in
    /// [`SignIn::finish_async`], the whole answer for a stream. It must not
    /// run the job itself before it returns: a stream's job reads ahead
    /// until its queue is full and then waits for the task that called the
    /// spawner. A pool with
    /// a limit therefore limits how many streams are open at once; further
    /// ones wait for a thread, and so does every other `*_async` call. A
    /// task that leaves its streams unread while it awaits another call can
    /// therefore wait for good once those streams hold every thread. A job
    /// dropped without having run ends
    /// [`Client::stream_response_async`] with [`ErrorKind::Temporary`]
    /// before anything is sent, and panics the task that awaits any other
    /// call. A panic of the spawner itself, such as Tokio's
    /// `spawn_blocking` outside a runtime, reaches the task that awaits the
    /// call. With the default spawner, inability to create a worker returns
    /// `Temporary`. A panic inside application code propagates through ordinary
    /// client futures; an async stream reports a lost worker as an error.
    /// [`background::run`] always starts a thread of its own.
    ///
    /// [`ErrorKind::Temporary`]: crate::ErrorKind::Temporary
    /// [`background::run`]: crate::background::run
    #[must_use]
    pub fn spawner(mut self, spawner: impl Fn(Job) + Send + Sync + 'static) -> Self {
        self.spawner = Some(Box::new(spawner));
        self
    }

    /// The client.
    #[must_use]
    pub fn build(self) -> Client {
        Client {
            inner: Arc::new(Inner {
                app: self.app,
                store: self.store,
                transport: self.transport,
                clock: self.clock,
                entropy: self.entropy,
                texts: self.texts,
                style: self.style,
                callback_port: self.callback_port,
                send_host_id: self.send_host_id,
                lock_patience: self.lock_patience,
                resend_after_server_error: self.resend_after_server_error,
                spawner: self.spawner,
                signing_in: Arc::default(),
            }),
        }
    }
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("app", &self.app)
            .field("callback_port", &self.callback_port)
            .field("send_host_id", &self.send_host_id)
            .field("lock_patience", &self.lock_patience)
            .finish_non_exhaustive()
    }
}
