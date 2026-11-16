//! kata's seams in the engine: a backend that runs each [`EmbeddedHost`]'s
//! cells somewhere other than the calling thread, a loader for the stored
//! values a cell's `start_cell` was not given, and the report of a heap hit.
//!
//! Without [`set_worker_backend`], every [`EmbeddedHost`] runs its cells on the
//! task that polls it, as upstream's does; nothing below changes that host.
//!
//! [`EmbeddedHost`]: crate::EmbeddedHost

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock, mpsc as std_mpsc},
};

use nanocode_sync::{mpsc, oneshot};
use serde_json::value::RawValue;

use crate::{
    CellJournaling, RuntimeEvent,
    cell::{CellTools, ExecutionState},
};

/// One `start_cell`, as a backend receives it. The engine's `Interrupt` is not
/// passed on: a backend's host ends a cell by `terminate`, which every
/// interrupt of a cell nanocode raises is followed by.
pub struct StartExecution {
    pub execution_id: u64,
    pub source: String,
    pub stored: HashMap<String, Arc<RawValue>>,
    pub tools: Arc<CellTools>,
    pub prelude: Option<Arc<str>>,
    pub journaling: Option<CellJournaling>,
}

/// What an [`EmbeddedHost`](crate::EmbeddedHost) a backend started asks of it,
/// in the order the host was asked.
pub enum HostCommand {
    Start(StartExecution),
    ToolResult {
        execution_id: u64,
        id: u64,
        encoded: String,
        success: bool,
    },
    Hold {
        execution_id: u64,
    },
    Release {
        execution_id: u64,
    },
    /// `terminate`: end whatever runs, then send [`Stopped`].
    Shutdown,
}

/// The sender of the events a backend's host reads, in order.
pub struct Events(mpsc::UnboundedSender<RuntimeEvent>);

impl Events {
    /// Sends `event` to the host; `false` once the host is gone.
    pub fn send(&self, event: RuntimeEvent) -> bool {
        self.0.send(event).is_ok()
    }
}

/// What `terminate` awaits: sent once nothing the backend started for the host
/// runs any more. Dropped unsent, it ends the wait too.
pub struct Stopped(oneshot::Sender<()>);

impl Stopped {
    pub fn send(self) {
        let _ = self.0.send(());
    }
}

/// One host's ends, handed to the backend [`set_worker_backend`] installs: the
/// commands the host sends (closed when the host is dropped), the sender of
/// the events it reads, the failure the host returns once that sender is gone
/// (`startup`, or a generic one when nothing was set), and [`Stopped`].
pub struct WorkerEnds {
    pub commands: std_mpsc::Receiver<HostCommand>,
    pub events: Events,
    pub startup: Arc<OnceLock<String>>,
    pub stopped: Stopped,
}

/// What starts the backend of each host spawned once it is installed; an `Err`
/// fails that spawn with its text.
pub type WorkerBackend = Box<dyn Fn(WorkerEnds) -> Result<(), String> + Send + Sync>;

static WORKER_BACKEND: OnceLock<WorkerBackend> = OnceLock::new();

/// Installs `backend` for every [`EmbeddedHost`](crate::EmbeddedHost) spawned
/// after this call. Once only: a later call changes nothing and returns its
/// `backend`.
pub fn set_worker_backend(backend: WorkerBackend) -> Result<(), WorkerBackend> {
    WORKER_BACKEND.set(backend)
}

/// What answers a cell's `load` of a key its stored values lack
/// ([`set_stored_loader`]): the value, or `None` for a key that holds none.
pub type StoredLoader = Box<dyn Fn(&str) -> Option<Arc<RawValue>> + Send + Sync>;

static STORED_LOADER: OnceLock<StoredLoader> = OnceLock::new();

/// Installs `loader` to answer, in every host of this process that runs its
/// cells itself, a cell's `load` of a key the stored values its `start_cell`
/// was given lack. It runs inside the cell's step, which waits for it. Once
/// only: a later call changes nothing and returns its `loader`. Without it,
/// such a `load` answers `undefined`, as upstream's does.
pub fn set_stored_loader(loader: StoredLoader) -> Result<(), StoredLoader> {
    STORED_LOADER.set(loader)
}

pub(crate) fn load_stored(key: &str) -> Option<Arc<RawValue>> {
    STORED_LOADER.get().and_then(|loader| loader(key))
}

/// The report of a cell's heap hit, sent as a notification of its own just
/// before the cell's `Error`: nanocode delivers a notification beside the
/// cell's result, where its truncation of that result does not reach it.
pub(crate) fn report_out_of_memory(state: &mut ExecutionState) {
    state.send(RuntimeEvent::Notify {
        cell_id: state.execution_id,
        text: format!(
            "Code Mode cell exceeded its {}-byte memory limit",
            crate::cell_memory()
        ),
    });
}

/// A host whose cells a backend runs.
pub(crate) struct Remote {
    commands: Option<std_mpsc::Sender<HostCommand>>,
    events: mpsc::UnboundedReceiver<RuntimeEvent>,
    startup: Arc<OnceLock<String>>,
    stopped: Option<oneshot::Receiver<()>>,
}

impl Remote {
    /// The installed backend's host, or `None` when no backend is installed.
    pub(crate) fn spawn() -> Option<Result<Self, String>> {
        let backend = WORKER_BACKEND.get()?;
        let (commands, received) = std_mpsc::channel();
        let (events, read) = mpsc::unbounded_channel();
        let (stopped, awaited) = oneshot::channel();
        let startup = Arc::new(OnceLock::new());
        let ends = WorkerEnds {
            commands: received,
            events: Events(events),
            startup: Arc::clone(&startup),
            stopped: Stopped(stopped),
        };
        Some(backend(ends).map(|()| Self {
            commands: Some(commands),
            events: read,
            startup,
            stopped: Some(awaited),
        }))
    }

    fn send(&self, command: HostCommand) -> Result<(), String> {
        self.commands
            .as_ref()
            .and_then(|commands| commands.send(command).ok())
            .ok_or_else(|| self.ended())
    }

    fn ended(&self) -> String {
        self.startup
            .get()
            .cloned()
            .unwrap_or_else(|| "the Code Mode host's backend ended".to_owned())
    }

    pub(crate) fn start_cell(&self, start: StartExecution) -> Result<(), String> {
        self.send(HostCommand::Start(start))
    }

    /// Cancel-safe: an event is taken off the channel only when it is returned.
    pub(crate) async fn read_event(&mut self) -> Result<RuntimeEvent, String> {
        match self.events.recv().await {
            Some(event) => Ok(event),
            None => Err(self.ended()),
        }
    }

    pub(crate) fn send_tool_result(
        &self,
        execution_id: u64,
        id: u64,
        encoded: String,
        success: bool,
    ) -> Result<(), String> {
        self.send(HostCommand::ToolResult {
            execution_id,
            id,
            encoded,
            success,
        })
    }

    pub(crate) fn hold(&self, execution_id: u64) -> Result<(), String> {
        self.send(HostCommand::Hold { execution_id })
    }

    pub(crate) fn release(&self, execution_id: u64) -> Result<(), String> {
        self.send(HostCommand::Release { execution_id })
    }

    /// Ends whatever the backend runs for this host, and waits until it says
    /// nothing does.
    pub(crate) async fn terminate(&mut self) {
        if let Some(commands) = self.commands.take() {
            let _ = commands.send(HostCommand::Shutdown);
        }
        if let Some(stopped) = self.stopped.take() {
            let _ = stopped.await;
        }
    }
}
