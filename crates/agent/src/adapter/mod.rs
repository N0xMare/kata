//! The attempt-scoped AGENT ADAPTER CONTRACT, and nothing that
//! performs I/O.
//!
//! ADR-0001 "Agent execution" admits one agent contract — nanocode embedded in
//! the worker as a library, as two kinds, whose adapter is
//! `kata-agent-nanocode` — and requires that *"each adapter declares what its
//! protocol offers, measured, in its module doc and in the adapter
//! qualification matrix, and refuses by name a request it cannot serve"*, that
//! *"agent processes, sessions, files, and stdio are worker-owned and
//! attempt-scoped"*, and that *"protocol disconnect after possible model or tool
//! issuance remains ambiguous; usage unknown is not recorded as zero"*.
//!
//! The first is met per adapter rather than by a type here: each adapter's module
//! doc records what its protocol offers, `crates/agent/tests/qualification_matrix.rs`
//! classifies it requirement by requirement, and a request it cannot serve is
//! refused by name.
//!
//! This module is the type-level statement of the last two:
//!
//! * [`AttemptScope`](crate::adapter::AttemptScope) carries [`GuestPath`](kata_types::execution_contract::GuestPath)-only
//!   mappings, so a host path is not expressible in what an adapter is handed —
//!   trust boundary 4 (*"Youki or an experimental VM receives only the capsule's
//!   mounts and capabilities"*) as a type rather than as a review rule.
//! * [`TurnOutcome::Ambiguous`](crate::adapter::TurnOutcome::Ambiguous) exists and is not a
//!   failure; the worker's turn driver (`kata_worker::agent_turn`) settles it as a PROVEN
//!   AMBIGUOUS attempt.
//!
//! # WHAT THIS MODULE DELIBERATELY CANNOT DO
//!
//! It cannot spawn anything. An adapter never builds a `Command`: the capsule's
//! init process arrives already running, as an [`InteractiveProcess`](crate::adapter::InteractiveProcess) the worker owns and
//! placed inside the attempt's capsule.
//! **`kata_worker::interactive_capsule::InteractiveCapsule` is the one production
//! implementor — a process running as the init of a rootless OCI container with live
//! stdio over three worker-owned FIFOs — and a hermetic double is the only other.**
//! That is
//! not a convention — `crates/agent/tests/adapter_contract.rs` reads this
//! directory's own source and fails if `std::process::Command`,
//! `tokio::process::Command` or `std::path` appears in it, the same
//! source-derived accounting `crates/core/tests/operational_crash_matrix.rs`
//! uses for its coverage claims. An adapter that could spawn its own child
//! could place it outside the capsule, and every containment property in trust
//! boundary 4 would then be a statement about the wrong process tree.
//!
//! No kind is qualified by being wired to a stage — qualification lives in
//! `crates/agent/tests/qualification_matrix.rs` against each kind's own
//! proving cells, and a stage reaches a kind only through the production
//! registry kata-worker builds (`kata_worker::adapter_registry::production`)
//! over
//! [`StaticAgentAdapterRegistry`](crate::adapter::capsule_registry::StaticAgentAdapterRegistry).

use std::process::ExitStatus;

use async_trait::async_trait;
use kata_types::agent::AdapterKind;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod capsule_registry;
pub mod scope;
pub mod session;

pub use scope::{AttemptScope, SessionSeed};
pub use session::{
    AgentSession, CleanupReport, FailedTurnCharge, IssuanceFrame, IssuanceWatermark, Marked,
    MayHaveIssued, SessionId, TurnOutcome, act_on_marked_frame, observe_frame,
};

/// Why [`AgentAdapter::open`] refused to produce a session.
///
/// Typed rather than a string because each arm is a different operational
/// situation: the first is an interactive process the worker handed over in a state
/// no protocol can be spoken over, the second a scope this protocol cannot
/// serve.
#[derive(Debug, thiserror::Error)]
pub enum OpenRefusal {
    /// The [`InteractiveProcess`] does not expose a stream the protocol needs (an
    /// already-taken stdin, a stdout the worker did not pipe).
    #[error(
        "adapter refuses to open a session: interactive process stream {stream} is unavailable"
    )]
    StreamUnavailable {
        /// Which stream — `stdin`, `stdout` or `stderr`.
        stream: &'static str,
    },
    /// The attempt scope is not usable for this adapter's protocol, with the
    /// reason stated.
    #[error("adapter refuses to open a session: {reason}")]
    Scope {
        /// What about the scope refuses the session.
        reason: String,
    },
}

/// A signal a session may deliver to the interactive process it does NOT own.
///
/// Three, because those are the three the teardown ladder in
/// [`crate::resource_bounds`] already distinguishes; an adapter has no business
/// naming an arbitrary signal number.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Signal {
    /// Polite interrupt (`SIGINT`) — a cancel the process may acknowledge.
    Interrupt,
    /// Graceful termination request (`SIGTERM`).
    Terminate,
    /// Unconditional kill (`SIGKILL`).
    Kill,
}

impl Signal {
    /// Stable lowercase label for logs.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Terminate => "terminate",
            Self::Kill => "kill",
        }
    }
}

/// An interactive process the WORKER owns — the capsule's init, already running
/// inside the attempt's capsule.
///
/// # The whole point is what an adapter is NOT given
///
/// An adapter receives streams and two lifecycle verbs. It receives no program
/// path, no argv, no environment, no working directory and no spawn verb, so
/// there is nothing for it to re-launch, re-point at a host path, or place
/// outside the capsule. The worker decides all of that
/// (`kata_worker::interactive_capsule::InteractiveCapsule::launch`), which is what makes trust boundary 4's *"agent callbacks and child processes
/// remain inside this boundary"* a property of the code rather than of the
/// adapter author's discipline.
///
/// Streams are TAKEN rather than borrowed: the adapter's reader owns its stream
/// for the life of the session, and `Option`-returning takers make a second take
/// a `None` the caller must handle instead of an aliasing bug.
#[async_trait]
pub trait InteractiveProcess: Send {
    /// Take the process's stdin sink. `None` once taken, or if the worker did
    /// not pipe it.
    fn take_stdin(&mut self) -> Option<Box<dyn AsyncWrite + Send + Unpin>>;

    /// Take the process's stdout source. `None` once taken, or if the worker did
    /// not pipe it.
    fn take_stdout(&mut self) -> Option<Box<dyn AsyncRead + Send + Unpin>>;

    /// Take the process's stderr source. `None` once taken, or if the worker did
    /// not pipe it.
    fn take_stderr(&mut self) -> Option<Box<dyn AsyncRead + Send + Unpin>>;

    /// Ask the worker to deliver `signal` to the process.
    ///
    /// # Errors
    ///
    /// The implementation's own error when the signal could not be delivered. A
    /// delivered signal is not a claim that the process EXITED — that claim is
    /// [`crate::resource_bounds::TeardownOutcome`]'s, and it requires a probe.
    async fn signal(&mut self, signal: Signal) -> kata_types::error::KataResult<()>;

    /// Wait for the process to exit.
    ///
    /// # Errors
    ///
    /// The implementation's own error when the exit status could not be
    /// observed.
    async fn wait(&mut self) -> kata_types::error::KataResult<ExitStatus>;
}

/// One admitted agent wire contract, as an attempt-scoped session factory.
///
/// Stateless: an adapter holds no session state (the session it returns does)
/// and no process (the caller hands one in). That is what lets one adapter value
/// serve every attempt of its kind, and what keeps every piece of per-attempt
/// state inside the [`AttemptScope`] the worker built.
pub trait AgentAdapter: Send + Sync {
    /// Which wire contract this adapter speaks.
    fn kind(&self) -> AdapterKind;

    /// Open a session over `process` for `scope`.
    ///
    /// # Errors
    ///
    /// [`OpenRefusal`] — a stream the worker did not hand over, or a scope this
    /// protocol cannot serve. Opening
    /// performs no model call, so a refusal here has issued nothing.
    fn open(
        &self,
        scope: AttemptScope,
        process: Box<dyn InteractiveProcess>,
    ) -> Result<Box<dyn AgentSession>, OpenRefusal>;
}
