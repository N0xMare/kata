//! In-flight ledger wire types — `LedgerEvent` and `AssignmentStatus`.
//!
//! These are the JSON shapes carried over the SSE feed at
//! `GET /api/v1/events` and folded from kata-core's attempt records. They live
//! here so the kata-client SDK can re-export the canonical Rust definitions
//! instead of maintaining a per-field mirror.
//!
//! The ledger machinery (`kata_core::ledger::InFlightLedger`, its broadcast
//! channels and the durable event log behind them) stays in `kata-core` because
//! it carries `DashMap`, `tokio::sync` and SQLite dependencies that have no
//! business in `kata-types`. Only the data shapes live here.
//!
//! The `Ulid` typing on `LedgerEvent::execution_id` and
//! `LedgerEvent::assignment_id` matches kata-core's representation
//! exactly; serde produces the same `"01ARZ3..."` JSON
//! string regardless of whether the Rust field is a `Ulid` or a
//! `String`. Choosing `Ulid` here means the strong typing extends all
//! the way through to SDK consumers.

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use ulid::Ulid;

/// Role kind for an observed agent invocation under a workflow stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentInvocationKind {
    Root,
    Worker,
    Reviewer,
    Stage,
}

/// Lifecycle state for an observed agent invocation, synchronized with its
/// assignment's lifecycle state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentInvocationStatus {
    Pending,
    AwaitingApproval,
    Dispatched,
    Running,
    Completed,
    Failed,
    Orphaned,
    Stalled,
}

impl AgentInvocationStatus {
    /// Wire string for this status — the `snake_case` serde tag,
    /// projected without round-tripping through serde for one field.
    #[must_use]
    pub fn as_tag(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Dispatched => "dispatched",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Orphaned => "orphaned",
            Self::Stalled => "stalled",
        }
    }

    /// True when this invocation has reached a terminal state
    /// (`Completed` / `Failed` / `Orphaned`).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Orphaned)
    }
}

/// Durable observed invocation record stored below an assignment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInvocationRecord {
    pub id: Ulid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Ulid>,
    pub assignment_id: Ulid,
    pub execution_id: Ulid,
    pub stage_name: SmolStr,
    pub kind: AgentInvocationKind,
    pub role: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<SmolStr>,
    /// The named [`EffectKind`](crate::effect::EffectKind) this stage's
    /// effect classifies to (derived from `agent_label`). Serde-default, so a
    /// row without it decodes as `None`. Makes the Effect boundary observable
    /// in the durable ledger with no behavior change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_kind: Option<crate::effect::EffectKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology_kind: Option<SmolStr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hint: Option<SmolStr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub progress_visibility: crate::workflow::ProgressVisibility,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owned_paths: Vec<SmolStr>,
    /// Whether assignment lifecycle transitions should update this
    /// invocation's status/timestamps. Root/direct invocations are backed by
    /// the assignment and stay synchronized; declared child roles remain
    /// independently tracked until a caller dispatches executable child
    /// assignments for them.
    #[serde(default = "default_sync_with_assignment")]
    pub sync_with_assignment: bool,
    pub status: AgentInvocationStatus,
    pub created_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatched_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at_ms: Option<u64>,
}

/// Query projection for every observed agent invocation in one execution.
///
/// `nodes` is a deterministic flat list. `roots`, `orphaned`, and each node's
/// `child_ids` make parent/child traversal cheap without recursive JSON.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentInvocationGraph {
    pub execution_id: Ulid,
    #[serde(default)]
    pub nodes: Vec<AgentInvocationGraphNode>,
    #[serde(default)]
    pub roots: Vec<Ulid>,
    #[serde(default)]
    pub orphaned: Vec<Ulid>,
}

impl AgentInvocationGraph {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// One observed invocation node in an execution-level graph projection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentInvocationGraphNode {
    pub id: Ulid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Ulid>,
    pub assignment_id: Ulid,
    pub execution_id: Ulid,
    pub stage_name: SmolStr,
    pub kind: AgentInvocationKind,
    pub role: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<SmolStr>,
    /// The named [`EffectKind`](crate::effect::EffectKind) this stage's
    /// effect classifies to, mirrored from the durable invocation record so the
    /// Effect boundary is observable in the execution-graph API. Additive +
    /// serde-default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_kind: Option<crate::effect::EffectKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology_kind: Option<SmolStr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hint: Option<SmolStr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub progress_visibility: crate::workflow::ProgressVisibility,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owned_paths: Vec<SmolStr>,
    #[serde(default)]
    pub sync_with_assignment: bool,
    pub status: AgentInvocationStatus,
    pub created_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatched_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at_ms: Option<u64>,
    #[serde(default)]
    pub child_ids: Vec<Ulid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_progress: Option<ProgressEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
}

fn default_sync_with_assignment() -> bool {
    true
}

/// Lifecycle state of a single assignment.
///
/// Terminal states (`Completed`, `Failed`, `Cancelled`, `Orphaned`) are latched in
/// the kata-core ledger: subsequent transitions are silently
/// discarded. The wire shape uses `tag = "kind"` discrimination — see
/// the `AssignmentStatus::tag` helper for the canonical string set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AssignmentStatus {
    /// Queued, no worker assigned yet.
    Pending,
    /// Parked pre-dispatch, waiting for operator approval via the
    /// `POST /api/v1/executions/{id}/approve` REST endpoint. The
    /// assignment was built and inserted but not yet sent to a
    /// worker.
    ///
    /// Non-terminal. Transitions to `Dispatched { worker_id }` on
    /// approve, or to `Failed { reason }` on reject.
    AwaitingApproval {
        /// Always `None` today — workers are selected at dispatch
        /// time, not pre-gated. Kept as `Option` for forward
        /// compatibility with a future "target a specific worker for
        /// approval" feature.
        worker_id: Option<SmolStr>,
        /// Human-readable explanation surfaced to the operator.
        reason: String,
    },
    /// Non-terminal (subworkflow) — the stage spawned a CHILD workflow
    /// execution and is parked awaiting its completion. It holds NO
    /// `worker_id`: parking frees the worker (the dispatch/start anchors are
    /// cleared) so a single-worker pool can run the child without deadlocking
    /// the parked parent. No worker frame ends the wait: it ends
    /// with the child's terminal publication, with the parent's, or by
    /// `Dispatcher::settle_abandoned_invocations` for a parent that will not
    /// publish with the wait parked. The child link is durable — it rides in
    /// this status, which persists in the ledger blob.
    AwaitingChildCompletion {
        /// The `ExecutionId` (as a `Ulid`) of the spawned child workflow
        /// execution this parent stage is waiting on. Durable across a crash, so
        /// the wait still names its child after a restart.
        child_execution_id: Ulid,
        /// Human-readable explanation surfaced to the operator (e.g. the child
        /// pack name).
        reason: String,
    },
    /// Dispatched to a worker, no result seen yet.
    Dispatched { worker_id: SmolStr },
    /// Worker acknowledged the assignment (first heartbeat or
    /// checkpoint seen).
    Running { worker_id: SmolStr },
    /// Terminal completion. A dispatched attempt carries its worker; a cache
    /// satisfaction or other undispatched stage has no worker to attribute.
    Completed { worker_id: Option<SmolStr> },
    /// Terminal — the worker reported `WorkerMessage::Failed`, or the
    /// orchestrator rejected the stage. `worker_id` is `None` only in
    /// the edge case where the failure happened before any worker was
    /// assigned (e.g. the dispatcher found no live worker and
    /// orphaned immediately).
    Failed {
        worker_id: Option<SmolStr>,
        reason: String,
    },
    /// Terminal — the attempt ended because an OPERATOR asked it to stop, and
    /// the main holds a durable `attempt_stop_requests` row standing against it.
    ///
    /// # Why this is its own terminal rather than a flag on [`Self::Failed`]
    ///
    /// Discriminating a cancel downstream by a PROSE match on the reason prefix
    /// `"cancelled:"` cannot work: `Dispatcher::handle_stage_failure`'s
    /// standing-stop branch rewrites the reason ("stage failed under a standing
    /// operator stop, …"), so an honoured cancel would terminalize the EXECUTION
    /// as `Failed` and take `require_terminal_lifecycle_for_parking`'s
    /// evidence-free `Completed | Failed => Ok(())` arm, reading NO stop-ack
    /// evidence at all. A flag on `Failed` would be two terminals behind one name
    /// and would let `is_terminal`, the ledger latch and the executor's
    /// failed-or-orphaned chain check each pick a different reading of it.
    ///
    /// # What the evidence-free arm would cost, stated exactly
    ///
    /// Not "every honoured cancel parks unsafely" — that claim is too big. The
    /// reactor acknowledges an attempt's stop from that
    /// attempt's own terminal frame BEFORE the frame reaches the standing-stop
    /// branch, so a LONE cancel arrives at the gate with nothing outstanding and
    /// its attempt settled; the evidence arm would have permitted the park too.
    /// The arm matters when the EXECUTION still holds a stop that terminal does
    /// not discharge — `WorkflowExecutor::cancel` asks every live attempt, the
    /// ack is per `(attempt_id, lease_epoch)`, and the gate's read is
    /// execution-scoped. A sibling attempt on a wedged worker is that population,
    /// and for it the park would open on a workspace a live worker still held.
    ///
    /// `worker_id` is `Option` for the same reason [`Self::Failed`]'s is: a
    /// cancel of an attempt whose placement was reclaimed to NULL is a real
    /// expressible shape, and refusing it in the delivery mapping would convert
    /// a legitimate terminal into an execution-wide unreadable chain.
    Cancelled {
        worker_id: Option<SmolStr>,
        reason: String,
    },
    /// Terminal — the worker died or a retry was exhausted before a
    /// real result could be collected. `prev_worker` is the last
    /// worker id the assignment was on before it was orphaned.
    Orphaned {
        prev_worker: Option<SmolStr>,
        reason: String,
    },
    /// Non-terminal, informational only — the worker has missed at least
    /// one heartbeat interval but is still within the grace window (not
    /// yet declared dead). The assignment's stored status in the ledger is
    /// **not changed** by this event; it remains `Dispatched` or `Running`.
    ///
    /// Emitted at most once per stall cycle per assignment. A "stall cycle"
    /// resets when the worker sends a new heartbeat; if the worker stalls
    /// again after recovery a second `Stalled` event fires.
    ///
    /// SSE consumers should use this as an early warning to surface a
    /// "worker appears slow" UI indicator before the orphan/resume flow
    /// fires.
    Stalled {
        worker_id: SmolStr,
        /// Wall-clock ms (Unix epoch) of the worker's last recorded heartbeat.
        last_heartbeat_at_ms: u64,
        /// Seconds elapsed beyond the configured heartbeat interval; i.e.
        /// how long the worker has been silent past its expected beat.
        stalled_for_secs: u64,
    },
}

impl AssignmentStatus {
    /// True if this status is terminal. Terminal states latch — further
    /// transitions on the same assignment are silently discarded by
    /// the kata-core ledger.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed { .. }
                | Self::Failed { .. }
                | Self::Cancelled { .. }
                | Self::Orphaned { .. }
        )
    }

    /// True if this attempt ended because an OPERATOR asked it to stop.
    ///
    /// The typed answer, never a `reason.starts_with("cancelled:")` prose
    /// match. Spelled here rather than
    /// `matches!`-ed at the call site so the execution-terminalization reader and
    /// any future one cannot drift into two definitions of "was cancelled".
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }

    /// Does a transition INTO this status belong to the WORKER-POOL LIFECYCLE
    /// census — the entry (`dispatched`) and the terminals that answer it?
    ///
    /// # This is an EXHAUSTIVENESS MECHANISM
    ///
    /// A new variant is missed by every consumer that reads this enum through a
    /// construct that is TOTAL BY DEFAULT rather than by checking — a `matches!`
    /// list, an `== Failed`, a `_ => {}` arm, or a string set in JavaScript —
    /// and the compiler catches none of them. Every reader that uses an
    /// exhaustive `match` is widened by the compiler, without anyone having to
    /// remember it (`kata_api::executor::record::aggregate_status` is the
    /// reference case).
    ///
    /// So the mechanism is not a new abstraction, it is the DELETION of the
    /// wildcard: a reader that must be total over `AssignmentStatus` spells
    /// every variant, and a `matches!` gate that cannot be checked moves here,
    /// where one exhaustive `match` answers for it. `kata_worker_assignments_total`'s
    /// emit gate is that gate.
    #[must_use]
    pub fn counts_in_the_worker_lifecycle_census(&self) -> bool {
        match self {
            // The ENTRY of the worker lifecycle — a single assignment that
            // re-dispatches legitimately emits one `dispatched` per distinct
            // dispatch, which is the intended "dispatched to a worker" semantic —
            // followed by its TERMINAL OUTCOMES, exactly `Self::is_terminal`'s
            // set. The terminals are spelled out rather than delegated to that
            // predicate so a future terminal has to be classified HERE too
            // instead of arriving silently through a widened `is_terminal`, which
            // would silently drop a terminal's ops line from `run_timing_logger`.
            //
            // One arm rather than two, because `clippy::match_same_arms` is right
            // that two arms with one body is a distinction the compiler cannot
            // keep: the entry and the terminals differ in what they MEAN, not in
            // what this answers.
            Self::Dispatched { .. }
            | Self::Completed { .. }
            | Self::Failed { .. }
            | Self::Cancelled { .. }
            | Self::Orphaned { .. } => true,
            // Everything else is an intermediate state of an assignment already
            // counted at `Dispatched`, or a state it never reached a worker in.
            // Counting any of them would double-count the entry.
            Self::Pending
            | Self::AwaitingApproval { .. }
            | Self::AwaitingChildCompletion { .. }
            | Self::Running { .. }
            | Self::Stalled { .. } => false,
        }
    }

    /// The current worker id this assignment is (or was most recently)
    /// on. `None` only for `Pending` and for `Failed`/`Orphaned`
    /// assignments that never reached a worker.
    #[must_use]
    pub fn worker_id(&self) -> Option<&SmolStr> {
        match self {
            Self::Dispatched { worker_id }
            | Self::Running { worker_id }
            | Self::Stalled { worker_id, .. } => Some(worker_id),
            Self::Completed { worker_id }
            | Self::AwaitingApproval { worker_id, .. }
            | Self::Failed { worker_id, .. }
            | Self::Cancelled { worker_id, .. } => worker_id.as_ref(),
            Self::Orphaned { prev_worker, .. } => prev_worker.as_ref(),
            // A parent parked awaiting a child holds no worker (it was freed so
            // the child can run — the single-worker no-deadlock invariant).
            Self::AwaitingChildCompletion { .. } | Self::Pending => None,
        }
    }

    /// Short human-readable tag for logs and audits. Stable; do not
    /// change these strings without bumping the schema version — they
    /// appear in durable state dumps.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::AwaitingApproval { .. } => "awaiting_approval",
            Self::Dispatched { .. } => "dispatched",
            Self::Running { .. } => "running",
            Self::Completed { .. } => "completed",
            Self::Failed { .. } => "failed",
            // The line that gives `AttemptLifecycle::Cancelled` its production
            // writer; the wire-status agreement cell derives the writer set from
            // this function's arms.
            Self::Cancelled { .. } => "cancelled",
            Self::Orphaned { .. } => "orphaned",
            Self::Stalled { .. } => "stalled",
            Self::AwaitingChildCompletion { .. } => "awaiting_child_completion",
        }
    }
}

/// Event delivered on every accepted ledger transition. SSE consumers
/// at `GET /api/v1/events` see these as the payload of
/// `event: ledger` frames.
///
/// The event carries just enough context to drive a reactor or
/// progress-streaming API without forcing the consumer to round-trip
/// through `InFlightLedger::get` for every message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerEvent {
    /// Execution id this event belongs to. Serializes as a string.
    pub execution_id: Ulid,
    /// Assignment id whose status changed. Serializes as a string.
    pub assignment_id: Ulid,
    /// Stage name from the workflow definition.
    pub stage_name: SmolStr,
    /// New status the assignment transitioned to.
    pub new_status: AssignmentStatus,
    /// Stage output captured when the status reaches `Completed`.
    pub output: Option<serde_json::Value>,
    /// The charge a TERMINAL non-completion made: the stage's own
    /// `token_usage` (or the authoritative `0` of a call that never billed)
    /// and the `child_invocation_summary` of a child execution it invoked,
    /// in the same shape a completion carries under `output`. `None` on a
    /// record without it — read as absent, never failed closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_charge: Option<crate::metering::TerminalCharge>,
}

/// Current schema version of the durable ledger-log envelope
/// ([`LedgerLogEvent::V1`]).
pub const LEDGER_LOG_EVENT_SCHEMA_V1: u64 = 1;

/// Schema-v1 body of a durable ledger-log event.
///
/// Field-for-field the persisted twin of [`LedgerEvent`]: it captures every
/// transition currently expressed by the flat SSE/SDK wire type (execution
/// id, assignment id, stage name, new status, completion output, and the
/// terminal charge). It is a DISTINCT type from
/// [`LedgerEvent`] on purpose — [`LedgerEvent`] is the live wire shape that
/// existing SSE/SDK consumers depend on and must stay byte-stable, whereas
/// `LedgerEventV1` is the versioned durable-log encoding that can evolve
/// under the [`LedgerLogEvent`] envelope's schema discriminant.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LedgerEventV1 {
    /// Execution id this event belongs to. Serializes as a string.
    pub execution_id: Ulid,
    /// Assignment id whose status changed. Serializes as a string.
    pub assignment_id: Ulid,
    /// Stage name from the workflow definition.
    pub stage_name: SmolStr,
    /// New status the assignment transitioned to.
    pub new_status: AssignmentStatus,
    /// Stage output captured when the status reaches `Completed`. An omitted key
    /// is no output; a present JSON null is a completed null value.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_durable_output"
    )]
    pub output: Option<serde_json::Value>,
    /// The execution's ORIGINAL wall-clock start (ms), stamped on first
    /// dispatch and carried forward on every transition of this assignment.
    /// `None` on a frame that does not carry it. Deliberately
    /// ABSENT from the flat SSE [`LedgerEvent`]: it is a durable-replay-only
    /// field, so the live wire shape stays byte-stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<u64>,
    /// The assignment's most-recent worker checkpoint sequence — the durable
    /// `attempts.last_checkpoint` safe point that
    /// `Dispatcher::record_checkpoint_and_fold_attempt` advances. Lets a resumed
    /// replay fold resume a stage that crashed mid-execution from its last safe
    /// point rather than re-run it. `None` on a frame that does not carry it, so
    /// a fold that never sees it re-runs the stage.
    /// Deliberately ABSENT from the flat SSE [`LedgerEvent`]: like
    /// `started_at_ms`, it is a durable-replay-only field, so the live wire
    /// shape stays byte-stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checkpoint: Option<u64>,
    /// The charge a TERMINAL non-completion made: the stage's own
    /// `token_usage` and the `child_invocation_summary` of a child execution
    /// it invoked, so a failed, cancelled or orphaned stage is charged what
    /// its billable work provably spent. Additive under the envelope — a
    /// record without it decodes to `None`, which the fold reads as "nothing
    /// charged" rather than failing closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_charge: Option<crate::metering::TerminalCharge>,
}

fn present_durable_output<'de, D>(decoder: D) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde_json::Value::deserialize(decoder).map(Some)
}

/// Versioned, append-only envelope persisted as the `ledger_events.db` payload
/// for one accepted ledger transition.
///
/// Wire shape is an object carrying an explicit `schema_version` discriminant
/// plus a nested `event` body, e.g.
/// `{"schema_version":1,"event":{ ...LedgerEventV1... }}`.
///
/// **Forward compatibility is load-bearing.** A newer kata may write an
/// envelope at a schema version an older reader does not understand. Rather
/// than erroring (which would strand or corrupt an older reader on a newer
/// log), an unrecognized version deserializes into [`LedgerLogEvent::Unknown`],
/// which preserves the raw JSON verbatim so no data is lost and the reader can
/// skip the frame gracefully. Re-serializing an `Unknown` reproduces the
/// original bytes.
#[derive(Clone, Debug, PartialEq)]
pub enum LedgerLogEvent {
    /// Schema-v1 payload — the currently-emitted encoding. Boxed so the
    /// envelope stays small (the rare `Unknown` variant would otherwise force
    /// every value to the size of a full `LedgerEventV1`). Serde-transparent:
    /// `Box<T>` (de)serializes exactly as `T`, so the wire format is unchanged.
    V1(Box<LedgerEventV1>),
    /// Forward-compat catch-all for a `schema_version` this build does not
    /// understand. Carries the parsed version and the full raw object so an
    /// older reader neither errors nor loses data.
    Unknown {
        /// The unrecognized `schema_version` value read off the wire.
        schema_version: u64,
        /// The complete original JSON object, preserved verbatim so
        /// re-serialization is lossless.
        raw: serde_json::Value,
    },
}

impl LedgerLogEvent {
    /// The `schema_version` discriminant this envelope carries.
    #[must_use]
    pub fn schema_version(&self) -> u64 {
        match self {
            Self::V1(_) => LEDGER_LOG_EVENT_SCHEMA_V1,
            Self::Unknown { schema_version, .. } => *schema_version,
        }
    }

    /// Recover the flat [`LedgerEvent`] wire shape from a known envelope.
    ///
    /// Returns `None` for [`LedgerLogEvent::Unknown`] — a future schema this
    /// build cannot interpret cannot be projected onto the current wire type.
    #[must_use]
    pub fn as_ledger_event(&self) -> Option<LedgerEvent> {
        match self {
            Self::V1(v1) => Some(LedgerEvent::from(v1.as_ref())),
            Self::Unknown { .. } => None,
        }
    }
}

impl From<&LedgerEvent> for LedgerEventV1 {
    fn from(e: &LedgerEvent) -> Self {
        Self {
            execution_id: e.execution_id,
            assignment_id: e.assignment_id,
            stage_name: e.stage_name.clone(),
            new_status: e.new_status.clone(),
            output: e.output.clone(),
            // The flat SSE type carries no start anchor; the ledger stamps it
            // separately. Default to `None` here
            // so callers that only have the flat event round-trip losslessly.
            started_at_ms: None,
            // Likewise the flat type carries no checkpoint sequence; the ledger
            // stamps it on the dedicated checkpoint frame. Default
            // `None` so a flat-event round-trip is lossless.
            last_checkpoint: None,
            terminal_charge: e.terminal_charge.clone(),
        }
    }
}

impl From<&LedgerEventV1> for LedgerEvent {
    fn from(v1: &LedgerEventV1) -> Self {
        // NOTE: `v1.started_at_ms` and `v1.last_checkpoint` are intentionally
        // dropped — the flat SSE wire type has no such fields and must stay
        // byte-stable. Lossless for the SSE path (which never carried either).
        Self {
            execution_id: v1.execution_id,
            assignment_id: v1.assignment_id,
            stage_name: v1.stage_name.clone(),
            new_status: v1.new_status.clone(),
            output: v1.output.clone(),
            terminal_charge: v1.terminal_charge.clone(),
        }
    }
}

impl From<&LedgerEvent> for LedgerLogEvent {
    fn from(e: &LedgerEvent) -> Self {
        Self::V1(Box::new(LedgerEventV1::from(e)))
    }
}

impl Serialize for LedgerLogEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        match self {
            Self::V1(v1) => {
                let mut st = serializer.serialize_struct("LedgerLogEvent", 2)?;
                st.serialize_field("schema_version", &LEDGER_LOG_EVENT_SCHEMA_V1)?;
                st.serialize_field("event", v1)?;
                st.end()
            }
            // The raw object already carries its own `schema_version` +
            // `event`; re-emit it verbatim so the round-trip is lossless.
            Self::Unknown { raw, .. } => raw.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for LedgerLogEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        let value = serde_json::Value::deserialize(deserializer)?;
        let schema_version = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| D::Error::custom("ledger log event missing integer `schema_version`"))?;
        if schema_version == LEDGER_LOG_EVENT_SCHEMA_V1 {
            let event = value.get("event").ok_or_else(|| {
                D::Error::custom("schema_version 1 ledger log event missing `event`")
            })?;
            let v1 = LedgerEventV1::deserialize(event).map_err(D::Error::custom)?;
            Ok(Self::V1(Box::new(v1)))
        } else {
            // Forward-compat: an unrecognized version is preserved verbatim
            // rather than rejected, so an older reader survives a newer log.
            Ok(Self::Unknown {
                schema_version,
                raw: value,
            })
        }
    }
}

/// Mid-stage informational progress frame surfaced by the worker while a
/// capsule runs (`WorkerMessage::CapsuleProgress`).
///
/// Distinct from [`LedgerEvent`] because this is **not** an
/// `AssignmentStatus` mutation — the assignment stays in
/// `Running { worker_id }` for its full lifetime. `ProgressEvent`s
/// are best-effort informational signal that operators / dashboards
/// opt into; subscribers that don't care simply ignore the
/// `event: progress` SSE frames.
///
/// The frame carries ONE observation's `preview` (not the accumulated
/// content), and the stream is lossy by design: the worker's rate window
/// coalesces a streamed observation (a text delta, an output line) into the
/// latest of its kind, so concatenating previews does not reassemble the
/// stage's text. A lifecycle observation (a model call's start or end, a tool
/// call) is never coalesced. Privacy shaping happens **at emission time** on
/// the worker — a stage configured with `progress_visibility = "summary"`
/// ships only the kind and a short head of its text;
/// `progress_visibility = "off"` suppresses the frame entirely so sensitive
/// reasoning never leaves the worker. `kata_worker::capsule_progress` holds
/// the shaping and the bounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressEvent {
    /// Execution id this progress frame belongs to. Stringifies as
    /// the canonical 26-char ULID.
    pub execution_id: Ulid,
    /// Assignment id of the running stage emitting progress.
    pub assignment_id: Ulid,
    /// Stage name from the workflow definition.
    pub stage_name: SmolStr,
    /// Cumulative bytes of content the worker OBSERVED for this
    /// assignment up to and including this frame's observation —
    /// coalesced observations count, so the offset can jump between
    /// frames. Non-decreasing across frames; consumers can drop
    /// out-of-order frames by comparing offsets.
    pub byte_offset: u64,
    /// The observation this frame carries: `<kind>` or `<kind>: <text>`,
    /// cut on a UTF-8 boundary to the stage's visibility bound (the whole
    /// preview at most 80 bytes under `summary`, 4 KiB under `full`) — or,
    /// on an attempt's last frame when its bounds refused anything, the
    /// worker's own `dropped: <n> …` accounting. Not a delta of the
    /// stage's text: see the type's note on coalescing.
    pub preview: String,
    /// Observations the emitting attempt's progress bounds dropped,
    /// cumulative since the attempt began — the rate window's
    /// coalescing is not a drop; a queue-full refusal or a spent
    /// byte budget is. Carried from `WorkerMessage::CapsuleProgress`, the
    /// only progress wire — the count is meaningful on every frame that
    /// produces one.
    #[serde(default)]
    pub dropped: u64,
    /// Wall-clock millis since the unix epoch the worker emitted the
    /// frame. Useful for end-to-end latency dashboards.
    pub at_ms: u64,
}

#[cfg(test)]
mod ledger_log_event_tests {
    use super::*;

    const EXEC: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const ASSIGN: &str = "01BX5ZZKBKACTAV9WEVGEMMVRZ";

    fn ulid(s: &str) -> Ulid {
        Ulid::from_string(s).expect("valid ulid")
    }

    fn base_event(status: AssignmentStatus) -> LedgerEvent {
        LedgerEvent {
            execution_id: ulid(EXEC),
            assignment_id: ulid(ASSIGN),
            stage_name: SmolStr::new("build"),
            new_status: status,
            output: None,
            terminal_charge: None,
        }
    }

    /// Every `AssignmentStatus` variant, so the round-trip test below covers
    /// the full transition vocabulary `LedgerEventV1` must encode.
    fn all_statuses() -> Vec<AssignmentStatus> {
        vec![
            AssignmentStatus::Pending,
            AssignmentStatus::AwaitingApproval {
                worker_id: Some(SmolStr::new("w1")),
                reason: "gate".into(),
            },
            AssignmentStatus::AwaitingChildCompletion {
                child_execution_id: ulid(EXEC),
                reason: "child pack".into(),
            },
            AssignmentStatus::Dispatched {
                worker_id: SmolStr::new("w2"),
            },
            AssignmentStatus::Running {
                worker_id: SmolStr::new("w2"),
            },
            AssignmentStatus::Completed {
                worker_id: Some(SmolStr::new("w2")),
            },
            AssignmentStatus::Failed {
                worker_id: Some(SmolStr::new("w2")),
                reason: "boom".into(),
            },
            AssignmentStatus::Cancelled {
                worker_id: Some(SmolStr::new("w2")),
                reason: "operator asked for a stop".into(),
            },
            AssignmentStatus::Orphaned {
                prev_worker: Some(SmolStr::new("w2")),
                reason: "dead".into(),
            },
            AssignmentStatus::Stalled {
                worker_id: SmolStr::new("w2"),
                last_heartbeat_at_ms: 1000,
                stalled_for_secs: 7,
            },
        ]
    }

    #[test]
    fn v1_round_trips_every_status_variant() {
        for status in all_statuses() {
            let tag = status.tag();
            let event = base_event(status);
            let envelope = LedgerLogEvent::from(&event);
            let json =
                serde_json::to_string(&envelope).unwrap_or_else(|e| panic!("serialize {tag}: {e}"));
            let back: LedgerLogEvent =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialize {tag}: {e}"));
            assert_eq!(envelope, back, "round-trip mismatch for status {tag}");
            assert_eq!(back.schema_version(), LEDGER_LOG_EVENT_SCHEMA_V1);
            // The bridge back to the flat wire type is lossless for V1.
            let recovered = back.as_ledger_event().expect("V1 recovers LedgerEvent");
            assert_eq!(recovered.new_status.tag(), tag);
            assert_eq!(recovered.execution_id, ulid(EXEC));
            assert_eq!(recovered.assignment_id, ulid(ASSIGN));
        }
    }

    #[test]
    fn v1_round_trips_with_output() {
        let mut event = base_event(AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w2")),
        });
        event.output = Some(serde_json::json!({"result": "ok", "n": 3}));
        let envelope = LedgerLogEvent::from(&event);
        let json = serde_json::to_string(&envelope).expect("serialize");
        let back: LedgerLogEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(envelope, back);
        let recovered = back.as_ledger_event().expect("recover");
        assert_eq!(recovered.output, event.output);
    }

    /// Forward-compat contract: an envelope written at a schema version this
    /// build does not understand must deserialize into `Unknown` (preserving
    /// the raw bytes) instead of erroring. Without the `Unknown` fallback in
    /// `Deserialize`, this call errors and the test fails — that is the
    /// non-vacuous proof.
    #[test]
    fn unknown_schema_version_deserializes_to_catch_all_without_data_loss() {
        let future = serde_json::json!({
            "schema_version": 999,
            "event": {"brand_new_field": "hello", "nested": {"x": 1}},
            "extra_top_level": true
        });
        let raw_str = serde_json::to_string(&future).unwrap();

        let decoded: LedgerLogEvent =
            serde_json::from_str(&raw_str).expect("unknown version must NOT error");

        match &decoded {
            LedgerLogEvent::Unknown {
                schema_version,
                raw,
            } => {
                assert_eq!(*schema_version, 999);
                // No data loss: the full original object is preserved verbatim.
                assert_eq!(*raw, future);
            }
            LedgerLogEvent::V1(_) => panic!("future version misdecoded as V1"),
        }
        assert_eq!(decoded.schema_version(), 999);
        // A future version cannot be projected onto the current wire type.
        assert!(decoded.as_ledger_event().is_none());

        // Re-serialization of an Unknown reproduces the original bytes exactly.
        let reser = serde_json::to_value(&decoded).unwrap();
        assert_eq!(reser, future);
    }

    #[test]
    fn missing_schema_version_is_an_error() {
        let bad = serde_json::json!({"event": {}});
        let res: Result<LedgerLogEvent, _> = serde_json::from_value(bad);
        assert!(res.is_err(), "missing schema_version must be rejected");
    }

    /// The `started_at_ms` time-bound anchor rides the versioned
    /// durable envelope losslessly, and is DROPPED by the bridge back to the
    /// flat SSE wire type (which has no such field). Non-vacuous: `Some(x)` in
    /// ⟹ `Some(x)` out of the envelope, and the flat projection carries no
    /// anchor at all — so the live wire shape stays byte-stable.
    #[test]
    fn v1_carries_started_at_ms_through_the_envelope_round_trip() {
        let v1 = LedgerEventV1 {
            execution_id: ulid(EXEC),
            assignment_id: ulid(ASSIGN),
            stage_name: SmolStr::new("build"),
            new_status: AssignmentStatus::Running {
                worker_id: SmolStr::new("w2"),
            },
            output: None,
            started_at_ms: Some(1_700_000_000_123),
            last_checkpoint: None,
            terminal_charge: None,
        };
        let envelope = LedgerLogEvent::V1(Box::new(v1.clone()));
        let json = serde_json::to_string(&envelope).expect("serialize");
        // The anchor is present on the durable envelope...
        assert!(
            json.contains("\"started_at_ms\":1700000000123"),
            "durable envelope must carry the anchor: {json}"
        );
        let back: LedgerLogEvent = serde_json::from_str(&json).expect("deserialize");
        match &back {
            LedgerLogEvent::V1(b) => {
                assert_eq!(
                    b.started_at_ms,
                    Some(1_700_000_000_123),
                    "anchor survives the envelope round-trip"
                );
            }
            LedgerLogEvent::Unknown { .. } => panic!("V1 misdecoded as Unknown"),
        }
        // ...but the flat SSE projection intentionally has no anchor field:
        // the live wire shape is unchanged (LedgerEvent has no `started_at_ms`).
        let flat = back.as_ledger_event().expect("V1 recovers LedgerEvent");
        let flat_json = serde_json::to_string(&flat).expect("serialize flat");
        assert!(
            !flat_json.contains("started_at_ms"),
            "flat SSE LedgerEvent must NOT carry the anchor (byte-stable wire): {flat_json}"
        );
    }

    /// A schema-v1 durable frame whose `event` object has no `started_at_ms`
    /// key must decode — the anchor defaults to `None`, never an error. Without
    /// `#[serde(default)]` this call would fail.
    #[test]
    fn frame_without_started_at_ms_decodes_to_none() {
        let old_format = serde_json::json!({
            "schema_version": 1,
            "event": {
                "execution_id": EXEC,
                "assignment_id": ASSIGN,
                "stage_name": "build",
                "new_status": {"kind": "running", "worker_id": "w2"}
            }
        });
        let decoded: LedgerLogEvent =
            serde_json::from_value(old_format).expect("a frame without the anchor must decode");
        match &decoded {
            LedgerLogEvent::V1(v1) => {
                assert_eq!(
                    v1.started_at_ms, None,
                    "an absent anchor decodes to None (forward-compat)"
                );
            }
            LedgerLogEvent::Unknown { .. } => panic!("schema v1 must decode as V1"),
        }
        // And it still projects onto the flat wire type — the run keeps going.
        assert!(decoded.as_ledger_event().is_some());
    }

    /// Golden wire-encoding snapshot: pins the exact durable JSON so an
    /// accidental format change (field rename/reorder, tag drift) is caught.
    #[test]
    fn golden_wire_encoding_snapshot() {
        let event = base_event(AssignmentStatus::Running {
            worker_id: SmolStr::new("worker-7"),
        });
        let envelope = LedgerLogEvent::from(&event);
        let json = serde_json::to_string(&envelope).expect("serialize");
        assert_eq!(
            json,
            r#"{"schema_version":1,"event":{"execution_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","assignment_id":"01BX5ZZKBKACTAV9WEVGEMMVRZ","stage_name":"build","new_status":{"kind":"running","worker_id":"worker-7"}}}"#
        );
    }

    #[test]
    fn durable_output_distinguishes_missing_from_explicit_null() {
        for output in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!({"result": 7})),
        ] {
            let mut event = base_event(AssignmentStatus::Completed {
                worker_id: Some(SmolStr::new("worker-7")),
            });
            event.output = output.clone();
            let envelope = LedgerLogEvent::from(&event);
            let encoded = serde_json::to_value(&envelope).unwrap();
            assert_eq!(encoded["event"].get("output").cloned(), output);
            let decoded: LedgerLogEvent = serde_json::from_value(encoded.clone()).unwrap();
            let LedgerLogEvent::V1(body) = &decoded else {
                panic!("current envelope");
            };
            assert_eq!(body.output, output);
            assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
        }
    }
}
