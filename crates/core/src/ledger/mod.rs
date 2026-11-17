//! The in-RAM event broadcast and delivery-projection plane.
//!
//! This file holds no worker-assignment rows: an attempt's authority is the operational
//! chain (`attempts`, `transitions`, `occurrences` in `operational.db`), and a stage's
//! lifecycle is read from it, never from a per-assignment mirror kept here.
//!
//! What remains is process-local and observational by construction: the
//! `events`/`seq_events` broadcasts that [`InFlightLedger::commit_delivery_batch`] fills
//! from the workflow-owned global producer's immutable frames, the progress
//! channel capsule settlement publishes into, and the execution-evidence
//! routing that writes to `operational.db` when a plane is bound.

use std::path::Path;
use std::sync::Arc;

use dashmap::DashMap;
use kata_types::error::{KataError, KataResult};
use kata_types::execution::ExecutionEvidence;
#[cfg(any(test, feature = "test-support"))]
use parking_lot::Mutex;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info};
use ulid::Ulid;

use crate::durable_event_log::DurableEventLog;
use crate::operational::delivery::DeliveryProjector;
use kata_types::time::now_ms;

// `AssignmentStatus`, `LedgerEvent` and the invocation/expansion vocabulary are
// the wire-stable data shapes consumed over the SSE feed and shared with the
// kata-client SDK; they live in `kata_types::ledger` so both crates share one
// canonical definition. Re-exporting preserves every existing
// `kata_core::AssignmentStatus` / `kata_core::LedgerEvent` import path.
pub use kata_types::ledger::{
    AgentInvocationGraph, AgentInvocationGraphNode, AgentInvocationKind, AgentInvocationRecord,
    AgentInvocationStatus, AssignmentStatus, LedgerEvent, LedgerLogEvent, ProgressEvent,
};

mod invocation;
mod replay;

pub use invocation::{agent_invocation_graph_from_records, invocation_status_for};

/// The reliable ledger-event stream `subscribe_ledger_reliable` hands the
/// SSE/replay drive: `(monotonic_seq, event)` pairs so a subscriber dedupes
/// frames that appear in both the log replay and the live tail.
pub type ReliableLedgerStream = ReceiverStream<(u64, Arc<LedgerEvent>)>;

pub use crate::operational::{ExecutionEvidenceClaimOutcome, ExecutionEvidenceRecord};

/// A test-armed evidence-append fault: `Ok(())` to let the append proceed, `Err` to fail
/// it exactly as the durable plane would.
///
/// The `Option<&str>` is the CLAIM KEY, so one hook can distinguish the claimed door from
/// the unclaimed one — which the callers under test treat differently (a claimed append
/// short-circuits on `AlreadyClaimed`, an unclaimed one always writes).
#[cfg(any(test, feature = "test-support"))]
pub type EvidenceFault =
    Arc<dyn Fn(Option<&str>, &ExecutionEvidenceRecord) -> KataResult<()> + Send + Sync>;

/// Capacity of the broadcast channel that publishes ledger events.
///
/// Broadcast channels buffer the last N events; a subscriber that
/// lags by more than N receives `RecvError::Lagged(n)` and must skip
/// to the current tail. 1024 is enough headroom for a few concurrent
/// runs on a single-node deployment without wasting memory.
const EVENT_BUFFER: usize = 1024;

/// Capacity of the broadcast channel that publishes
/// informational `ProgressEvent`s. Sized larger than the ledger
/// channel because progress frames can arrive at chunk-rate from
/// multiple concurrent stages, while the ledger channel only fires
/// on real status transitions.
const PROGRESS_EVENT_BUFFER: usize = 4096;

/// The in-RAM broadcast + delivery + evidence-routing surface.
///
/// Every field here is process-local or read-projection: nothing on it is an
/// authority. The durable facts a stage's lifecycle reads — attempt, chain
/// transition, occurrence — live on `operational.db`.
#[derive(Clone)]
pub struct InFlightLedger {
    /// Execution-level metadata rows, keyed by evidence record id.
    ///
    /// A READ PROJECTION of `execution_evidence` on the operational plane, seeded by
    /// [`Self::bind_operational`] and appended to by the two evidence verbs. It is not
    /// an authority: `execution_evidence_records` serves per-execution reads off it,
    /// and the durable answer is always the table.
    evidence_rows: Arc<DashMap<Ulid, ExecutionEvidenceRecord>>,
    /// The OPERATIONAL plane, when this ledger has one — the durable home of
    /// execution-level evidence.
    ///
    /// `None` is the SCRATCH posture: evidence lives in `evidence_rows` for this
    /// process and nowhere else. An in-memory node has no durable plane to write to,
    /// and inventing one would be a second authority.
    operational: Arc<std::sync::OnceLock<Arc<crate::operational::OperationalDb>>>,
    /// The `(execution_id, claim_key)` set an UNBOUND ledger dedupes evidence claims
    /// against — the in-RAM twin of `execution_evidence_claims`, kept where the routing
    /// decision is made. Never consulted when a plane is bound: the table is the boundary
    /// then, and a second in-RAM copy of it would be a second answer.
    scratch_evidence_claims: Arc<DashMap<(Ulid, String), ()>>,
    /// FAULT-INJECTION seam for the two evidence verbs — see [`EvidenceFault`].
    ///
    /// Compiled only under `test-support`; the only setter is
    /// [`Self::arm_evidence_fault`].
    #[cfg(any(test, feature = "test-support"))]
    evidence_fault: Arc<Mutex<Option<EvidenceFault>>>,
    /// Broadcast sender for ledger events. Subscribers clone an
    /// `Arc<InFlightLedger>` and call `subscribe()`.
    events: broadcast::Sender<LedgerEvent>,
    /// Sequenced broadcast for [`Self::subscribe_ledger_reliable`]. Carries
    /// `(monotonic_seq, LedgerEvent)` so the reliable relay task can
    /// deduplicate events that appear in both the log replay phase and
    /// the live broadcast tail.
    seq_events: broadcast::Sender<(u64, LedgerEvent)>,
    /// Durable delivery log populated only by `commit_delivery_batch`, used for
    /// reliable replay and quiet catchup after a missed notification.
    event_log: Arc<DurableEventLog>,
    /// Fault-injection hook: fires after the delivery batch commits and before
    /// either broadcast send. Panicking inside exercises the durable-write-
    /// before-broadcast invariant in tests. Compiled only under `test-support`.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    pub after_append_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Broadcast sender for informational progress frames.
    /// Distinct from `events` because progress is high-rate and
    /// should not poison the ledger lag-detection signal — a
    /// dashboard that falls behind on chunks should refetch state
    /// for `LedgerEvent`s but is welcome to drop progress frames
    /// silently. Subscribers call [`InFlightLedger::subscribe_progress`].
    progress: broadcast::Sender<ProgressEvent>,
    /// The sole delivery allocator/projector. The workflow-owned global producer
    /// supplies immutable frames; no mirror mutation appends to this store.
    delivery: Arc<DeliveryProjector>,
}

impl InFlightLedger {
    /// An in-RAM ledger — the scratch posture. The cheapest option; always
    /// succeeds. Used by tests and by harnesses that run without a durable
    /// event log.
    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn in_memory() -> Arc<Self> {
        Self::in_memory_with_capacity(EVENT_BUFFER)
    }

    /// An in-RAM ledger with a specific broadcast channel capacity for both
    /// `events` and `seq_events`. Used by tests that need to provoke `Lagged`
    /// errors to exercise lag-recovery paths.
    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn in_memory_with_capacity(capacity: usize) -> Arc<Self> {
        let (events, _rx) = broadcast::channel(capacity);
        let (seq_events, _srx) = broadcast::channel(capacity);
        let event_log = Arc::new(
            DurableEventLog::open_in_memory().expect("in-memory DurableEventLog is infallible"),
        );
        let event_log_for_delivery = Arc::clone(&event_log);
        let (progress, _prx) = broadcast::channel(PROGRESS_EVENT_BUFFER);
        Arc::new(Self {
            evidence_rows: Arc::new(DashMap::new()),
            operational: Arc::new(std::sync::OnceLock::new()),
            scratch_evidence_claims: Arc::new(DashMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            evidence_fault: Arc::new(Mutex::new(None)),
            events,
            seq_events,
            event_log,
            #[cfg(any(test, feature = "test-support"))]
            after_append_hook: None,
            progress,
            delivery: Arc::new(
                DeliveryProjector::open(event_log_for_delivery)
                    .expect("in-memory DeliveryProjector is infallible"),
            ),
        })
    }

    /// An in-RAM ledger with an after-append hook.
    ///
    /// The hook fires inside `commit_delivery_batch` after the durable write and before
    /// either broadcast send. Panicking inside simulates a crash between persist
    /// and broadcast for fault-injection tests. Never called by production code.
    #[doc(hidden)]
    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn in_memory_with_hook(hook: Arc<dyn Fn() + Send + Sync>) -> Arc<Self> {
        let mut ledger = Self::in_memory();
        Arc::get_mut(&mut ledger)
            .expect("a fresh ledger is uniquely owned")
            .after_append_hook = Some(hook);
        ledger
    }

    /// Flush the derived delivery plane's event log — the `ledger_events.db`
    /// WAL checkpoint the shutdown journal records.
    ///
    /// # Errors
    ///
    /// The log's own.
    pub fn checkpoint(&self) -> KataResult<()> {
        self.event_log.checkpoint()
    }

    /// Open the ledger over `events_path` — the durable event log on disk.
    /// The delivery projector opens over the same log and validates its
    /// retained cursor before any replay drive reads it.
    ///
    /// # Errors
    ///
    /// The event-log open's and the delivery projector's.
    pub fn open_at(events_path: &Path) -> KataResult<Arc<Self>> {
        let (events, _rx) = broadcast::channel(EVENT_BUFFER);
        let (seq_events, _srx) = broadcast::channel(EVENT_BUFFER);
        let event_log = Arc::new(DurableEventLog::open(events_path)?);
        let delivery = Arc::new(DeliveryProjector::open(Arc::clone(&event_log))?);
        let (progress, _prx) = broadcast::channel(PROGRESS_EVENT_BUFFER);
        info!(event_seq_seed = delivery.reserved_head(), "ledger opened");
        Ok(Arc::new(Self {
            evidence_rows: Arc::new(DashMap::new()),
            operational: Arc::new(std::sync::OnceLock::new()),
            scratch_evidence_claims: Arc::new(DashMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            evidence_fault: Arc::new(Mutex::new(None)),
            events,
            seq_events,
            event_log,
            #[cfg(any(test, feature = "test-support"))]
            after_append_hook: None,
            progress,
            delivery,
        }))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LedgerEvent> {
        self.events.subscribe()
    }

    pub fn subscribe_progress(&self) -> broadcast::Receiver<ProgressEvent> {
        self.progress.subscribe()
    }

    pub fn emit_progress(&self, event: ProgressEvent) {
        // Byte-level visibility into mid-stage progress.
        // One counter labeled per stage_name. The execution_id is
        // intentionally NOT a label dimension — Prometheus would
        // explode with one series per execution. Operators correlate
        // execution_id from logs/SSE if they need finer attribution.
        // The increment uses `byte_offset` deltas conservatively:
        // the worker emits monotonically-increasing offsets, so the
        // increment for *this* frame is the new content's bytes —
        // i.e. `preview.len()` in `Full` mode and the raw chunk
        // bytes the worker counted in `Summary` mode (which is
        // greater than or equal to the truncated `preview.len()`).
        //
        // We pass the chunk-bytes count via the WorkerMessage path,
        // not via `preview.len()` here, so the metric matches the
        // real backend stream regardless of preview shaping. The
        // reactor passes that delta as `byte_offset - prev_offset`;
        // we cannot reconstruct it lock-free in `emit_progress`
        // without a per-assignment cursor, so the counter is updated
        // by the reactor instead. Keep this comment as a contract
        // pointer.
        let _ = self.progress.send(event);
    }
}
