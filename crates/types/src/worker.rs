//! Worker inventory wire types.
//!
//! These types describe the read-only worker list surfaced by
//! `GET /api/v1/workers` and re-exported by the SDK. The inventory is a
//! live supervisor snapshot only; configured-but-disconnected topology
//! workers and credential lifecycle data are intentionally not represented.

use serde::{Deserialize, Serialize};

/// The id prefix the main assigns to every worker that completes the
/// local-socket handshake — `local-worker-{seq}`.
///
/// ONE AUTHORITY, because hand-spelled copies drift invisibly. A smoke that
/// polls for a worker attribution with a hand-spelled prefix that disagrees
/// with the emitter fails with `execution … never pinned to a worker; last
/// worker_id="local-worker-0"` — a message that denies the attribution while
/// printing it.
///
/// A `starts_with(LOCAL_WORKER_ID_PREFIX)` cannot drift from the emitter the
/// way a literal can: rename the scheme and the compiler carries every reader
/// with it.
pub const LOCAL_WORKER_ID_PREFIX: &str = "local-worker-";

/// Stable read-only snapshot of one registered worker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerSnapshot {
    /// Worker id as registered with the main supervisor.
    pub id: String,
    /// Lowercase transport kind: `local_socket` for every production worker
    /// (the supervised node and external daemons alike); the transport crate's
    /// test double reports `in_process`.
    pub transport: String,
    /// Sorted worker capability labels.
    pub capabilities: Vec<String>,
    /// Whether the underlying transport currently reports healthy.
    pub alive: bool,
    /// Number of assignments currently attributed to this worker.
    pub active_assignment_count: u32,
}

/// Ordered worker inventory response.
pub type WorkerInventory = Vec<WorkerSnapshot>;
