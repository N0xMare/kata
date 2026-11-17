//! Subsystem health wire types — body of `GET /api/v1/health`.
//!
//! Pure data: no DashMap, no Arc, no I/O. The mutable `SystemHealth`
//! aggregator (which owns a DashMap and updates timestamps on
//! `report`) stays in `kata-core::health` and produces a snapshot of
//! these types when serializing.
//!
//! These types live here, not in `kata-core`, so the kata-client SDK can
//! re-export the canonical Rust definitions instead of mirroring the wire
//! JSON shape locally; the SDK re-exports `SubsystemId` / `SubsystemHealth` / `HealthSnapshot`
//! directly from this module. The aggregate `SystemHealth` struct
//! stays in `kata-core` because it carries DashMap/Arc and is not
//! meaningful on the wire.

use serde::{Deserialize, Serialize};

/// Every subsystem that reports health to the main.
///
/// The seven variants match the implemented subsystem set. Adding a
/// variant is a breaking wire change for every consumer of the health
/// snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsystemId {
    /// Agent subsystem (backends, worktrees, clients).
    Agent,
    /// Workflow orchestrator.
    Workflow,
    /// Storage engine (qmdb, journals, SQLite).
    Storage,
    /// Version control subsystem.
    Vcs,
    /// REST API surface.
    Api,
    /// Core runtime itself.
    Core,
    /// Worker pool manager.
    WorkerPool,
}

impl SubsystemId {
    /// All variants, in canonical order.
    pub const ALL: [SubsystemId; 7] = [
        SubsystemId::Agent,
        SubsystemId::Workflow,
        SubsystemId::Storage,
        SubsystemId::Vcs,
        SubsystemId::Api,
        SubsystemId::Core,
        SubsystemId::WorkerPool,
    ];
}

/// Current operational state of a subsystem. Wire shape carries the
/// `state` discriminator and a per-variant payload of `since` +
/// `reason` for the non-`Healthy` variants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SubsystemHealth {
    /// Fully operational.
    Healthy,
    /// Partially operational — some requests still served, supervision
    /// may pause dispatch of work that depends on this subsystem.
    Degraded {
        /// Unix millis when the transition occurred.
        since: u64,
        /// Human-readable reason. Surfaced via `GET /api/v1/health`.
        reason: String,
    },
    /// Not operational. Dependent subsystems should back off.
    Unavailable {
        /// Unix millis when the transition occurred.
        since: u64,
        /// Human-readable reason.
        reason: String,
    },
}

impl SubsystemHealth {
    /// Convenience constructor.
    #[must_use]
    pub fn healthy() -> Self {
        SubsystemHealth::Healthy
    }

    /// `true` if the subsystem is `Healthy`.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, SubsystemHealth::Healthy)
    }

    /// `true` if the subsystem is `Unavailable`.
    #[must_use]
    pub fn is_unavailable(&self) -> bool {
        matches!(self, SubsystemHealth::Unavailable { .. })
    }
}

/// JSON-serialisable snapshot of every subsystem's health at a single
/// point in time. Emitted by `GET /api/v1/health`. The aggregate
/// `kata-core::SystemHealth` produces one of these via its
/// `snapshot()` method.
///
/// The pair-vector field name `subsystems` is the wire-stable shape;
/// kata-core sorts the entries by `SubsystemId` so the JSON output is
/// deterministic across calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSnapshot {
    /// Unix millis of the last subsystem `report` call. `0` if no
    /// subsystem has ever reported.
    pub last_updated_millis: u64,
    /// Per-subsystem health, sorted by `SubsystemId` for deterministic
    /// JSON output.
    pub subsystems: Vec<(SubsystemId, SubsystemHealth)>,
}

impl HealthSnapshot {
    /// Returns `true` if every subsystem (or none) is `Healthy`.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.subsystems
            .iter()
            .all(|(_, h): &(SubsystemId, SubsystemHealth)| h.is_healthy())
    }

    /// Returns `true` if any subsystem is `Unavailable`.
    #[must_use]
    pub fn is_unavailable(&self) -> bool {
        self.subsystems
            .iter()
            .any(|(_, h): &(SubsystemId, SubsystemHealth)| h.is_unavailable())
    }
}
