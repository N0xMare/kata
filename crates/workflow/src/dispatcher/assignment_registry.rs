//! Process-local assignment hot state. Durable lifecycle remains in operational.db.
//!
//! Retention is the live/parked set plus admissions currently waiting for dispatch
//! capacity and failed authority reads awaiting reconciliation. No historical
//! commands or stall cycles are retained. This is not a global admission cap:
//! capacity policy and cross-process resource cleanup are separate concerns.
//! A restart reconstructs checked commands through checked replay; timing and
//! deduplication are process-local and are not reconstructed from history.

use std::collections::HashMap;

use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};

use super::{AssignmentTiming, Ulid};

#[derive(Default)]
struct AssignmentHotState {
    timing: Option<AssignmentTiming>,
    stalled_heartbeat: Option<u64>,
}

#[derive(Default)]
pub(super) struct AssignmentRegistry {
    entries: Mutex<HashMap<Ulid, AssignmentHotState>>,
}

impl AssignmentRegistry {
    pub(super) fn timing_mut(&self, id: Ulid) -> Option<MappedMutexGuard<'_, AssignmentTiming>> {
        MutexGuard::try_map(self.entries.lock(), |entries| {
            entries.get_mut(&id)?.timing.as_mut()
        })
        .ok()
    }

    pub(super) fn insert_timing(&self, id: Ulid, timing: AssignmentTiming) {
        self.entries.lock().entry(id).or_default().timing = Some(timing);
    }

    pub(super) fn take_timing(&self, id: Ulid) -> Option<AssignmentTiming> {
        self.entries.lock().get_mut(&id)?.timing.take()
    }

    /// Removal is one ownership transition across timing and dedup state: the
    /// entry is consumed whole, and its timing is returned for release
    /// accounting.
    pub(super) fn retire(&self, id: Ulid) -> Option<AssignmentTiming> {
        let mut entries = self.entries.lock();
        entries.remove(&id)?.timing
    }

    /// One dedup per (assignment, heartbeat): a stall observation is recorded once
    /// per heartbeat the sweep re-derives it for.
    pub(super) fn claim_stall(&self, id: Ulid, heartbeat: u64) -> bool {
        let mut entries = self.entries.lock();
        let entry = entries.entry(id).or_default();
        if entry.stalled_heartbeat == Some(heartbeat) {
            return false;
        }
        entry.stalled_heartbeat = Some(heartbeat);
        true
    }

    pub(super) fn release_stall(&self, id: Ulid, heartbeat: u64) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.get_mut(&id)
            && entry.stalled_heartbeat == Some(heartbeat)
        {
            entry.stalled_heartbeat = None;
        }
    }

    pub(super) fn ids(&self) -> Vec<Ulid> {
        self.entries.lock().keys().copied().collect()
    }
}
