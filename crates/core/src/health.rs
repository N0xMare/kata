//! `SystemHealth` — per-subsystem operational state tracking.
//!
//! Every subsystem reports its own health transitions via
//! [`SystemHealth::report`]. The struct is `Send + Sync`.
//!
//! The wire-relevant data shapes ([`SubsystemId`], [`SubsystemHealth`],
//! [`HealthSnapshot`]) live in [`kata_types::health`] so the client SDK can
//! re-export them verbatim. The aggregator [`SystemHealth`] (DashMap + Atomic) stays
//! here because it's stateful and `kata-types` is dep-light by design.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

// Re-export the canonical wire types from `kata-types` so
// `kata_core::SubsystemId` / `kata_core::SubsystemHealth` resolve here too.
pub use kata_types::health::{HealthSnapshot, SubsystemHealth, SubsystemId};

/// Aggregate, shareable view of every subsystem's health.
///
/// `Clone` produces a shallow copy (both handles see the same backing
/// map and timestamp), so `Core` can hand a `SystemHealth` clone to any
/// subsystem that wants to report its own state.
#[derive(Debug, Clone, Default)]
pub struct SystemHealth {
    inner: Arc<SystemHealthInner>,
}

#[derive(Debug, Default)]
struct SystemHealthInner {
    subsystems: DashMap<SubsystemId, SubsystemHealth>,
    last_updated_millis: AtomicU64,
}

impl SystemHealth {
    /// Build an empty health tracker with no subsystems registered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Report a new `health` value for `subsystem`. Replaces any
    /// previous entry and updates the last-updated timestamp.
    pub fn report(&self, subsystem: SubsystemId, health: SubsystemHealth) {
        self.inner.subsystems.insert(subsystem, health);
        let now = kata_types::time::now_ms();
        self.inner.last_updated_millis.store(now, Ordering::Release);
    }

    /// Current health of a single subsystem, or `None` if it has never
    /// reported.
    #[must_use]
    pub fn get(&self, subsystem: SubsystemId) -> Option<SubsystemHealth> {
        self.inner
            .subsystems
            .get(&subsystem)
            .map(|r| r.value().clone())
    }

    /// Snapshot every subsystem's health in deterministic order.
    #[must_use]
    pub fn snapshot(&self) -> HealthSnapshot {
        let mut subsystems: Vec<(SubsystemId, SubsystemHealth)> = self
            .inner
            .subsystems
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect();
        subsystems.sort_by_key(|(id, _)| *id);
        HealthSnapshot {
            last_updated_millis: self.inner.last_updated_millis.load(Ordering::Acquire),
            subsystems,
        }
    }

    /// Overall health of the whole system:
    /// * `Unavailable` if any reported subsystem is `Unavailable`.
    /// * else `Degraded` if any reported subsystem is `Degraded`.
    /// * else `Healthy` (including the all-empty case).
    #[must_use]
    pub fn overall(&self) -> SubsystemHealth {
        let mut degraded: Option<(u64, String)> = None;
        let mut unavailable: Option<(u64, String)> = None;
        for entry in &self.inner.subsystems {
            match entry.value() {
                SubsystemHealth::Healthy => {}
                SubsystemHealth::Degraded { since, reason } => {
                    if degraded.is_none() {
                        degraded = Some((*since, reason.clone()));
                    }
                }
                SubsystemHealth::Unavailable { since, reason } => {
                    if unavailable.is_none() {
                        unavailable = Some((*since, reason.clone()));
                    }
                }
            }
        }
        if let Some((since, reason)) = unavailable {
            SubsystemHealth::Unavailable { since, reason }
        } else if let Some((since, reason)) = degraded {
            SubsystemHealth::Degraded { since, reason }
        } else {
            SubsystemHealth::Healthy
        }
    }
}
