//! Capability-aware dispatch scheduler.
//!
//! `DispatchScheduler` combines worker capability metadata from the
//! `WorkerPoolSupervisor` with liveness information from the
//! `HeartbeatMonitor` to plan the best available worker. Actual dispatch,
//! ledger transitions, timeouts, and re-dispatch are owned by the checked
//! workflow dispatcher.

use kata_types::error::{KataError, KataResult};
use smol_str::SmolStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::heartbeat::{HeartbeatMonitor, LivenessState};
use crate::supervisor::WorkerInfo;
use crate::supervisor::WorkerPoolSupervisor;

/// One scheduler-visible worker candidate for read-only placement planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerPlacementCandidate {
    pub worker_id: SmolStr,
    pub active_assignment_count: u32,
}

/// What a placement DEMANDS of a worker's containment.
///
/// # Why this is a parameter and not another `requirements` string
///
/// `requirements: &[String]` is matched against `WorkerInfo::capabilities`,
/// which is the OPERATOR's free-form vocabulary — `WorkerResource::Custom`
/// accepts any non-empty string, so a containment demand spelled there would be
/// satisfied by an operator typing the same characters into a worker config. The
/// demand is derived from the stage's CHECKED contract and is answered by a
/// MEASURED-then-claimed fact, so it travels in its own type and meets
/// [`ClaimedContainment`] rather than a string list.
///
/// # Why every public selection door takes it
///
/// Adding it as a parameter rather than defaulting it is what makes a caller
/// SAY. The one door that does not take it —
/// `DispatchScheduler::select_worker` — is test-support-gated for exactly that
/// reason: a production placement cannot reach a predicate that quietly assumed
/// `Unconstrained`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementContainment {
    /// The work being placed needs a certified containment provider on the
    /// worker. Derived from the dispatched sandbox directive's
    /// `ExecBackend::provider_posture()`, never from a label.
    CertifiedContainerRequired,

    /// The work being placed makes no containment demand of the worker.
    Unconstrained,
}

/// Dispatches assignments to workers based on capabilities, liveness,
/// and current load.
pub struct DispatchScheduler {
    supervisor: Arc<WorkerPoolSupervisor>,
    heartbeat: Arc<HeartbeatMonitor>,
}

impl DispatchScheduler {
    /// Create a new scheduler backed by the given supervisor and heartbeat
    /// monitor.
    #[must_use]
    pub fn new(supervisor: Arc<WorkerPoolSupervisor>, heartbeat: Arc<HeartbeatMonitor>) -> Self {
        Self {
            supervisor,
            heartbeat,
        }
    }

    /// Select the best worker for an assignment that requires the given
    /// capabilities.
    ///
    /// Selection strategy:
    /// 1. Filter to workers whose capabilities are a superset of
    ///    `requirements`.
    /// 2. Filter by the heartbeat monitor's tri-state liveness check:
    ///    - [`LivenessState::Alive`] — eligible.
    ///    - [`LivenessState::Dead`] — **excluded** unconditionally,
    ///      regardless of what the transport reports. `is_alive()` collapses
    ///      `Dead` and `Unknown` into `false`, so a selector built on it would
    ///      let the transport-fallback branch route to explicitly-dead workers.
    ///    - [`LivenessState::Unknown`] — fall back to
    ///      `transport.is_alive()` (in-process tests that never register
    ///      with the heartbeat monitor still need to be routable).
    /// 3. Filter on the containment demand — see [`PlacementContainment`].
    /// 4. Among survivors, pick the worker with the fewest active
    ///    assignments (least-loaded).
    ///
    /// Returns `KataError::Network` if no eligible worker is found.
    ///
    /// # Test-support only
    ///
    /// This is the one selection door that does not take a
    /// [`PlacementContainment`], and it is gated rather than defaulted so that
    /// no PRODUCTION placement can reach the predicate having quietly assumed
    /// [`PlacementContainment::Unconstrained`]. Production dispatch calls
    /// [`Self::select_worker_excluding_with_preference`], which makes the caller
    /// say.
    #[cfg(any(test, feature = "test-support"))]
    pub fn select_worker(&self, requirements: &[String]) -> KataResult<SmolStr> {
        self.select_worker_excluding(requirements, &[], PlacementContainment::Unconstrained)
    }

    /// Like [`Self::select_worker`] but prefers `preferred_worker_id` when
    /// that worker is still eligible for the same capability/liveness
    /// predicate. If the preferred worker is missing, dead, disconnected, or
    /// lacks capabilities, selection falls back to normal least-loaded routing.
    #[cfg(any(test, feature = "test-support"))]
    pub fn select_worker_with_preference(
        &self,
        requirements: &[String],
        preferred_worker_id: Option<&SmolStr>,
    ) -> KataResult<SmolStr> {
        self.select_worker_excluding_with_preference(
            requirements,
            &[],
            preferred_worker_id,
            PlacementContainment::Unconstrained,
        )
    }

    /// Like `Self::select_worker` but skips any worker in `excluded`.
    ///
    /// The dispatcher passes an empty list: an attempt is placed once, and a
    /// failed send settles it rather than retrying it on another worker.
    ///
    /// `containment` is deliberately NOT carried through `excluded`: a
    /// containment shortfall is a STATIC property of a host, not a per-retry
    /// exclusion, and folding it into that list would make
    /// [`Self::placement_candidates`] — the read-only planning view whose whole
    /// contract is that it shares this predicate — advertise capacity dispatch
    /// would reject.
    pub fn select_worker_excluding(
        &self,
        requirements: &[String],
        excluded: &[SmolStr],
        containment: PlacementContainment,
    ) -> KataResult<SmolStr> {
        self.select_worker_excluding_with_preference(requirements, excluded, None, containment)
    }

    /// Like [`Self::select_worker_excluding`] with an optional preferred
    /// worker affinity. The preference is soft: placement falls through to
    /// another eligible worker when the preferred one is not usable.
    pub fn select_worker_excluding_with_preference(
        &self,
        requirements: &[String],
        excluded: &[SmolStr],
        preferred_worker_id: Option<&SmolStr>,
        containment: PlacementContainment,
    ) -> KataResult<SmolStr> {
        let candidates = self.placement_candidates_excluding(requirements, excluded, containment);
        if let Some(preferred_worker_id) = preferred_worker_id
            && let Some(candidate) = candidates
                .iter()
                .find(|candidate| &candidate.worker_id == preferred_worker_id)
        {
            return Ok(candidate.worker_id.clone());
        }
        candidates
            .into_iter()
            .next()
            .map(|candidate| candidate.worker_id)
            .ok_or_else(|| KataError::Network("no eligible worker for requirements".into()))
    }

    /// Count workers that the scheduler would consider for the given
    /// capability requirements.
    ///
    /// This intentionally shares the same capability, containment, and
    /// heartbeat-aware transport predicate as [`Self::select_worker_excluding`]
    /// so read-only preflight surfaces cannot advertise capacity that POST
    /// routing would reject.
    #[must_use]
    pub fn eligible_worker_count(
        &self,
        requirements: &[String],
        containment: PlacementContainment,
    ) -> usize {
        self.supervisor
            .iter_workers()
            .filter(|entry| {
                self.worker_is_eligible(entry.key(), entry.value(), requirements, containment)
            })
            .count()
    }

    /// Return scheduler-visible placement candidates for a requirement set.
    ///
    /// This is a read-only planning view: it uses the same capability,
    /// containment, heartbeat, and transport-liveness predicate as dispatch,
    /// then orders candidates by current load and worker id. Callers may layer
    /// their own simulated reservations on top, but this method does not reserve
    /// worker capacity or mutate assignment counters.
    #[must_use]
    pub fn placement_candidates(
        &self,
        requirements: &[String],
        containment: PlacementContainment,
    ) -> Vec<WorkerPlacementCandidate> {
        self.placement_candidates_excluding(requirements, &[], containment)
    }

    /// Return read-only placement candidates while excluding specific workers.
    #[must_use]
    pub fn placement_candidates_excluding(
        &self,
        requirements: &[String],
        excluded: &[SmolStr],
        containment: PlacementContainment,
    ) -> Vec<WorkerPlacementCandidate> {
        let mut candidates = self
            .supervisor
            .iter_workers()
            .filter_map(|entry| {
                if excluded.iter().any(|worker_id| worker_id == entry.key()) {
                    return None;
                }
                if !self.worker_is_eligible(entry.key(), entry.value(), requirements, containment) {
                    return None;
                }
                Some(WorkerPlacementCandidate {
                    worker_id: entry.key().clone(),
                    active_assignment_count: entry
                        .value()
                        .active_assignments
                        .load(Ordering::Relaxed),
                })
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|a, b| {
            a.active_assignment_count
                .cmp(&b.active_assignment_count)
                .then_with(|| a.worker_id.cmp(&b.worker_id))
        });
        candidates
    }

    /// The ONE eligibility predicate every door above shares.
    ///
    /// The containment arm lives here rather than at each call site,
    /// so `select`, `count`, and `candidates` cannot come to different answers
    /// about the same worker. The match over [`PlacementContainment`] is
    /// exhaustive: a future demand must be decided here at compile time, not
    /// absorbed by a wildcard — the shape `unsupported_provider_placement`
    /// exists to keep out of placement.
    fn worker_is_eligible(
        &self,
        worker_id: &SmolStr,
        info: &WorkerInfo,
        requirements: &[String],
        containment: PlacementContainment,
    ) -> bool {
        let has_caps = requirements
            .iter()
            .all(|req| info.capabilities.iter().any(|cap| cap == req));
        if !has_caps {
            return false;
        }

        match containment {
            PlacementContainment::Unconstrained => {}
            PlacementContainment::CertifiedContainerRequired => {
                if !info.containment.satisfies_certified_container() {
                    return false;
                }
            }
        }

        match self.heartbeat.liveness(worker_id) {
            LivenessState::Dead => false,
            LivenessState::Alive | LivenessState::Unknown => info.transport.is_alive(),
        }
    }

    // PLACED AT THE END OF THIS `impl` rather than beside its siblings: the
    // register anchors citations into this file BY LINE, and a citation is a
    // coordinate — an insertion above one rots it onto different, real, correct
    // code, which a re-read confirms instead of catching.
}
