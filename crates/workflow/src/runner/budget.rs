//! Per-execution + per-stage cost-budget tracker.
//!
//! Lives inside the runner; consumed by `apply_event` after each
//! `Completed` transition. Stage cost is read directly from the
//! per-assignment output JSON's `token_usage.cost_micro_usd` field
//! (set by the executor) so the tracker doesn't have to
//! re-resolve `(backend, model)` at sum time.
//!
//! Resolution rule: per-stage
//! policy wins over workflow policy when both are set; the two
//! scopes track running cost independently. A stage that has its
//! own `Halt` budget can trip without also tripping the workflow-
//! level limit (which may be set higher).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use kata_types::BudgetPolicy;
use kata_types::workflow::StageId;
use ulid::Ulid;

const GAUGE_BUDGET_MICRO_USD: &str = "kata_workflow_budget_micro_usd";

/// Scope of a budget crossing for event/metric labeling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetScope {
    /// Workflow-wide running cost.
    Workflow,
    /// Per-stage running cost (`stage_id` is the offending stage).
    Stage(StageId),
}

impl BudgetScope {
    /// Operator-facing label for events/metrics. Format
    /// `"workflow"` or `"stage:<name>"`.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Workflow => "workflow".to_owned(),
            Self::Stage(id) => format!("stage:{}", id.0.as_str()),
        }
    }
}

/// One budget crossing — returned by [`BudgetTracker::record_completion`]
/// when a Halt-mode policy trips. The runner consumes this to fail
/// the offending stage and cascade skip-dependents.
#[derive(Debug, Clone)]
pub struct BudgetTrip {
    pub scope: BudgetScope,
    pub limit_micro_usd: u64,
    pub observed_micro_usd: u64,
    /// `true` for `Halt` (caller must act); `false` for `Warn`
    /// (already emitted by the tracker as a side effect).
    pub is_halt: bool,
}

impl BudgetTrip {
    /// Operator-facing failure reason string for `Halt` trips. Used
    /// by the runner to populate the failed assignment's error
    /// message so dashboards can distinguish budget-driven failures
    /// from regular stage errors.
    #[must_use]
    pub fn reason(&self, stage_id: &StageId) -> String {
        format!(
            "budget_exceeded: {} reached {} micro-USD (limit: {} micro-USD); failed at stage {:?}",
            self.scope.label(),
            self.observed_micro_usd,
            self.limit_micro_usd,
            stage_id.0.as_str(),
        )
    }
}

/// Per-execution budget tracker. Constructed once per workflow run
/// in the runner; `record_completion` is called from `apply_event`
/// on each `Completed` transition.
pub struct BudgetTracker {
    /// Execution id stamped on every gauge emission so Prometheus can
    /// select a single run's cost time-series via the label.
    execution_id: Ulid,
    /// Workflow-wide running cost in micro-USD.
    workflow_running_micro_usd: AtomicU64,
    /// Per-stage running cost. Keyed by stage id; populated lazily
    /// on first observation. Stages with `BudgetPolicy::Unlimited`
    /// still get an entry so the gauge has a stable time-series
    /// even for unenforced stages, but the entry is only read on
    /// budget-check time for enforcing scopes.
    stage_running_micro_usd: Mutex<HashMap<StageId, u64>>,
    /// Workflow-scope `Warn` debounce flag (emit once per crossing).
    workflow_warn_emitted: AtomicBool,
    /// Per-stage `Warn` debounce flags.
    stage_warn_emitted: Mutex<HashMap<StageId, bool>>,
}

impl BudgetTracker {
    /// Construct a fresh tracker for the given execution. All running
    /// costs start at 0. The `execution_id` is stamped on every
    /// `kata_workflow_budget_micro_usd` gauge emission.
    #[must_use]
    pub fn new(execution_id: Ulid) -> Self {
        Self {
            execution_id,
            workflow_running_micro_usd: AtomicU64::new(0),
            stage_running_micro_usd: Mutex::new(HashMap::new()),
            workflow_warn_emitted: AtomicBool::new(false),
            stage_warn_emitted: Mutex::new(HashMap::new()),
        }
    }

    /// Add `cost_micro_usd` to the per-stage and workflow running
    /// totals, then check the deepest applicable policy. Returns
    /// `Some(BudgetTrip { is_halt: true, ... })` only when a
    /// `Halt`-mode budget crossed and the runner needs to act;
    /// returns `None` otherwise (including `Warn` crossings, which
    /// are reported as a side effect via the caller-supplied
    /// `emit_warn` closure).
    ///
    /// `emit_warn` is the recorder for `Warn`-mode crossings — the
    /// runner injects an event-bus publisher + metric incrementer
    /// here so `BudgetTracker` stays free of `kata-core` deps.
    pub fn record_completion<F>(
        &self,
        stage_id: &StageId,
        cost_micro_usd: u64,
        workflow_policy: BudgetPolicy,
        stage_policy: BudgetPolicy,
        emit_warn: F,
    ) -> Option<BudgetTrip>
    where
        F: Fn(&BudgetScope, u64, u64),
    {
        // Update both counters unconditionally so the gauge tracks
        // running cost even for `Unlimited` scopes (the dashboard
        // can still see "what did we spend" without enforcement).
        let new_workflow = self
            .workflow_running_micro_usd
            .fetch_add(cost_micro_usd, Ordering::Relaxed)
            + cost_micro_usd;
        let new_stage = {
            let mut guard = self
                .stage_running_micro_usd
                .lock()
                .expect("budget tracker stage map mutex poisoned");
            let entry = guard.entry(stage_id.clone()).or_insert(0);
            *entry += cost_micro_usd;
            *entry
        };

        // Emit running-cost gauges on every Completed event so
        // dashboards get a continuous signal. Labelled by execution_id
        // (to select a single run) and scope (workflow vs per-stage).
        // The u64→f64 cast loses precision above 2^53 micro-USD (~$9T);
        // practical run costs never approach that boundary.
        #[allow(clippy::cast_precision_loss)]
        let workflow_f64 = new_workflow as f64;
        #[allow(clippy::cast_precision_loss)]
        let stage_f64 = new_stage as f64;
        let eid = self.execution_id.to_string();
        metrics::gauge!(
            GAUGE_BUDGET_MICRO_USD,
            "execution_id" => eid.clone(),
            "scope" => "workflow",
        )
        .set(workflow_f64);
        metrics::gauge!(
            GAUGE_BUDGET_MICRO_USD,
            "execution_id" => eid,
            "scope" => BudgetScope::Stage(stage_id.clone()).label(),
        )
        .set(stage_f64);

        // Resolution rule: per-stage wins over
        // workflow. We check stage first; if it trips Halt, return
        // immediately. If stage is Unlimited or only Warn, fall
        // through to the workflow check.
        if let Some(trip) = Self::check_scope(
            BudgetScope::Stage(stage_id.clone()),
            stage_policy,
            new_stage,
        ) {
            if trip.is_halt {
                return Some(trip);
            }
            // Warn-mode: emit the side effect, debounce by scope.
            self.emit_warn_once(
                &trip.scope,
                &emit_warn,
                trip.observed_micro_usd,
                trip.limit_micro_usd,
            );
        }

        if let Some(trip) = Self::check_scope(BudgetScope::Workflow, workflow_policy, new_workflow)
        {
            if trip.is_halt {
                return Some(trip);
            }
            self.emit_warn_once(
                &trip.scope,
                &emit_warn,
                trip.observed_micro_usd,
                trip.limit_micro_usd,
            );
        }

        None
    }

    /// Sum the running cost for a single scope. `None` for
    /// `Unlimited`. `Some(trip)` when running > limit; `is_halt`
    /// reflects the policy.
    fn check_scope(scope: BudgetScope, policy: BudgetPolicy, running: u64) -> Option<BudgetTrip> {
        let limit = policy.limit_micro_usd()?;
        if running > limit {
            Some(BudgetTrip {
                scope,
                limit_micro_usd: limit,
                observed_micro_usd: running,
                is_halt: policy.is_halt(),
            })
        } else {
            None
        }
    }

    fn emit_warn_once<F>(&self, scope: &BudgetScope, emit_warn: &F, observed: u64, limit: u64)
    where
        F: Fn(&BudgetScope, u64, u64),
    {
        let already = match scope {
            BudgetScope::Workflow => self.workflow_warn_emitted.swap(true, Ordering::Relaxed),
            BudgetScope::Stage(id) => {
                let mut guard = self
                    .stage_warn_emitted
                    .lock()
                    .expect("budget tracker warn map mutex poisoned");
                let entry = guard.entry(id.clone()).or_insert(false);
                let prev = *entry;
                *entry = true;
                prev
            }
        };
        if !already {
            emit_warn(scope, observed, limit);
        }
    }

    /// Workflow-wide running cost in micro-USD. Read on the runner's hot path by
    /// the cost-`Bound` check (the captured walk-away ceiling is
    /// compared against this same accumulator the budget policy watches), and by
    /// tests + dashboard/gauge integrations.
    #[must_use]
    pub fn workflow_running_micro_usd(&self) -> u64 {
        self.workflow_running_micro_usd.load(Ordering::Relaxed)
    }

    /// Per-stage running cost in micro-USD. Returns 0 if the stage
    /// hasn't recorded any completions yet.
    #[must_use]
    #[allow(dead_code)]
    pub fn stage_running_micro_usd(&self, stage_id: &StageId) -> u64 {
        self.stage_running_micro_usd
            .lock()
            .expect("budget tracker stage map mutex poisoned")
            .get(stage_id)
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn stage(id: &str) -> StageId {
        StageId(smol_str::SmolStr::new(id))
    }

    #[test]
    fn record_completion_unlimited_no_trip() {
        let t = BudgetTracker::new(Ulid::new());
        let trip = t.record_completion(
            &stage("s1"),
            5_000_000,
            BudgetPolicy::Unlimited,
            BudgetPolicy::Unlimited,
            |_, _, _| panic!("unlimited must not emit warn"),
        );
        assert!(trip.is_none());
        assert_eq!(t.workflow_running_micro_usd(), 5_000_000);
        assert_eq!(t.stage_running_micro_usd(&stage("s1")), 5_000_000);
    }

    #[test]
    fn workflow_halt_trips_on_overshoot() {
        let t = BudgetTracker::new(Ulid::new());
        let trip = t.record_completion(
            &stage("s1"),
            1_500_000,
            BudgetPolicy::Halt {
                limit_micro_usd: 1_000_000,
            },
            BudgetPolicy::Unlimited,
            |_, _, _| {},
        );
        let trip = trip.expect("halt should trip");
        assert!(trip.is_halt);
        assert_eq!(trip.scope, BudgetScope::Workflow);
        assert_eq!(trip.limit_micro_usd, 1_000_000);
        assert_eq!(trip.observed_micro_usd, 1_500_000);
    }

    #[test]
    fn per_stage_halt_trips_independently_of_workflow() {
        let t = BudgetTracker::new(Ulid::new());
        // Stage s1 has its own halt at 500k; workflow halt is 10M
        // (well above the stage's spend). Stage trips first.
        let trip = t
            .record_completion(
                &stage("s1"),
                600_000,
                BudgetPolicy::Halt {
                    limit_micro_usd: 10_000_000,
                },
                BudgetPolicy::Halt {
                    limit_micro_usd: 500_000,
                },
                |_, _, _| {},
            )
            .expect("stage halt should trip");
        assert!(trip.is_halt);
        assert_eq!(trip.scope, BudgetScope::Stage(stage("s1")));
    }

    #[test]
    fn warn_emits_event_once_per_scope() {
        let t = BudgetTracker::new(Ulid::new());
        let emitted = Mutex::new(0u32);
        let emit = |_: &BudgetScope, _: u64, _: u64| {
            *emitted.lock().unwrap() += 1;
        };
        // First crossing: emits.
        let trip = t.record_completion(
            &stage("s1"),
            1_500_000,
            BudgetPolicy::Warn {
                limit_micro_usd: 1_000_000,
            },
            BudgetPolicy::Unlimited,
            emit,
        );
        assert!(trip.is_none(), "warn must not return a halt trip");
        assert_eq!(*emitted.lock().unwrap(), 1);
        // Second over-limit completion: should NOT re-emit
        // (debounce — once per scope per crossing).
        let _ = t.record_completion(
            &stage("s1"),
            500_000,
            BudgetPolicy::Warn {
                limit_micro_usd: 1_000_000,
            },
            BudgetPolicy::Unlimited,
            emit,
        );
        assert_eq!(
            *emitted.lock().unwrap(),
            1,
            "warn must be debounced once per scope per crossing"
        );
    }

    #[test]
    fn budget_scope_label_format() {
        assert_eq!(BudgetScope::Workflow.label(), "workflow");
        assert_eq!(BudgetScope::Stage(stage("draft")).label(), "stage:draft");
    }

    #[test]
    fn trip_reason_format() {
        let trip = BudgetTrip {
            scope: BudgetScope::Workflow,
            limit_micro_usd: 1_000_000,
            observed_micro_usd: 1_500_000,
            is_halt: true,
        };
        let reason = trip.reason(&stage("s1"));
        assert!(reason.contains("budget_exceeded"));
        assert!(reason.contains("workflow"));
        assert!(reason.contains("1500000"));
        assert!(reason.contains("1000000"));
        assert!(reason.contains("\"s1\""));
    }
}
