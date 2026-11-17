//! Workflow orchestrator state machine.
//!
//! The `Orchestrator` tracks stage states, computes ready-to-dispatch stages,
//! and records completions and failures. It does **not** call agent backends
//! directly: it produces stage names that the transport layer turns into
//! capsule `DispatchFrame`s and delivers to workers.

use std::collections::HashSet;

use dashmap::DashMap;
use indexmap::IndexMap;
use kata_types::{KataError, KataResult};
use smol_str::SmolStr;

use crate::dag::WorkflowDag;
use crate::execution_program::ExecutionProgram;

/// Orchestrator-local stage state. Distinct from the wire-level
/// `kata_types::workflow::StageState` which is a pure enum; this carries
/// associated data (output, failure reason, retry count).
#[derive(Clone, Debug)]
pub enum StageState {
    /// Waiting for dependencies.
    Pending,
    /// All dependencies satisfied; eligible for dispatch.
    Ready,
    /// Dispatched to a worker.
    Dispatched {
        /// Optional worker identity.
        worker_id: Option<SmolStr>,
    },
    /// Paused pre-dispatch waiting for operator approval. The
    /// runner parked the attempt on the durable approval gate after
    /// seeing `StageDefinition.approval = true`. The orchestrator treats
    /// this as "in progress" — downstream stages will not advance
    /// until it transitions to `Dispatched` on approve or
    /// `Failed` on reject.
    AwaitingApproval {
        /// Human-readable reason the stage waits for the operator.
        reason: String,
    },
    /// Stage completed successfully.
    Completed {
        /// Stage output payload.
        output: serde_json::Value,
    },
    /// Stage failed.
    Failed {
        /// Human-readable failure reason.
        reason: String,
        /// Number of retries attempted.
        retries: u32,
    },
    /// Stage skipped (e.g., `skip_if` condition evaluated to true).
    Skipped {
        /// Reason the stage was skipped.
        reason: String,
    },
}

impl StageState {
    /// This state's variant NAME, for the transition-refusal messages below.
    ///
    /// # Why this exists rather than `{:?}` on the value
    ///
    /// Formatting `std::mem::discriminant(other)` would render
    /// `Discriminant(5)`. That is defect class "ambiguous name" in
    /// its most literal form: it identifies the blocking state by a compiler-
    /// assigned index that is not a stable API, is not documented anywhere, changes
    /// the moment a variant is added or reordered, and cannot be mapped back to a
    /// state by the operator reading it — or by the engineer debugging it. In
    /// `cannot complete stage "solo" in state Failed` the state name IS the
    /// diagnosis (a late completion arriving after the stage already failed).
    ///
    /// Debug on the VALUE is not the fix either: `Completed { output }` would splice
    /// a whole stage payload into an error string. The variant name is the fact
    /// these messages actually want.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Ready => "Ready",
            Self::Dispatched { .. } => "Dispatched",
            Self::AwaitingApproval { .. } => "AwaitingApproval",
            Self::Completed { .. } => "Completed",
            Self::Failed { .. } => "Failed",
            Self::Skipped { .. } => "Skipped",
        }
    }
}

/// Workflow orchestrator. Drives the stage state machine and produces
/// dispatch decisions without executing stages itself.
pub struct Orchestrator {
    dag: WorkflowDag,
    state: DashMap<SmolStr, StageState>,
}

impl Orchestrator {
    /// Create a new orchestrator from the checked execution program.
    ///
    /// This path is used by program-backed runner construction and resume:
    /// stage readiness is driven entirely by the checked dependency graph
    /// retained in [`ExecutionProgramStage`](crate::execution_program::ExecutionProgramStage).
    pub fn from_execution_program(program: &ExecutionProgram) -> KataResult<Self> {
        let deps: IndexMap<SmolStr, Vec<SmolStr>> = program
            .stages
            .iter()
            .map(|(stage_id, stage)| {
                (
                    stage_id.0.clone(),
                    stage
                        .depends_on
                        .iter()
                        .map(|dependency| dependency.0.clone())
                        .collect(),
                )
            })
            .collect();
        let dag = WorkflowDag::build_from_deps(&deps)?;
        Ok(Self::from_dag(dag))
    }

    fn from_dag(dag: WorkflowDag) -> Self {
        let state = DashMap::new();
        for name in dag.topological_order() {
            state.insert(name.clone(), StageState::Pending);
        }

        Self { dag, state }
    }

    /// Advance the workflow: compute stages that are ready for dispatch.
    ///
    /// A stage becomes ready when all its dependencies are `Completed` (or
    /// `Skipped`) and the stage is currently `Pending`. Ready stages are
    /// atomically transitioned to `Ready`.
    ///
    /// Returns the names of newly-ready stages.
    pub fn advance(&self) -> Vec<SmolStr> {
        let completed = self.completed_set();
        let ready_names = self.dag.ready_stages(&completed);

        let mut newly_ready = Vec::new();
        for name in ready_names {
            let mut entry = self.state.get_mut(&name).unwrap();
            if matches!(*entry, StageState::Pending) {
                *entry = StageState::Ready;
                newly_ready.push(name);
            }
        }
        newly_ready
    }

    /// Mark a stage as successfully completed with the given output.
    ///
    /// `AwaitingApproval` is a valid source state: the operator may
    /// reject a paused stage, which the dispatcher translates into
    /// a `Failed` ledger event — but defensively we also allow a
    /// direct complete transition in case a late-arriving cached
    /// output ever lands during the approval window.
    pub fn complete_stage(&self, name: &str, output: serde_json::Value) -> KataResult<()> {
        let key = SmolStr::new(name);
        let mut entry = self
            .state
            .get_mut(&key)
            .ok_or_else(|| KataError::Validation(format!("unknown stage: \"{name}\"")))?;

        match &*entry {
            StageState::Ready
            | StageState::Dispatched { .. }
            | StageState::AwaitingApproval { .. } => {
                *entry = StageState::Completed { output };
                Ok(())
            }
            other => Err(KataError::Validation(format!(
                "cannot complete stage \"{name}\" in state {}",
                other.name()
            ))),
        }
    }

    /// Mark a stage as failed with the given reason.
    ///
    /// `AwaitingApproval` is a valid source state: operator reject
    /// transitions the ledger `AwaitingApproval → Failed`, and the
    /// runner's `apply_event` must be able to drive the orchestrator
    /// through the same transition without erroring.
    pub fn fail_stage(&self, name: &str, reason: String) -> KataResult<()> {
        let key = SmolStr::new(name);
        let mut entry = self
            .state
            .get_mut(&key)
            .ok_or_else(|| KataError::Validation(format!("unknown stage: \"{name}\"")))?;

        match &*entry {
            StageState::Ready
            | StageState::Dispatched { .. }
            | StageState::AwaitingApproval { .. } => {
                *entry = StageState::Failed { reason, retries: 0 };
                Ok(())
            }
            StageState::Failed { retries, .. } => {
                let retries = *retries;
                *entry = StageState::Failed {
                    reason,
                    retries: retries + 1,
                };
                Ok(())
            }
            other => Err(KataError::Validation(format!(
                "cannot fail stage \"{name}\" in state {}",
                other.name()
            ))),
        }
    }

    /// Pause a stage on an approval gate.
    ///
    /// Accepted source states: `{Ready, Dispatched, Completed}`.
    ///
    /// - **`Ready` → `AwaitingApproval`**: the canonical pre-dispatch
    ///   case. Runner calls this from `apply_event` when its
    ///   `submit_stage` parked the attempt on the durable approval
    ///   gate (stage carried `approval = true`).
    /// - **`Dispatched` → `AwaitingApproval`**: the escalate-mid-
    ///   loop case. A review-loop iteration left the worker stage in
    ///   `Dispatched { worker_id }` (synthetic iter-N assignment); the
    ///   loop runtime then exhausted iterations with
    ///   `OnMaxAction::Escalate` and parks the stage on a synthetic
    ///   approval. The stage's actual output (if any) is preserved in
    ///   the runner's `outputs[]` map; the orchestrator transition is
    ///   purely an operator-blocker.
    /// - **`Completed` → `AwaitingApproval`**: the post-iter-N escalate
    ///   case where the loop's last iteration's terminal already
    ///   landed and the worker is `Completed`. Same operator-blocker
    ///   semantics — output stays in `outputs[]`.
    ///
    /// Rejected: `Pending`, `Running`, `AwaitingApproval` (idempotent
    /// double-pause is an error so callers learn about it),
    /// `Failed`, `Orphaned`, `Skipped`.
    ///
    /// Adding `Running` would be a one-line extension if a future
    /// call site needs to pause an in-flight stage; today no caller
    /// does (escalate fires after the last iteration's terminal).
    pub fn pause_stage_for_approval(&self, name: &str, reason: String) -> KataResult<()> {
        let key = SmolStr::new(name);
        let mut entry = self
            .state
            .get_mut(&key)
            .ok_or_else(|| KataError::Validation(format!("unknown stage: \"{name}\"")))?;

        match &*entry {
            StageState::Ready | StageState::Dispatched { .. } | StageState::Completed { .. } => {
                *entry = StageState::AwaitingApproval { reason };
                Ok(())
            }
            other => Err(KataError::Validation(format!(
                "cannot pause stage \"{name}\" for approval in state {}",
                other.name()
            ))),
        }
    }

    /// Resume a paused stage into `Dispatched` when the dispatcher
    /// has picked a worker after operator approval. The runner
    /// calls this when its `apply_event` sees a `Dispatched` event
    /// for a stage currently in `AwaitingApproval` state.
    /// Transition is `AwaitingApproval → Dispatched { worker_id }`.
    pub fn dispatch_stage_after_approval(
        &self,
        name: &str,
        worker_id: Option<SmolStr>,
    ) -> KataResult<()> {
        let key = SmolStr::new(name);
        let mut entry = self
            .state
            .get_mut(&key)
            .ok_or_else(|| KataError::Validation(format!("unknown stage: \"{name}\"")))?;

        match &*entry {
            StageState::AwaitingApproval { .. } => {
                *entry = StageState::Dispatched { worker_id };
                Ok(())
            }
            other => Err(KataError::Validation(format!(
                "cannot dispatch-after-approval stage \"{name}\" in state {}",
                other.name()
            ))),
        }
    }

    /// RELEASE a stage HELD for an operator's input back to `Pending` — the one transition
    /// out of a hold (a blocking human request's input wait was accepted).
    /// `AwaitingApproval → Pending`, and nothing else.
    ///
    /// `Pending`, not `Ready`: the ready-selection pass
    /// (`advance_checked_ready_stages`) already submits a `Pending` stage whose
    /// dependencies are terminal, under the `max_concurrency` cap, so the released stage
    /// is submitted by the one path that submits every other stage — never by a second
    /// list, which a replay folding the stage's LATER frames would have to reconcile.
    ///
    /// # Errors
    ///
    /// An unknown stage, or one in any state but `AwaitingApproval`.
    pub fn release_held_stage(&self, name: &str) -> KataResult<()> {
        let key = SmolStr::new(name);
        let mut entry = self
            .state
            .get_mut(&key)
            .ok_or_else(|| KataError::Validation(format!("unknown stage: \"{name}\"")))?;
        match &*entry {
            StageState::AwaitingApproval { .. } => {
                *entry = StageState::Pending;
                Ok(())
            }
            other => Err(KataError::Validation(format!(
                "cannot release held stage \"{name}\" in state {}",
                other.name()
            ))),
        }
    }

    /// Force a stage from `Pending` to `Ready` regardless of DAG
    /// dependency state. Used by the review-loop resolution
    /// path: the reviewer's DAG dep (the worker) may have been
    /// interrupted through intermediate loop iterations that bypass
    /// the orchestrator, leaving the reviewer in Pending even
    /// though the loop runtime considers it ready to finalize.
    /// No-op for stages already in `Ready` or `Dispatched`.
    pub fn promote_to_ready(&self, name: &str) -> KataResult<()> {
        let key = SmolStr::new(name);
        let mut entry = self
            .state
            .get_mut(&key)
            .ok_or_else(|| KataError::Validation(format!("unknown stage: \"{name}\"")))?;

        match &*entry {
            StageState::Pending => {
                *entry = StageState::Ready;
                Ok(())
            }
            // Already at Ready or further-along non-terminal states;
            // caller's follow-up complete/fail transition will land
            // from there.
            StageState::Ready
            | StageState::Dispatched { .. }
            | StageState::AwaitingApproval { .. } => Ok(()),
            other => Err(KataError::Validation(format!(
                "cannot promote stage \"{name}\" to Ready from {}",
                other.name()
            ))),
        }
    }

    /// Mark a stage as Skipped with the given reason. Accepts the
    /// stage in any non-terminal state — used by the review
    /// loop `Aborted` resolution to short-circuit a reviewer that
    /// never ran because its worker failed first. A Skipped stage
    /// counts as terminal for [`is_finished`] but does not count as
    /// a failure for the runner's `collect_failures` scan.
    pub fn skip_stage(&self, name: &str, reason: String) -> KataResult<()> {
        let key = SmolStr::new(name);
        let mut entry = self
            .state
            .get_mut(&key)
            .ok_or_else(|| KataError::Validation(format!("unknown stage: \"{name}\"")))?;

        match &*entry {
            StageState::Pending
            | StageState::Ready
            | StageState::Dispatched { .. }
            | StageState::AwaitingApproval { .. } => {
                *entry = StageState::Skipped { reason };
                Ok(())
            }
            other => Err(KataError::Validation(format!(
                "cannot skip stage \"{name}\" in state {}",
                other.name()
            ))),
        }
    }

    /// Skip every stage that transitively depends on `root`,
    /// terminating the cascade at the orchestrator level so the
    /// runner's outer loop stops dispatching downstream waste.
    ///
    /// Walks the DAG forward from `root` (BFS over the parse-time-
    /// validated edge set; the DAG is cycle-free so termination is
    /// bounded by `stages.len()`). For each transitive dependent
    /// that is in a non-terminal state (`Pending | Ready |
    /// Dispatched | AwaitingApproval`), transitions it to
    /// `Skipped { reason: "upstream failed: <root>" }`. Stages
    /// already in a terminal state (`Completed | Failed | Skipped`)
    /// are left unchanged — the cascade respects existing terminal
    /// transitions.
    ///
    /// Called from review-loop `Aborted` resolution after the worker
    /// is marked Failed; without this the runner would keep
    /// dispatching downstream stages and either fail them late or
    /// run them on stale inputs before the workflow-level failure
    /// aggregator surfaced the original abort.
    ///
    /// `root` itself is NOT skipped — the caller already transitioned
    /// it to its appropriate terminal state. Errors from skip-source
    /// state mismatches are silently swallowed; a stage that races
    /// past `Ready` to `Completed` between the BFS scan and the
    /// skip transition is fine to leave alone.
    pub fn skip_dependents(&self, root: &str) {
        // Snapshot the stage list once so we don't iterate state
        // while mutating it via skip_stage.
        let all_stages: Vec<SmolStr> = self.state.iter().map(|e| e.key().clone()).collect();
        let root_key = SmolStr::new(root);

        // Compute the transitive set of stages whose `depends_on`
        // chain reaches `root`. Fixed-point iteration on the parse-
        // time-validated DAG; bounded by `all_stages.len()` because
        // each pass either adds a new stage to `to_skip` or terminates.
        let mut to_skip: std::collections::HashSet<SmolStr> = std::collections::HashSet::new();
        loop {
            let mut changed = false;
            for stage in &all_stages {
                if stage == &root_key || to_skip.contains(stage) {
                    continue;
                }
                let Some(deps) = self.dag.dependencies(stage.as_str()) else {
                    continue;
                };
                if deps.iter().any(|d| d == &root_key || to_skip.contains(d)) {
                    to_skip.insert(stage.clone());
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        let reason = format!("upstream failed: {root}");
        for stage in to_skip {
            // Best-effort skip; ignore source-state mismatches (a
            // race could leave the stage Completed/Failed/Skipped
            // already, in which case the cascade has nothing to do).
            let _ = self.skip_stage(stage.as_str(), reason.clone());
        }
    }

    /// Whether all stages are in a terminal state (Completed, Failed, or Skipped).
    pub fn is_finished(&self) -> bool {
        self.state.iter().all(|entry| {
            matches!(
                entry.value(),
                StageState::Completed { .. }
                    | StageState::Failed { .. }
                    | StageState::Skipped { .. }
            )
        })
    }

    /// List every stage NOT in a terminal state, paired with
    /// a short tag for its current variant. Used by the runner's
    /// end-of-run consistency check + by the API-level divergence
    /// detector to surface "ExecutionStatus says completed but the
    /// orchestrator has Pending stages" cases.
    pub fn unfinished_stages(&self) -> Vec<(SmolStr, &'static str)> {
        self.state
            .iter()
            .filter_map(|entry| {
                let tag = match entry.value() {
                    StageState::Pending => "Pending",
                    StageState::Ready => "Ready",
                    StageState::Dispatched { .. } => "Dispatched",
                    StageState::AwaitingApproval { .. } => "AwaitingApproval",
                    StageState::Completed { .. }
                    | StageState::Failed { .. }
                    | StageState::Skipped { .. } => return None,
                };
                Some((entry.key().clone(), tag))
            })
            .collect()
    }

    /// Is any stage in a live in-flight state — `Ready`, `Dispatched`,
    /// or `AwaitingApproval`?
    ///
    /// This is the replay drive's race-free wait-vs-stuck discriminator. A stage
    /// stays `Ready` (submitted, worker running) or `Dispatched`/`AwaitingApproval`
    /// until its terminal ledger event is DURABLE and FOLDED into the orchestrator
    /// — so a stage that has completed in the ledger's in-memory DashMap but whose
    /// event is not yet durable still reads as in-flight here, never as "finished".
    /// Because this is derived purely from folded durable state, the replay engine
    /// can never observe the DashMap-leads-durable-head window that the fixed-point's
    /// stuck detector papered over. `false` + `!is_finished()` at `A == H` ⟹ every
    /// unfinished stage is `Pending` behind a failed/skipped upstream ⟹ genuinely
    /// stuck.
    #[must_use]
    pub fn has_in_flight_stage(&self) -> bool {
        self.state.iter().any(|entry| {
            matches!(
                entry.value(),
                StageState::Ready
                    | StageState::Dispatched { .. }
                    | StageState::AwaitingApproval { .. }
            )
        })
    }

    /// Get the current state of a stage by name.
    pub fn stage_state(&self, name: &str) -> Option<StageState> {
        self.state.get(name).map(|entry| entry.value().clone())
    }

    /// Force a stage from any non-terminal source state
    /// into `Dispatched { worker_id }`. Used by the installed-main
    /// restart-recovery path to re-attach the orchestrator to an
    /// in-flight ledger row whose worker may still be running. The
    /// dispatcher's heartbeat and deadline sweeps handle whatever happens
    /// to the worker next; the orchestrator just needs to know "this stage is in
    /// flight, do not re-dispatch it".
    ///
    /// Distinct from [`Self::dispatch_stage_after_approval`], which
    /// only accepts `AwaitingApproval` and is part of the operator
    /// approval flow. This method accepts `Pending`, `Ready`,
    /// `Dispatched`, and `AwaitingApproval` — any non-terminal
    /// state — and refuses terminal states (which is a hard
    /// invariant of the resume flow: once terminal, the stage
    /// state must be reconstructed via complete/fail/skip).
    pub fn force_dispatched_for_resume(
        &self,
        name: &str,
        worker_id: Option<SmolStr>,
    ) -> KataResult<()> {
        let key = SmolStr::new(name);
        let mut entry = self
            .state
            .get_mut(&key)
            .ok_or_else(|| KataError::Validation(format!("unknown stage: \"{name}\"")))?;

        match &*entry {
            StageState::Pending
            | StageState::Ready
            | StageState::Dispatched { .. }
            | StageState::AwaitingApproval { .. } => {
                *entry = StageState::Dispatched { worker_id };
                Ok(())
            }
            other => Err(KataError::Validation(format!(
                "cannot force-dispatch stage \"{name}\" for resume in state {}",
                other.name()
            ))),
        }
    }

    /// Reference to the DAG.
    pub fn dag(&self) -> &WorkflowDag {
        &self.dag
    }

    /// Collect the set of completed and skipped stage names.
    fn completed_set(&self) -> HashSet<SmolStr> {
        self.state
            .iter()
            .filter(|entry| {
                matches!(
                    entry.value(),
                    StageState::Completed { .. } | StageState::Skipped { .. }
                )
            })
            .map(|entry| entry.key().clone())
            .collect()
    }
}
