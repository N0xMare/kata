//! THE OCI DIVERT: on the single engine, which
//! operation a ready stage is decides who resolves it.
//!
//! # What this module is
//!
//! [`WorkflowRunner::divert_under_capsule_profile`] lowers the stage to its typed
//! [`RuntimeOperation`], HOLDS it first when a blocking human request targeting it is not
//! yet answered (`WorkflowRunner::hold_for_blocking_inputs`, `runner::input_wait` — the
//! request is its own program-level `Wait(Input)` occurrence, whatever the stage runs), and
//! otherwise routes it:
//!
//! | operation | route |
//! |---|---|
//! | `Execute { executor: Command }` | the CAPSULE path (`submit_stage_as_capsule`), with this lowering |
//! | `Execute { executor: Agent }` | the SAME path — its `CapsuleProcess::Agent` turn is assembled there (a stage whose adapter the node did not declare was refused `adapter_*` at CHECK) |
//! | `Join` | resolved MAIN-SIDE here ([`WorkflowRunner::resolve_join`]) — no capsule, no dispatch |
//! | `Wait(For)`, `Wait(Until)` | PARKED main-side here ([`WorkflowRunner::park_timer`]) — a durable timer the deadline sweep resolves |
//! | `Invoke` | STARTED main-side (`WorkflowRunner::invoke_child` (`dispatch::invoke`)) — one parked attempt and one linked child execution, admitted in one transaction; the child's terminal publication resolves it |
//! | `ExpandBounded` (a `topology` or `dynamic_fanout` stage) | the EXPANSION's claim trigger (`WorkflowRunner::claim_stage_expansion`) — the member capsules dispatch at child coordinates off the expansion's own drive pass |
//! | anything else — including `Wait(Input)`, which is program-level and never a stage's | refused by name, [`STAGE_OPERATION_UNSUPPORTED`] |
//!
//! It runs in `submit_stage` right after the checked-dispatch preflight and BEFORE the
//! render and the sandbox resolution: a main-resolved operation runs no process, so it has
//! no command to render and no box to resolve, and resolving one would materialize a
//! workspace for work that never reads it. The arms live here so a new main-resolved
//! operation adds its arm without editing `submit_stage`.
//!
//! # The timer, and who wakes it
//!
//! [`WorkflowRunner::park_timer`] only PARKS: one transaction claims the stage's
//! occurrence with an `executor = 'main'` attempt in `awaiting_timer`, its durable deadline
//! computed in that transaction (`For` anchored at the claim transition's own
//! `recorded_at_ms`, `Until` at its instant). The WAKE is the deadline sweep's
//! `Dispatcher::sweep_due_waits`, which accepts it `{"deadline_ms": …}` once the deadline
//! has passed — up to one heartbeat interval after it. The claim folds
//! `Pending` and the park is no wire event, so the stage reads in flight until that
//! acceptance reaches the fold; a runner that RESUMES over a parked timer re-submits the
//! stage, and the claim converges on the live attempt (`AlreadyLive`), which is the timer
//! still in flight — never a second claim and never a re-anchored deadline.

use kata_core::operational::{
    AttemptLifecycle, MainAttemptSpec, MainClaimAndResolveOutcome, MainClaimOutcome, MainOperation,
    MainResolution, MainWait, OccurrenceBinding,
};
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{
    ActionExecutor, ExecuteOperation, OperationPath, RuntimeOperation, WaitOperation,
};
use kata_types::workflow::{ExecutionId, StageId};
use smol_str::SmolStr;
use tracing::{info, warn};
use ulid::Ulid;

use crate::runner::WorkflowRunner;
use kata_program::execution_program::{
    LoweredOperation, durable_sleep_deadline, lower_stage_operation, occurrence_for,
};
use kata_types::wait::DurableSleep;

/// A lowered STAGE operation that is neither a capsule nor main-resolved (a
/// `select`, an input `wait` — program-level operations, never a stage's).
const STAGE_OPERATION_UNSUPPORTED: &str = "stage_operation_unsupported";

/// A `memory_snapshot()` stage presented on a node whose runner carries no
/// memory store: the attempt claims and resolves `failed` with this verdict,
/// so the refusal is recorded and idempotent rather than a poisoned dispatch.
const MEMORY_SNAPSHOT_STORE_UNAVAILABLE: &str = "memory_snapshot_store_unavailable";

/// Where [`WorkflowRunner::divert_under_capsule_profile`] sent a ready stage.
pub(in crate::runner) enum CapsuleProfileRoute {
    /// Resolved main-side; nothing is dispatched and the stage's frames reach the fold
    /// through the chain.
    Resolved,
    /// A capsule command: continue to `submit_stage_as_capsule` with THIS lowering, so the
    /// operation that was routed is the operation that is assembled.
    Capsule(Box<LoweredOperation>),
}

fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("main-resolved dispatch refused: {reason}"))
}

impl WorkflowRunner {
    /// Lower `stage_name`, hold it on an unanswered blocking request, or route it — see the
    /// module docs for the table.
    ///
    /// # Errors
    ///
    /// A stage that does not lower (`LoweringError`, by name); the hold's refusals; the two
    /// refusals the table names; and [`Self::resolve_join`]'s.
    pub(in crate::runner) fn divert_under_capsule_profile(
        &self,
        stage_name: &SmolStr,
    ) -> KataResult<CapsuleProfileRoute> {
        let lowered = lower_stage_operation(&self.execution_program, &StageId(stage_name.clone()))
            .map_err(|error| {
                KataError::Validation(format!(
                    "capsule dispatch refused: stage {stage_name} does not lower: {error:?}"
                ))
            })?;
        // THE INPUT HOLD, before the stage's own operation is
        // routed: a stage targeted by a blocking human request whose input wait is not
        // accepted runs nothing yet, whatever it would run.
        if self.hold_for_blocking_inputs(stage_name)? {
            return Ok(CapsuleProfileRoute::Resolved);
        }
        match &lowered.contract.operation {
            RuntimeOperation::Execute(
                ExecuteOperation {
                    executor: ActionExecutor::Command,
                    ..
                }
                | ExecuteOperation {
                    executor: ActionExecutor::Agent { .. },
                    ..
                },
            ) => Ok(CapsuleProfileRoute::Capsule(Box::new(lowered))),
            RuntimeOperation::Join { inputs } => {
                self.resolve_join(stage_name, &lowered, inputs)?;
                Ok(CapsuleProfileRoute::Resolved)
            }
            RuntimeOperation::Wait(WaitOperation::For { delay_ms }) => {
                self.park_timer(stage_name, &lowered, DurableSleep::For { ms: *delay_ms })?;
                Ok(CapsuleProfileRoute::Resolved)
            }
            RuntimeOperation::Wait(WaitOperation::Until { epoch_ms }) => {
                self.park_timer(
                    stage_name,
                    &lowered,
                    DurableSleep::Until {
                        epoch_ms: *epoch_ms,
                    },
                )?;
                Ok(CapsuleProfileRoute::Resolved)
            }
            // The lowering's `program` is this stage's own bound child hash
            // (`stage_operation` reads `subworkflow.bound`), so `invoke_child` starts the
            // bound child itself and there is no second hash to compare.
            RuntimeOperation::Invoke { .. } => {
                self.invoke_child(stage_name, &lowered)?;
                Ok(CapsuleProfileRoute::Resolved)
            }
            // A `workspace_effect` stage is a MAIN-RESOLVED effect, not a
            // capsule: `submit_workspace_effect` claims the stage's attempt at
            // its own occurrence (parking under `approval_required`), runs the
            // jj verbs at the main, and resolves it — the same recorded-effect
            // contract the `/work` apply's `MainOperation::WorkApply` carries.
            RuntimeOperation::Execute(ExecuteOperation {
                executor: ActionExecutor::Effect { .. },
                ..
            }) => {
                self.submit_workspace_effect(stage_name, &lowered)?;
                Ok(CapsuleProfileRoute::Resolved)
            }
            // A `topology(..)` or `dynamic_fanout` stage lowers
            // to `ExpandBounded` at its OWN coordinate: the stage's submit is
            // the expansion's claim trigger. Its members — the root at
            // `path.child(0)`, the children at `path.child(1..)` (declared for
            // a topology, request-minted for a fanout) — are dispatched at
            // child coordinates by the expansion's own drive pass, never
            // through this arm, and the stage's completion arrives only
            // through the accepted record's apply.
            RuntimeOperation::ExpandBounded { .. } => {
                self.claim_stage_expansion(&lowered)?;
                Ok(CapsuleProfileRoute::Resolved)
            }
            // A `memory_snapshot()` stage is a MAIN-RESOLVED read, not a
            // capsule: the node's memory store answers it just before the
            // claim-and-resolve transaction records it — no process runs.
            RuntimeOperation::MemorySnapshot { query } => {
                self.resolve_memory_snapshot(stage_name, &lowered, *query)?;
                Ok(CapsuleProfileRoute::Resolved)
            }
            operation => Err(refused(&format!(
                "{STAGE_OPERATION_UNSUPPORTED}: stage {stage_name} lowers to `{}`{}, \
                 which is neither a capsule command nor a main-resolved operation under the \
                 `oci` profile",
                operation.as_tag(),
                match operation {
                    RuntimeOperation::Execute(execute) => {
                        format!(" (executor `{}`)", execute.executor.as_tag())
                    }
                    _ => String::new(),
                }
            ))),
        }
    }

    /// RESOLVE a `parallel()` JOIN main-side: claim and resolve its occurrence in one
    /// transaction (`OperationalDb::resolve_join`), only if every input occurrence is
    /// accepted — and with the branches' `/work` fan-in merged in the same
    /// transaction.
    ///
    /// The fan-in plan is derived HERE from the program, not trusted from anywhere: the
    /// join lands its merged delta on the head at the JOIN's own coordinate, and each
    /// input contributes the head at the coordinate its stages actually ran under —
    /// `work_head_coordinate` over the input stage, which is `parent.pushed(join, exit)`
    /// exactly when the exit is private to this barrier, and the barrier's own
    /// coordinate (the ambient arm) for a shared input.
    ///
    /// A merged delta rides the join's accepted output (`work_delta_artifact_id`), and
    /// the apply sweep lands it as `#apply/<join>` through the ordinary legs — jj for
    /// an isolated head, CAS-only otherwise — while the successor gate holds the
    /// barrier's dependents until it does.
    ///
    /// A re-presented join CONVERGES (`AlreadyAccepted`, or `AlreadyResolvedTerminal`
    /// on the recorded conflict verdict) and writes nothing. Its frames reach the
    /// runner's fold through the chain like any attempt's: the claim as `Pending`, the
    /// resolution as `Completed { worker_id: None }` or `Failed`.
    ///
    /// # Errors
    ///
    /// `join_input_unaccepted` (nothing written); an input path that names no stage of
    /// this program, or does not lower; `work_head_coordinate`'s ambiguity refusal for a
    /// stage enclosed by incomparable forks; a live unresolved main attempt at the
    /// join's occurrence, which no writer produces (a join is claimed and resolved in
    /// ONE transaction); storage faults. A `work_fanin_conflict` is NOT an error — it is
    /// the join's recorded `failed` resolution, which the fold turns into the stage's
    /// failure.
    fn resolve_join(
        &self,
        stage_name: &SmolStr,
        lowered: &LoweredOperation,
        inputs: &[OperationPath],
    ) -> KataResult<()> {
        let execution = ExecutionId(self.execution_id);
        let parent = kata_program::execution_program::work_head_coordinate(
            &self.execution_program,
            &StageId(stage_name.clone()),
        )?;
        let fanin = kata_core::operational::JoinFanIn {
            parent,
            inputs: inputs
                .iter()
                .map(|path| {
                    let input = self.stage_at_path(stage_name, path)?;
                    let input_lowered = lower_stage_operation(&self.execution_program, &input)
                        .map_err(|error| {
                            refused(&format!(
                                "join {stage_name}'s input {} does not lower: {error:?}",
                                input.0
                            ))
                        })?;
                    Ok(kata_core::operational::JoinFanInInput {
                        occurrence: occurrence_for(
                            &self.execution_program,
                            execution,
                            &input_lowered,
                        )
                        .id()
                        .0
                        .0,
                        branch: kata_program::execution_program::work_head_coordinate(
                            &self.execution_program,
                            &input,
                        )?,
                        label: input.0.to_string(),
                    })
                })
                .collect::<KataResult<Vec<_>>>()?,
        };
        let input_count = fanin.inputs.len();
        let spec = MainAttemptSpec {
            stage_id: stage_name.to_string(),
            occurrence: OccurrenceBinding::new(
                occurrence_for(&self.execution_program, execution, lowered),
                None,
                None,
            ),
        };
        let attempt_id = Ulid::new();
        let outcome = self
            .dispatcher
            .execution_lifecycle()
            .db()
            .resolve_join(attempt_id, &spec, &fanin)?;
        match outcome {
            MainClaimAndResolveOutcome::Resolved {
                claim_seq,
                resolve_seq,
            } => info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                %attempt_id,
                claim_seq,
                resolve_seq,
                inputs = input_count,
                "runner: resolved a join main-side"
            ),
            // The merge refused: the join's attempt is recorded `failed` with the
            // conflict's reason, and the fold of that frame is what fails the run —
            // this arm only logs, and never retries a settled verdict.
            MainClaimAndResolveOutcome::ResolvedFailed {
                claim_seq,
                resolve_seq,
            } => info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                %attempt_id,
                claim_seq,
                resolve_seq,
                inputs = input_count,
                "runner: a join resolved failed main-side (the recorded fan-in conflict)"
            ),
            MainClaimAndResolveOutcome::AlreadyAccepted { attempt_id } => info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                %attempt_id,
                "runner: a re-presented join converged on its accepted resolution"
            ),
            MainClaimAndResolveOutcome::AlreadyResolvedTerminal { attempt_id, state } => {
                info!(
                    execution_id = %self.execution_id,
                    stage = %stage_name,
                    %attempt_id,
                    state = %state.as_str(),
                    "runner: a re-presented join converged on its recorded terminal verdict"
                );
            }
            MainClaimAndResolveOutcome::AlreadyLive { attempt_id, state } => {
                return Err(KataError::Storage(format!(
                    "join {stage_name}'s occurrence holds a LIVE main attempt {attempt_id} in \
                     `{}`; a join is claimed and resolved in one transaction, so no writer leaves \
                     one unresolved",
                    state.as_str()
                )));
            }
        }
        Ok(())
    }

    /// RESOLVE a `memory_snapshot()` stage main-side: read the node's native
    /// memory store under the authored `kind`/`status` filter and claim +
    /// resolve the stage's occurrence in ONE transaction
    /// (`OperationalDb::claim_and_resolve_main_attempt`,
    /// `MainOperation::MemorySnapshot`), so there is no durable instant at
    /// which the attempt exists unresolved — a crash before the commit leaves
    /// neither, and after it both.
    ///
    /// The accepted output is `{"content": <snapshot JSON>}` — the same
    /// envelope shape a worker-produced stage output carries — so the fold's
    /// `inject_parsed_if_declared` validates the declared snapshot fields and
    /// injects `parsed`, and a downstream `{{ stages.<id>.parsed.objects }}`
    /// reads the snapshot's objects.
    ///
    /// An ACCEPTED occurrence converges: its row is read first, and an
    /// accepted one returns before the store is touched, so a re-presentation
    /// neither re-reads the store nor fails on a fault there. A FAILED
    /// resolution is not settled: it is retried at the next presentation
    /// (`converge_in_tx` folds only live and accepted attempts, so the plane
    /// mints a further attempt), and that attempt resolves on the store the
    /// runner carries THEN — the same `failed` verdict while the node still
    /// has no store, an accepted snapshot once it has one. The store read
    /// precedes the claim, so a crash mid-resolution records no attempt and a
    /// re-presentation retries cleanly; once the claim-and-resolve transaction
    /// commits, the recorded resolution is what the chain replays.
    ///
    /// # Errors
    ///
    /// A memory-store read or serialization fault; a live unresolved main
    /// attempt at the occurrence, which no writer produces (a snapshot is
    /// claimed and resolved in ONE transaction); a recorded-verdict outcome
    /// (`ResolvedFailed`, `AlreadyResolvedTerminal`), which only
    /// `resolve_join` answers; the claim's refusals and storage faults. A
    /// node with NO memory store is NOT an error here — the attempt claims and
    /// resolves `failed` with [`MEMORY_SNAPSHOT_STORE_UNAVAILABLE`], a
    /// recorded verdict the fold turns into the stage's failure.
    ///
    /// `pub(in crate::runner)` because a loop member's memory snapshot
    /// (`runner::expansion`) resolves through the same door — one resolution
    /// path.
    pub(in crate::runner) fn resolve_memory_snapshot(
        &self,
        stage_name: &SmolStr,
        lowered: &LoweredOperation,
        query: kata_types::workflow::MemorySnapshotSpec,
    ) -> KataResult<()> {
        let occurrence = occurrence_for(
            &self.execution_program,
            ExecutionId(self.execution_id),
            lowered,
        );
        let lifecycle = self.dispatcher.execution_lifecycle();
        let db = lifecycle.db();
        if let Some(accepted) = db
            .occurrence(occurrence.id().0.0)?
            .and_then(|row| row.accepted)
        {
            info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                attempt_id = %accepted.attempt_id,
                "runner: a re-presented memory snapshot converged on its accepted resolution"
            );
            return Ok(());
        }
        let output = match self.memory_store.as_ref() {
            Some(store) => {
                let snapshot = store.snapshot(query.kind, query.status)?;
                let content = serde_json::to_string(&snapshot).map_err(|error| {
                    KataError::Internal(format!(
                        "memory snapshot for stage {stage_name} does not serialize: {error}"
                    ))
                })?;
                serde_json::json!({ "content": content })
            }
            None => serde_json::Value::Null,
        };
        let resolution = if self.memory_store.is_some() {
            MainResolution::Complete { output: &output }
        } else {
            MainResolution::Fail {
                reason: MEMORY_SNAPSHOT_STORE_UNAVAILABLE,
                terminal_charge: None,
            }
        };
        let spec = MainAttemptSpec {
            stage_id: stage_name.to_string(),
            occurrence: OccurrenceBinding::new(occurrence, None, None),
        };
        let attempt_id = Ulid::new();
        let outcome = db.claim_and_resolve_main_attempt(
            attempt_id,
            &spec,
            MainOperation::MemorySnapshot,
            &resolution,
        )?;
        match outcome {
            // Both resolutions answer `Resolved`, so the line is chosen by the
            // resolution this call recorded: an accepted snapshot, or a
            // store-less one recorded `failed` with
            // `MEMORY_SNAPSHOT_STORE_UNAVAILABLE`, whose frame the fold turns
            // into the stage's failure. That verdict does not settle the
            // occurrence: a later presentation mints a further attempt.
            MainClaimAndResolveOutcome::Resolved {
                claim_seq,
                resolve_seq,
            } => match resolution {
                MainResolution::Complete { .. } => info!(
                    execution_id = %self.execution_id,
                    stage = %stage_name,
                    %attempt_id,
                    claim_seq,
                    resolve_seq,
                    kind = ?query.kind.map(kata_types::memory::MemoryObjectKind::label),
                    status = ?query.status.map(kata_types::memory::MemoryObjectStatus::label),
                    "runner: resolved a memory snapshot main-side"
                ),
                // The resolution above is built `Complete` or `Fail`, never `Cancel`.
                MainResolution::Fail { reason, .. } | MainResolution::Cancel { reason, .. } => {
                    warn!(
                        execution_id = %self.execution_id,
                        stage = %stage_name,
                        %attempt_id,
                        claim_seq,
                        resolve_seq,
                        reason,
                        "runner: a memory snapshot resolved FAILED main-side; the next \
                         presentation retries it"
                    );
                }
            },
            // An acceptance committed between the row read above and this
            // transaction.
            MainClaimAndResolveOutcome::AlreadyAccepted { attempt_id } => info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                %attempt_id,
                "runner: a re-presented memory snapshot converged on its accepted resolution"
            ),
            // `resolve_join`'s answers: `claim_and_resolve_main_attempt` never
            // answers either, so a store-less snapshot, resolved `failed`,
            // reads as `Resolved` above.
            MainClaimAndResolveOutcome::ResolvedFailed { .. }
            | MainClaimAndResolveOutcome::AlreadyResolvedTerminal { .. } => {
                return Err(KataError::Storage(format!(
                    "memory snapshot {stage_name}'s claim-and-resolve answered a \
                     recorded-verdict outcome, which `resolve_join` alone produces"
                )));
            }
            MainClaimAndResolveOutcome::AlreadyLive { attempt_id, state } => {
                return Err(KataError::Storage(format!(
                    "memory snapshot {stage_name}'s occurrence holds a LIVE main attempt \
                     {attempt_id} in `{}`; a memory snapshot is claimed and resolved in one \
                     transaction, so no writer leaves one unresolved",
                    state.as_str()
                )));
            }
        }
        Ok(())
    }

    /// PARK a durable sleep main-side: claim its occurrence with one `executor = 'main'`
    /// attempt in `awaiting_timer`, its durable deadline computed INSIDE the claim's
    /// transaction (`OperationalDb::claim_main_attempt` with `MainWait::Timer`) — a `For`
    /// anchored at the claim transition's own `recorded_at_ms`, so no later reading of any
    /// clock (a resume's, a boot's) can move it; an `Until` at its instant.
    ///
    /// A re-presented sleep CONVERGES and writes nothing: `AlreadyLive` in
    /// `awaiting_timer` is the timer still in flight (the resume of a runner over a parked
    /// timer re-submits its stage, because the claim folds `Pending`), and
    /// `AlreadyAccepted` is a timer the sweep already resolved, whose acceptance reaches
    /// the fold through the chain.
    ///
    /// # Errors
    ///
    /// [`DURABLE_SLEEP_UNREPRESENTABLE`](kata_program::execution_program::DURABLE_SLEEP_UNREPRESENTABLE)
    /// (defense in depth behind the CHECK door); a live main attempt at the occurrence in
    /// any state but `awaiting_timer`, which no writer produces; the claim's refusals and
    /// storage faults.
    fn park_timer(
        &self,
        stage_name: &SmolStr,
        lowered: &LoweredOperation,
        sleep: DurableSleep,
    ) -> KataResult<()> {
        let deadline = durable_sleep_deadline(stage_name, sleep)?;
        let spec = MainAttemptSpec {
            stage_id: stage_name.to_string(),
            occurrence: OccurrenceBinding::new(
                occurrence_for(
                    &self.execution_program,
                    ExecutionId(self.execution_id),
                    lowered,
                ),
                None,
                None,
            ),
        };
        let attempt_id = Ulid::new();
        match self
            .dispatcher
            .execution_lifecycle()
            .db()
            .claim_main_attempt(attempt_id, &spec, MainWait::Timer(deadline))?
        {
            MainClaimOutcome::Claimed {
                claim_seq,
                wait_deadline_ms,
                ..
            } => info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                %attempt_id,
                claim_seq,
                ?wait_deadline_ms,
                "runner: parked a durable timer main-side"
            ),
            MainClaimOutcome::AlreadyLive {
                attempt_id,
                state: AttemptLifecycle::AwaitingTimer,
            } => info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                %attempt_id,
                "runner: a re-presented timer converged on its parked attempt; still in flight"
            ),
            MainClaimOutcome::AlreadyLive { attempt_id, state } => {
                return Err(KataError::Storage(format!(
                    "timer {stage_name}'s occurrence holds a LIVE main attempt {attempt_id} in \
                     `{}`; a timer is claimed parked in `awaiting_timer` and leaves it only by \
                     its resolution, so no writer leaves one elsewhere",
                    state.as_str()
                )));
            }
            MainClaimOutcome::AlreadyAccepted { attempt_id } => info!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                %attempt_id,
                "runner: a re-presented timer converged on its accepted resolution"
            ),
        }
        Ok(())
    }

    /// The stage a flat stage-segment `[index]` path names — the inverse the lowering's
    /// `join_inputs` minted it by (`operation_path_at(index)` over `program.stages`).
    fn stage_at_path(&self, join: &SmolStr, path: &OperationPath) -> KataResult<StageId> {
        let [coordinate] = path.0.as_slice() else {
            return Err(refused(&format!(
                "join {join}'s input path {:?} is not a stage coordinate",
                path.0
            )));
        };
        usize::try_from(*coordinate)
            .ok()
            .and_then(|index| self.execution_program.stages.keys().nth(index))
            .cloned()
            .ok_or_else(|| {
                refused(&format!(
                    "join {join}'s input path {:?} names no stage of this program",
                    path.0
                ))
            })
    }
}

/// THE OCI DIVERT's routing, reachable from this crate's integration tests.
///
/// For the reason `submit_stage_as_capsule_for_test` states: `submit_stage` is
/// `pub(in crate::runner)`. This door runs the divert's ROUTE and, for a main-resolved
/// operation, its RESOLUTION — every write the divert makes. It does NOT stand in for the
/// divert's CONDITION or its position in `submit_stage`; the whole-drive cell and the live
/// differential cover those through `WorkflowRunner::run`.
#[cfg(any(test, feature = "test-support"))]
impl WorkflowRunner {
    /// `Ok(true)` when the stage was resolved main-side, `Ok(false)` when it routed to the
    /// capsule path (which this door does not enter).
    ///
    /// # Errors
    ///
    /// [`WorkflowRunner::divert_under_capsule_profile`]'s, verbatim.
    #[doc(hidden)]
    pub fn divert_under_capsule_profile_for_test(&self, stage_name: &SmolStr) -> KataResult<bool> {
        Ok(matches!(
            self.divert_under_capsule_profile(stage_name)?,
            CapsuleProfileRoute::Resolved
        ))
    }
}
