//! `branch()` ROUTING under the `oci` execution profile.
//!
//! # What is accepted, exactly once
//!
//! A route's DECISION is a logical execution of its own: the `Select` operation the
//! checked lowerer mints for `branch_routes[j]` at `operation_path_at(stage_count + j)`.
//! Under this profile it is accepted through the ONE acceptance door, as the
//! outcome of a MAIN-RESOLVED attempt claimed and resolved in one transaction
//! (`OperationalDb::claim_and_resolve_main_attempt`). Its output is a
//! [`SelectRecord`]: the verdict, the taken arm, and every skipped target.
//!
//! The SKIPPED STAGES ARE NOT OCCURRENCES. An occurrence is a logical execution, and a
//! skipped stage has none; minting a "skipped" acceptance per target would fabricate an
//! outcome for work that never ran, at N writes and N crash windows. Skips are applied in
//! memory by the orchestrator's existing `skip_stage` + `skip_dependents`, from the ONE
//! accepted record, and re-derived from it on every replay.
//!
//! # The durable decision is authoritative
//!
//! [`WorkflowRunner::resolve_selects_for_condition`] recomputes the decision from the
//! condition's envelope every time the condition's completion folds, and then:
//!
//! * an ACCEPTED `Select` is read and applied — it is never re-resolved; a recomputed
//!   decision that disagrees with it is refused `select_decision_diverged` rather than
//!   silently preferred in either direction;
//! * a `Select` that already resolved WITHOUT an acceptance (a verdict that decided
//!   nothing, resolved `failed`) is not claimed again;
//! * otherwise it is claimed and resolved once.
//!
//! A storage error resolving it propagates out of the fold, so no arm target is ever
//! submitted on an undecided route.
//!
//! # Replay
//!
//! Nothing is re-derived outside the fold. The condition's `Completed` frame re-runs the
//! read path above, and the `Select`'s own frames (`#op/<path>`) are intercepted at the top
//! of the fold ([`WorkflowRunner::fold_program_operation`]): a `Completed` re-applies its
//! record's skips idempotently, a `Failed`/`Cancelled` records the failed operation and
//! skips the condition's dependents. So resume needs no separate branch-skip
//! reconstruction.
//!
//! # A failed route fails the run
//!
//! A `Select` resolved `failed` (`select_verdict_unreadable`, `select_verdict_unmatched`)
//! is recorded in `WorkflowRunner::failed_program_operations`, which `collect_failures`
//! reports, so the run fails. Both
//! refusals are unreachable from a checked pack (load-time exhaustiveness plus
//! output-schema validation); they are defences. The one verdict a route reads that
//! is not the condition stage's own output, the refine tag an accepted loop
//! exhaustion routes under an unmet quorum (`route_accepted_exhaustion`), is kept
//! inside the route's arm tags by CHECK's `loop_accept_quorum_route_needs_refine_tag`,
//! which refuses the pack rather than letting such a route skip its arms.

use kata_core::operational::{
    AttemptExecutor, AttemptLifecycle, MainAttemptSpec, MainClaimAndResolveOutcome, MainOperation,
    MainResolution, OccurrenceBinding, OccurrenceSettlement,
};
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{OccurrenceRef, OperationPath};
use kata_types::workflow::{BranchRoute, ExecutionId};
use smol_str::SmolStr;
use ulid::Ulid;

use super::WorkflowRunner;
use crate::attempt_delivery::FoldOutcome;
use kata_program::execution_program::select::{SelectRecord, SelectRefusal, select_decision};
use kata_program::execution_program::{
    ExecutionProgram, lower_branch_route, lower_stage_operation,
};

/// A recomputed route decision disagrees with the durable one.
const SELECT_DECISION_DIVERGED: &str = "select_decision_diverged";

/// What one route's `Select` durably concluded.
enum Resolved {
    /// Accepted with this record.
    Decided(SelectRecord),
    /// Resolved without an acceptance, for this reason.
    Failed(String),
}

impl WorkflowRunner {
    /// Route the verdict of `completed_stage`, which just completed with `envelope`.
    ///
    /// Resolves each route's `Select` occurrence against the completion envelope.
    pub(super) fn route_after_completion(
        &self,
        completed_stage: &SmolStr,
        envelope: &serde_json::Value,
    ) -> KataResult<()> {
        self.resolve_selects_for_condition(completed_stage, envelope)
    }

    /// Resolve — or read, if already resolved — the `Select` of every route whose
    /// condition is `condition`, and apply each one's durable conclusion.
    ///
    /// # Errors
    ///
    /// A route that does not lower; a plane read or write failure; a durable record that
    /// does not decode; and [`SELECT_DECISION_DIVERGED`]. Each propagates out of the fold,
    /// so no arm of an undecided route is submitted.
    pub(super) fn resolve_selects_for_condition(
        &self,
        condition: &SmolStr,
        envelope: &serde_json::Value,
    ) -> KataResult<()> {
        for (index, route) in self.execution_program.branch_routes.iter().enumerate() {
            if route.condition_stage.0 != *condition {
                continue;
            }
            self.resolve_route(index, route, envelope)?;
        }
        Ok(())
    }

    /// Resolve — or read — `branch_routes[index]`'s `Select` against `envelope` and
    /// apply its durable conclusion: the per-route step of
    /// [`Self::resolve_selects_for_condition`].
    ///
    /// # Errors
    ///
    /// As [`Self::resolve_selects_for_condition`].
    pub(super) fn resolve_route(
        &self,
        index: usize,
        route: &BranchRoute,
        envelope: &serde_json::Value,
    ) -> KataResult<()> {
        match self.resolve_select(index, route, envelope)? {
            Resolved::Decided(record) => self.apply_select_skips(&record),
            Resolved::Failed(reason) => self.record_failed_select(index, route, reason)?,
        }
        Ok(())
    }

    fn resolve_select(
        &self,
        index: usize,
        route: &BranchRoute,
        envelope: &serde_json::Value,
    ) -> KataResult<Resolved> {
        let (occurrence, path) = self.select_occurrence(index)?;
        let recomputed = match select_decision(route, envelope) {
            Ok(decision) => Ok(SelectRecord::new(
                route,
                self.condition_occurrence(route)?,
                &decision,
            )),
            Err(refusal) => Err(failure_reason(route, &refusal)),
        };
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());

        // The durable conclusion, if there is one, is authoritative.
        if let Some(durable) = self.durable_select(&occurrence, &path)? {
            return agree(&path, durable, recomputed);
        }

        let attempt_id = Ulid::new();
        let spec = MainAttemptSpec {
            stage_id: path.program_operation_stage_id(),
            occurrence: OccurrenceBinding::new(occurrence.clone(), None, None),
        };
        let output;
        let resolution = match &recomputed {
            Ok(record) => {
                output = record.to_output();
                MainResolution::Complete { output: &output }
            }
            Err(reason) => MainResolution::Fail {
                reason,
                terminal_charge: None,
            },
        };
        match db.claim_and_resolve_main_attempt(
            attempt_id,
            &spec,
            MainOperation::Select,
            &resolution,
        )? {
            MainClaimAndResolveOutcome::Resolved { .. } => {
                tracing::info!(
                    execution_id = %self.execution_id,
                    condition = %route.condition_stage.0,
                    %attempt_id,
                    operation = %spec.stage_id,
                    accepted = recomputed.is_ok(),
                    "branch route: resolved its Select occurrence"
                );
                Ok(match recomputed {
                    Ok(record) => Resolved::Decided(record),
                    Err(reason) => Resolved::Failed(reason),
                })
            }
            // Another resolver committed between the read above and this claim: read
            // what it committed, and hold it to the same agreement.
            MainClaimAndResolveOutcome::AlreadyAccepted { .. } => {
                let durable = self.durable_select(&occurrence, &path)?.ok_or_else(|| {
                    KataError::Storage(format!(
                        "operational.db answered that Select {} is accepted and holds no \
                         accepted outcome for it",
                        spec.stage_id
                    ))
                })?;
                agree(&path, durable, recomputed)
            }
            MainClaimAndResolveOutcome::AlreadyLive { attempt_id, state } => {
                Err(KataError::Storage(format!(
                    "Select {} has a LIVE main attempt {attempt_id} in `{}`; a Select is claimed \
                     and resolved in one transaction, so no Select attempt is ever live",
                    spec.stage_id,
                    state.as_str()
                )))
            }
            // `resolve_join`'s answers: a recorded terminal verdict is a join's
            // (`work_fanin_conflict`), which `claim_and_resolve_main_attempt`
            // never answers — a Select that resolved `failed` reads as `Resolved`.
            MainClaimAndResolveOutcome::ResolvedFailed { .. }
            | MainClaimAndResolveOutcome::AlreadyResolvedTerminal { .. } => {
                Err(KataError::Storage(format!(
                    "Select {}'s claim-and-resolve answered a recorded-verdict outcome, \
                     which `resolve_join` alone produces",
                    spec.stage_id,
                )))
            }
        }
    }

    /// The `Select` occurrence of route `index` and its path.
    fn select_occurrence(&self, index: usize) -> KataResult<(OccurrenceRef, OperationPath)> {
        let lowered = lower_branch_route(&self.execution_program, index).map_err(|error| {
            KataError::Validation(format!(
                "branch route {index} does not lower to a Select operation: {error:?}"
            ))
        })?;
        Ok((
            OccurrenceRef::new(
                ExecutionId(self.execution_id),
                self.execution_program.program_hash,
                lowered.contract.id(),
                lowered.path.clone(),
            ),
            lowered.path,
        ))
    }

    /// The condition stage's occurrence, rendered — the logical execution the decision
    /// was made from.
    fn condition_occurrence(&self, route: &BranchRoute) -> KataResult<String> {
        let lowered = lower_stage_operation(&self.execution_program, &route.condition_stage)
            .map_err(|error| {
                KataError::Validation(format!(
                    "branch condition stage {:?} does not lower: {error:?}",
                    route.condition_stage.0
                ))
            })?;
        Ok(OccurrenceRef::new(
            ExecutionId(self.execution_id),
            self.execution_program.program_hash,
            lowered.contract.id(),
            lowered.path,
        )
        .id()
        .0
        .to_string())
    }

    /// What the plane durably holds for this `Select`: its accepted record, or the reason
    /// its attempt resolved without an acceptance, or nothing.
    fn durable_select(
        &self,
        occurrence: &OccurrenceRef,
        path: &OperationPath,
    ) -> KataResult<Option<Resolved>> {
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let occurrence_id = occurrence.id().0.0;
        let Some(settlement) = db.occurrence_settlement(occurrence_id)? else {
            return Ok(None);
        };
        let attempts = match settlement {
            OccurrenceSettlement::Accepted { accepted, .. } => {
                let output = db
                    .accepted_attempt_output(self.execution_id, accepted.attempt_id)?
                    .ok_or_else(|| {
                        KataError::Storage(format!(
                            "Select {} is accepted and its accepting transition carries no output",
                            path.program_operation_stage_id()
                        ))
                    })?;
                return decode_record(path, &output).map(|record| Some(Resolved::Decided(record)));
            }
            OccurrenceSettlement::Unaccepted { attempts, .. } => attempts,
        };
        if let Some(failed) = attempts.iter().find(|attempt| {
            attempt.executor == AttemptExecutor::Main
                && matches!(
                    attempt.state,
                    AttemptLifecycle::Failed | AttemptLifecycle::Cancelled
                )
        }) {
            return Ok(Some(Resolved::Failed(format!(
                "Select {} resolved `{}` (attempt {}) without an acceptance",
                path.program_operation_stage_id(),
                failed.state.as_str(),
                failed.attempt_id
            ))));
        }
        Ok(None)
    }

    /// Skip every target a durable record names — `skip_stage` plus `skip_dependents`,
    /// both idempotent, so a replay and a re-fold converge on one state.
    fn apply_select_skips(&self, record: &SelectRecord) {
        for target in &record.not_taken_targets {
            let reason = format!(
                "branch not taken: condition {:?} verdict {:?} selected arm {:?}",
                record.condition_stage, record.verdict, record.taken
            );
            // A target already terminal is fine to leave; `skip_stage` refuses a terminal
            // source, so its error is ignored and the cascade still runs.
            let _ = self.orchestrator.skip_stage(target, reason);
            self.orchestrator.skip_dependents(target);
        }
    }

    /// Record route `index`'s `Select` as FAILED and skip its condition's dependents, so
    /// no arm runs and `collect_failures` fails the run.
    fn record_failed_select(
        &self,
        index: usize,
        route: &BranchRoute,
        reason: String,
    ) -> KataResult<()> {
        let (_, path) = self.select_occurrence(index)?;
        self.failed_program_operations
            .write()
            .insert(path.program_operation_stage_id(), reason);
        self.orchestrator
            .skip_dependents(route.condition_stage.0.as_str());
        Ok(())
    }

    /// FOLD one frame of a program-level operation's own attempt (`#op/<path>`).
    ///
    /// Intercepted at the top of the fold, before every stage-name route, because the
    /// name is no stage's: the structured-output door would otherwise refuse it as an
    /// unknown base stage. A `Completed` re-applies the accepted record's skips; a
    /// `Failed`/`Cancelled` records the failed operation; every other frame (the claim's
    /// `pending`) changes nothing.
    ///
    /// # Errors
    ///
    /// A path that is no route's `Select` in this program, and an accepted output that is
    /// not a [`SelectRecord`] for that route.
    pub(super) fn fold_program_operation(
        &self,
        path: &OperationPath,
        outcome: &FoldOutcome,
        outputs: &mut std::collections::BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        // A blocking human request's input wait is the other
        // program-level operation with frames (`runner::input_wait`). An
        // `ExpandBounded` is the third — its accepted record is applied
        // to the orchestrator inside `runner::expansion`.
        match kata_program::execution_program::program_operation_at(&self.execution_program, path) {
            Some(kata_program::execution_program::ProgramOperationAt::Input(_)) => {
                return self.fold_input_wait(path, outcome);
            }
            Some(kata_program::execution_program::ProgramOperationAt::Expansion(kind)) => {
                return self.fold_expansion(path, kind, outcome, outputs);
            }
            _ => {}
        }
        let index = self.select_route_index(path)?;
        let route = &self.execution_program.branch_routes[index];
        match outcome {
            FoldOutcome::Completed { output } => {
                let output = output.as_ref().ok_or_else(|| {
                    KataError::Internal(format!(
                        "Select {} completed with no output",
                        path.program_operation_stage_id()
                    ))
                })?;
                let record = decode_record(path, output)?;
                let selector =
                    kata_types::execution_contract::branch_route_selector(route).to_string();
                if record.route != selector {
                    return Err(diverged(
                        path,
                        &format!(
                            "its record names route {} and the program's route {index} is {selector}",
                            record.route
                        ),
                    ));
                }
                self.apply_select_skips(&record);
            }
            FoldOutcome::Failed { reason, .. } | FoldOutcome::Cancelled { reason, .. } => {
                self.record_failed_select(index, route, reason.clone())?;
            }
            FoldOutcome::Orphaned { .. }
            | FoldOutcome::Dispatched { .. }
            | FoldOutcome::AwaitingChildCompletion { .. }
            | FoldOutcome::AwaitingApproval { .. }
            | FoldOutcome::InFlight => {}
        }
        Ok(())
    }

    /// The route whose `Select` sits at `path`, or a refusal naming the path.
    fn select_route_index(&self, path: &OperationPath) -> KataResult<usize> {
        branch_route_index_at(&self.execution_program, path).ok_or_else(|| {
            KataError::Validation(format!(
                "program operation {} is no branch route's Select in this program ({} \
                     stages, {} routes)",
                path.program_operation_stage_id(),
                self.execution_program.stages.len(),
                self.execution_program.branch_routes.len()
            ))
        })
    }

    /// Every program-level operation that resolved FAILED, as `collect_failures` lines.
    pub(super) fn failed_program_operation_lines(&self) -> Vec<String> {
        self.failed_program_operations
            .read()
            .iter()
            .map(|(coordinate, reason)| {
                format!("program operation \"{coordinate}\" failed: {reason}")
            })
            .collect()
    }
}

/// The reason a `Select` that decided nothing resolves `failed` with.
fn failure_reason(route: &BranchRoute, refusal: &SelectRefusal) -> String {
    format!(
        "{}: {}",
        refusal.reason_code(),
        refusal.describe(&route.condition_stage)
    )
}

/// The index of the branch route whose `Select` sits at `path` in `program`, or `None` —
/// the `Select` arm of `program_operation_at`, the one inverse of the flat coordinate space
/// (`lower_branch_route` mints `operation_path_at(stage_count + j)`).
fn branch_route_index_at(program: &ExecutionProgram, path: &OperationPath) -> Option<usize> {
    // Through the ONE inverse of the flat coordinate space, so a route and an input wait
    // can never be told apart two ways.
    match kata_program::execution_program::program_operation_at(program, path)? {
        kata_program::execution_program::ProgramOperationAt::Select(index) => Some(index),
        kata_program::execution_program::ProgramOperationAt::Expansion(_)
        | kata_program::execution_program::ProgramOperationAt::Input(_) => None,
    }
}

fn decode_record(path: &OperationPath, output: &serde_json::Value) -> KataResult<SelectRecord> {
    SelectRecord::from_output(output).map_err(|error| {
        KataError::Storage(format!(
            "the accepted outcome of Select {} is not a Select record: {error}",
            path.program_operation_stage_id()
        ))
    })
}

fn diverged(path: &OperationPath, detail: &str) -> KataError {
    KataError::Validation(format!(
        "{SELECT_DECISION_DIVERGED}: Select {}: {detail}. The durable decision is \
         authoritative and a recomputed one that disagrees with it is refused, never applied \
         in its place",
        path.program_operation_stage_id()
    ))
}

/// Hold a recomputed decision to the durable one. Agreement returns the DURABLE one.
fn agree(
    path: &OperationPath,
    durable: Resolved,
    recomputed: Result<SelectRecord, String>,
) -> KataResult<Resolved> {
    match (durable, recomputed) {
        (Resolved::Decided(durable), Ok(recomputed)) if durable == recomputed => {
            Ok(Resolved::Decided(durable))
        }
        (Resolved::Decided(durable), Ok(recomputed)) => Err(diverged(
            path,
            &format!("accepted {durable:?}, recomputed {recomputed:?}"),
        )),
        (Resolved::Decided(durable), Err(reason)) => Err(diverged(
            path,
            &format!("accepted {durable:?}, and the recomputation decides nothing: {reason}"),
        )),
        (Resolved::Failed(durable), Err(_)) => Ok(Resolved::Failed(durable)),
        (Resolved::Failed(durable), Ok(recomputed)) => Err(diverged(
            path,
            &format!("{durable}, and the recomputation decides {recomputed:?}"),
        )),
    }
}

#[cfg(test)]
#[path = "select_tests.rs"]
mod tests;
