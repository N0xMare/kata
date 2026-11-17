//! ExecutionRecord aggregation from live assignment state.

use kata_program::execution_program::ExecutionProgram;
use kata_types::execution::{ExecutionProgramIdentity, ExecutionRecord, ExecutionStatus};
use std::collections::BTreeMap;

use super::evidence_merge::{
    closeout_evidence_from_assignments, controller_decision_evidence_from_assignments,
    execution_evidence_from_records, merge_check_artifact_evidence,
    merge_validation_report_evidence, validation_evidence_from_assignments,
};
use super::worker_selection::failure_message;

/// Aggregate every `ChainAssignmentState` for a single execution into one
/// `ExecutionRecord`. Pure function — no I/O, no locks.
///
/// `ExecutionRecord` itself lives in [`kata_types::execution`], but this
/// constructor stays in `kata-api` because it depends on
/// [`kata_workflow::attempt_delivery::ChainAssignmentState`] / [`kata_types::ledger::AssignmentStatus`],
/// which carry the SQLite ledger and dispatcher dependencies that
/// `kata-types` deliberately does not pull in. With the type living in
/// another crate an inherent impl is not legal, so this is a free function.
///
/// `execution_id` is the canonical grouping key; `workflow_name` must
/// be passed in by the caller because it isn't carried on
/// `ChainAssignmentState` (the name lives on the `WorkflowDefinition` the
/// runner was built from).
///
/// Empty lifecycle input yields an empty `Pending` record — the convention the
/// HTTP layer uses for "submitted but no real stage assignments have landed
/// yet." Kata-reserved execution metadata assignments may still be projected
/// into `ExecutionRecord.evidence`, but they do not affect lifecycle status,
/// worker attribution, timing, cost, or outputs.
///
/// Aggregation rules (priority order, highest wins):
/// - any `Failed` or `Orphaned` assignment -> `Failed`
/// - empty lifecycle input -> `Pending`
/// - every assignment `Completed` -> `Completed`
/// - any `Running` or `Dispatched` -> `Running`
/// - else (all `Pending`) -> `Pending`
///
/// Input is sorted by `stage_name` up front so every "first-in-order"
/// decision (worker attribution, failure message) is deterministic
/// regardless of how the caller obtained the vec — without this sort,
/// `GET /executions/{id}` could return a different error message on
/// successive polls.
///
/// Also includes typed execution-level evidence rows from the ledger metadata
/// plane, and the CHECKED PROGRAM whose `validation_criterion(stage = ..)`
/// declarations decide which completed stage's output projects as validation
/// evidence.
///
/// `checked_program: None` projects NO validation evidence from assignment rows
/// — fail-closed. The durable validation-report rows the RUNNER wrote are
/// unaffected: they arrive through `typed_evidence`, not through this
/// projection.
#[must_use]
pub fn execution_record_from_assignments_with_program_and_evidence(
    execution_id: ulid::Ulid,
    workflow_name: String,
    execution_program: Option<ExecutionProgramIdentity>,
    checked_program: Option<&ExecutionProgram>,
    mut assignments: Vec<kata_workflow::attempt_delivery::ChainAssignmentState>,
    typed_evidence: Vec<kata_core::ExecutionEvidenceRecord>,
) -> ExecutionRecord {
    assignments.sort_by(|a, b| a.stage_name.cmp(&b.stage_name));
    let lifecycle_assignments = assignments.clone();

    // submitted_at_ms is recovered from the Ulid's embedded
    // timestamp — execution_ids are minted at submit time, so
    // this avoids needing a separate ledger field.
    let submitted_at_ms = ulid::Ulid::timestamp_ms(&execution_id);
    let id = execution_id.to_string();
    let mut evidence = execution_evidence_from_records(&typed_evidence);
    for report in validation_evidence_from_assignments(checked_program, &lifecycle_assignments) {
        for artifact in &report.check_artifacts {
            merge_check_artifact_evidence(&mut evidence.check_artifacts, artifact.clone());
        }
        merge_validation_report_evidence(&mut evidence.validation_reports, report);
    }
    evidence
        .closeout_reports
        .extend(closeout_evidence_from_assignments(&lifecycle_assignments));
    evidence
        .controller_decisions
        .extend(controller_decision_evidence_from_assignments(
            &lifecycle_assignments,
        ));
    let execution_program = execution_program.or_else(|| evidence.execution_program.clone());

    if lifecycle_assignments.is_empty() {
        return ExecutionRecord {
            id,
            workflow_name,
            execution_program,
            status: ExecutionStatus::Pending,
            submitted_at_ms,
            started_at_ms: None,
            finished_at_ms: None,
            worker_id: "pending".to_string(),
            outputs: None,
            error: None,
            running_cost_micro_usd: 0,
            child_cost_micro_usd: 0,
            metering: kata_types::metering::MeteringSummary::default(),
            warnings: Vec::new(),
            agent_invocation_graph: None,
            evidence,
            routing: Vec::new(),
            capsule_networks: Vec::new(),
            target: None,
        };
    }

    let (status, terminal_detail_idx) = aggregate_status(&lifecycle_assignments);

    let started_at_ms = lifecycle_assignments
        .iter()
        .filter_map(|s| s.started_at_ms)
        .min();

    let finished_at_ms = if status.is_terminal() {
        lifecycle_assignments
            .iter()
            .filter_map(|s| s.finished_at_ms)
            .max()
    } else {
        None
    };

    let worker_id = lifecycle_assignments
        .iter()
        .find_map(|s| s.status.worker_id().map(ToString::to_string))
        .unwrap_or_else(|| "pending".to_string());

    let outputs = if matches!(status, ExecutionStatus::Completed) {
        collect_outputs(&lifecycle_assignments)
    } else {
        None
    };

    // A cancelled record carries no error of its own — but the chain's cancel
    // reason is the reason it ended, so it rides `error` when one was given.
    let error = if matches!(status, ExecutionStatus::Failed | ExecutionStatus::Cancelled) {
        terminal_detail_idx.and_then(|idx| failure_message(&lifecycle_assignments[idx]))
    } else {
        None
    };

    // Cumulative running cost. Sum the per-stage `cost_micro_usd`
    // embedded in each Completed assignment's output JSON (set by the
    // executor alongside the `token_usage` blob) PLUS every failed/cancelled/orphaned assignment's
    // `terminal_charge`, so a stage that billed before ending is charged exactly what a completed
    // one is. Only in-flight assignments contribute 0 — an LLM response has no known cost until a
    // terminal records it. `cost_micro_usd` is ABSENT (not `0`) on a stage whose cost the worker
    // could not determine, so `and_then(as_u64)` skips it and this stays a sum of KNOWN costs. That
    // is the honest arithmetic — and it is a LOWER BOUND whenever `metering.unmetered_stages > 0`,
    // which is exactly why the summary below has to travel with the number rather than beside it in
    // a log.
    //
    // Read through `envelope_cost_micro_usd`, the ONE sum every reader
    // shares, so an `Invoke` stage's `child_invocation_summary.token_usage.
    // cost_micro_usd` charges the parent's record exactly as it charged the
    // parent's budget fold: the child's known spend is part of what this
    // execution spent. A FAILED/CANCELLED/ORPHANED stage's `terminal_charge`
    // re-expressed through `TerminalCharge::envelope()` — the same reader —
    // means a stage that provably billed before ending is charged here too.
    let running_cost_micro_usd: u64 = lifecycle_assignments
        .iter()
        .map(|s| {
            s.output
                .as_ref()
                .map_or(0, kata_types::metering::envelope_cost_micro_usd)
                .saturating_add(s.terminal_charge.as_ref().map_or(0, |charge| {
                    kata_types::metering::envelope_cost_micro_usd(&charge.envelope())
                }))
        })
        .sum();
    // The child half of the same sum, read by the same envelope reader, so a sum
    // across records can count a child's spend once (`own_cost_micro_usd`).
    let child_cost_micro_usd: u64 = lifecycle_assignments
        .iter()
        .map(|s| {
            s.output
                .as_ref()
                .map_or(0, kata_types::metering::envelope_child_cost_micro_usd)
                .saturating_add(s.terminal_charge.as_ref().map_or(0, |charge| {
                    kata_types::metering::envelope_child_cost_micro_usd(&charge.envelope())
                }))
        })
        .sum();

    // The QUALITY of that sum, projected onto the record an operator
    // reads. Derived from the same durable assignment outputs, so it cannot
    // disagree with the number it qualifies.
    let metering = metering_summary(&lifecycle_assignments);

    // Operator-actionable warnings. The WALK-AWAY is what this array carries —
    // see [`walkaway_halt_warnings`].
    //
    // There is no "declared more stages than dispatched" warning: a branch
    // workflow legitimately leaves a declared arm undispatched.
    // Unmetered stages ride the same carrier for the same reason: `warnings`
    // is derived from the durable rows and no lifecycle arm rewrites it, so an
    // unmeterable stage survives a clobber of any field that a lifecycle read
    // reassigns. A count on `metering` tells an operator THAT it happened; the
    // warning line tells them which stage and what to do about it.
    let mut warnings: Vec<String> = walkaway_halt_warnings(&lifecycle_assignments);
    warnings.extend(metering.warnings());
    ExecutionRecord {
        id,
        workflow_name,
        execution_program,
        status,
        submitted_at_ms,
        started_at_ms: started_at_ms.and_then(|v| u64::try_from(v).ok()),
        finished_at_ms: finished_at_ms.and_then(|v| u64::try_from(v).ok()),
        worker_id,
        outputs,
        error,
        running_cost_micro_usd,
        child_cost_micro_usd,
        metering,
        warnings,
        // The invocation graph is DERIVED from the attempt rows and the checked
        // program by the executor's record read (`invocation_graph`), not folded
        // from these assignments: no attempt writes an invocation row.
        agent_invocation_graph: None,
        evidence,
        routing: Vec::new(),
        capsule_networks: Vec::new(),
        target: None,
    }
}

/// Fold every completed assignment's `token_usage.cost` into the
/// execution's [`MeteringSummary`].
///
/// Reads the SAME durable assignment outputs `running_cost_micro_usd` sums, so
/// the quality and the number are two projections of one source and cannot
/// drift.
///
/// A stage whose output carries no `cost` object at all — a synthetic
/// assignment the worker never produced — is SKIPPED rather than counted as
/// unmetered. Counting it would make such an execution report itself
/// unmeasurable and (under a hard policy) halt, which is a false positive in the
/// direction that costs an operator a working run. Its `cost_micro_usd`, if
/// present, still sums.
fn metering_summary(
    assignments: &[kata_workflow::attempt_delivery::ChainAssignmentState],
) -> kata_types::metering::MeteringSummary {
    let mut summary = kata_types::metering::MeteringSummary::default();
    for state in assignments {
        if let Some(output) = state.output.as_ref() {
            if let Some(cost) = output
                .get("token_usage")
                .and_then(|tu| tu.get("cost"))
                .and_then(|c| {
                    serde_json::from_value::<kata_types::metering::MeteredCost>(c.clone()).ok()
                })
            {
                summary.fold(&state.stage_name, &cost);
            }
            // An `Invoke` stage's `child_invocation_summary.metering` is the
            // child execution's own quality rollup. It reaches the parent's record
            // under the parent's stage name as the path prefix, so an unmeterable
            // call a child made shows on this record as `<parent>/<child stage>`
            // rather than vanishing into the child's lower bound.
            if let Some(nested) = output
                .get("child_invocation_summary")
                .and_then(|cs| cs.get("metering"))
                .and_then(|m| {
                    serde_json::from_value::<kata_types::metering::MeteringSummary>(m.clone()).ok()
                })
            {
                summary.absorb(&state.stage_name, &nested);
            }
        }
        // A terminal charge carries the SAME two facts on the same
        // fields: the stage's own `token_usage.cost` folded under its name,
        // and the `child_invocation_summary.metering` of a child execution it
        // invoked absorbed beneath it — so a failed `Invoke` parent's record
        // shows the child's unmetered stages exactly as a completed one's
        // does.
        if let Some(charge) = state.terminal_charge.as_ref() {
            if let Some(usage) = charge.token_usage.as_ref() {
                summary.fold(&state.stage_name, &usage.cost);
            }
            if let Some(nested) = charge
                .child_invocation_summary
                .as_ref()
                .and_then(|summary| summary.metering.as_ref())
            {
                summary.absorb(&state.stage_name, nested);
            }
        }
    }
    summary
}

/// Marker prefix every walk-away warning carries, so a script can grep one
/// string rather than parse prose.
pub const WALKAWAY_HALT_WARNING_PREFIX: &str = "walk_away_halt:";

/// Marker prefix of the warning a record carries when this binary cannot read the
/// execution's durable checked program (an older or future checked-program schema,
/// undecodable bytes, a body that does not bind its hash). Every projection the
/// program binds is absent from such a record, and without this warning the
/// absence would be silent: a finished execution would read as one that had no
/// validation evidence, routes or invocation graph at all.
pub const CHECKED_PROGRAM_UNREADABLE_WARNING_PREFIX: &str = "checked_program_unreadable:";

/// Name each WALK-AWAY halt row this execution carries, as an operator-facing
/// warning.
///
/// # Why the warning exists when `status` already says `Failed`
///
/// Because `status` is CLOBBERABLE: `aggregate_status` derives `Failed` from
/// exactly these rows, and [`super::WorkflowExecutor::try_get_execution_by_ulid`]
/// then reconciles `record.status` with the operational lifecycle. `warnings` is
/// derived HERE, from the durable rows, and no lifecycle arm rewrites it. So the
/// one fact an unattended operator most needs — *this run stopped early on a
/// guard you set* — survives on a second, independently-derived field rather
/// than resting entirely on one.
///
/// # It also carries what no other field can
///
/// The stages downstream of a halt are never dispatched, so they hold no
/// assignment row: they are ABSENT from `outputs` and from
/// `agent_invocation_graph` rather than present-and-skipped. Nothing else on the
/// record says work was dropped, so the warning says it.
///
/// Row identification is [`kata_types::bound::is_walkaway_halt_row`] — the SAME
/// predicate `kata_workflow`'s writers and idempotence check use, not a second
/// spelling of the two markers; the predicate lives in the lowest crate both
/// sides share. The `#` sentinel is reserved
/// for synthetic rows, so a declared stage can never collide with one.
fn walkaway_halt_warnings(
    assignments: &[kata_workflow::attempt_delivery::ChainAssignmentState],
) -> Vec<String> {
    assignments
        .iter()
        .filter_map(|state| {
            let name = state.stage_name.as_str();
            if !kata_types::bound::is_walkaway_halt_row(name) {
                return None;
            }
            let kata_types::ledger::AssignmentStatus::Failed { reason, .. } = &state.status else {
                return None;
            };
            Some(format!(
                "{WALKAWAY_HALT_WARNING_PREFIX} stage `{name}`: {reason}. Stages downstream of \
                 the halt were never dispatched, so they are absent from this record."
            ))
        })
        .collect()
}

/// Classify a non-empty `assignments` slice into an aggregate
/// `ExecutionStatus`, alongside the index of the entry the caller builds the
/// error message from — the first `Cancelled` when the aggregate is
/// `Cancelled`, else the first `Failed`/`Orphaned` (if any).
///
/// `Cancelled` wins over `Failed`/`Orphaned` for the same reason it wins in
/// `terminal_lifecycle_for_run`: the execution's terminal intent is the
/// operator's stop, and that is a public status, so
/// the two derivations must agree on the same rows.
///
/// # One row per SEAT, one verdict per STAGE
///
/// A stage's capsule retry chain mints one durable attempt row per seat
/// (`capsule_failure_retry`'s `stage_path.child(k)`); each folds its own
/// terminal — a `failed` seat the retry superseded is durable TRUTH and the
/// fold reports it as `Failed`, but it is not the stage's outcome: only the
/// chain HEAD — the seat whose last lifecycle frame is latest — speaks for
/// the stage. Aggregating per row therefore double-counts history: a stage
/// whose seat 0 failed and whose retried seat 1 completed would read `Failed`
/// even though the stage completed — the exact misreport
/// `a_failed_panel_member_retries_on_the_next_panel_agent_live` asserts
/// against. The collapse keys on `stage_name`: same-named rows are seats of
/// one chain by construction — fanout children, loop iterations and the
/// synthetic `#…` rows all carry unique names (`seen_stage_names`,
/// `<base>#iter-N`), so nothing unrelated can fold together — and orders them
/// by `settled_seq`, the authority sequence of each row's own last lifecycle
/// frame. Every other consumer stays per row: outputs fold the completing
/// seat's `Completed`, cost sums every terminal's charge, and the invocation
/// graph keeps every seat.
pub(super) fn aggregate_status(
    assignments: &[kata_workflow::attempt_delivery::ChainAssignmentState],
) -> (ExecutionStatus, Option<usize>) {
    let mut any_failed_or_orphaned = false;
    let mut any_cancelled = false;
    let mut all_completed = true;
    let mut any_running_or_dispatched = false;
    let mut first_failure_idx: Option<usize> = None;
    let mut first_cancelled_idx: Option<usize> = None;

    // The chain head of each stage — the row its latest lifecycle frame wrote.
    // `into_values` yields the heads keyed by stage name, so `sort_unstable`
    // puts them back in the slice's own order and keeps every
    // "first-in-order" tie-break deterministic exactly as the un-collapsed
    // iteration's was.
    let mut heads: BTreeMap<&str, usize> = BTreeMap::new();
    for (idx, state) in assignments.iter().enumerate() {
        heads
            .entry(state.stage_name.as_str())
            .and_modify(|head| {
                if state.settled_seq > assignments[*head].settled_seq {
                    *head = idx;
                }
            })
            .or_insert(idx);
    }
    let mut head_order: Vec<usize> = heads.into_values().collect();
    head_order.sort_unstable();

    for idx in head_order {
        let state = &assignments[idx];
        match &state.status {
            kata_types::ledger::AssignmentStatus::Cancelled { .. } => {
                any_cancelled = true;
                all_completed = false;
                if first_cancelled_idx.is_none() {
                    first_cancelled_idx = Some(idx);
                }
            }
            kata_types::ledger::AssignmentStatus::Failed { .. }
            | kata_types::ledger::AssignmentStatus::Orphaned { .. } => {
                any_failed_or_orphaned = true;
                all_completed = false;
                if first_failure_idx.is_none() {
                    first_failure_idx = Some(idx);
                }
            }
            kata_types::ledger::AssignmentStatus::Completed { .. } => {}
            // `AwaitingApproval` folds into the same "running-ish"
            // bucket so an execution with a gated stage surfaces as
            // `running` (not `pending`) — the
            // execution really is in progress, it's just waiting on
            // an operator instead of a worker.
            kata_types::ledger::AssignmentStatus::Running { .. }
            | kata_types::ledger::AssignmentStatus::Dispatched { .. }
            | kata_types::ledger::AssignmentStatus::AwaitingApproval { .. }
            // A parent parked awaiting a child execution is in progress
            // (the child-completion sweep re-dispatches it), so the execution
            // reads `running` while the subworkflow runs.
            | kata_types::ledger::AssignmentStatus::AwaitingChildCompletion { .. }
            | kata_types::ledger::AssignmentStatus::Stalled { .. } => {
                all_completed = false;
                any_running_or_dispatched = true;
            }
            kata_types::ledger::AssignmentStatus::Pending => {
                all_completed = false;
            }
        }
    }

    let (status, detail_idx) = if any_cancelled {
        (ExecutionStatus::Cancelled, first_cancelled_idx)
    } else if any_failed_or_orphaned {
        (ExecutionStatus::Failed, first_failure_idx)
    } else if all_completed {
        (ExecutionStatus::Completed, None)
    } else if any_running_or_dispatched {
        (ExecutionStatus::Running, None)
    } else {
        (ExecutionStatus::Pending, None)
    };
    (status, detail_idx)
}

/// Build the `outputs` map from every `Completed` assignment.
/// `None` outputs materialise as `serde_json::Value::Null` so the
/// stage key is still present in the response. Returns `None` if no
/// assignment was `Completed`.
pub(super) fn collect_outputs(
    assignments: &[kata_workflow::attempt_delivery::ChainAssignmentState],
) -> Option<BTreeMap<String, serde_json::Value>> {
    let map: BTreeMap<String, serde_json::Value> = assignments
        .iter()
        .filter(|s| {
            matches!(
                s.status,
                kata_types::ledger::AssignmentStatus::Completed { .. }
            )
        })
        .map(|s| {
            (
                s.stage_name.to_string(),
                s.output.clone().unwrap_or(serde_json::Value::Null),
            )
        })
        .collect();
    if map.is_empty() { None } else { Some(map) }
}
