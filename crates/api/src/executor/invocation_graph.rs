//! The execution record's agent-invocation graph, DERIVED from durable facts.
//!
//! Under the one engine no attempt writes an invocation row: a capsule or
//! main-resolved attempt is the invocation. [`derived_invocation_graph`] builds
//! one [`AgentInvocationRecord`] per attempt row whose stage the CHECKED
//! PROGRAM authorizes, from three durable sources only — the `attempts` row
//! (identity, lifecycle state, counters, timing anchors), the attempt's
//! occurrence path (member → parent), and the checked program's stage (kind,
//! role, agent label, model hint, timeout, progress visibility, owned paths).
//! Nothing is written; nothing is guessed:
//!
//! * no checked program → no graph (the caller passes none);
//! * an attempt whose `stage_id` no checked stage authorizes (`#apply/<stage>`
//!   work applies, `#op/…` joins and selects) → no node.
//!
//! A node carries no sandbox and no working tree: the checked stage carries a
//! sandbox REFERENCE resolved against node configuration at dispatch, and a
//! capsule runs on `/work`, never on a host working tree — neither is an
//! execution fact the record could read back.

use kata_core::{AgentInvocationGraph, AgentInvocationKind, AgentInvocationRecord};
use kata_program::execution_program::ExecutionProgram;
use kata_program::invocation_plan::InvocationRoleKind;
use kata_types::effect::EffectKind;
use kata_types::execution_contract::{OperationPath, parse_child_invocation_stage_name};
use kata_types::workflow::StageId;
use smol_str::SmolStr;
use ulid::Ulid;

/// The durable facts the derivation reads off ONE `attempts` row.
#[derive(Debug)]
pub(super) struct InvocationAttempt {
    pub(super) attempt_id: Ulid,
    pub(super) stage_id: String,
    /// The attempt projection's lifecycle state; `None` before the first fold.
    pub(super) state: Option<String>,
    pub(super) dispatched_at_ms: Option<i64>,
    pub(super) started_at_ms: Option<i64>,
    pub(super) finished_at_ms: Option<i64>,
    /// The bound occurrence's operation path.
    pub(super) path: OperationPath,
    /// The accepted output, when the attempt's occurrence has one.
    pub(super) output: Option<serde_json::Value>,
}

/// The graph of every attempt the checked program authorizes, or `None` when
/// there is none.
///
/// A member attempt (`<base>#child-<role>[-<label>]`) names as its parent the
/// `<base>` attempt at its expansion's ROOT coordinate (see [`parent_attempt`]),
/// so a fanout inside a loop iteration binds to that iteration's root and to no
/// other.
#[must_use]
pub(super) fn derived_invocation_graph(
    execution_id: Ulid,
    program: &ExecutionProgram,
    attempts: &[InvocationAttempt],
) -> Option<AgentInvocationGraph> {
    let records: Vec<(AgentInvocationRecord, Option<&serde_json::Value>)> = attempts
        .iter()
        .filter_map(|attempt| {
            let record = invocation_record(execution_id, program, attempts, attempt)?;
            Some((record, attempt.output.as_ref()))
        })
        .collect();
    let graph = kata_core::agent_invocation_graph_from_records(
        execution_id,
        records
            .iter()
            .map(|(record, output)| (record, None, *output)),
    );
    (!graph.is_empty()).then_some(graph)
}

/// The record ONE attempt derives, or `None` when no checked stage authorizes
/// its `stage_id`.
fn invocation_record(
    execution_id: Ulid,
    program: &ExecutionProgram,
    attempts: &[InvocationAttempt],
    attempt: &InvocationAttempt,
) -> Option<AgentInvocationRecord> {
    let stage_id = program.checked_stage_id_for_runtime_stage(&attempt.stage_id)?;
    let stage = program.stages.get(&stage_id)?;
    let envelope = &stage.invocation_envelope;
    let (role, parent_id) = match parse_child_invocation_stage_name(&attempt.stage_id) {
        Some((base, tail)) if base == stage_id.0 => (
            stage.child_role_for_runtime_tail(&tail)?,
            parent_attempt(attempts, &stage_id, &attempt.path),
        ),
        _ => (&envelope.root, None),
    };
    let agent_label = role.agent.clone().or_else(|| stage.op.agent_label.clone());
    Some(AgentInvocationRecord {
        id: attempt.attempt_id,
        parent_id,
        assignment_id: attempt.attempt_id,
        execution_id,
        stage_name: SmolStr::new(&attempt.stage_id),
        kind: invocation_kind(role.kind),
        role: role.role.clone(),
        effect_kind: Some(EffectKind::from_agent_label(agent_label.as_deref())),
        agent_label,
        topology_kind: Some(envelope.topology_kind.clone()),
        model_hint: stage.policies.model_hint.clone(),
        timeout_ms: Some(stage.policies.timeout_ms),
        progress_visibility: stage.policies.progress_visibility,
        owned_paths: stage.produces_files.clone(),
        sync_with_assignment: true,
        status: kata_core::invocation_status_for(attempt.state.as_deref().unwrap_or("pending")),
        created_at_ms: attempt.attempt_id.timestamp_ms(),
        dispatched_at_ms: millis(attempt.dispatched_at_ms),
        started_at_ms: millis(attempt.started_at_ms),
        finished_at_ms: millis(attempt.finished_at_ms),
    })
}

/// The `<base>` attempt that is `member`'s expansion ROOT: an expansion's
/// member `m` sits at `expansion.child(m)` and its root (member 0, the base
/// stage's own capsule) at `expansion.child(0)`. A path with no member
/// coordinate, or one whose coordinate is 0 (the root itself), names no parent.
/// When the root was retried, the LATEST attempt at that path — the one whose
/// output minted the members — is the parent (`attempts` is in ordinal order).
fn parent_attempt(
    attempts: &[InvocationAttempt],
    base: &StageId,
    member: &OperationPath,
) -> Option<Ulid> {
    let (&coordinate, expansion) = member.0.split_last()?;
    if coordinate == 0 {
        return None;
    }
    attempts
        .iter()
        .rev()
        .find(|candidate| {
            candidate.stage_id == base.0.as_str()
                && candidate.path.0.split_last() == Some((&0, expansion))
        })
        .map(|candidate| candidate.attempt_id)
}

fn invocation_kind(kind: InvocationRoleKind) -> AgentInvocationKind {
    match kind {
        InvocationRoleKind::Root => AgentInvocationKind::Root,
        InvocationRoleKind::Worker => AgentInvocationKind::Worker,
        InvocationRoleKind::Reviewer => AgentInvocationKind::Reviewer,
        InvocationRoleKind::Stage => AgentInvocationKind::Stage,
    }
}

fn millis(value: Option<i64>) -> Option<u64> {
    value.and_then(|ms| u64::try_from(ms).ok())
}
