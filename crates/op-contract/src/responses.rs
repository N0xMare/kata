//! Typed response struct per class-A operation.
//!
//! Minimal + owned. The api/client MAY convert their richer projection types (e.g.
//! `kata_client::operator_projection::ExecutionExplainSummary`) into these owned structs. A
//! face envelopes only these (`crate::OpResponse`); a richer document of its own — the
//! CLI's `kata workflows check`, `kata explain`, `kata usage` — is emitted bare, never
//! tagged with an operation it is not the response of.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Default cap on the number of executions [`ListResponse`] returns when the
/// request omits `limit`.
pub const DEFAULT_LIST_LIMIT: u32 = 20;

/// Response for `Operation::Author`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuthorResponse {
    /// The config path that was created (or would be, under `print`).
    pub config: String,
    /// Whether a file was written (`false` under `print`).
    pub created: bool,
}

/// Response for `Operation::Check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CheckResponse {
    /// Workflow name.
    pub name: String,
    /// Whether the checked program passed the verifier (respecting
    /// `deny_warnings`).
    pub passed: bool,
    /// Verifier status label (`pass` / `warn` / `error`).
    pub status: String,
    /// Verifier error-diagnostic count.
    pub error_count: usize,
    /// Verifier warning-diagnostic count.
    pub warning_count: usize,
    /// Verifier info-diagnostic count.
    pub info_count: usize,
    /// The node-dependent fact classes this check DEFERRED — exactly the
    /// classes it did not judge: `agents` (`[agents]` declarations, credential
    /// pairings), `ceilings` (`[node] *_ceiling`) and `egress` (`[node]
    /// egress_allow`) when the process installed no node (`kata check` on a host
    /// with no booted node), `environment` (the bound environment's `PATH`
    /// programs) when it bound none — all judged at admission instead. Empty on
    /// a booted node.
    #[serde(default)]
    pub deferred_node_facts: Vec<String>,
    /// What each capsule-running stage's network will be on this node: one row
    /// per capsule a stage can run — a shell stage's one, an agent stage's
    /// primary then every fallback panel member, each naming its `agent`. Empty
    /// when the check ran
    /// with no node installed (see [`Self::deferred_node_facts`]), and for
    /// `all = true`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capsule_networks: Vec<StageCapsuleNetwork>,
}

/// One stage's capsule network, as the `check` and `observe` operations state
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StageCapsuleNetwork {
    /// The stage.
    pub stage: String,
    /// On a `check` row of an agent stage, the agent label the capsule runs
    /// under — the primary or a fallback panel member, each stated on its own
    /// row. Absent on a shell stage's row and on every `observe` row (which
    /// states each DECLARED capsule's own network, whichever member it ran).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// `offline`, or `egress` (authored `net = "host"`).
    pub posture: String,
    /// The exact `host:port` authorities the capsule may reach; empty for
    /// `offline`.
    pub allowlist: Vec<String>,
}

/// Response for `Operation::Run`.
///
/// `terminal` and `wait_timed_out` are what make a bounded
/// [`crate::requests::RunRequest::wait`] answerable WITHOUT string-matching
/// `status`. A wait that expires is reported here — a successful submission
/// whose observation was cut short — and never as an
/// [`crate::OpError`], which carries no data and would throw away the
/// `execution_id` the caller needs to resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunResponse {
    /// The submitted execution's id.
    pub execution_id: String,
    /// The execution status at return time.
    pub status: String,
    /// Whether `status` is a terminal state. Same word, same meaning as
    /// [`ObserveResponse::terminal`] — an agent reading both responses must not
    /// have to learn two vocabularies for one concept. Always `false` for a
    /// non-waiting run that has not yet been scheduled.
    pub terminal: bool,
    /// `true` ONLY when `wait` was requested and the bound elapsed with the
    /// execution still non-terminal. Never `true` for a run submitted without
    /// `wait`, and never `true` alongside `terminal: true`.
    pub wait_timed_out: bool,
}

/// Response for `Operation::Observe`.
///
/// Projects the engine's rich `ExecutionRecord` so a failed run's
/// response carries enough to DEBUG it (current/last stage, failure reason,
/// stage outputs, wave/iteration, terminal detail) rather than just a status
/// enum. No new engine state is invented here — every field is a projection of
/// data the executor already reconstructs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObserveResponse {
    /// Execution id.
    pub execution_id: String,
    /// Workflow name.
    pub workflow_name: String,
    /// Execution status label.
    pub status: String,
    /// Whether the execution has reached a terminal state.
    pub terminal: bool,
    /// Name of the stage currently dispatched/running, if any. `None` once
    /// the execution is terminal or before any stage has been observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_stage: Option<String>,
    /// Name of the most-recently-active stage observed for this execution
    /// (running or terminal), derived from the agent-invocation graph.
    /// `None` when no stage activity has been recorded yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_stage: Option<String>,
    /// The execution-level failure message on a failed run. `None` on
    /// success or while running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// Stage outputs recorded so far, keyed by stage name. Populated on a
    /// successful terminal execution; empty on failure or while running.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub stage_outputs: BTreeMap<String, serde_json::Value>,
    /// The wave id of the latest recorded controller decision, when this
    /// execution is part of an autonomous factory sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wave: Option<String>,
    /// Retry/resume iteration of the last-active stage (0 for a stage's first
    /// attempt), when a stage has been observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iteration: Option<u32>,
    /// A short human-readable summary of the terminal outcome. `None` while
    /// the execution is still pending/running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_detail: Option<String>,
    /// The network each capsule this execution declared was given, read off
    /// the declared capsule, one row per distinct (stage, network). Empty until
    /// a capsule is declared.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capsule_networks: Vec<StageCapsuleNetwork>,
}

/// One row of `Operation::List`'s enumeration — enough for an agent that lost
/// its `execution_id` to re-acquire it (id, status, workflow name, started).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionSummary {
    /// Execution id.
    pub execution_id: String,
    /// Workflow name.
    pub workflow_name: String,
    /// Execution status label.
    pub status: String,
    /// Milliseconds since UNIX epoch the execution was submitted.
    pub submitted_at_ms: u64,
}

/// Response for `Operation::List`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ListResponse {
    /// Recent executions, most-recently-submitted first, capped at the
    /// request's `limit` (or [`DEFAULT_LIST_LIMIT`]).
    pub executions: Vec<ExecutionSummary>,
}

/// Response for `Operation::Approve`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApproveResponse {
    /// Execution id whose gate was approved.
    pub execution_id: String,
    /// Whether the approval was applied.
    pub approved: bool,
}

/// Response for `Operation::Reject`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RejectResponse {
    /// Execution id whose gate was rejected.
    pub execution_id: String,
    /// Whether the rejection was applied.
    pub rejected: bool,
}

/// Response for `Operation::Cancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CancelResponse {
    /// Execution id the stop was asked for.
    pub execution_id: String,
    /// Whether at least one live attempt's worker was ASKED to stop.
    ///
    /// The field is deliberately not named `cancelled`. `true` means a stop frame reached a
    /// transport; it does NOT mean any work ended, and an operator who reads it as "cancelled" will
    /// believe a stage stopped while it is still running and still spending. Whether it actually
    /// stopped is the worker's own attempt-terminal frame, projected at
    /// `ExecutionRecord.evidence.worker_stops[].awaiting_worker_acknowledgement` and readable
    /// through the `observe` operation.
    ///
    /// `false` means there was nothing live to ask — a terminal execution, or one
    /// whose attempts hold no placement.
    pub stop_requested: bool,
}

/// Response for `Operation::Promote`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PromoteResponse {
    /// Execution id whose candidate was promoted.
    pub execution_id: String,
    /// Whether the promotion was applied.
    pub promoted: bool,
}

/// Response for `Operation::ForgeReconcile`: each pending export as the
/// reconcile left it, read back from the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ForgeReconcileResponse {
    /// Execution id whose exports were reconciled.
    pub execution_id: String,
    /// Every `forge_export` that was pending, in claim order.
    pub exports: Vec<ReconciledForgeExport>,
}

/// One `forge_export` as `Operation::ForgeReconcile` left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReconciledForgeExport {
    /// The export's attempt.
    pub attempt_id: String,
    /// Its stage.
    pub stage_id: String,
    /// The attempt's state afterwards: `pending` while an intent stays open,
    /// else how it resolved (`completed`, `failed`, `cancelled`).
    pub state: String,
    /// The attempt's last intent, as recorded; `None` when it recorded none.
    pub intent: Option<ReconciledForgeIntent>,
}

/// A forge intent as recorded, for `Operation::ForgeReconcile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReconciledForgeIntent {
    /// The effect's index within its attempt (the marker's `<index>`).
    pub effect_index: i64,
    /// `push` or `pull_request`.
    pub effect: String,
    /// `performed`, `not_performed` or `unclassified`; `None` while open.
    pub verdict: Option<String>,
    /// The observer's reads the remote left unanswered.
    pub unanswered_reads: u32,
    /// What the last unanswered read failed with.
    pub last_read_error: Option<String>,
    /// The error the effect's own command returned, if it returned one.
    pub command_error: Option<String>,
}

/// Response for `Operation::DischargeStop`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DischargeStopResponse {
    /// Execution id whose stop was addressed.
    pub execution_id: String,
    /// The attempt the discharged stop was addressed to.
    pub attempt_id: String,
    /// The generation the discharged stop was addressed to.
    pub lease_epoch: i64,
    /// Whether this call performed the discharge. `false` means it was already
    /// discharged by a BYTE-IDENTICAL earlier assertion — an operator surface's
    /// ordinary double-click, reported rather than hidden. A discharge already
    /// made by the WORKER is a refusal, not this.
    pub discharged: bool,
    /// Who asserted it, echoed back so the caller sees the attribution that
    /// actually landed (which on a re-submission is the FIRST one).
    pub operator: String,
    /// How the discharge was determined. Always `operator_asserted` — see
    /// `DischargeStopRequest` for why there is no probe mode.
    pub provenance: String,
    /// Whether the discharge rests on a machine PROOF. Always `false`, and carried
    /// explicitly rather than assumed: a consumer that re-derived it could invent
    /// its own reading, and the wrong reading here presents a human's judgement as
    /// the engine's confirmation.
    pub rests_on_a_proof: bool,
    /// The operator's own words, echoed from the durable record.
    pub assertion: String,
    /// How many of this execution's stops remain outstanding AFTER the discharge.
    ///
    /// The number the operator actually came for: it is what still refuses their
    /// `park`, and reporting it here saves attempting a destructive operation to
    /// find out. Zero does NOT by itself authorize parking — the predicate also
    /// requires every attempt to have settled.
    pub outstanding_stops_remaining: usize,
}
