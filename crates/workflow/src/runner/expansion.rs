//! The ONE door an `ExpandBounded` drives through.
//!
//! An expansion — a `loop(..)`, a `topology(..)`, a bounded fanout — resolves
//! at the main as ONE `pending` attempt at its own `#op/<path>` coordinate
//! (`kata_core::operational::expansion` owns the durable surface). Its MEMBERS
//! are ordinary capsule attempts minted at CHILD coordinates —
//! `expand_path.child(N).child(m)` for iteration `N`'s member `m` of a review
//! loop, `expand_path.child(m)` for member `m` of a static `topology(..)` —
//! so this module adds the one member seam beside
//! `dispatch::capsule_submit::submit_stage_as_capsule` rather than a parallel
//! dispatch path: a member IS a stage dispatch; only its coordinate differs.
//!
//! A static `topology(..)`'s expansion sits at the parent stage's OWN flat
//! coordinate (member 0 is the root attempt; members `1..=children.len()` the
//! declared child roles under their durable `<base>#child-<role>` spellings,
//! all minted in one fanout), `maximum` is 1, and its accepted record resolves
//! `Settled` — the fan-in attach then augments the root's accepted output with
//! `child_invocations` / `child_invocation_summary` through the
//! `attach_child_invocation_rows` rows. The failure order is required child
//! first, optional tolerated, then review quorum, read off the member
//! occurrences the derive walks. Each member maps its OWN `/work` branch of the
//! stage's head (`expansion_member_work_coordinate`), and the settle merges
//! the branches in its resolving transaction
//! (`OperationalDb::resolve_expansion_attempt_merging`) — so concurrent writers
//! never go stale against each other, and a contested path fails the stage
//! `work_fanin_conflict` instead of one write silently winning.
//!
//! # The driver
//!
//! Under the `oci` profile a review-loop member never dispatches at its own
//! stage coordinate: the DAG reaches the body-entry member exactly once, and
//! `submit_stage`'s capsule arm diverts that submission into
//! [`WorkflowRunner::claim_expansion_for_member`] — the expansion's claim
//! trigger. From there the expansion drives itself: the fixed-point pass's
//! [`WorkflowRunner::drive_pending_expansions`] walks every `pending`
//! expansion attempt, [`WorkflowRunner::derive_expansion`] recomputes the
//! member state from durable occurrences alone — the first coordinate that
//! minted no occurrence gets [`ExpansionDrive::Dispatch`], a live member
//! attempt gets `Wait`, a dead one gets `Failed`, and a gate verdict, a bound
//! trip or the spent bound gets the terminal [`ExpansionRecord`]. Member
//! frames are intercepted in the fold before every stage-name route
//! ([`WorkflowRunner::fold_expansion_member`]); the `#op` frames land in
//! [`WorkflowRunner::fold_expansion`], which is where the accepted record's
//! orchestrator effects are applied — the member stages' transitions are the
//! record's, never a member frame's.
//!
//! # The durable record and its replay rule
//!
//! The expansion's accepted outcome is an [`ExpansionRecord`]
//! (`{"expansion": {…}}`). A replay recomputes the decision from the durable
//! member outcomes and holds it to the recorded one through [`agree`]: a
//! record that disagrees is refused [`EXPANSION_DECISION_DIVERGED`], and an
//! in-memory loop state is never the authority either way.

use std::collections::BTreeMap;

use kata_core::operational::{
    AttemptCustody, AttemptExecutor, AttemptLifecycle, ExpansionClaimOutcome, ExpansionSpec,
    MainAttemptSpec, MainResolution, OccurrenceBinding, OccurrenceSettlement, PendingExpansion,
};
use kata_types::error::{KataError, KataResult};
use kata_types::execution::{ExecutionCheckedDispatchGuardStatus, ExecutionCheckedDispatchKind};
use kata_types::execution_contract::{OccurrenceRef, OperationPath, RuntimeOperation};
use kata_types::review_loop::{LoopVerdictAction, OnMaxAction};
use kata_types::workflow::{ExecutionId, StageId};
use smol_str::SmolStr;
use tracing::{debug, info, warn};
use ulid::Ulid;

use super::WorkflowRunner;
use super::dispatch::{
    CheckedDispatchEvidenceContext, ChildInvocationRow, attach_child_invocation_rows,
    child_invocation_prompt, child_invocation_stage_name, evaluate_review_quorum,
    review_quorum_failure_reason,
};
use crate::attempt_delivery::FoldOutcome;
use crate::capsule_assembly::RenderedCommand;
use kata_program::execution_program::expansion::{
    ExpansionMember, ExpansionOnMax, ExpansionRecord, ExpansionResolution, ExpansionVerdict,
};
use kata_program::execution_program::select::verdict_tag;
use kata_program::execution_program::{
    DerivedDispatchKind, ReviewLoopParticipant, preflight_derived_dispatch,
};
use kata_program::execution_program::{
    ExecutionInvocationEnvelope, ExpansionKind, LoweredOperation, ProgramOperationAt,
    lower_dynamic_fanout_expansion, lower_expansion_member, lower_review_loop,
    lower_topology_expansion, plans_dynamic_fanout, plans_static_topology, program_operation_at,
};
use kata_program::invocation_plan::InvocationRoleKind;
use kata_program::orchestrator::StageState;

/// A recomputed expansion decision disagrees with the durable one.
pub(super) const EXPANSION_DECISION_DIVERGED: &str = "expansion_decision_diverged";

/// What an expansion's occurrence durably concluded — the mirror of
/// `runner::select`'s `Resolved`.
#[derive(Debug)]
enum Resolved {
    /// Accepted with this record.
    Decided(ExpansionRecord),
    /// Resolved without an acceptance, for this reason.
    Failed(String),
}

/// The expansion's `MainAttemptSpec` + durable [`ExpansionSpec`], built off the
/// ONE lowering — the contract id, the path, the template and the policy all
/// read out of `expansion`, so the claim cannot spell a different expansion
/// than the one lowered.
///
/// # Errors
///
/// [`KataError::Validation`] when `expansion`'s contract carries no
/// `ExpandBounded` — claiming the expansion of a non-expansion is a caller
/// mistake.
fn expansion_claim_parts(
    runner: &WorkflowRunner,
    expansion: &LoweredOperation,
) -> KataResult<(MainAttemptSpec, ExpansionSpec)> {
    let RuntimeOperation::ExpandBounded {
        template,
        maximum,
        policy_hash,
    } = &expansion.contract.operation
    else {
        return Err(KataError::Validation(format!(
            "claim_expansion requires an `ExpandBounded` lowering; {}'s contract is a `{}`",
            expansion.path.program_operation_stage_id(),
            expansion.contract.operation.as_tag(),
        )));
    };
    let spec = MainAttemptSpec {
        stage_id: expansion.path.program_operation_stage_id(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                ExecutionId(runner.execution_id),
                runner.execution_program.program_hash,
                expansion.contract.id(),
                expansion.path.clone(),
            ),
            None,
            None,
        ),
    };
    let durable = ExpansionSpec {
        operation: expansion.contract.id().0.to_string(),
        path: expansion.path.clone(),
        stage: expansion.contract.source_stage.0.to_string(),
        template: template.clone(),
        maximum: *maximum,
        policy: policy_hash.to_string(),
    };
    Ok((spec, durable))
}

impl WorkflowRunner {
    /// CLAIM `expansion`'s `pending` main attempt — the expansion's one
    /// double-spend guard (see `kata_core::operational::expansion`). The
    /// convergent answers stand on their own: `AlreadyLive` means the
    /// expansion is mid-flight and its driver re-drives from the durable
    /// record, `AlreadyAccepted` means the decision stands, `RecordedTerminal`
    /// means the recorded verdict IS the answer.
    fn claim_expansion(&self, expansion: &LoweredOperation) -> KataResult<ExpansionClaimOutcome> {
        let (spec, durable) = expansion_claim_parts(self, expansion)?;
        self.dispatcher
            .execution_lifecycle()
            .db()
            .claim_expansion_attempt(Ulid::new(), &spec, &durable)
    }

    /// The ONE lowering of `kind`'s expansion — every site that maps a
    /// durable expansion path back to its lowering (the drive, the `#op`
    /// fold) goes through this so the kind can never be resolved two ways.
    fn lower_expansion_at(
        &self,
        kind: ExpansionKind,
    ) -> Result<LoweredOperation, kata_program::execution_program::LoweringError> {
        match kind {
            ExpansionKind::ReviewLoop(index) => lower_review_loop(&self.execution_program, index),
            ExpansionKind::Topology(index) => {
                lower_topology_expansion(&self.execution_program, index)
            }
            ExpansionKind::LoopMemberTopology {
                loop_index,
                iteration,
                member,
            } => kata_program::execution_program::lower_loop_member_topology(
                &self.execution_program,
                loop_index,
                iteration,
                member,
            ),
            ExpansionKind::DynamicFanout(index) => {
                lower_dynamic_fanout_expansion(&self.execution_program, index)
            }
        }
    }

    /// Where a topology expansion of `kind` is SEATED — `None` for a review
    /// loop. Every topology question the driver asks (its stage, its parent
    /// prompt, its root's authority, what an unmet quorum means, what its
    /// settle applies) is answered off this.
    fn topology_seat(&self, kind: ExpansionKind) -> KataResult<Option<TopologySeat>> {
        Ok(match kind {
            ExpansionKind::ReviewLoop(_) => None,
            // A `dynamic_fanout` stage is a stage-seated topology whose
            // children the root's output requests; `derive_topology` reads the
            // roster off the stage's plan.
            ExpansionKind::Topology(stage_index) | ExpansionKind::DynamicFanout(stage_index) => {
                Some(TopologySeat::Stage(stage_index))
            }
            ExpansionKind::LoopMemberTopology {
                loop_index,
                iteration,
                member,
            } => {
                let config = self
                    .execution_program
                    .review_loops
                    .get(loop_index)
                    .ok_or_else(|| {
                        KataError::Internal(format!(
                            "review loop {loop_index} is not in the program"
                        ))
                    })?;
                let mut members = config.effective_body_stages();
                members.push(StageId(config.reviewer_stage.clone()));
                let stage = members.get(member as usize).ok_or_else(|| {
                    KataError::Internal(format!(
                        "review loop {loop_index} has no template member {member}"
                    ))
                })?;
                let stage_index = self
                    .execution_program
                    .stages
                    .keys()
                    .position(|id| id == stage)
                    .ok_or_else(|| {
                        KataError::Internal(format!(
                            "review loop {loop_index}'s member stage {} is not in the program",
                            stage.0
                        ))
                    })?;
                Some(TopologySeat::LoopMember {
                    stage_index,
                    loop_index,
                    iteration,
                    member,
                    gate: member as usize + 1 == members.len(),
                })
            }
        })
    }

    /// CLAIM a stage's own expansion — the oci divert's arm for a stage whose
    /// lowering IS the `ExpandBounded` (`dispatch::main_resolved` routes it
    /// here instead of to a capsule): a static `topology` stage's checked
    /// member set or a `dynamic_fanout` stage's runtime-minted one. The stage
    /// stays `Ready`: the drive pass dispatches its members — the root at
    /// `path.child(0)`, the children at `path.child(1..)` — and its completion
    /// arrives only through the accepted record's apply.
    pub(in crate::runner) fn claim_stage_expansion(
        &self,
        expansion: &LoweredOperation,
    ) -> KataResult<()> {
        if let ExpansionClaimOutcome::Claimed { claim_seq } = self.claim_expansion(expansion)? {
            info!(
                execution_id = %self.execution_id,
                %claim_seq,
                operation = %expansion.path.program_operation_stage_id(),
                "expansion: claimed a stage expansion's durable main attempt"
            );
        }
        Ok(())
    }

    /// What the plane durably holds for `expansion`: its accepted record, the
    /// reason its attempt resolved without an acceptance, or nothing while it
    /// is live or unclaimed.
    fn durable_expansion(&self, expansion: &LoweredOperation) -> KataResult<Option<Resolved>> {
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let (spec, _) = expansion_claim_parts(self, expansion)?;
        let occurrence_id = spec.occurrence.occurrence_id();
        let Some(settlement) = db.occurrence_settlement(occurrence_id)? else {
            return Ok(None);
        };
        let attempts = match settlement {
            OccurrenceSettlement::Accepted { accepted, .. } => {
                let output = db
                    .accepted_attempt_output(self.execution_id, accepted.attempt_id)?
                    .ok_or_else(|| {
                        KataError::Storage(format!(
                            "expansion {} is accepted and its accepting transition carries no \
                             output",
                            expansion.path.program_operation_stage_id()
                        ))
                    })?;
                return ExpansionRecord::from_output(&output)
                    .map(|record| Some(Resolved::Decided(record)))
                    .map_err(|error| {
                        KataError::Storage(format!(
                            "the accepted outcome of expansion {} is not an expansion record: \
                             {error}",
                            expansion.path.program_operation_stage_id()
                        ))
                    });
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
                "expansion {} resolved `{}` (attempt {}) without an acceptance",
                expansion.path.program_operation_stage_id(),
                failed.state.as_str(),
                failed.attempt_id
            ))));
        }
        Ok(None)
    }
}

/// Which seat of a loop member's retry chain a derive reached: attempt 0 at
/// the member's own coordinate, seat `k` at `coordinate.child(k)`.
#[derive(Debug)]
enum MemberSeat {
    /// The member's own coordinate.
    First,
    /// A structured-output retry: the seat before it was accepted with an
    /// output that failed the member stage's declared contract, `error` the
    /// validator's message its prompt carries.
    Validation { seat: u32, error: String },
    /// A transient model provider re-run: the seat before it failed
    /// TRANSIENTLY, and this one is due at `due_at_ms`, its backoff after that
    /// failure's terminal frame.
    TransientRerun { seat: u32, due_at_ms: u64 },
}

impl MemberSeat {
    /// The seat's index on its chain.
    const fn index(&self) -> u32 {
        match self {
            Self::First => 0,
            Self::Validation { seat, .. } | Self::TransientRerun { seat, .. } => *seat,
        }
    }

    /// The seat's coordinate under the member's own `coordinate`.
    fn coordinate(&self, coordinate: &OperationPath) -> OperationPath {
        match self.index() {
            0 => coordinate.clone(),
            seat => coordinate.child(seat),
        }
    }
}

/// What the durable member state says the expansion does next — the whole
/// decision space [`WorkflowRunner::derive_expansion`] can answer.
enum ExpansionDrive {
    /// Coordinate `(iteration, member)`'s next seat minted no occurrence yet —
    /// dispatch it, at the seat [`MemberSeat`] names.
    Dispatch {
        iteration: u32,
        member: u32,
        seat: MemberSeat,
    },
    /// The next member's occurrence holds a live (non-terminal) worker attempt.
    Wait,
    /// The next member seat is a transient provider re-run whose backoff has
    /// not passed: nothing runs until its due instant, and a restart
    /// re-derives the seat and that instant from the failed seat's terminal.
    Backoff,
    /// The whole decision is derived — resolve `completed` with this record.
    Decided(ExpansionRecord),
    /// The bound spent under `on_max = "escalate"` — park the main attempt on
    /// this reason. The record it would decide stays out until the gate's own
    /// decision resolves it: the approve door decides it.
    ///
    /// # Why the park holds what is behind the loop
    ///
    /// The park is a `main_parked` chain fact with no delivery envelope
    /// (`envelope_for` maps `MAIN_ATTEMPT_PARKED_KIND` to `NotADeliveryEvent`),
    /// so neither the live fold nor a resumed one applies it: the loop's
    /// authored stages stay as the claim left them, its gate `Pending`, and
    /// every stage behind the gate waits on that gate. Only the approve's
    /// `main_resolved` frame, folded through `WorkflowRunner::fold_expansion`'s
    /// `Completed` arm, completes the gate (`apply_expansion_decided`) and
    /// releases its dependents; a reject fails the loop and releases nothing.
    /// `a_parked_escalate_gate_holds_its_dependents_until_the_approve` pins it.
    Park {
        record: ExpansionRecord,
        reason: String,
    },
    /// The recorded verdict is failure — resolve `failed` on this reason. A
    /// member death carries [`MemberDeath`] so the orchestrator apply can
    /// reproduce the iteration-0-DAG-failure vs later-iteration-abort
    /// split; an expansion-internal failure (a verdict no vocabulary maps)
    /// carries none.
    Failed {
        reason: String,
        death: Option<MemberDeath>,
    },
}

/// One member attempt's terminal death, as the derive found it.
#[derive(Clone, Debug)]
struct MemberDeath {
    /// The iteration coordinate that died.
    iteration: u32,
    /// The member index that died.
    member: u32,
    /// The member's authored stage.
    stage: SmolStr,
    /// The member attempt's own recorded reason — what its stage fails with
    /// on the iteration-0 DAG-failure arm (the expansion's reason is the
    /// wider abort message).
    member_reason: String,
}

/// The member state one derive walk accumulated — every input the member
/// dispatch renders with, and every envelope the resolution applies. Nothing
/// here is in-memory run state: each field came off a durable occurrence or
/// its accepted output, so a re-derive after a crash is byte-identical.
#[derive(Default)]
struct ExpansionView {
    /// Accepted member occurrences so far, in `(iteration, member)` order —
    /// the `ExpansionRecord::members` row set.
    members: Vec<ExpansionMember>,
    /// Classified gate verdicts so far — the `verdicts` row set.
    verdicts: Vec<ExpansionVerdict>,
    /// Member index → its DEEPEST accepted envelope — the resolving
    /// iteration's on an admitted loop, the last completed one under
    /// `on_max = "accept"`, and exactly the envelope `run show` projects from
    /// the member's last attempt in every case. (The authored name carries
    /// the resolving iteration, so a downstream consumer and `run show`
    /// answer the same iteration.)
    latest_member_envelope: BTreeMap<u32, serde_json::Value>,
    /// Member index → its authored stage — the same nth-key lookup
    /// `lower_expansion_member` performs, cached per index.
    member_stage: BTreeMap<u32, SmolStr>,
    /// The current iteration's accepted member envelopes by authored stage —
    /// the `stages.*` context a member render reads its same-iteration
    /// siblings through.
    current_iter_outputs: BTreeMap<SmolStr, serde_json::Value>,
    /// The exit member's envelope at the deepest iteration reached.
    latest_worker: Option<serde_json::Value>,
    /// The gate's envelope at the deepest iteration reached — the
    /// terminal envelope the reviewer
    /// stage completes with.
    latest_reviewer: Option<serde_json::Value>,
    /// The gate's `parsed.feedback` at the deepest verdict — the
    /// refine prompt's `{{ review.feedback }}`.
    latest_feedback: Option<String>,
    /// Per-loop bound accounting: every charge record each accepted member's
    /// attempts made (`kata_program::loops::LoopSpend::charge`), cost and tokens.
    spend: kata_program::loops::LoopSpend,
    /// The per-loop time anchor — the earliest member occurrence's
    /// `created_at_ms` (the first member's dispatch instant).
    started_at_ms: Option<u64>,
    /// What stopped the loop short of its gate's own answer, when something
    /// did — a per-loop bound's trip or the run's walk-away. Its reason is the
    /// feedback a walk-away exhaustion carries (riding ahead of the reviewer's).
    stop: Option<LoopStop>,
    /// The template's full member count — set before any member is visited,
    /// so a derive that stops early still knows the whole shape (the apply
    /// needs it to name the non-exit members).
    member_count: u32,
}

/// What stopped a loop short of its gate's own answer — re-derived off durable
/// rows by every derive, so the record's apply reads the same cause on a replay.
#[derive(Clone, Debug)]
enum LoopStop {
    /// One of the loop's own bounds tripped: `kata_program::loops::loop_bounds_trip`'s
    /// reason.
    Bound(String),
    /// The RUN walked away: `WorkflowRunner::dispatch_unless_walked_away`'s
    /// reason. The candidate the loop ended on is then no gate's judgement, so
    /// no route on the gate takes an arm, whatever its `on_exhaustion` adopts.
    RunWalkedAway(String),
}

impl LoopStop {
    /// The stop's operator-facing reason.
    fn reason(&self) -> &str {
        match self {
            Self::Bound(reason) | Self::RunWalkedAway(reason) => reason,
        }
    }
}

/// Where a static-`topology` expansion is seated — the stage's own
/// coordinate, or a loop member's coordinate at one iteration. The ONE
/// topology driver is seat-generic; the seat answers exactly four questions:
/// the parent prompt (a loop member renders with the loop's `review.*` context),
/// the root member's checked authority and approval bypass (the loop's rule),
/// what an UNMET quorum means (a loop GATE settles and the loop refines; every
/// other seat fails), and what the settle applies (a stage seat completes its
/// stage; a loop seat leaves every orchestrator transition to the loop).
#[derive(Clone, Copy, Debug)]
enum TopologySeat {
    /// The stage's own coordinate `[stage_index]`.
    Stage(usize),
    /// Member `member` of `review_loops[loop_index]` at `iteration`.
    LoopMember {
        /// The topology stage's `stages` index.
        stage_index: usize,
        /// The enclosing loop.
        loop_index: usize,
        /// The iteration the topology runs in.
        iteration: u32,
        /// The loop template member it is.
        member: u32,
        /// Whether that member is the loop's gate.
        gate: bool,
    },
}

impl TopologySeat {
    /// The topology stage's `stages` index, whichever seat.
    const fn stage_index(self) -> usize {
        match self {
            Self::Stage(stage_index) | Self::LoopMember { stage_index, .. } => stage_index,
        }
    }
}

/// What a loop member that is a NESTED static topology durably holds, as
/// the loop's derive reads it.
enum NestedMember {
    /// The nested expansion minted no occurrence — the loop dispatches (claims) it.
    Unminted,
    /// Its `#op` attempt is live — wait.
    Live,
    /// Its `#op` attempt resolved without an acceptance, for this reason — a
    /// member death.
    Dead(String),
    /// Settled — the member's accepted answer.
    Accepted(NestedAcceptance),
}

/// A settled nested topology, as one loop member.
struct NestedAcceptance {
    /// The topology's fan-in envelope — the member's envelope for every loop
    /// read (`latest_member_envelope`, siblings, the gate verdict, the cost).
    envelope: serde_json::Value,
    /// The nested occurrence's mint instant.
    created_at_ms: i64,
    /// Its acceptance instant.
    accepted_at_ms: i64,
    /// The record's `quorum_unmet` — a gate's quorum not met.
    quorum_unmet: Option<String>,
}

/// One loop member, lowered, authorized and rendered —
/// [`WorkflowRunner::prepare_loop_member`]'s answer.
struct PreparedLoopMember<'a> {
    /// The member's lowering at `expand_path.child(N).child(m)` — an `Execute`,
    /// or a static topology's nested `ExpandBounded`.
    lowered: LoweredOperation,
    /// The member's authored stage.
    member_stage: StageId,
    /// The checked authority the member dispatches under.
    checked_stage: &'a kata_program::execution_program::ExecutionProgramStage,
    /// The member's rendered prompt (`review.*` + same-iteration `stages.*`).
    rendered: String,
    /// The iteration ≥ 1 body-member approval bypass, when one applies.
    approval_bypass_reason: Option<String>,
}

/// The fan-in envelope a settled topology's stage carries — the root member's
/// accepted output (already `parsed`-injected at its member fold) augmented with
/// `child_invocations` / `child_invocation_summary` from `view`'s rows — and the
/// root's settling attempt. Pure over `view`, so a loop's derive and the settle's fold build the
/// identical bytes.
///
/// # Errors
///
/// An internal fault when `view` holds no accepted root, and
/// `attach_child_invocation_rows`'s.
fn topology_fan_in_envelope(
    base_stage: &SmolStr,
    plan: &ExecutionInvocationEnvelope,
    view: &TopologyView,
) -> KataResult<(Ulid, serde_json::Value)> {
    let Some(root) = view.rows.get(&0) else {
        return Err(KataError::Internal(format!(
            "topology expansion for \"{base_stage}\" settled with no root member row"
        )));
    };
    let mut envelope = root.output.clone().ok_or_else(|| {
        KataError::Internal(format!(
            "topology expansion for \"{base_stage}\" settled and its root member accepted no \
             output"
        ))
    })?;
    attach_topology_fan_in(&mut envelope, base_stage, plan, view)?;
    Ok((root.attempt_id, envelope))
}

/// Attach a settled topology's fan-in onto `envelope` (the root's accepted,
/// `parsed`-injected output): a static topology's `child_invocations` /
/// `child_invocation_summary`, or — for a dynamic fanout — the dynamic
/// shape. One body for the settle's fold
/// and a loop's derive, so both build the identical bytes.
///
/// # Errors
///
/// The attach's own (a non-object envelope).
fn attach_topology_fan_in(
    envelope: &mut serde_json::Value,
    base_stage: &SmolStr,
    plan: &ExecutionInvocationEnvelope,
    view: &TopologyView,
) -> KataResult<()> {
    let rows: Vec<Option<ChildInvocationRow<'_>>> = view
        .children
        .iter()
        .map(|child| {
            view.rows
                .get(&child.member())
                .map(|row| ChildInvocationRow {
                    stage_name: row.stage_name.clone(),
                    assignment_id: row.attempt_id.to_string(),
                    status_tag: row.status_tag,
                    output: row.output.as_ref(),
                    is_completed: row.output.is_some(),
                    terminal_failure_reason: row.terminal_failure_reason.clone(),
                })
        })
        .collect();
    if plan.dynamic_fanout {
        // The dynamic envelope (`dynamic_fanout: true`, per-request
        // `owned_paths`, the enforced mutation scope). The capsule route merges
        // the branches at the settle, so no linked-worktree patch record rides it.
        let requests: Vec<super::dispatch::DynamicChildRequest> = view
            .children
            .iter()
            .filter_map(|child| match child {
                ChildMember::Requested { request, .. } => Some(request.clone()),
                ChildMember::Declared { .. } => None,
            })
            .collect();
        super::dispatch::attach_dynamic_child_invocation_rows(
            envelope,
            &requests,
            &rows,
            plan,
            view.mutation_scope.as_ref(),
            None,
        )?;
    } else {
        attach_child_invocation_rows(envelope, plan, base_stage, &rows)?;
    }
    Ok(())
}

/// What a static-`topology` expansion's member walk answers — the topology
/// twin of [`ExpansionDrive`], minus the bound/escalate arms a loop carries
/// and a `maximum = 1` fanout never lowers.
enum TopologyDrive {
    /// Members that minted no occurrence — dispatch them. Member 0 always
    /// arrives alone (the declared children mint only once the parent itself
    /// dispatched); the children arrive together, the one-pass
    /// fanout.
    Dispatch { members: Vec<u32> },
    /// The root parked on its authored gate, or a member's attempt is live —
    /// nothing to do this pass.
    Wait,
    /// Every member terminal, every required child completed, the declared
    /// quorum held — resolve `completed` with the `Settled` record.
    Decided(ExpansionRecord),
    /// The expansion's terminal answer is failure — resolve `failed`.
    Failed { reason: String },
}

/// One member's durable state as a topology derive read it — the fields the
/// fan-in attach and the record need, no more.
struct TopologyMemberRow {
    /// The member's durable stage spelling (`<base>` for member 0,
    /// `<base>#child-<role>` for members ≥ 1).
    stage_name: SmolStr,
    /// Its settling attempt — the accepted one when it accepted, the last
    /// terminal one when it died.
    attempt_id: Ulid,
    /// `completed` / `failed` / `cancelled` / `orphaned` — the
    /// `ChildInvocationRow` status spelling.
    status_tag: &'static str,
    /// The accepted envelope (a `completed` member), `None` for a dead one.
    output: Option<serde_json::Value>,
    /// Its terminal failure reason (a dead member), `None` for an accepted
    /// one.
    terminal_failure_reason: Option<String>,
}

/// The member state one topology derive accumulated — the same rule
/// [`ExpansionView`] carries: every field came off a durable occurrence or
/// its accepted output, so a re-derive after a crash is byte-identical.
#[derive(Default)]
struct TopologyView {
    /// Every member occurrence the expansion minted AND accepted, in member
    /// order — the `ExpansionRecord::members` row set.
    members: Vec<ExpansionMember>,
    /// Member index → its settled row (accepted or dead). A live or
    /// undispatched member has no row.
    rows: BTreeMap<u32, TopologyMemberRow>,
    /// Member indices that minted no occurrence, in member order.
    missing: Vec<u32>,
    /// A member's attempt is live non-terminal (excluding member 0's parked
    /// gate, which is `root_parked`).
    live: bool,
    /// Member 0 holds a PARKED (awaiting-approval) attempt — children of an
    /// undispatched parent never mint, so a parked root holds the whole
    /// fanout.
    root_parked: bool,
    /// The child roster past member 0 — the declared roles of a static
    /// topology, or the requests a dynamic fanout's accepted root made.
    children: Vec<ChildMember>,
    /// The enforced `owned_paths` scope a dynamic fanout settled under.
    mutation_scope: Option<super::dispatch::MutationScopeCheck>,
    /// The ROOT's next retry seat — `Some((k, error))` when the
    /// root's accepted attempt `k - 1` failed its structured output and retry
    /// `k` (at the root seat's `child(k)`) is unminted.
    root_retry: Option<(u32, String)>,
}

/// One child member (`m ≥ 1`) of a stage expansion.
#[derive(Clone, Debug)]
enum ChildMember {
    /// Declared `topology` role `index` — member `index + 1`.
    Declared {
        /// The member index.
        member: u32,
        /// The role's index in the checked plan's `children`.
        index: usize,
    },
    /// Accepted request `member - 1` of the root's `child_invocation_requests`
    /// — validated against the checked plan by
    /// `dynamic_child_requests`.
    Requested {
        /// The member index.
        member: u32,
        /// The validated request.
        request: super::dispatch::DynamicChildRequest,
    },
}

impl ChildMember {
    /// The member index.
    const fn member(&self) -> u32 {
        match self {
            Self::Declared { member, .. } | Self::Requested { member, .. } => *member,
        }
    }
}

impl WorkflowRunner {
    /// The `review_loops[k]` whose member set contains `stage` — body stages
    /// and the gate. `None` for a stage no loop owns; the `oci` capsule arm
    /// of `submit_stage` asks this before it would dispatch the stage itself.
    pub(super) fn expansion_member_loop(&self, stage: &StageId) -> Option<usize> {
        self.execution_program
            .review_loops
            .iter()
            .position(|config| {
                config.reviewer_stage == stage.0
                    || config
                        .effective_body_stages()
                        .iter()
                        .any(|member| member == stage)
            })
    }

    /// Whether `stage`'s submit is an EXPANSION's claim trigger — a `loop(..)`
    /// member (the DAG reaches only its body-entry member), a `topology(..)` or a
    /// dynamic fan-out stage — whose members and retry chains that expansion's
    /// own derive dispatches, never the stage's plain paths.
    pub(super) fn stage_seats_an_expansion(&self, stage: &StageId) -> bool {
        self.expansion_member_loop(stage).is_some()
            || self
                .execution_program
                .stages
                .get(stage)
                .is_some_and(|checked| {
                    plans_static_topology(checked) || plans_dynamic_fanout(checked)
                })
    }

    /// CLAIM the `review_loops[loop_index]` expansion — the member-divert's
    /// one job. The member stage stays `Ready`: the expansion's own drive
    /// pass dispatches its members at child coordinates and never this
    /// stage's bare path, and the claim's convergent answers
    /// (`AlreadyLive`/`AlreadyAccepted`/`RecordedTerminal`) are all fine for
    /// a re-drive to converge on.
    pub(super) fn claim_expansion_for_member(&self, loop_index: usize) -> KataResult<()> {
        let expansion =
            lower_review_loop(&self.execution_program, loop_index).map_err(|error| {
                KataError::Validation(format!(
                    "review loop {loop_index} does not lower: {error:?}"
                ))
            })?;
        if let ExpansionClaimOutcome::Claimed { claim_seq } = self.claim_expansion(&expansion)? {
            info!(
                execution_id = %self.execution_id,
                %claim_seq,
                operation = %expansion.path.program_operation_stage_id(),
                "expansion: claimed the durable main attempt"
            );
        }
        Ok(())
    }

    /// The member coordinate of the attempt `assignment_id`, when it is one —
    /// `expand_path.child(N).child(m)` with `expand_path` naming an
    /// `ExpandBounded` of this program. `None` for every attempt that is not
    /// a member's: an unbound attempt, a bare-path stage attempt, a
    /// `main`-executor attempt's `#op` coordinate (intercepted before this
    /// read in the fold).
    pub(super) fn expansion_member_path_of(
        &self,
        assignment_id: Ulid,
    ) -> KataResult<Option<OperationPath>> {
        if self.execution_program.review_loops.is_empty()
            && !self
                .execution_program
                .stages
                .values()
                .any(|stage| plans_static_topology(stage) || plans_dynamic_fanout(stage))
        {
            return Ok(None);
        }
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let Some(recovered) = db.recovered_attempt(assignment_id)? else {
            return Ok(None);
        };
        let occurrence_id = recovered.occurrence_id;
        let Some(row) = db.occurrence(occurrence_id.0.0)? else {
            return Ok(None);
        };
        let Some(path) = OperationPath::from_canonical_bytes(&row.operation_path) else {
            return Err(KataError::Storage(format!(
                "occurrence {}'s stored operation_path does not decode canonically",
                occurrence_id.0,
            )));
        };
        if path.0.len() < 2 {
            return Ok(None);
        }
        // A STAGE expansion member (topology or dynamic fanout) sits at
        // `expand_path.child(m)` — its parent IS the expansion. A LOOP member
        // sits at `expand_path.child(N).child(m)` — its parent is an iteration
        // coordinate and its GRANDPARENT is the expansion.
        // `program_operation_at` answers the kind, so the loop's iteration
        // coordinate `[l, N]` — whose parent IS the loop's `ExpandBounded` —
        // can never pass for a stage-expansion member: `ReviewLoop` is
        // neither `Topology` nor `DynamicFanout`.
        let parent = OperationPath(path.0[..path.0.len() - 1].to_vec());
        if matches!(
            program_operation_at(&self.execution_program, &parent),
            Some(ProgramOperationAt::Expansion(
                ExpansionKind::Topology(_)
                    | ExpansionKind::LoopMemberTopology { .. }
                    | ExpansionKind::DynamicFanout(_)
            ))
        ) {
            return Ok(Some(path));
        }
        if path.0.len() >= 3 {
            let expansion_path = OperationPath(path.0[..path.0.len() - 2].to_vec());
            if matches!(
                program_operation_at(&self.execution_program, &expansion_path),
                Some(ProgramOperationAt::Expansion(ExpansionKind::ReviewLoop(_)))
            ) {
                return Ok(Some(path));
            }
        }
        // A topology ROOT's structured-output RETRY sits at
        // `expand_path.child(0).child(k)` — its grandparent is the expansion
        // and its parent the root seat (member 0), which is no expansion.
        if path.0.len() >= 3 && path.0[path.0.len() - 2] == 0 {
            let expansion_path = OperationPath(path.0[..path.0.len() - 2].to_vec());
            if matches!(
                program_operation_at(&self.execution_program, &expansion_path),
                Some(ProgramOperationAt::Expansion(
                    ExpansionKind::Topology(_)
                        | ExpansionKind::LoopMemberTopology { .. }
                        | ExpansionKind::DynamicFanout(_)
                ))
            ) {
                return Ok(Some(path));
            }
        }
        // A loop member's structured-output RETRY sits one level
        // below the member, at `loop.child(N).child(m).child(k)` — its
        // great-grandparent is the loop. (A nested topology's member at the same
        // depth was answered above: its parent IS the nested expansion.)
        if path.0.len() >= 4 {
            let expansion_path = OperationPath(path.0[..path.0.len() - 3].to_vec());
            if matches!(
                program_operation_at(&self.execution_program, &expansion_path),
                Some(ProgramOperationAt::Expansion(ExpansionKind::ReviewLoop(_)))
            ) {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    /// The durable write of ONE computed [`kata_program::loops::RolloverContext`]
    /// — the distilled summary object keyed `{execution_id}:{memory_key}`,
    /// fired by the durable expansion's member-0 dispatch at a generation
    /// boundary off its own folded view. Best-effort + idempotent: a missing
    /// store, a same-key rewrite after resume, or a store error is logged, never
    /// propagated.
    pub(crate) fn persist_rollover_memory(
        &self,
        worker_stage: &str,
        ctx: &kata_program::loops::RolloverContext,
    ) {
        let Some(store) = self.memory_store.as_ref() else {
            return;
        };
        let scope = self
            .memory_scope
            .clone()
            .unwrap_or(kata_types::memory::MemoryScope::Global);
        // The durable object id is execution-PREFIXED so a memory store shared
        // across executions can't collide on the execution-independent
        // `ctx.memory_key` (two runs both hitting gen-1 for the same worker).
        // The prompt surfaces the bare `ctx.memory_key`; the two intentionally
        // differ — the object resolves within-execution via provenance.source_id
        // (set to `ctx.memory_key` below), not by a raw get of the surfaced key.
        let object_id = format!("{}:{}", self.execution_id, ctx.memory_key);
        let proposal = kata_types::memory::MemoryProposal {
            proposal_id: None,
            // Fresh object per generation (the key embeds the generation), so the
            // create expects no prior revision. A duplicate write of the same
            // boundary after resume conflicts and is swallowed below.
            expected_revision: Some(0),
            object: kata_types::memory::MemoryObjectDraft {
                id: Some(object_id),
                kind: kata_types::memory::MemoryObjectKind::Finding,
                status: kata_types::memory::MemoryObjectStatus::Active,
                scope,
                title: Some(format!(
                    "loop rollover: {} generation {}",
                    worker_stage, ctx.generation
                )),
                body: serde_json::json!({
                    "worker_stage": worker_stage,
                    "generation": ctx.generation,
                    "iterations_elapsed": ctx.iterations_elapsed,
                    "summary": ctx.summary,
                }),
                tags: vec!["rollover".to_owned(), "continue-as-new".to_owned()],
                links: Vec::new(),
                provenance: kata_types::memory::MemoryProvenance {
                    source_kind: kata_types::memory::MemorySourceKind::Workflow,
                    source_id: Some(ctx.memory_key.clone()),
                    execution_id: Some(self.execution_id.to_string()),
                    agent_id: None,
                    path: None,
                },
            },
            source_file: None,
        };
        match store.apply_proposal(proposal) {
            Ok(resp) if resp.status == "conflict" => {
                debug!(
                    execution_id = %self.execution_id,
                    worker_stage = %worker_stage,
                    generation = ctx.generation,
                    "rollover memory already persisted for this generation (resume re-fire)"
                );
            }
            Ok(_) => {
                info!(
                    execution_id = %self.execution_id,
                    worker_stage = %worker_stage,
                    generation = ctx.generation,
                    memory_key = %ctx.memory_key,
                    "continue-as-new: distilled rollover summary persisted to memory plane"
                );
            }
            Err(err) => {
                warn!(
                    execution_id = %self.execution_id,
                    worker_stage = %worker_stage,
                    generation = ctx.generation,
                    error = %err,
                    "rollover memory write failed (best-effort; resume unaffected)"
                );
            }
        }
    }

    /// Close-the-loop: fire the iteration-writeback hook for a
    /// just-completed loop iteration. Best-effort + idempotent — a failure here
    /// is logged, not propagated, because the terminal writeback at run-end
    /// re-applies (CAS no-op for what already landed) and surfaces any hard
    /// error. With a `None` hook (no memory store / no declared writebacks)
    /// writebacks land only at terminal.
    pub(crate) fn fire_iteration_writeback(&self, completed_iteration: u32) {
        let Some(hook) = self.iteration_writeback_hook.as_ref() else {
            return;
        };
        match hook.on_iteration_complete(completed_iteration) {
            Ok(count) if count > 0 => {
                info!(
                    execution_id = %self.execution_id,
                    completed_iteration,
                    count,
                    "close-the-loop: per-iteration memory writeback applied"
                );
            }
            Ok(_) => {}
            Err(err) => {
                warn!(
                    execution_id = %self.execution_id,
                    completed_iteration,
                    error = %err,
                    "close-the-loop: per-iteration writeback failed (terminal pass will reconcile)"
                );
            }
        }
    }

    /// FOLD one member frame — a stage attempt bound at a member coordinate.
    ///
    /// The member frame is NEVER its stage's own completion: a member's
    /// durable terminal is the expansion's input, and the orchestrator's
    /// member-stage transitions are the accepted record's to apply (the
    /// record owns the transition and every member fold converges to it on
    /// replay).
    ///
    /// It IS its own charge: every member frame that billed — each completion
    /// (an accepted one, and a structured-output retry's rejected one alike)
    /// and each failed, cancelled or orphaned terminal's charge — is folded into
    /// the workflow-scope accumulators here, at its own frame and nowhere else,
    /// under [`member_charge_stage`]. The accepted record's apply charges
    /// nothing, so a member's spend is counted exactly once, on the live path
    /// and on a replay that re-folds the same frames.
    pub(super) fn fold_expansion_member(
        &self,
        stage_name: &SmolStr,
        assignment_id: Ulid,
        outcome: &FoldOutcome,
        recorded_at_ms: u64,
    ) -> KataResult<()> {
        let charge_stage = member_charge_stage(stage_name);
        match outcome {
            // The member's declared-outputs injection runs here exactly as the
            // ordinary Completed arm's does — the accepted output is AMENDED
            // with `parsed`, which is where the gate's `parsed.<verdict_field>`
            // comes from (the derive reads the amended bytes). A `QueuedRetry`
            // means the output failed its declared-output check and the
            // validation-retry machinery owns the next attempt, exactly as for
            // any capsule stage. What a member frame NEVER does: insert into
            // `outputs` or transition the orchestrator — those are the
            // accepted record's to apply.
            FoldOutcome::Completed { output } => {
                let Some(output) = output.clone() else {
                    return Err(KataError::Internal(format!(
                        "runner: Completed event for member assignment {assignment_id} has no output"
                    )));
                };
                // The completion billed whether or not its output meets the
                // member's contract: charged before the injection decides.
                let trip = self.check_halts_for_stage(&charge_stage, &output, recorded_at_ms);
                self.settle_charged_frame(&charge_stage, trip, "expansion member completion")?;
                // A topology CHILD member's durable spelling is synthetic
                // (`<base>#child-<role>`): its Completed frame goes to the
                // fan-in before any declared-output validation, so a
                // child's envelope is read RAW (the review-verdict and fan-in
                // readers parse `content`/`verdict` off it) and never
                // `parsed`-injected. Member 0 — the authored stage spelling —
                // injects exactly as the ordinary Completed arm does: `parsed`
                // is where the accepted record's stage completion reads its
                // declared output through.
                if super::dispatch::parse_child_invocation_stage_name(stage_name.as_str()).is_none()
                {
                    let _ = self.inject_parsed_if_declared(stage_name, assignment_id, output)?;
                }
            }
            FoldOutcome::Failed {
                terminal_charge, ..
            }
            | FoldOutcome::Cancelled {
                terminal_charge, ..
            }
            | FoldOutcome::Orphaned {
                terminal_charge, ..
            } => {
                // A terminal charge can trip a workflow halt, exactly as any
                // stage's terminal can.
                let trip = terminal_charge.as_ref().and_then(|charge| {
                    self.check_halts_for_terminal_charge(&charge_stage, charge, recorded_at_ms)
                });
                self.settle_charged_frame(&charge_stage, trip, "expansion member termination")?;
            }
            FoldOutcome::Dispatched { worker_id } => {
                // A parked member (iter-0 gate, or a gated member the
                // operator just approved) resumes through the same
                // orchestrator edge any gated stage does.
                if matches!(
                    self.orchestrator.stage_state(stage_name.as_str()),
                    Some(StageState::AwaitingApproval { .. })
                ) {
                    self.orchestrator
                        .dispatch_stage_after_approval(stage_name, Some(worker_id.clone()))?;
                }
            }
            FoldOutcome::AwaitingApproval { reason } => {
                // A gated member parked: the stage's orchestrator mirror is
                // the authored stage (the `#iter-N` spellings never exist as
                // orchestrator stages). Idempotent — a re-fold sees the stage
                // already paused.
                if !matches!(
                    self.orchestrator.stage_state(stage_name.as_str()),
                    Some(StageState::AwaitingApproval { .. })
                ) {
                    self.replay_promote_if_pending(stage_name);
                    self.orchestrator
                        .pause_stage_for_approval(stage_name, reason.clone())?;
                }
            }
            FoldOutcome::AwaitingChildCompletion { .. } | FoldOutcome::InFlight => {}
        }
        Ok(())
    }

    /// FOLD one frame of the expansion's own `#op/<path>` attempt — the
    /// accepted record is applied to the orchestrator here, and only here.
    ///
    /// `Completed` recomputes the decision off the durable member outcomes
    /// and holds the durable record to it through [`agree`], then applies the
    /// resolution's orchestrator effects (member completions, the worker's
    /// terminal, branch routing — the loop-resolution arm the record
    /// names). `Failed`/`Cancelled` record the failed operation and apply
    /// the abort semantics ([`Self::apply_expansion_failed`]): the iteration-0 DAG-failure
    /// vs later-iteration-abort split rides the derive's [`MemberDeath`].
    /// `AwaitingApproval` would apply the escalation park (the worker
    /// pauses, the gate completes, the branch arms skip), but no frame
    /// delivers it: an expansion's park has no delivery envelope, so the park
    /// holds the gate's dependents instead (`ExpansionDrive::Park`).
    pub(super) fn fold_expansion(
        &self,
        path: &OperationPath,
        kind: ExpansionKind,
        outcome: &FoldOutcome,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let expansion = self.lower_expansion_at(kind).map_err(|error| {
            KataError::Storage(format!(
                "expansion {} maps to {kind:?} and does not lower: {error:?}",
                path.program_operation_stage_id()
            ))
        })?;
        if let Some(seat) = self.topology_seat(kind)? {
            return self.fold_topology_expansion(&expansion, seat, outcome, outputs);
        }
        let ExpansionKind::ReviewLoop(loop_index) = kind else {
            return Err(KataError::Internal(format!(
                "expansion {}'s kind is neither ReviewLoop nor a stage expansion",
                path.program_operation_stage_id()
            )));
        };
        match outcome {
            FoldOutcome::Completed { .. } => {
                let Some(Resolved::Decided(durable)) = self.durable_expansion(&expansion)? else {
                    return Err(KataError::Storage(format!(
                        "expansion {} completed and holds no accepted record — the resolve \
                         writes both in one transaction",
                        path.program_operation_stage_id()
                    )));
                };
                let (drive, view) = self.derive_expansion(&expansion, loop_index)?;
                let recomputed: Result<ExpansionRecord, String> = match &drive {
                    ExpansionDrive::Decided(record) | ExpansionDrive::Park { record, .. } => {
                        Ok(record.clone())
                    }
                    ExpansionDrive::Failed { reason, .. } => Err(reason.clone()),
                    ExpansionDrive::Dispatch { .. }
                    | ExpansionDrive::Wait
                    | ExpansionDrive::Backoff => {
                        Err("the expansion still owes member executions".to_owned())
                    }
                };
                let Resolved::Decided(record) =
                    agree(&expansion.path, Resolved::Decided(durable), recomputed)?
                else {
                    return Err(KataError::Internal(
                        "agree on a decided expansion cannot answer Failed".to_owned(),
                    ));
                };
                self.apply_expansion_decided(loop_index, &record, &view, outputs)
            }
            FoldOutcome::Failed { reason, .. } | FoldOutcome::Cancelled { reason, .. } => {
                self.failed_program_operations
                    .write()
                    .insert(path.program_operation_stage_id(), reason.clone());
                let (drive, view) = self.derive_expansion(&expansion, loop_index)?;
                let death = match &drive {
                    ExpansionDrive::Failed { death, .. } => death.clone(),
                    _ => None,
                };
                self.apply_expansion_failed(loop_index, reason, death, &view, outputs)
            }
            FoldOutcome::AwaitingApproval { reason } => {
                let (_, view) = self.derive_expansion(&expansion, loop_index)?;
                self.apply_expansion_gate_parked(loop_index, reason, &view, outputs)
            }
            FoldOutcome::Orphaned { .. }
            | FoldOutcome::Dispatched { .. }
            | FoldOutcome::AwaitingChildCompletion { .. }
            | FoldOutcome::InFlight => Ok(()),
        }
    }

    /// FOLD one frame of a TOPOLOGY expansion's own `#op/<path>` attempt —
    /// [`Self::fold_expansion`]'s `Topology` arm. `Completed` re-derives the
    /// `Settled` record off the member rows and holds the durable one to it
    /// through [`agree`], then applies the fan-in (`apply_topology_decided`);
    /// `Failed`/`Cancelled` records the failed operation and fails the stage
    /// (`apply_topology_failed`). A topology expansion never parks —
    /// `AwaitingApproval` is unreachable and refused, never silently folded.
    ///
    /// A LOOP-seated topology touches no orchestrator state either way:
    /// `Completed` still holds the record to the recompute and amends the
    /// root's accepted output with the fan-in, but the member stage's
    /// transition is the enclosing loop's to apply (its derive reads this
    /// expansion as one member), and a failure is the loop's member death,
    /// not a failed program operation of its own.
    fn fold_topology_expansion(
        &self,
        expansion: &LoweredOperation,
        seat: TopologySeat,
        outcome: &FoldOutcome,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let stage_index = seat.stage_index();
        let (stage_id, plan) = self
            .execution_program
            .stages
            .iter()
            .nth(stage_index)
            .map(|(stage_id, stage)| (stage_id.clone(), stage.invocation_envelope.clone()))
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "topology expansion {} maps to stages[{stage_index}] and the program \
                     holds no stage there",
                    expansion.path.program_operation_stage_id()
                ))
            })?;
        let base_stage = stage_id.0;
        match outcome {
            FoldOutcome::Completed { .. } => {
                let Some(Resolved::Decided(durable)) = self.durable_expansion(expansion)? else {
                    return Err(KataError::Storage(format!(
                        "topology expansion {} completed and holds no accepted record — \
                         the resolve writes both in one transaction",
                        expansion.path.program_operation_stage_id()
                    )));
                };
                let (drive, view) = self.derive_topology(expansion, seat)?;
                let recomputed: Result<ExpansionRecord, String> = match &drive {
                    TopologyDrive::Decided(record) => Ok(record.clone()),
                    TopologyDrive::Failed { reason } => Err(reason.clone()),
                    TopologyDrive::Dispatch { .. } | TopologyDrive::Wait => {
                        Err("the expansion still owes member executions".to_owned())
                    }
                };
                // The record only has to AGREE — the apply's whole input is
                // the recomputed member view (the same bytes `agree` just held
                // the durable record to), so the agreed record binds nowhere.
                let Resolved::Decided(_) =
                    agree(&expansion.path, Resolved::Decided(durable), recomputed)?
                else {
                    return Err(KataError::Internal(
                        "agree on a decided expansion cannot answer Failed".to_owned(),
                    ));
                };
                match seat {
                    TopologySeat::Stage(_) => {
                        self.apply_topology_decided(&base_stage, &plan, &view, outputs)
                    }
                    TopologySeat::LoopMember { .. } => {
                        let (root, envelope) = topology_fan_in_envelope(&base_stage, &plan, &view)?;
                        self.amend_or_defer_output(root, envelope)
                    }
                }
            }
            FoldOutcome::Failed { reason, .. } | FoldOutcome::Cancelled { reason, .. } => {
                match seat {
                    TopologySeat::Stage(_) => {
                        self.failed_program_operations
                            .write()
                            .insert(expansion.path.program_operation_stage_id(), reason.clone());
                        self.apply_topology_failed(&base_stage, reason)
                    }
                    TopologySeat::LoopMember { .. } => Ok(()),
                }
            }
            FoldOutcome::AwaitingApproval { .. } => Err(KataError::Internal(format!(
                "topology expansion {} parked `awaiting_approval` — a static topology \
                 carries no escalate arm, so no writer parks one",
                expansion.path.program_operation_stage_id()
            ))),
            FoldOutcome::Orphaned { .. }
            | FoldOutcome::Dispatched { .. }
            | FoldOutcome::AwaitingChildCompletion { .. }
            | FoldOutcome::InFlight => Ok(()),
        }
    }

    /// The derive: walk `expansion`'s member coordinates in order, read each
    /// member's durable premise, and answer [`ExpansionDrive`]. Pure over the
    /// durable rows — the identical re-derivation a replay performs, which is
    /// what makes [`agree`] meaningful.
    ///
    /// # Errors
    ///
    /// The durable-row faults a walk can hit — an occurrence that holds no
    /// attempt, an accepted member with no accepted output — and the two
    /// verdict refusals (a missing `parsed.<field>` tag, a tag outside the
    /// configured vocabulary).
    fn derive_expansion(
        &self,
        expansion: &LoweredOperation,
        loop_index: usize,
    ) -> KataResult<(ExpansionDrive, ExpansionView)> {
        let RuntimeOperation::ExpandBounded {
            template, maximum, ..
        } = &expansion.contract.operation
        else {
            return Err(KataError::Internal(format!(
                "derive_expansion requires an `ExpandBounded` lowering; {}'s contract is a `{}`",
                expansion.path.program_operation_stage_id(),
                expansion.contract.operation.as_tag(),
            )));
        };
        let member_count = u32::try_from(template.len()).map_err(|_| {
            KataError::Internal(format!(
                "expansion {}'s template does not fit a u32 member index",
                expansion.path.program_operation_stage_id()
            ))
        })?;
        if member_count < 2 {
            return Err(KataError::Internal(format!(
                "expansion {}'s template holds {member_count} member(s); a loop's template \
                 always ends in its gate and holds at least a worker",
                expansion.path.program_operation_stage_id()
            )));
        }
        let config = &self.execution_program.review_loops[loop_index];
        let gate_config = config.effective_gate_verdict();
        let verdict_field = gate_config.verdict_field.as_str();
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let mut view = ExpansionView {
            member_count,
            ..ExpansionView::default()
        };
        for iteration in 0..*maximum {
            view.current_iter_outputs.clear();
            for member in 0..member_count {
                let coordinate = expansion.path.child(iteration).child(member);
                let lowered = lower_expansion_member(
                    &self.execution_program,
                    expansion,
                    coordinate.clone(),
                    member,
                )
                .map_err(|error| {
                    KataError::Internal(format!(
                        "expansion member ({iteration}, {member}) does not lower: {error:?}"
                    ))
                })?;
                let member_stage = lowered.contract.source_stage.0.clone();
                let mut occurrence = OccurrenceRef::new(
                    ExecutionId(self.execution_id),
                    self.execution_program.program_hash,
                    lowered.contract.id(),
                    coordinate.clone(),
                );
                view.member_stage
                    .entry(member)
                    .or_insert_with(|| member_stage.clone());
                // A static-topology member is a NESTED expansion at this
                // coordinate — its durable answer is the nested `#op` attempt's,
                // and its envelope is the topology's fan-in envelope.
                let nested = if matches!(
                    lowered.contract.operation,
                    RuntimeOperation::ExpandBounded { .. }
                ) {
                    match self.nested_topology_member(&lowered, loop_index, iteration, member)? {
                        NestedMember::Unminted => {
                            let drive = self.dispatch_unless_walked_away(
                                expansion,
                                config,
                                iteration,
                                member,
                                MemberSeat::First,
                                &mut view,
                            )?;
                            return Ok((drive, view));
                        }
                        NestedMember::Live => return Ok((ExpansionDrive::Wait, view)),
                        NestedMember::Dead(member_reason) => {
                            return Ok((
                                ExpansionDrive::Failed {
                                    reason: format!(
                                        "review loop aborted by stage \"{member_stage}\" \
                                         failure: {member_reason}"
                                    ),
                                    death: Some(MemberDeath {
                                        iteration,
                                        member,
                                        stage: member_stage,
                                        member_reason,
                                    }),
                                },
                                view,
                            ));
                        }
                        NestedMember::Accepted(accepted) => Some(accepted),
                    }
                } else {
                    None
                };
                let (envelope, created_ms, accepted_ms, quorum_unmet) = if let Some(nested) = nested
                {
                    (
                        nested.envelope,
                        nested.created_at_ms,
                        nested.accepted_at_ms,
                        nested.quorum_unmet,
                    )
                } else {
                    // The member's structured-output RETRY CHAIN:
                    // attempt 0 at the member's own coordinate, retry `k` at
                    // `coordinate.child(k)`. An accepted attempt whose output
                    // fails the member stage's declared contract hands the walk
                    // to the next seat while the stage's `validate_retries`
                    // allows; a spent budget fails the loop with the
                    // validator's own message.
                    let retry_policy = super::effect::EffectCoerceRetryPolicy::from_policies(
                        &self
                            .execution_program
                            .stages
                            .get(&StageId(member_stage.clone()))
                            .ok_or_else(|| {
                                KataError::Internal(format!(
                                    "loop member stage {member_stage} is not in the program"
                                ))
                            })?
                            .policies,
                    );
                    // A transient model provider failure on a seat hands the
                    // walk to the next seat too — a re-run on the same agent,
                    // `TRANSIENT_PROVIDER_RERUNS` times per member chain, due
                    // after its backoff from the failed seat's terminal frame:
                    // the plain stage's rule (`capsule_failure_retry`).
                    let mut seat = MemberSeat::First;
                    let mut validations = 0u32;
                    let mut transient_reruns = 0u32;
                    loop {
                        let at = OccurrenceRef::new(
                            ExecutionId(self.execution_id),
                            self.execution_program.program_hash,
                            lowered.contract.id(),
                            seat.coordinate(&coordinate),
                        );
                        // The occurrence and its attempts come from ONE
                        // snapshot: a completion committing between two reads
                        // would pair an unaccepted occurrence with a
                        // `completed` attempt and read a finished member dead.
                        let Some(settlement) = db.occurrence_settlement(at.id().0.0)? else {
                            // A re-run inside its backoff waits — unless the run
                            // walked away, or latched its outcome (a cancel among
                            // them): then nothing more is claimed in it, and the
                            // dispatch below ends the walk now, not at the
                            // backoff's end.
                            if let MemberSeat::TransientRerun { due_at_ms, .. } = &seat
                                && *due_at_ms > super::dispatch::now_ms()
                                && self.durable_walkaway_halt_rows()?.is_empty()
                                && !self.outcome_latched()?
                            {
                                return Ok((ExpansionDrive::Backoff, view));
                            }
                            let drive = self.dispatch_unless_walked_away(
                                expansion, config, iteration, member, seat, &mut view,
                            )?;
                            return Ok((drive, view));
                        };
                        let (row, accepted) = match settlement {
                            OccurrenceSettlement::Accepted {
                                occurrence,
                                accepted,
                            } => (occurrence, accepted),
                            OccurrenceSettlement::Unaccepted { attempts, .. } => {
                                // Minted but unaccepted — live (wait) or dead (fail).
                                // One occurrence is resolved by one attempt, so the
                                // attempts here are at most one live generation
                                // plus the terminal ones. A MAIN-RESOLVED
                                // member (a `workspace_effect` claimed pending and
                                // crashed before its resolve) is exactly such a
                                // live-but-unaccepted member — its attempts are
                                // `executor = 'main'`, which the settlement carries
                                // beside the worker ones.
                                #[cfg(any(test, feature = "test-support"))]
                                super::run_member_read_interleave(self.execution_id, at.id().0.0);
                                // The sweep's own order: a pending main attempt is
                                // driven by `drive_pending_workspace_effects`, so
                                // the derive's `Wait` is the honest answer while it
                                // is live.
                                if attempts.is_empty() {
                                    return Err(KataError::Storage(format!(
                                        "expansion member occurrence {} of {} holds no attempt \
                                             — its claim binds the first in one transaction",
                                        at.id().0,
                                        expansion.path.program_operation_stage_id(),
                                    )));
                                }
                                if attempts.iter().any(|attempt| {
                                    attempt.state.custody() != AttemptCustody::Settled
                                }) {
                                    return Ok((ExpansionDrive::Wait, view));
                                }
                                let dead = attempts
                                    .last()
                                    .expect("attempts is non-empty when it has no live one");
                                let mut member_reason =
                                    dead.terminal_reason.clone().unwrap_or_else(|| {
                                        format!(
                                            "member attempt {} resolved `{}` without a recorded \
                                             reason",
                                            dead.attempt_id,
                                            dead.state.as_str()
                                        )
                                    });
                                // The plain stage's gates first: a seat the
                                // operator stopped is never re-run, nor one kata
                                // cannot rule out having had effects
                                // (`failure_is_retryable`), whatever class its
                                // terminal records.
                                if transient_reruns < super::dispatch::TRANSIENT_PROVIDER_RERUNS
                                    && dead.state != AttemptLifecycle::Cancelled
                                    && self.failure_is_retryable(dead.attempt_id)?
                                    && let Some(terminal) =
                                        db.occurrence_provider_failure(at.id().0.0)?
                                    && terminal.class
                                        == kata_types::effect::ProviderFailureClass::Transient
                                {
                                    let due_at_ms = super::dispatch::transient_rerun_due_ms(
                                        &self.transient_rerun_backoff_ms,
                                        transient_reruns,
                                        u64::try_from(terminal.recorded_at_ms).unwrap_or(0),
                                    );
                                    // A re-run due past the run's `time_bound` is
                                    // not run: the member fails here, naming it.
                                    match self.transient_rerun_past_time_bound(due_at_ms) {
                                        None => {
                                            seat = MemberSeat::TransientRerun {
                                                seat: seat.index() + 1,
                                                due_at_ms,
                                            };
                                            transient_reruns += 1;
                                            continue;
                                        }
                                        Some(past) => {
                                            member_reason = format!("{member_reason}; {past}");
                                        }
                                    }
                                }
                                return Ok((
                                    ExpansionDrive::Failed {
                                        reason: format!(
                                            "review loop aborted by stage \"{member_stage}\" \
                                                 failure: {member_reason}"
                                        ),
                                        death: Some(MemberDeath {
                                            iteration,
                                            member,
                                            stage: member_stage,
                                            member_reason,
                                        }),
                                    },
                                    view,
                                ));
                            }
                        };
                        let raw_envelope = db
                            .accepted_attempt_output(self.execution_id, accepted.attempt_id)?
                            .ok_or_else(|| {
                                KataError::Storage(format!(
                                    "expansion member occurrence {} of {} is accepted and \
                                         its accepting transition carries no output",
                                    at.id().0,
                                    expansion.path.program_operation_stage_id(),
                                ))
                            })?;
                        match self.member_output_validity(&member_stage, raw_envelope)? {
                            Ok(envelope) => {
                                occurrence = at;
                                break (envelope, row.created_at_ms, accepted.at_ms, None);
                            }
                            Err(error) if retry_policy.should_retry(validations) => {
                                validations += 1;
                                seat = MemberSeat::Validation {
                                    seat: seat.index() + 1,
                                    error,
                                };
                            }
                            Err(member_reason) => {
                                return Ok((
                                    ExpansionDrive::Failed {
                                        reason: member_reason.clone(),
                                        death: Some(MemberDeath {
                                            iteration,
                                            member,
                                            stage: member_stage,
                                            member_reason,
                                        }),
                                    },
                                    view,
                                ));
                            }
                        }
                    }
                };
                view.members.push(ExpansionMember {
                    iteration,
                    member,
                    stage: member_stage.to_string(),
                    occurrence: occurrence.id().0.to_string(),
                });
                view.latest_member_envelope.insert(member, envelope.clone());
                let created = u64::try_from(created_ms).unwrap_or(0);
                view.started_at_ms = Some(
                    view.started_at_ms
                        .map_or(created, |earlier| earlier.min(created)),
                );
                // Charge the loop with EVERYTHING the member's attempts billed,
                // read off its coordinate's subtree rather than off the accepted
                // envelope alone: a structured-output retry's rejected turn, a
                // failed attempt's terminal charge (an advisory topology child's,
                // a dispatched attempt's charge-less terminal read as unknown) and
                // a nested topology's every root and child attempt all spent. The
                // member is accepted, so every attempt under its coordinate is
                // settled and the read is as replay-stable as the envelope.
                for record in db.charge_records_under(self.execution_id, &coordinate)? {
                    view.spend.charge(member_stage.as_str(), &record);
                }
                // A per-loop bound trips on the ACCEPTED member before
                // any gate classification (`kata_program::loops::loop_bounds_trip`),
                // read at the member's own
                // accepted instant.
                let accepted_at = u64::try_from(accepted_ms).unwrap_or(0);
                if let Some(trip) = kata_program::loops::loop_bounds_trip(
                    &config.bounds,
                    &view.spend,
                    view.started_at_ms,
                    accepted_at,
                ) {
                    view.stop = Some(LoopStop::Bound(trip.clone()));
                    let record = expansion_record(
                        expansion,
                        ExpansionResolution::Exhausted {
                            iterations: iteration + 1,
                            on_max: expansion_on_max(config.on_max),
                        },
                        &view,
                    );
                    return Ok((
                        exhausted_drive(config, record, Exhaustion::BoundTrip(&trip)),
                        view,
                    ));
                }
                if member + 1 == member_count {
                    // THE GATE — classify the verdict, append the verdict row,
                    // and end or continue the walk.
                    let feedback = envelope
                        .get("parsed")
                        .and_then(|parsed| parsed.get("feedback"))
                        .and_then(serde_json::Value::as_str)
                        .map(String::from);
                    view.latest_reviewer = Some(envelope.clone());
                    let tag = verdict_tag(&envelope, verdict_field).ok_or_else(|| {
                        KataError::Validation(format!(
                            "review loop reviewer \"{member_stage}\" envelope missing a \
                             \"parsed.{verdict_field}\" verdict (a string tag or a single-key \
                             variant object); did the reviewer stage declare `{verdict_field}` \
                             in its outputs?"
                        ))
                    })?;
                    let action = gate_config.classify(&tag).ok_or_else(|| {
                        KataError::Validation(format!(
                            "review loop reviewer \"{member_stage}\" emitted unknown verdict \
                             \"{tag}\" for field \"{verdict_field}\"; expected one of \
                             approve={:?}, refine={:?}, block={:?}",
                            gate_config.approve, gate_config.refine, gate_config.block,
                        ))
                    })?;
                    // A gate topology that settled with its quorum UNMET is a
                    // `refine` whatever its root's tag reads, and the quorum's own
                    // reason rides the refine prompt's `{{ review.feedback }}`.
                    let (action, feedback) = match &quorum_unmet {
                        Some(reason) => (
                            LoopVerdictAction::Refine,
                            Some(match feedback {
                                Some(root) => format!("{root}\n\nreview quorum not met: {reason}"),
                                None => format!("review quorum not met: {reason}"),
                            }),
                        ),
                        None => (action, feedback),
                    };
                    view.latest_feedback.clone_from(&feedback);
                    view.verdicts.push(ExpansionVerdict {
                        iteration,
                        verdict: tag,
                        feedback: feedback.clone(),
                        quorum_unmet: quorum_unmet.clone(),
                    });
                    match action {
                        LoopVerdictAction::Approve => {
                            let record = expansion_record(
                                expansion,
                                ExpansionResolution::Approved { iteration },
                                &view,
                            );
                            return Ok((ExpansionDrive::Decided(record), view));
                        }
                        LoopVerdictAction::Block => {
                            let record = expansion_record(
                                expansion,
                                ExpansionResolution::Blocked { iteration },
                                &view,
                            );
                            return Ok((ExpansionDrive::Decided(record), view));
                        }
                        LoopVerdictAction::Refine => {
                            if iteration + 1 >= *maximum {
                                let record = expansion_record(
                                    expansion,
                                    ExpansionResolution::Exhausted {
                                        iterations: iteration + 1,
                                        on_max: expansion_on_max(config.on_max),
                                    },
                                    &view,
                                );
                                let last_feedback = feedback.as_deref().unwrap_or("none");
                                return Ok((
                                    exhausted_drive(
                                        config,
                                        record,
                                        Exhaustion::Iterations { last_feedback },
                                    ),
                                    view,
                                ));
                            }
                            // Refine inside the bound: fall out of the member
                            // walk; the next iteration's coordinates mint next.
                        }
                    }
                } else {
                    if member + 2 == member_count {
                        view.latest_worker = Some(envelope.clone());
                    }
                    view.current_iter_outputs.insert(member_stage, envelope);
                }
            }
        }
        // Every iteration that ran classified its gate — reaching here means
        // `maximum` is 0, the only configuration a checked program cannot
        // carry.
        Err(KataError::Internal(format!(
            "expansion {} ran its maximum of {maximum} iterations without a gate verdict — \
             a `maximum` of 0 never lowers",
            expansion.path.program_operation_stage_id()
        )))
    }

    /// The derive reached coordinate `(iteration, member)` — `seat` naming which
    /// seat of its retry chain — and nothing is minted there: dispatch it, unless
    /// the RUN has walked away.
    ///
    /// A walk-away is any row `durable_walkaway_halt_rows` reads (a workflow
    /// bound's, a halting `cost_budget`'s, a fail-closed metering halt's). Once
    /// one is durable the loop dispatches nothing more: it resolves `Exhausted`
    /// under its own `on_exhaustion`, counting `iteration` as run when any of
    /// its members already minted, and its exhaustion names the row. Whatever
    /// that `on_exhaustion` adopts, the record's apply releases nothing behind
    /// any member (`release_nothing_behind_loop`: the fold passed the walk-away
    /// row before the record that names it), and no route on the gate takes an
    /// arm (off the `LoopStop::RunWalkedAway` this sets). The rows
    /// are durable and never removed, so a replay's recompute reaches this same
    /// coordinate with the same answer — and a loop that decided before the walk
    /// away (a verdict, its own bound, `max_iterations`) never reaches a dispatch
    /// point, so its record is untouched.
    fn dispatch_unless_walked_away(
        &self,
        expansion: &LoweredOperation,
        config: &kata_types::review_loop::ReviewLoop,
        iteration: u32,
        member: u32,
        seat: MemberSeat,
        view: &mut ExpansionView,
    ) -> KataResult<ExpansionDrive> {
        let Some(row) = self.durable_walkaway_halt_rows()?.into_iter().next() else {
            return Ok(ExpansionDrive::Dispatch {
                iteration,
                member,
                seat,
            });
        };
        let trip = format!(
            "the run walked away (\"{row}\" recorded a walk-away halt), so the loop dispatches \
             no further member"
        );
        view.stop = Some(LoopStop::RunWalkedAway(trip.clone()));
        let started = u32::from(member > 0 || !matches!(seat, MemberSeat::First));
        let record = expansion_record(
            expansion,
            ExpansionResolution::Exhausted {
                iterations: iteration + started,
                on_max: expansion_on_max(config.on_max),
            },
            view,
        );
        Ok(exhausted_drive(
            config,
            record,
            Exhaustion::BoundTrip(&trip),
        ))
    }

    // ── static `topology(..)` ───────────────────────────────────────────
    //
    // Same claim/drive/fold machinery as a review loop's; only the member
    // coordinates (`path.child(m)`, member 0 the root), the member semantics
    // (a one-pass fanout over the declared children) and the terminal shape
    // (`Settled`, plus the `child_invocations` fan-in) differ.

    /// Read loop member `(iteration, member)` of `review_loops[loop_index]` that
    /// is a nested static topology off durable rows: its `#op` occurrence
    /// unminted, live, dead, or accepted — and, accepted, the topology's fan-in
    /// envelope recomputed from its own members exactly as its settle built it.
    fn nested_topology_member(
        &self,
        nested: &LoweredOperation,
        loop_index: usize,
        iteration: u32,
        member: u32,
    ) -> KataResult<NestedMember> {
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let (spec, _) = expansion_claim_parts(self, nested)?;
        let occurrence_id = spec.occurrence.occurrence_id();
        // One snapshot for the occurrence and its attempts — see the loop arm
        // of `derive_expansion`.
        let Some(settlement) = db.occurrence_settlement(occurrence_id)? else {
            return Ok(NestedMember::Unminted);
        };
        let attempts = match settlement {
            OccurrenceSettlement::Accepted {
                occurrence,
                accepted,
            } => {
                let output = db
                    .accepted_attempt_output(self.execution_id, accepted.attempt_id)?
                    .ok_or_else(|| {
                        KataError::Storage(format!(
                            "nested topology {} is accepted and its accepting transition carries \
                             no output",
                            nested.path.program_operation_stage_id()
                        ))
                    })?;
                let record = ExpansionRecord::from_output(&output).map_err(|error| {
                    KataError::Storage(format!(
                        "the accepted outcome of nested topology {} is not an expansion record: \
                         {error}",
                        nested.path.program_operation_stage_id()
                    ))
                })?;
                let seat = self
                    .topology_seat(ExpansionKind::LoopMemberTopology {
                        loop_index,
                        iteration,
                        member,
                    })?
                    .ok_or_else(|| {
                        KataError::Internal("a loop-member topology always has a seat".to_owned())
                    })?;
                let (_, view) = self.derive_topology(nested, seat)?;
                let (stage_id, plan) = self
                    .execution_program
                    .stages
                    .iter()
                    .nth(seat.stage_index())
                    .map(|(stage_id, stage)| (stage_id.0.clone(), &stage.invocation_envelope))
                    .ok_or_else(|| {
                        KataError::Internal(format!(
                            "nested topology {} maps to a stage the program does not hold",
                            nested.path.program_operation_stage_id()
                        ))
                    })?;
                let (_, envelope) = topology_fan_in_envelope(&stage_id, plan, &view)?;
                return Ok(NestedMember::Accepted(NestedAcceptance {
                    envelope,
                    created_at_ms: occurrence.created_at_ms,
                    accepted_at_ms: accepted.at_ms,
                    quorum_unmet: record.quorum_unmet,
                }));
            }
            OccurrenceSettlement::Unaccepted { attempts, .. } => attempts,
        };
        #[cfg(any(test, feature = "test-support"))]
        super::run_member_read_interleave(self.execution_id, occurrence_id);
        let attempts: Vec<_> = attempts
            .into_iter()
            .filter(|attempt| attempt.executor == AttemptExecutor::Main)
            .collect();
        if attempts.is_empty()
            || attempts
                .iter()
                .any(|attempt| attempt.state.custody() != AttemptCustody::Settled)
        {
            return Ok(NestedMember::Live);
        }
        let dead = attempts
            .last()
            .expect("attempts is non-empty when it has no live one");
        Ok(NestedMember::Dead(
            dead.terminal_reason.clone().unwrap_or_else(|| {
                format!(
                    "nested topology attempt {} resolved `{}` without a recorded reason",
                    dead.attempt_id,
                    dead.state.as_str()
                )
            }),
        ))
    }

    /// The child roster past member 0. A static topology's is its declared
    /// roles; a DYNAMIC fanout's is the request array its root's
    /// accepted output carries, validated against the CHECKED plan by
    /// `dynamic_child_requests` (declared roles, the declared agent, no
    /// required-role downgrade, `owned_paths` normalized and disjoint,
    /// `fanout_limit` / `max_concurrency`) — empty while the root has no
    /// accepted output. `Err` is the request array's refusal, verbatim.
    fn topology_roster(
        plan: &ExecutionInvocationEnvelope,
        base_stage: &SmolStr,
        dynamic: bool,
        root_output: Option<&serde_json::Value>,
    ) -> Result<Vec<ChildMember>, String> {
        if !dynamic {
            return Ok((0..plan.children.len())
                .map(|index| ChildMember::Declared {
                    member: u32::try_from(index + 1).expect("a checked role count fits a u32"),
                    index,
                })
                .collect());
        }
        let Some(output) = root_output else {
            return Ok(Vec::new());
        };
        let requests = super::dispatch::dynamic_child_requests(plan, base_stage, output)
            .map_err(|error| error.to_string())?;
        requests
            .into_iter()
            .enumerate()
            .map(|(index, request)| {
                let member = u32::try_from(index + 1).map_err(|_| {
                    format!("stage \"{base_stage}\" requested more children than a u32 indexes")
                })?;
                Ok(ChildMember::Requested { member, request })
            })
            .collect()
    }

    /// Lower child member `child` of `expansion` at `expansion.path.child(m)` —
    /// a declared role through the template (`lower_expansion_member`), a
    /// request through `lower_dynamic_fanout_member` under the request's
    /// durable `<base>#child-<role>-<label>` spelling and declared agent.
    fn lower_topology_child(
        &self,
        expansion: &LoweredOperation,
        child: &ChildMember,
    ) -> KataResult<LoweredOperation> {
        let coordinate = expansion.path.child(child.member());
        let lowered = match child {
            ChildMember::Declared { member, .. } => {
                lower_expansion_member(&self.execution_program, expansion, coordinate, *member)
            }
            ChildMember::Requested { request, .. } => {
                kata_program::execution_program::lower_dynamic_fanout_member(
                    &self.execution_program,
                    expansion,
                    coordinate,
                    &StageId(request.child_stage.clone()),
                    request.agent.as_deref(),
                )
            }
        };
        lowered.map_err(|error| {
            KataError::Internal(format!(
                "topology member {} does not lower: {error:?}",
                child.member()
            ))
        })
    }

    /// Read member `member` (lowered as `lowered`) of `expansion` off its
    /// durable occurrence into `view`: unminted → `missing`; live → `live` (or
    /// `root_parked` for a parked member 0); dead → a row carrying its terminal
    /// reason; accepted → a row carrying its accepted output, plus the record's
    /// member entry.
    fn read_topology_member(
        &self,
        db: &kata_core::operational::OperationalDb,
        expansion: &LoweredOperation,
        lowered: &LoweredOperation,
        member: u32,
        view: &mut TopologyView,
    ) -> KataResult<()> {
        let member_stage = lowered.contract.source_stage.0.clone();
        let occurrence = OccurrenceRef::new(
            ExecutionId(self.execution_id),
            self.execution_program.program_hash,
            lowered.contract.id(),
            lowered.path.clone(),
        );
        // One snapshot for the occurrence and its attempts — see the loop arm
        // of `derive_expansion`.
        let Some(settlement) = db.occurrence_settlement(occurrence.id().0.0)? else {
            view.missing.push(member);
            return Ok(());
        };
        let accepted = match settlement {
            OccurrenceSettlement::Accepted { accepted, .. } => accepted,
            OccurrenceSettlement::Unaccepted { attempts, .. } => {
                #[cfg(any(test, feature = "test-support"))]
                super::run_member_read_interleave(self.execution_id, occurrence.id().0.0);
                let attempts: Vec<_> = attempts
                    .into_iter()
                    .filter(|attempt| attempt.executor == AttemptExecutor::Worker)
                    .collect();
                if attempts.is_empty() {
                    return Err(KataError::Storage(format!(
                        "topology member occurrence {} of {} holds no attempt — its claim binds \
                         the first in one transaction",
                        occurrence.id().0,
                        expansion.path.program_operation_stage_id(),
                    )));
                }
                if attempts
                    .iter()
                    .any(|attempt| attempt.state.custody() != AttemptCustody::Settled)
                {
                    // Member 0 parked on its authored gate holds the whole
                    // fanout: children mint only once the parent was
                    // dispatched, so a parked root is a `Wait`, never a
                    // `Dispatch`. Any other live member is a plain `Wait`.
                    if member == 0
                        && attempts
                            .iter()
                            .any(|attempt| attempt.state == AttemptLifecycle::AwaitingApproval)
                    {
                        view.root_parked = true;
                    } else {
                        view.live = true;
                    }
                    return Ok(());
                }
                let dead = attempts
                    .last()
                    .expect("attempts is non-empty when it has no live one");
                let reason = dead.terminal_reason.clone().unwrap_or_else(|| {
                    format!(
                        "member attempt {} resolved `{}` without a recorded reason",
                        dead.attempt_id,
                        dead.state.as_str()
                    )
                });
                view.rows.insert(
                    member,
                    TopologyMemberRow {
                        stage_name: member_stage,
                        attempt_id: dead.attempt_id,
                        status_tag: dead.state.as_str(),
                        output: None,
                        terminal_failure_reason: Some(reason),
                    },
                );
                return Ok(());
            }
        };
        let envelope = db
            .accepted_attempt_output(self.execution_id, accepted.attempt_id)?
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "topology member occurrence {} of {} is accepted and its accepting \
                     transition carries no output",
                    occurrence.id().0,
                    expansion.path.program_operation_stage_id(),
                ))
            })?;
        view.members.push(ExpansionMember {
            iteration: 0,
            member,
            stage: member_stage.to_string(),
            occurrence: occurrence.id().0.to_string(),
        });
        view.rows.insert(
            member,
            TopologyMemberRow {
                stage_name: member_stage,
                attempt_id: accepted.attempt_id,
                status_tag: "completed",
                output: Some(envelope),
                terminal_failure_reason: None,
            },
        );
        Ok(())
    }

    /// Read the topology ROOT (member 0, lowered as `root`) off its
    /// structured-output RETRY CHAIN — attempt 0 at the root's
    /// seat, retry `k` at `seat.child(k)` — into `view`: the first accepted
    /// attempt whose envelope meets the root stage's declared contract is the
    /// root's row (augmented with `parsed`); an invalid one hands the walk to
    /// the next seat while the stage's `validate_retries` allows, and an
    /// unminted next seat is `missing` with `root_retry` naming it; a spent
    /// budget is a dead root carrying the validator's message. The children are
    /// read RAW, never validated (they reach the fan-in before validation).
    fn read_topology_root_chain(
        &self,
        db: &kata_core::operational::OperationalDb,
        expansion: &LoweredOperation,
        root: &LoweredOperation,
        view: &mut TopologyView,
    ) -> KataResult<()> {
        let stage_name = root.contract.source_stage.0.clone();
        let policy = super::effect::EffectCoerceRetryPolicy::from_policies(
            &self
                .execution_program
                .stages
                .get(&StageId(stage_name.clone()))
                .ok_or_else(|| {
                    KataError::Internal(format!(
                        "topology root stage {stage_name} is not in the program"
                    ))
                })?
                .policies,
        );
        let mut retry = 0u32;
        let mut last_error: Option<String> = None;
        loop {
            let mut seat = root.clone();
            if retry > 0 {
                seat.path = root.path.child(retry);
            }
            let mut probe = TopologyView::default();
            self.read_topology_member(db, expansion, &seat, 0, &mut probe)?;
            if !probe.missing.is_empty() {
                view.missing.push(0);
                view.root_retry = last_error.map(|error| (retry, error));
                return Ok(());
            }
            if probe.root_parked || probe.live {
                view.root_parked |= probe.root_parked;
                view.live |= probe.live;
                return Ok(());
            }
            let mut row = probe
                .rows
                .remove(&0)
                .expect("a minted, terminal root seat leaves a row");
            let Some(output) = row.output.take() else {
                view.rows.insert(0, row);
                return Ok(());
            };
            match self.member_output_validity(&stage_name, output)? {
                Ok(envelope) => {
                    row.output = Some(envelope);
                    view.rows.insert(0, row);
                    view.members.append(&mut probe.members);
                    return Ok(());
                }
                Err(error) if policy.should_retry(retry) => {
                    last_error = Some(error);
                    retry += 1;
                }
                Err(error) => {
                    row.status_tag = "failed";
                    row.terminal_failure_reason = Some(error);
                    view.rows.insert(0, row);
                    return Ok(());
                }
            }
        }
    }

    /// A dynamic fanout's `mutation_policy = "owned_paths"` scope,
    /// held over each member's RECORDED `/work` delta — the capsule route's
    /// observation: an owned-path WORKER child (`dynamic_child_uses_linked_worktree`)
    /// must change only inside its own `owned_paths`; the root and every other
    /// child only inside the union of all owned paths. `Ok(None)` under any
    /// other policy; `Ok(Err(reason))` is the violation —
    /// it fails the stage before any branch merges, so nothing lands.
    fn owned_path_mutation_scope(
        &self,
        plan: &ExecutionInvocationEnvelope,
        base_stage: &SmolStr,
        children: &[ChildMember],
        view: &TopologyView,
    ) -> KataResult<Result<Option<super::dispatch::MutationScopeCheck>, String>> {
        if !matches!(
            plan.mutation_policy,
            Some(kata_types::workflow::MutationPolicy::OwnedPaths)
        ) {
            return Ok(Ok(None));
        }
        let owned_union: Vec<SmolStr> = children
            .iter()
            .filter_map(|child| match child {
                ChildMember::Requested { request, .. } => Some(request.owned_paths.iter().cloned()),
                ChildMember::Declared { .. } => None,
            })
            .flatten()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let quoted = |paths: &[SmolStr]| {
            paths
                .iter()
                .map(|path| format!("\"{path}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut every_changed: Vec<SmolStr> = Vec::new();
        let mut members: Vec<(u32, Option<&super::dispatch::DynamicChildRequest>)> =
            vec![(0, None)];
        members.extend(children.iter().map(|child| match child {
            ChildMember::Requested { member, request } => (*member, Some(request)),
            ChildMember::Declared { member, .. } => (*member, None),
        }));
        for (member, request) in members {
            let changed = self.member_delta_paths(view, member)?;
            let own_scope = request.filter(|request| {
                super::dispatch::dynamic_child_uses_linked_worktree(plan, request)
            });
            let scope: &[SmolStr] = own_scope.map_or(owned_union.as_slice(), |request| {
                request.owned_paths.as_slice()
            });
            let offenders: Vec<SmolStr> = changed
                .iter()
                .filter(|path| {
                    !scope
                        .iter()
                        .any(|owned| super::dispatch::path_is_inside_owned_scope(path, owned))
                })
                .cloned()
                .collect();
            if !offenders.is_empty() {
                return Ok(Err(match own_scope {
                    Some(request) => format!(
                        "stage \"{base_stage}\" dynamic child \"{}\" observed changed path(s) \
                         outside declared owned_paths in its /work delta: changed_paths=[{}] \
                         owned_paths=[{}]",
                        request.child_stage,
                        quoted(&offenders),
                        quoted(&request.owned_paths),
                    ),
                    None => format!(
                        "stage \"{base_stage}\" mutation_policy=owned_paths observed changed \
                         path(s) outside declared owned_paths in a /work delta: \
                         changed_paths=[{}] owned_paths=[{}]",
                        quoted(&offenders),
                        quoted(&owned_union),
                    ),
                }));
            }
            every_changed.extend(changed);
        }
        every_changed.sort();
        every_changed.dedup();
        Ok(Ok(Some(super::dispatch::MutationScopeCheck {
            changed_paths: every_changed,
            owned_paths: owned_union,
        })))
    }

    /// The paths member `member`'s ACCEPTED outcome's `/work` delta changed —
    /// `[]` for a member that accepted no delta (or no outcome).
    fn member_delta_paths(&self, view: &TopologyView, member: u32) -> KataResult<Vec<SmolStr>> {
        let Some(text) = view
            .rows
            .get(&member)
            .and_then(|row| row.output.as_ref())
            .and_then(|output| output.get("work_delta_artifact_id"))
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(Vec::new());
        };
        let artifact = text
            .parse::<kata_types::primitives::ContentHash>()
            .map_err(|_| {
                KataError::Storage(format!(
                    "member {member}'s accepted outcome names work delta {text:?}, not a content hash"
                ))
            })?;
        let store = self.cache_store.as_ref().ok_or_else(|| {
            KataError::Storage(
                "an owned_paths fanout's member delta cannot be read: this node has no content \
                 store attached"
                    .to_owned(),
            )
        })?;
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let delta = crate::dispatcher::work_apply::load_work_delta(&db, store.cas(), artifact.0)?;
        Ok(delta
            .changes()
            .iter()
            .map(|change| SmolStr::new(change.path.as_str()))
            .collect())
    }

    /// What a topology expansion's member walk answers — the topology twin of
    /// [`ExpansionDrive`], minus the bound/escalate arms a loop carries and a
    /// `maximum = 1` topology never lowers.
    fn derive_topology(
        &self,
        expansion: &LoweredOperation,
        seat: TopologySeat,
    ) -> KataResult<(TopologyDrive, TopologyView)> {
        let stage_index = seat.stage_index();
        let mut quorum_unmet: Option<String> = None;
        let RuntimeOperation::ExpandBounded { .. } = &expansion.contract.operation else {
            return Err(KataError::Internal(format!(
                "derive_topology requires an `ExpandBounded` lowering; {}'s contract is a `{}`",
                expansion.path.program_operation_stage_id(),
                expansion.contract.operation.as_tag(),
            )));
        };
        let stage_id = self
            .execution_program
            .stages
            .keys()
            .nth(stage_index)
            .cloned()
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "topology expansion {} maps to stages[{stage_index}] and the program holds \
                     no stage there",
                    expansion.path.program_operation_stage_id()
                ))
            })?;
        let plan = &self
            .execution_program
            .stages
            .get(&stage_id)
            .expect("stage_id was just read out of the same map")
            .invocation_envelope;
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let mut view = TopologyView::default();
        // Member 0 — the root, the stage's own payload — first: a DYNAMIC
        // fanout's children are the root's accepted answer, so the roster
        // past member 0 is only knowable once the root's row is read.
        let root = lower_expansion_member(
            &self.execution_program,
            expansion,
            expansion.path.child(0),
            0,
        )
        .map_err(|error| {
            KataError::Internal(format!("topology root member does not lower: {error:?}"))
        })?;
        self.read_topology_root_chain(&db, expansion, &root, &mut view)?;
        let dynamic = plans_dynamic_fanout(
            self.execution_program
                .stages
                .get(&stage_id)
                .expect("stage_id was just read out of the same map"),
        );
        let root_output = view.rows.get(&0).and_then(|row| row.output.clone());
        let roster = Self::topology_roster(plan, &stage_id.0, dynamic, root_output.as_ref());
        let (children, request_refusal) = match roster {
            Ok(children) => (children, None),
            Err(reason) => (Vec::new(), Some(reason)),
        };
        for child in &children {
            let lowered = self.lower_topology_child(expansion, child)?;
            self.read_topology_member(&db, expansion, &lowered, child.member(), &mut view)?;
        }
        view.children.clone_from(&children);
        // The decision, in order:
        //
        // 1. the root unminted → dispatch IT ALONE — children mint only once
        //    the parent itself dispatched — unless the run walked away;
        // 2. the root parked on its gate → wait (same rule);
        // 3. the root dead → the expansion's answer is the root's own reason
        //    (the parent's terminal IS the stage's);
        // 4. (dynamic) the root's request array refused by the checked plan →
        //    that refusal, verbatim (`dynamic_child_requests`'s phrasing);
        // 5. a dead REQUIRED child → the required-child failure, verbatim
        //    — it fires before the all-terminal wait and before quorum;
        // 6. undispatched children → the one-pass fanout mint, unless the run
        //    walked away;
        // 7. a live member → wait;
        // 8. (dynamic) a child that itself requested children →
        //    `dynamic_fanout_nested`;
        // 9. all terminal → the declared review quorum (advisory failures and
        //    absent optional reviewers ride the evaluation, never the drive);
        // 10. (dynamic, `mutation_policy = "owned_paths"`) every changed path
        //    inside its owner's scope;
        // 11. settle.
        if view.missing.contains(&0) {
            let drive = self.topology_dispatch_unless_walked_away(vec![0], view.live)?;
            return Ok((drive, view));
        }
        if view.root_parked {
            return Ok((TopologyDrive::Wait, view));
        }
        if let Some(root) = view.rows.get(&0)
            && let Some(reason) = &root.terminal_failure_reason
        {
            return Ok((
                TopologyDrive::Failed {
                    reason: reason.clone(),
                },
                view,
            ));
        }
        if view.rows.contains_key(&0)
            && let Some(reason) = request_refusal
        {
            return Ok((TopologyDrive::Failed { reason }, view));
        }
        for child in &children {
            let (role, required, phrase) = match child {
                ChildMember::Declared { index, .. } => {
                    let role = &plan.children[*index];
                    (&role.role, role.required, "required child invocation")
                }
                ChildMember::Requested { request, .. } => (
                    &request.role,
                    request.required,
                    "required dynamic child invocation",
                ),
            };
            if !required {
                continue;
            }
            if let Some(reason) = view
                .rows
                .get(&child.member())
                .and_then(|row| row.terminal_failure_reason.as_ref())
            {
                return Ok((
                    TopologyDrive::Failed {
                        reason: format!("{phrase} \"{role}\" failed: {reason}"),
                    },
                    view,
                ));
            }
        }
        if !view.missing.is_empty() {
            let drive =
                self.topology_dispatch_unless_walked_away(view.missing.clone(), view.live)?;
            return Ok((drive, view));
        }
        if view.live {
            return Ok((TopologyDrive::Wait, view));
        }
        for child in &children {
            if let ChildMember::Requested { request, member } = child
                && view
                    .rows
                    .get(member)
                    .and_then(|row| row.output.as_ref())
                    .is_some_and(super::dispatch::declares_child_requests)
            {
                return Ok((
                    TopologyDrive::Failed {
                        reason: format!(
                            "dynamic_fanout_nested: dynamic child \"{}\" of stage \"{}\" \
                             requested child invocations of its own — a dynamic child never \
                             plans children",
                            request.child_stage, stage_id.0
                        ),
                    },
                    view,
                ));
            }
        }
        if let Some(quorum) = plan.review_quorum.as_ref() {
            let evaluation = evaluate_review_quorum(children.iter().filter_map(|child| {
                let (role, kind, required) = match child {
                    ChildMember::Declared { index, .. } => {
                        let role = &plan.children[*index];
                        (role.role.clone(), role.kind, role.required)
                    }
                    ChildMember::Requested { request, .. } => {
                        (request.role.clone(), request.kind, request.required)
                    }
                };
                (kind == InvocationRoleKind::Reviewer).then(|| {
                    super::dispatch::ReviewerObservation {
                        role,
                        required,
                        output: view
                            .rows
                            .get(&child.member())
                            .and_then(|row| row.output.as_ref()),
                    }
                })
            }));
            if let Some(reason) = review_quorum_failure_reason(quorum, &evaluation) {
                // On a loop's GATE an unmet quorum is the loop's refine,
                // not the gate's failure — the topology settles carrying the
                // reason, and the loop's derive turns it into the iteration's
                // `refine` verdict. Every other seat fails, as standalone.
                if matches!(seat, TopologySeat::LoopMember { gate: true, .. }) {
                    quorum_unmet = Some(reason);
                } else {
                    return Ok((TopologyDrive::Failed { reason }, view));
                }
            }
        }
        if dynamic {
            match self.owned_path_mutation_scope(plan, &stage_id.0, &children, &view)? {
                Ok(scope) => view.mutation_scope = scope,
                Err(reason) => return Ok((TopologyDrive::Failed { reason }, view)),
            }
        }
        let record = ExpansionRecord {
            operation: expansion.contract.id().0.to_string(),
            path: expansion.path.program_operation_stage_id(),
            stage: stage_id.0.to_string(),
            resolution: ExpansionResolution::Settled,
            members: view.members.clone(),
            verdicts: Vec::new(),
            quorum_unmet,
        };
        Ok((TopologyDrive::Decided(record), view))
    }

    /// The topology derive reached a dispatch point — `members` minted nothing
    /// yet: its root (or the root's structured-output retry seat), or its
    /// children, declared or requested — so dispatch them, unless the RUN has
    /// walked away.
    ///
    /// Once any walk-away row is durable (`durable_walkaway_halt_rows`, the read
    /// a loop's `dispatch_unless_walked_away` makes) the topology dispatches
    /// nothing more: it waits while a member it already minted is `live` (a
    /// static topology's children mint once its root DISPATCHED, so the root
    /// may still be running), and then resolves FAILED, naming the row — never
    /// with a member in flight, as a loop's dispatch point is reached only once
    /// its earlier members settled. A root parked on its authored gate still
    /// waits for the operator (the derive's earlier `Wait`), as an escalated
    /// loop parks after a walk-away, and the operator's approve RUNS it: the
    /// root was minted before the walk-away, so its capsule starts on the
    /// approve rather than at a dispatch point, and the topology stops at its
    /// children.
    ///
    /// FAILED, because a topology's only terminals are its settle and its
    /// failure — it has no exhaustion terminal, which is a loop's: the settle
    /// needs every member terminal (the fan-in merges each member's branch and
    /// the record names each), and a topology that stopped short has members
    /// that never minted, so the stage has no answer to complete with. Its
    /// failure is the stage's failure (`apply_topology_failed`: the stage fails
    /// and its dependents are skipped); a LOOP-seated topology's is the loop's
    /// member death, which aborts the loop. Members already minted are not
    /// cancelled — they finish, and release nothing. The rows are durable and
    /// never removed, and a topology that settled reached no dispatch point, so
    /// the recompute a settle's fold makes is untouched.
    fn topology_dispatch_unless_walked_away(
        &self,
        members: Vec<u32>,
        live: bool,
    ) -> KataResult<TopologyDrive> {
        let Some(row) = self.durable_walkaway_halt_rows()?.into_iter().next() else {
            return Ok(TopologyDrive::Dispatch { members });
        };
        if live {
            return Ok(TopologyDrive::Wait);
        }
        Ok(TopologyDrive::Failed {
            reason: format!(
                "the run walked away (\"{row}\" recorded a walk-away halt), so the topology \
                 dispatches no further member"
            ),
        })
    }

    /// Drive one `pending` TOPOLOGY expansion attempt one step — the
    /// kind-arm [`Self::drive_expansion`] takes after the spec check. The
    /// resolve calls are the same durable doors the loop's drive uses.
    async fn drive_topology(
        &self,
        pending: &PendingExpansion,
        expansion: &LoweredOperation,
        seat: TopologySeat,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let (drive, view) = self.derive_topology(expansion, seat)?;
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        match drive {
            TopologyDrive::Dispatch { members } => {
                // Settle-first, the loop's Dispatch rule: a member maps its own
                // `/work` branch, and the branch's fork point is frozen at
                // the first member's dispatch.
                self.drive_pending_work_applies()?;
                self.dispatch_topology_members(expansion, seat, &members, &view, outputs)
                    .await
            }
            TopologyDrive::Wait => Ok(()),
            TopologyDrive::Decided(record) => {
                // The settle MERGES the members' `/work` branches, so every
                // member's own apply must have advanced its branch first — a
                // member apply still owed is a wait, never a merge over a branch
                // that does not yet hold the member's write.
                self.drive_pending_work_applies()?;
                let owed = db
                    .pending_work_applies(self.execution_id)?
                    .iter()
                    .any(|row| {
                        OperationPath::from_canonical_bytes(&row.operation_path).is_some_and(
                            |path| {
                                path.0.len() == expansion.path.0.len() + 1
                                    && path.0.starts_with(&expansion.path.0)
                            },
                        )
                    });
                if owed {
                    return Ok(());
                }
                let fanin = self.topology_fan_in(expansion, seat.stage_index(), &view)?;
                match db.resolve_expansion_attempt_merging(
                    pending.attempt_id,
                    &record.to_output(),
                    &fanin,
                )? {
                    Some(_) => {
                        info!(
                            execution_id = %self.execution_id,
                            operation = %expansion.path.program_operation_stage_id(),
                            "expansion: resolved a static topology's record"
                        );
                        Ok(())
                    }
                    None => Ok(()),
                }
            }
            TopologyDrive::Failed { reason } => {
                db.resolve_expansion_attempt(
                    pending.attempt_id,
                    &MainResolution::Fail {
                        reason: &reason,
                        terminal_charge: None,
                    },
                )?;
                Ok(())
            }
        }
    }

    /// The `/work` fan-in a topology's settle merges: the
    /// expanding stage's own head as the parent, and one input per ACCEPTED
    /// member — its occurrence, its own branch, its durable spelling as the
    /// label a conflict report names. A dead optional member contributed no
    /// accepted outcome, so it contributes no branch.
    fn topology_fan_in(
        &self,
        expansion: &LoweredOperation,
        stage_index: usize,
        view: &TopologyView,
    ) -> KataResult<kata_core::operational::JoinFanIn> {
        let stage_id = self
            .execution_program
            .stages
            .keys()
            .nth(stage_index)
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "topology expansion {} maps to stages[{stage_index}] and the program holds \
                     no stage there",
                    expansion.path.program_operation_stage_id()
                ))
            })?;
        let parent = kata_program::execution_program::work_head_coordinate(
            &self.execution_program,
            stage_id,
        )?;
        let mut inputs = Vec::with_capacity(view.members.len());
        for member in &view.members {
            let coordinate = expansion.path.child(member.member);
            let lowered = match view
                .children
                .iter()
                .find(|child| child.member() == member.member)
            {
                Some(child) => self.lower_topology_child(expansion, child)?,
                None => lower_expansion_member(
                    &self.execution_program,
                    expansion,
                    coordinate.clone(),
                    member.member,
                )
                .map_err(|error| {
                    KataError::Internal(format!(
                        "topology member {} does not lower: {error:?}",
                        member.member
                    ))
                })?,
            };
            let occurrence = OccurrenceRef::new(
                ExecutionId(self.execution_id),
                self.execution_program.program_hash,
                lowered.contract.id(),
                coordinate.clone(),
            );
            let branch = kata_program::execution_program::expansion_member_work_coordinate(
                &self.execution_program,
                &coordinate,
                &member.stage,
            )?
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "topology member {} at {} names no stage-expansion branch",
                    member.member,
                    coordinate.program_operation_stage_id()
                ))
            })?;
            inputs.push(kata_core::operational::JoinFanInInput {
                occurrence: occurrence.id().0.0,
                branch,
                label: member.stage.clone(),
            });
        }
        Ok(kata_core::operational::JoinFanIn { parent, inputs })
    }

    /// Dispatch every member of `members` — the topology fanout. Member 0 IS
    /// the parent stage's own dispatch (its render, its checked stage, its
    /// authored gate); member `m ≥ 1` is declared child `m − 1`, minted under
    /// its `<base>#child-<role>` spelling on `ExecutableChild` authority —
    /// the executable-child derived-dispatch arm.
    async fn dispatch_topology_members(
        &self,
        expansion: &LoweredOperation,
        seat: TopologySeat,
        members: &[u32],
        view: &TopologyView,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let stage_index = seat.stage_index();
        let stage_id = self
            .execution_program
            .stages
            .keys()
            .nth(stage_index)
            .cloned()
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "topology expansion {} maps to stages[{stage_index}] and the program \
                     holds no stage there",
                    expansion.path.program_operation_stage_id()
                ))
            })?;
        let base_stage = stage_id.0.clone();
        // The parent prompt renders ONCE — member 0 runs it verbatim, every
        // child's invocation prompt is its header over the same bytes. A
        // stage seat renders the stage as the DAG would; a loop seat
        // renders the loop member exactly as its own dispatch would have —
        // `review.*`, same-iteration siblings, the loop's checked authority
        // and its iteration ≥ 1 approval bypass for the root — recomputed off
        // the loop's durable derive, so a crash re-renders identical bytes.
        let (checked_stage, rendered_parent, root_bypass) = match seat {
            TopologySeat::Stage(_) => {
                let checked_stage = kata_program::execution_program::preflight_stage_dispatch(
                    &self.execution_program,
                    &stage_id,
                )
                .map_err(|error| KataError::Validation(error.to_string()))?;
                let human_requests_ctx = self.human_request_template_context(&base_stage)?;
                let external_inputs_ctx =
                    self.external_input_template_context(&base_stage, &base_stage);
                let memory_ctx = self.memory_selector_template_context(&base_stage)?;
                let workspace_ctx = self.workspace_template_context()?;
                let rendered = self.render_checked_prompt(
                    &base_stage,
                    checked_stage,
                    outputs,
                    None,
                    human_requests_ctx.as_ref(),
                    external_inputs_ctx.as_ref(),
                    memory_ctx.as_ref(),
                    workspace_ctx.as_ref(),
                )?;
                (checked_stage, rendered, None)
            }
            TopologySeat::LoopMember {
                loop_index,
                iteration,
                member,
                ..
            } => {
                let review_loop =
                    lower_review_loop(&self.execution_program, loop_index).map_err(|error| {
                        KataError::Internal(format!(
                            "review loop {loop_index} does not lower: {error:?}"
                        ))
                    })?;
                let (_, loop_view) = self.derive_expansion(&review_loop, loop_index)?;
                let prepared = self.prepare_loop_member(
                    &review_loop,
                    loop_index,
                    iteration,
                    member,
                    &loop_view,
                    outputs,
                )?;
                (
                    prepared.checked_stage,
                    prepared.rendered,
                    prepared.approval_bypass_reason,
                )
            }
        };
        let plan = &checked_stage.invocation_envelope;
        for &member in members {
            let child = (member != 0)
                .then(|| view.children.iter().find(|child| child.member() == member))
                .flatten();
            let lowered = match child {
                Some(child) => self.lower_topology_child(expansion, child)?,
                None => lower_expansion_member(
                    &self.execution_program,
                    expansion,
                    expansion.path.child(member),
                    member,
                )
                .map_err(|error| {
                    KataError::Internal(format!(
                        "topology member {member} does not lower: {error:?}"
                    ))
                })?,
            };
            // The member's capsule class reads `op.agent_label`; the member's
            // executor already resolved it (role agent → `drivers[0]`, a
            // shell role → `Command`). Members only ever lower `Execute`
            // arms — the lowering refuses every other member class.
            let member_label = match &lowered.contract.operation {
                RuntimeOperation::Execute(execute) => match &execute.executor {
                    kata_types::execution_contract::ActionExecutor::Command => {
                        SmolStr::new(kata_types::agent::BackendType::Shell.label())
                    }
                    kata_types::execution_contract::ActionExecutor::Agent { drivers } => {
                        drivers.first().cloned().ok_or_else(|| {
                            KataError::Internal(format!(
                                "topology member {member} lowers to `agent` with no drivers"
                            ))
                        })?
                    }
                    kata_types::execution_contract::ActionExecutor::Effect { .. } => {
                        return Err(KataError::Internal(format!(
                            "topology member {member} lowers to `effect` — the lowering \
                             refuses workspace-effect members"
                        )));
                    }
                },
                operation => {
                    return Err(KataError::Internal(format!(
                        "topology member {member} lowers to `{}` — a capsule member runs \
                         `Execute {{ Command | Agent }}`",
                        operation.as_tag()
                    )));
                }
            };
            // The root's structured-output retry `k` runs at the
            // root seat's `child(k)`: an agent root re-rendered with the
            // validation feedback, a command root re-running its own command.
            let root_retry = (member == 0).then(|| view.root_retry.clone()).flatten();
            let lowered = match &root_retry {
                Some((k, _)) => {
                    let mut seat = lowered;
                    seat.path = seat.path.child(*k);
                    seat
                }
                None => lowered,
            };
            let (member_checked, attempted, prompt) = if member == 0 {
                let mut member_checked = checked_stage.clone();
                member_checked.op.agent_label = Some(member_label);
                let prompt = match &root_retry {
                    Some((_, error))
                        if matches!(
                            &lowered.contract.operation,
                            RuntimeOperation::Execute(execute)
                                if matches!(
                                    execute.executor,
                                    kata_types::execution_contract::ActionExecutor::Agent { .. }
                                )
                        ) =>
                    {
                        super::effect::EffectCoerceRetryPolicy::from_policies(
                            &checked_stage.policies,
                        )
                        .build_retry_prompt(
                            &base_stage,
                            &rendered_parent,
                            error,
                        )?
                    }
                    _ => rendered_parent.clone(),
                };
                (member_checked, base_stage.clone(), prompt)
            } else if let Some(ChildMember::Requested { request, .. }) = child {
                // A requested child, on `DynamicChild` derived authority: the
                // checked role, the request's stage spelling, the dynamic
                // header over the request's prompt.
                let derived_preflight = preflight_derived_dispatch(
                    &self.execution_program,
                    &stage_id,
                    DerivedDispatchKind::DynamicChild {
                        role: &request.role,
                        derived_stage: &request.child_stage,
                    },
                );
                let derived_preflight = match derived_preflight {
                    Ok(preflight) => preflight,
                    Err(error) => {
                        let message = error.to_string();
                        self.record_checked_dispatch_guard_evidence(
                            &stage_id,
                            self.execution_program.stages.get(&stage_id),
                            ExecutionCheckedDispatchGuardStatus::Failed,
                            Some(message.clone()),
                            CheckedDispatchEvidenceContext::derived(
                                ExecutionCheckedDispatchKind::DynamicFanoutChild,
                                &request.child_stage,
                            ),
                        )?;
                        return Err(KataError::Validation(message));
                    }
                };
                let attempted = derived_preflight.expected_stage_name.clone();
                self.record_checked_dispatch_guard_evidence(
                    &stage_id,
                    Some(derived_preflight.checked_stage),
                    ExecutionCheckedDispatchGuardStatus::Passed,
                    None,
                    CheckedDispatchEvidenceContext::derived(
                        ExecutionCheckedDispatchKind::DynamicFanoutChild,
                        &attempted,
                    ),
                )?;
                let mut member_checked = derived_preflight.checked_stage.clone();
                member_checked.op.agent_label = Some(member_label);
                let effective_agent_label = request
                    .agent
                    .clone()
                    .or_else(|| checked_stage.op.agent_label.clone());
                let prompt = super::dispatch::dynamic_child_prompt(
                    &base_stage,
                    request,
                    effective_agent_label.as_deref(),
                );
                (member_checked, attempted, prompt)
            } else {
                let child = &plan.children[(member - 1) as usize];
                let derived_preflight = match preflight_derived_dispatch(
                    &self.execution_program,
                    &stage_id,
                    DerivedDispatchKind::ExecutableChild { role: &child.role },
                ) {
                    Ok(preflight) => preflight,
                    Err(error) => {
                        let message = error.to_string();
                        self.record_checked_dispatch_guard_evidence(
                            &stage_id,
                            self.execution_program.stages.get(&stage_id),
                            ExecutionCheckedDispatchGuardStatus::Failed,
                            Some(message.clone()),
                            CheckedDispatchEvidenceContext::derived(
                                ExecutionCheckedDispatchKind::ExecutableChild,
                                &SmolStr::new(child_invocation_stage_name(
                                    &base_stage,
                                    &child.role,
                                )),
                            ),
                        )?;
                        return Err(KataError::Validation(message));
                    }
                };
                let attempted = derived_preflight.expected_stage_name.clone();
                self.record_checked_dispatch_guard_evidence(
                    &stage_id,
                    Some(derived_preflight.checked_stage),
                    ExecutionCheckedDispatchGuardStatus::Passed,
                    None,
                    CheckedDispatchEvidenceContext::derived(
                        ExecutionCheckedDispatchKind::ExecutableChild,
                        &attempted,
                    ),
                )?;
                let mut member_checked = derived_preflight.checked_stage.clone();
                member_checked.op.agent_label = Some(member_label);
                let effective_agent_label = child
                    .agent
                    .clone()
                    .or_else(|| checked_stage.op.agent_label.clone());
                let prompt = child_invocation_prompt(
                    &base_stage,
                    child,
                    &rendered_parent,
                    effective_agent_label.as_deref(),
                );
                (member_checked, attempted, prompt)
            };
            // The checked authority is the parent's either way — member 0's
            // clone, `preflight_derived_dispatch`'s base stage for a child —
            // so `member_checked`'s policies ARE `checked_stage`'s here; the
            // member's own `agent_label` narrowing is the only field that
            // differs and the sandbox reads none of it.
            let directive = self
                .dispatcher
                .resolve_sandbox(
                    member_checked.policies.sandbox.as_ref(),
                    &self.execution_program.sandbox_profiles,
                    Ulid::new(),
                    self.execution_id,
                    member_checked.should_confine_to_declared_inputs(),
                    member_checked.is_content_cacheable(),
                )
                .await?;
            // The authored `approval` gate applies to the ROOT member only —
            // a declared child bypasses it on a named reason
            // ("executable child invocation").
            let approval_bypass_reason = if member == 0 {
                root_bypass.clone().or_else(|| {
                    (root_retry.is_some() && member_checked.policies.approval_required)
                        .then(|| "schema-validation retry".to_owned())
                })
            } else if member_checked.policies.approval_required {
                Some(match child {
                    Some(ChildMember::Requested { .. }) => "dynamic child invocation".to_owned(),
                    _ => "executable child invocation".to_owned(),
                })
            } else {
                None
            };
            info!(
                execution_id = %self.execution_id,
                stage = %base_stage,
                %member,
                attempted = %attempted,
                "expansion: dispatching topology member"
            );
            self.submit_member_as_capsule(
                &attempted,
                &stage_id,
                &member_checked,
                &lowered,
                directive,
                &RenderedCommand::rendered(prompt),
                approval_bypass_reason,
            )
            .await?;
        }
        Ok(())
    }

    /// Apply a `Settled` topology record to the orchestrator — the durable
    /// record is the bound decision; `view` supplies the member envelopes it
    /// names. The completion arm: the root's accepted output is `parsed`-injected (a
    /// passthrough — its member fold already injected and amended it), the
    /// fan-in attaches onto it, the root's attempt is amended, and the STAGE
    /// completes — the children are never orchestrator stages. Branch routing
    /// is deliberately absent: the fan-in completion takes over before the
    /// routing leg could run, so a child-bearing stage never evaluates routes.
    /// A loop-terminal transition is deliberately absent too: only a STAGE-seated topology
    /// reaches this arm — a topology that is a `loop(..)` member is seated at the loop member's
    /// coordinate, its fold applies no orchestrator transition, and the loop's own record completes
    /// the member stage.
    fn apply_topology_decided(
        &self,
        base_stage: &SmolStr,
        plan: &ExecutionInvocationEnvelope,
        view: &TopologyView,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let Some(root) = view.rows.get(&0) else {
            return Err(KataError::Internal(format!(
                "topology expansion for \"{base_stage}\" settled with no root member row"
            )));
        };
        let output = root.output.clone().ok_or_else(|| {
            KataError::Internal(format!(
                "topology expansion for \"{base_stage}\" settled and its root member \
                 accepted no output"
            ))
        })?;
        let mut envelope =
            match self.inject_parsed_if_declared(base_stage, root.attempt_id, output)? {
                super::dispatch::InjectOutcome::Augmented(env) => env,
                // Unreachable: the derive settles only over a root envelope
                // that already met its contract (`read_topology_root_chain`),
                // so this inject is a passthrough — kept for the enum's
                // completeness.
                super::dispatch::InjectOutcome::QueuedRetry => return Ok(()),
            };
        attach_topology_fan_in(&mut envelope, base_stage, plan, view)?;
        // The root attempt's accepted output is amended with the fan-in,
        // reached through the same deferred door a member inject uses.
        self.amend_or_defer_output(root.attempt_id, envelope.clone())?;
        if matches!(
            self.orchestrator.stage_state(base_stage.as_str()),
            Some(StageState::Pending)
        ) {
            self.orchestrator.promote_to_ready(base_stage.as_str())?;
        }
        // No charge here: the root and every child were charged at their own
        // member frames (`fold_expansion_member`), and this envelope's fan-in
        // summary restates the children's cost — charging it would count them
        // twice.
        if !matches!(
            self.orchestrator.stage_state(base_stage.as_str()),
            Some(StageState::Completed { .. })
        ) {
            self.orchestrator
                .complete_stage(base_stage.as_str(), envelope.clone())?;
            outputs.insert(base_stage.clone(), envelope);
        }
        // A topology that settles after the run walked away releases nothing.
        self.release_nothing_after_walk_away(base_stage.as_str());
        Ok(())
    }

    /// Apply a FAILED topology expansion to the orchestrator: the STAGE fails
    /// (the members' synthetic spellings were never orchestrator stages, so
    /// there is nothing else to transition) and its dependents cascade-skip —
    /// `apply_expansion_failed`'s abort shape, narrowed to one stage.
    fn apply_topology_failed(&self, base_stage: &SmolStr, reason: &str) -> KataResult<()> {
        self.replay_promote_if_pending(base_stage.as_str());
        if !self.member_stage_terminal(base_stage)
            && self
                .orchestrator
                .fail_stage(base_stage.as_str(), reason.to_owned())
                .is_err()
        {
            self.orchestrator
                .skip_stage(base_stage.as_str(), format!("aborted: {reason}"))?;
        }
        self.orchestrator.skip_dependents(base_stage.as_str());
        Ok(())
    }
}

/// The stage a member frame's charge is folded under at workflow scope. A
/// topology child's synthetic `<base>#child-<role>` spelling is no stage: its
/// spend is its topology stage `<base>`'s — the stage whose `cost_budget`
/// covers it and whose dependents a walk-away it trips must skip. Every other
/// member frame (a loop member, a topology root, a retry of either) carries
/// its authored stage.
fn member_charge_stage(stage_name: &SmolStr) -> SmolStr {
    super::dispatch::parse_child_invocation_stage_name(stage_name.as_str())
        .map_or_else(|| stage_name.clone(), |(base, _)| base)
}

/// The `Exhausted` decision's drive arm: `escalate` parks the expansion on
/// the operator reason; `accept`/`fail` decide at once.
fn exhausted_drive(
    config: &kata_types::review_loop::ReviewLoop,
    record: ExpansionRecord,
    cause: Exhaustion<'_>,
) -> ExpansionDrive {
    match config.on_max {
        OnMaxAction::Escalate => ExpansionDrive::Park {
            record,
            reason: escalate_reason(config, cause),
        },
        OnMaxAction::Accept | OnMaxAction::Fail => ExpansionDrive::Decided(record),
    }
}

/// The `ExpansionRecord` a derive reached — the one deterministic
/// construction the resolve writes and the replay recomputes.
fn expansion_record(
    expansion: &LoweredOperation,
    resolution: ExpansionResolution,
    view: &ExpansionView,
) -> ExpansionRecord {
    ExpansionRecord {
        operation: expansion.contract.id().0.to_string(),
        path: expansion.path.program_operation_stage_id(),
        stage: expansion.contract.source_stage.0.to_string(),
        resolution,
        members: view.members.clone(),
        verdicts: view.verdicts.clone(),
        quorum_unmet: None,
    }
}

impl WorkflowRunner {
    /// The fixed-point pass's expansion leg: every `pending` expansion
    /// attempt of this execution re-derives and takes one step — dispatch the
    /// next member, resolve the decided record, park the spent escalate.
    /// Convergent by construction: a resolve that landed since the read makes
    /// `resolve_expansion_attempt` answer `None` and the drive is a no-op.
    pub(super) async fn drive_pending_expansions(
        &self,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        // A drive can CLAIM another expansion — a loop member that is a static
        // topology — so the enumeration repeats until it yields no
        // attempt this pass has not driven yet: a nested claim is driven in
        // the same pass that claimed it.
        let mut driven = std::collections::BTreeSet::new();
        loop {
            let fresh: Vec<PendingExpansion> = db
                .pending_expansion_attempts(self.execution_id)?
                .into_iter()
                .filter(|pending| driven.insert(pending.attempt_id))
                .collect();
            if fresh.is_empty() {
                return Ok(());
            }
            for pending in fresh {
                self.drive_expansion(&pending, outputs).await?;
            }
        }
    }

    /// Drive one `pending` expansion attempt one step. The spec the claim
    /// recorded is re-verified against the program's own lowering before
    /// anything acts on it — a spec the lowering does not reproduce is a
    /// stored-record fault, never a silently-driven expansion.
    async fn drive_expansion(
        &self,
        pending: &PendingExpansion,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let (kind, expansion) = self.lower_pending_expansion(pending)?;
        if let Some(seat) = self.topology_seat(kind)? {
            return self
                .drive_topology(pending, &expansion, seat, outputs)
                .await;
        }
        let ExpansionKind::ReviewLoop(loop_index) = kind else {
            return Err(KataError::Internal(format!(
                "expansion {}'s kind is neither ReviewLoop nor a stage expansion",
                expansion.path.program_operation_stage_id()
            )));
        };
        let (drive, view) = self.derive_expansion(&expansion, loop_index)?;
        self.act_on_expansion_drive(pending, &expansion, loop_index, drive, view, outputs)
            .await
    }

    /// Whether pending expansion attempt `attempt_id` of this execution is a
    /// `loop(..)` whose only open work is a member's transient re-run inside its
    /// backoff ([`ExpansionDrive::Backoff`]) — a park the ordered-shutdown
    /// detach loses nothing by: no attempt is live, nothing dispatches before
    /// the due instant, and the replay re-derives the seat and that instant.
    /// `false` for any other attempt, a topology, or a loop with a live member.
    pub(super) fn expansion_waits_out_a_backoff(&self, attempt_id: Ulid) -> KataResult<bool> {
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let Some(pending) = db
            .pending_expansion_attempts(self.execution_id)?
            .into_iter()
            .find(|pending| pending.attempt_id == attempt_id)
        else {
            return Ok(false);
        };
        let (kind, expansion) = self.lower_pending_expansion(&pending)?;
        let ExpansionKind::ReviewLoop(loop_index) = kind else {
            return Ok(false);
        };
        Ok(matches!(
            self.derive_expansion(&expansion, loop_index)?.0,
            ExpansionDrive::Backoff
        ))
    }

    /// The program's own lowering of pending expansion attempt `pending`,
    /// re-verified against the spec its claim recorded — a spec the lowering
    /// does not reproduce is a stored-record fault, never a silently-driven
    /// expansion.
    fn lower_pending_expansion(
        &self,
        pending: &PendingExpansion,
    ) -> KataResult<(ExpansionKind, LoweredOperation)> {
        let kind = match program_operation_at(&self.execution_program, &pending.spec.path) {
            Some(ProgramOperationAt::Expansion(kind)) => kind,
            other => {
                return Err(KataError::Storage(format!(
                    "pending expansion {} names a path this program maps to {other:?}, \
                     never to an ExpandBounded",
                    pending.spec.path.program_operation_stage_id(),
                )));
            }
        };
        let expansion = self.lower_expansion_at(kind).map_err(|error| {
            KataError::Storage(format!(
                "pending expansion {} maps to {kind:?} and does not lower: {error:?}",
                pending.spec.path.program_operation_stage_id()
            ))
        })?;
        if pending.spec.operation != expansion.contract.id().0.to_string()
            || pending.spec.path != expansion.path
        {
            return Err(KataError::Storage(format!(
                "pending expansion attempt {}'s recorded spec disagrees with the program's \
                 own lowering of it (spec operation {}, path {}; lowering {})",
                pending.attempt_id,
                pending.spec.operation,
                pending.spec.path.program_operation_stage_id(),
                expansion.path.program_operation_stage_id(),
            )));
        }
        Ok((kind, expansion))
    }

    /// Take the one step `drive` names for loop expansion `expansion`
    /// (pending attempt `pending`, its derive's `view`).
    async fn act_on_expansion_drive(
        &self,
        pending: &PendingExpansion,
        expansion: &LoweredOperation,
        loop_index: usize,
        drive: ExpansionDrive,
        view: ExpansionView,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        match drive {
            ExpansionDrive::Dispatch {
                iteration,
                member,
                seat,
            } => {
                // The member maps the `/work` head the LAST accepted member's
                // apply advanced: settle pending applies first, or iteration
                // N+1 would map a head that iteration N has not landed on.
                self.drive_pending_work_applies()?;
                self.dispatch_expansion_member(
                    expansion, loop_index, iteration, member, seat, &view, outputs,
                )
                .await
            }
            ExpansionDrive::Wait | ExpansionDrive::Backoff => Ok(()),
            ExpansionDrive::Decided(record) => {
                // Land every owed `/work` apply first — a nested topology
                // member's merged delta is recorded under its own `#op`,
                // which no stage-named successor gate reads, so the loop's
                // dependents must not be released over a head it has not
                // reached yet.
                self.drive_pending_work_applies()?;
                let output = record.to_output();
                match db.resolve_expansion_attempt(
                    pending.attempt_id,
                    &MainResolution::Complete { output: &output },
                )? {
                    Some(_) => {
                        info!(
                            execution_id = %self.execution_id,
                            operation = %expansion.path.program_operation_stage_id(),
                            resolution = ?record.resolution,
                            "expansion: resolved its record"
                        );
                        Ok(())
                    }
                    None => Ok(()),
                }
            }
            ExpansionDrive::Park { record, reason } => {
                if db
                    .park_expansion_attempt(pending.attempt_id, &reason, &record.to_output())?
                    .is_some()
                {
                    info!(
                        execution_id = %self.execution_id,
                        operation = %expansion.path.program_operation_stage_id(),
                        "expansion: bound spent under `escalate`; the gate is parked"
                    );
                }
                Ok(())
            }
            ExpansionDrive::Failed { reason, .. } => {
                db.resolve_expansion_attempt(
                    pending.attempt_id,
                    &MainResolution::Fail {
                        reason: &reason,
                        terminal_charge: None,
                    },
                )?;
                Ok(())
            }
        }
    }

    /// Dispatch iteration `iteration`'s member `member` of `expansion` — the
    /// derive's `Dispatch` arm. Everything the member is rendered and
    /// authorized with comes out of `view` (durable) and `outputs` (the run's
    /// accumulated non-member completions), so two runs at the same durable
    /// state render the identical bytes.
    async fn dispatch_expansion_member(
        &self,
        expansion: &LoweredOperation,
        loop_index: usize,
        iteration: u32,
        member: u32,
        seat: MemberSeat,
        view: &ExpansionView,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let mut prepared =
            self.prepare_loop_member(expansion, loop_index, iteration, member, view, outputs)?;
        prepared.lowered.path = seat.coordinate(&prepared.lowered.path);
        // A transient provider re-run `k` runs at the member seat's `child(k)`
        // re-rendered from the same inputs (no feedback), and an authored
        // approval gate is not asked again ("failure retry") — the plain
        // stage's re-run rule.
        if matches!(seat, MemberSeat::TransientRerun { .. })
            && prepared.checked_stage.policies.approval_required
            && prepared.approval_bypass_reason.is_none()
        {
            prepared.approval_bypass_reason = Some("failure retry".to_owned());
        }
        // Retry `k` of the member's structured-output chain runs
        // at the member seat's `child(k)`: an AGENT member re-rendered with
        // the validation feedback, a COMMAND member re-running
        // its own command verbatim (the plain-stage rule), and an authored
        // approval gate not asked again ("schema-validation retry").
        if let MemberSeat::Validation { error, .. } = seat {
            let policy = super::effect::EffectCoerceRetryPolicy::from_policies(
                &prepared.checked_stage.policies,
            );
            if matches!(
                prepared.lowered.contract.operation,
                RuntimeOperation::Execute(kata_types::execution_contract::ExecuteOperation {
                    executor: kata_types::execution_contract::ActionExecutor::Agent { .. },
                    ..
                })
            ) {
                prepared.rendered = policy.build_retry_prompt(
                    &prepared.member_stage.0,
                    &prepared.rendered,
                    &error,
                )?;
            }
            if prepared.checked_stage.policies.approval_required
                && prepared.approval_bypass_reason.is_none()
            {
                prepared.approval_bypass_reason = Some("schema-validation retry".to_owned());
            }
        }
        // A static-topology member is its own nested expansion — the loop
        // CLAIMS it; its members dispatch off its own drive, rendered with the
        // same `prepare_loop_member` answer this member would have run with.
        if matches!(
            prepared.lowered.contract.operation,
            RuntimeOperation::ExpandBounded { .. }
        ) {
            if let ExpansionClaimOutcome::Claimed { claim_seq } =
                self.claim_expansion(&prepared.lowered)?
            {
                info!(
                    execution_id = %self.execution_id,
                    %claim_seq,
                    operation = %prepared.lowered.path.program_operation_stage_id(),
                    "expansion: claimed a loop member's nested topology"
                );
            }
            return Ok(());
        }
        // The two MAIN-RESOLVED member classes resolve at the member
        // seat through the same doors a top-level stage takes — the drive
        // drained every earlier member's pending `/work` apply (the
        // `Dispatch` arm's `drive_pending_work_applies`), so a
        // `workspace_effect` member's verbs fence on the head the iteration
        // built, and a `memory_snapshot` member answers inside its
        // claim-and-resolve transaction.
        match &prepared.lowered.contract.operation {
            RuntimeOperation::MemorySnapshot { query } => {
                self.resolve_memory_snapshot(&prepared.member_stage.0, &prepared.lowered, *query)?;
                return Ok(());
            }
            RuntimeOperation::Execute(kata_types::execution_contract::ExecuteOperation {
                executor: kata_types::execution_contract::ActionExecutor::Effect { .. },
                ..
            }) => {
                self.submit_workspace_effect(&prepared.member_stage.0, &prepared.lowered)?;
                return Ok(());
            }
            _ => {}
        }
        // A member is a capsule dispatch — the shared predicate
        // `member_operation_is_oci_runnable` the CHECK door admits a loop
        // member by (`Execute { Command | Agent }`; a nested static topology
        // and the main-resolved classes were served above). Any other
        // operation (a `Wait`, a `Join`, an `Invoke`) is a member class with
        // no dispatch answer and is refused by name rather than mis-routed.
        // Reachable only when a program predates the CHECK door —
        // `refuse_program_under_capsule_profile` refuses the same set under
        // `loop_member_not_a_capsule_under_oci`.
        if !kata_program::execution_program::member_operation_is_oci_runnable(
            &prepared.lowered.contract.operation,
        ) {
            return Err(KataError::Validation(format!(
                "expansion member ({iteration}, {member}) (stage {}) lowers to `{}`, which \
                 has no dispatch answer inside an iteration — under `oci` a loop member is \
                 an `Execute {{ Command | Agent }}` capsule, a `memory_snapshot` or \
                 `workspace_effect`, or a static topology",
                prepared.member_stage.0,
                prepared.lowered.contract.operation.as_tag(),
            )));
        }
        let directive = self
            .dispatcher
            .resolve_sandbox(
                prepared.checked_stage.policies.sandbox.as_ref(),
                &self.execution_program.sandbox_profiles,
                Ulid::new(),
                self.execution_id,
                prepared.checked_stage.should_confine_to_declared_inputs(),
                prepared.checked_stage.is_content_cacheable(),
            )
            .await?;
        info!(
            execution_id = %self.execution_id,
            stage = %prepared.member_stage.0,
            %iteration, %member,
            "expansion: dispatching member"
        );
        self.submit_stage_as_capsule(
            &prepared.member_stage.0,
            &prepared.lowered,
            directive,
            &RenderedCommand::rendered(prepared.rendered),
            prepared.approval_bypass_reason,
        )
        .await
    }

    /// Everything iteration `iteration`'s member `member` of `review_loops[loop_index]`
    /// is lowered, authorized and rendered with — the checked authority (static at a
    /// body member's iteration 0, `ReviewLoopIteration`-derived otherwise, with its
    /// guard evidence), the per-iteration effects member 0 fires, the `review.*` and
    /// same-iteration `stages.*` render, and the iteration ≥ 1 approval bypass. Shared
    /// by the member's own dispatch and, for a static-topology member, by its
    /// nested topology's drive, so the root renders with exactly the bytes a plain
    /// member would have. Deterministic over `view` (durable) and `outputs`.
    fn prepare_loop_member(
        &self,
        expansion: &LoweredOperation,
        loop_index: usize,
        iteration: u32,
        member: u32,
        view: &ExpansionView,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<PreparedLoopMember<'_>> {
        let RuntimeOperation::ExpandBounded { template, .. } = &expansion.contract.operation else {
            return Err(KataError::Internal(
                "dispatch_expansion_member requires an `ExpandBounded` lowering".to_owned(),
            ));
        };
        let member_count = u32::try_from(template.len()).map_err(|_| {
            KataError::Internal(format!(
                "expansion {}'s template does not fit a u32 member index",
                expansion.path.program_operation_stage_id()
            ))
        })?;
        let coordinate = expansion.path.child(iteration).child(member);
        let lowered =
            lower_expansion_member(&self.execution_program, expansion, coordinate, member)
                .map_err(|error| {
                    KataError::Internal(format!(
                        "expansion member ({iteration}, {member}) does not lower: {error:?}"
                    ))
                })?;
        let member_stage = lowered.contract.source_stage.clone();
        let participant = if member + 1 == member_count {
            ReviewLoopParticipant::Reviewer
        } else if member + 2 == member_count {
            ReviewLoopParticipant::Worker
        } else {
            ReviewLoopParticipant::BodyMember
        };
        let attempted = kata_program::loops::iteration_stage_name(&member_stage.0, iteration);
        // The dispatch rule: a body member at iteration 0 IS the
        // stage's static dispatch (the derived `ReviewLoopIteration` kind refuses
        // it by name); the gate is derived at every iteration, and every member
        // at iteration ≥ 1 is.
        let checked_stage = if participant != ReviewLoopParticipant::Reviewer && iteration == 0 {
            match kata_program::execution_program::preflight_stage_dispatch(
                &self.execution_program,
                &member_stage,
            ) {
                Ok(checked_stage) => {
                    self.record_checked_dispatch_guard_evidence(
                        &member_stage,
                        Some(checked_stage),
                        ExecutionCheckedDispatchGuardStatus::Passed,
                        None,
                        CheckedDispatchEvidenceContext::static_stage(),
                    )?;
                    checked_stage
                }
                Err(error) => {
                    let message = error.to_string();
                    self.record_checked_dispatch_guard_evidence(
                        &member_stage,
                        self.execution_program.stages.get(&member_stage),
                        ExecutionCheckedDispatchGuardStatus::Failed,
                        Some(message.clone()),
                        CheckedDispatchEvidenceContext::static_stage(),
                    )?;
                    return Err(KataError::Validation(message));
                }
            }
        } else {
            let derived_preflight = match preflight_derived_dispatch(
                &self.execution_program,
                &member_stage,
                DerivedDispatchKind::ReviewLoopIteration {
                    participant,
                    iteration,
                },
            ) {
                Ok(preflight) => preflight,
                Err(error) => {
                    let message = error.to_string();
                    self.record_checked_dispatch_guard_evidence(
                        &member_stage,
                        self.execution_program.stages.get(&member_stage),
                        ExecutionCheckedDispatchGuardStatus::Failed,
                        Some(message.clone()),
                        CheckedDispatchEvidenceContext::derived(
                            ExecutionCheckedDispatchKind::ReviewLoopIteration,
                            &attempted,
                        ),
                    )?;
                    return Err(KataError::Validation(message));
                }
            };
            self.record_checked_dispatch_guard_evidence(
                &member_stage,
                Some(derived_preflight.checked_stage),
                ExecutionCheckedDispatchGuardStatus::Passed,
                None,
                CheckedDispatchEvidenceContext::derived(
                    ExecutionCheckedDispatchKind::ReviewLoopIteration,
                    &attempted,
                ),
            )?;
            derived_preflight.checked_stage
        };
        let config = &self.execution_program.review_loops[loop_index];
        // Two per-iteration effects fire before the iteration's first stage
        // dispatches, and member 0 of `iteration` is that seam: the just-completed iteration's
        // declared memory writebacks (so this iteration's live selector reads
        // observe them — the final iteration's is the terminal pass's), and
        // the continue-as-new durable write when `iteration` opens a new
        // rollover generation. Both re-fire harmlessly on a re-derived
        // dispatch — the writeback is CAS-idempotent and the rollover key
        // conflicts swallowed.
        if member == 0 && iteration >= 1 {
            self.fire_iteration_writeback(iteration - 1);
        }
        let rollover = kata_program::loops::rollover_context_for(
            config,
            iteration,
            view.latest_feedback.as_deref(),
        );
        if member == 0
            && let Some(ctx) = rollover.as_ref().filter(|ctx| ctx.at_boundary)
        {
            self.persist_rollover_memory(config.worker_stage.as_str(), ctx);
        }
        // `{{ review.* }}` — the shared `render_review_context` shape:
        // generation-0 byte-identical, the `rollover` descriptor carried from
        // generation ≥ 1, and at a generation boundary `previous_output` /
        // `feedback` replaced by the bounded distilled summary.
        let review_ctx = kata_program::loops::render_review_context(
            iteration,
            view.latest_worker.as_ref(),
            view.latest_feedback.as_deref(),
            rollover.as_ref(),
        );
        // `{{ stages.* }}` — the run's non-member completions, plus the
        // current iteration's earlier members, plus the worker base for the
        // gate (the latest worker output under its own name).
        let mut prior_outputs = outputs.clone();
        for (stage, envelope) in &view.current_iter_outputs {
            prior_outputs.insert(stage.clone(), envelope.clone());
        }
        if participant == ReviewLoopParticipant::Reviewer {
            prior_outputs.insert(
                SmolStr::new(config.worker_stage.as_str()),
                view.latest_worker
                    .clone()
                    .unwrap_or(serde_json::Value::Null),
            );
        }
        let human_requests_ctx = self.human_request_template_context(&member_stage.0)?;
        let external_inputs_ctx = self.external_input_template_context(&member_stage.0, &attempted);
        let memory_ctx = self.memory_selector_template_context(&member_stage.0)?;
        let workspace_ctx = self.workspace_template_context()?;
        let rendered = self.render_checked_prompt(
            &attempted,
            checked_stage,
            &prior_outputs,
            Some(&review_ctx),
            human_requests_ctx.as_ref(),
            external_inputs_ctx.as_ref(),
            memory_ctx.as_ref(),
            workspace_ctx.as_ref(),
        )?;
        // Iteration ≥1 body members bypass the authored `approval` gate on
        // checked authority: the loop's own gate is the reviewer's.
        // The GATE keeps its gate on every iteration (the reviewer parks each
        // iteration, by design).
        let approval_bypass_reason = if checked_stage.policies.approval_required
            && participant != ReviewLoopParticipant::Reviewer
            && iteration >= 1
        {
            Some(format!(
                "review loop {} member at iteration {iteration} (>= 1): the loop's \
                 own gate is the reviewer's",
                expansion.path.program_operation_stage_id(),
            ))
        } else {
            None
        };
        Ok(PreparedLoopMember {
            lowered,
            member_stage,
            checked_stage,
            rendered,
            approval_bypass_reason,
        })
    }

    /// Apply an ACCEPTED expansion record to the orchestrator — the durable
    /// record is the bound decision; `view` supplies the member envelopes it
    /// names, one arm per resolution:
    /// `Approved`/`Blocked`/`Exhausted{accept,fail,escalate-adopted}`.
    fn apply_expansion_decided(
        &self,
        loop_index: usize,
        record: &ExpansionRecord,
        view: &ExpansionView,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let config = &self.execution_program.review_loops[loop_index];
        let worker_base = config.worker_stage.clone();
        let reviewer_base = config.reviewer_stage.clone();
        let member_count = view.member_count;
        let worker_stub = || {
            serde_json::json!({
                "content": "",
                "stage": worker_base.as_str(),
            })
        };
        match &record.resolution {
            ExpansionResolution::Approved { .. } => {
                self.complete_body_members(member_count, view, outputs);
                let w = view.latest_worker.clone().unwrap_or_else(worker_stub);
                self.complete_member_stage(&worker_base, w, outputs);
                self.complete_member_stage(
                    &reviewer_base,
                    view.latest_reviewer.clone().unwrap_or_default(),
                    outputs,
                );
                if let Some(envelope) = &view.latest_reviewer {
                    self.route_after_completion(&reviewer_base, envelope)?;
                }
            }
            ExpansionResolution::Blocked { .. } => {
                self.complete_body_members(member_count, view, outputs);
                let gate_has_branch = self
                    .execution_program
                    .branch_routes
                    .iter()
                    .any(|route| route.condition_stage.0 == reviewer_base);
                if gate_has_branch {
                    let w = view.latest_worker.clone().unwrap_or_else(worker_stub);
                    self.complete_member_stage(&worker_base, w.clone(), outputs);
                } else {
                    let reason = format!(
                        "review blocked: {}",
                        view.latest_feedback
                            .as_deref()
                            .unwrap_or("no feedback provided")
                    );
                    self.replay_promote_if_pending(worker_base.as_str());
                    if !self.member_stage_terminal(&worker_base) {
                        self.orchestrator.fail_stage(worker_base.as_str(), reason)?;
                    }
                    if let Some(w) = view.latest_worker.clone() {
                        outputs.insert(SmolStr::new(worker_base.as_str()), w);
                    }
                }
                self.complete_member_stage(
                    &reviewer_base,
                    view.latest_reviewer.clone().unwrap_or_default(),
                    outputs,
                );
                // With no route on the gate the block is the loop's answer — its
                // failed worker — so nothing behind the gate may run on the
                // candidate it refused: the gate completes as the record's member
                // and its dependents are skipped, exactly as `Exhausted{fail}`'s
                // are. A route on the gate routes the block instead (below).
                if !gate_has_branch {
                    self.orchestrator.skip_dependents(reviewer_base.as_str());
                }
                if let Some(envelope) = &view.latest_reviewer {
                    self.route_after_completion(&reviewer_base, envelope)?;
                }
            }
            // A `Settled` record is a TOPOLOGY expansion's answer — the kind
            // routes through `fold_topology_expansion` to
            // `apply_topology_decided` before this loop apply ever sees it,
            // so reaching here is a kind-routing fault, never a foldable one.
            ExpansionResolution::Settled => {
                return Err(KataError::Internal(format!(
                    "a `Settled` expansion record reached `review_loops[{loop_index}]`'s \
                     apply — that resolution is a static topology's, which folds through \
                     the topology arm"
                )));
            }
            ExpansionResolution::Exhausted { on_max, .. } => {
                // A RUN walk-away stopped the loop (`dispatch_unless_walked_away`;
                // this fold's own recompute re-derived the cause into `view`): the
                // candidate it ended on is no gate's judgement, so no route on the
                // gate takes an arm. (What the record releases is the walk-away
                // latch's to decide, `release_nothing_behind_loop`.)
                let run_walked_away = matches!(view.stop, Some(LoopStop::RunWalkedAway(_)));
                self.complete_body_members(member_count, view, outputs);
                match on_max {
                    ExpansionOnMax::Fail => {
                        let reason = exhausted_reason(config, view);
                        self.replay_promote_if_pending(worker_base.as_str());
                        if !self.member_stage_terminal(&worker_base) {
                            self.orchestrator.fail_stage(worker_base.as_str(), reason)?;
                        }
                    }
                    ExpansionOnMax::Accept | ExpansionOnMax::Escalate => {
                        // Escalate ADOPTED: the parked gate was approved and
                        // the worker takes its last iteration's output —
                        // `accept` and the operator's approve converge on the
                        // same completion.
                        let w = view.latest_worker.clone().unwrap_or_else(worker_stub);
                        self.complete_member_stage(&worker_base, w.clone(), outputs);
                    }
                }
                self.complete_member_stage(
                    &reviewer_base,
                    view.latest_reviewer.clone().unwrap_or_default(),
                    outputs,
                );
                // Under `fail` the loop's answer is its failed worker: the gate
                // completes as the record's member, but nothing behind it may run
                // on the candidate the loop ended on — its dependents are
                // skipped, exactly as a walk-away's are. (After a run walk-away,
                // under every `on_exhaustion`, `release_nothing_behind_loop`
                // skips them below.)
                if matches!(on_max, ExpansionOnMax::Fail) {
                    self.orchestrator.skip_dependents(reviewer_base.as_str());
                }
                // `accept` ADOPTS the gate's last classified report and routes
                // it — when that report judged the candidate the loop ended on —
                // through `route_accepted_exhaustion`, which rewrites a
                // quorum-unmet verdict's field to the refine tag. Under `fail`
                // the loop's own exhaustion owns the run, after a run walk-away
                // no arm may run either, and an adopted `escalate` had its arms
                // skipped when it parked. A per-loop
                // bound that tripped before the last iteration's gate
                // classified leaves no report that judged the candidate
                // (`ExpansionRecord::is_unjudged_accept_exhaustion`): routing an
                // earlier iteration's report would let an arm act on a tree no
                // gate judged, so every arm is skipped instead, before any
                // quorum rewrite, and an isolated run that ends on that
                // candidate parks it at closeout.
                match (on_max, &view.latest_reviewer) {
                    (ExpansionOnMax::Accept, Some(report))
                        if !run_walked_away && !record.is_unjudged_accept_exhaustion() =>
                    {
                        self.route_accepted_exhaustion(loop_index, view, report)?;
                    }
                    _ => self.skip_all_branch_arms_for_condition(&reviewer_base),
                }
            }
        }
        self.release_nothing_behind_loop(loop_index);
        Ok(())
    }

    /// A loop record that applies after the run walked away releases nothing:
    /// every stage behind any of `review_loops[loop_index]`'s members — the gate's
    /// dependents and its route arms, and a stage that depends on the worker or a
    /// body member directly — is skipped
    /// ([`WorkflowRunner::release_nothing_after_walk_away`]), whatever the record
    /// decided. Run AFTER the record's member transitions, so the members
    /// themselves (each other's dependents) keep the terminal the record gave
    /// them.
    fn release_nothing_behind_loop(&self, loop_index: usize) {
        let config = &self.execution_program.review_loops[loop_index];
        for member in &config.body_stages {
            self.release_nothing_after_walk_away(member.0.as_str());
        }
        self.release_nothing_after_walk_away(config.worker_stage.as_str());
        self.release_nothing_after_walk_away(config.reviewer_stage.as_str());
    }

    /// Route the gate's last classified `report` of `review_loops[loop_index]`,
    /// which exhausted under `accept`.
    ///
    /// When the verdict that classified `report` met its quorum (or the gate
    /// declares none), every route on the gate routes `report` exactly as it
    /// routes a completion. When that verdict's `review_quorum` was NOT met, the
    /// verdict's action was `refine` whatever the root's tag read, so the root's
    /// report is not what the loop classified: a route that reads the loop's
    /// verdict field routes the report with that field rewritten to the loop's
    /// refine tag (`loop_gate_quorum_needs_default_verdicts` keeps a quorum gate
    /// on the default vocabulary, whose refine tag is `refine`, and
    /// `loop_accept_quorum_route_needs_refine_tag` makes it one of that route's
    /// arm tags, so the route takes an arm), and a route on
    /// any OTHER field of the report — a value the quorum refused — skips every
    /// arm. A quorum-refused candidate therefore never takes an arm its root's
    /// tag alone would select.
    fn route_accepted_exhaustion(
        &self,
        loop_index: usize,
        view: &ExpansionView,
        report: &serde_json::Value,
    ) -> KataResult<()> {
        let config = &self.execution_program.review_loops[loop_index];
        let gate = &config.reviewer_stage;
        let quorum_unmet = view
            .verdicts
            .last()
            .is_some_and(|verdict| verdict.quorum_unmet.is_some());
        if !quorum_unmet {
            return self.route_after_completion(gate, report);
        }
        let gate_config = config.effective_gate_verdict();
        let refine_tag = gate_config.refine.first().ok_or_else(|| {
            KataError::Internal(format!(
                "loop gate {gate:?}'s verdict vocabulary names no refine tag; \
                 `LoopVerdictConfig::validate` refuses an empty refine set"
            ))
        })?;
        let mut refined = report.clone();
        let parsed = refined
            .get_mut("parsed")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "loop gate {gate:?}'s classified report carries no `parsed` object; \
                     its verdict was read from one"
                ))
            })?;
        parsed.insert(
            gate_config.verdict_field.to_string(),
            serde_json::Value::String(refine_tag.to_string()),
        );
        for (index, route) in self.execution_program.branch_routes.iter().enumerate() {
            if route.condition_stage.0 != *gate {
                continue;
            }
            if route.verdict_field == gate_config.verdict_field {
                self.resolve_route(index, route, &refined)?;
            } else {
                self.skip_route_arms(gate, route);
            }
        }
        Ok(())
    }

    /// Apply the parked-escalation effects — the durable `#op` attempt's
    /// `awaiting_approval` frame folds here: the worker pauses (its latest
    /// output rides `outputs`), the reviewer completes, the members complete,
    /// the gate's branch arms skip. The parked attempt itself is the
    /// escalation gate.
    fn apply_expansion_gate_parked(
        &self,
        loop_index: usize,
        reason: &str,
        view: &ExpansionView,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let config = &self.execution_program.review_loops[loop_index];
        let worker_base = config.worker_stage.clone();
        let reviewer_base = config.reviewer_stage.clone();
        let member_count = view.member_count;
        if !self.member_stage_terminal(&worker_base)
            && !matches!(
                self.orchestrator.stage_state(worker_base.as_str()),
                Some(StageState::AwaitingApproval { .. })
            )
        {
            self.replay_promote_if_pending(worker_base.as_str());
            self.orchestrator
                .pause_stage_for_approval(worker_base.as_str(), reason.to_owned())?;
        }
        if let Some(w) = view.latest_worker.clone() {
            outputs.insert(SmolStr::new(worker_base.as_str()), w);
        }
        self.complete_body_members(member_count, view, outputs);
        self.complete_member_stage(
            &reviewer_base,
            view.latest_reviewer.clone().unwrap_or_default(),
            outputs,
        );
        self.skip_all_branch_arms_for_condition(&reviewer_base);
        Ok(())
    }

    /// Apply a FAILED expansion to the orchestrator — the loop abort, except
    /// the iteration-0 non-exit member death, which is
    /// an ordinary DAG failure (only that member fails; the rest of the
    /// loop stages sit `Pending` behind it and the run reports stuck-with-
    /// failed-stage).
    fn apply_expansion_failed(
        &self,
        loop_index: usize,
        reason: &str,
        death: Option<MemberDeath>,
        view: &ExpansionView,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let config = &self.execution_program.review_loops[loop_index];
        let worker_base = config.worker_stage.clone();
        let reviewer_base = config.reviewer_stage.clone();
        let member_count = view.member_count;
        if let Some(death) = &death
            && death.iteration == 0
            && death.member + 2 < member_count
        {
            // Loop-member deaths are intercepted only from iteration 1 — a
            // NON-EXIT body member that dies at iteration 0 is a plain DAG
            // failure: the member's own stage fails and nothing else
            // transitions. (The worker and the gate are intercepted at every
            // iteration — their death is always the abort below.)
            self.replay_promote_if_pending(death.stage.as_str());
            if !self.member_stage_terminal(&death.stage) {
                self.orchestrator
                    .fail_stage(death.stage.as_str(), death.member_reason.clone())?;
            }
            return Ok(());
        }
        // The abort: the worker fails, the gate and never-run members skip,
        // members that ran keep their deepest completion (`Completed`),
        // and the worker's dependents cascade-skip.
        self.complete_body_members(member_count, view, outputs);
        self.replay_promote_if_pending(worker_base.as_str());
        if !self.member_stage_terminal(&worker_base)
            && self
                .orchestrator
                .fail_stage(worker_base.as_str(), reason.to_owned())
                .is_err()
        {
            self.orchestrator
                .skip_stage(worker_base.as_str(), format!("aborted: {reason}"))?;
        }
        for member in 0..member_count.saturating_sub(1) {
            let Some(stage) = view.member_stage.get(&member) else {
                continue;
            };
            if stage.as_str() == worker_base.as_str() {
                continue;
            }
            if view.latest_member_envelope.contains_key(&member) {
                continue; // completed above with its deepest envelope
            }
            if !self.member_stage_terminal(stage) {
                self.orchestrator
                    .skip_stage(stage.as_str(), format!("aborted: {reason}"))?;
            }
        }
        if !self.member_stage_terminal(&reviewer_base) {
            self.orchestrator
                .skip_stage(reviewer_base.as_str(), format!("aborted: {reason}"))?;
        }
        self.orchestrator.skip_dependents(worker_base.as_str());
        self.release_nothing_behind_loop(loop_index);
        Ok(())
    }

    /// Whether the orchestrator already holds `stage` terminal — the guard
    /// every resolution apply carries so a re-fold converges rather than
    /// erroring on a `cannot <verb> stage in state <terminal>`.
    fn member_stage_terminal(&self, stage: &SmolStr) -> bool {
        matches!(
            self.orchestrator.stage_state(stage.as_str()),
            Some(
                StageState::Completed { .. }
                    | StageState::Failed { .. }
                    | StageState::Skipped { .. }
            )
        )
    }

    /// Complete ONE member stage with `envelope` (promoting it out of
    /// `Pending` first — under `oci` only the body-entry member's stage ever
    /// reaches `Ready`, the rest sit `Pending` until the record applies),
    /// and record it in `outputs`. No-op when the stage is already terminal.
    fn complete_member_stage(
        &self,
        stage: &SmolStr,
        envelope: serde_json::Value,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) {
        if !self.member_stage_terminal(stage) {
            self.replay_promote_if_pending(stage.as_str());
            if let Err(error) = self
                .orchestrator
                .complete_stage(stage.as_str(), envelope.clone())
            {
                warn!(
                    execution_id = %self.execution_id,
                    %stage,
                    %error,
                    "expansion: member stage did not complete with the record's envelope"
                );
            }
        }
        self.record_output_closure_observation(stage, stage);
        outputs.insert(stage.clone(), envelope);
    }

    /// Complete every non-exit body member (template indices `0..len-2`) that
    /// ran, with its DEEPEST accepted envelope — the resolving iteration's
    /// answer `run show` projects off the member's last attempt, so the run's
    /// `outputs` and the show read agree: a member completed at iteration 0
    /// and never rewritten would leave a stale member beside the approved
    /// worker for any downstream read.
    fn complete_body_members(
        &self,
        member_count: u32,
        view: &ExpansionView,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) {
        for member in 0..member_count.saturating_sub(2) {
            let Some(stage) = view.member_stage.get(&member) else {
                continue;
            };
            if let Some(envelope) = view.latest_member_envelope.get(&member) {
                self.complete_member_stage(stage, envelope.clone(), outputs);
            }
        }
    }
}

/// The `ExpansionOnMax` an authored `OnMaxAction` maps to in the record.
fn expansion_on_max(on_max: OnMaxAction) -> ExpansionOnMax {
    match on_max {
        OnMaxAction::Accept => ExpansionOnMax::Accept,
        OnMaxAction::Fail => ExpansionOnMax::Fail,
        OnMaxAction::Escalate => ExpansionOnMax::Escalate,
    }
}

/// Why a loop exhausted — a walk-away (a per-loop bound's own message, an
/// exceeded ceiling or an unenforceable one alike, or the run's own walk-away),
/// or the gate refined through `max_iterations` (the last verdict's feedback).
#[derive(Clone, Copy, Debug)]
enum Exhaustion<'a> {
    /// `kata_program::loops::loop_bounds_trip`'s reason, or
    /// `WorkflowRunner::dispatch_unless_walked_away`'s.
    BoundTrip(&'a str),
    /// The iteration ceiling, with the last gate's feedback.
    Iterations { last_feedback: &'a str },
}

/// The operator-facing reason a spent bound parks under: a bound trip leads
/// with its own message, an iteration exhaustion leads with the iteration
/// count.
fn escalate_reason(config: &kata_types::review_loop::ReviewLoop, cause: Exhaustion<'_>) -> String {
    match cause {
        Exhaustion::BoundTrip(trip) => {
            format!("review loop walk-away: {trip}; operator escalation requested")
        }
        Exhaustion::Iterations { last_feedback } => format!(
            "review loop exhausted after {} iterations; operator escalation requested. \
             Last feedback: {last_feedback}",
            config.max_iterations,
        ),
    }
}

/// The worker-failure reason an `Exhausted{Fail}` resolution applies.
fn exhausted_reason(config: &kata_types::review_loop::ReviewLoop, view: &ExpansionView) -> String {
    let display = view
        .stop
        .as_ref()
        .map(|stop| stop.reason().to_owned())
        .or_else(|| view.latest_feedback.clone())
        .unwrap_or_else(|| "none".to_owned());
    if view.stop.is_some() {
        format!("review loop walk-away: {display}")
    } else {
        format!(
            "review loop exhausted after {} iterations; last feedback: {display}",
            config.max_iterations,
        )
    }
}
impl WorkflowRunner {
    /// CLAIM the `review_loops[loop_index]` expansion's durable main attempt —
    /// the test door for the claim [`Self::claim_expansion_for_member`] rides.
    ///
    /// # Errors
    ///
    /// `claim_expansion`'s set.
    #[doc(hidden)]
    pub fn claim_expansion_for_test(&self, loop_index: usize) -> KataResult<ExpansionClaimOutcome> {
        let expansion =
            lower_review_loop(&self.execution_program, loop_index).map_err(|error| {
                KataError::Validation(format!(
                    "review loop {loop_index} does not lower: {error:?}"
                ))
            })?;
        self.claim_expansion(&expansion)
    }

    /// Drive every `pending` expansion attempt one step, exactly as one drive pass does —
    /// the test door a cell uses to act as a SECOND driver of the same execution.
    ///
    /// # Errors
    ///
    /// `drive_pending_expansions`'s set.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub async fn drive_pending_expansions_for_test(&self) -> KataResult<()> {
        self.drive_pending_expansions(&BTreeMap::new()).await
    }

    /// The expansion's durable conclusion as a JSON view for tests — the
    /// accepted `{"expansion": {…}}` record, `{"expansion_failed": reason}` for
    /// a resolution without an acceptance, `None` while live or unclaimed.
    ///
    /// # Errors
    ///
    /// `durable_expansion`'s set, plus a loop index the program does not carry.
    #[doc(hidden)]
    pub fn durable_expansion_record_for_test(
        &self,
        loop_index: usize,
    ) -> KataResult<Option<serde_json::Value>> {
        let expansion =
            lower_review_loop(&self.execution_program, loop_index).map_err(|error| {
                KataError::Validation(format!(
                    "review loop {loop_index} does not lower: {error:?}"
                ))
            })?;
        Ok(match self.durable_expansion(&expansion)? {
            Some(Resolved::Decided(record)) => Some(record.to_output()),
            Some(Resolved::Failed(reason)) => Some(serde_json::json!({"expansion_failed": reason})),
            None => None,
        })
    }
}

fn diverged(path: &OperationPath, detail: &str) -> KataError {
    KataError::Validation(format!(
        "{EXPANSION_DECISION_DIVERGED}: expansion {}: {detail}. The durable decision is \
         authoritative and a recomputed one that disagrees with it is refused, never applied \
         in its place",
        path.program_operation_stage_id()
    ))
}

/// Hold a recomputed decision to the durable one. Agreement returns the
/// DURABLE record — the recorded one is the bound decision.
fn agree(
    path: &OperationPath,
    durable: Resolved,
    recomputed: Result<ExpansionRecord, String>,
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
mod tests {
    use super::*;
    use kata_program::execution_program::expansion::{ExpansionMember, ExpansionResolution};

    fn path() -> OperationPath {
        OperationPath(vec![4])
    }

    fn record(outcome: ExpansionResolution) -> ExpansionRecord {
        ExpansionRecord {
            operation: "ab".repeat(32),
            path: "#op/4".to_owned(),
            stage: "worker".to_owned(),
            resolution: outcome,
            members: vec![ExpansionMember {
                iteration: 0,
                member: 0,
                stage: "worker".to_owned(),
                occurrence: "cd".repeat(32),
            }],
            verdicts: vec![],
            quorum_unmet: None,
        }
    }

    #[test]
    fn an_agreeing_recomputation_returns_the_durable_record() {
        let durable = record(ExpansionResolution::Approved { iteration: 1 });
        let resolved = agree(
            &path(),
            Resolved::Decided(durable.clone()),
            Ok(record(ExpansionResolution::Approved { iteration: 1 })),
        )
        .expect("agreement resolves");
        assert!(matches!(resolved, Resolved::Decided(found) if found == durable));
    }

    #[test]
    fn a_disagreeing_recomputation_is_refused_as_diverged() {
        let error = agree(
            &path(),
            Resolved::Decided(record(ExpansionResolution::Approved { iteration: 1 })),
            Ok(record(ExpansionResolution::Approved { iteration: 2 })),
        )
        .expect_err("a record that disagrees is refused, never preferred");
        assert!(
            error.to_string().contains(EXPANSION_DECISION_DIVERGED),
            "the refusal is named: {error}"
        );
    }

    #[test]
    fn a_recomputation_that_decides_nothing_against_a_decision_diverges() {
        let error = agree(
            &path(),
            Resolved::Decided(record(ExpansionResolution::Approved { iteration: 0 })),
            Err("member 1 never accepted".to_owned()),
        )
        .expect_err("a recomputation that decides nothing diverges from a decided record");
        assert!(error.to_string().contains(EXPANSION_DECISION_DIVERGED));
    }

    #[test]
    fn a_recorded_failure_converges_with_a_recomputed_one() {
        let resolved = agree(
            &path(),
            Resolved::Failed("member 2 failed".to_owned()),
            Err("member 2 failed".to_owned()),
        )
        .expect("a recorded failure and a recomputed failure agree");
        assert!(matches!(resolved, Resolved::Failed(reason) if reason == "member 2 failed"));
    }

    #[test]
    fn a_recorded_failure_against_a_recomputed_decision_diverges() {
        let error = agree(
            &path(),
            Resolved::Failed("member 2 failed".to_owned()),
            Ok(record(ExpansionResolution::Approved { iteration: 0 })),
        )
        .expect_err("a recorded failure and a recomputed decision diverge");
        assert!(error.to_string().contains(EXPANSION_DECISION_DIVERGED));
    }
}
