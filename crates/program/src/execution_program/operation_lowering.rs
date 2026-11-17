//! The lowerer from the checked
//! IR ([`ExecutionProgram`]) to the typed operation contracts in
//! [`kata_types::execution_contract`].
//!
//! # Scope: command, agent, wait, join, typed VCS effect, select, bounded expansion,
//! invoke, input wait, memory snapshot
//!
//! Ten operation shapes are produced. Nothing in THIS module schedules, dispatches,
//! authorizes, or records anything, but its output is not shadow-only: under the
//! `oci` execution profile the runtime ISSUES what it lowers. The submit path's divert
//! (`runner::dispatch::main_resolved`) routes [`lower_stage_operation`]'s answer — an
//! `Execute { executor: Command }` to the capsule path, a `Join`, a `Wait` or an `Invoke`
//! to its main-side arm — the `Select` resolver (`runner::select`) and the input-wait hold
//! (`runner::input_wait`) mint their occurrences at the flat program-operation
//! coordinates ([`operation_path_at`], inverted by [`program_operation_at`]), and
//! [`lower_program_operations`] is the report `kata workflows check --format json` prints.
//! The one construct that reads the lowering to run a stage is the typed
//! `memory_snapshot()`: it is main-resolved (a snapshot run by kata itself needs
//! no capsule), so its operation is issued unconditionally.
//!
//! | authored construct | typed operation |
//! |---|---|
//! | a plain shell command stage | [`RuntimeOperation::Execute`] `{ executor: `[`ActionExecutor::Command`]`, .. }` |
//! | an agent stage, `agent="x"` or `agent=["x","y"]` | [`RuntimeOperation::Execute`] `{ executor: `[`ActionExecutor::Agent`]`{drivers}, .. }` |
//! | `sleep(for_ms=..)` / `sleep(until_ms=..)` | [`RuntimeOperation::Wait`] (`For` / `Until`) |
//! | the synthetic `parallel()` fan-in barrier | [`RuntimeOperation::Join`] over its dependencies' paths |
//! | `workspace_effect(op=..)` | [`RuntimeOperation::Execute`] `{ executor: `[`ActionExecutor::Effect`]`, .. }` |
//! | one `branch(..)` route | [`RuntimeOperation::Select`] (PROGRAM-level, see below) |
//! | one `loop(..)` (`review_loops` entry) | [`RuntimeOperation::ExpandBounded`] (PROGRAM-level, see below) |
//! | `subworkflow(pack=..)` | [`RuntimeOperation::Invoke`] `{ program: `the bound child's hash`, params_hash }` |
//! | one BLOCKING `human_request(stage=..)` | [`RuntimeOperation::Wait`] (`Input`, PROGRAM-level, see below) |
//! | `memory_snapshot(kind=.., status=..)` | [`RuntimeOperation::MemorySnapshot`] `{ query }` (main-resolved on every profile) |
//!
//! Every other authored construct is REFUSED BY NAME through [`LoweringRefusal`].
//! A `subworkflow` stage is not refused: its child program is bound at CHECK
//! ([`SubworkflowSpec::bound`](super::types::SubworkflowSpec::bound)), so its
//! `Invoke` names a frozen program rather than a pack name.
//!
//! **Lowering is not running.** A subworkflow stage LOWERS to an `Invoke`; what RUNS it is
//! the `Invoke` arm (`runner::dispatch::invoke`),
//! which starts the bound child as a separate, linked execution.
//!
//! **A BLOCKING human request is its own operation, not a property of its stage**.
//! Its target stage lowers to whatever it would
//! run anyway; the request lowers to a PROGRAM-level [`WaitOperation::Input`] — an
//! operator's ANSWER is a durable input wait, not a `Wait` over a clock and not a gate on
//! the stage's own action — and the runtime holds the target until that wait is
//! accepted, then renders the target from the ACCEPTED answer, so the answer is in the
//! target's argv and therefore in its capsule's identity.
//!
//! **`approval_required` is NOT refused.** An approval gate is not an operation: it is
//! a gate on the stage's own capsule ATTEMPT, so the stage lowers to
//! the operation it would run anyway, and `authorize_attempt` derives the gate from the
//! checked stage and parks the attempt, bound to its capsule, until an operator
//! decides. The approval policy reaches the capsule's identity through the stage's
//! `contract_hash` (`PreparedAction` → `CapsuleId`).
//!
//! # Which agent runs is an ATTEMPT fact, and never enters a path
//!
//! An agent stage's [`ActionExecutor::Agent`] carries the AUTHORED ordered driver
//! list — `op.agent_panel` verbatim when the author wrote a panel, else the one
//! `op.agent_label`. It does NOT carry which member runs: a panel advances to
//! `panel[min(i, len - 1)]` off the dispatcher's durable failure-retry attempt
//! counter `i`, which is a runtime fact. So the panel is in the operation's
//! IDENTITY (try-A-then-B is not try-B-then-A) while the chosen member is in
//! neither the identity nor the [`OperationPath`] — the same discipline that keeps
//! attempt ordinals out of an [`OccurrenceRef`].
//!
//! # Stage, route, loop and input paths live in ONE flat coordinate space
//!
//! [`OperationPath`] here is a single coordinate over the concatenation
//! `stages ++ branch_routes ++ review_loops ++ blocking_input_requests`: the stage at
//! position `i` of [`ExecutionProgram::stages`] (BTreeMap / stage-id order) gets
//! `[i]`, the route at position `j` of [`ExecutionProgram::branch_routes`]
//! (canonical condition-stage order) gets `[stage_count + j]`, the loop at position
//! `k` of [`ExecutionProgram::review_loops`] (authored order) gets
//! `[stage_count + route_count + k]`, and the blocking request at position `n` of
//! [`blocking_input_requests`] (the human-request queue's order, filtered to
//! `blocking && stage.is_some()`) gets `[stage_count + route_count + loop_count + n]`.
//! That is the smallest rule that keeps the four segments' paths distinct while
//! staying a pure function of the checked program; a second coordinate would have to
//! invent a meaning for the first one. [`program_operation_at`] is its one inverse over
//! the three program-level segments.
//!
//! A deeper coordinate appears in exactly two places. A REVIEW LOOP's iteration:
//! the occurrence of template member `m` in iteration `N` of an expansion at
//! `expand_path` is `expand_path.child(N).child(m)`, for every `N` INCLUDING 0
//! (see [`OperationPath::child`], which states the rule and the aliasing it
//! forbids); this module emits the expansion and the runtime that runs
//! iterations mints their children. A STATIC `topology` stage's member:
//! member `m` of the stage's own `ExpandBounded` at `[i]` sits at
//! `path.child(m)` = `[i, m]` — member 0 the root attempt, members
//! `1..=children.len()` the declared children — and the expansion's template
//! names each member's own coordinate (a loop's names the member STAGE's flat
//! coordinate instead). The child-coordinate rule is the same rule; only the
//! depth differs.
//!
//! A path carries NO attempt ordinal, no retry count, and no worker placement
//! coordinate — those are runtime facts and must never rotate a logical
//! identity. By CONVENTION this module is the only producer of one: nothing in
//! the type prevents another.
//!
//! # The refused set, and the order it is decided in
//!
//! [`stage_refusal_before_operation`] checks the classes that DOMINATE the choice
//! of operation, in exactly the order [`LoweringRefusal`]'s first arms are
//! declared; [`stage_operation`] then picks the operation shape and can refuse
//! only with the arms declared after them. So a stage that belongs to several
//! refused classes always yields one deterministic arm (the first-declared one
//! that applies). The five route/loop/input/program/path-scoped arms
//! ([`LoweringRefusal::SelectConditionUnknown`],
//! [`LoweringRefusal::ExpansionMemberRefused`],
//! [`LoweringRefusal::InputTargetUnknown`],
//! [`LoweringRefusal::PathCoordinateOverflow`],
//! [`LoweringRefusal::SourceHashAbsent`]) are decided last, outside
//! [`stage_operation`], because they are not properties of the stage — the first
//! three can never refuse a stage at all.
//!
//! A STAGE lowers if and only if ALL of the following hold: its panel primary,
//! if it declares a panel, agrees with the routing label the rest of its op
//! carries; AND it is one of
//!
//! * a subworkflow stage (an `Invoke`, decided first among the shapes: such a stage
//!   carries no authored agent);
//! * a `parallel()` barrier every one of whose dependencies itself lowers;
//! * a durable sleep;
//! * a `memory_snapshot()` stage (a `MemorySnapshot` over its authored filter);
//! * a workspace-effect stage carrying its typed op;
//! * a static `topology` stage — an `ExpandBounded` over `1 + children`
//!   members at its own coordinate, every member a capsule-runnable
//!   `Execute { Command | Agent }`;
//! * a `dynamic_fanout` stage — the same `ExpandBounded` shape whose template
//!   holds member 0 only, its request-derived members minted at runtime;
//! * a shell-backed stage whose checked [`Computation`] is
//!   [`Computation::ProcessAction`]; or
//! * an agent stage that names at least one driver (a panel, or a bound
//!   `agent_label`);
//!
//! and its program carries a source hash and a path coordinate that fits `u32`.
//! A ROUTE lowers if and only if its condition stage exists in the program, under
//! the same program-scoped conditions. A REVIEW LOOP lowers if and only if every
//! member of its template — its `effective_body_stages()` in order, then its
//! reviewer gate — both exists in the program and itself lowers. A BLOCKING REQUEST
//! lowers if and only if its target stage exists in the program, under the same
//! program-scoped conditions; whether the TARGET lowers is the target's own verdict,
//! reported in the stage lists, and does not refuse the wait.
//!
//! LOOP MEMBERSHIP IS NOT A REFUSED CLASS: a loop's body stages and its gate
//! ARE its template, so each one lowers as the ordinary operation its own fields
//! name and the expansion references their coordinates.
//!
//! # What this knowingly accepts
//!
//! Nothing. An arm target lowers as an ordinary command, and the
//! [`RuntimeOperation::Select`] per route carries the routing: an arm target's
//! operation identity does not say whether the arm runs, which is a statement the
//! Select answers rather than a gap.
//!
//! What this lowerer does NOT mint, and deliberately: the RUNTIME-DERIVED dispatches
//! a stage can acquire while running — the `<worker>#escalate-gate` the review
//! runner synthesizes when a loop exhausts under `on_max = escalate`, and the
//! `#validate-M` re-dispatches a failed structured-output validation spends. Those
//! are attempts and synthetic ledger rows, not authored constructs, so they have
//! no place in a coordinate space taken over the checked program. Identity already
//! covers the authored fact behind the first: `on_max` is hashed into an
//! expansion's `policy_hash`, so a loop that escalates is a different operation
//! from one that fails, whether or not the escalation ever happens.
//!
//! # Identity discipline
//!
//! `source_hash` is [`ExecutionProgramSource::source_hash`](super::ExecutionProgramSource)
//! and nothing else: substituting `normalized_definition_hash` would make the
//! source map claim provenance over bytes it never saw, so its absence is a
//! refusal instead.

use kata_types::agent::BackendType;
use kata_types::effect::EffectKind;
use kata_types::execution_class::Computation;
use kata_types::execution_contract::{
    ActionExecutor, ExecuteOperation, InputRequestFields, OccurrenceRef, OperationContract,
    OperationPath, OperationSourceMap, RuntimeOperation, WaitOperation, branch_route_selector,
    input_request_selector, loop_policy_selector,
};
use kata_types::primitives::ContentHash;
use kata_types::review_loop::ReviewLoop;
use kata_types::source::SourceSpan;
use kata_types::workflow::{BranchRoute, ExecutionId, StageId, SynthesizedStage};
use serde::Serialize;
use smol_str::SmolStr;

use kata_types::wait::DurableSleep;

use super::types::{
    ExecutionHumanRequest, ExecutionInvocationEnvelope, ExecutionProgram, ExecutionProgramStage,
};

/// Schema version of [`OperationLoweringReport`], the shadow comparison document
/// this module emits. Independent of
/// [`kata_types::execution_contract::EXECUTION_CONTRACT_SCHEMA_VERSION`]: this
/// is the report's shape, not the contract's: the lowered and refused stages
/// (each lowered one with its operation `kind`), and the program-level
/// `selects` / `refused_selects`, `expansions` / `refused_expansions` and
/// `inputs` / `refused_inputs` lists. A subworkflow stage lowers to kind
/// `invoke`, a `memory_snapshot()` stage to kind `memory_snapshot`, and a static
/// `topology` or `dynamic_fanout` stage to `expand_bounded` at its own stage
/// coordinate (a `topology` member of a `loop(..)` template is seated per
/// iteration at the member's coordinate). Any change to that shape bumps this
/// version.
pub const OPERATION_LOWERING_SCHEMA_VERSION: u32 = 9;

/// Why a stage — or a branch route — did not lower. Each arm names one class the
/// lowering refuses.
///
/// The declaration order IS the decision order (see the module docs), so each
/// arm's refused set is "the stages in this class that are in none of the
/// classes above it".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoweringRefusal {
    /// The stage declares an agent fallback panel whose PRIMARY
    /// (`op.agent_panel[0]`) is not the routing label the rest of its op carries
    /// (`op.agent_label`, or `op.agent` when that is absent). The two spellings
    /// then name different preferred drivers and the stage has no honest ordered
    /// driver list, so it refuses rather than picking one of the two.
    ///
    /// NOT frontend-producible: the panel lowering writes the primary into
    /// `op.agent`, `op.agent_label`, and `op.agent_panel[0]` from one value. Its
    /// refused set is therefore exactly the DECODED or HAND-BUILT programs whose
    /// two fields disagree — the same reason [`Self::JoinInputRefused`] budgets a
    /// cycle a checked program cannot have.
    ///
    /// Decided BEFORE the operation shape: a disagreeing op has no executor,
    /// whatever else the stage looks like.
    AgentPanelPrimaryMismatch,
    /// The stage declares an agent fallback panel ANY of whose members is a
    /// DETERMINISTIC executor label (`shell`, `workspace_effect` — the set
    /// [`kata_types::agent::is_deterministic_agent_label`] reserves).
    ///
    /// A panel is AGENT-ONLY. Panel advance re-dispatches a failed attempt to the
    /// next member, and a deterministic label names a command executor, which
    /// lowers to [`ActionExecutor::Command`] / [`ActionExecutor::Effect`] and
    /// carries no driver list to advance through. `agent = ["shell", "codex"]`
    /// would therefore lower to a `Command` naming NOTHING about codex while the
    /// panel's failure-retry advance still re-dispatched to codex on failure — an
    /// identity narrower than the mechanism, which is exactly the defect class this
    /// lowerer exists to make impossible.
    ///
    /// Checked over EVERY member, not just the primary, because the advance
    /// reaches every member. `decode_agent_kwarg` refuses the same thing at the
    /// authoring surface; this arm is what a DECODED or hand-built program hits,
    /// so the guarantee does not depend on having come through the frontend.
    ///
    /// Decided BEFORE the operation shape, beside
    /// [`Self::AgentPanelPrimaryMismatch`]: such a panel has no coherent executor
    /// whatever else the stage looks like.
    PanelOnDeterministicExecutor,
    /// A `parallel()` fan-in barrier the lowering cannot express as a join over
    /// exactly what it waits on. Its refused set is precisely three cases, and no
    /// others: a dependency that NAMES NO STAGE in `program.stages`; a dependency
    /// that is itself REFUSED (by any arm, including this one); and a barrier
    /// CHAIN longer than `program.stages.len()` — reachable only when
    /// `depends_on` has a cycle, which a checked program cannot have but a
    /// hand-built or decoded one can, so the walk spends a budget and refuses
    /// instead of overflowing the stack.
    ///
    /// A [`RuntimeOperation::Join`] is exactly the set of paths it waits on, so a
    /// join over a subset would be a narrower barrier wearing the same identity —
    /// refuse the whole join rather than half-lower it.
    ///
    /// The dependency walk ([`join_inputs`] → [`stage_operation`]) is
    /// UNMEMOIZED: a barrier's dependency is classified afresh each time it is
    /// reached, so a diamond of barriers re-decides shared ancestors once per
    /// path. Deliberate at this size — the whole-program walk is over programs of
    /// tens of stages and the classification is pure — and the budget above
    /// bounds the depth, not the breadth.
    JoinInputRefused,
    /// The stage's resolved executor is the in-process `workspace_effect`
    /// backend, but the checked stage carries no typed
    /// [`WorkspaceEffectOp`](kata_types::workflow::WorkspaceEffectOp) in
    /// [`ExecutionProgramStage::workspace_effect_op`]. FAIL-CLOSED: the only
    /// other place the mutation is written down is the synthesized directive
    /// prompt, and recovering a semantic fact by parsing a prompt string is not a
    /// contract this lowerer will rely on.
    WorkspaceEffectOpAbsent,
    /// The stage is an AGENT stage that names NO driver: it declares no panel and
    /// its `op.agent_label` is `None`, which is the checked IR's spelling of the
    /// `any` selector (`stage(prompt=..)` with no `agent=`).
    ///
    /// Refused rather than lowered with `drivers: []`, and rather than lowered
    /// with whatever `[agents.default]` happens to bind. kata inherits the host's
    /// answer and refuses when there is none: an operator's default is a fact
    /// about a machine's config, not about the authored program, so a checked IR
    /// may not name it — and an empty driver list would be a POSITIVE claim that
    /// the program decided its own executor when it declined to.
    ///
    /// Its refused set is exactly "an agent stage whose `agent_label` is `None`
    /// and whose `agent_panel` is empty". A frontend produces that only for the
    /// `any` selector; a hand-built program that writes `op.agent` alone also
    /// lands here, because `op.agent_label` is the checked IR's routing label and
    /// an unset routing label is unbound however the rest of the op reads.
    AgentSelectorUnbound,
    /// The checked execution class of a stage on the COMMAND path is not
    /// [`Computation::ProcessAction`] — a pure transform or a durable wait,
    /// neither of which spawns a command. A fail-closed guard on the class axis:
    /// no shipped pack reaches it today, and it refuses rather than trusting the
    /// label when that stops being true. It is deliberately NOT asked of the
    /// other shapes: an effect stage is `PureTransform` (admission 1) or
    /// `ProcessAction` (admission 2, forge export) by construction, and asking a
    /// `Wait` for `ProcessAction` would refuse the one class that is correct for
    /// it.
    NotProcessAction,
    /// A branch route's `condition_stage` names no stage in the program, so the
    /// route's [`OperationContract::source_stage`] would claim provenance over a
    /// stage that does not exist. ROUTE-scoped: it can never refuse a stage.
    SelectConditionUnknown,
    /// A review loop has a template member — a body stage or the reviewer gate —
    /// that NAMES NO STAGE in `program.stages`, or that the lowering REFUSES.
    /// LOOP-scoped: it can never refuse a stage or a route.
    ///
    /// ALL-OR-NOTHING, for the reason [`Self::JoinInputRefused`] is: a
    /// [`RuntimeOperation::ExpandBounded`] IS its template, so an expansion over
    /// the members that happen to lower would be a DIFFERENT loop — one that skips
    /// part of its body every iteration — wearing the same identity.
    ExpansionMemberRefused,
    /// A BLOCKING human request's target `stage` names no stage in `program.stages`, so
    /// the input wait would hold — and its [`OperationContract::source_stage`] would claim
    /// provenance over — a stage that does not exist. INPUT-scoped: it can never refuse a
    /// stage, a route or a loop.
    ///
    /// Its refused set is exactly the blocking requests (`blocking && stage.is_some()`)
    /// whose `stage` is absent from `program.stages`; a non-blocking request, or one with
    /// no `stage`, is no input wait at all and appears in neither input list.
    InputTargetUnknown,
    /// The operation's flat coordinate does not fit a `u32`, so no
    /// [`OperationPath`] can be minted for it. Reachable only for a program with
    /// more than `u32::MAX` stages-plus-routes; a refusal rather than a panic
    /// because a lowerer that aborts the process is a worse answer than one that
    /// declines the program.
    PathCoordinateOverflow,
    /// The program carries no source hash, so no honest source map can be built.
    /// Program-scoped, so it refuses every stage AND every route of such a
    /// program. Decided LAST, outside [`stage_operation`], because it is not a
    /// property of either.
    SourceHashAbsent,
}

impl LoweringRefusal {
    /// Stable snake_case name, identical to the serde representation. Tests and
    /// operator surfaces name a refusal through this rather than `Debug`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentPanelPrimaryMismatch => "agent_panel_primary_mismatch",
            Self::PanelOnDeterministicExecutor => "panel_on_deterministic_executor",
            Self::JoinInputRefused => "join_input_refused",
            Self::WorkspaceEffectOpAbsent => "workspace_effect_op_absent",
            Self::AgentSelectorUnbound => "agent_selector_unbound",
            Self::NotProcessAction => "not_process_action",
            Self::SelectConditionUnknown => "select_condition_unknown",
            Self::ExpansionMemberRefused => "expansion_member_refused",
            Self::InputTargetUnknown => "input_target_unknown",
            Self::PathCoordinateOverflow => "path_coordinate_overflow",
            Self::SourceHashAbsent => "source_hash_absent",
        }
    }
}

/// Failure of [`lower_stage_operation`] / [`lower_branch_route`].
///
/// A stage id that names no stage, a route index past the end of
/// `branch_routes`, a loop index past the end of `review_loops`, or an input index
/// past the end of [`blocking_input_requests`], is NOT a refusal: refusals classify authored
/// constructs the lowering declines to lower, and an absent subject is a caller mistake. Keeping
/// the two apart means a caller cannot count a typo as a refused construct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoweringError {
    /// `stage_id` names no stage in `program.stages`.
    UnknownStage(StageId),
    /// `route_index` is past the end of `program.branch_routes`.
    UnknownRoute(usize),
    /// `loop_index` is past the end of `program.review_loops`.
    UnknownLoop(usize),
    /// `input_index` is past the end of [`blocking_input_requests`].
    UnknownInput(usize),
    /// `stage_index` is past the end of `program.stages` — the coordinate an
    /// indexed door (the expansion driver) asks about, where there is no stage
    /// id to name because no stage exists there.
    UnknownStageIndex(usize),
    /// `member` is past the end of an expansion's template — an absent member,
    /// like an absent stage, is a caller mistake rather than a refused
    /// construct.
    UnknownMember(u32),
    /// `expansion`'s contract carries no `ExpandBounded` — a member of a
    /// non-expansion is a caller mistake.
    NotAnExpansion,
    /// `member_coordinate` is not a strict child of the expansion's own path
    /// whose last coordinate is `member` — a member seated at any other
    /// coordinate would alias another occurrence (an expansion's members are
    /// `expand_path.child(N).child(m)`, per [`OperationPath::child`]).
    NotAMemberCoordinate,
    /// The subject exists and the lowering refuses it.
    Refused(LoweringRefusal),
}

/// One lowered stage or route: the typed contract, its authored source map, and
/// its stable path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredOperation {
    pub contract: OperationContract,
    pub source_map: OperationSourceMap,
    pub path: OperationPath,
}

/// Mint the flat [`OperationPath`] for one coordinate in the
/// `stages ++ branch_routes` space (see the module docs). THE one path rule, and
/// public so its refused set is testable without a program of four billion
/// stages.
///
/// # Errors
///
/// [`LoweringRefusal::PathCoordinateOverflow`] when `coordinate` exceeds `u32`.
pub fn operation_path_at(coordinate: usize) -> Result<OperationPath, LoweringRefusal> {
    u32::try_from(coordinate)
        .map(|coordinate| OperationPath(vec![coordinate]))
        .map_err(|_| LoweringRefusal::PathCoordinateOverflow)
}

/// Lower one stage to its typed operation, or say why it refuses.
///
/// # Errors
///
/// [`LoweringError::UnknownStage`] when `stage_id` is absent from the program;
/// [`LoweringError::Refused`] with the first applicable [`LoweringRefusal`]
/// otherwise.
pub fn lower_stage_operation(
    program: &ExecutionProgram,
    stage_id: &StageId,
) -> Result<LoweredOperation, LoweringError> {
    let Some((index, (_, stage))) = program
        .stages
        .iter()
        .enumerate()
        .find(|(_, (candidate, _))| *candidate == stage_id)
    else {
        return Err(LoweringError::UnknownStage(stage_id.clone()));
    };
    lower_stage_at(program, index, stage).map_err(LoweringError::Refused)
}

/// Lower one review loop to its program-level [`RuntimeOperation::ExpandBounded`],
/// or say why it refuses.
///
/// # Errors
///
/// [`LoweringError::UnknownLoop`] when `loop_index` is past the end of
/// `program.review_loops`; [`LoweringError::Refused`] otherwise.
pub fn lower_review_loop(
    program: &ExecutionProgram,
    loop_index: usize,
) -> Result<LoweredOperation, LoweringError> {
    let Some(review_loop) = program.review_loops.get(loop_index) else {
        return Err(LoweringError::UnknownLoop(loop_index));
    };
    lower_loop_at(program, loop_index, review_loop).map_err(LoweringError::Refused)
}

/// The review-loop iteration an occurrence's [`OperationPath`] sits inside —
/// `None` when it belongs to no iteration of any loop the program lowered.
///
/// Iteration `N`'s member `m` of the review loop lowered at `expand_path`
/// lands at `expand_path.child(N).child(m)` — [`OperationPath::child`]'s
/// expansion iteration rule — so a member path has exactly
/// `expand_path.len() + 2` coordinates, `expand_path` as prefix, and `N` at
/// `expand_path.len()`. A topology member (`expand_path.child(m)`, one
/// coordinate) and every stage outside an expansion answer `None`; callers
/// that need a number map `None` to `0`, the same answer the `#iter-N`
/// spelling gave an unadorned name.
///
/// THE one decode of that coordinate — the memory-writeback matcher and the
/// observe projection both read a capsule attempt's loop position through it,
/// so they cannot disagree about which iteration an attempt belonged to.
#[must_use]
pub fn loop_iteration_coordinate(path: &OperationPath, program: &ExecutionProgram) -> Option<u32> {
    for loop_index in 0..program.review_loops.len() {
        if let Ok(lowered) = lower_review_loop(program, loop_index)
            && path.0.len() == lowered.path.0.len() + 2
            && path.0[..lowered.path.0.len()] == lowered.path.0[..]
        {
            return Some(path.0[lowered.path.0.len()]);
        }
    }
    None
}

/// Lower the static-`topology` stage at `stages` index `stage_index` to its
/// `ExpandBounded`, or say why it refuses. The expansion sits at the stage's
/// OWN coordinate `[stage_index]` — a stage that expands over children has no
/// operation beside the expansion itself.
///
/// # Errors
///
/// [`LoweringError::UnknownStage`] when `stage_index` names no stage of the
/// program (indexed — the driver reads coordinates, not ids);
/// [`LoweringError::Refused`] otherwise, including
/// [`LoweringRefusal::ExpansionMemberRefused`] for a stage at that index that
/// plans no static topology.
pub fn lower_topology_expansion(
    program: &ExecutionProgram,
    stage_index: usize,
) -> Result<LoweredOperation, LoweringError> {
    let Some((_, stage)) = program.stages.iter().nth(stage_index) else {
        return Err(LoweringError::UnknownStageIndex(stage_index));
    };
    if !plans_static_topology(stage) {
        return Err(LoweringError::Refused(
            LoweringRefusal::ExpansionMemberRefused,
        ));
    }
    lower_stage_at(program, stage_index, stage).map_err(LoweringError::Refused)
}

/// Lower the `dynamic_fanout` stage at `stages` index `stage_index` to its
/// `ExpandBounded`, or say why it refuses — the indexed twin of
/// [`lower_topology_expansion`] for the expansion whose member list mints at
/// runtime. The expansion sits at the stage's OWN coordinate
/// `[stage_index]`, its checked template holding member 0 (the root) only.
///
/// # Errors
///
/// [`LoweringError::UnknownStage`] when `stage_index` names no stage of the
/// program; [`LoweringError::Refused`] otherwise, including
/// [`LoweringRefusal::ExpansionMemberRefused`] for a stage at that index that
/// plans no dynamic fanout.
pub fn lower_dynamic_fanout_expansion(
    program: &ExecutionProgram,
    stage_index: usize,
) -> Result<LoweredOperation, LoweringError> {
    let Some((_, stage)) = program.stages.iter().nth(stage_index) else {
        return Err(LoweringError::UnknownStageIndex(stage_index));
    };
    if !plans_dynamic_fanout(stage) {
        return Err(LoweringError::Refused(
            LoweringRefusal::ExpansionMemberRefused,
        ));
    }
    lower_stage_at(program, stage_index, stage).map_err(LoweringError::Refused)
}

/// Lower member `member` of `expansion` — the `member`-th entry of its
/// `ExpandBounded` template — as that member's own stage operation, seated at
/// `member_coordinate`.
///
/// The member lowers through the same [`lower_stage_at`] the stage lists use —
/// a member IS an ordinary stage operation — then is re-seated at
/// `member_coordinate`, which must be a strict child of `expansion.path`
/// ending in `member` (`expand_path.child(iteration).child(member)` for a
/// loop): the occurrence at that coordinate cannot alias the member stage's
/// own bare-path occurrence, and the coordinate is the only thing about the
/// lowering that differs.
///
/// # Errors
///
/// [`LoweringError::NotAnExpansion`] when `expansion`'s contract carries no
/// `ExpandBounded`; [`LoweringError::UnknownMember`] when `member` is past the
/// template's end; [`LoweringError::NotAMemberCoordinate`] when
/// `member_coordinate` does not strictly extend `expansion.path` ending in
/// `member`; [`LoweringError::Refused`] when the template entry is not a flat
/// stage coordinate or the member stage does not lower (defensive —
/// [`expansion_template`] admits only members that lower).
pub fn lower_expansion_member(
    program: &ExecutionProgram,
    expansion: &LoweredOperation,
    member_coordinate: OperationPath,
    member: u32,
) -> Result<LoweredOperation, LoweringError> {
    let RuntimeOperation::ExpandBounded { template, .. } = &expansion.contract.operation else {
        return Err(LoweringError::NotAnExpansion);
    };
    let member_usize = usize::try_from(member).map_err(|_| LoweringError::UnknownMember(member))?;
    let Some(flat) = template.get(member_usize) else {
        return Err(LoweringError::UnknownMember(member));
    };
    if !member_coordinate.0.starts_with(expansion.path.0.as_slice())
        || member_coordinate.0.len() <= expansion.path.0.len()
        || member_coordinate.0.last() != Some(&member)
    {
        return Err(LoweringError::NotAMemberCoordinate);
    }
    // A TOPOLOGY expansion's template entry is the member's own coordinate —
    // `expand_path.child(m)` — so the entry and the coordinate it claims to
    // seat must agree; any other spelling of the member is the
    // not-a-member-coordinate mistake the check above just established.
    if flat == &member_coordinate {
        return lower_topology_member(program, expansion, member, member_coordinate);
    }
    let [stage_index] = flat.0.as_slice() else {
        return Err(LoweringError::Refused(
            LoweringRefusal::ExpansionMemberRefused,
        ));
    };
    let stage_index = usize::try_from(*stage_index)
        .map_err(|_| LoweringError::Refused(LoweringRefusal::PathCoordinateOverflow))?;
    let Some((_, stage)) = program.stages.iter().nth(stage_index) else {
        return Err(LoweringError::Refused(
            LoweringRefusal::ExpansionMemberRefused,
        ));
    };
    // A static-topology member of a loop lowers to its own
    // `ExpandBounded` SEATED at the member coordinate: its template is that
    // coordinate's `child(r)`, so every iteration's topology mints distinct
    // member coordinates and a distinct contract.
    if plans_static_topology(stage) {
        return lower_stage_at_path(program, stage, member_coordinate)
            .map_err(LoweringError::Refused);
    }
    let mut lowered =
        lower_stage_at(program, stage_index, stage).map_err(LoweringError::Refused)?;
    lowered.path = member_coordinate;
    Ok(lowered)
}

/// The nested `ExpandBounded` of the static-`topology` stage that is member
/// `member` of `review_loops[loop_index]` at iteration `iteration`,
/// seated at `loop_path.child(iteration).child(member)`.
///
/// # Errors
///
/// [`lower_review_loop`]'s; [`lower_expansion_member`]'s; and
/// [`LoweringRefusal::ExpansionMemberRefused`] when that member's stage plans no
/// static topology.
pub fn lower_loop_member_topology(
    program: &ExecutionProgram,
    loop_index: usize,
    iteration: u32,
    member: u32,
) -> Result<LoweredOperation, LoweringError> {
    let review_loop = lower_review_loop(program, loop_index)?;
    let lowered = lower_expansion_member(
        program,
        &review_loop,
        review_loop.path.child(iteration).child(member),
        member,
    )?;
    if !matches!(
        lowered.contract.operation,
        RuntimeOperation::ExpandBounded { .. }
    ) {
        return Err(LoweringError::Refused(
            LoweringRefusal::ExpansionMemberRefused,
        ));
    }
    Ok(lowered)
}

/// Lower member `member` of a TOPOLOGY expansion — member 0 the root attempt
/// (the parent's own payload, stage-named `source_stage`), member `m` child
/// `m - 1` (stage-named `source_stage#child-<role>`, the same synthetic id a
/// child frame carries).
///
/// The member's contract `source_stage` IS that name: `authorize_attempt`
/// stamps the attempt's `stage_id` off it, so the durable member frame lands
/// on the stage spelling a child assignment uses
/// (`parse_child_invocation_stage_name` decodes it for every fold-time route).
/// `OperationContract::new` hashes `source_stage`, so the name IS the
/// member's contract identity — two children of one parent can never share a
/// contract id.
///
/// # Errors
///
/// [`LoweringError::UnknownMember`] for a `member` past `children.len()`;
/// [`LoweringError::Refused`] with [`LoweringRefusal::ExpansionMemberRefused`]
/// when the parent's stage is absent or the member's executor does not lower
/// to `Execute { Command | Agent }` (the [`topology_expansion_operation`]
/// check is re-run here so a member lowered in isolation refuses identically).
fn lower_topology_member(
    program: &ExecutionProgram,
    expansion: &LoweredOperation,
    member: u32,
    member_coordinate: OperationPath,
) -> Result<LoweredOperation, LoweringError> {
    let parent = &expansion.contract.source_stage;
    let Some(stage) = program.stages.get(parent) else {
        return Err(LoweringError::Refused(
            LoweringRefusal::ExpansionMemberRefused,
        ));
    };
    let member_usize = usize::try_from(member).map_err(|_| LoweringError::UnknownMember(member))?;
    if member_usize > stage.invocation_envelope.children.len() {
        return Err(LoweringError::UnknownMember(member));
    }
    let executor = topology_member_executor(program, stage, member_usize, program.stages.len())
        .map_err(LoweringError::Refused)?;
    let member_stage = if member_usize == 0 {
        parent.clone()
    } else {
        let role = &stage.invocation_envelope.children[member_usize - 1].role;
        StageId(SmolStr::new(
            kata_types::execution_contract::child_invocation_stage_name(&parent.0, role),
        ))
    };
    let contract = OperationContract::new(
        member_stage.clone(),
        RuntimeOperation::Execute(ExecuteOperation {
            executor,
            contract_hash: stage.contract_hash,
        }),
    );
    let source_hash = source_hash(program).map_err(LoweringError::Refused)?;
    Ok(LoweredOperation {
        source_map: OperationSourceMap {
            operation: contract.id(),
            stage: member_stage.clone(),
            source_hash,
            authored_label: member_stage.0.clone(),
            span: stage.authored_span.clone(),
        },
        contract,
        path: member_coordinate,
    })
}

/// Lower one member of a `dynamic_fanout` expansion — the RUNTIME-minted member
/// a checked template cannot name. Member 0 is the ROOT: its contract
/// `source_stage` is the parent stage's own id and `role_agent` is `None`. A
/// member `m >= 1` is request `m - 1` of the accepted array: `member_stage` is
/// the synthetic `<parent>#child-<role>-<label>` id the runtime minted and
/// `role_agent` is the request's declared agent (the verifier requires it).
///
/// `member_coordinate` must be a strict child of `expansion.path` ending in the
/// member index (`expand_path.child(m)`); for member 0 it must equal the
/// template's only entry. The member stage names the contract
/// (`OperationContract::new` hashes `source_stage`), so two dynamic children can
/// never share a contract id.
///
/// # Errors
///
/// [`LoweringError::NotAnExpansion`] when `expansion`'s contract carries no
/// `ExpandBounded`; [`LoweringError::NotAMemberCoordinate`] when
/// `member_coordinate` does not strictly extend `expansion.path`, or member 0
/// is not the template's seat; [`LoweringError::Refused`] with
/// [`LoweringRefusal::ExpansionMemberRefused`] when the parent's stage is
/// absent or the member's executor does not lower to
/// `Execute { Command | Agent }`.
pub fn lower_dynamic_fanout_member(
    program: &ExecutionProgram,
    expansion: &LoweredOperation,
    member_coordinate: OperationPath,
    member_stage: &StageId,
    role_agent: Option<&str>,
) -> Result<LoweredOperation, LoweringError> {
    let RuntimeOperation::ExpandBounded { template, .. } = &expansion.contract.operation else {
        return Err(LoweringError::NotAnExpansion);
    };
    let Some(&member) = member_coordinate.0.last() else {
        return Err(LoweringError::NotAMemberCoordinate);
    };
    if !member_coordinate.0.starts_with(expansion.path.0.as_slice())
        || member_coordinate.0.len() <= expansion.path.0.len()
    {
        return Err(LoweringError::NotAMemberCoordinate);
    }
    if member == 0 && Some(&member_coordinate) != template.first() {
        return Err(LoweringError::NotAMemberCoordinate);
    }
    let parent = &expansion.contract.source_stage;
    let Some(stage) = program.stages.get(parent) else {
        return Err(LoweringError::Refused(
            LoweringRefusal::ExpansionMemberRefused,
        ));
    };
    let executor = dynamic_member_executor(program, stage, role_agent, program.stages.len())
        .map_err(LoweringError::Refused)?;
    let contract = OperationContract::new(
        member_stage.clone(),
        RuntimeOperation::Execute(ExecuteOperation {
            executor,
            contract_hash: stage.contract_hash,
        }),
    );
    let source_hash = source_hash(program).map_err(LoweringError::Refused)?;
    Ok(LoweredOperation {
        source_map: OperationSourceMap {
            operation: contract.id(),
            stage: member_stage.clone(),
            source_hash,
            authored_label: member_stage.0.clone(),
            span: stage.authored_span.clone(),
        },
        contract,
        path: member_coordinate,
    })
}

/// Whether one lowered operation can be a `loop(..)` BODY member under the
/// `oci` capsule profile — the single predicate the CHECK door
/// (`compile::refuse_program_under_capsule_profile`) and the member dispatch
/// (`runner::expansion::dispatch_expansion_member`) share, so a member the
/// door admits is exactly a member the member dispatch serves.
///
/// Admitted: an `Execute { Command | Agent }` — the operation a shell or agent
/// capsule runs — and an `ExpandBounded`, the static `topology` member whose
/// own nested expansion drives its children. Admitted too are
/// the two MAIN-RESOLVED member classes: a `MemorySnapshot`, resolved
/// inside its claim-and-resolve transaction at the member seat, and an
/// `Execute { Effect }` (a `workspace_effect` member), which the drive
/// dispatches main-side at the member seat AFTER every earlier member's
/// pending `/work` apply has landed. Refused: every other shape — a `Wait`
/// (a `durable_sleep` member), an `Invoke` (a `subworkflow` member), or a
/// `Join` — has no dispatch answer inside an iteration, so admitting it at
/// CHECK defers the refusal to a mid-run `KataError::Validation` the member
/// dispatch would have to raise.
#[must_use]
pub fn member_operation_is_oci_runnable(operation: &RuntimeOperation) -> bool {
    matches!(
        operation,
        RuntimeOperation::ExpandBounded { .. }
            | RuntimeOperation::MemorySnapshot { .. }
            | RuntimeOperation::Execute(ExecuteOperation {
                executor: ActionExecutor::Command
                    | ActionExecutor::Agent { .. }
                    | ActionExecutor::Effect { .. },
                ..
            })
    )
}

/// Whether one lowered operation can be a `loop(..)` GATE member under `oci`
/// — [`member_operation_is_oci_runnable`]'s admitted set minus the two
/// main-resolved classes: a gate is a verdict capsule (or a static topology
/// gate), never a workspace mutation or a memory read. The gate's refusal
/// names the same `loop_member_not_a_capsule_under_oci` token.
#[must_use]
pub fn gate_operation_is_oci_runnable(operation: &RuntimeOperation) -> bool {
    matches!(
        operation,
        RuntimeOperation::ExpandBounded { .. }
            | RuntimeOperation::Execute(ExecuteOperation {
                executor: ActionExecutor::Command | ActionExecutor::Agent { .. },
                ..
            })
    )
}

/// Lower one branch route to its program-level [`RuntimeOperation::Select`], or
/// say why it refuses.
///
/// # Errors
///
/// [`LoweringError::UnknownRoute`] when `route_index` is past the end of
/// `program.branch_routes`; [`LoweringError::Refused`] otherwise.
pub fn lower_branch_route(
    program: &ExecutionProgram,
    route_index: usize,
) -> Result<LoweredOperation, LoweringError> {
    let Some(route) = program.branch_routes.get(route_index) else {
        return Err(LoweringError::UnknownRoute(route_index));
    };
    lower_route_at(program, route_index, route).map_err(LoweringError::Refused)
}

/// The BLOCKING human requests, each a program-level input wait: the human-request
/// queue's requests with `blocking && stage.is_some()`, in queue order. Position `n` in
/// this sequence is the input's segment index — the fourth segment of the flat
/// coordinate space (see the module docs). THE one filter: the lowering, the runtime's
/// hold and the answer door all enumerate through it, so none can count a request the
/// others do not.
pub fn blocking_input_requests(
    program: &ExecutionProgram,
) -> impl Iterator<Item = &ExecutionHumanRequest> {
    program
        .human_request_queue
        .requests
        .iter()
        .filter(|request| request.blocking && request.stage.is_some())
}

/// Lower the `input_index`-th blocking human request ([`blocking_input_requests`]) to its
/// program-level [`RuntimeOperation::Wait`] (`Input`), or say why it refuses.
///
/// # Errors
///
/// [`LoweringError::UnknownInput`] when `input_index` is past the end of
/// [`blocking_input_requests`]; [`LoweringError::Refused`] otherwise.
pub fn lower_blocking_request(
    program: &ExecutionProgram,
    input_index: usize,
) -> Result<LoweredOperation, LoweringError> {
    let Some(request) = blocking_input_requests(program).nth(input_index) else {
        return Err(LoweringError::UnknownInput(input_index));
    };
    lower_input_at(program, input_index, request).map_err(LoweringError::Refused)
}

/// Which PROGRAM-LEVEL operation a flat path names — the one inverse of the three
/// program-level segments `branch_routes ++ review_loops ++ blocking_input_requests` (see the
/// module docs), PLUS the one stage-segment expansion: a static `topology` stage's own
/// coordinate `[i]` names its `ExpandBounded`, because a stage that expands over children
/// has no operation beside the expansion itself. `None` for any other stage coordinate, a
/// coordinate past the last segment, and a path that is not one coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramOperationAt {
    /// The `Select` of `branch_routes[j]`.
    Select(usize),
    /// An `ExpandBounded` — which kind the coordinate names.
    Expansion(ExpansionKind),
    /// The input wait of the `n`-th [`blocking_input_requests`].
    Input(usize),
}

/// Which `ExpandBounded` a flat path names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpansionKind {
    /// The `ExpandBounded` of `review_loops[k]` — at the program-level segment's
    /// `stages + routes + k` coordinate; its members run iterations under
    /// `path.child(N).child(m)`.
    ReviewLoop(usize),
    /// The `ExpandBounded` of the static-`topology` stage at `stages` index `i` —
    /// at the stage's OWN coordinate `[i]`; its members are `path.child(m)`
    /// (member 0 the root attempt, members `1..=children.len()` the declared
    /// children).
    Topology(usize),
    /// The `ExpandBounded` of a static-`topology` stage that is member
    /// `member` of `review_loops[loop_index]`, at iteration `iteration`. It sits
    /// at the loop member's own coordinate
    /// `loop_path.child(iteration).child(member)`; its members are that
    /// coordinate's `child(r)` exactly as a stage-seated topology's are.
    LoopMemberTopology {
        /// The enclosing loop's `review_loops` index.
        loop_index: usize,
        /// The loop iteration the topology runs in.
        iteration: u32,
        /// The loop template member the topology stage is.
        member: u32,
    },
    /// The `ExpandBounded` of the `dynamic_fanout` stage at `stages` index `i` —
    /// at the stage's OWN coordinate `[i]`; member 0 is the root attempt and
    /// members `1..=requests.len()` mint at runtime off the accepted request
    /// array.
    DynamicFanout(usize),
}

/// [`ProgramOperationAt`] for `path` in `program`.
#[must_use]
pub fn program_operation_at(
    program: &ExecutionProgram,
    path: &OperationPath,
) -> Option<ProgramOperationAt> {
    // A loop member's own coordinate `[loop, iteration, member]` names an
    // operation exactly when that member's stage plans a static topology:
    // the member IS the nested topology's `ExpandBounded`.
    if let [loop_coordinate, iteration, member] = path.0.as_slice() {
        let Some(ProgramOperationAt::Expansion(ExpansionKind::ReviewLoop(loop_index))) =
            program_operation_at(program, &OperationPath(vec![*loop_coordinate]))
        else {
            return None;
        };
        let stage = loop_member_stage(program, loop_index, *member)?;
        return plans_static_topology(stage).then_some(ProgramOperationAt::Expansion(
            ExpansionKind::LoopMemberTopology {
                loop_index,
                iteration: *iteration,
                member: *member,
            },
        ));
    }
    let [coordinate] = path.0.as_slice() else {
        return None;
    };
    let coordinate = usize::try_from(*coordinate).ok()?;
    if let Some((_, stage)) = program.stages.iter().nth(coordinate) {
        // A stage coordinate names a program-level operation only when the
        // stage's operation IS one: a `topology` or `dynamic_fanout` stage
        // lowers to `ExpandBounded` at its own coordinate. Any other stage's
        // `[i]` is a stage coordinate, not a program operation — `None`.
        if plans_dynamic_fanout(stage) {
            return Some(ProgramOperationAt::Expansion(ExpansionKind::DynamicFanout(
                coordinate,
            )));
        }
        return plans_static_topology(stage).then_some(ProgramOperationAt::Expansion(
            ExpansionKind::Topology(coordinate),
        ));
    }
    let mut rest = coordinate.checked_sub(program.stages.len())?;
    if rest < program.branch_routes.len() {
        return Some(ProgramOperationAt::Select(rest));
    }
    rest -= program.branch_routes.len();
    if rest < program.review_loops.len() {
        return Some(ProgramOperationAt::Expansion(ExpansionKind::ReviewLoop(
            rest,
        )));
    }
    rest -= program.review_loops.len();
    (rest < blocking_input_requests(program).count()).then_some(ProgramOperationAt::Input(rest))
}

/// The fields [`input_request_selector`] hashes, read off one checked request.
#[must_use]
fn input_request_fields(request: &ExecutionHumanRequest) -> InputRequestFields<'_> {
    InputRequestFields {
        id: request.id.as_str(),
        stage: request.stage.as_ref().map(|stage| stage.0.as_str()),
        question: request.question.as_str(),
        default_assumption: request.default_assumption.as_str(),
        timeout_ms: request.timeout_ms,
        priority: request.priority.as_str(),
        context: request.context.as_deref(),
    }
}

/// The one stage-lowering body. Both doors reach the typed operation through
/// here, so the whole-program walk does not re-scan `stages` for an index it
/// already has, and neither door can drift from the other's refused set.
///
/// `index` is the stage's position in `program.stages` (BTreeMap order) and
/// becomes its flat path coordinate.
fn lower_stage_at(
    program: &ExecutionProgram,
    index: usize,
    stage: &ExecutionProgramStage,
) -> Result<LoweredOperation, LoweringRefusal> {
    lower_stage_at_path(program, stage, operation_path_at(index)?)
}

/// [`lower_stage_at`] seated at an explicit `path` — the stage's own `[i]`, or
/// (for a static topology that is a loop member) the member's
/// coordinate, which the topology's template is built under.
fn lower_stage_at_path(
    program: &ExecutionProgram,
    stage: &ExecutionProgramStage,
    path: OperationPath,
) -> Result<LoweredOperation, LoweringRefusal> {
    let operation = stage_operation(program, stage, &path, program.stages.len())?;
    let source_hash = source_hash(program)?;
    let contract = OperationContract::new(stage.stage_id.clone(), operation);
    Ok(LoweredOperation {
        source_map: OperationSourceMap {
            operation: contract.id(),
            stage: stage.stage_id.clone(),
            source_hash,
            authored_label: SmolStr::new(stage.stage_id.0.as_str()),
            span: stage.authored_span.clone(),
        },
        contract,
        path,
    })
}

/// The one route-lowering body. The Select's `source_stage` is the route's
/// CONDITION stage — the authored construct the route hangs off — and its
/// `authored_label` is that stage's id, which is the only authored name a
/// `branch(..)` declaration has.
fn lower_route_at(
    program: &ExecutionProgram,
    route_index: usize,
    route: &BranchRoute,
) -> Result<LoweredOperation, LoweringRefusal> {
    if !program.stages.contains_key(&route.condition_stage) {
        return Err(LoweringRefusal::SelectConditionUnknown);
    }
    let path = operation_path_at(program.stages.len() + route_index)?;
    let source_hash = source_hash(program)?;
    let contract = OperationContract::new(
        route.condition_stage.clone(),
        RuntimeOperation::Select {
            selector: branch_route_selector(route),
        },
    );
    Ok(LoweredOperation {
        source_map: OperationSourceMap {
            operation: contract.id(),
            stage: route.condition_stage.clone(),
            source_hash,
            authored_label: SmolStr::new(route.condition_stage.0.as_str()),
            // The CONDITION stage's span — the same stage this map already names,
            // so the provenance and the coordinate cannot disagree. `lower_route_at`
            // has already refused an absent condition stage, so the lookup is
            // total; it is written as one anyway rather than as an `expect`,
            // because a source map is provenance and a missing span is `None`,
            // never a panic.
            span: stage_span(program, &route.condition_stage),
        },
        contract,
        path,
    })
}

/// The one loop-lowering body. The expansion's `source_stage` and
/// `authored_label` are the loop's WORKER stage — the only authored name a
/// `loop()` declaration has, and the stage a reader looks for when asking which
/// loop this is.
fn lower_loop_at(
    program: &ExecutionProgram,
    loop_index: usize,
    review_loop: &ReviewLoop,
) -> Result<LoweredOperation, LoweringRefusal> {
    let template = expansion_template(program, review_loop)?;
    let path = operation_path_at(program.stages.len() + program.branch_routes.len() + loop_index)?;
    let source_hash = source_hash(program)?;
    let worker = StageId(review_loop.worker_stage.clone());
    let contract = OperationContract::new(
        worker.clone(),
        RuntimeOperation::ExpandBounded {
            template,
            maximum: review_loop.max_iterations,
            policy_hash: loop_policy_selector(review_loop),
        },
    );
    Ok(LoweredOperation {
        source_map: OperationSourceMap {
            operation: contract.id(),
            stage: worker.clone(),
            source_hash,
            authored_label: SmolStr::new(worker.0.as_str()),
            // The WORKER stage's span: the authored `loop()` hangs off it, and
            // `expansion_template` has already established that every template
            // member — the worker among them — is a stage of this program.
            span: stage_span(program, &worker),
        },
        contract,
        path,
    })
}

/// The one input-lowering body. The wait's `source_stage` is its TARGET stage — the
/// stage it holds, and the one authored stage a `human_request(stage=..)` names — and its
/// `authored_label` is the request id, the name an operator answers it by.
fn lower_input_at(
    program: &ExecutionProgram,
    input_index: usize,
    request: &ExecutionHumanRequest,
) -> Result<LoweredOperation, LoweringRefusal> {
    let target = request
        .stage
        .as_ref()
        .filter(|target| program.stages.contains_key(*target))
        .ok_or(LoweringRefusal::InputTargetUnknown)?;
    let path = operation_path_at(
        program.stages.len()
            + program.branch_routes.len()
            + program.review_loops.len()
            + input_index,
    )?;
    let source_hash = source_hash(program)?;
    let contract = OperationContract::new(
        target.clone(),
        RuntimeOperation::Wait(WaitOperation::Input {
            request: input_request_selector(input_request_fields(request)),
        }),
    );
    Ok(LoweredOperation {
        source_map: OperationSourceMap {
            operation: contract.id(),
            stage: target.clone(),
            source_hash,
            authored_label: request.id.clone(),
            // The TARGET stage's span: a request carries none of its own, and the
            // target is the stage this map already names.
            span: stage_span(program, target),
        },
        contract,
        path,
    })
}

/// The ORDERED template a bounded expansion repeats: the loop's
/// [`ReviewLoop::effective_body_stages`] in order, then its reviewer gate.
///
/// ALL-OR-NOTHING ([`LoweringRefusal::ExpansionMemberRefused`]): a member that
/// names no stage, or that the lowering refuses, refuses the whole expansion,
/// because an expansion over a subset of the body is a different loop wearing the
/// same identity.
///
/// The gate is LAST and the body is in `effective_body_stages()` order because
/// that is the order the loop runner dispatches one iteration in — the body
/// sub-DAG in dependency order, then the gate once its exit stage completes. The
/// template hashes in order, so a reordered body rotates the expansion identity.
fn expansion_template(
    program: &ExecutionProgram,
    review_loop: &ReviewLoop,
) -> Result<Vec<OperationPath>, LoweringRefusal> {
    let mut members = review_loop.effective_body_stages();
    members.push(StageId(review_loop.reviewer_stage.clone()));
    let mut template = Vec::with_capacity(members.len());
    for member in &members {
        let Some((index, (_, stage))) = program
            .stages
            .iter()
            .enumerate()
            .find(|(_, (candidate, _))| *candidate == member)
        else {
            return Err(LoweringRefusal::ExpansionMemberRefused);
        };
        let member_path = operation_path_at(index)?;
        // A member that does not lower refuses the whole loop (all-or-nothing).
        // A static `topology(..)` member lowers to its OWN `ExpandBounded` and
        // is admitted: each iteration seats it at the member's
        // coordinate `loop_path.child(N).child(m)`, its members one level
        // below (`lower_expansion_member`, `ExpansionKind::LoopMemberTopology`).
        stage_operation(program, stage, &member_path, program.stages.len())
            .map_err(|_| LoweringRefusal::ExpansionMemberRefused)?;
        template.push(member_path);
    }
    Ok(template)
}

/// The checked stage that is template member `member` of `review_loops[loop_index]`
/// — the body stages in order, then the gate (`expansion_template`'s order) —
/// or `None` past the template's end.
pub(crate) fn loop_member_stage(
    program: &ExecutionProgram,
    loop_index: usize,
    member: u32,
) -> Option<&ExecutionProgramStage> {
    let review_loop = program.review_loops.get(loop_index)?;
    let mut members = review_loop.effective_body_stages();
    members.push(StageId(review_loop.reviewer_stage.clone()));
    let stage = members.get(usize::try_from(member).ok()?)?;
    program.stages.get(stage)
}

/// One stage's authoring span, or `None` when the stage carries none — or names
/// no stage at all. TOTAL by construction: a source map is PROVENANCE, so an
/// unknown origin is an absent span and never a refusal or a panic.
fn stage_span(program: &ExecutionProgram, stage_id: &StageId) -> Option<SourceSpan> {
    program
        .stages
        .get(stage_id)
        .and_then(|stage| stage.authored_span.clone())
}

/// The program's authored source hash, or the program-scoped refusal.
fn source_hash(program: &ExecutionProgram) -> Result<ContentHash, LoweringRefusal> {
    program
        .source
        .source_hash
        .ok_or(LoweringRefusal::SourceHashAbsent)
}

/// The logical occurrence of a lowered operation within one execution. Nothing
/// about the attempt, lease, or worker enters it — see
/// [`OccurrenceRef`]'s own contract.
#[must_use]
pub fn occurrence_for(
    program: &ExecutionProgram,
    execution: ExecutionId,
    lowered: &LoweredOperation,
) -> OccurrenceRef {
    OccurrenceRef::new(
        execution,
        program.program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    )
}

/// One lowered stage as the shadow comparison document reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoweredStageReport {
    pub stage: StageId,
    /// [`RuntimeOperation::as_tag`] — which typed shape the stage lowered to, so
    /// the comparison document says WHAT it became and not only that it became
    /// something.
    pub kind: &'static str,
    /// Hex [`OperationContractId`](kata_types::execution_contract::OperationContractId).
    pub operation: String,
    pub path: OperationPath,
}

/// One refused stage and the single class it was refused under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusedStageReport {
    pub stage: StageId,
    pub refusal: LoweringRefusal,
}

/// One lowered branch route, keyed by the condition stage it hangs off. The
/// selector is reported so a re-targeted arm is a visible diff in the comparison
/// document rather than only a rotated operation id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoweredSelectReport {
    pub condition_stage: StageId,
    pub selector: String,
    pub operation: String,
    pub path: OperationPath,
}

/// One refused branch route and the class it was refused under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusedSelectReport {
    pub condition_stage: StageId,
    pub refusal: LoweringRefusal,
}

/// One lowered review loop, keyed by the worker stage its expansion hangs off. The
/// template, the ceiling, and the policy hash are reported so a retuned loop is a
/// visible diff in the comparison document rather than only a rotated operation id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoweredExpansionReport {
    pub worker_stage: StageId,
    pub template: Vec<OperationPath>,
    pub maximum: u32,
    pub policy: String,
    pub operation: String,
    pub path: OperationPath,
}

/// One refused review loop and the class it was refused under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusedExpansionReport {
    pub worker_stage: StageId,
    pub refusal: LoweringRefusal,
}

/// One lowered blocking human request, keyed by its request id. The `request` selector
/// is reported so a reworded question or a changed default is a visible diff in the
/// comparison document rather than only a rotated operation id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoweredInputReport {
    pub request: SmolStr,
    pub target_stage: StageId,
    pub selector: String,
    pub operation: String,
    pub path: OperationPath,
}

/// One refused blocking human request and the class it was refused under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusedInputReport {
    pub request: SmolStr,
    pub target_stage: StageId,
    pub refusal: LoweringRefusal,
}

/// Whole-program lowering verdicts, in `ExecutionProgram::stages` (stage-id)
/// order within each stage list and `branch_routes` (canonical) order within each
/// route list, so the document is a byte-stable comparison artifact.
///
/// Four independent totality invariants, and no fifth:
///
/// * `lowered.len() + refused.len() == stages.len()` — every stage appears in
///   exactly one of the two stage lists;
/// * `selects.len() + refused_selects.len() == branch_routes.len()` — every route
///   appears in exactly one of the two route lists;
/// * `expansions.len() + refused_expansions.len() == review_loops.len()` — every
///   review loop appears in exactly one of the two expansion lists;
/// * `inputs.len() + refused_inputs.len() == blocking_input_requests().count()` — every
///   blocking human request appears in exactly one of the two input lists.
///
/// A Select, an ExpandBounded and an input wait are PROGRAM-level operations, so none
/// is counted against the stage total: `lowered + refused == stage_count` still holds,
/// and only because the routes, the loops and the inputs are counted separately. An
/// input's TARGET is an ordinary stage and appears in the stage lists under its own
/// verdict. A loop's
/// MEMBERS are ordinary stages and DO appear in the stage lists — they are the
/// expansion's template, which references their coordinates rather than consuming
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationLoweringReport {
    pub schema_version: u32,
    pub lowered: Vec<LoweredStageReport>,
    pub refused: Vec<RefusedStageReport>,
    pub selects: Vec<LoweredSelectReport>,
    pub refused_selects: Vec<RefusedSelectReport>,
    pub expansions: Vec<LoweredExpansionReport>,
    pub refused_expansions: Vec<RefusedExpansionReport>,
    pub inputs: Vec<LoweredInputReport>,
    pub refused_inputs: Vec<RefusedInputReport>,
}

/// Lower every stage, branch route, review loop and blocking human request of a
/// program, partitioning each into lowered operations and named refusals.
#[must_use]
pub fn lower_program_operations(program: &ExecutionProgram) -> OperationLoweringReport {
    let mut lowered = Vec::new();
    let mut refused = Vec::new();
    for (index, (stage_id, stage)) in program.stages.iter().enumerate() {
        match lower_stage_at(program, index, stage) {
            Ok(operation) => lowered.push(LoweredStageReport {
                stage: stage_id.clone(),
                kind: operation.contract.operation.as_tag(),
                operation: operation.contract.id().0.to_string(),
                path: operation.path,
            }),
            Err(refusal) => refused.push(RefusedStageReport {
                stage: stage_id.clone(),
                refusal,
            }),
        }
    }
    let mut selects = Vec::new();
    let mut refused_selects = Vec::new();
    for (route_index, route) in program.branch_routes.iter().enumerate() {
        match lower_route_at(program, route_index, route) {
            Ok(operation) => selects.push(LoweredSelectReport {
                // READ OFF THE CONTRACT, never recomputed from the route: the
                // reported selector and the reported operation id must be the
                // same statement about the same route, and a second call to
                // `branch_route_selector` here would be a second statement that
                // could drift from the one the id was taken over.
                selector: match &operation.contract.operation {
                    RuntimeOperation::Select { selector } => selector.to_string(),
                    other => unreachable!("a lowered route is a Select, got {other:?}"),
                },
                condition_stage: route.condition_stage.clone(),
                operation: operation.contract.id().0.to_string(),
                path: operation.path,
            }),
            Err(refusal) => refused_selects.push(RefusedSelectReport {
                condition_stage: route.condition_stage.clone(),
                refusal,
            }),
        }
    }
    let mut expansions = Vec::new();
    let mut refused_expansions = Vec::new();
    for (loop_index, review_loop) in program.review_loops.iter().enumerate() {
        let worker_stage = StageId(review_loop.worker_stage.clone());
        match lower_loop_at(program, loop_index, review_loop) {
            // READ OFF THE CONTRACT, never recomputed from the loop, for the
            // reason the Select's selector is: the reported template, ceiling and
            // policy and the reported operation id must be one statement about one
            // loop.
            Ok(operation) => {
                let RuntimeOperation::ExpandBounded {
                    template,
                    maximum,
                    policy_hash,
                } = &operation.contract.operation
                else {
                    unreachable!(
                        "a lowered loop is an ExpandBounded, got {:?}",
                        operation.contract.operation
                    )
                };
                expansions.push(LoweredExpansionReport {
                    worker_stage,
                    template: template.clone(),
                    maximum: *maximum,
                    policy: policy_hash.to_string(),
                    operation: operation.contract.id().0.to_string(),
                    path: operation.path.clone(),
                });
            }
            Err(refusal) => refused_expansions.push(RefusedExpansionReport {
                worker_stage,
                refusal,
            }),
        }
    }
    let mut inputs = Vec::new();
    let mut refused_inputs = Vec::new();
    for (input_index, request) in blocking_input_requests(program).enumerate() {
        let target_stage = request
            .stage
            .clone()
            .expect("blocking_input_requests yields only stage-scoped requests");
        match lower_input_at(program, input_index, request) {
            // READ OFF THE CONTRACT, never recomputed from the request, for the reason
            // the Select's selector is.
            Ok(operation) => {
                let RuntimeOperation::Wait(WaitOperation::Input { request: selector }) =
                    &operation.contract.operation
                else {
                    unreachable!(
                        "a lowered blocking request is an input Wait, got {:?}",
                        operation.contract.operation
                    )
                };
                inputs.push(LoweredInputReport {
                    request: request.id.clone(),
                    target_stage,
                    selector: selector.to_string(),
                    operation: operation.contract.id().0.to_string(),
                    path: operation.path.clone(),
                });
            }
            Err(refusal) => refused_inputs.push(RefusedInputReport {
                request: request.id.clone(),
                target_stage,
                refusal,
            }),
        }
    }
    OperationLoweringReport {
        schema_version: OPERATION_LOWERING_SCHEMA_VERSION,
        lowered,
        refused,
        selects,
        refused_selects,
        expansions,
        refused_expansions,
        inputs,
        refused_inputs,
    }
}

/// The typed operation one stage lowers to, or the first applicable
/// [`LoweringRefusal`]. Checked in [`LoweringRefusal`] declaration order: the
/// dominating classes first ([`stage_refusal_before_operation`]), then the
/// operation shape.
///
/// `join_budget` bounds the dependency recursion a `parallel()` barrier walks
/// (a barrier may fan in another barrier). A checked program's `depends_on`
/// relation is acyclic, so `stages.len()` is a strict bound on the longest chain;
/// spending it makes a CYCLIC program — which only a hand-built or decoded
/// program can be — refuse instead of overflowing the stack.
fn stage_operation(
    program: &ExecutionProgram,
    stage: &ExecutionProgramStage,
    path: &OperationPath,
    join_budget: usize,
) -> Result<RuntimeOperation, LoweringRefusal> {
    if let Some(refusal) = stage_refusal_before_operation(stage) {
        return Err(refusal);
    }
    // A static `topology(..)` stage does not lower to ONE operation: it expands
    // over its declared child roles. Its own stage coordinate is the
    // expansion's (`[i]`), and its members — the root attempt (member 0) and
    // each child (members `1..=children.len()`) — are the child occurrences
    // `path.child(m)` the template names, in dispatch order. ALL-OR-NOTHING
    // for the same reason [`expansion_template`] is: an expansion over a
    // subset of the roles is a different topology wearing the same identity,
    // so a member that cannot lower to `Execute { Command | Agent }` refuses
    // the whole stage's expansion ([`LoweringRefusal::ExpansionMemberRefused`]).
    if plans_static_topology(stage) {
        return topology_expansion_operation(program, stage, path, join_budget);
    }
    // A `dynamic_fanout` stage is the same shape with its member list deferred:
    // the checked template holds member 0 — the ROOT, the stage's own payload —
    // and every request the runtime verifier accepts mints `path.child(n)`
    // (`lower_dynamic_fanout_member`). ALL-OR-NOTHING still holds on what the
    // check CAN fix: the root executor must be capsule-runnable and every
    // declared role's agent must map to `Command` or `Agent`, so a role whose
    // agent resolves to a `workspace_effect` refuses the whole stage before the
    // expansion mints — a request for that role can never mint a member that
    // lowers.
    if plans_dynamic_fanout(stage) {
        return dynamic_fanout_expansion_operation(program, stage, path, join_budget);
    }
    stage_payload_operation(program, stage, join_budget)
}

/// The typed operation a stage's own PAYLOAD lowers to — every shape that is
/// one operation rather than an expansion over children. `stage_operation`
/// routes here once the refused set and the static-topology arm are decided;
/// a topology member's own executor resolves through it too (member 0 IS the
/// stage's payload).
fn stage_payload_operation(
    program: &ExecutionProgram,
    stage: &ExecutionProgramStage,
    join_budget: usize,
) -> Result<RuntimeOperation, LoweringRefusal> {
    // FIRST among the shapes: a subworkflow stage carries no authored agent, so an
    // executor-first order would refuse it `AgentSelectorUnbound`.
    if let Some(subworkflow) = stage.subworkflow.as_ref() {
        return Ok(RuntimeOperation::Invoke {
            program: subworkflow.bound.program_hash(),
            params_hash: invoke_params_hash(&subworkflow.params),
        });
    }
    if stage.synthesized == Some(SynthesizedStage::ParallelJoin) {
        return Ok(RuntimeOperation::Join {
            inputs: join_inputs(program, stage, join_budget)?,
        });
    }
    if let Some(sleep) = stage.durable_sleep {
        return Ok(RuntimeOperation::Wait(match sleep {
            DurableSleep::For { ms } => WaitOperation::For { delay_ms: ms },
            DurableSleep::Until { epoch_ms } => WaitOperation::Until { epoch_ms },
        }));
    }
    // With the OTHER markers, BEFORE the executor shape: a `memory_snapshot()`
    // stage names no executor — its `query` IS the operation — so the same
    // authored `agent`/`run` defaults that stand under a sleep would lower it
    // to a `Command` that runs nothing.
    if let Some(query) = stage.memory_snapshot {
        return Ok(RuntimeOperation::MemorySnapshot { query });
    }
    let executor = match resolved_backend(stage) {
        Some(BackendType::Shell) => {
            if stage.execution_class.computation != Computation::ProcessAction {
                return Err(LoweringRefusal::NotProcessAction);
            }
            ActionExecutor::Command
        }
        Some(BackendType::WorkspaceEffect) => ActionExecutor::Effect {
            effect_kind: EffectKind::WorkspaceEffect,
            op: stage
                .workspace_effect_op
                .ok_or(LoweringRefusal::WorkspaceEffectOpAbsent)?,
        },
        // Every other resolution is an AGENT: a model/agent CLI backend, or a
        // label that resolves to no [`BackendType`] at all (a config-defined
        // alias, or the `any` sentinel). An alias can never name a command
        // executor — `KataConfig::validate` reserves the deterministic labels —
        // so the only question left is which drivers the author named.
        _ => ActionExecutor::Agent {
            drivers: agent_drivers(stage)?,
        },
    };
    Ok(RuntimeOperation::Execute(ExecuteOperation {
        executor,
        contract_hash: stage.contract_hash,
    }))
}

/// The `ExpandBounded` a static `topology(..)` stage lowers to at its OWN stage
/// coordinate `path`. The template is `path.child(m)` for every member —
/// member 0 is the ROOT (the parent's own attempt, executed on the stage's
/// payload) and members `1..=children.len()` are the declared children, in the
/// envelope's order (`workers` then `reviewers`, as the plan preview writes
/// them). `maximum` is 1: a static topology runs its member set once.
///
/// The member executor of member `m` is fixed HERE, at lowering, so a member
/// that cannot lower to a capsule-runnable `Execute` refuses the whole stage's
/// expansion before anything mints the template
/// ([`LoweringRefusal::ExpansionMemberRefused`]) — a topology stage whose
/// payload is a `Join`, an `Invoke`, a `Wait` or an `Effect` has no
/// capsule-runnable root, exactly as a child role naming a `workspace_effect`
/// selector has no capsule-runnable child.
fn topology_expansion_operation(
    program: &ExecutionProgram,
    stage: &ExecutionProgramStage,
    path: &OperationPath,
    join_budget: usize,
) -> Result<RuntimeOperation, LoweringRefusal> {
    let envelope = &stage.invocation_envelope;
    let member_count = 1usize + envelope.children.len();
    let mut template = Vec::with_capacity(member_count);
    for member in 0..member_count {
        topology_member_executor(program, stage, member, join_budget)?;
        let member_index =
            u32::try_from(member).map_err(|_| LoweringRefusal::PathCoordinateOverflow)?;
        template.push(path.child(member_index));
    }
    Ok(RuntimeOperation::ExpandBounded {
        template,
        maximum: 1,
        policy_hash: topology_policy_selector(envelope),
    })
}

/// The `ActionExecutor` topology member `member` dispatches as — member 0 is
/// the ROOT: it executes the stage's own payload verbatim (the root attempt
/// dispatches on the stage's own selector; an authored
/// `topology.root.agent` is invocation-RECORD metadata and never re-binds it).
/// Member `m` runs child `m - 1`: a role naming `agent=` executes as that
/// driver (its first attempt on the role's selector, later failure retries on
/// the parent's panel members after the primary — effective-label
/// then `panel[min(i, len-1)]` order); a role naming `shell` executes the
/// command; a role naming nothing inherits the stage's payload executor
/// verbatim.
///
/// # Errors
///
/// [`LoweringRefusal::ExpansionMemberRefused`] when the resolved executor is
/// not `Command` or `Agent` — a member a capsule cannot run refuses the whole
/// expansion (all-or-nothing, [`expansion_template`]'s rule).
fn topology_member_executor(
    program: &ExecutionProgram,
    stage: &ExecutionProgramStage,
    member: usize,
    join_budget: usize,
) -> Result<ActionExecutor, LoweringRefusal> {
    let role_agent = match member {
        0 => None,
        m => stage
            .invocation_envelope
            .children
            .get(m - 1)
            .and_then(|child| child.agent.as_deref()),
    };
    let Some(label) = role_agent else {
        let RuntimeOperation::Execute(ExecuteOperation { executor, .. }) =
            stage_payload_operation(program, stage, join_budget)?
        else {
            return Err(LoweringRefusal::ExpansionMemberRefused);
        };
        return match executor {
            ActionExecutor::Command | ActionExecutor::Agent { .. } => Ok(executor),
            ActionExecutor::Effect { .. } => Err(LoweringRefusal::ExpansionMemberRefused),
        };
    };
    match BackendType::from_label(label) {
        Some(BackendType::Shell) => Ok(ActionExecutor::Command),
        Some(BackendType::WorkspaceEffect) => Err(LoweringRefusal::ExpansionMemberRefused),
        _ => {
            let mut drivers = Vec::with_capacity(stage.op.agent_panel.len().max(1));
            drivers.push(SmolStr::new(label));
            drivers.extend(stage.op.agent_panel.iter().skip(1).cloned());
            Ok(ActionExecutor::Agent { drivers })
        }
    }
}

/// The `ExpandBounded` a `dynamic_fanout` stage lowers to at its OWN stage
/// coordinate `path`. Its member list is a runtime answer — the request array
/// the root member's output carries — so the checked template is exactly
/// `[path.child(0)]`: member 0, the ROOT, executed on the stage's own payload.
/// Every request the runtime verifier accepts mints
/// `path.child(i + 1)` for the request at index `i`
/// (`lower_dynamic_fanout_member`). `maximum`
/// is 1: the fanout runs its member set once.
///
/// The executor checks run HERE, at lowering: member 0 must be
/// capsule-runnable exactly as a topology root must be, and every DECLARED
/// role's agent must map to `Command` or `Agent` — a request can only name a
/// declared role (`dynamic_child_requests`), so a role whose agent resolves to
/// a `workspace_effect` could otherwise be accepted by the verifier and mint a
/// member that cannot lower after the run exists. A role declaring NO agent
/// never mints a member (its requests refuse `must declare an agent`), so it
/// is no lowering refusal.
fn dynamic_fanout_expansion_operation(
    program: &ExecutionProgram,
    stage: &ExecutionProgramStage,
    path: &OperationPath,
    join_budget: usize,
) -> Result<RuntimeOperation, LoweringRefusal> {
    // Member 0 is the root: the stage's own payload executor.
    dynamic_member_executor(program, stage, None, join_budget)?;
    for role in &stage.invocation_envelope.children {
        if let Some(agent) = role.agent.as_deref() {
            dynamic_member_executor(program, stage, Some(agent), join_budget)?;
        }
    }
    Ok(RuntimeOperation::ExpandBounded {
        template: vec![path.child(0)],
        maximum: 1,
        policy_hash: topology_policy_selector(&stage.invocation_envelope),
    })
}

/// The `ActionExecutor` a dynamic member dispatches as. Member 0 is the ROOT —
/// `role_agent` is `None` and the executor is the stage's own payload verbatim,
/// refusing when the payload does not lower to `Execute { Command | Agent }`.
/// A request-derived member carries `Some(role.agent)` (the request verifier
/// requires the declared agent): `shell` executes the command,
/// `workspace_effect` refuses, and any other label drives as that agent with
/// the parent's panel tail as retry fallbacks — the same rule
/// [`topology_member_executor`] applies to a role's declared agent.
///
/// # Errors
///
/// [`LoweringRefusal::ExpansionMemberRefused`] when the resolved executor is
/// not `Command` or `Agent`.
fn dynamic_member_executor(
    program: &ExecutionProgram,
    stage: &ExecutionProgramStage,
    role_agent: Option<&str>,
    join_budget: usize,
) -> Result<ActionExecutor, LoweringRefusal> {
    let Some(label) = role_agent else {
        let RuntimeOperation::Execute(ExecuteOperation { executor, .. }) =
            stage_payload_operation(program, stage, join_budget)?
        else {
            return Err(LoweringRefusal::ExpansionMemberRefused);
        };
        return match executor {
            ActionExecutor::Command | ActionExecutor::Agent { .. } => Ok(executor),
            ActionExecutor::Effect { .. } => Err(LoweringRefusal::ExpansionMemberRefused),
        };
    };
    match BackendType::from_label(label) {
        Some(BackendType::Shell) => Ok(ActionExecutor::Command),
        Some(BackendType::WorkspaceEffect) => Err(LoweringRefusal::ExpansionMemberRefused),
        _ => {
            let mut drivers = Vec::with_capacity(stage.op.agent_panel.len().max(1));
            drivers.push(SmolStr::new(label));
            drivers.extend(stage.op.agent_panel.iter().skip(1).cloned());
            Ok(ActionExecutor::Agent { drivers })
        }
    }
}

/// The `policy_hash` of a topology expansion: the checked invocation envelope —
/// children, bounds (`max_concurrency`, `fanout_limit`), `dynamic_fanout`,
/// `mutation_policy`, `review_quorum`, `topology_kind` and `root` — hashed over
/// its CANONICAL JSON under a versioned domain, so any policy change (a role
/// added, a bound retuned, a quorum re-worded) rotates the expansion's identity
/// while a byte-identical envelope does not.
fn topology_policy_selector(envelope: &ExecutionInvocationEnvelope) -> ContentHash {
    let canonical = kata_types::idempotency::canonicalize_args(
        &serde_json::to_value(envelope).unwrap_or(serde_json::Value::Null),
    );
    let mut hasher = blake3::Hasher::new();
    kata_types::cache::hash_field(&mut hasher, "kata.execution.topology_policy.v1", &[]);
    kata_types::cache::hash_field(&mut hasher, "policy", &canonical);
    ContentHash::new(*hasher.finalize().as_bytes())
}

/// The `params_hash` of an [`RuntimeOperation::Invoke`]: the authored constant
/// params the parent passes its child, hashed over their CANONICAL JSON bytes
/// (`canonicalize_args`, sorted keys) under a versioned domain, so key order cannot
/// rotate the identity while any changed name or value must. An empty map is a value
/// too, and hashes as `{}`.
fn invoke_params_hash(params: &serde_json::Map<String, serde_json::Value>) -> ContentHash {
    let canonical =
        kata_types::idempotency::canonicalize_args(&serde_json::Value::Object(params.clone()));
    let mut hasher = blake3::Hasher::new();
    kata_types::cache::hash_field(&mut hasher, "kata.execution.invoke_params.v1", &[]);
    kata_types::cache::hash_field(&mut hasher, "params", &canonical);
    ContentHash::new(*hasher.finalize().as_bytes())
}

/// Whether `stage` plans STATIC child invocations — a declared `topology` role
/// list with no dynamic fanout. These stages lower to `ExpandBounded` at their
/// own stage coordinate.
pub fn plans_static_topology(stage: &ExecutionProgramStage) -> bool {
    !stage.invocation_envelope.children.is_empty() && !stage.invocation_envelope.dynamic_fanout
}

/// Whether `stage` plans DYNAMIC child invocations — `dynamic_fanout`, whose
/// member list is the runtime request array the root member's output carries.
/// These stages lower to `ExpandBounded` at their own stage coordinate: the
/// checked template holds member 0 (the root executor) only, and each
/// request the verifier accepts mints a member coordinate at runtime.
pub fn plans_dynamic_fanout(stage: &ExecutionProgramStage) -> bool {
    stage.invocation_envelope.dynamic_fanout
}

/// The refused classes that DOMINATE the choice of operation shape: whatever else
/// such a stage looks like, the lowering cannot express it. Checked in
/// [`LoweringRefusal`] declaration order.
fn stage_refusal_before_operation(stage: &ExecutionProgramStage) -> Option<LoweringRefusal> {
    if stage
        .op
        .agent_panel
        .first()
        .is_some_and(|primary| primary.as_str() != routing_label(stage))
    {
        return Some(LoweringRefusal::AgentPanelPrimaryMismatch);
    }
    if stage
        .op
        .agent_panel
        .iter()
        .any(|member| kata_types::agent::is_deterministic_agent_label(member.as_str()))
    {
        return Some(LoweringRefusal::PanelOnDeterministicExecutor);
    }
    None
}

/// The ORDERED driver list an agent stage's executor carries: the authored
/// `op.agent_panel` VERBATIM when there is one (`drivers[0]` is the primary, later
/// entries are the failure-retry fallbacks in order), else the single
/// `op.agent_label`.
///
/// Never `[]`: see [`LoweringRefusal::AgentSelectorUnbound`] for why an unbound
/// selector refuses instead. The panel's agreement with `op.agent_label` was
/// already established by [`stage_refusal_before_operation`], so reading the panel
/// verbatim here cannot disagree with the routing label the rest of the program
/// dispatches on.
fn agent_drivers(stage: &ExecutionProgramStage) -> Result<Vec<SmolStr>, LoweringRefusal> {
    if !stage.op.agent_panel.is_empty() {
        return Ok(stage.op.agent_panel.clone());
    }
    let label = stage
        .op
        .agent_label
        .clone()
        .ok_or(LoweringRefusal::AgentSelectorUnbound)?;
    Ok(vec![label])
}

/// The paths a `parallel()` barrier joins: the flat coordinate of each stage its
/// `depends_on` names. ALL-OR-NOTHING — a dependency that names no stage, or that
/// the lowering refuses, makes the whole join refuse
/// ([`LoweringRefusal::JoinInputRefused`]), because a `Join` over a subset of the
/// barrier's dependencies is a different barrier wearing the same identity.
///
/// Input order is the barrier's authored `depends_on` order, which the frontend
/// mints in branch order; `RuntimeOperation::Join` hashes its inputs in order, so
/// a reordered fan-in rotates the join identity.
fn join_inputs(
    program: &ExecutionProgram,
    barrier: &ExecutionProgramStage,
    budget: usize,
) -> Result<Vec<OperationPath>, LoweringRefusal> {
    let Some(budget) = budget.checked_sub(1) else {
        return Err(LoweringRefusal::JoinInputRefused);
    };
    let mut inputs = Vec::with_capacity(barrier.depends_on.len());
    for dependency in &barrier.depends_on {
        let Some((index, (_, stage))) = program
            .stages
            .iter()
            .enumerate()
            .find(|(_, (candidate, _))| *candidate == dependency)
        else {
            return Err(LoweringRefusal::JoinInputRefused);
        };
        let input_path = operation_path_at(index)?;
        if stage_operation(program, stage, &input_path, budget).is_err() {
            return Err(LoweringRefusal::JoinInputRefused);
        }
        inputs.push(input_path);
    }
    Ok(inputs)
}

/// The stage's ROUTING LABEL as the checked IR carries it: `op.agent_label` when
/// the backend-selector lowering wrote one, else the raw `op.agent` a labelled
/// selector leaves behind. THE one reading, so the executor resolution, the panel
/// agreement check, and the driver list cannot drift apart.
fn routing_label(stage: &ExecutionProgramStage) -> &str {
    stage
        .op
        .agent_label
        .as_deref()
        .unwrap_or_else(|| stage.op.agent.as_str())
}

/// The stage's resolved executor backend. Resolution goes through
/// [`BackendType::from_label`] — the tree's single label→backend mapping — rather
/// than matching label strings here.
fn resolved_backend(stage: &ExecutionProgramStage) -> Option<BackendType> {
    BackendType::from_label(routing_label(stage))
}
