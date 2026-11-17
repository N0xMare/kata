//! The shipped-corpus authority over the typed operation lowering
//! (`execution_program::operation_lowering`), which the `oci` submit path issues.
//!
//! The property is that *the shipped workflow corpus lowers deterministically*
//! and that identity is independently covered. This file is that authority for the command, agent,
//! wait, join, typed-VCS-effect, invoke, select, bounded-expansion and input-wait
//! shapes:
//!
//! * every stage of every shipped pack is either LOWERED (to a shape a predicate
//!   over LITERAL IR FIELDS predicts) or REFUSED BY NAME — the child-invocation
//!   class by a hand-written per-pack table rather than the lowerer's own
//!   predicate — never silently dropped, and never both; every `branch_routes`
//!   entry yields exactly one
//!   `Select`;
//! * the verdicts and the derived identities are byte-identical across two
//!   independent compiles of the same source;
//! * an occurrence identity moves with the execution and the path and with
//!   nothing else — asserted partly by reading the serialized field list of
//!   [`OccurrenceRef`] itself, which is an observation of the TYPE's shape rather
//!   than a restatement of the lowerer's;
//! * each shape's identity ROTATES when the thing it names changes: a stage
//!   contract, a sleep deadline, a barrier's fan-in, an effect's op, a route's arm
//!   target;
//! * each refused class is named by the exact arm, on a pack (or an inline pack)
//!   that really contains that construct;
//! * every shipped wait/join/invoke smoke run main-side under `oci` lowers to the shape a
//!   HAND-WRITTEN table read off its source says (`WAIT_SMOKE_STAGES`,
//!   `WAIT_SMOKE_SELECTS`, `WAIT_SMOKE_INPUTS`).
//!
//! The corpus walk mirrors `program_body_hash.rs` /`examples_corpus.rs`: the
//! root-level `.star` packs of `workflows/std`, `workflows/examples` and
//! `workflows/smoke`, compiled
//! through the library's own loader roots, with a floor so a shrinking corpus
//! fails instead of passing vacuously.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use kata_program::execution_program::{
    ExecutionHumanRequest, ExecutionProgram, ExecutionProgramStage, ExpansionKind, LoweringError,
    LoweringRefusal, OperationLoweringReport, ProgramOperationAt,
    compile_execution_program_from_file, compile_starlark_execution_program,
    lower_blocking_request, lower_branch_route, lower_dynamic_fanout_member,
    lower_expansion_member, lower_program_operations, lower_review_loop, lower_stage_operation,
    lower_topology_expansion, occurrence_for, operation_path_at, program_operation_at,
};
use kata_types::execution_contract::{
    ActionExecutor, InputRequestFields, OccurrenceRef, OperationPath, RuntimeOperation,
    WaitOperation, branch_route_selector, input_request_selector, loop_policy_selector,
};
use kata_types::wait::DurableSleep;
use kata_types::workflow::{BranchArm, ExecutionId};
use kata_types::workflow::{StageId, SynthesizedStage, WorkspaceEffectOp};
use ulid::Ulid;

/// The inline pack that witnesses the WAIT shape for the checked-IR coverage manifest
/// (`source_preflight:inline-durable-sleep-lowering`). The shipped `sleep()` pack,
/// `workflows/smoke/sleep-smoke.star`, is covered by the corpus walk and
/// `WAIT_SMOKE_STAGES` too; the manifest row names this source.
const INLINE_SLEEP_PACK: &str = "a = stage(id = \"a\", run = \":\", agent = \"shell\")\n\
     nap = sleep(id = \"nap\", for_ms = 60000, depends_on = [a])\n\
     b = stage(id = \"b\", run = \":\", agent = \"shell\", depends_on = [nap])\n\
     workflow(\"nap\", root = [a])\n";

/// Below this many lowered stage operations the corpus has stopped exercising the
/// lowerer. Measured at about 200 (command, agent, effect and join operations
/// across the shipped packs); pinned at roughly HALF, so this is a collapse
/// detector rather than a tripwire that benign pack churn reds.
const LOWERED_FLOOR: usize = 100;

/// Below this many compiled packs the corpus walk has stopped seeing the library
/// (53 today), the same floor `program_body_hash.rs` uses.
const PACK_FLOOR: usize = 20;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workflow crate lives under <repo>/crates/workflow")
        .to_path_buf()
}

/// Loader roots: both walked roots plus the bundled factory root, so a pack that
/// `load()`s `kata/std.star` or `kata/factory.star` resolves.
fn loader_roots() -> Vec<PathBuf> {
    let workflows = repo_root().join("workflows");
    vec![
        workflows.join("std"),
        workflows.join("examples"),
        workflows.join("kata-factory"),
        workflows.join("smoke"),
    ]
}

/// Root-level `.star` packs of `workflows/std`, `workflows/examples` and
/// `workflows/smoke`, sorted.
fn corpus_packs() -> Vec<PathBuf> {
    let workflows = repo_root().join("workflows");
    let mut packs = Vec::new();
    for dir in [
        workflows.join("std"),
        workflows.join("examples"),
        workflows.join("smoke"),
    ] {
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "star") {
                packs.push(path);
            }
        }
    }
    packs.sort();
    packs
}

/// Compile one pack, or `None` when this binary cannot compile it — a pack that
/// fails to compile is `just workflows-check-all`'s business, exactly as in
/// `program_body_hash.rs`.
fn compile(path: &Path) -> Option<ExecutionProgram> {
    compile_execution_program_from_file(path, &loader_roots()).ok()
}

fn compiled_corpus() -> Vec<(PathBuf, ExecutionProgram)> {
    let compiled: Vec<(PathBuf, ExecutionProgram)> = corpus_packs()
        .into_iter()
        .filter_map(|path| compile(&path).map(|program| (path, program)))
        .collect();
    assert!(
        compiled.len() >= PACK_FLOOR,
        "the corpus walk must see the shipped library: only {} packs compiled",
        compiled.len()
    );
    compiled
}

/// Compile an inline pack, for a construct no shipped pack carries.
fn inline(source: &str, name: &str) -> ExecutionProgram {
    compile_starlark_execution_program(source, name, &[])
        .unwrap_or_else(|e| panic!("the inline pack {name} must compile: {e}"))
}

fn pack(relative: &str) -> ExecutionProgram {
    let path = repo_root().join("workflows").join(relative);
    compile(&path).unwrap_or_else(|| panic!("the shipped pack {relative} must compile"))
}

/// The refusal arm the report assigns to each stage, by stage id.
fn refusals(report: &OperationLoweringReport) -> BTreeMap<String, LoweringRefusal> {
    report
        .refused
        .iter()
        .map(|entry| (entry.stage.0.to_string(), entry.refusal))
        .collect()
}

fn lowered_stages(report: &OperationLoweringReport) -> Vec<String> {
    report
        .lowered
        .iter()
        .map(|entry| entry.stage.0.to_string())
        .collect()
}

fn execution(byte: u8) -> ExecutionId {
    ExecutionId(Ulid::from_bytes([byte; 16]))
}

fn stage_id(id: &str) -> StageId {
    StageId(smol_str::SmolStr::new(id))
}

/// Read a stage's authored agent label out of the IR the way the CHECKED PROGRAM
/// presents it, as literal strings — deliberately NOT through
/// `BackendType::from_label` or `ExecutionProgramStage::is_deterministic_executor`,
/// so this test's notion of "a shell command stage" does not come from the same
/// helper the lowerer resolves with.
fn authored_label(program: &ExecutionProgram, stage_id: &StageId) -> String {
    let stage = &program.stages[stage_id];
    stage
        .op
        .agent_label
        .as_deref()
        .unwrap_or_else(|| stage.op.agent.as_str())
        .to_string()
}

/// The ORDERED template a review loop's expansion must carry, recomputed here
/// from `program.review_loops` — the loop's `effective_body_stages()` in order,
/// then its reviewer gate — so the template is observed independently of the
/// lowerer's own walk.
fn template_members(review_loop: &kata_types::review_loop::ReviewLoop) -> Vec<StageId> {
    let mut members = review_loop.effective_body_stages();
    members.push(StageId(review_loop.reviewer_stage.clone()));
    members
}

/// The flat stage coordinate of every stage, read off `program.stages`' own
/// (BTreeMap / stage-id) order rather than from the lowerer.
fn stage_coordinates(program: &ExecutionProgram) -> BTreeMap<String, u32> {
    program
        .stages
        .keys()
        .enumerate()
        .map(|(index, stage_id)| {
            (
                stage_id.0.to_string(),
                u32::try_from(index).expect("a test corpus program has few stages"),
            )
        })
        .collect()
}

/// What the lowering must produce for one stage, expressed ONLY over literal
/// checked-IR fields. `Join` carries no inputs here: the fan-in is asserted
/// separately against the dependencies' own coordinates.
#[derive(Debug, PartialEq, Eq)]
enum Expected {
    Refused(LoweringRefusal),
    Command,
    /// The ORDERED driver list the agent executor must carry.
    Agent(Vec<smol_str::SmolStr>),
    Effect(WorkspaceEffectOp),
    Wait(WaitOperation),
    Join,
    /// The bound child program's hash an `Invoke` must name.
    Invoke(kata_types::primitives::ContentHash),
    /// The member count a static `topology(..)` stage's `ExpandBounded` must
    /// carry — the root plus one member per declared child.
    ExpandBounded(usize),
    /// The authored `memory_snapshot()` filter the main-side read must carry.
    MemorySnapshot(kata_types::workflow::MemorySnapshotSpec),
}

/// The shape label this file's histograms and coverage claims speak.
fn shape_label(expected: &Expected) -> &'static str {
    match expected {
        Expected::Command => "execute:command",
        Expected::Agent(_) => "execute:agent",
        Expected::Effect(_) => "execute:effect",
        Expected::Wait(_) => "wait",
        Expected::Join => "join",
        Expected::Invoke(_) => "invoke",
        Expected::ExpandBounded(_) => "expand_bounded",
        Expected::MemorySnapshot(_) => "memory_snapshot",
        Expected::Refused(_) => unreachable!("a refusal has no shape"),
    }
}

/// The corpus stages that plan CHILD INVOCATIONS — hand-written facts about each pack,
/// read off its SOURCE: every one is a stage whose `topology(...)` declares a non-empty
/// `workers = [...]` or `reviewers = [...]` role list (directly in the pack, or through the
/// `kata/factory.star` helper named beside it). None authors dynamic fanout, so every
/// entry is a STATIC topology and expands; a `dynamic_fanout` entry would still
/// refuse `child_invocation`, and the arm reads that flag off the literal envelope.
///
/// A TABLE, not a predicate over `invocation_envelope.children`: "does this stage plan
/// children" is the lowerer's own expand condition (`plans_static_topology`), and
/// restating it here would make this file agree with the lowerer by construction for
/// exactly the class it is meant to check. Each entry must name a stage the corpus walk
/// actually visits — see `every_shipped_pack_lowers_every_stage_or_refuses_by_name` —
/// so the table cannot rot into naming nothing, and a topology stage missing from it
/// still lands in the generic agent/command arms and fails against `ExpandBounded`.
const CHILD_INVOCATION_STAGES: &[(&str, &str)] = &[
    // `topology(workers = [...])` on the implement and research stages, and
    // `topology(reviewers = [...])` on review, authored in the pack itself.
    ("std/kata-loop-lite.star", "implement"),
    ("std/kata-loop-lite.star", "research"),
    ("std/kata-loop-lite.star", "review"),
    // `plan_boundary_workflow` → `repo_research_stage`: `workers = [...]`.
    ("std/kata-loop-plan-check-std.star", "research"),
    // `factory_context_stage` (`workers = [...]`) and `factory_review_stage`
    // (`reviewers = [...]`), through each self-improve workflow helper.
    ("std/std.software_factory.kata_self_improve.star", "context"),
    ("std/std.software_factory.kata_self_improve.star", "review"),
    (
        "std/std.software_factory.kata_self_improve_inloop.star",
        "context",
    ),
    (
        "std/std.software_factory.kata_self_improve_inloop.star",
        "review",
    ),
    (
        "std/std.software_factory.kata_self_improve_inloop_gatesplit.star",
        "context",
    ),
    (
        "std/std.software_factory.kata_self_improve_inloop_gatesplit.star",
        "review",
    ),
    // `factory_preflight_review_stage`: `reviewers = [...]`. Its preflight CONTEXT stage
    // declares no role list, and is not here.
    (
        "std/std.software_factory.kata_self_improve_preflight.star",
        "review",
    ),
];

/// A corpus pack's key in [`CHILD_INVOCATION_STAGES`]: its path under `workflows/`.
fn corpus_key(path: &Path) -> String {
    path.strip_prefix(repo_root().join("workflows"))
        .expect("a corpus pack lives under workflows/")
        .display()
        .to_string()
}

/// The expected outcome for one stage, computed ONLY from literal checked-IR
/// fields — and, for child invocations, from [`CHILD_INVOCATION_STAGES`]. BIDIRECTIONAL by construction: it says both what must lower and what
/// must not, so an arm that over-refuses fails as loudly as one that
/// under-refuses.
///
/// A barrier's join is all-or-nothing over its dependencies, so this RECURSES
/// over `depends_on` through itself rather than consulting the lowering report:
/// reading the report's verdicts would make this predicate a mirror of the
/// lowerer for exactly the case the join arm is about. `budget` bounds the
/// barrier chain the same way the refused set says it is bounded — a dependency
/// naming no stage, a dependency that refuses, and an over-long (cyclic) chain
/// are the three `JoinInputRefused` cases, and all three are stated here.
fn expected_for(
    pack: &str,
    program: &ExecutionProgram,
    stage_id: &StageId,
    budget: usize,
) -> Expected {
    let stage = &program.stages[stage_id];

    // DYNAMIC FANOUT lowers to `ExpandBounded` at the stage's
    // own coordinate whose checked template is the ROOT alone — its children
    // mint at runtime off the root's request array. The flag is a literal
    // checked-IR field, read verbatim here as the panel arms read theirs.
    if stage.invocation_envelope.dynamic_fanout {
        return Expected::ExpandBounded(1);
    }
    // A panel's PRIMARY is the IR's own routing label; a decoded program whose
    // two spellings disagree has no single answer to "which driver is preferred",
    // so it refuses. Read off both literal fields, never through the lowerer.
    let routing = stage
        .op
        .agent_label
        .as_deref()
        .unwrap_or_else(|| stage.op.agent.as_str());
    if stage
        .op
        .agent_panel
        .first()
        .is_some_and(|primary| primary.as_str() != routing)
    {
        return Expected::Refused(LoweringRefusal::AgentPanelPrimaryMismatch);
    }
    // A panel is agent-only: a deterministic member has no driver list to advance
    // through. The reserved labels are spelled out HERE as literals rather than
    // read through `is_deterministic_agent_label`, so this predicate does not
    // consult the same helper the lowerer decides with.
    if stage
        .op
        .agent_panel
        .iter()
        .any(|member| matches!(member.as_str(), "shell" | "workspace_effect"))
    {
        return Expected::Refused(LoweringRefusal::PanelOnDeterministicExecutor);
    }
    // PREMISE, not a branch: every compiled pack carries a source hash, so the
    // program-scoped `SourceHashAbsent` arm (decided LAST, after every stage
    // class) is out of this predicate's reach and must not be guessed at here.
    assert!(
        program.source.source_hash.is_some(),
        "a compiled pack carries its source hash"
    );
    // A STATIC TOPOLOGY expands at the stage's own coordinate — decided after
    // the refusal arms (they dominate, as `stage_refusal_before_operation`
    // runs first) and before every payload shape (the expansion dominates
    // those, as `stage_operation` routes to it before `stage_payload_operation`).
    if CHILD_INVOCATION_STAGES.contains(&(pack, stage_id.0.as_str())) {
        return topology_expected(pack, program, stage, budget);
    }
    payload_expected(pack, program, stage, budget)
}

/// The member-executor leg of a static `topology(..)` stage's expectation —
/// the mirror of `topology_member_executor` stated over the literal envelope.
/// Member 0 (the ROOT) and every child role naming no `agent` run the stage's
/// own payload: only `Execute { Command | Agent }` is capsule-runnable, so a
/// payload that is `Invoke`, `Join`, `Wait` or `Effect` refuses the whole
/// expansion `ExpansionMemberRefused` — all-or-nothing, one refused member
/// refuses the stage — while a payload that REFUSES propagates its own arm.
/// A child naming `agent = "shell"` runs the command; any other agent label
/// runs as that driver; `agent = "workspace_effect"` has no capsule form and
/// refuses the same all-or-nothing arm.
fn topology_expected(
    pack: &str,
    program: &ExecutionProgram,
    stage: &ExecutionProgramStage,
    budget: usize,
) -> Expected {
    let inherited = payload_expected(pack, program, stage, budget);
    match inherited {
        Expected::Refused(refusal) => return Expected::Refused(refusal),
        Expected::Command | Expected::Agent(_) => {}
        _ => return Expected::Refused(LoweringRefusal::ExpansionMemberRefused),
    }
    for child in &stage.invocation_envelope.children {
        if matches!(child.agent.as_deref(), Some("workspace_effect")) {
            return Expected::Refused(LoweringRefusal::ExpansionMemberRefused);
        }
    }
    Expected::ExpandBounded(1 + stage.invocation_envelope.children.len())
}

/// The payload shapes — every arm [`stage_operation`] reaches once the refusal
/// and static-topology arms are past. A topology member's INHERITED executor
/// (member 0 the root, plus every child role naming no `agent`) resolves
/// through exactly this predicate, so `topology_expected` calls it rather
/// than restating the shapes.
fn payload_expected(
    pack: &str,
    program: &ExecutionProgram,
    stage: &ExecutionProgramStage,
    budget: usize,
) -> Expected {
    // A subworkflow stage lowers to an `Invoke` naming its BOUND child program, read
    // off the literal checked-IR field.
    if let Some(subworkflow) = stage.subworkflow.as_ref() {
        return Expected::Invoke(subworkflow.bound.program_hash());
    }
    if stage.synthesized == Some(SynthesizedStage::ParallelJoin) {
        let Some(budget) = budget.checked_sub(1) else {
            return Expected::Refused(LoweringRefusal::JoinInputRefused);
        };
        let every_input_lowers = stage.depends_on.iter().all(|dependency| {
            program.stages.contains_key(dependency)
                && !matches!(
                    expected_for(pack, program, dependency, budget),
                    Expected::Refused(_)
                )
        });
        return if every_input_lowers {
            Expected::Join
        } else {
            Expected::Refused(LoweringRefusal::JoinInputRefused)
        };
    }
    if let Some(sleep) = stage.durable_sleep {
        return Expected::Wait(match sleep {
            DurableSleep::For { ms } => WaitOperation::For { delay_ms: ms },
            DurableSleep::Until { epoch_ms } => WaitOperation::Until { epoch_ms },
        });
    }
    // A `memory_snapshot()` marker stage, claimed beside the durable-sleep
    // arm — its `agent = "shell"` surface is the inert placeholder the
    // builtin writes, never a command the routing match may read.
    if let Some(query) = stage.memory_snapshot {
        return Expected::MemorySnapshot(query);
    }
    let routing = stage
        .op
        .agent_label
        .as_deref()
        .unwrap_or_else(|| stage.op.agent.as_str());
    match routing {
        "shell" => {
            if format!("{:?}", stage.execution_class.computation) == "ProcessAction" {
                Expected::Command
            } else {
                Expected::Refused(LoweringRefusal::NotProcessAction)
            }
        }
        "workspace_effect" => match stage.workspace_effect_op {
            Some(op) => Expected::Effect(op),
            None => Expected::Refused(LoweringRefusal::WorkspaceEffectOpAbsent),
        },
        // An AGENT stage. Its drivers are the authored panel verbatim when there
        // is one, else the single routing label — and `agent_label == None` (the
        // `any` selector) names NO driver, so it refuses rather than claiming an
        // empty ordered fallback list.
        _ => {
            if stage.op.agent_panel.is_empty() {
                match &stage.op.agent_label {
                    Some(label) => Expected::Agent(vec![label.clone()]),
                    None => Expected::Refused(LoweringRefusal::AgentSelectorUnbound),
                }
            } else {
                Expected::Agent(stage.op.agent_panel.clone())
            }
        }
    }
}

/// The lowerer's verdict for one stage, projected onto [`Expected`] so the two
/// are comparable. The typed operation is read off the CONTRACT (through the
/// single-stage door), not off the report's summary strings.
fn actual_for(program: &ExecutionProgram, stage_id: &StageId) -> Expected {
    match lower_stage_operation(program, stage_id) {
        Err(LoweringError::Refused(refusal)) => Expected::Refused(refusal),
        Err(other) => panic!("stage {stage_id:?} must exist: {other:?}"),
        Ok(lowered) => match lowered.contract.operation {
            RuntimeOperation::Execute(execute) => match execute.executor {
                ActionExecutor::Command => Expected::Command,
                ActionExecutor::Effect { op, .. } => Expected::Effect(op),
                ActionExecutor::Agent { drivers } => Expected::Agent(drivers),
            },
            RuntimeOperation::Wait(wait) => Expected::Wait(wait),
            RuntimeOperation::Join { .. } => Expected::Join,
            RuntimeOperation::Invoke { program, .. } => Expected::Invoke(program),
            RuntimeOperation::ExpandBounded { template, .. } => {
                Expected::ExpandBounded(template.len())
            }
            RuntimeOperation::MemorySnapshot { query } => Expected::MemorySnapshot(query),
            RuntimeOperation::Select { .. } => {
                panic!("stage {stage_id:?} lowered to Select, which no stage operation claims")
            }
        },
    }
}

/// 1 — TOTALITY + the positive claim, for every shape. Every stage of every
/// shipped pack lands in exactly one of the two stage lists, and lands in the one
/// the literal-IR predicate names; every `branch_routes` entry yields exactly one
/// `Select`; every `review_loops` entry lands in exactly one of the two expansion
/// lists. The lowered total carries a floor so the walk cannot quietly stop
/// covering the library.
#[test]
fn every_shipped_pack_lowers_every_stage_or_refuses_by_name() {
    let mut total_lowered = 0usize;
    let mut total_stages = 0usize;
    let mut total_selects = 0usize;
    let mut total_expansions = 0usize;
    let mut total_inputs = 0usize;
    let mut refusal_histogram: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut kind_histogram: BTreeMap<String, usize> = BTreeMap::new();
    let mut child_entries_seen = 0usize;

    for (path, program) in compiled_corpus() {
        let name = path.display().to_string();
        let report = lower_program_operations(&program);
        let lowered: BTreeSet<String> = lowered_stages(&report).into_iter().collect();
        let refused = refusals(&report);

        for stage_id in program.stages.keys() {
            let id = stage_id.0.to_string();
            let in_lowered = lowered.contains(&id);
            let in_refused = refused.contains_key(&id);
            assert!(
                in_lowered ^ in_refused,
                "{name}: stage {id:?} must be lowered or refused, exactly one \
                 (lowered={in_lowered}, refused={in_refused})"
            );
        }
        assert_eq!(
            lowered.len() + refused.len(),
            program.stages.len(),
            "{name}: the report must carry no stage the program does not have"
        );
        // The SECOND totality invariant, and the reason the first still reads
        // `lowered + refused == stage_count` now that Selects exist: a route is a
        // program-level operation and is accounted for separately.
        assert_eq!(
            report.selects.len() + report.refused_selects.len(),
            program.branch_routes.len(),
            "{name}: every branch route must be lowered or refused, exactly once"
        );
        assert_eq!(
            report.selects.len(),
            program.branch_routes.len(),
            "{name}: every shipped route lowers; refusals here are {:?}",
            report.refused_selects
        );
        // The THIRD totality invariant: a review loop is a program-level
        // expansion, counted against `review_loops` and against neither of the
        // other two totals.
        assert_eq!(
            report.expansions.len() + report.refused_expansions.len(),
            program.review_loops.len(),
            "{name}: every review loop must be expanded or refused, exactly once"
        );
        // The FOURTH totality invariant: a blocking human request is a program-level
        // input wait, counted against the blocking requests — read here off the
        // literal queue, not through the lowerer's own filter — and against none of the
        // other three totals.
        let blocking: Vec<_> = program
            .human_request_queue
            .requests
            .iter()
            .filter(|request| request.blocking && request.stage.is_some())
            .collect();
        assert_eq!(
            report.inputs.len() + report.refused_inputs.len(),
            blocking.len(),
            "{name}: every blocking human request must be an input or refused, exactly once"
        );
        assert!(
            report.refused_inputs.is_empty(),
            "{name}: every shipped blocking request targets a stage of its pack: {:?}",
            report.refused_inputs
        );

        let key = corpus_key(&path);
        for (pack, stage) in CHILD_INVOCATION_STAGES {
            if *pack == key {
                assert!(
                    program.stages.contains_key(&stage_id(stage)),
                    "{name}: CHILD_INVOCATION_STAGES names {stage:?}, which this pack does not have"
                );
                child_entries_seen += 1;
            }
        }
        let coordinates = stage_coordinates(&program);
        for stage_id in program.stages.keys() {
            let expected = expected_for(&key, &program, stage_id, program.stages.len());
            let actual = actual_for(&program, stage_id);
            assert_eq!(
                expected, actual,
                "{name}: stage {stage_id:?} — the literal-IR predicate (child invocations: the table) says \
                 {expected:?}, the lowerer says {actual:?}"
            );
            if expected == Expected::Join {
                let lowered =
                    lower_stage_operation(&program, stage_id).expect("the barrier lowers");
                let inputs = match &lowered.contract.operation {
                    RuntimeOperation::Join { inputs } => inputs.clone(),
                    other => panic!("{name}: {stage_id:?} must be a join, got {other:?}"),
                };
                let expected_inputs: Vec<OperationPath> = program.stages[stage_id]
                    .depends_on
                    .iter()
                    .map(|dependency| OperationPath(vec![coordinates[dependency.0.as_str()]]))
                    .collect();
                assert_eq!(
                    inputs, expected_inputs,
                    "{name}: {stage_id:?} must join exactly its depends_on, in order"
                );
            }
            if let Expected::ExpandBounded(members) = expected {
                let lowered =
                    lower_stage_operation(&program, stage_id).expect("the topology expands");
                // The expansion sits at the stage's OWN coordinate — the same
                // flat index every non-expanding stage claims — and its
                // template is `path.child(m)` for each of the `members`
                // members, member 0 the root, in envelope order.
                assert_eq!(
                    lowered.path,
                    OperationPath(vec![coordinates[stage_id.0.as_str()]]),
                    "{name}: {stage_id:?}'s expansion path is its own stage coordinate"
                );
                let (template, maximum) = match &lowered.contract.operation {
                    RuntimeOperation::ExpandBounded {
                        template, maximum, ..
                    } => (template, maximum),
                    other => panic!("{name}: {stage_id:?} must expand, got {other:?}"),
                };
                assert_eq!(
                    template.len(),
                    members,
                    "{name}: {stage_id:?}'s template is the root plus its declared children"
                );
                for (member, entry) in template.iter().enumerate() {
                    assert_eq!(
                        *entry,
                        lowered
                            .path
                            .child(u32::try_from(member).expect("small program")),
                        "{name}: {stage_id:?}'s template[{member}] is its own child coordinate"
                    );
                }
                assert_eq!(
                    *maximum, 1,
                    "{name}: a static topology runs its members once"
                );
            }
        }

        // The Select paths live past every stage path, which is the whole reason
        // the flat coordinate space is safe.
        for (index, entry) in report.selects.iter().enumerate() {
            assert_eq!(
                entry.path,
                OperationPath(vec![
                    u32::try_from(program.stages.len() + index).expect("small program")
                ]),
                "{name}: a route's path is stage_count + route_index"
            );
            assert!(
                program.stages.contains_key(&entry.condition_stage),
                "{name}: a lowered route's condition stage exists"
            );
        }

        // Every expansion's path sits past every stage path AND every route path,
        // which is what makes the third flat segment safe.
        for (index, entry) in report.expansions.iter().enumerate() {
            assert_eq!(
                entry.path,
                OperationPath(vec![
                    u32::try_from(program.stages.len() + program.branch_routes.len() + index)
                        .expect("small program")
                ]),
                "{name}: an expansion's path is stage_count + route_count + loop_index"
            );
        }

        // Every input's path sits past every stage, route and loop path, in queue order,
        // and names the request and its target literally.
        for (index, (entry, request)) in report.inputs.iter().zip(&blocking).enumerate() {
            assert_eq!(
                entry.path,
                OperationPath(vec![
                    u32::try_from(
                        program.stages.len()
                            + program.branch_routes.len()
                            + program.review_loops.len()
                            + index
                    )
                    .expect("small program")
                ]),
                "{name}: an input's path is stage_count + route_count + loop_count + index"
            );
            assert_eq!(entry.request, request.id, "{name}: queue order");
            assert_eq!(Some(&entry.target_stage), request.stage.as_ref());
        }

        total_lowered += lowered.len();
        total_stages += program.stages.len();
        total_selects += report.selects.len();
        total_expansions += report.expansions.len();
        total_inputs += report.inputs.len();
        for entry in &report.refused {
            *refusal_histogram.entry(entry.refusal.as_str()).or_default() += 1;
        }
        for entry in &report.refused_expansions {
            *refusal_histogram.entry(entry.refusal.as_str()).or_default() += 1;
        }
        for entry in &report.lowered {
            let shape = shape_label(&actual_for(&program, &entry.stage));
            *kind_histogram.entry(shape.to_string()).or_default() += 1;
        }
    }

    assert!(
        total_lowered >= LOWERED_FLOOR,
        "only {total_lowered} of {total_stages} corpus stages lowered; floor is {LOWERED_FLOOR}. \
         refusals: {refusal_histogram:?}"
    );
    // The corpus must exercise each stage shape this file claims — `wait` from
    // `sleep-smoke.star`, `invoke` from `subworkflow-parent-smoke.star`, and
    // `expand_bounded` from the static `topology` stages above.
    for shape in [
        "execute:command",
        "execute:agent",
        "execute:effect",
        "join",
        "wait",
        "invoke",
        "expand_bounded",
    ] {
        assert!(
            kind_histogram.get(shape).copied().unwrap_or_default() > 0,
            "the corpus must lower at least one {shape}; shapes are {kind_histogram:?}"
        );
    }
    assert!(
        total_selects > 0,
        "the corpus must carry branch routes to lower as Selects"
    );
    assert!(
        total_expansions > 0,
        "the corpus must carry review loops to lower as bounded expansions"
    );
    assert!(
        total_inputs > 0,
        "the corpus must carry blocking human requests to lower as input waits"
    );
    assert_eq!(
        child_entries_seen,
        CHILD_INVOCATION_STAGES.len(),
        "every CHILD_INVOCATION_STAGES entry must name a pack the corpus walk compiled"
    );
    eprintln!(
        "corpus histogram — shapes {kind_histogram:?}, selects {total_selects}, \
         expansions {total_expansions}, inputs {total_inputs}, refusals {refusal_histogram:?}"
    );
}

/// 2 — DETERMINISM. Two independent compiles of the same pack produce a
/// byte-identical report and identical occurrence identities for a fixed
/// [`ExecutionId`], for stages and routes alike.
#[test]
fn lowering_is_deterministic_across_two_independent_compiles() {
    let execution = execution(9);
    let mut checked = 0usize;
    for path in corpus_packs() {
        let (Some(first), Some(second)) = (compile(&path), compile(&path)) else {
            continue;
        };
        let name = path.display().to_string();
        assert_eq!(
            serde_json::to_string(&lower_program_operations(&first)).expect("report serializes"),
            serde_json::to_string(&lower_program_operations(&second)).expect("report serializes"),
            "{name}: the lowering report must be byte-identical across two compiles"
        );
        for stage_id in first.stages.keys() {
            let occurrence = |program: &ExecutionProgram| {
                lower_stage_operation(program, stage_id)
                    .ok()
                    .map(|lowered| occurrence_for(program, execution, &lowered).id())
            };
            assert_eq!(
                occurrence(&first),
                occurrence(&second),
                "{name}: stage {stage_id:?} must keep its occurrence identity across compiles"
            );
        }
        for index in 0..first.branch_routes.len() {
            let occurrence = |program: &ExecutionProgram| {
                lower_branch_route(program, index)
                    .ok()
                    .map(|lowered| occurrence_for(program, execution, &lowered).id())
            };
            assert_eq!(
                occurrence(&first),
                occurrence(&second),
                "{name}: route {index} must keep its occurrence identity across compiles"
            );
        }
        for index in 0..first.review_loops.len() {
            let occurrence = |program: &ExecutionProgram| {
                lower_review_loop(program, index)
                    .ok()
                    .map(|lowered| occurrence_for(program, execution, &lowered).id())
            };
            assert_eq!(
                occurrence(&first),
                occurrence(&second),
                "{name}: loop {index} must keep its occurrence identity across compiles"
            );
        }
        checked += 1;
    }
    assert!(checked >= PACK_FLOOR, "only {checked} packs compiled twice");
}

/// 3 — OCCURRENCE IDENTITY carries the execution and the path, and the TYPE
/// carries no placement coordinate at all. The field-name assertion reads
/// [`OccurrenceRef`]'s own serialized shape, so it fails if a later change adds an
/// attempt/lease/worker/ordinal field to the type even though this lowerer never
/// sets one.
#[test]
fn occurrence_identity_ignores_execution_placement_facts_and_tracks_path() {
    let program = pack("examples/hello-workflow.star");
    let stage_id = program
        .stages
        .keys()
        .find(|id| lower_stage_operation(&program, id).is_ok())
        .expect("hello-workflow lowers at least one command stage")
        .clone();
    let lowered = lower_stage_operation(&program, &stage_id).expect("the stage lowers");

    let one = occurrence_for(&program, execution(1), &lowered);
    let two = occurrence_for(&program, execution(2), &lowered);
    assert_ne!(
        one.id(),
        two.id(),
        "a different execution must be a different occurrence"
    );

    let deeper = OccurrenceRef::new(one.execution, one.program, one.operation, one.path.child(3));
    assert_ne!(
        one.id(),
        deeper.id(),
        "a deeper expansion path must be a different occurrence"
    );
    assert_eq!(
        one.path,
        OperationPath(vec![one.path.0[0]]),
        "the lowered path is a single flat coordinate"
    );

    let fields: Vec<String> = serde_json::to_value(&one)
        .expect("an occurrence reference serializes")
        .as_object()
        .expect("it serializes as an object")
        .keys()
        .cloned()
        .collect();
    for forbidden in [
        "attempt",
        "lease",
        "worker",
        "ordinal",
        "placement",
        "retry",
    ] {
        assert!(
            !fields.iter().any(|field| field.contains(forbidden)),
            "OccurrenceRef must carry no {forbidden}-like field; fields are {fields:?}"
        );
    }
    assert!(
        fields.iter().any(|field| field == "execution") && fields.iter().any(|f| f == "path"),
        "the fields this identity DOES bind must be present: {fields:?}"
    );
}

/// 4 — CHANGED BINDING invalidates identity. Rotating a stage's `contract_hash`
/// rotates both the operation id and the occurrence id; renaming the stage
/// rotates the operation id.
#[test]
fn changed_contract_hash_rotates_operation_and_occurrence_identity() {
    let program = pack("examples/hello-workflow.star");
    let stage_id = program
        .stages
        .keys()
        .find(|id| lower_stage_operation(&program, id).is_ok())
        .expect("hello-workflow lowers at least one command stage")
        .clone();
    let base = lower_stage_operation(&program, &stage_id).expect("the stage lowers");
    let base_occurrence = occurrence_for(&program, execution(4), &base).id();

    let mut rotated = program.clone();
    let stage = rotated
        .stages
        .get_mut(&stage_id)
        .expect("the stage is present");
    stage.contract_hash = kata_types::primitives::ContentHash::new([0xa5; 32]);
    let moved = lower_stage_operation(&rotated, &stage_id).expect("the stage still lowers");
    assert_ne!(
        base.contract.id(),
        moved.contract.id(),
        "a changed stage contract must rotate the operation identity"
    );
    assert_ne!(
        base_occurrence,
        occurrence_for(&rotated, execution(4), &moved).id(),
        "a changed stage contract must rotate the occurrence identity"
    );

    let mut renamed = program.clone();
    let mut stage = renamed
        .stages
        .remove(&stage_id)
        .expect("the stage is present");
    let new_id = stage_id_renamed(&stage_id);
    stage.stage_id = new_id.clone();
    renamed.stages.insert(new_id.clone(), stage);
    let renamed_lowered =
        lower_stage_operation(&renamed, &new_id).expect("the renamed stage lowers");
    assert_ne!(
        base.contract.id(),
        renamed_lowered.contract.id(),
        "the authored stage id is part of the operation identity"
    );
    assert_eq!(
        renamed_lowered.source_map.authored_label.as_str(),
        new_id.0.as_str(),
        "the source map's authored label is the authored stage id"
    );
}

fn stage_id_renamed(stage_id: &StageId) -> StageId {
    StageId(smol_str::SmolStr::new(format!("{}_renamed", stage_id.0)))
}

/// 5 — each REFUSED CLASS is named by its exact arm, on a pack that really
/// carries that construct; and a subworkflow, which is not a refused class, lowers
/// to an `Invoke` over its bound child, compiled inline against the corpus library roots
/// (the rig `subworkflow-parent-smoke.star` is in `WAIT_SMOKE_STAGES`).
///
/// A checked `topology` role list lowers to `ExpandBounded` at the stage's own
/// coordinate, and so does a `dynamic_fanout` envelope, whose checked template is the
/// root alone — the children the root's output requests mint at runtime. Neither an
/// approval gate nor a blocking human request refuses its stage: the gate
/// is a gate on the stage's own capsule attempt, and the
/// request is its own program-level input wait, both witnessed below.
#[test]
fn child_invocation_is_refused_by_name_while_gates_requests_and_subworkflows_lower() {
    let expect = |program: &ExecutionProgram, label: &str, cases: &[(&str, LoweringRefusal)]| {
        let report = lower_program_operations(program);
        let refused = refusals(&report);
        for (stage, arm) in cases {
            assert_eq!(
                refused.get(*stage).copied(),
                Some(*arm),
                "{label}: stage {stage:?} must be refused as {arm:?}; report refusals are \
                 {refused:?}, lowered {:?}",
                lowered_stages(&report)
            );
            assert_eq!(
                lower_stage_operation(program, &stage_id(stage)),
                Err(LoweringError::Refused(*arm)),
                "{label}: the single-stage door must refuse {stage:?} with the same arm"
            );
        }
    };

    // A subworkflow stage carries no authored agent at all, and it is not a
    // refused class: it lowers to an `Invoke` over the child program bound at check
    // (the shipped `hello-workflow`, resolved through the corpus library roots).
    let sub = compile_starlark_execution_program(
        "a = stage(id = \"a\", run = \":\", agent = \"shell\")\n\
         c = subworkflow(id = \"child\", pack = \"hello-workflow\", depends_on = [a])\n\
         workflow(\"sub\", root = [a])\n",
        "sub.star",
        &loader_roots(),
    )
    .expect("the inline subworkflow parent compiles against the shipped library");
    let bound = sub.stages[&stage_id("child")]
        .subworkflow
        .as_ref()
        .expect("the child stage is a subworkflow")
        .bound
        .program_hash();
    assert_eq!(
        bound,
        pack("examples/hello-workflow.star").program_hash,
        "the bound child is exactly the shipped pack's compiled program"
    );
    match lower_stage_operation(&sub, &stage_id("child")) {
        Ok(lowered) => match lowered.contract.operation {
            RuntimeOperation::Invoke { program, .. } => assert_eq!(program, bound),
            other => panic!("a subworkflow lowers to an Invoke, got {other:?}"),
        },
        Err(error) => panic!("a subworkflow stage must lower, got {error:?}"),
    }

    // A DECODED program whose panel primary disagrees with the routing label the
    // rest of the IR carries: the two spellings name different preferred drivers,
    // so there is no honest ordered list. Not frontend-producible — the panel
    // lowering writes the primary into both — so the witness is a mutation of a
    // compiled program.
    let mut disagreeing = inline(
        "p = stage(id = \"p\", prompt = \"x\", agent = [\"claude_code\", \"codex\"])\n\
         workflow(\"panel\", root = [p])\n",
        "panel.star",
    );
    let panel_stage = disagreeing
        .stages
        .get_mut(&stage_id("p"))
        .expect("the panel stage is present");
    assert_eq!(
        panel_stage
            .op
            .agent_panel
            .first()
            .map(smol_str::SmolStr::as_str),
        panel_stage.op.agent_label.as_deref(),
        "the premise: the frontend agrees with itself"
    );
    panel_stage.op.agent_label = Some(smol_str::SmolStr::new("codex"));
    expect(
        &disagreeing,
        "decoded panel whose primary disagrees",
        &[("p", LoweringRefusal::AgentPanelPrimaryMismatch)],
    );

    // Neither a declared approval gate nor a blocking human request refuses its stage.
    // The gate is a gate on the stage's own capsule attempt, so `human-gate-approval`'s
    // `deploy` lowers to the command it runs; the request is its
    // own PROGRAM-level input wait, so `durable-wait-signal`'s `decide` lowers to its
    // command too and the request appears in the report's input list
    // (`a_blocking_request_lowers_to_one_program_level_input_wait` pins its shape).
    assert!(
        lower_stage_operation(
            &pack("examples/human-gate-approval.star"),
            &stage_id("deploy")
        )
        .is_ok(),
        "an approval-gated shell stage lowers to its command"
    );
    let blocking = pack("examples/durable-wait-signal.star");
    assert!(
        !blocking.stages[&stage_id("decide")]
            .policies
            .approval_required,
        "the point of this case: the blocking park is NOT spelled as approval_required"
    );
    assert!(
        matches!(
            lower_stage_operation(&blocking, &stage_id("decide"))
                .expect("a blocking request's target lowers under its own verdict")
                .contract
                .operation,
            RuntimeOperation::Execute(_)
        ),
        "the target of a blocking request lowers to the command it runs"
    );
    let report = lower_program_operations(&blocking);
    assert!(report.refused.is_empty(), "{:?}", report.refused);
    assert_eq!(
        report
            .inputs
            .iter()
            .map(|input| (input.request.as_str(), input.target_stage.0.as_str()))
            .collect::<Vec<_>>(),
        [("proceed_q", "decide")]
    );

    // DYNAMIC FANOUT lowers: the shipped corpus authors only
    // static role lists, so the witness is a MUTATED compiled program —
    // `research`'s envelope gains `dynamic_fanout`. Its `ExpandBounded` sits at
    // the stage's own coordinate with the ROOT as the template's only member
    // (the children mint at runtime), `maximum = 1`.
    let mut dynamic = pack("std/kata-loop-plan-check-std.star").clone();
    let fanout_stage = dynamic
        .stages
        .get_mut(&stage_id("research"))
        .expect("the topology stage is present");
    assert!(
        !fanout_stage.invocation_envelope.children.is_empty(),
        "the premise: the stage declares a role list"
    );
    fanout_stage.invocation_envelope.dynamic_fanout = true;
    let lowered = lower_stage_operation(&dynamic, &stage_id("research"))
        .expect("a dynamic fanout stage lowers");
    let RuntimeOperation::ExpandBounded {
        template, maximum, ..
    } = &lowered.contract.operation
    else {
        panic!("a dynamic fanout lowers to ExpandBounded: {lowered:?}");
    };
    assert_eq!(
        (template.as_slice(), *maximum),
        (&[lowered.path.child(0)][..], 1),
        "the root is the checked template's only member"
    );

    // A stage id that names nothing is a caller mistake, never a refused class.
    let hello = pack("examples/hello-workflow.star");
    let absent = stage_id("no_such_stage");
    assert_eq!(
        lower_stage_operation(&hello, &absent),
        Err(LoweringError::UnknownStage(absent))
    );
    // Neither is a route index past the end of the route list.
    assert_eq!(
        lower_branch_route(&hello, 0),
        Err(LoweringError::UnknownRoute(0))
    );
}

/// 6 — THE MARKER IS A FACT ABOUT THE PROGRAM, observed from the compiled IR
/// rather than from the operation it produces. Every pack that authors
/// `parallel()` carries exactly one `ParallelJoin`-marked stage per barrier, each
/// one the shell no-op the frontend mints; every pack that authors no
/// `parallel()` carries none.
///
/// This is the independent half of the JOIN claim: the join test asserts what the
/// lowerer does with the marker, this asserts the marker means what its name says
/// — read from `program.stages` and the pack SOURCE TEXT, never from the lowering
/// report.
#[test]
fn the_parallel_join_marker_is_present_exactly_on_authored_parallel_barriers() {
    let mut packs_with_barriers = 0usize;
    for (path, program) in compiled_corpus() {
        let name = path.display().to_string();
        let source = std::fs::read_to_string(&path).expect("a compiled pack is readable");
        // What the AUTHOR wrote, read out of the source bytes — not out of the IR.
        let authors_parallel = source.contains("parallel(");

        let marked: Vec<&StageId> = program
            .stages
            .iter()
            .filter(|(_, stage)| stage.synthesized == Some(SynthesizedStage::ParallelJoin))
            .map(|(stage_id, _)| stage_id)
            .collect();
        assert_eq!(
            !marked.is_empty(),
            authors_parallel,
            "{name}: the pack {} parallel(), but carries {} marked barrier(s)",
            if authors_parallel {
                "authors"
            } else {
                "does not author"
            },
            marked.len()
        );
        for stage_id in &marked {
            let stage = &program.stages[*stage_id];
            assert_eq!(
                stage.op.prompt_template.trim(),
                ":",
                "{name}: a marked barrier is the frontend's shell no-op"
            );
            assert!(
                stage.depends_on.len() >= 2,
                "{name}: a barrier fans in every branch, got {:?}",
                stage.depends_on
            );
        }
        if !marked.is_empty() {
            packs_with_barriers += 1;
        }
    }
    assert!(
        packs_with_barriers >= 3,
        "the corpus must still exercise parallel(), only {packs_with_barriers} packs do"
    );
}

/// 7 — the coverage manifest's claims about this lowerer are TRUE: each feature's
/// representative pack really produces the operation shape the feature names. The
/// manifest's own fail-closed pass (`checked_ir_coverage.rs`) proves the features
/// are declared and referenced; this proves the referenced packs exercise them.
#[test]
fn the_coverage_manifest_representatives_really_lower_each_operation_shape() {
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/checked-ir-fixtures.json"),
        )
        .expect("the checked-IR corpus is readable"),
    )
    .expect("the checked-IR corpus parses");

    // The representative fixture id and the shipped pack it stands for, per
    // feature. Paired here because the manifest carries fixture ids, not pack
    // paths.
    let claims: [(&str, &str, &str, &str); 7] = [
        (
            "kata.execution.typed_command_operation",
            "source_preflight:kata-work-item-cli-lowering",
            "std/kata-work-item.star",
            "execute:command",
        ),
        (
            "kata.execution.typed_join_operation",
            "source_preflight:parallel-smoke-cli-lowering",
            "smoke/parallel-smoke.star",
            "join",
        ),
        (
            "kata.execution.typed_effect_operation",
            "source_preflight:workspace-effect-smoke-cli-lowering",
            "smoke/workspace-effect-smoke.star",
            "execute:effect",
        ),
        (
            // The wait feature's manifest witness is the inline pack this file
            // compiles (it predates the rig `sleep-smoke.star`); the fixture row
            // names it.
            "kata.execution.typed_wait_operation",
            "source_preflight:inline-durable-sleep-lowering",
            INLINE_SLEEP_PACK,
            "wait",
        ),
        (
            "kata.execution.typed_select_operation",
            "source_preflight:branch-routing-cli-lowering",
            "examples/branch-routing.star",
            "select",
        ),
        (
            "kata.execution.typed_agent_operation",
            "source_preflight:self-review-cli-lowering",
            "std/self-review.star",
            "execute:agent",
        ),
        (
            "kata.execution.typed_expansion_operation",
            "source_preflight:review-loop-smoke-cli-lowering",
            "smoke/review-loop-smoke.star",
            "expand_bounded",
        ),
    ];

    for (feature, fixture, pack_path, shape) in claims {
        let representative = manifest["coverage_manifest"]["representatives"]
            .as_array()
            .expect("representatives are an array")
            .iter()
            .find(|entry| {
                entry["feature_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|id| id == feature))
            })
            .unwrap_or_else(|| panic!("no representative claims {feature}"));
        assert_eq!(
            representative["fixture"], fixture,
            "this test knows which pack {fixture} stands for; re-pair it if the manifest moves"
        );

        let program = if pack_path == INLINE_SLEEP_PACK {
            inline(INLINE_SLEEP_PACK, "inline-durable-sleep.star")
        } else {
            pack(pack_path)
        };
        let report = lower_program_operations(&program);
        let produced: BTreeSet<String> = match shape {
            "select" => report
                .selects
                .iter()
                .map(|_| "select".to_string())
                .collect(),
            "expand_bounded" => report
                .expansions
                .iter()
                .map(|_| "expand_bounded".to_string())
                .collect(),
            _ => report
                .lowered
                .iter()
                .map(|entry| shape_label(&actual_for(&program, &entry.stage)).to_string())
                .collect(),
        };
        assert!(
            produced.contains(shape),
            "{pack_path} must exercise {feature} ({shape}); it produced {produced:?} \
             with refusals {:?}",
            refusals(&report)
        );
    }
}

/// 8 — WAIT. A `sleep()` stage lowers to the typed wait operation, one variant per
/// authored spelling, and the wake target is part of the identity. Asserted
/// against the literal `durable_sleep` field, over an inline pack because both
/// spellings and a changed deadline are needed (the one shipped sleep,
/// `sleep-smoke.star`, authors `for_ms` only).
#[test]
fn a_durable_sleep_stage_lowers_to_the_typed_wait_operation() {
    let relative = inline(INLINE_SLEEP_PACK, "nap.star");
    let nap = stage_id("nap");
    assert_eq!(
        relative.stages[&nap].durable_sleep,
        Some(DurableSleep::For { ms: 60000 }),
        "the literal IR marker this claim is about"
    );
    let lowered = lower_stage_operation(&relative, &nap).expect("a durable sleep lowers");
    assert_eq!(
        lowered.contract.operation,
        RuntimeOperation::Wait(WaitOperation::For { delay_ms: 60000 }),
        "a relative sleep is a For wait carrying the authored delay"
    );
    assert_eq!(
        lowered.source_map.authored_label.as_str(),
        "nap",
        "the wait's source map names the authored stage"
    );

    let absolute = inline(
        "a = stage(id = \"a\", run = \":\", agent = \"shell\")\n\
         nap = sleep(id = \"nap\", until_ms = 1893456000000, depends_on = [a])\n\
         workflow(\"nap\", root = [a])\n",
        "until.star",
    );
    assert_eq!(
        absolute.stages[&nap].durable_sleep,
        Some(DurableSleep::Until {
            epoch_ms: 1_893_456_000_000
        })
    );
    let until = lower_stage_operation(&absolute, &nap).expect("an absolute sleep lowers");
    assert_eq!(
        until.contract.operation,
        RuntimeOperation::Wait(WaitOperation::Until {
            epoch_ms: 1_893_456_000_000
        }),
        "an absolute sleep is an Until wait carrying the authored deadline"
    );

    // IDENTITY ROTATION: the wake target is semantic, so moving it moves the id,
    // and a relative delay is never the same operation as an absolute deadline.
    assert_ne!(
        lowered.contract.id(),
        until.contract.id(),
        "For and Until are different operations even on the same stage"
    );
    let mut moved = relative.clone();
    moved
        .stages
        .get_mut(&nap)
        .expect("the sleep stage is present")
        .durable_sleep = Some(DurableSleep::For { ms: 60001 });
    assert_ne!(
        lowered.contract.id(),
        lower_stage_operation(&moved, &nap)
            .expect("it still lowers")
            .contract
            .id(),
        "a changed delay must rotate the wait identity"
    );
}

/// 9 — JOIN. The synthetic `parallel()` barrier lowers to a join over exactly the
/// paths of the stages it fans in, in `depends_on` order, and the fan-in is part
/// of the identity.
#[test]
fn a_parallel_barrier_lowers_to_a_join_over_its_dependencies() {
    let program = pack("smoke/parallel-smoke.star");
    let barrier = stage_id("__parallel_join_0");
    assert_eq!(
        program.stages[&barrier].synthesized,
        Some(SynthesizedStage::ParallelJoin),
        "the literal IR marker this claim is about"
    );
    let coordinates = stage_coordinates(&program);
    let lowered = lower_stage_operation(&program, &barrier).expect("the barrier lowers");
    let expected: Vec<OperationPath> = program.stages[&barrier]
        .depends_on
        .iter()
        .map(|dependency| OperationPath(vec![coordinates[dependency.0.as_str()]]))
        .collect();
    assert!(
        expected.len() >= 2,
        "the barrier fans in both branches: {expected:?}"
    );
    assert_eq!(
        lowered.contract.operation,
        RuntimeOperation::Join {
            inputs: expected.clone()
        },
        "the join's inputs are its dependencies' paths, in depends_on order"
    );

    // IDENTITY ROTATION: drop one branch from the fan-in and the join is a
    // different operation.
    let mut narrowed = program.clone();
    let dropped = narrowed
        .stages
        .get_mut(&barrier)
        .expect("the barrier is present");
    dropped.depends_on.truncate(1);
    assert_ne!(
        lowered.contract.id(),
        lower_stage_operation(&narrowed, &barrier)
            .expect("a one-input join still lowers")
            .contract
            .id(),
        "a narrower fan-in must rotate the join identity"
    );
}

/// 10 — JOIN is ALL-OR-NOTHING. A barrier whose dependency the lowering refuses
/// refuses as [`LoweringRefusal::JoinInputRefused`] rather than lowering a join
/// over the subset that happens to lower.
#[test]
fn a_join_over_a_refused_dependency_refuses_rather_than_half_lowering() {
    let mut program = pack("smoke/parallel-smoke.star");
    let barrier = stage_id("__parallel_join_0");
    let branch = program.stages[&barrier]
        .depends_on
        .first()
        .expect("the barrier fans in at least one branch")
        .clone();
    // Turn ONE fanned-in branch into a construct the lowering refuses (a panel
    // naming a deterministic executor), leaving the other lowering.
    program
        .stages
        .get_mut(&branch)
        .expect("the branch is present")
        .op
        .agent_panel = vec![smol_str::SmolStr::new("shell")];
    assert_eq!(
        lower_stage_operation(&program, &branch),
        Err(LoweringError::Refused(
            LoweringRefusal::PanelOnDeterministicExecutor
        )),
        "the premise: the dependency is refused"
    );
    assert_eq!(
        lower_stage_operation(&program, &barrier),
        Err(LoweringError::Refused(LoweringRefusal::JoinInputRefused)),
        "a join over a refused dependency must refuse, not narrow itself"
    );

    // A dependency that names no stage at all is the same refusal: the join's
    // input set cannot be honest either way.
    let mut dangling = pack("smoke/parallel-smoke.star");
    dangling
        .stages
        .get_mut(&barrier)
        .expect("the barrier is present")
        .depends_on = vec![stage_id("no_such_stage")];
    assert_eq!(
        lower_stage_operation(&dangling, &barrier),
        Err(LoweringError::Refused(LoweringRefusal::JoinInputRefused)),
        "a join over an absent dependency must refuse"
    );
}

/// 11 — TYPED VCS EFFECT. A `workspace_effect` stage lowers to
/// [`ActionExecutor::Effect`] naming both the effect family and the authored op,
/// read from the checked stage's typed field and never from the directive prompt.
#[test]
fn a_workspace_effect_stage_lowers_to_the_typed_effect_operation() {
    let program = pack("smoke/workspace-effect-smoke.star");
    for (id, op) in [
        ("record", WorkspaceEffectOp::Commit),
        ("park", WorkspaceEffectOp::Park),
    ] {
        let stage = stage_id(id);
        // The literal IR facts this claim is about.
        assert_eq!(
            authored_label(&program, &stage),
            "workspace_effect",
            "{id}: the authored executor label"
        );
        assert_eq!(
            program.stages[&stage].workspace_effect_op,
            Some(op),
            "{id}: the checked stage carries its typed op"
        );
        let lowered = lower_stage_operation(&program, &stage).expect("an effect stage lowers");
        assert_eq!(
            lowered.contract.operation,
            RuntimeOperation::Execute(kata_types::execution_contract::ExecuteOperation {
                executor: ActionExecutor::Effect {
                    effect_kind: kata_types::effect::EffectKind::WorkspaceEffect,
                    op,
                },
                contract_hash: program.stages[&stage].contract_hash,
            }),
            "{id}: the effect names its family and its op"
        );
    }

    // IDENTITY ROTATION: the op is what distinguishes a park from a promote, and
    // two effect stages can carry the same `contract_hash`, so the op MUST be in
    // the identity.
    let park = stage_id("park");
    let base = lower_stage_operation(&program, &park).expect("park lowers");
    let mut promoted = program.clone();
    promoted
        .stages
        .get_mut(&park)
        .expect("the park stage is present")
        .workspace_effect_op = Some(WorkspaceEffectOp::Promote);
    assert_ne!(
        base.contract.id(),
        lower_stage_operation(&promoted, &park)
            .expect("promote lowers")
            .contract
            .id(),
        "a different workspace mutation must be a different operation"
    );
}

/// 12 — the effect arm FAILS CLOSED. A stage whose resolved executor is the
/// workspace-effect backend but whose checked stage carries no typed op is
/// refused, rather than recovered by parsing the synthesized directive prompt.
#[test]
fn an_effect_stage_with_no_typed_op_is_refused() {
    let mut program = pack("smoke/workspace-effect-smoke.star");
    let park = stage_id("park");
    // The directive prompt still says `park` — which is exactly the string this
    // lowerer must refuse to read.
    assert!(
        program.stages[&park]
            .op
            .prompt_template
            .contains("\"op\":\"park\""),
        "the premise: the op is still recoverable from the prompt, and must not be \
         recovered from it — prompt is {:?}",
        program.stages[&park].op.prompt_template
    );
    program
        .stages
        .get_mut(&park)
        .expect("the park stage is present")
        .workspace_effect_op = None;
    assert_eq!(
        lower_stage_operation(&program, &park),
        Err(LoweringError::Refused(
            LoweringRefusal::WorkspaceEffectOpAbsent
        )),
        "an effect stage with no typed op must refuse"
    );
}

/// 13 — SELECT. Every `BranchRoute` of every shipped pack yields exactly one
/// program-level Select whose selector is a deterministic function of the route's
/// canonical content, distinct per route, and whose path is past every stage
/// path.
#[test]
fn every_branch_route_lowers_to_exactly_one_select() {
    let mut packs_with_routes = 0usize;
    let mut routes_seen = 0usize;
    for (path, program) in compiled_corpus() {
        if program.branch_routes.is_empty() {
            continue;
        }
        let name = path.display().to_string();
        let report = lower_program_operations(&program);
        assert_eq!(
            report.selects.len(),
            program.branch_routes.len(),
            "{name}: one Select per route"
        );
        let mut selectors = BTreeSet::new();
        for (index, route) in program.branch_routes.iter().enumerate() {
            let lowered = lower_branch_route(&program, index).expect("a shipped route lowers");
            assert_eq!(
                lowered.contract.source_stage, route.condition_stage,
                "{name}: a Select's source stage is the route's condition stage"
            );
            assert_eq!(
                lowered.contract.operation,
                RuntimeOperation::Select {
                    selector: branch_route_selector(route)
                },
                "{name}: the selector is the route's canonical content hash"
            );
            assert_eq!(
                lowered.path,
                OperationPath(vec![
                    u32::try_from(program.stages.len() + index).expect("small program")
                ]),
                "{name}: a route's path is stage_count + route_index"
            );
            assert!(
                !program
                    .stages
                    .keys()
                    .enumerate()
                    .any(|(stage_index, _)| OperationPath(vec![
                        u32::try_from(stage_index).expect("small program")
                    ]) == lowered.path),
                "{name}: a route path must be distinct from every stage path"
            );
            selectors.insert(branch_route_selector(route).to_string());
            routes_seen += 1;
        }
        assert_eq!(
            selectors.len(),
            program.branch_routes.len(),
            "{name}: two routes must not share a selector"
        );
        packs_with_routes += 1;
    }
    assert!(
        packs_with_routes >= 3 && routes_seen >= 3,
        "the corpus must still exercise branch(): {packs_with_routes} packs, {routes_seen} routes"
    );
}

/// 14 — SELECTOR ROTATION. The selector is a function of the route's content, so
/// re-targeting an arm rotates it — the property that makes a Select a checkable
/// statement about routing rather than a label. Mutated on the COMPILED program,
/// so the rotation is observed over the checked IR and not over source text.
#[test]
fn a_retargeted_branch_arm_rotates_the_selector() {
    let program = pack("examples/branch-routing.star");
    assert_eq!(
        program.branch_routes.len(),
        1,
        "branch-routing authors exactly one route"
    );
    let base = lower_branch_route(&program, 0).expect("the route lowers");

    let mut retargeted = program.clone();
    let route = &mut retargeted.branch_routes[0];
    let arm = route.arms.first().expect("a route has arms").clone();
    route.arms[0] = BranchArm {
        tag: arm.tag.clone(),
        targets: vec![stage_id("classify")],
    };
    let moved = lower_branch_route(&retargeted, 0).expect("the route still lowers");
    assert_ne!(
        base.contract.operation, moved.contract.operation,
        "a re-targeted arm must rotate the selector"
    );
    assert_ne!(
        base.contract.id(),
        moved.contract.id(),
        "a rotated selector must rotate the operation identity"
    );

    // A re-TAGGED arm rotates it too, and so does an added arm.
    let mut retagged = program.clone();
    retagged.branch_routes[0].arms[0].tag = smol_str::SmolStr::new("shipp");
    assert_ne!(
        base.contract.operation,
        lower_branch_route(&retagged, 0)
            .expect("it lowers")
            .contract
            .operation,
        "a re-tagged arm must rotate the selector"
    );

    // And the verdict FIELD the route reads is part of it.
    let mut refielded = program.clone();
    refielded.branch_routes[0].verdict_field = smol_str::SmolStr::new("other");
    assert_ne!(
        base.contract.operation,
        lower_branch_route(&refielded, 0)
            .expect("it lowers")
            .contract
            .operation,
        "the verdict field is part of the selector"
    );
}

/// 15 — the Select arm FAILS CLOSED. A route whose condition stage names no stage
/// in the program is refused rather than lowered against a stage that does not
/// exist.
#[test]
fn a_route_whose_condition_stage_is_absent_is_refused() {
    let mut program = pack("examples/branch-routing.star");
    program.branch_routes[0].condition_stage = stage_id("no_such_stage");
    assert_eq!(
        lower_branch_route(&program, 0),
        Err(LoweringError::Refused(
            LoweringRefusal::SelectConditionUnknown
        )),
        "a route must not claim provenance over an absent condition stage"
    );
    let report = lower_program_operations(&program);
    assert!(
        report.selects.is_empty(),
        "the refused route must not appear as a Select"
    );
    assert_eq!(
        report
            .refused_selects
            .iter()
            .map(|entry| entry.refusal)
            .collect::<Vec<_>>(),
        vec![LoweringRefusal::SelectConditionUnknown],
        "and it must appear, by name, in the refused route list"
    );
}

/// 16 — PATH MINTING refuses instead of panicking. The flat coordinate is a `u32`
/// and a coordinate that does not fit is a named refusal, not an `expect` that
/// aborts the process mid-lowering.
#[test]
fn a_path_coordinate_past_u32_is_refused() {
    assert_eq!(operation_path_at(0), Ok(OperationPath(vec![0])));
    assert_eq!(
        operation_path_at(usize::from(u16::MAX)),
        Ok(OperationPath(vec![u32::from(u16::MAX)]))
    );
    let past = usize::try_from(u64::from(u32::MAX) + 1).expect("64-bit host");
    assert_eq!(
        operation_path_at(past),
        Err(LoweringRefusal::PathCoordinateOverflow),
        "a coordinate past u32 must be refused by name"
    );
}

/// 17 — AGENT. An agent stage lowers to [`ActionExecutor::Agent`] carrying its
/// AUTHORED drivers: the ordered `op.agent_panel` verbatim when there is one, else
/// the single `op.agent_label`. Read off the checked IR's literal fields on one
/// side and off the lowered contract on the other, over the whole shipped corpus,
/// so neither side is the other's mirror.
#[test]
fn an_agent_stage_lowers_to_the_agent_executor_with_its_authored_drivers() {
    let mut agent_operations = 0usize;
    let mut distinct_drivers = BTreeSet::new();
    for (path, program) in compiled_corpus() {
        let name = path.display().to_string();
        for stage_id in program.stages.keys() {
            let Expected::Agent(authored) =
                expected_for(&corpus_key(&path), &program, stage_id, program.stages.len())
            else {
                continue;
            };
            let lowered = lower_stage_operation(&program, stage_id)
                .unwrap_or_else(|e| panic!("{name}: {stage_id:?} must lower as an agent: {e:?}"));
            assert_eq!(
                lowered.contract.operation,
                RuntimeOperation::Execute(kata_types::execution_contract::ExecuteOperation {
                    executor: ActionExecutor::Agent {
                        drivers: authored.clone(),
                    },
                    contract_hash: program.stages[stage_id].contract_hash,
                }),
                "{name}: {stage_id:?} must carry exactly its authored drivers"
            );
            assert!(
                !authored.is_empty(),
                "{name}: {stage_id:?} — a lowered agent operation never claims an \
                 empty driver list"
            );
            distinct_drivers.insert(format!("{authored:?}"));
            agent_operations += 1;
        }
    }
    assert!(
        agent_operations >= 20 && distinct_drivers.len() >= 2,
        "the corpus must exercise the agent executor: {agent_operations} operations \
         over {} distinct driver lists",
        distinct_drivers.len()
    );

    // IDENTITY ROTATION: the driver list is semantic, so changing it moves the id
    // while `contract_hash` is untouched.
    let program = pack("std/self-review.star");
    let stage = stage_id("review");
    let base = lower_stage_operation(&program, &stage).expect("an agent stage lowers");
    let mut relabelled = program.clone();
    relabelled
        .stages
        .get_mut(&stage)
        .expect("the stage is present")
        .op
        .agent_label = Some(smol_str::SmolStr::new("some_other_driver"));
    assert_ne!(
        base.contract.id(),
        lower_stage_operation(&relabelled, &stage)
            .expect("it still lowers")
            .contract
            .id(),
        "a different driver must be a different operation"
    );
}

/// 18 — the AGENT arm FAILS CLOSED on the `any` selector. `agent_label == None`
/// names no driver at all: kata inherits the host's answer and refuses when there
/// is none, an operator default is not an IR fact, and `drivers: []` would be a
/// false claim that the operation names its own executor. No shipped pack authors
/// a bare `prompt=` stage without `agent=`, so the witness is inline.
#[test]
fn an_unbound_any_selector_refuses_rather_than_claiming_an_empty_driver_list() {
    let program = inline(
        "p = stage(id = \"p\", prompt = \"do a thing\")\n\
         workflow(\"unbound\", root = [p])\n",
        "unbound.star",
    );
    let unbound = stage_id("p");
    // The literal IR facts this claim is about: no routing label, and no panel.
    assert_eq!(
        program.stages[&unbound].op.agent_label, None,
        "the premise: the `any` selector binds no routing label"
    );
    assert!(
        program.stages[&unbound].op.agent_panel.is_empty(),
        "the premise: there is no panel to fall back on either"
    );
    assert_eq!(
        lower_stage_operation(&program, &unbound),
        Err(LoweringError::Refused(
            LoweringRefusal::AgentSelectorUnbound
        )),
        "an unbound selector must refuse by name"
    );

    // And nothing anywhere in the corpus lowers to an EMPTY driver list — the
    // false positive this arm exists to prevent.
    for (path, program) in compiled_corpus() {
        let report = lower_program_operations(&program);
        for entry in &report.lowered {
            if let Expected::Agent(drivers) = actual_for(&program, &entry.stage) {
                assert!(
                    !drivers.is_empty(),
                    "{}: {:?} lowered to an agent with no drivers",
                    path.display(),
                    entry.stage
                );
            }
        }
    }
}

/// 19 — PANEL. An authored fallback panel lowers to the ORDERED driver list
/// verbatim, and the order is semantic: `try-A-then-B` is not `try-B-then-A`, so
/// rotating the panel rotates the operation id. The rotation is observed on a
/// MUTATED COMPILED PROGRAM with `contract_hash` untouched, so it is attributable
/// to the drivers and to nothing else.
#[test]
fn a_panel_lowers_to_ordered_drivers_and_reordering_rotates_the_operation_id() {
    let program = inline(
        "p = stage(id = \"p\", prompt = \"x\", agent = [\"claude_code\", \"codex\"])\n\
         workflow(\"panel\", root = [p])\n",
        "panel.star",
    );
    let panel = stage_id("p");
    assert_eq!(
        program.stages[&panel]
            .op
            .agent_panel
            .iter()
            .map(smol_str::SmolStr::as_str)
            .collect::<Vec<_>>(),
        vec!["claude_code", "codex"],
        "the literal IR fact this claim is about"
    );
    let base = lower_stage_operation(&program, &panel).expect("a panel stage lowers");
    assert_eq!(
        base.contract.operation,
        RuntimeOperation::Execute(kata_types::execution_contract::ExecuteOperation {
            executor: ActionExecutor::Agent {
                drivers: vec![
                    smol_str::SmolStr::new("claude_code"),
                    smol_str::SmolStr::new("codex"),
                ],
            },
            contract_hash: program.stages[&panel].contract_hash,
        }),
        "the panel is the ordered driver list, primary first"
    );

    let mut rotated = program.clone();
    let stage = rotated
        .stages
        .get_mut(&panel)
        .expect("the panel stage is present");
    stage.op.agent_panel.reverse();
    // The primary IS the routing label, so rotating the panel moves both.
    stage.op.agent_label = stage.op.agent_panel.first().cloned();
    let moved = lower_stage_operation(&rotated, &panel).expect("the rotated panel lowers");
    assert_eq!(
        moved.contract.operation,
        RuntimeOperation::Execute(kata_types::execution_contract::ExecuteOperation {
            executor: ActionExecutor::Agent {
                drivers: vec![
                    smol_str::SmolStr::new("codex"),
                    smol_str::SmolStr::new("claude_code"),
                ],
            },
            contract_hash: program.stages[&panel].contract_hash,
        }),
        "the rotated panel is the rotated driver list"
    );
    assert_ne!(
        base.contract.id(),
        moved.contract.id(),
        "an ordered fallback list is ordered: rotating it must rotate the identity"
    );
}

/// 20 — EXPANSION. Each `ReviewLoop` lowers to exactly one
/// [`RuntimeOperation::ExpandBounded`] whose `template` is the coordinates of the
/// loop's `effective_body_stages()` IN ORDER followed by its reviewer gate, whose
/// `maximum` is the authored `max_iterations`, and whose `policy_hash` is the
/// loop's own policy selector. Asserted over every shipped loop pack, from
/// `program.review_loops` and `program.stages`' own order rather than from the
/// lowerer's walk.
#[test]
fn each_review_loop_lowers_to_one_expand_bounded_over_its_body_and_gate() {
    let mut loops_seen = 0usize;
    let mut packs_with_loops = 0usize;
    for (path, program) in compiled_corpus() {
        if program.review_loops.is_empty() {
            continue;
        }
        let name = path.display().to_string();
        let coordinates = stage_coordinates(&program);
        for (index, review_loop) in program.review_loops.iter().enumerate() {
            let members = template_members(review_loop);
            assert!(
                members.len() >= 2,
                "{name}: a loop's template is at least a body member and its gate"
            );
            // INDEPENDENT premise: does every template member exist and lower?
            // A refused member refuses the outer expansion (all-or-nothing). A
            // member that is itself an `ExpandBounded` — a static `topology`
            // stage inside the loop — LOWERS: each iteration
            // seats it at the member's own coordinate, so the loop's template
            // names it at its stage coordinate like any other member.
            let every_member_lowers = members.iter().all(|member| {
                program.stages.contains_key(member)
                    && !matches!(
                        expected_for(&corpus_key(&path), &program, member, program.stages.len()),
                        Expected::Refused(_)
                    )
            });
            let lowered = lower_review_loop(&program, index);
            if !every_member_lowers {
                assert_eq!(
                    lowered,
                    Err(LoweringError::Refused(
                        LoweringRefusal::ExpansionMemberRefused
                    )),
                    "{name}: loop {index} has a refused template member, so the whole \
                     expansion must refuse"
                );
                continue;
            }
            let lowered =
                lowered.unwrap_or_else(|e| panic!("{name}: loop {index} must lower: {e:?}"));
            let expected_template: Vec<OperationPath> = members
                .iter()
                .map(|member| OperationPath(vec![coordinates[member.0.as_str()]]))
                .collect();
            assert_eq!(
                lowered.contract.operation,
                RuntimeOperation::ExpandBounded {
                    template: expected_template,
                    maximum: review_loop.max_iterations,
                    policy_hash: loop_policy_selector(review_loop),
                },
                "{name}: loop {index} expands over its body then its gate"
            );
            // The expansion hangs off the WORKER stage — the authored name a
            // `loop()` declaration has.
            assert_eq!(
                lowered.contract.source_stage.0.as_str(),
                review_loop.worker_stage.as_str(),
                "{name}: loop {index} is sourced at its worker stage"
            );
            assert_eq!(
                lowered.source_map.authored_label.as_str(),
                review_loop.worker_stage.as_str(),
                "{name}: loop {index}'s authored label is its worker stage"
            );
            loops_seen += 1;
        }
        packs_with_loops += 1;
    }
    assert!(
        packs_with_loops >= 5 && loops_seen >= 5,
        "the corpus must still exercise loop(): {packs_with_loops} packs, {loops_seen} \
         lowered expansions"
    );

    // A loop index past the end of the loop list is a caller mistake, never a
    // refused construct — the same distinction `lower_branch_route` keeps.
    let hello = pack("examples/hello-workflow.star");
    assert!(hello.review_loops.is_empty());
    assert_eq!(
        lower_review_loop(&hello, 0),
        Err(LoweringError::UnknownLoop(0))
    );
}

/// 21 — there is no `loop_member` refusal arm, because loop-member stages ARE the
/// expansion template: each one lowers as the ordinary operation its own fields
/// name, and the expansion references their coordinates rather than replacing
/// them.
#[test]
fn loop_member_stages_now_lower_as_ordinary_operations() {
    let program = pack("smoke/multistage-loop-smoke.star");
    assert_eq!(program.review_loops.len(), 1);
    let members = template_members(&program.review_loops[0]);
    assert_eq!(
        members.iter().map(|m| m.0.as_str()).collect::<Vec<_>>(),
        vec!["stage_a", "stage_b", "controller"],
        "the literal IR fact this claim is about: body in order, then the gate"
    );
    for member in &members {
        let lowered = lower_stage_operation(&program, member)
            .unwrap_or_else(|e| panic!("{member:?} must lower as an ordinary stage: {e:?}"));
        assert_eq!(
            lowered.contract.operation,
            RuntimeOperation::Execute(kata_types::execution_contract::ExecuteOperation {
                executor: ActionExecutor::Command,
                contract_hash: program.stages[member].contract_hash,
            }),
            "{member:?}: a shell loop member is an ordinary command operation"
        );
    }
    let report = lower_program_operations(&program);
    for member in &members {
        assert!(
            report.lowered.iter().any(|entry| &entry.stage == member),
            "{member:?} must appear in the LOWERED list, not the refused one; \
             refusals are {:?}",
            refusals(&report)
        );
    }
    assert_eq!(
        report.expansions.len(),
        1,
        "and the loop itself is the one expansion"
    );
}

/// One named single-field mutation of a review loop's policy.
type LoopMutation = Box<dyn Fn(&mut kata_types::review_loop::ReviewLoop)>;

/// 22 — the POLICY is part of the expansion identity. Two loops differing only in
/// a policy field the template and the maximum cannot see — the exhaustion action,
/// a walk-away bound, the rollover window — are different operations. Mutated on
/// the COMPILED program so the rotation is attributable to the policy alone.
#[test]
fn two_loops_differing_only_in_on_exhaustion_or_bounds_get_different_operation_ids() {
    let program = pack("smoke/review-loop-smoke.star");
    assert_eq!(program.review_loops.len(), 1);
    let base = lower_review_loop(&program, 0).expect("the loop lowers");
    let base_template = match &base.contract.operation {
        RuntimeOperation::ExpandBounded {
            template, maximum, ..
        } => (template.clone(), *maximum),
        other => panic!("a lowered loop is an expansion, got {other:?}"),
    };

    let variants: Vec<(&str, LoopMutation)> = vec![
        (
            "on_exhaustion",
            Box::new(|l: &mut kata_types::review_loop::ReviewLoop| {
                l.on_max = kata_types::review_loop::OnMaxAction::Accept;
            }),
        ),
        (
            "bounds",
            Box::new(|l: &mut kata_types::review_loop::ReviewLoop| {
                l.bounds = vec![kata_types::bound::Bound::time(60_000).expect("positive ms")];
            }),
        ),
        (
            "rollover",
            Box::new(|l: &mut kata_types::review_loop::ReviewLoop| {
                l.rollover_after_iterations = Some(7);
            }),
        ),
    ];
    let mut ids = BTreeSet::new();
    ids.insert(base.contract.id().0.to_string());
    for (label, mutate) in variants {
        let mut moved = program.clone();
        mutate(&mut moved.review_loops[0]);
        let lowered = lower_review_loop(&moved, 0).expect("the mutated loop still lowers");
        assert_eq!(
            match &lowered.contract.operation {
                RuntimeOperation::ExpandBounded {
                    template, maximum, ..
                } => (template.clone(), *maximum),
                other => panic!("{other:?}"),
            },
            base_template,
            "{label}: the premise — the template and the maximum are unchanged, so \
             only the policy can move the id"
        );
        assert_ne!(
            base.contract.id(),
            lowered.contract.id(),
            "{label}: a different loop policy must be a different operation"
        );
        ids.insert(lowered.contract.id().0.to_string());
    }
    assert_eq!(
        ids.len(),
        4,
        "each policy variant is its own operation: {ids:?}"
    );
}

/// 23 — the EXPANSION is ALL-OR-NOTHING. A loop one of whose template members the
/// lowering refuses refuses as [`LoweringRefusal::ExpansionMemberRefused`] rather
/// than expanding over the members that happen to lower: an expansion over a
/// subset of the body is a DIFFERENT loop wearing the same identity.
#[test]
fn an_expansion_over_a_refused_member_refuses_rather_than_half_lowering() {
    let mut program = pack("smoke/multistage-loop-smoke.star");
    let body_entry = program.review_loops[0]
        .effective_body_stages()
        .first()
        .expect("the loop has a body")
        .clone();
    assert!(
        lower_review_loop(&program, 0).is_ok(),
        "the premise: the loop lowers before the member is spoiled"
    );
    // Turn ONE body member into a construct the lowering refuses (a panel naming
    // a deterministic executor), leaving every other member lowering.
    program
        .stages
        .get_mut(&body_entry)
        .expect("the body member is present")
        .op
        .agent_panel = vec![smol_str::SmolStr::new("shell")];
    assert_eq!(
        lower_stage_operation(&program, &body_entry),
        Err(LoweringError::Refused(
            LoweringRefusal::PanelOnDeterministicExecutor
        )),
        "the premise: the member is refused"
    );
    assert_eq!(
        lower_review_loop(&program, 0),
        Err(LoweringError::Refused(
            LoweringRefusal::ExpansionMemberRefused
        )),
        "an expansion over a refused member must refuse, not narrow itself"
    );
    let report = lower_program_operations(&program);
    assert!(report.expansions.is_empty());
    assert_eq!(
        report
            .refused_expansions
            .iter()
            .map(|entry| entry.refusal)
            .collect::<Vec<_>>(),
        vec![LoweringRefusal::ExpansionMemberRefused],
        "and it must appear, by name, in the refused expansion list"
    );

    // A template member that names NO stage at all is the same refusal.
    let mut dangling = pack("smoke/multistage-loop-smoke.star");
    dangling.review_loops[0].body_stages = vec![stage_id("no_such_stage"), body_entry];
    assert_eq!(
        lower_review_loop(&dangling, 0),
        Err(LoweringError::Refused(
            LoweringRefusal::ExpansionMemberRefused
        )),
        "an expansion over an absent member must refuse"
    );
}

/// 24 — THE ITERATION RULE, pinned over [`OperationPath::child`] itself. The
/// occurrence of template member `m` in iteration `N` of an expansion at
/// `expand_path` is `expand_path.child(N).child(m)` — for EVERY `N` INCLUDING 0.
/// Iteration 0 is a child coordinate like any other and is deliberately NOT the
/// bare expansion path, so no iteration's occurrence can ever alias the expansion
/// operation that owns it. This test is the statement of the rule the expansion
/// runtime follows.
#[test]
fn an_iteration_is_a_child_coordinate_of_the_expansion_path() {
    let program = pack("smoke/multistage-loop-smoke.star");
    let expansion = lower_review_loop(&program, 0).expect("the loop lowers");
    let template_len = match &expansion.contract.operation {
        RuntimeOperation::ExpandBounded { template, .. } => template.len(),
        other => panic!("a lowered loop is an expansion, got {other:?}"),
    };
    let expand_path = expansion.path.clone();

    let mut minted = BTreeSet::new();
    for iteration in 0..program.review_loops[0].max_iterations {
        for member in 0..u32::try_from(template_len).expect("a small template") {
            let occurrence = expand_path.child(iteration).child(member);
            assert_eq!(
                occurrence.0.len(),
                expand_path.0.len() + 2,
                "an iteration's member path is two coordinates deeper than the expansion"
            );
            assert_eq!(
                occurrence.0[..expand_path.0.len()],
                expand_path.0[..],
                "and it extends the expansion path rather than replacing it"
            );
            assert_ne!(
                occurrence, expand_path,
                "no iteration's occurrence is the expansion's own path"
            );
            assert!(
                minted.insert(occurrence.clone()),
                "every (iteration, member) pair is its own coordinate: {occurrence:?} repeated"
            );
        }
    }
    assert_eq!(
        minted.len(),
        template_len * usize::try_from(program.review_loops[0].max_iterations).expect("small"),
        "one coordinate per (iteration, member)"
    );
    // Iteration 0 is a CHILD, not the bare path — the aliasing this rule forbids.
    assert_ne!(
        expand_path.child(0),
        expand_path,
        "iteration 0 is a child coordinate like any other"
    );
    assert!(
        minted.contains(&expand_path.child(0).child(0)),
        "and it is among the minted coordinates"
    );
}

/// 25 — AUTHORING PROVENANCE. Every lowered operation's source map carries the
/// span of the stage it came from, read off `ExecutionProgramStage::authored_span`
/// on one side and off the `OperationSourceMap` on the other. A `Select` carries
/// its route's CONDITION stage's span and an `ExpandBounded` its loop's WORKER
/// stage's span — the same stage each one already names as its `source_stage`, so
/// the span and the provenance claim cannot disagree.
///
/// Also asserted, over every span the corpus produces: `file` is a BASENAME. The
/// locked authoring rule is that a content-hashed IR may not name a machine's
/// facts, and an absolute path is exactly such a fact; checking it HERE, on the
/// far side of the lowerer, proves no host path reached a typed operation
/// whatever the frontend did.
#[test]
fn every_source_map_carries_its_authored_stage_span() {
    let mut spans_seen = 0usize;
    let mut packs_with_spans = 0usize;
    for (path, program) in compiled_corpus() {
        let name = path.display().to_string();
        let mut pack_spans = 0usize;

        let span_of = |stage_id: &StageId| program.stages[stage_id].authored_span.clone();

        for stage_id in program.stages.keys() {
            let Ok(lowered) = lower_stage_operation(&program, stage_id) else {
                continue;
            };
            assert_eq!(
                lowered.source_map.span,
                span_of(stage_id),
                "{name}: {stage_id:?} — the source map must carry the stage's own \
                 authored span"
            );
            if lowered.source_map.span.is_some() {
                pack_spans += 1;
            }
        }

        for (index, route) in program.branch_routes.iter().enumerate() {
            let lowered = lower_branch_route(&program, index).expect("a shipped route lowers");
            assert_eq!(
                lowered.source_map.span,
                span_of(&route.condition_stage),
                "{name}: route {index} must carry its CONDITION stage's span"
            );
            assert_eq!(
                lowered.source_map.stage, route.condition_stage,
                "{name}: and name that same stage as its provenance"
            );
        }

        for (index, review_loop) in program.review_loops.iter().enumerate() {
            let Ok(lowered) = lower_review_loop(&program, index) else {
                continue;
            };
            let worker = StageId(review_loop.worker_stage.clone());
            assert_eq!(
                lowered.source_map.span,
                span_of(&worker),
                "{name}: loop {index} must carry its WORKER stage's span"
            );
            assert_eq!(
                lowered.source_map.stage, worker,
                "{name}: and name that same stage as its provenance"
            );
        }

        // No host path may reach a typed operation. Asserted on every span this
        // pack's operations carry, not only on the stage ones.
        for stage_id in program.stages.keys() {
            if let Ok(lowered) = lower_stage_operation(&program, stage_id)
                && let Some(span) = &lowered.source_map.span
            {
                assert!(
                    !span.file.contains('/'),
                    "{name}: {stage_id:?} — a span's file must be a BASENAME, got {:?}",
                    span.file
                );
                assert!(
                    span.line >= 1 && span.column >= 1,
                    "{name}: {stage_id:?} — a span is 1-based, got {span}"
                );
            }
        }

        spans_seen += pack_spans;
        if pack_spans > 0 {
            packs_with_spans += 1;
        }
    }
    assert!(
        spans_seen >= 100 && packs_with_spans >= PACK_FLOOR,
        "the corpus must carry authored spans into the typed operations: \
         {spans_seen} spans over {packs_with_spans} packs"
    );
}

/// 26 — a span is PROVENANCE, not contract material. Moving a stage's authored
/// span — what a whitespace-only re-indent of a pack does — moves the source map
/// and rotates NO operation id, so re-formatting a pack cannot invalidate a cached
/// result. The checked IR keeps `authored_span` out of `contract_hash` for the
/// same reason; this is the same claim one layer up, asserted at the typed
/// operation rather than at the stage.
#[test]
fn moving_an_authored_span_moves_the_source_map_and_no_operation_id() {
    let program = pack("examples/hello-workflow.star");
    let stage_id = program
        .stages
        .keys()
        .find(|id| lower_stage_operation(&program, id).is_ok())
        .expect("hello-workflow lowers a stage")
        .clone();
    let base = lower_stage_operation(&program, &stage_id).expect("the stage lowers");
    assert!(
        base.source_map.span.is_some(),
        "the premise: this stage carries an authored span"
    );

    let mut reindented = program.clone();
    reindented
        .stages
        .get_mut(&stage_id)
        .expect("the stage is present")
        .authored_span = Some(kata_types::source::SourceSpan {
        file: "hello-workflow.star".to_string(),
        line: 999,
        column: 7,
    });
    let moved = lower_stage_operation(&reindented, &stage_id).expect("it still lowers");

    assert_ne!(
        base.source_map.span, moved.source_map.span,
        "the premise: the span really moved"
    );
    assert_eq!(
        base.contract.id(),
        moved.contract.id(),
        "a moved span must rotate NO operation identity"
    );
    assert_eq!(
        occurrence_for(&program, execution(6), &base).id(),
        occurrence_for(&reindented, execution(6), &moved).id(),
        "nor any occurrence identity"
    );
}

/// 27 — A PANEL IS AGENT-ONLY, refused at AUTHORING. An agent fallback panel
/// advances to the next member on a backend/spawn failure; a DETERMINISTIC member
/// (`shell`, `workspace_effect`) is a command executor, which lowers to
/// [`ActionExecutor::Command`] / `Effect` and carries no driver list at all. So
/// `agent = ["shell", "codex"]` would lower to a `Command` that says nothing about
/// codex while the dispatcher's panel advance would still re-dispatch to codex —
/// an identity NARROWER than the mechanism, which is this codebase's costliest
/// recurring defect. The authoring surface refuses it outright.
#[test]
fn a_panel_naming_a_deterministic_executor_is_refused_at_authoring() {
    // ANY member, not just the primary: the advance reaches every one of them.
    for source in [
        "p = stage(id = \"p\", run = \":\", agent = [\"shell\", \"codex\"])\n\
         workflow(\"panel\", root = [p])\n",
        "p = stage(id = \"p\", prompt = \"x\", agent = [\"codex\", \"shell\"])\n\
         workflow(\"panel\", root = [p])\n",
        "p = stage(id = \"p\", prompt = \"x\", agent = [\"codex\", \"workspace_effect\"])\n\
         workflow(\"panel\", root = [p])\n",
    ] {
        let error = compile_starlark_execution_program(source, "panel.star", &[])
            .expect_err("a panel naming a deterministic executor must not compile");
        let rendered = format!("{error}");
        assert!(
            rendered.contains("panel") && rendered.contains("shell"),
            "the refusal must name the construct and the reserved labels, got {rendered:?}"
        );
    }

    // And the refused set is NOT wider than that: an all-agent panel still
    // compiles, and a SCALAR deterministic agent is untouched.
    let panel = inline(
        "p = stage(id = \"p\", prompt = \"x\", agent = [\"claude_code\", \"codex\"])\n\
         workflow(\"panel\", root = [p])\n",
        "ok-panel.star",
    );
    assert_eq!(panel.stages[&stage_id("p")].op.agent_panel.len(), 2);
    let shell = inline(
        "s = stage(id = \"s\", run = \":\", agent = \"shell\")\n\
         workflow(\"shell\", root = [s])\n",
        "ok-shell.star",
    );
    assert!(shell.stages[&stage_id("s")].op.agent_panel.is_empty());
}

/// 28 — and the lowerer refuses it too, so a DECODED or hand-built program cannot
/// bypass the authoring check. Checked over ANY member: a panel whose primary is
/// an agent but whose fallback is `shell` is exactly the case the authoring
/// refusal exists for, and it is the one a decoded program can still present.
#[test]
fn a_decoded_panel_naming_a_deterministic_executor_is_refused_by_the_lowerer() {
    let base = inline(
        "p = stage(id = \"p\", prompt = \"x\", agent = [\"claude_code\", \"codex\"])\n\
         workflow(\"panel\", root = [p])\n",
        "panel.star",
    );
    let panel = stage_id("p");
    assert!(
        lower_stage_operation(&base, &panel).is_ok(),
        "the premise: an all-agent panel lowers"
    );

    // A deterministic FALLBACK — primary untouched, so the routing label still
    // resolves to an agent backend and only the panel membership is wrong.
    let mut fallback = base.clone();
    fallback
        .stages
        .get_mut(&panel)
        .expect("the panel stage is present")
        .op
        .agent_panel = vec![
        smol_str::SmolStr::new("claude_code"),
        smol_str::SmolStr::new("shell"),
    ];
    assert_eq!(
        lower_stage_operation(&fallback, &panel),
        Err(LoweringError::Refused(
            LoweringRefusal::PanelOnDeterministicExecutor
        )),
        "a deterministic panel member must refuse, whatever the primary is"
    );

    // A deterministic PRIMARY: the case that would otherwise lower to a Command
    // and silently drop the fallbacks.
    let mut primary = base.clone();
    let stage = primary
        .stages
        .get_mut(&panel)
        .expect("the panel stage is present");
    stage.op.agent_panel = vec![
        smol_str::SmolStr::new("shell"),
        smol_str::SmolStr::new("codex"),
    ];
    stage.op.agent_label = Some(smol_str::SmolStr::new("shell"));
    stage.op.agent = smol_str::SmolStr::new("shell");
    assert_eq!(
        lower_stage_operation(&primary, &panel),
        Err(LoweringError::Refused(
            LoweringRefusal::PanelOnDeterministicExecutor
        )),
        "a deterministic primary must refuse rather than lower to a Command that \
         drops the fallbacks"
    );

    // `workspace_effect` is the other reserved label, and it is refused too.
    let mut effect = base.clone();
    effect
        .stages
        .get_mut(&panel)
        .expect("the panel stage is present")
        .op
        .agent_panel = vec![
        smol_str::SmolStr::new("claude_code"),
        smol_str::SmolStr::new("workspace_effect"),
    ];
    assert_eq!(
        lower_stage_operation(&effect, &panel),
        Err(LoweringError::Refused(
            LoweringRefusal::PanelOnDeterministicExecutor
        ))
    );
}

/// A blocking request as the checked IR carries it, targeting `stage`.
fn blocking_request(index: u32, id: &str, stage: &str) -> ExecutionHumanRequest {
    ExecutionHumanRequest {
        index,
        id: smol_str::SmolStr::new(id),
        stage: Some(stage_id(stage)),
        priority: smol_str::SmolStr::new("high"),
        question: format!("{id}?"),
        default_assumption: "proceed".to_owned(),
        context: None,
        blocking: true,
        timeout_ms: Some(1_000),
    }
}

/// A BLOCKING human request lowers to ONE PROGRAM-LEVEL
/// `Wait(Input)` in the FOURTH flat segment (`stages ++ routes ++ loops ++
/// blocking_requests`), whose `request` is the selector over the request's literal
/// fields, whose source stage is its target, and which [`program_operation_at`] maps
/// back to it — while a non-blocking request is no operation at all. The identity
/// tracks the authored default and ignores the request's queue index.
///
/// **Would red if:** the blocking arm still refused its target (the target would be in
/// `refused`), or the segment were counted from the loops' start (the input would
/// alias the loop's path, and the inverse would answer `Expansion`).
#[test]
fn a_blocking_request_lowers_to_one_program_level_input_wait() {
    // A pack with a route-free loop so the fourth segment starts after a non-empty third.
    let mut program = pack("examples/code-review-loop.star");
    assert!(
        !program.review_loops.is_empty(),
        "the premise: a pack with a loop, so the segment boundary is exercised"
    );
    let target = program.stages.keys().next().expect("a stage").0.to_string();
    let mut advisory = blocking_request(0, "advisory_q", &target);
    advisory.blocking = false;
    advisory.timeout_ms = None;
    program.human_request_queue.requests = vec![
        advisory,
        blocking_request(1, "first_q", &target),
        blocking_request(2, "second_q", &target),
    ];
    let segment = program.stages.len() + program.branch_routes.len() + program.review_loops.len();

    let report = lower_program_operations(&program);
    // v6: a static `topology` stage lowers to `expand_bounded` at its own
    // stage coordinate and `child_invocation` narrows to `dynamic_fanout`.
    assert_eq!(
        report.schema_version,
        kata_program::execution_program::OPERATION_LOWERING_SCHEMA_VERSION
    );
    assert!(
        !report.refused.iter().any(|entry| entry.stage.0 == target),
        "a blocking request no longer refuses its target: {:?}",
        report.refused
    );
    assert_eq!(
        report
            .inputs
            .iter()
            .map(|input| (input.request.as_str(), input.path.clone()))
            .collect::<Vec<_>>(),
        [
            (
                "first_q",
                OperationPath(vec![u32::try_from(segment).unwrap()])
            ),
            (
                "second_q",
                OperationPath(vec![u32::try_from(segment + 1).unwrap()])
            ),
        ],
        "the advisory request is no input; the blocking ones follow queue order"
    );
    assert!(report.refused_inputs.is_empty());

    let lowered = lower_blocking_request(&program, 0).expect("the first input lowers");
    let request = &program.human_request_queue.requests[1];
    let literal = input_request_selector(InputRequestFields {
        id: "first_q",
        stage: Some(target.as_str()),
        question: "first_q?",
        default_assumption: "proceed",
        timeout_ms: Some(1_000),
        priority: "high",
        context: None,
    });
    assert_eq!(
        lowered.contract.operation,
        RuntimeOperation::Wait(WaitOperation::Input { request: literal })
    );
    assert_eq!(lowered.contract.source_stage.0, target);
    assert_eq!(lowered.source_map.authored_label, request.id);
    assert_eq!(
        report.inputs[0].selector,
        literal.to_string(),
        "the report reads the selector off the contract"
    );
    assert_eq!(
        lower_blocking_request(&program, 2),
        Err(LoweringError::UnknownInput(2)),
        "an index past the blocking requests is a caller mistake, not a refusal"
    );

    // The one inverse over the three program-level segments.
    assert_eq!(
        program_operation_at(&program, &lowered.path),
        Some(ProgramOperationAt::Input(0))
    );
    assert_eq!(
        program_operation_at(
            &program,
            &OperationPath(vec![u32::try_from(segment - 1).unwrap()])
        ),
        Some(ProgramOperationAt::Expansion(ExpansionKind::ReviewLoop(
            program.review_loops.len() - 1
        )))
    );
    assert_eq!(
        program_operation_at(
            &program,
            &OperationPath(vec![u32::try_from(segment + 2).unwrap()])
        ),
        None,
        "past the last input"
    );
    assert_eq!(
        program_operation_at(&program, &OperationPath(vec![0])),
        None,
        "a stage coordinate is no program-level operation"
    );

    // The authored default is identity; the queue index is not.
    let mut redefaulted = program.clone();
    redefaulted.human_request_queue.requests[1].default_assumption = "hold".to_owned();
    assert_ne!(
        lower_blocking_request(&redefaulted, 0)
            .unwrap()
            .contract
            .id(),
        lowered.contract.id(),
        "a changed default assumption rotates the wait's identity"
    );
    let mut reindexed = program.clone();
    reindexed.human_request_queue.requests[1].index = 7;
    assert_eq!(
        lower_blocking_request(&reindexed, 0).unwrap().contract.id(),
        lowered.contract.id(),
        "the queue index is not identity"
    );
}

/// A blocking request whose TARGET names no stage is refused `input_target_unknown`,
/// input-scoped: it refuses no stage, and its sibling still lowers.
#[test]
fn a_blocking_request_whose_target_is_absent_is_refused_input_scoped() {
    let mut program = pack("examples/durable-wait-signal.star");
    program
        .human_request_queue
        .requests
        .push(blocking_request(1, "ghost_q", "no_such_stage"));
    let report = lower_program_operations(&program);
    assert_eq!(
        report
            .refused_inputs
            .iter()
            .map(|entry| (entry.request.as_str(), entry.refusal))
            .collect::<Vec<_>>(),
        [("ghost_q", LoweringRefusal::InputTargetUnknown)]
    );
    assert_eq!(report.inputs.len(), 1, "proceed_q still lowers");
    assert!(report.refused.is_empty(), "no stage is refused for it");
    assert_eq!(
        lower_blocking_request(&program, 1),
        Err(LoweringError::Refused(LoweringRefusal::InputTargetUnknown))
    );
}

/// A stage shape as a HAND-WRITTEN fact about a shipped pack's source.
#[derive(Debug, Clone, Copy)]
enum Fact {
    /// A shell stage: `Execute { executor: Command }` — under `oci`, a capsule.
    Command,
    /// A `sleep(for_ms = N)`: `Wait(For { delay_ms: N })` — under `oci`, a main-side timer.
    SleepFor(u64),
    /// The `parallel()` barrier over the named branches, in order: `Join` — under `oci`,
    /// resolved main-side.
    Join(&'static [&'static str]),
    /// A `subworkflow(pack = P)`: `Invoke` naming the program the stage BOUND for `P` —
    /// under `oci`, a separate linked execution.
    Invoke(&'static str),
}

/// EVERY stage of every shipped wait/join/invoke smoke run under `oci`, and the shape each must
/// lower to, read off the pack SOURCE by hand — not computed from the IR, so the table
/// cannot agree with the lowerer by construction. Each listed pack's stages must be
/// exactly the ones listed here. An approval gate (`deploy`) and a content-cache stage
/// (`digest`) lower to the command they run: neither is an operation of its own.
const WAIT_SMOKE_STAGES: &[(&str, &[(&str, Fact)])] = &[
    (
        "smoke/join-outputs-smoke.star",
        &[
            ("left", Fact::Command),
            ("right", Fact::Command),
            ("__parallel_join_0", Fact::Join(&["left", "right"])),
            ("collector", Fact::Command),
        ],
    ),
    (
        "smoke/sleep-smoke.star",
        &[
            ("before", Fact::Command),
            ("nap", Fact::SleepFor(3000)),
            ("after", Fact::Command),
        ],
    ),
    (
        "smoke/subworkflow-parent-smoke.star",
        &[
            ("before", Fact::Command),
            ("sub", Fact::Invoke("subworkflow-child-smoke")),
            ("after", Fact::Command),
        ],
    ),
    (
        "smoke/subworkflow-child-smoke.star",
        &[("first", Fact::Command), ("second", Fact::Command)],
    ),
    (
        "smoke/capsule-reuse-smoke.star",
        &[("digest", Fact::Command)],
    ),
    (
        "examples/human-gate-approval.star",
        &[("prepare", Fact::Command), ("deploy", Fact::Command)],
    ),
    (
        "examples/durable-wait-signal.star",
        &[("decide", Fact::Command)],
    ),
    (
        "examples/durable-wait-timeout.star",
        &[("decide", Fact::Command)],
    ),
    (
        "smoke/branch-walkaway-smoke.star",
        &[
            ("decide", Fact::Command),
            ("first", Fact::Command),
            ("second", Fact::Command),
        ],
    ),
    (
        "examples/branch-routing.star",
        &[
            ("classify", Fact::Command),
            ("ship", Fact::Command),
            ("hold", Fact::Command),
        ],
    ),
];

/// Every `branch(on = …)` in the shipped branch smokes, by condition stage, read off the
/// source: each is ONE program-level `Select` at `stage_count + route_index`.
const WAIT_SMOKE_SELECTS: &[(&str, &[&str])] = &[
    ("smoke/branch-walkaway-smoke.star", &["decide"]),
    ("examples/branch-routing.star", &["classify"]),
];

/// Every BLOCKING `human_request(…)` in the shipped durable-wait packs, as
/// `(request id, target stage)` in queue order, read off the source: each is ONE
/// program-level `Wait(Input)` past the stage, route and loop segments.
const WAIT_SMOKE_INPUTS: &[(&str, &[(&str, &str)])] = &[
    (
        "examples/durable-wait-signal.star",
        &[("proceed_q", "decide")],
    ),
    (
        "examples/durable-wait-timeout.star",
        &[("proceed_q", "decide")],
    ),
];

/// The smoke rigs that exercise waits and child invocation lower to the
/// shapes the hand-written tables above say, and to nothing else: every stage, every
/// route, every blocking request, with their flat coordinates.
///
/// **Would red if:** a wait/join/invoke construct stopped lowering to its operation (a join run
/// as a command, a sleep refused, an `Invoke` naming another child, a gate or a cached
/// stage refused), a route or blocking request vanished from its segment, or one of the
/// packs gained or lost a stage without this table being re-read against its source.
#[test]
fn the_wait_smokes_lower_to_their_hand_written_shapes() {
    for (relative, stages) in WAIT_SMOKE_STAGES {
        let program = pack(relative);
        let listed: BTreeSet<&str> = stages.iter().map(|(stage, _)| *stage).collect();
        let actual: BTreeSet<&str> = program.stages.keys().map(|id| id.0.as_str()).collect();
        assert_eq!(
            listed, actual,
            "{relative}: the table lists exactly its stages"
        );
        let coordinates = stage_coordinates(&program);
        for (stage, fact) in *stages {
            let lowered = lower_stage_operation(&program, &stage_id(stage))
                .unwrap_or_else(|e| panic!("{relative}: {stage} must lower, got {e:?}"));
            match (fact, &lowered.contract.operation) {
                (Fact::Command, RuntimeOperation::Execute(execute))
                    if execute.executor == ActionExecutor::Command => {}
                (Fact::SleepFor(ms), RuntimeOperation::Wait(WaitOperation::For { delay_ms }))
                    if delay_ms == ms => {}
                (Fact::Join(inputs), RuntimeOperation::Join { inputs: joined }) => {
                    let expected: Vec<OperationPath> = inputs
                        .iter()
                        .map(|input| OperationPath(vec![coordinates[*input]]))
                        .collect();
                    assert_eq!(joined, &expected, "{relative}: {stage} joins its branches");
                }
                (Fact::Invoke(child), RuntimeOperation::Invoke { program: bound, .. }) => {
                    let spec = program.stages[&stage_id(stage)]
                        .subworkflow
                        .as_ref()
                        .expect("an Invoke stage is a subworkflow");
                    assert_eq!(spec.pack.as_str(), *child, "{relative}: {stage}'s pack");
                    assert_eq!(
                        *bound,
                        spec.bound.program_hash(),
                        "{relative}: {stage} names the program it bound for {child}"
                    );
                }
                (fact, operation) => {
                    panic!("{relative}: {stage} must lower to {fact:?}, got {operation:?}")
                }
            }
        }
    }

    for (relative, conditions) in WAIT_SMOKE_SELECTS {
        let program = pack(relative);
        let report = lower_program_operations(&program);
        assert_eq!(
            report
                .selects
                .iter()
                .map(|entry| entry.condition_stage.0.as_str())
                .collect::<Vec<_>>(),
            conditions.to_vec(),
            "{relative}: one Select per authored branch(), by condition stage"
        );
        for (index, entry) in report.selects.iter().enumerate() {
            assert_eq!(
                entry.path,
                OperationPath(vec![u32::try_from(program.stages.len() + index).unwrap()]),
                "{relative}: the Select sits in the second segment"
            );
        }
    }

    for (relative, requests) in WAIT_SMOKE_INPUTS {
        let program = pack(relative);
        let report = lower_program_operations(&program);
        assert!(report.refused_inputs.is_empty(), "{relative}: {report:?}");
        assert_eq!(
            report
                .inputs
                .iter()
                .map(|entry| (entry.request.as_str(), entry.target_stage.0.as_str()))
                .collect::<Vec<_>>(),
            requests.to_vec(),
            "{relative}: one input wait per blocking request, in queue order"
        );
        let segment =
            program.stages.len() + program.branch_routes.len() + program.review_loops.len();
        for (index, entry) in report.inputs.iter().enumerate() {
            assert_eq!(
                entry.path,
                OperationPath(vec![u32::try_from(segment + index).unwrap()]),
                "{relative}: the input wait sits in the fourth segment"
            );
            assert_eq!(
                program_operation_at(&program, &entry.path),
                Some(ProgramOperationAt::Input(index))
            );
        }
    }
}

/// 24 — an expansion MEMBER lowers as its own stage operation, reseated at a
/// CHILD coordinate of the expansion's path (`expand_path.child(N).child(m)`):
/// the contract is the member stage's own, and only the coordinate differs, so
/// the member's occurrence cannot alias the stage's bare-path one. The refused
/// set is exact: a non-expansion subject, a member past the template's end, and
/// any coordinate that is not a strict child of the expansion path ending in
/// `member`.
#[test]
fn an_expansion_member_lowers_at_a_child_coordinate_and_refuses_everything_else() {
    let program = pack("smoke/multistage-loop-smoke.star");
    let expansion = lower_review_loop(&program, 0).expect("the loop lowers");
    let RuntimeOperation::ExpandBounded { template, .. } = &expansion.contract.operation else {
        panic!("the loop lowers to ExpandBounded")
    };
    assert_eq!(template.len(), 3, "body sequence then gate");

    // Member 0 of iteration 0 — `stage_a` — seated at `expand.child(0).child(0)`:
    // the member's CONTRACT is stage_a's own; only the path is reseated.
    let coordinate = expansion.path.child(0).child(0);
    let member = lower_expansion_member(&program, &expansion, coordinate.clone(), 0)
        .expect("member 0 lowers");
    let stage_a = lower_stage_operation(&program, &stage_id("stage_a"))
        .expect("the member stage lowers on its own");
    assert_eq!(
        member.path, coordinate,
        "the member is reseated at the child"
    );
    assert_eq!(
        member.contract, stage_a.contract,
        "the member keeps its own stage contract — the iteration lives in the path, \
         never in the identity"
    );
    // And a deeper iteration coordinate works identically (member 1, iteration 7).
    let deep = expansion.path.child(7).child(1);
    let member_b = lower_expansion_member(&program, &expansion, deep.clone(), 1)
        .expect("member 1 at iteration 7 lowers");
    assert_eq!(member_b.path, deep);
    assert_eq!(
        member_b.contract.source_stage.0.as_str(),
        "stage_b",
        "template member 1 is stage_b"
    );

    // A member past the template's end is a caller mistake, not a refusal.
    assert_eq!(
        lower_expansion_member(&program, &expansion, expansion.path.child(0).child(9), 9),
        Err(LoweringError::UnknownMember(9))
    );
    // A subject carrying no ExpandBounded is a caller mistake.
    assert_eq!(
        lower_expansion_member(&program, &stage_a, stage_a.path.child(0), 0),
        Err(LoweringError::NotAnExpansion)
    );
    // Coordinates that are not a strict child of the expansion's path ending in
    // `member`: the expansion's own bare path, another subtree, and a child
    // ending in a DIFFERENT member index.
    for (coordinate, label) in [
        (expansion.path.clone(), "the expansion's own coordinate"),
        (
            OperationPath(vec![9, 0, 0]),
            "a coordinate outside the expansion",
        ),
        (
            expansion.path.child(0).child(1),
            "a child ending in another member index",
        ),
    ] {
        assert_eq!(
            lower_expansion_member(&program, &expansion, coordinate, 0),
            Err(LoweringError::NotAMemberCoordinate),
            "{label} must be refused"
        );
    }
}

/// 25 — TOPOLOGY EXPANSION + MEMBER. A static `topology(..)` stage's own
/// coordinate IS the expansion's: `lower_topology_expansion` lowers it to
/// `ExpandBounded` with `maximum = 1` and the template `path.child(m)` for
/// every member — member 0 the ROOT (the stage's own payload executor), member
/// `m` child `m - 1` under the synthetic `<base>#child-<role>` contract
/// identity. Asserted against the literal
/// envelope and the stage's literal routing label on one side and the lowered
/// contracts on the other.
#[test]
fn a_static_topology_expands_at_its_stage_coordinate_with_root_then_children() {
    let program = pack("std/kata-loop-lite.star");
    let index = program
        .stages
        .keys()
        .position(|id| id.0.as_str() == "research")
        .expect("research is a stage");
    let stage = &program.stages[&stage_id("research")];
    // The literal envelope facts this claim is about: two worker roles, in
    // authored order, each naming `agent = "default"`.
    let roles: Vec<&str> = stage
        .invocation_envelope
        .children
        .iter()
        .map(|child| child.role.as_str())
        .collect();
    assert_eq!(
        roles,
        ["codebase_researcher", "docs_researcher"],
        "the premise: the authored worker roles, in order"
    );

    let expansion = lower_topology_expansion(&program, index).expect("the topology expands");
    assert_eq!(
        expansion.path,
        OperationPath(vec![u32::try_from(index).expect("small program")]),
        "the expansion's path is the stage's own flat coordinate"
    );
    let RuntimeOperation::ExpandBounded {
        template,
        maximum,
        policy_hash,
    } = &expansion.contract.operation
    else {
        panic!("a static topology lowers to ExpandBounded")
    };
    assert_eq!(*maximum, 1, "a static topology runs its member set once");
    let expected_template: Vec<OperationPath> = (0..=roles.len())
        .map(|member| {
            expansion
                .path
                .child(u32::try_from(member).expect("small program"))
        })
        .collect();
    assert_eq!(
        *template, expected_template,
        "the template is the flat child coordinate of every member, in order"
    );
    assert_ne!(
        *policy_hash,
        kata_types::primitives::ContentHash::new([0; 32]),
        "the policy hash is the canonical envelope selector, never a zero filler"
    );

    // Member 0 is the ROOT: it runs the stage's own payload on the stage's own
    // routing label, stage-named exactly `research`.
    let root = lower_expansion_member(&program, &expansion, expansion.path.child(0), 0)
        .expect("member 0 lowers");
    assert_eq!(root.contract.source_stage, stage_id("research"));
    assert_eq!(root.path, expansion.path.child(0));
    assert_eq!(
        root.contract.operation,
        RuntimeOperation::Execute(kata_types::execution_contract::ExecuteOperation {
            executor: ActionExecutor::Agent {
                drivers: vec![smol_str::SmolStr::new(
                    stage
                        .op
                        .agent_label
                        .as_deref()
                        .expect("the stage's routing label is a literal field")
                )],
            },
            contract_hash: stage.contract_hash,
        }),
        "the root member executes the stage's own payload executor"
    );

    // Member `m` is child `m - 1`, stage-named `<base>#child-<role>` and
    // executing the role's `agent` label.
    for (member, &role) in roles.iter().enumerate() {
        let member_index = u32::try_from(member + 1).expect("small program");
        let child = lower_expansion_member(
            &program,
            &expansion,
            expansion.path.child(member_index),
            member_index,
        )
        .expect("a child member lowers");
        let expected_stage =
            kata_types::execution_contract::child_invocation_stage_name("research", role);
        assert_eq!(
            child.contract.source_stage.0.as_str(),
            expected_stage.as_str(),
            "the child's contract identity is the synthetic child stage name"
        );
        assert_eq!(child.path, expansion.path.child(member_index));
        assert_eq!(
            child.contract.operation,
            RuntimeOperation::Execute(kata_types::execution_contract::ExecuteOperation {
                executor: ActionExecutor::Agent {
                    drivers: vec![smol_str::SmolStr::new("default")],
                },
                contract_hash: stage.contract_hash,
            }),
            "the child executes its role's agent label"
        );
    }

    // A member past the template's end is a caller mistake; so is a stage
    // index past the stage list, and a non-topology stage index is the
    // expansion's refused arm.
    assert_eq!(
        lower_expansion_member(&program, &expansion, expansion.path.child(3), 3),
        Err(LoweringError::UnknownMember(3))
    );
    assert_eq!(
        lower_topology_expansion(&program, program.stages.len()),
        Err(LoweringError::UnknownStageIndex(program.stages.len()))
    );
    let ordinary = program
        .stages
        .keys()
        .position(|id| id.0.as_str() == "validate")
        .expect("validate is a stage");
    assert_eq!(
        lower_topology_expansion(&program, ordinary),
        Err(LoweringError::Refused(
            LoweringRefusal::ExpansionMemberRefused
        )),
        "a stage that plans no static topology refuses the expansion door"
    );

    // Coordinates that are not the flat child the template names: the
    // expansion's own bare path, a loop-shaped `child(0).child(0)`, a child of
    // a different member index, and a coordinate outside the expansion. The
    // loop-shaped one is refused by the all-or-nothing member arm — the
    // topology template entry is not a flat stage coordinate to re-seat.
    assert_eq!(
        lower_expansion_member(&program, &expansion, expansion.path.clone(), 0),
        Err(LoweringError::NotAMemberCoordinate),
        "the expansion's own coordinate is no member"
    );
    assert_eq!(
        lower_expansion_member(&program, &expansion, expansion.path.child(0).child(0), 0),
        Err(LoweringError::Refused(
            LoweringRefusal::ExpansionMemberRefused
        )),
        "a loop-shaped coordinate is not a topology member's own coordinate"
    );
    assert_eq!(
        lower_expansion_member(&program, &expansion, expansion.path.child(1), 0),
        Err(LoweringError::NotAMemberCoordinate),
        "a child ending in another member index is refused"
    );
    assert_eq!(
        lower_expansion_member(
            &program,
            &expansion,
            OperationPath(vec![u32::MAX - 1, 0]),
            0
        ),
        Err(LoweringError::NotAMemberCoordinate),
        "a coordinate outside the expansion is refused"
    );
}

/// 26 — REFUSAL NAMES. `LoweringRefusal::as_str` is the surface corpus
/// histograms and operator reports name a refusal through, so every variant's
/// stable snake_case is asserted verbatim — a variant silently renaming (or
/// naming `""`) folds every refusal under one wrong label. (Mutation survivor:
/// `as_str` returning `""`.)
#[test]
fn a_lowering_refusals_name_is_its_stable_snake_case() {
    for (refusal, name) in [
        (
            LoweringRefusal::AgentPanelPrimaryMismatch,
            "agent_panel_primary_mismatch",
        ),
        (
            LoweringRefusal::PanelOnDeterministicExecutor,
            "panel_on_deterministic_executor",
        ),
        (LoweringRefusal::JoinInputRefused, "join_input_refused"),
        (
            LoweringRefusal::WorkspaceEffectOpAbsent,
            "workspace_effect_op_absent",
        ),
        (
            LoweringRefusal::AgentSelectorUnbound,
            "agent_selector_unbound",
        ),
        (LoweringRefusal::NotProcessAction, "not_process_action"),
        (
            LoweringRefusal::SelectConditionUnknown,
            "select_condition_unknown",
        ),
        (
            LoweringRefusal::ExpansionMemberRefused,
            "expansion_member_refused",
        ),
        (LoweringRefusal::InputTargetUnknown, "input_target_unknown"),
        (
            LoweringRefusal::PathCoordinateOverflow,
            "path_coordinate_overflow",
        ),
        (LoweringRefusal::SourceHashAbsent, "source_hash_absent"),
    ] {
        assert_eq!(refusal.as_str(), name, "{refusal:?} names itself");
    }
}

/// An inline `topology` whose WORKER role declares `agent = "shell"` — the one
/// executor arm no shipped pack lowers: every corpus child role names an agent
/// label, so `BackendType::Shell → ActionExecutor::Command` is exercised here,
/// not by a pack. (Mutation survivor: deleting the `Some(BackendType::Shell)`
/// arm lowers a shell child as `Agent { drivers: ["shell"] }` — a member no
/// capsule can run, wearing a label that names no agent driver.)
const SHELL_CHILD_TOPOLOGY_PACK: &str = r#"
parent = stage(
    id = "parent",
    agent = "shell",
    run = "printf 'root ok\\n'",
    topology = topology(
        "root_with_shell_worker",
        root = role("the_root", agent = "shell"),
        workers = [
            role("shell_worker", agent = "shell"),
        ],
        max_concurrency = 2,
    ),
)

workflow(
    "shell-child-topology",
    description = "Coverage: a topology worker role on the shell executor.",
    root = [parent],
)
"#;

/// 27 — SHELL CHILD. A `role(agent = "shell")` member lowers to
/// `ActionExecutor::Command`, exactly as the root member's shell payload does —
/// a child's `agent` label selects the executor, and `"shell"` names the
/// command backend, never an agent driver.
#[test]
fn a_topology_member_on_the_shell_backend_lowers_to_a_command() {
    let program = inline(SHELL_CHILD_TOPOLOGY_PACK, "shell-child-topology.star");
    let index = program
        .stages
        .keys()
        .position(|id| id.0.as_str() == "parent")
        .expect("parent is a stage");
    let expansion = lower_topology_expansion(&program, index).expect("the topology expands");

    // The root keeps the stage's own Command executor; the WORKER is the arm
    // under test — `BackendType::from_label("shell")` → `Command`.
    let root = lower_expansion_member(&program, &expansion, expansion.path.child(0), 0)
        .expect("the root member lowers");
    assert_eq!(
        root.contract.operation,
        RuntimeOperation::Execute(kata_types::execution_contract::ExecuteOperation {
            executor: ActionExecutor::Command,
            contract_hash: program.stages[&stage_id("parent")].contract_hash,
        }),
        "the root member runs the stage's own shell command"
    );
    let child = lower_expansion_member(&program, &expansion, expansion.path.child(1), 1)
        .expect("the shell worker lowers");
    assert_eq!(
        child.contract.source_stage.0.as_str(),
        "parent#child-shell_worker",
    );
    assert_eq!(
        child.contract.operation,
        RuntimeOperation::Execute(kata_types::execution_contract::ExecuteOperation {
            executor: ActionExecutor::Command,
            contract_hash: program.stages[&stage_id("parent")].contract_hash,
        }),
        "a role declaring agent = \"shell\" lowers to the command executor, \
         not an agent driver named \"shell\""
    );
}

/// 28 — DYNAMIC MEMBER COORDINATE. `lower_dynamic_fanout_member` refuses every
/// coordinate that is not a strict child of the expansion's own path — a
/// coordinate that merely has a deeper length but lives in ANOTHER subtree is
/// not a member of this fanout. (Mutation survivor: `!starts_with || len <=`
/// under `&&` lets a foreign longer coordinate fall through and lower.)
#[test]
fn a_dynamic_fanout_member_outside_the_expansion_subtree_is_refused() {
    // The shipped corpus authors no `dynamic_fanout`, so the witness is the
    // same mutated-envelope program the dynamic-fanout lowering case uses.
    let mut program = pack("std/kata-loop-plan-check-std.star").clone();
    let fanout_stage = program
        .stages
        .get_mut(&stage_id("research"))
        .expect("the topology stage is present");
    fanout_stage.invocation_envelope.dynamic_fanout = true;
    let expansion = lower_stage_operation(&program, &stage_id("research"))
        .expect("a dynamic fanout stage lowers");
    let RuntimeOperation::ExpandBounded { .. } = &expansion.contract.operation else {
        panic!("a dynamic fanout lowers to ExpandBounded")
    };

    // The real member seat lowers: a request-minted child at
    // `expand_path.child(1)`.
    let child_stage = stage_id("research#child-codebase_researcher-x");
    let member = lower_dynamic_fanout_member(
        &program,
        &expansion,
        expansion.path.child(1),
        &child_stage,
        Some("codex"),
    )
    .expect("a request-minted child lowers at the expansion's child seat");
    assert_eq!(member.path, expansion.path.child(1));
    assert_eq!(member.contract.source_stage, child_stage);

    // A LONGER coordinate in a foreign subtree is no member of this expansion:
    // it is a prefix miss AND a strict-child miss together.
    assert_eq!(
        lower_dynamic_fanout_member(
            &program,
            &expansion,
            OperationPath(vec![u32::MAX - 1, 5]),
            &child_stage,
            Some("codex"),
        ),
        Err(LoweringError::NotAMemberCoordinate),
        "a coordinate outside the expansion's subtree must refuse, not lower"
    );
    // The expansion's own path (not a strict child) refuses too.
    assert_eq!(
        lower_dynamic_fanout_member(
            &program,
            &expansion,
            expansion.path.clone(),
            &child_stage,
            Some("codex"),
        ),
        Err(LoweringError::NotAMemberCoordinate),
        "the expansion's own coordinate is no member"
    );
}
