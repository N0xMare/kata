//! No shipped pack may put a MODEL stage that can write the candidate between
//! the proof that authorizes a `promote` and the `promote` itself.
//!
//! # The defect this pins
//!
//! `CandidateTreePin` (`kata_types::execution`) is the identity fence: the
//! runner stamps the tree a recorded validation criterion bound, the provider
//! compares it against the SETTLED candidate after the snapshot that produces
//! the commit about to land, and refuses on inequality. It is a RUNTIME
//! refusal, and by the time it fires the run has already been dispatched and
//! paid for — for a model-driven loop that is the expensive half.
//!
//! `workflows/std/kata-gate-fix-loop.star` shipped in exactly the shape the
//! fence refuses. Its loop body was `sequence(gate_run, fix)`, re-run WHOLE each
//! iteration, so the model stage `fix` (oci, `workspace-rw`) ran AFTER the
//! green `gate_run` and BEFORE the controller chose `promote` — including on the
//! iteration whose `gate_run` was green. The tree that would land was not the
//! tree that was judged, and the pack's own promote was refusable. A comment
//! recording such a hazard is not a check; this file is.
//!
//! # THE REFUSED SET, exactly
//!
//! For every pack under `workflows/{std,kata-factory,examples}` that carries an
//! in-graph `workspace_effect op="promote"` stage `P`, and every stage `V`
//! named by a REQUIRED `validation_criterion`, this test refuses a stage `S`
//! such that:
//!
//! 1. `S` is reachable from `V` along program edges, and `P` is reachable from
//!    `S` — i.e. `S` can execute after the proof and before the land; AND
//! 2. `S` routes to a MODEL executor ([`stage_executor_is_model`] — neither
//!    `shell` nor `workspace_effect`); AND
//! 3. `S`'s checked class grants [`Workspace::MutableCandidate`] — it can write
//!    tracked content in the candidate.
//!
//! `V` and `P` themselves are never members.
//!
//! # What it does NOT refuse, and why the line is drawn at the executor
//!
//! It does NOT refuse a *shell* stage with candidate write authority in that
//! position. `workflows/examples/gold-loop.star` has one — `approve`
//! (`agent="shell"`, `approval=True`, no declared sandbox, therefore
//! `HostUnconfined` + `MutableCandidate`) sits between `validate` and `land`
//! and is admitted here.
//!
//! That is not the corpus being accommodated; it is the same line the product
//! already draws. `kata_types::agent::is_deterministic_agent_label` — the
//! predicate `stage_executor_is_model` ultimately routes on — is what makes a
//! `shell` verdict acceptable as promotion proof and a model verdict not. A
//! shell stage's whole behaviour is the authored `run=` script, frozen into
//! `op.prompt_hash` and readable in the pack by whoever reviews it; a model
//! stage's is not knowable from the IR at all. Refusing the first from a static
//! check would be a refusal wider than anything the check can see, and it would
//! refuse the human-approval shape that is the single most important case the
//! tree-id pin exists to ADMIT (a human does not write to the tree, so identity
//! holds).
//!
//! The runtime fence still covers both: it compares tree ids and does not care
//! which executor moved the bytes. This test is the STATIC half — it catches
//! the systematic, always-fires case at check time, before an execution id is
//! minted.
//!
//! # Why a test and not a load-time refusal
//!
//! A load refusal would have to hold for every authorable graph, including ones
//! nobody has written yet, and its refused set would have to be defended
//! against the whole space rather than against the shipped corpus. This asserts
//! a property of what kata SHIPS — the packs an author copies — which is a
//! narrower and honestly-provable claim.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use kata_program::execution_program::{
    ExecutionProgram, ExecutionProgramStage, compile_execution_program_from_file,
    compile_starlark_execution_program, stage_executor_is_model, stage_routes_to_workspace_effect,
};
use kata_types::execution_class::Workspace;
use kata_types::workflow::{StageId, WorkspaceEffect, WorkspaceEffectOp};

/// `<repo>` — the crate lives at `<repo>/crates/workflow`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/crates/workflow")
        .to_path_buf()
}

fn loader_roots() -> Vec<PathBuf> {
    let wf = repo_root().join("workflows");
    vec![
        wf.join("std"),
        wf.join("kata-factory"),
        wf.join("examples"),
        wf.join("smoke"),
    ]
}

fn collect_star(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_star(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "star") {
            out.push(path);
        }
    }
}

/// Every shipped pack under the three product roots, and every `workflows/smoke`
/// rig, sorted.
fn shipped_packs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for sub in ["std", "kata-factory", "examples", "smoke"] {
        collect_star(&repo_root().join("workflows").join(sub), &mut out);
    }
    out.sort();
    out
}

/// `workflows/std/kata/std.star` and `workflows/kata-factory/kata/factory.star`
/// are the shared Starlark LIBRARIES, not workflows — neither calls `workflow()`
/// at module scope, so compiling one by path is a category error rather than a
/// pack failure.
fn is_library_not_a_pack(pack: &Path) -> bool {
    pack.ends_with("std/kata/std.star") || pack.ends_with("kata-factory/kata/factory.star")
}

fn compile(pack: &Path) -> Result<ExecutionProgram, String> {
    let mut roots = loader_roots();
    if let Some(dir) = pack.parent() {
        roots.insert(0, dir.to_path_buf());
    }
    compile_execution_program_from_file(pack, &roots).map_err(|error| error.to_string())
}

/// Stages carrying `workspace_effect op="promote"`, read from the checked
/// directive prompt the way `classify_executor` reads it — never from the stage
/// id, which is an author's free choice.
fn promote_stages(program: &ExecutionProgram) -> Vec<StageId> {
    program
        .stages
        .iter()
        .filter(|(_, stage)| {
            stage_routes_to_workspace_effect(stage)
                && WorkspaceEffect::from_directive_prompt(&stage.op.prompt_template)
                    .is_some_and(|effect| effect.op == WorkspaceEffectOp::Promote)
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// The stages a REQUIRED validation criterion names as its proof.
fn required_proof_stages(program: &ExecutionProgram) -> Vec<StageId> {
    program
        .validation_criteria
        .criteria
        .iter()
        .filter(|criterion| criterion.required)
        .filter_map(|criterion| criterion.stage.clone())
        .collect()
}

fn successors(program: &ExecutionProgram) -> BTreeMap<StageId, Vec<StageId>> {
    let mut map: BTreeMap<StageId, Vec<StageId>> = BTreeMap::new();
    for edge in &program.edges {
        map.entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
    }
    map
}

fn predecessors(program: &ExecutionProgram) -> BTreeMap<StageId, Vec<StageId>> {
    let mut map: BTreeMap<StageId, Vec<StageId>> = BTreeMap::new();
    for edge in &program.edges {
        map.entry(edge.to.clone())
            .or_default()
            .push(edge.from.clone());
    }
    map
}

fn reachable(from: &StageId, adjacency: &BTreeMap<StageId, Vec<StageId>>) -> BTreeSet<StageId> {
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([from.clone()]);
    while let Some(node) = queue.pop_front() {
        for next in adjacency.get(&node).into_iter().flatten() {
            if seen.insert(next.clone()) {
                queue.push_back(next.clone());
            }
        }
    }
    seen
}

/// Every stage that can execute strictly after `proof` and strictly before
/// `promote`: forward-reachable from the proof AND backward-reachable from the
/// promote, with both endpoints removed.
fn between(program: &ExecutionProgram, proof: &StageId, promote: &StageId) -> Vec<StageId> {
    let after = reachable(proof, &successors(program));
    let before = reachable(promote, &predecessors(program));
    let mut out: Vec<StageId> = after.intersection(&before).cloned().collect();
    out.retain(|id| id != proof && id != promote);
    out
}

/// The refused predicate, spelled once.
fn can_rewrite_the_judged_tree(stage: &ExecutionProgramStage) -> bool {
    stage_executor_is_model(stage) && stage.execution_class.workspace == Workspace::MutableCandidate
}

/// One line per offending position.
fn offenders(program: &ExecutionProgram, pack: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for promote in promote_stages(program) {
        for proof in required_proof_stages(program) {
            for candidate in between(program, &proof, &promote) {
                let Some(stage) = program.stages.get(&candidate) else {
                    continue;
                };
                if can_rewrite_the_judged_tree(stage) {
                    out.push(format!(
                        "{}: model stage `{}` (workspace={:?}) can run after the proof stage \
                         `{}` and before the promote `{}`, so the tree that lands is not the \
                         tree that was judged and `CandidateTreePin::require_tree` refuses the \
                         promote",
                        pack.display(),
                        candidate.0,
                        stage.execution_class.workspace,
                        proof.0,
                        promote.0,
                    ));
                }
            }
        }
    }
    out
}

/// THE ASSERTION. Every shipped pack that lands on the operator's trunk keeps
/// its proof unseparated from its land by anything a model can write through.
#[test]
fn no_shipped_pack_lets_a_model_stage_rewrite_the_judged_tree_before_it_lands() {
    let packs = shipped_packs();
    assert!(
        packs.len() > 40,
        "the shipped corpus must be walked, found only {} packs — the roots moved",
        packs.len()
    );

    let mut with_promote = 0usize;
    let mut failures = Vec::new();
    for pack in &packs {
        if is_library_not_a_pack(pack) {
            continue;
        }
        let program = compile(pack).unwrap_or_else(|reason| {
            panic!("shipped pack {} must compile: {reason}", pack.display())
        });
        if promote_stages(&program).is_empty() {
            continue;
        }
        with_promote += 1;
        failures.extend(offenders(&program, pack));
    }

    assert!(
        with_promote >= 2,
        "this test measures nothing unless it walks the packs that PROMOTE; found {with_promote}"
    );
    assert!(
        failures.is_empty(),
        "{} position(s) put a candidate-writing model stage between a required proof and a \
         promote:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// The test above is worthless if its own predicate cannot see the shape it
/// exists to refuse. This is the counterfactual, over the pack that HAD it: a
/// body ordered `sequence(gate_run, fix)` — the proof first, the model second —
/// puts `fix` between the proof and the promote, and the offender list names it.
///
/// Authored inline rather than read from disk, so fixing the shipped pack does
/// not delete the proof that the check has teeth.
#[test]
fn the_pre_fix_body_order_is_exactly_what_this_refuses() {
    let source = r#"
gate_run = stage(
    id = "gate_run",
    agent = "shell",
    run = "printf '{\"status\":\"passed\"}\\n'",
)
fix = stage(
    id = "fix",
    agent = "default",
    sandbox = "rw",
    depends_on = ["gate_run"],
    prompt = "fix whatever gate_run reported",
    produces = contract("FixResult", {"summary": field("string")}),
)
controller = stage(
    id = "controller",
    agent = "codex",
    sandbox = "ro",
    depends_on = ["fix"],
    prompt = "decide",
    produces = contract("D", {
        "decision": field(variant({
            "promote": contract("P", {"rationale": field("string")}),
            "park": contract("K", {"rationale": field("string")}),
            "retry": contract("R", {"rationale": field("string")}),
        })),
    }),
)
promote_effect = stage(id = "promote_effect", agent = "workspace_effect", op = "promote")
park_effect = stage(id = "park_effect", agent = "workspace_effect", op = "park")
retry_noop = stage(id = "retry_noop", agent = "shell", run = "printf '{\"noop\":1}\\n'")
loop(
    body = sequence(gate_run, fix),
    gate = controller,
    max_iterations = 2,
    gate_verdict = {
        "field": "decision",
        "refine": ["retry"],
        "approve": ["promote"],
        "block": ["park"],
    },
)
branch(
    on = controller,
    verdict_field = "decision",
    arms = {"promote": promote_effect, "park": park_effect, "retry": retry_noop},
)
workflow(
    "pre-fix-body-order",
    description = "The shape the identity fence refuses: proof, then model, then promote.",
    root = [gate_run, fix, controller],
    worktree_isolated = True,
    validation_criteria = [
        validation_criterion(
            "green",
            description = "The gate slice exits 0.",
            stage = "gate_run",
            commands = ["true"],
            required = True,
        ),
    ],
    sandbox_profiles = {
        "rw": sandbox_profile(workspace = "rw", net = "host"),
        "ro": sandbox_profile(net = "host"),
    },
)
"#;
    let roots: Vec<PathBuf> = Vec::new();
    let program = compile_starlark_execution_program(source, "pre-fix-body-order.star", &roots)
        .expect("the pre-fix shape LOADS — that is the whole problem");

    let found = offenders(&program, Path::new("pre-fix-body-order.star"));
    assert_eq!(
        found.len(),
        1,
        "the predicate must name exactly the model stage between the proof and the promote; \
         found {found:?}"
    );
    assert!(
        found[0].contains("`fix`"),
        "the offender must be named: {found:?}"
    );

    // PRECISION, both directions: the read-only model gate on the same path is
    // NOT an offender, or this check would refuse every controller.
    let controller = program
        .stages
        .get(&StageId(smol_str::SmolStr::new("controller")))
        .expect("controller stage");
    assert_eq!(controller.execution_class.workspace, Workspace::ReadOnly);
    assert!(
        stage_executor_is_model(controller),
        "the controller is a model stage — the exclusion must come from its WORKSPACE axis, \
         not from its executor"
    );
    assert!(
        !can_rewrite_the_judged_tree(controller),
        "a `workspace-ro` model gate cannot rewrite the judged tree and must be admitted"
    );
}
