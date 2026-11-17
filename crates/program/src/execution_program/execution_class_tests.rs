//! Derivation proofs: constructed-stage tuples, and BRIDGE EQUIVALENCE over
//! every stage of every shipped pack.
//!
//! The bridge is the load-bearing equivalence proof: the derived seven-axis
//! predicates must agree with the stage-level predicates on every real
//! shipped-pack stage.

use std::path::{Path, PathBuf};

use kata_types::execution_class::{
    CheckedExecutionClass, CheckedOpContext, Computation, Containment, Determinism,
    ExternalIssuance, Network, PreCommitRecovery, Workspace,
};
use kata_types::sandbox::SandboxRef;
use smol_str::SmolStr;

use super::{DerivedExecutionClass, derive_execution_class};
use crate::execution_program::{
    ExecutionProgram, ExecutionProgramStage, ExecutionPromptRendering, ExecutionStageOp,
    ExecutionStageOpKind, compile_execution_program_from_file, compile_starlark_execution_program,
};

fn compile_wf(src: &str) -> ExecutionProgram {
    compile_starlark_execution_program(src, "derive_test.star", &[]).expect("pack compiles")
}

fn stage<'a>(program: &'a ExecutionProgram, id: &str) -> &'a ExecutionProgramStage {
    program
        .stages
        .values()
        .find(|s| s.stage_id.0 == id)
        .unwrap_or_else(|| panic!("no stage {id}"))
}

fn derive(program: &ExecutionProgram, id: &str) -> DerivedExecutionClass {
    derive_execution_class(stage(program, id), &program.sandbox_profiles)
        .expect("a compiled process stage always carries a sandbox")
}

// ── Constructed-stage derivation tuples ────────────────────────────────────

#[test]
fn derives_the_model_editor_tuple() {
    // A model stage with a writable candidate and a live network is the
    // candidate-editor tuple: requires BOTH a certified container AND a
    // durable issuance claim.
    let program = compile_wf(
        r#"
impl = stage(id = "impl", agent = "codex", prompt = "edit the tree", sandbox = "s")
workflow(
    "wf",
    root = [impl],
    sandbox_profiles = {"s": sandbox_profile(workspace = "rw", net = "host")},
)
"#,
    );
    let d = derive(&program, "impl");
    assert_eq!(
        d.class,
        CheckedExecutionClass {
            computation: Computation::ProcessAction,
            determinism: Determinism::Nondeterministic,
            containment: Containment::Contained,
            workspace: Workspace::MutableCandidate,
            network: Network::Unrestricted,
            external_issuance: ExternalIssuance::DurableActivity,
            pre_commit_recovery: PreCommitRecovery::ReconcileRequired,
        }
    );
    assert_eq!(d.op, CheckedOpContext::Standard);
    assert!(d.validate().is_ok());
    assert_eq!(d.class.containment, Containment::Contained);
    assert_eq!(d.class.external_issuance, ExternalIssuance::DurableActivity);
    assert!(!d.class.is_content_cache_eligible());
    assert!(d.class.is_workspace_mutating());
}

/// **A model stage's network axis is `Unrestricted` whatever `net` says.**
///
/// A model stage's turn talks to its model provider from the process hosting
/// the worker whatever its capsule may reach, so an `Offline` axis —
/// "construction removes network" — would be a guarantee the stage does not
/// get. The shell twin of the same profile stays `Offline`: its capsule IS
/// offline on every node.
#[test]
fn a_model_stage_authored_offline_derives_an_unrestricted_network() {
    let program = compile_wf(
        r#"
review = stage(id = "review", agent = "codex", prompt = "review the tree", sandbox = "s")
check = stage(id = "check", agent = "shell", run = "true", sandbox = "s", depends_on = ["review"])
workflow(
    "wf",
    root = [review],
    sandbox_profiles = {"s": sandbox_profile(workspace = "ro", net = "offline")},
)
"#,
    );
    let model = derive(&program, "review");
    assert_eq!(
        model.class.network,
        Network::Unrestricted,
        "a model stage authored `net = \"offline\"` may not claim an offline network: {:?}",
        model.class
    );
    assert!(model.validate().is_ok(), "the tuple is closed-world valid");
    assert_eq!(
        stage(&program, "review").execution_class,
        model.class,
        "the CARRIED class is the derived one"
    );
    let shell = derive(&program, "check");
    assert_eq!(
        shell.class.network,
        Network::Offline,
        "the shell twin under the same profile is offline: {:?}",
        shell.class
    );
}

/// The stage declares no `produces_files=`, so its writable tree is UNBOUNDED:
/// the axis whose meaning is *"a certified provider enforces and captures the
/// output set"* (`DeclaredOutputs`) may not be asserted, and the class is
/// `MutableCandidate` and refused the content cache — a stale-hit hole
/// otherwise. `ExecBackend::Oci` does enforce a declared closure (the capsule
/// route's adoption judge, `Dispatcher::judge_work_delta_scope`), so this rests
/// on the STAGE half of the conjunction alone; the declared-closure
/// counter-fixture at the end of the test body exercises the other half. The
/// stage's confinement is asserted by
/// [`a_hermetic_writable_shell_stage_keeps_confinement_and_loses_cacheability`].
#[test]
fn derives_a_hermetic_shell_build_as_an_unbounded_candidate_and_not_cacheable() {
    let program = compile_wf(
        r#"
b = stage(id = "b", agent = "shell", run = "make", sandbox = "h")
workflow(
    "wf",
    root = [b],
    sandbox_profiles = {"h": sandbox_profile(workspace = "rw", net = "offline")},
)
"#,
    );
    let d = derive(&program, "b");
    assert_eq!(
        d.class,
        CheckedExecutionClass {
            computation: Computation::ProcessAction,
            determinism: Determinism::Deterministic,
            containment: Containment::Contained,
            workspace: Workspace::MutableCandidate,
            network: Network::Offline,
            external_issuance: ExternalIssuance::None,
            pre_commit_recovery: PreCommitRecovery::RecomputeAllowed,
        }
    );
    assert!(d.validate().is_ok());
    assert!(
        !d.class.is_content_cache_eligible(),
        "no provider bounds this stage's writes, so its result may not be keyed \
         by content: {:?}",
        d.class
    );
    // Bridge: agrees with the stage-level predicates.
    let s = stage(&program, "b");
    assert_eq!(
        d.class.is_content_cache_eligible(),
        s.is_content_cacheable()
    );
    assert_eq!(
        d.class.is_workspace_mutating(),
        s.execution_class.is_workspace_mutating()
    );

    // DECLARING an output closure is the OTHER half of the conjunction, and
    // this is the half a reader is most likely to assume away: the same stage
    // WITH `produces_files=` derives `DeclaredOutputs` and IS content-cache
    // eligible, because `ExecBackend::Oci` enforces a declared write closure
    // (`Dispatcher::judge_work_delta_scope` refuses any `/work` delta outside
    // it, `work_delta_out_of_scope`).
    //
    // Both conjuncts are satisfied here, so the pair proves only the STAGE
    // conjunct (the assertions above, same profile, no `produces_files=`,
    // `MutableCandidate`). The BACKEND conjunct's load-bearingness is proved in
    // `kata_types` (`oci_is_the_one_backend_that_enforces_a_declared_write_closure`),
    // not here.
    let declared = compile_wf(
        r#"
b = stage(id = "b", agent = "shell", run = "make", sandbox = "h", produces_files = ["out/kata"])
workflow(
    "wf",
    root = [b],
    sandbox_profiles = {"h": sandbox_profile(workspace = "rw", net = "offline")},
)
"#,
    );
    let declared_stage = stage(&declared, "b");
    assert_eq!(
        declared_stage.produces_files,
        vec![SmolStr::new("out/kata")],
        "the fixture must actually carry the declared closure"
    );
    let declared_class = derive(&declared, "b").class;
    assert_eq!(
        declared_class.workspace,
        Workspace::DeclaredOutputs,
        "a declared output closure on a backend that ENFORCES one is a BOUND write \
         set — both halves of `write_closure_bound` are satisfied here, and the \
         undeclared fixture above is the same profile with the stage half removed"
    );
    assert!(
        declared_class.is_content_cache_eligible(),
        "`DeclaredOutputs` is content-cache eligible by definition — that IS the \
         capability this conjunction exists to unlock: {declared_class:?}"
    );
    assert_eq!(
        declared_class.is_content_cache_eligible(),
        declared_stage.is_content_cacheable(),
        "the derived class and the stage predicate must not disagree about the same \
         stage"
    );
}

#[test]
fn derives_a_readonly_offline_shell_as_cacheable_but_not_mutating() {
    let program = compile_wf(
        r#"
b = stage(id = "b", agent = "shell", run = "true", sandbox = "ro")
workflow(
    "wf",
    root = [b],
    sandbox_profiles = {"ro": sandbox_profile(net = "offline")},
)
"#,
    );
    let d = derive(&program, "b");
    assert_eq!(d.class.workspace, Workspace::ReadOnly);
    assert_eq!(d.class.determinism, Determinism::Deterministic);
    assert!(d.class.is_content_cache_eligible());
    assert!(!d.class.is_workspace_mutating());
    assert!(d.validate().is_ok());
}

#[test]
fn derives_a_plain_shell_as_the_materialized_confined_default() {
    // A plain shell stage is lowered with the explicit confined default and
    // derives the hermetic read-only tuple — never
    // `HostUnconfined + MutableCandidate + Unrestricted + DurableActivity +
    // ManualResolution`.
    let program = compile_wf(
        r#"
b = stage(id = "b", agent = "shell", run = "true")
workflow("wf", root = [b])
"#,
    );
    let d = derive(&program, "b");
    assert_eq!(
        d.class,
        CheckedExecutionClass {
            computation: Computation::ProcessAction,
            determinism: Determinism::Deterministic,
            containment: Containment::Contained,
            workspace: Workspace::ReadOnly,
            network: Network::Offline,
            external_issuance: ExternalIssuance::None,
            pre_commit_recovery: PreCommitRecovery::RecomputeAllowed,
        }
    );
    assert!(d.validate().is_ok());
    assert!(d.class.is_content_cache_eligible());
    assert!(!d.class.is_workspace_mutating());
}

#[test]
fn net_host_shell_is_nondeterministic_and_durable() {
    // R4 forbids Deterministic + Unrestricted, so a net=host shell derives
    // Nondeterministic + DurableActivity + ManualResolution (no adapter
    // observation contract). The membrane cannot blind-re-execute it.
    let program = compile_wf(
        r#"
b = stage(id = "b", agent = "shell", run = "curl example.com", sandbox = "net")
workflow(
    "wf",
    root = [b],
    sandbox_profiles = {"net": sandbox_profile(net = "host")},
)
"#,
    );
    let d = derive(&program, "b");
    assert_eq!(d.class.determinism, Determinism::Nondeterministic);
    assert_eq!(d.class.network, Network::Unrestricted);
    assert_eq!(d.class.external_issuance, ExternalIssuance::DurableActivity);
    assert_eq!(
        d.class.pre_commit_recovery,
        PreCommitRecovery::ManualResolution
    );
    assert!(d.validate().is_ok());
}

#[test]
fn host_workspace_ro_is_refused_by_the_matrix_and_is_no_longer_authorable() {
    // `exec = host` derives HostUnconfined; `fs = workspace-ro` derives
    // ReadOnly, and the closed-world matrix refuses that unenforced ro-under-host
    // label with an R-code — an unenforced containment/ro label is a lie. The
    // pair cannot be AUTHORED at all (there is no `exec=`/`fs=` kwarg, and
    // `sandbox = "host"` lowers to `fs = host`), so the refusal is
    // asserted where the tuple can still be built: the typed derivation, which
    // is also the only way such a profile still reaches production (a decoded
    // program). R6 (HostUnconfined admits only workspace None/MutableCandidate)
    // fires first, ahead of R7 (ReadOnly requires Contained).
    let profile = kata_types::sandbox::SandboxProfile {
        exec: kata_types::sandbox::ExecBackend::Host,
        net: kata_types::sandbox::NetPolicy::Host,
        ..kata_types::sandbox::SandboxProfile::confined_default()
    };
    let op = ExecutionStageOp {
        kind: ExecutionStageOpKind::Stage,
        agent: "shell".into(),
        agent_label: Some("shell".into()),
        agent_panel: Vec::new(),
        prompt_rendering: ExecutionPromptRendering::default(),
        prompt_present: true,
        prompt_template: "true".into(),
        prompt_hash: None,
    };
    let sandbox = SandboxRef::Inline(Box::new(profile));
    let derived = super::derive_execution_class_from_parts(
        super::StagePayload::Op,
        &op,
        Some(&sandbox),
        &std::collections::BTreeMap::new(),
        &[],
    )
    .expect("a declared sandbox always derives");
    assert_eq!(derived.class.containment, Containment::HostUnconfined);
    assert_eq!(derived.class.workspace, Workspace::ReadOnly);
    let refusal = derived
        .validate()
        .expect_err("host + workspace-ro is an unenforceable read-only label");
    assert_eq!(
        refusal.code, "R6",
        "R6 fires first for host + workspace-ro: {refusal}"
    );

    // And the authoring surface cannot even spell the pair any more.
    let err = compile_starlark_execution_program(
        r#"
b = stage(id = "b", agent = "shell", run = "true", sandbox = "hro")
workflow(
    "wf",
    root = [b],
    sandbox_profiles = {"hro": sandbox_profile(exec = "host", net = "host")},
)
"#,
        "host_ro.star",
        &[],
    )
    .expect_err("`sandbox_profile()` takes no backend keyword");
    assert!(
        err.to_string()
            .contains("Found `exec` extra named parameter(s)"),
        "the refusal must name the keyword the signature lacks: {err}"
    );
}

#[test]
fn derives_workspace_effect_park_as_admission_one() {
    let program = compile_wf(
        r#"
seed = stage(id = "seed", agent = "shell", run = "true")
park = stage(id = "park", agent = "workspace_effect", op = "park", depends_on = ["seed"])
workflow("wf", root = [seed, park], worktree_isolated = True)
"#,
    );
    let d = derive(&program, "park");
    assert_eq!(
        d.class,
        CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION
    );
    assert_eq!(d.op, CheckedOpContext::WorkspacePark);
    assert!(
        d.validate().is_ok(),
        "admission 1 is valid under a workspace-provider op"
    );
    assert!(
        !d.class.is_content_cache_eligible(),
        "a recorded mutation is never cacheable"
    );
    assert!(d.class.is_workspace_mutating());
    // Bridge holds for admission 1.
    let s = stage(&program, "park");
    assert_eq!(
        d.class.is_content_cache_eligible(),
        s.is_content_cacheable()
    );
    assert_eq!(
        d.class.is_workspace_mutating(),
        s.execution_class.is_workspace_mutating()
    );
}

#[test]
fn derives_workspace_effect_promote_and_commit_ops() {
    for (op, expected) in [
        ("promote", CheckedOpContext::WorkspacePromote),
        ("commit", CheckedOpContext::WorkspaceCommit),
    ] {
        // The `validation_criteria` block is not what this test measures — it is
        // what a graph carrying a `promote` must declare
        // (`validate_in_graph_promote_declares_a_criterion`). It is present for
        // BOTH ops so the two arms differ only in the op under test.
        let src = format!(
            r#"
seed = stage(id = "seed", agent = "shell", run = "true")
eff = stage(id = "eff", agent = "workspace_effect", op = "{op}", depends_on = ["seed"])
workflow(
    "wf",
    root = [seed, eff],
    worktree_isolated = True,
    validation_criteria = [
        validation_criterion(
            "seeded",
            description = "the deterministic seed stage succeeded",
            stage = "seed",
            commands = ["true"],
            required = True,
        ),
    ],
)
"#
        );
        let program = compile_wf(&src);
        let d = derive(&program, "eff");
        assert_eq!(
            d.class,
            CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION
        );
        assert_eq!(d.op, expected, "op {op}");
        assert!(d.validate().is_ok());
    }
}

#[test]
fn derives_forge_export_as_admission_two() {
    // A forge land stage classifies under admission 2
    // with workspace=None (the candidate binds as a tree-id input).
    let program = compile_wf(
        r#"
seed = stage(id = "seed", agent = "shell", run = "true")
snap = stage(id = "snap", agent = "workspace_effect", op = "commit", depends_on = ["seed"])
land = stage(
    id = "land",
    agent = "workspace_effect",
    op = "forge_export",
    depends_on = ["snap"],
)
workflow("wf", root = [seed, snap, land], worktree_isolated = True)
"#,
    );
    let d = derive(&program, "land");
    assert_eq!(d.class, CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE);
    assert_eq!(d.op, CheckedOpContext::ForgeLand);
    assert!(
        d.validate().is_ok(),
        "admission 2 is valid under the forge-land adapter op"
    );
    assert_eq!(d.class.workspace, Workspace::None);
    assert_eq!(d.class.external_issuance, ExternalIssuance::DurableActivity);
    assert!(!d.class.is_content_cache_eligible());

    // The class binds the exported candidate as an immutable INPUT
    // (workspace=None), so `is_workspace_mutating` is false on the derived and
    // the hashed class alike — forge `land` is NON-mutating. (The load-time
    // `model_reuse` cache guard separately refuses envelope-replay on this adapter-issuance stage
    // via `is_adapter_issuance`.) No shipped pack uses forge_export.
    let s = stage(&program, "land");
    assert!(!s.execution_class.is_workspace_mutating());
    assert!(!d.class.is_workspace_mutating());
    assert!(
        d.class.is_adapter_issuance(),
        "forge land is an effect-adapter issuance (admission 2)"
    );
    // Both bridges now hold (reader == class).
    assert_eq!(
        d.class.is_workspace_mutating(),
        s.execution_class.is_workspace_mutating()
    );
    assert_eq!(
        d.class.is_content_cache_eligible(),
        s.is_content_cacheable()
    );
}

// ── Bridge equivalence over every shipped pack ─────────────────────────────

/// R2's base row, spelled out axis by axis rather than read back through
/// [`CheckedExecutionClass::MAIN_RESOLVED_WAIT`], the constant the derivation
/// returns.
fn r2_base_row() -> CheckedExecutionClass {
    CheckedExecutionClass {
        computation: Computation::WaitForInput,
        determinism: Determinism::Nondeterministic,
        containment: Containment::InProcess,
        workspace: Workspace::None,
        network: Network::Offline,
        external_issuance: ExternalIssuance::None,
        pre_commit_recovery: PreCommitRecovery::AwaitRecordedInput,
    }
}

/// R2: a durable `sleep()` and a `parallel()` join barrier are
/// MAIN-RESOLVED WAITS, and the CARRIED class on the compiled stage says so — the
/// whole R2 base row, spelled out axis by axis in [`r2_base_row`] rather than read
/// back through the constant the derivation returns. A sibling `shell` stage in the same pack
/// stays a `ProcessAction`, so the arm is keyed on the payload, not on the inert
/// `shell` op a sleep and a join still carry.
#[test]
fn a_sleep_and_a_join_carry_the_r2_wait_for_input_class() {
    let program = compile_wf(
        r#"
a = stage(id = "a", agent = "shell", run = "true")
b = stage(id = "b", agent = "shell", run = "true")
join = parallel(a, b)
nap = sleep(id = "nap", for_ms = 1000)
after = stage(id = "after", agent = "shell", run = "true")
sequence(join, nap)
sequence(nap, after)
workflow("wf", root = [a, b])
"#,
    );
    let r2_row = r2_base_row();
    let joins: Vec<&ExecutionProgramStage> = program
        .stages
        .values()
        .filter(|s| s.synthesized == Some(kata_types::workflow::SynthesizedStage::ParallelJoin))
        .collect();
    assert_eq!(joins.len(), 1, "the pack mints exactly one join barrier");
    for waiting in [stage(&program, "nap"), joins[0]] {
        assert_eq!(
            waiting.execution_class, r2_row,
            "stage {} is a main-resolved wait and must carry R2's base row",
            waiting.stage_id.0
        );
        waiting
            .execution_class
            .validate(CheckedOpContext::Standard)
            .expect("the R2 row is a valid closed-world tuple under the standard op");
    }
    assert_eq!(
        stage(&program, "after").execution_class.computation,
        Computation::ProcessAction,
        "a shell stage beside the waits is still a process action"
    );
}

/// A `memory_snapshot()` stage is MAIN-RESOLVED on every
/// profile — the main reads its own memory store and accepts the stage — so it
/// carries R2's base row, not the `Contained` + content-cache-eligible process
/// class the frontend's inert `shell`/`:` defaults would derive. A sibling shell
/// stage that reads the snapshot stays a `ProcessAction`.
#[test]
fn a_memory_snapshot_carries_the_r2_wait_for_input_class() {
    let program = compile_wf(
        r#"
memory_context = memory_snapshot(id = "memory_context", kind = "task", status = "active")
summarize = stage(id = "summarize", agent = "shell", run = "true", depends_on = [memory_context])
workflow("wf", root = [memory_context])
"#,
    );
    let snapshot = stage(&program, "memory_context");
    assert!(
        snapshot.memory_snapshot.is_some(),
        "the stage is a memory snapshot"
    );
    assert_eq!(
        snapshot.execution_class,
        r2_base_row(),
        "a memory snapshot is a main-resolved read and must carry R2's base row"
    );
    assert!(!snapshot.execution_class.is_content_cache_eligible());
    assert_ne!(snapshot.execution_class.containment, Containment::Contained);
    snapshot
        .execution_class
        .validate(CheckedOpContext::Standard)
        .expect("the R2 row is a valid closed-world tuple under the standard op");
    assert_eq!(
        stage(&program, "summarize").execution_class.computation,
        Computation::ProcessAction,
        "a shell stage beside the snapshot is still a process action"
    );
}

/// A `subworkflow()` stage lowers to `Invoke`, which the main
/// STARTS (one parked attempt, one linked child execution) and the child's
/// terminal publication resolves — no worker runs the parent stage. It carries
/// R2's base row, not the `agent = any` model class (`Contained`, `net = host`,
/// durable issuance) its unauthored executor would derive.
#[test]
fn a_subworkflow_carries_the_r2_wait_for_input_class() {
    let library = tempfile::tempdir().expect("library tempdir");
    std::fs::write(
        library.path().join("child.star"),
        "only = stage(id = \"only\", agent = \"shell\", run = \":\")\nworkflow(\"child\", root = only)\n",
    )
    .expect("write the child pack");
    let program = compile_starlark_execution_program(
        r#"
sub = subworkflow(id = "sub", pack = "child")
after = stage(id = "after", agent = "shell", run = "true", depends_on = [sub])
workflow("wf", root = [sub])
"#,
        "derive_test.star",
        &[library.path().to_path_buf()],
    )
    .expect("the parent compiles against its child library");
    let sub = stage(&program, "sub");
    assert!(sub.subworkflow.is_some(), "the stage is a subworkflow");
    assert_eq!(
        sub.execution_class,
        r2_base_row(),
        "a subworkflow stage is a main-resolved invocation and must carry R2's base row"
    );
    assert_ne!(sub.execution_class.containment, Containment::Contained);
    assert_ne!(
        sub.execution_class.external_issuance,
        ExternalIssuance::DurableActivity
    );
    sub.execution_class
        .validate(CheckedOpContext::Standard)
        .expect("the R2 row is a valid closed-world tuple under the standard op");
    assert_eq!(
        stage(&program, "after").execution_class.computation,
        Computation::ProcessAction,
        "a shell stage beside the invocation is still a process action"
    );
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/crates/program")
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

/// Every top-level `.star` under `workflows/std` and `workflows/examples` — the
/// shipped pack surface — and `workflows/smoke`, the gate rigs. Library files
/// live under `.../kata/` subdirs and are excluded by the non-recursive scan.
fn shipped_packs() -> Vec<PathBuf> {
    let wf = repo_root().join("workflows");
    let mut out = Vec::new();
    for dir in [wf.join("std"), wf.join("examples"), wf.join("smoke")] {
        for entry in std::fs::read_dir(&dir).expect("read pack dir").flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|e| e == "star") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// A workspace_effect forge `land` stage — the sole modeled case where the
/// class (workspace=None) diverges from a coarse "every workspace effect
/// mutates" reading. No shipped pack uses it (asserted below).
fn is_forge_export(d: DerivedExecutionClass) -> bool {
    d.op == CheckedOpContext::ForgeLand
}

/// THE BRIDGE EQUIVALENCE PROOF. For every stage of every shipped pack:
/// (a) the derived tuple is VALID; (b) `is_content_cache_eligible` ≡
/// `is_content_cacheable`; (c) the derived `is_workspace_mutating` ≡ the
/// stage's hashed class's (forge_export excepted — see [`is_forge_export`]).
#[test]
fn derived_predicates_bridge_the_stage_predicates_on_every_shipped_pack() {
    let packs = shipped_packs();
    assert!(
        packs.len() >= 40,
        "expected the full shipped pack corpus, found {}",
        packs.len()
    );

    let roots = loader_roots();
    let mut stage_count = 0usize;
    let mut forge_export_count = 0usize;
    let mut net_reclassified: Vec<String> = Vec::new();
    let mut cache_mismatches: Vec<String> = Vec::new();
    let mut mutate_mismatches: Vec<String> = Vec::new();
    let mut confine_mismatches: Vec<String> = Vec::new();
    let mut confining_stages = 0usize;
    let mut invalid: Vec<String> = Vec::new();
    let mut carried_mismatches: Vec<String> = Vec::new();

    for pack in &packs {
        let program = compile_execution_program_from_file(pack, &roots)
            .unwrap_or_else(|e| panic!("compile {}: {e}", pack.display()));
        let pack_name = pack.file_stem().unwrap().to_string_lossy();

        for stage in program.stages.values() {
            stage_count += 1;
            let d = derive_execution_class(stage, &program.sandbox_profiles)
                .expect("a compiled process stage always carries a sandbox");
            let site = format!("{pack_name}::{}", stage.stage_id.0);

            if let Err(refusal) = d.validate() {
                invalid.push(format!("{site}: {refusal} {:?}", d.class));
            }

            // (a) the two derivation readers agree. The lowering builds its
            // `PayloadMarkers` from the authored definition; `derive_execution_class`
            // builds its own from the assembled stage (`StagePayload::of_stage`).
            // The class the lowering CARRIED and the one re-derived here must be
            // the same tuple on every shipped stage, or one reader dropped a
            // marker the other reads.
            if d.class != stage.execution_class {
                carried_mismatches.push(format!(
                    "{site}: re-derived={:?} carried={:?}",
                    d.class, stage.execution_class
                ));
            }

            // (b) cache-eligibility bridge — holds for ALL stages.
            let existing_cache = stage.is_content_cacheable();
            if d.class.is_content_cache_eligible() != existing_cache {
                cache_mismatches.push(format!(
                    "{site}: derived={} existing={existing_cache} {:?}",
                    d.class.is_content_cache_eligible(),
                    d.class
                ));
            }

            // (d) CONFINEMENT bridge: the shipped
            // `should_confine_to_declared_inputs` must BE
            // `class_needs_no_ambient_host_input`, over every real stage.
            // Without this the sweep tests below would prove a property of the
            // helper even if production read the cacheability conjunction.
            if stage.should_confine_to_declared_inputs()
                != crate::execution_program::types::class_needs_no_ambient_host_input(
                    stage.execution_class,
                )
            {
                confine_mismatches.push(format!(
                    "{site}: should_confine={} predicate={} {:?}",
                    stage.should_confine_to_declared_inputs(),
                    crate::execution_program::types::class_needs_no_ambient_host_input(
                        stage.execution_class
                    ),
                    d.class
                ));
            }
            if stage.should_confine_to_declared_inputs() {
                confining_stages += 1;
            }

            // (c) workspace-mutation bridge — forge_export excepted.
            if is_forge_export(d) {
                forge_export_count += 1;
            } else {
                let existing_mut = stage.execution_class.is_workspace_mutating();
                if d.class.is_workspace_mutating() != existing_mut {
                    mutate_mismatches.push(format!(
                        "{site}: derived={} existing={existing_mut} {:?}",
                        d.class.is_workspace_mutating(),
                        d.class
                    ));
                }
            }

            // Enumeration: a shell (deterministic-executor, not the in-process
            // workspace_effect) reaching a live network is reclassified
            // Nondeterministic + Unrestricted + DurableActivity.
            let is_workspace_effect = stage.is_workspace_effect_executor();
            if stage.is_deterministic_executor()
                && !is_workspace_effect
                && d.class.network == Network::Unrestricted
            {
                assert_eq!(d.class.determinism, Determinism::Nondeterministic);
                assert_eq!(d.class.external_issuance, ExternalIssuance::DurableActivity);
                net_reclassified.push(site);
            }
        }
    }

    assert!(
        invalid.is_empty(),
        "shipped-pack stages derived INVALID tuples:\n  {}",
        invalid.join("\n  ")
    );
    assert!(
        carried_mismatches.is_empty(),
        "the assembled-stage derivation disagrees with the class the lowering carried on:\n  {}",
        carried_mismatches.join("\n  ")
    );
    assert!(
        cache_mismatches.is_empty(),
        "content-cache-eligibility bridge FAILED on:\n  {}",
        cache_mismatches.join("\n  ")
    );
    assert!(
        mutate_mismatches.is_empty(),
        "workspace-mutation bridge FAILED on:\n  {}",
        mutate_mismatches.join("\n  ")
    );
    assert!(
        confine_mismatches.is_empty(),
        "the CONFINEMENT bridge FAILED — `should_confine_to_declared_inputs` is \
         not `class_needs_no_ambient_host_input` any more:\n  {}",
        confine_mismatches.join("\n  ")
    );
    assert!(
        confining_stages > 0,
        "NON-VACUITY: no shipped stage confines to its declared inputs, so the \
         confinement bridge above is satisfied by observing nothing"
    );
    assert_eq!(
        forge_export_count, 3,
        "exactly the agent-change, checked-command and change packs ship a \
         `forge_export` stage — the bridge exception they exercise is `ForgeLand`'s \
         ADMISSION_ADAPTER_ISSUANCE, which is non-mutating although it is a workspace \
         effect: the candidate binds as an immutable tree-id input"
    );
    // The reclassification is non-empty: at least the net=host shell smoke.
    assert!(
        !net_reclassified.is_empty(),
        "expected at least one net=host / no-sandbox shell reclassification"
    );
    assert!(
        stage_count > 100,
        "expected a substantial shipped-pack stage corpus, saw {stage_count}"
    );
}

// ── can an ISSUING stage honestly claim determinism? ───────────────────────

/// Every `ExecutionStageOp` shape the executor classifier distinguishes, paired
/// with the name the failure message should print. This is the executor half of
/// the derivation's input space: `classify_executor` routes on the agent label
/// and (for the in-process backend) the directive prompt, and on nothing else,
/// so enumerating those enumerates the axis.
fn every_classified_executor_op() -> Vec<(&'static str, ExecutionStageOp)> {
    use kata_types::workflow::{WORKSPACE_EFFECT_AGENT_LABEL, WorkspaceEffect, WorkspaceEffectOp};

    let op = |agent: &str, prompt: &str| ExecutionStageOp {
        kind: ExecutionStageOpKind::Stage,
        agent: SmolStr::new(agent),
        agent_label: Some(SmolStr::new(agent)),
        agent_panel: Vec::new(),
        prompt_rendering: ExecutionPromptRendering::Template,
        prompt_present: true,
        prompt_template: prompt.to_string(),
        prompt_hash: None,
    };
    let effect = |effect_op: WorkspaceEffectOp| {
        WorkspaceEffect {
            op: effect_op,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        }
        .directive_prompt()
    };
    vec![
        ("shell", op("shell", "true")),
        ("model:claude_code", op("claude_code", "do the thing")),
        ("model:codex", op("codex", "do the thing")),
        ("model:unknown-label", op("planner", "do the thing")),
        (
            "workspace_effect:park",
            op(
                WORKSPACE_EFFECT_AGENT_LABEL,
                &effect(WorkspaceEffectOp::Park),
            ),
        ),
        (
            "workspace_effect:promote",
            op(
                WORKSPACE_EFFECT_AGENT_LABEL,
                &effect(WorkspaceEffectOp::Promote),
            ),
        ),
        (
            "workspace_effect:commit",
            op(
                WORKSPACE_EFFECT_AGENT_LABEL,
                &effect(WorkspaceEffectOp::Commit),
            ),
        ),
        (
            "workspace_effect:forge_export",
            op(
                WORKSPACE_EFFECT_AGENT_LABEL,
                &effect(WorkspaceEffectOp::ForgeExport),
            ),
        ),
        (
            "workspace_effect:unparseable-directive",
            op(WORKSPACE_EFFECT_AGENT_LABEL, "junk"),
        ),
    ]
}

/// Every sandbox resolution the derivation distinguishes: absent, an unresolved
/// named ref, and the full `exec x fs x net` product over the policies a profile
/// can carry.
fn every_resolved_sandbox() -> Vec<(String, Option<SandboxRef>)> {
    use kata_types::sandbox::{ExecBackend, FsPolicy, MountSpec, NetPolicy, SandboxProfile};

    // `None` is deliberately NOT a posture here: a
    // process executor handed no sandbox is REFUSED by the derivation rather
    // than read as host-unconfined (`UnmaterializedSandbox`), an arm of its own.
    let mut out: Vec<(String, Option<SandboxRef>)> = vec![(
        "<named, unresolved>".to_string(),
        Some(SandboxRef::Named("nothing-declares-this".into())),
    )];
    let custom = |writable: bool| FsPolicy::Custom {
        mounts: vec![MountSpec {
            host_path: "/a".into(),
            mount_point: "/a".into(),
            writable,
        }],
    };
    for exec in ExecBackend::all() {
        for fs in [
            FsPolicy::Host,
            FsPolicy::WorkspaceRo,
            FsPolicy::WorkspaceRw,
            FsPolicy::Scratch,
            custom(false),
            custom(true),
        ] {
            for net in [NetPolicy::Host, NetPolicy::Offline] {
                let profile = SandboxProfile {
                    exec: exec.clone(),
                    fs: fs.clone(),
                    net: net.clone(),
                    secrets: std::collections::BTreeMap::new(),
                    locked: false,
                    image: None,
                    toolchain: None,
                    rootfs: None,
                    requires: Vec::new(),
                };
                out.push((
                    format!("exec={exec:?} fs={fs:?} net={net:?}"),
                    Some(SandboxRef::Inline(Box::new(profile))),
                ));
            }
        }
    }
    out
}

/// The THIRD input the derivation reads, added when
/// `workspace_from_fs` was re-keyed onto the declared output closure.
///
/// The derivation consults only the closure's EMPTINESS, so two points span the
/// axis exactly. Sweeping it matters anyway: without it every sweep below would
/// silently measure only the undeclared half, and the conjunct that decides
/// `DeclaredOutputs` would be exercised on one side only — which is how a
/// derivation axis gets added and never tested.
fn every_declared_output_closure() -> Vec<(&'static str, Vec<SmolStr>)> {
    vec![
        ("produces_files=[]", Vec::new()),
        (
            "produces_files=[out/x.bin]",
            vec![SmolStr::new("out/x.bin")],
        ),
    ]
}

// ── Confinement vs cacheability — the DERIVATION half of the refusal ────────

/// The predicate `ExecutionProgramStage::should_confine_to_declared_inputs`
/// MEANS: nothing in this class's DECLARED semantics requires an undeclared,
/// ambient host input.
///
/// Transcribed INDEPENDENTLY here — the matrix-side statement of the same
/// predicate lives in `kata_types::execution_class`'s
/// `needs_no_ambient_host_input` (`crates/types/src/execution_class/tests.rs`).
/// Two transcriptions rather than one shared helper is the same choice
/// `expected_valid_closed_world` makes against
/// `CheckedExecutionClass::validate` — a shared bug is unlikely to hide in both.
///
/// Production spells the same predicate as
/// [`crate::execution_program::types::class_needs_no_ambient_host_input`], so
/// this transcription is an independent oracle against a shipped function, and
/// the tests below assert the two AGREE rather than assuming it.
fn needs_no_ambient_host_input(c: CheckedExecutionClass) -> bool {
    c.computation == Computation::ProcessAction
        && c.determinism == Determinism::Deterministic
        && c.containment == Containment::Contained
        && c.network == Network::Offline
        && c.external_issuance == ExternalIssuance::None
        && c.pre_commit_recovery == PreCommitRecovery::RecomputeAllowed
}

/// Over the derivation's WHOLE input space, the
/// confinement verdict is decided by the six axes that describe what an action
/// must REACH, and NOT by the workspace axis that describes what it may write.
///
/// # The GAP TUPLE
///
/// A hermetic, offline, non-issuing shell action holding an unbounded writable
/// tree (`ProcessAction`, `Deterministic`, `Contained`, `MutableCandidate`,
/// `Offline`, issuance `None`, `RecomputeAllowed`) is the one closed-world-VALID
/// tuple by which the confinement selection exceeds the cacheability selection
/// (`confinement_predicate_is_strictly_wider_than_cacheability_by_one_valid_tuple`,
/// `crates/types/src/execution_class/tests.rs`). The DERIVATION reaches it,
/// because that tuple is precisely what a hermetic writable stage with an
/// unbounded output set is.
///
/// # What this asserts, and why each half is needed
///
/// 1. **The gap tuple is REACHABLE.** Non-vacuity for everything below: if the
///    tuple vanished, every remaining assertion would be satisfied by observing
///    nothing.
/// 2. **The shipped predicate agrees with the independent transcription** on
///    every derived class. `class_needs_no_ambient_host_input` is the shipped
///    predicate; [`needs_no_ambient_host_input`] above is a separate spelling of
///    the same six axes. A disagreement means one of them drifted.
///
///    LIMIT: a `should_confine_to_declared_inputs` that read the cacheability
///    conjunction while the helper stayed in place would leave this test GREEN,
///    because it never calls the method. The binding assertion is the
///    confinement bridge inside
///    [`derived_predicates_bridge_the_stage_predicates_on_every_shipped_pack`],
///    which asks the METHOD on every shipped stage; that one goes red, and so
///    does
///    [`a_hermetic_writable_shell_stage_keeps_confinement_and_loses_cacheability`].
/// 3. **The workspace axis does not gate confinement.** For every derived class,
///    the verdict is unchanged when the workspace axis is varied across all four
///    of its values — stated as a QUANTIFIED property rather than as "the four
///    shipped stages still confine", because the shipped corpus is a sample and
///    the decode door is not.
/// 4. **A confining class need not be cacheable.** The gap tuple confines and is
///    NOT content-cache eligible, which is the whole point of the split: an
///    action nobody bounded is the one that most needs bounding.
#[test]
fn confinement_is_decided_without_the_workspace_axis_over_the_whole_derivation() {
    use crate::execution_program::types::class_needs_no_ambient_host_input;

    let profiles = std::collections::BTreeMap::new();
    let mut derived = 0usize;
    let mut confining = 0usize;
    let mut gap = 0usize;
    let mut oracle_disagreements: Vec<String> = Vec::new();
    let mut workspace_sensitive: Vec<String> = Vec::new();
    let mut confining_and_cacheable_gap: Vec<String> = Vec::new();

    for (executor, op) in every_classified_executor_op() {
        for (posture, sandbox) in every_resolved_sandbox() {
            for (outputs, produces) in every_declared_output_closure() {
                let class = super::derive_execution_class_from_parts(
                    super::StagePayload::Op,
                    &op,
                    sandbox.as_ref(),
                    &profiles,
                    &produces,
                )
                .expect("every enumerated posture carries a sandbox")
                .class;
                let site = format!("{executor} / {posture} {outputs}");
                derived += 1;

                // (2) the shipped predicate against the independent oracle.
                let production = class_needs_no_ambient_host_input(class);
                if production != needs_no_ambient_host_input(class) {
                    oracle_disagreements.push(format!("{site}: {class:?}"));
                }
                if production {
                    confining += 1;
                }

                // (3) vary ONLY the workspace axis and re-ask. The verdict must
                // not move. This is the property the repoint bought, stated over
                // every tuple the derivation reaches rather than over the four
                // shipped stages that happen to move today.
                for workspace in [
                    Workspace::None,
                    Workspace::ReadOnly,
                    Workspace::DeclaredOutputs,
                    Workspace::MutableCandidate,
                ] {
                    let perturbed = CheckedExecutionClass { workspace, ..class };
                    if class_needs_no_ambient_host_input(perturbed) != production {
                        workspace_sensitive.push(format!(
                            "{site}: workspace {} flips the confinement verdict {class:?}",
                            workspace.label()
                        ));
                    }
                }

                // (1) + (4) the tuple the re-key mints: confining, and refused by
                // the content cache.
                if production && class.workspace == Workspace::MutableCandidate {
                    gap += 1;
                    if class.is_content_cache_eligible() {
                        confining_and_cacheable_gap.push(format!("{site}: {class:?}"));
                    }
                }
            }
        }
    }

    assert!(
        oracle_disagreements.is_empty(),
        "the shipped `class_needs_no_ambient_host_input` disagreed with this \
         module's independent transcription:\n  {}",
        oracle_disagreements.join("\n  ")
    );
    assert!(
        workspace_sensitive.is_empty(),
        "the confinement predicate still reads the WORKSPACE axis — that is the \
         coupling the repoint removed, and it is how a cacheability demotion \
         silently strips a stage's confinement:\n  {}",
        workspace_sensitive.join("\n  ")
    );
    assert!(
        confining_and_cacheable_gap.is_empty(),
        "an UNBOUNDED writable tree was judged content-cache eligible:\n  {}",
        confining_and_cacheable_gap.join("\n  ")
    );
    // NON-VACUITY. `gap > 0` is the re-key's own receipt: before it, the
    // derivation could not mint a confining `MutableCandidate` at all.
    assert!(
        confining > 0 && gap > 0,
        "the sweep saw {confining} confining classes and {gap} confining-yet-\
         unbounded ones out of {derived}; a zero on either side means the \
         `workspace_from_fs` re-key is not in effect and every assertion above \
         is vacuous"
    );
}

/// **THE DIRECTIVE-LEVEL GUARD the re-key could not land without** — a hermetic
/// `workspace-rw` shell stage KEEPS its confinement stamp and LOSES its
/// cacheability stamp, in one assertion, on a compiled stage.
///
/// # FAILURE MODE this exists for
///
/// Every other assertion on `should_confine_to_declared_inputs` is written over
/// a MODEL stage, which is `MutableCandidate` already, so without this test a
/// change that dropped a hermetic shell stage off the confined arm would go
/// unobserved.
///
/// # What it fixes, and the gap against what it CLAIMS
///
/// It fixes the two STAMP SOURCES —
/// [`ExecutionProgramStage::should_confine_to_declared_inputs`] and
/// [`ExecutionProgramStage::is_content_cacheable`] — which the dispatcher's
/// submit path copies verbatim onto `SandboxDirective::confine_to_declared_inputs`
/// and `SandboxDirective::content_cacheable`. It does NOT run the dispatcher, so
/// it does not observe the ASSEMBLED directive: a defect that dropped the stamp
/// between these verdicts and the directive would pass here.
#[test]
fn a_hermetic_writable_shell_stage_keeps_confinement_and_loses_cacheability() {
    // The exact shape of the four shipped stages that move:
    // `agent = "shell"` + `exec = "bwrap"` + `net = "offline"` +
    // `fs = "workspace-rw"`, declaring no `produces_files=`.
    let program = compile_wf(
        r#"
b = stage(id = "b", agent = "shell", run = "make", sandbox = "h")
workflow(
    "wf",
    root = [b],
    sandbox_profiles = {"h": sandbox_profile(workspace = "rw", net = "offline")},
)
"#,
    );
    let s = stage(&program, "b");
    assert!(
        s.produces_files.is_empty(),
        "the fixture must declare NO output closure — that is what the four \
         shipped stages do and what makes the demotion correct"
    );
    assert_eq!(
        s.execution_class.workspace,
        Workspace::MutableCandidate,
        "an undeclared, unenforced output set is a writable tree nobody bounded"
    );
    assert!(
        !s.is_content_cacheable(),
        "a MutableCandidate workspace is never content-cache eligible — this is \
         the content-cache eligibility rule"
    );
    assert_eq!(
        s.should_confine_to_declared_inputs(),
        crate::execution_program::types::class_needs_no_ambient_host_input(s.execution_class),
        "the shipped method must BE the honest predicate, not merely agree with \
         it on this fixture"
    );
    assert!(
        s.should_confine_to_declared_inputs(),
        "CONFINEMENT MUST SURVIVE THE DEMOTION. If this is red, the stage just \
         moved off the hermetic bwrap arm — operator `$PATH` auto-mount back, \
         `$HOME` bound, resolver + TLS bound — as collateral damage from a \
         cacheability correction, which is exactly the coupling the repoint of \
         `should_confine_to_declared_inputs` removed."
    );

    // The CONTROL: the sibling that does NOT move. A `workspace-ro` hermetic
    // shell stage keeps BOTH stamps, so the assertions above are discriminating
    // a real split rather than reporting a predicate that is constant.
    let ro = compile_wf(
        r#"
b = stage(id = "b", agent = "shell", run = "true", sandbox = "ro")
workflow(
    "wf",
    root = [b],
    sandbox_profiles = {"ro": sandbox_profile(net = "offline")},
)
"#,
    );
    let ro = stage(&ro, "b");
    assert_eq!(ro.execution_class.workspace, Workspace::ReadOnly);
    assert!(ro.is_content_cacheable());
    assert!(ro.should_confine_to_declared_inputs());
}

/// **A model/agent stage is excluded from declared-input confinement by
/// TWO INDEPENDENT conjuncts**, read off the DERIVATION rather than constructed,
/// over every sandbox posture a model stage can be authored with.
///
/// # FAILURE MODE this guards
///
/// A confined agent stage loses the `$PATH` entry and `$HOME` its CLI resolves
/// through, so the stage cannot launch. The pincer that makes it decisive: a
/// model stage is a `ProcessAction`,
/// the matrix refuses `ProcessAction + InProcess` (R3), and `HostUnconfined` is
/// refused at compile by `[containment] require_contained_model_stages` (shipped
/// node default `true`) — so confining model stages leaves no way to author a
/// working agent stage at all.
///
/// # Why TWO conjuncts and not one
///
/// `derive_process_class` sets `determinism = Nondeterministic` for every model
/// executor UNCONDITIONALLY, and `external_issuance = DurableActivity` whenever
/// `is_model || network != Offline` — the `is_model` disjunct fires even for an
/// OFFLINE model stage. R13 then forces recovery off `RecomputeAllowed`. So a
/// future edit that relaxed exactly ONE conjunct would still not start confining
/// agent stages; it takes two.
#[test]
fn every_derived_model_class_fails_confinement_on_determinism_and_on_issuance() {
    let profiles = std::collections::BTreeMap::new();
    let mut model_rows = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    for (executor, op) in every_classified_executor_op() {
        if !executor.starts_with("model:") {
            continue;
        }
        for (posture, sandbox) in every_resolved_sandbox() {
            for (outputs, produces) in every_declared_output_closure() {
                let class = super::derive_execution_class_from_parts(
                    super::StagePayload::Op,
                    &op,
                    sandbox.as_ref(),
                    &profiles,
                    &produces,
                )
                .expect("every enumerated posture carries a sandbox")
                .class;
                let posture = format!("{posture} {outputs}");
                model_rows += 1;

                // Conjunct 1 — the determinism claim is never made.
                if class.determinism != Determinism::Nondeterministic {
                    offenders.push(format!(
                        "{executor} / {posture}: claims determinism {class:?}"
                    ));
                }
                // Conjunct 2 — issuance is always durable, INDEPENDENTLY of the
                // network posture (the `is_model` disjunct).
                if class.external_issuance != ExternalIssuance::DurableActivity {
                    offenders.push(format!("{executor} / {posture}: issues nothing {class:?}"));
                }
                // …and therefore the predicate refuses it, twice over. Asked of
                // the SHIPPED predicate as well as this module's transcription:
                // `should_confine_to_declared_inputs` reads
                // `class_needs_no_ambient_host_input`, so a drift between the
                // two would otherwise leave this test green while production
                // confined an agent stage.
                if needs_no_ambient_host_input(class)
                    || crate::execution_program::types::class_needs_no_ambient_host_input(class)
                {
                    offenders.push(format!("{executor} / {posture}: CONFINABLE {class:?}"));
                }
                if class.is_content_cache_eligible() {
                    offenders.push(format!("{executor} / {posture}: cacheable {class:?}"));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a model/agent stage became confinable — a confined wrap binds no `$HOME` \
         and its CLI cannot resolve:\n  {}",
        offenders.join("\n  ")
    );
    assert!(
        // 3 model executors × 25 postures (2 backends × 6 fs × 2 net, plus the
        // undeclared arm — 37 while `firecracker` was a third backend) × 2.
        model_rows >= 3 * 25 * 2,
        "non-vacuity: expected every model executor label across every sandbox \
         posture across both declared-output-closure points, saw {model_rows} rows"
    );
}

// ── The one `Network` value with no `NetPolicy` preimage ───────────────────

/// `Network::BrokeredOnly` is unreachable from any authorable workflow, and the
/// reason is this LOWERING rather than a refusal anywhere.
///
/// # Why this test exists
///
/// Five doc sites (four in `kata-types`, one in `kata-worker`'s
/// certification-face test) said a `BrokeredOnly` class was *"refused at
/// placement (no certified broker)"*. It is not refused anywhere — placement
/// reads no class at all (`Dispatcher::select_capsule_worker` asks every
/// capsule's worker the one constant `CAPSULE_PLACEMENT`), and no production
/// code reads `BrokeredOnly`. `kata_types`'s
/// `brokered_only_is_accepted_if_carried_enforced_as_profile_and_refused_nowhere`
/// states the refused-nowhere half. This is the other half: the value is
/// unreachable because [`super::derive_process_class`] — the ONE place a
/// resolved sandbox posture becomes a checked class — is exhaustive over the two
/// shipped `NetPolicy` variants and mints only `Offline`/`Unrestricted`.
///
/// That distinction is load-bearing: a reader of "refused at placement" could
/// conclude a broker fence test is buildable, when in fact the class has no
/// producer and any such rig would have to mint one by hand — a property of the
/// rig.
///
/// # Non-vacuity
///
/// A sweep that derived NOTHING would satisfy "no arm yields `BrokeredOnly`" for
/// free, so the derived set is asserted to be EXACTLY `{Offline, Unrestricted}`
/// — both present — rather than merely brokered-free.
#[test]
fn brokered_only_is_the_one_network_value_the_lowering_cannot_mint() {
    use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy};

    use super::{Executor, SandboxResolution, derive_process_class};

    let mut derived: Vec<Network> = vec![
        // The undeclared/unresolvable arm, which never consults a `NetPolicy`.
        derive_process_class(Executor::Shell, SandboxResolution::HostUnconfined, &[]).network,
        derive_process_class(Executor::Model, SandboxResolution::HostUnconfined, &[]).network,
    ];

    for net in NetPolicy::SHIPPED {
        for exec in ExecBackend::all() {
            for fs in [
                FsPolicy::Host,
                FsPolicy::WorkspaceRo,
                FsPolicy::WorkspaceRw,
                FsPolicy::Scratch,
            ] {
                for executor in [Executor::Shell, Executor::Model] {
                    let class = derive_process_class(
                        executor,
                        SandboxResolution::Declared {
                            exec: exec.clone(),
                            fs: fs.clone(),
                            net: net.clone(),
                        },
                        // The network axis does not read the output closure at
                        // all; the empty set is the shipped-stage majority and
                        // keeps this sweep about `NetPolicy`.
                        &[],
                    );
                    assert_ne!(
                        class.network,
                        Network::BrokeredOnly,
                        "MEASURED CHANGE: the lowering minted `brokered_only` from \
                         net={net:?} exec={exec:?} fs={fs:?}. `BrokeredOnly` now HAS a \
                         preimage, so the accepted-if-carried / enforced-as-profile / \
                         refused-nowhere wording must be re-derived.",
                    );
                    derived.push(class.network);
                }
            }
        }
    }

    derived.sort_unstable_by_key(|network| network.label());
    derived.dedup();
    assert_eq!(
        derived,
        vec![Network::Offline, Network::Unrestricted],
        "the lowering's whole image must be {{offline, unrestricted}} — both present, \
         so the absence of `brokered_only` is a measurement rather than an empty sweep"
    );
}

/// **A MODEL STAGE CAN NEVER BE CONFINED, stated as a closed-world property.**
///
/// [`crate::execution_program::types::class_needs_no_ambient_host_input`] —
/// the predicate `should_confine_to_declared_inputs` now IS — conjoins
/// `Determinism::Deterministic`. That single conjunct is what makes an agent or
/// model stage unconfinable, and it is load-bearing outside the class:
/// `kata_workflow::capsule_assembly` mints the declared-reads `/work` view
/// (`CapsuleWorkView`) from `should_confine_to_declared_inputs`, so a confinable
/// model stage would run its agent inside a view narrowed to its declared reads.
///
/// # Why this exists as a SEPARATE test from the model sweep
///
/// [`every_derived_model_class_fails_confinement_on_determinism_and_on_issuance`]
/// asks the question of the DERIVATION IMAGE, over classes derived from shipped
/// executors. This one asks it of the CLOSED-WORLD PRODUCT — all 1,728 tuples,
/// including the ones only the decode door can present. A carried class arrives
/// at the worker without passing the derivation, so the derivation image is the
/// wrong domain for a property the worker depends on.
///
/// # WHAT THIS DOES NOT LICENSE
///
/// The entailment is a fact about the PREDICATE over CLASSES, not a licence to
/// use one directive bit as a proxy for another axis: a directive carries
/// `confine_to_declared_inputs` and `content_cacheable` as two booleans and no
/// class, and a directive can be confined AND nondeterministic.
///
/// # REFUSES vs CLAIMS
///
/// REFUSES: any tuple in the closed-world product the shipped predicate ACCEPTS
/// while carrying `Nondeterministic`.
///
/// CLAIMS nothing about the CONVERSE — a deterministic class need not confine (a
/// deterministic `net = "host"` stage does not) — and nothing about what any
/// consumer of the confinement bit may infer from it.
#[test]
fn a_nondeterministic_class_can_never_be_confined_over_the_closed_world_product() {
    use crate::execution_program::types::class_needs_no_ambient_host_input;

    let mut swept = 0usize;
    let mut confining = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for computation in [
        Computation::PureTransform,
        Computation::ProcessAction,
        Computation::WaitForInput,
    ] {
        for determinism in [Determinism::Deterministic, Determinism::Nondeterministic] {
            for containment in [
                Containment::InProcess,
                Containment::Contained,
                Containment::HostUnconfined,
            ] {
                for workspace in [
                    Workspace::None,
                    Workspace::ReadOnly,
                    Workspace::DeclaredOutputs,
                    Workspace::MutableCandidate,
                ] {
                    for network in [
                        Network::Offline,
                        Network::BrokeredOnly,
                        Network::Unrestricted,
                    ] {
                        for external_issuance in
                            [ExternalIssuance::None, ExternalIssuance::DurableActivity]
                        {
                            for pre_commit_recovery in [
                                PreCommitRecovery::RecomputeAllowed,
                                PreCommitRecovery::AwaitRecordedInput,
                                PreCommitRecovery::ReconcileRequired,
                                PreCommitRecovery::ManualResolution,
                            ] {
                                let class = CheckedExecutionClass {
                                    computation,
                                    determinism,
                                    containment,
                                    workspace,
                                    network,
                                    external_issuance,
                                    pre_commit_recovery,
                                };
                                swept += 1;
                                if !class_needs_no_ambient_host_input(class) {
                                    continue;
                                }
                                confining += 1;
                                if class.determinism != Determinism::Deterministic {
                                    violations.push(format!("{class:?}"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    assert_eq!(
        swept, 1728,
        "the closed-world product must be swept exhaustively; an axis gained or \
         lost a variant and this sweep was not updated (swept={swept})"
    );
    // Non-vacuity in BOTH directions: a predicate that accepted nothing, or
    // everything, would satisfy the entailment while proving nothing.
    assert!(
        confining > 0 && confining < swept,
        "the confinement predicate must select a PROPER, NON-EMPTY subset of the \
         product, else the entailment below is vacuous \
         (confining={confining}, swept={swept})"
    );
    assert!(
        violations.is_empty(),
        "`class_needs_no_ambient_host_input` accepted {} NONDETERMINISTIC \
         class(es), so `capsule_assembly` would narrow a nondeterministic stage's \
         `/work` to its declared reads. Either \
         restore the `Determinism::Deterministic` conjunct, or give the directive \
         its own determinism bit before relaxing this one:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

/// A `Custom` mount is HOST state, and a host-state filesystem may never derive
/// `Deterministic` — which is what makes it content-cache eligible.
///
/// A stage with a contained, offline profile and a custom mount binding `/` at
/// `/` WRITABLE, plus `produces_files` and `cache_policy="content_cache"`, must
/// not derive `determinism=deterministic` / `content_cache_eligible=true`:
/// it would read and write the whole host while its result was
/// content-addressed as a hermetic function of its declared inputs. A narrow
/// `matches!(fs, Some(FsPolicy::Host))` steps over it — `Custom` is not `Host` —
/// which is why `FsPolicy::reaches_host_state` owns the question.
///
/// READ-ONLY IS NOT SAFE EITHER, and the sweep below asserts both: the mounted
/// host path's CONTENT is not a component of any cache key kata computes, so two
/// runs against different host state collide on one key.
#[test]
fn a_custom_mount_is_host_state_and_never_derives_deterministic() {
    use crate::execution_program::execution_class::{
        Executor, SandboxResolution, derive_process_class,
    };
    use kata_types::execution_class::Determinism;
    use kata_types::sandbox::{ExecBackend, FsPolicy, MountSpec, NetPolicy, SandboxProfile};

    for writable in [false, true] {
        let profile = SandboxProfile {
            exec: ExecBackend::Oci,
            fs: FsPolicy::Custom {
                mounts: vec![MountSpec {
                    host_path: "/".into(),
                    mount_point: "/".into(),
                    writable,
                }],
            },
            net: NetPolicy::Offline,
            secrets: std::collections::BTreeMap::new(),
            locked: false,
            image: None,
            toolchain: None,
            rootfs: None,
            requires: Vec::new(),
        };
        let class = derive_process_class(
            Executor::Shell,
            SandboxResolution::Declared {
                exec: profile.exec.clone(),
                fs: profile.fs.clone(),
                net: profile.net.clone(),
            },
            &["out.txt".into()],
        );
        assert_eq!(
            class.determinism,
            Determinism::Nondeterministic,
            "a custom mount of the host root (writable={writable}) derived Deterministic"
        );
        assert!(
            !class.is_content_cache_eligible(),
            "a custom mount of the host root (writable={writable}) is content-cache eligible: \
             {class:?}"
        );
    }
}
