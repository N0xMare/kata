//! The CONFINED DEFAULT, read off the production lowering and dispatch paths.
//!
//! An unauthored stage lowers to an EXPLICIT confined directive.
//! The default `fs` is `workspace-ro`.
//! `sandbox = "host"` is the reserved, only, explicit opt-out.
//! No containment-defeat lever is read: under the one engine no defeat lever
//!     has a reader, and a refusal of an unenforced defeat would refuse more
//!     than any mechanism enforces.
//! `sandbox_profile()` takes no backend, filesystem-policy or pool keyword.
//!
//! Nothing here mirrors the derivation: each assertion reads the lowered
//! `ExecutionProgram` a pack compiles to, or the error the compiler returns.

use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_types::execution_class::{Containment, Determinism, Network, Workspace};
use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy, SandboxRef};
use kata_types::workflow::StageId;
use smol_str::SmolStr;

fn compile(src: &str) -> kata_types::KataResult<ExecutionProgram> {
    compile_starlark_execution_program(src, "confined_default.star", &[])
}

fn stage<'a>(
    program: &'a ExecutionProgram,
    id: &str,
) -> &'a kata_program::execution_program::ExecutionProgramStage {
    program
        .stages
        .get(&StageId(SmolStr::new(id)))
        .unwrap_or_else(|| panic!("stage {id} exists"))
}

fn inline_profile(
    stage: &kata_program::execution_program::ExecutionProgramStage,
) -> &kata_types::sandbox::SandboxProfile {
    match stage.policies.sandbox.as_ref() {
        Some(SandboxRef::Inline(profile)) => profile,
        other => panic!(
            "stage {} must carry an EXPLICIT inline sandbox after lowering, got {other:?}",
            stage.stage_id.0
        ),
    }
}

// ---------------------------------------------------------------------------
// The plain `run=` stage
// ---------------------------------------------------------------------------

/// A plain `run=` stage that authors NOTHING is lowered with the explicit
/// confined default — `oci`, `workspace-ro`, `offline` — derives the hermetic
/// read-only class, and is content-cache eligible by class — never `None` and
/// never `HostUnconfined`.
#[test]
fn a_plain_run_stage_lowers_to_the_explicit_confined_default() {
    let program = compile(
        r#"
s = stage(id = "s", agent = "shell", run = "printf '{}\n'")
workflow("plain", root = [s])
"#,
    )
    .expect("a plain stage compiles");
    let s = stage(&program, "s");
    let profile = inline_profile(s);
    assert_eq!(profile.exec, ExecBackend::Oci, "confined");
    assert_eq!(profile.fs, FsPolicy::WorkspaceRo, "read-only workspace");
    assert_eq!(profile.net, NetPolicy::Offline, "confined-OFFLINE");
    assert_eq!(profile.toolchain, None);
    assert_eq!(profile.rootfs, None);
    assert_eq!(s.execution_class.containment, Containment::Contained);
    assert_eq!(s.execution_class.workspace, Workspace::ReadOnly);
    assert_eq!(s.execution_class.network, Network::Offline);
    assert_eq!(s.execution_class.determinism, Determinism::Deterministic);
    assert!(
        s.is_content_cacheable(),
        "a plain stage is content-cache eligible BY CLASS under the confined default — the \
         population the node-default root exists to serve"
    );
    assert!(
        s.should_confine_to_declared_inputs(),
        "and it is held to its declared inputs, so the node-default root applies"
    );
}

/// The materialized default IS `sandbox_profile()` with no arguments: the two
/// spellings lower to the same profile and the same contract hash, so the
/// default is not a second posture an author cannot see.
#[test]
fn the_materialized_default_is_byte_identical_to_an_empty_sandbox_profile() {
    let implicit = compile(
        r#"
s = stage(id = "s", agent = "shell", run = "true")
workflow("w", root = [s])
"#,
    )
    .expect("compiles");
    let explicit = compile(
        r#"
s = stage(id = "s", agent = "shell", run = "true", sandbox = sandbox_profile())
workflow("w", root = [s])
"#,
    )
    .expect("compiles");
    assert_eq!(
        stage(&implicit, "s").policies.sandbox,
        stage(&explicit, "s").policies.sandbox
    );
    assert_eq!(
        stage(&implicit, "s").contract_hash,
        stage(&explicit, "s").contract_hash,
        "the default is materialized, not derived late: the two programs carry one contract"
    );
}

// ---------------------------------------------------------------------------
// The confined default on a MODEL stage — the CLI must stay reachable
// ---------------------------------------------------------------------------

/// A model stage that authors no sandbox is confined exactly as a shell stage
/// is — `oci`, `workspace-ro`, `net = offline` — and lowers to the same
/// profile and contract hash as the same stage authoring `sandbox =
/// sandbox_profile()`. `offline` grants none of the node's `[node]
/// egress_allow`, and the capsule reaches nothing: the turn's model calls
/// leave from the process hosting the worker
/// (`capsule_rules::capsule_network_for`, pinned in `capsule_assembly.rs`).
/// Its class is `Nondeterministic`, so the confined arm that strips the agent
/// CLI (`should_confine_to_declared_inputs`: toolchain-only `PATH`, no
/// `$HOME`) is NOT selected for it. The rule is `materialize_sandbox`'s
/// executor match.
#[test]
fn a_model_stage_authoring_no_sandbox_is_confined_offline_and_keeps_its_cli_reachable() {
    let program = compile(
        r#"
s = stage(id = "s", agent = "codex", prompt = "inspect and report")
workflow("model", root = [s])
"#,
    )
    .expect("a plain model stage compiles under the shipped containment policy");
    let explicit = compile(
        r#"
s = stage(id = "s", agent = "codex", prompt = "inspect and report", sandbox = sandbox_profile())
workflow("model", root = [s])
"#,
    )
    .expect("the explicit spelling compiles");
    let s = stage(&program, "s");
    let profile = inline_profile(s);
    assert_eq!(profile.exec, ExecBackend::Oci);
    assert_eq!(profile.fs, FsPolicy::WorkspaceRo);
    assert_eq!(
        profile.net,
        NetPolicy::Offline,
        "a model executor's default reaches none of the node's egress"
    );
    assert_eq!(
        s.policies.sandbox,
        stage(&explicit, "s").policies.sandbox,
        "the model default is `sandbox_profile()`"
    );
    assert_eq!(
        s.contract_hash,
        stage(&explicit, "s").contract_hash,
        "the two spellings carry one contract"
    );
    assert_eq!(s.execution_class.containment, Containment::Contained);
    assert_eq!(s.execution_class.determinism, Determinism::Nondeterministic);
    assert_eq!(
        s.execution_class.network,
        Network::Unrestricted,
        "a model stage's class claims no offline network whatever `net` says"
    );
    assert!(
        !s.is_content_cacheable(),
        "a model stage is never content-cacheable"
    );
    assert!(
        !s.should_confine_to_declared_inputs(),
        "the toolchain-only / no-$HOME arm must not be selected for a model stage: that arm \
         strips the host agent CLI the stage spawns"
    );
}

/// The API surface shares the model-stage default: `POST /api/v1/agents/run`
/// with `sandbox` omitted compiles (`compile_agent_run_execution_program`) a
/// synthetic model stage that authors no sandbox, so it lowers to the same
/// confined `oci` / `workspace-ro` / `offline` profile as a Starlark model
/// stage authoring none — never the node's `[node] egress_allow`.
///
/// **Would red if:** the model-stage arm of `materialize_sandbox` returned
/// `net = host`, or the agent-run compiler filled an omitted `sandbox` with a
/// directive of its own.
#[test]
fn an_agent_run_omitting_sandbox_lowers_to_the_confined_offline_default() {
    let request: kata_types::agent_run::AgentRunRequest = serde_json::from_value(
        serde_json::json!({"prompt": "inspect and report", "agent": "codex"}),
    )
    .expect("a minimal agent-run request parses");
    assert!(request.sandbox.is_none(), "the request authors no sandbox");
    let program = kata_program::execution_program::compile_agent_run_execution_program(&request)
        .expect("a sandbox-less agent run compiles");
    assert_eq!(program.stages.len(), 1, "one synthetic stage");
    let s = program.stages.values().next().expect("one stage");
    let profile = inline_profile(s);
    assert_eq!(profile.exec, ExecBackend::Oci);
    assert_eq!(profile.fs, FsPolicy::WorkspaceRo);
    assert_eq!(
        profile.net,
        NetPolicy::Offline,
        "an agent run omitting `sandbox` reaches none of the node's egress"
    );
    assert_eq!(s.execution_class.containment, Containment::Contained);
}

/// An agent run's `sandbox: {}` (every field left to its default) IS the omitted
/// field: the two compile to the same stage `SandboxProfile` — `oci`,
/// `workspace_ro`, `offline` — and the same program hash, and so does a request
/// spelling those defaults out. `{}` once selected an all-host directive, which
/// CHECK refuses under the one engine.
///
/// **Would red if:** a `ByoSandboxRequest` field defaulted to anything but the
/// model-stage default (`{}` is refused `host_sandbox_unsupported_under_oci`), or a
/// request equal to the default authored an inline profile of its own (the program
/// hash differs from the omitted field's).
#[test]
fn an_agent_run_s_empty_sandbox_is_the_omitted_sandbox() {
    let compile_run = |body: serde_json::Value| {
        let request: kata_types::agent_run::AgentRunRequest =
            serde_json::from_value(body).expect("the agent-run request parses");
        kata_program::execution_program::compile_agent_run_execution_program(&request)
    };
    let omitted =
        compile_run(serde_json::json!({"prompt": "inspect and report", "agent": "codex"}))
            .expect("a sandbox-less agent run compiles");
    let omitted_profile =
        inline_profile(omitted.stages.values().next().expect("one stage")).clone();
    for body in [
        serde_json::json!({"prompt": "inspect and report", "agent": "codex", "sandbox": {}}),
        serde_json::json!({
            "prompt": "inspect and report",
            "agent": "codex",
            "sandbox": {"exec": "oci", "fs": "workspace_ro", "net": "offline"},
        }),
    ] {
        let program = compile_run(body.clone())
            .unwrap_or_else(|error| panic!("{body}: the default sandbox compiles: {error}"));
        assert_eq!(
            inline_profile(program.stages.values().next().expect("one stage")),
            &omitted_profile,
            "{body}: the same profile as the omitted field"
        );
        assert_eq!(
            program.program_hash, omitted.program_hash,
            "{body}: the same program as the omitted field"
        );
    }
}

/// An agent run that asks for host execution explicitly is judged as before: the
/// all-host directive (`{"exec": "host", "fs": "host", "net": "host"}`, what `{}`
/// once meant) is refused `host_sandbox_unsupported_under_oci` at CHECK, and
/// `{"exec": "host"}` alone — `host` beside the defaults `workspace_ro` and
/// `offline` — is refused too, as the host-and-offline pair no host stage can
/// enforce. A request differing from the default in `net` alone (`"host"`)
/// authors an inline profile with that field and the defaults beside it.
#[test]
fn an_agent_run_s_explicit_host_exec_is_refused_at_check() {
    let refusal = |sandbox: serde_json::Value| {
        let request: kata_types::agent_run::AgentRunRequest = serde_json::from_value(
            serde_json::json!({"prompt": "inspect and report", "agent": "codex", "sandbox": sandbox}),
        )
        .expect("the agent-run request parses");
        kata_program::execution_program::compile_agent_run_execution_program(&request)
            .expect_err("a host exec is refused at CHECK")
            .to_string()
    };
    let all_host = refusal(serde_json::json!({"exec": "host", "fs": "host", "net": "host"}));
    assert!(
        all_host.contains("host_sandbox_unsupported_under_oci"),
        "refused by name: {all_host}"
    );
    let host_exec = refusal(serde_json::json!({"exec": "host"}));
    assert!(
        host_exec.contains("`host` exec backend with `net = \"offline\"` is not supported"),
        "refused naming the pair: {host_exec}"
    );
    let request: kata_types::agent_run::AgentRunRequest = serde_json::from_value(
        serde_json::json!({"prompt": "inspect and report", "agent": "codex", "sandbox": {"net": "host"}}),
    )
    .expect("the agent-run request parses");
    let program = kata_program::execution_program::compile_agent_run_execution_program(&request)
        .expect("an oci run with host networking compiles");
    let profile = inline_profile(program.stages.values().next().expect("one stage"));
    assert_eq!(profile.exec, ExecBackend::Oci);
    assert_eq!(profile.fs, FsPolicy::WorkspaceRo);
    assert_eq!(profile.net, NetPolicy::Host);
}

/// The word cannot be shadowed: a `sandbox_profiles` entry named `host` is
/// refused at load, naming the reservation.
#[test]
fn a_profile_named_host_is_refused_so_the_opt_out_cannot_be_redefined() {
    let err = compile(
        r#"
s = stage(id = "s", agent = "shell", run = "true", sandbox = "host")
workflow(
    "shadow",
    root = [s],
    sandbox_profiles = {"host": sandbox_profile(net = "offline")},
)
"#,
    )
    .expect_err("a profile named `host` must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("reserved") && msg.contains("\"host\""),
        "the refusal must name the reservation: {msg}"
    );
}

// ---------------------------------------------------------------------------
// The keyword surface is the signature
// ---------------------------------------------------------------------------

/// A keyword `sandbox_profile()`'s signature does not declare is refused when the
/// pack compiles, naming it — `exec=`, `fs=` and `pool=` included — never ignored.
///
/// **Watched red:** with a `#[starlark(kwargs)]` catch-all added to the signature
/// and left unread, every leg compiles.
#[test]
fn a_keyword_sandbox_profile_does_not_declare_is_refused_naming_it() {
    for (kwarg, value) in [
        ("exec", "\"bwrap\""),
        ("fs", "\"workspace-rw\""),
        ("pool", "{\"min\": 1}"),
    ] {
        let error = compile(&format!(
            "s = stage(id = \"s\", agent = \"shell\", run = \"true\", sandbox = \
             sandbox_profile({kwarg} = {value}, net = \"offline\"))\n\
             workflow(\"unknown-kwarg\", root = [s])\n"
        ))
        .expect_err("an undeclared keyword must refuse")
        .to_string();
        assert!(
            error.contains(&format!("Found `{kwarg}` extra named parameter(s)"))
                && error.contains("sandbox_profile"),
            "the refusal names the keyword and the call: {error}"
        );
    }
    // NON-VACUITY: the same profile without the keyword compiles.
    compile(
        r#"
s = stage(id = "s", agent = "shell", run = "true", sandbox = sandbox_profile(net = "offline"))
workflow("declared-kwargs", root = [s])
"#,
    )
    .expect("a profile of declared keywords compiles");
}

/// The surviving view kwarg: `workspace = "rw"` is the one way to a writable
/// workspace, and it is `MutableCandidate` (never content-cacheable) without a
/// bounded output closure — unchanged from `fs = "workspace-rw"`.
#[test]
fn workspace_rw_is_the_surviving_spelling_of_a_writable_view() {
    let program = compile(
        r#"
s = stage(id = "s", agent = "shell", run = "touch out", sandbox = sandbox_profile(workspace = "rw"))
workflow("rw", root = [s])
"#,
    )
    .expect("compiles");
    let s = stage(&program, "s");
    assert_eq!(inline_profile(s).fs, FsPolicy::WorkspaceRw);
    assert_eq!(
        inline_profile(s).net,
        NetPolicy::Offline,
        "net still defaults to offline"
    );
    assert_eq!(s.execution_class.workspace, Workspace::MutableCandidate);
    assert!(!s.is_content_cacheable());
}

// ---------------------------------------------------------------------------
// The corpus census, derived by the lowering itself
// ---------------------------------------------------------------------------

/// No process stage of any shipped pack carries `None` after lowering, and the
/// only stages that do are in-process workspace effects. This is the confined
/// default measured over the corpus rather than asserted on one fixture.
#[test]
fn no_shipped_process_stage_carries_none_after_lowering() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("repo root")
        .to_path_buf();
    let roots = vec![root.join("workflows")];
    let mut packs = Vec::new();
    for dir in ["std", "kata-factory", "examples", "smoke"] {
        collect(&root.join("workflows").join(dir), &mut packs);
    }
    assert!(
        packs.len() >= 20,
        "premise: the corpus was found ({} packs)",
        packs.len()
    );
    let mut process_stages = 0usize;
    let mut effects = 0usize;
    let mut compiled = 0usize;
    for pack in &packs {
        let Ok(program) =
            kata_program::execution_program::compile_execution_program_from_file(pack, &roots)
        else {
            continue; // libraries that never drain at module scope
        };
        compiled += 1;
        for stage in program.stages.values() {
            let is_effect = stage.op.agent_label.as_deref()
                == Some(kata_types::workflow::WORKSPACE_EFFECT_AGENT_LABEL)
                || stage.op.agent.as_str() == kata_types::workflow::WORKSPACE_EFFECT_AGENT_LABEL;
            if is_effect {
                effects += 1;
                assert_eq!(
                    stage.policies.sandbox,
                    None,
                    "{}: an effect carries no sandbox",
                    pack.display()
                );
            } else {
                process_stages += 1;
                assert!(
                    stage.policies.sandbox.is_some(),
                    "{}::{} is a process stage carrying NO sandbox after lowering",
                    pack.display(),
                    stage.stage_id.0
                );
            }
        }
    }
    println!(
        "CONFINED-DEFAULT packs_compiled={compiled} process_stages={process_stages} effect_stages={effects}"
    );
    assert!(compiled >= 20 && process_stages >= 100);
}

fn collect(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "star") {
            out.push(path);
        }
    }
}
