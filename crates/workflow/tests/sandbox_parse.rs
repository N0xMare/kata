//! Integration coverage for the sandbox-aware Starlark
//! compiler projection.
//!
//! Two tests, one per sandbox-reference shape:
//!
//!   1. `named_profile_resolves_and_round_trips` — stage refs a
//!      named workflow-local profile; the compiled artifact has the profile
//!      populated, the checked IR stage's `SandboxRef::Named` matches the map
//!      key, and the artifact round-trips through serde_json unchanged.
//!   2. `inline_sandbox_normalizes_to_inline_variant` — stage
//!      declares the profile inline as a table; checked IR produces
//!      `SandboxRef::Inline` with matching fields.
//!
//! The host+offline profile check is pinned by
//! `an_offline_host_profile_is_refused_with_a_recourse_that_exists`
//! (`crates/program/src/parser/validate.rs`): no pack can reach it, because
//! `sandbox_profile()` takes no backend keyword.

use kata_types::error::KataError;
use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy, SandboxRef};
use kata_types::workflow::StageId;
use smol_str::SmolStr;

fn compile_artifact(
    star: &str,
) -> Result<kata_program::preflight::WorkflowCompiledArtifact, KataError> {
    kata_program::preflight::build_starlark_workflow_compiled_artifact(star, "sandbox.star", &[])
}

// ---- Test 1: named profile resolves + serde round-trip ----

#[test]
fn named_profile_resolves_and_round_trips() {
    let star = r#"
build = stage(
    id = "build",
    agent = "worker",
    sandbox = "builder",
    prompt = "build the thing",
)
workflow(
    "sandbox-named",
    root = [build],
    sandbox_profiles = {
        "builder": sandbox_profile(workspace = "rw", net = "offline"),
    },
)
"#;

    let artifact = compile_artifact(star).expect("named-profile workflow must compile");

    // Profile registered at workflow scope.
    let profile = artifact
        .sandbox_profiles
        .get("builder")
        .expect("builder profile must be registered");
    assert_eq!(profile.exec, ExecBackend::Oci);
    assert_eq!(profile.fs, FsPolicy::WorkspaceRw);
    assert_eq!(profile.net, NetPolicy::Offline);

    // Stage ref resolves by name.
    let stage = artifact
        .execution_program
        .stages
        .get(&StageId(SmolStr::new("build")))
        .expect("build stage must exist");
    match stage
        .policies
        .sandbox
        .as_ref()
        .expect("build stage must carry a sandbox ref")
    {
        SandboxRef::Named(name) => {
            assert_eq!(name, "builder");
            assert!(
                artifact.sandbox_profiles.contains_key(name),
                "named sandbox ref \"{name}\" must be present in sandbox_profiles",
            );
        }
        SandboxRef::Inline(_) => panic!("expected Named, got Inline"),
    }

    // JSON round-trip preserves the whole compiled artifact.
    let json = serde_json::to_string(&artifact).expect("serialize");
    let back: kata_program::preflight::WorkflowCompiledArtifact =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, back);
}

// ---- Test 2: inline sandbox normalizes to inline variant ----

#[test]
fn inline_sandbox_normalizes_to_inline_variant() {
    let star = r#"
quick = stage(
    id = "quick",
    agent = "reviewer",
    prompt = "quick review",
    sandbox = sandbox_profile(net = "offline"),
)
workflow("sandbox-inline", root = [quick])
"#;

    let artifact = compile_artifact(star).expect("inline-sandbox workflow must compile");

    // No named profiles — the stage owns its sandbox inline.
    assert!(
        artifact.sandbox_profiles.is_empty(),
        "inline sandbox should not populate sandbox_profiles"
    );

    let stage = artifact
        .execution_program
        .stages
        .get(&StageId(SmolStr::new("quick")))
        .expect("quick stage must exist");
    let sandbox = stage
        .policies
        .sandbox
        .as_ref()
        .expect("quick stage must carry an inline sandbox");
    match sandbox {
        SandboxRef::Inline(profile) => {
            assert_eq!(profile.exec, ExecBackend::Oci);
            assert_eq!(profile.fs, FsPolicy::WorkspaceRo);
            assert_eq!(profile.net, NetPolicy::Offline);
            assert!(
                profile.secrets.is_empty(),
                "inline profile should have no secrets when unspecified"
            );
        }
        SandboxRef::Named(_) => panic!("expected Inline, got Named"),
    }
}
