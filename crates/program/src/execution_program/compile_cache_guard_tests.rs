//! Load-guard proofs for ADR-0001's "mutable candidate work represented by
//! envelope-only replay" refusal.
//!
//! The `cache_policy=model_reuse` guard in [`compile_execution_program_with_options`]
//! must key on the DERIVED execution class, never on the agent LABEL. A
//! `model_reuse` cache HIT replays only the recorded output envelope; it never
//! re-performs the stage's file writes. So any stage whose derived class is
//! workspace-mutating (or an adapter issuance) must be refused at load,
//! regardless of whether its executor happens to wear a "deterministic" label.
//!
//! The label and the class DISAGREE for real, authorable configurations: a
//! `shell` stage wears a deterministic label while its derived class can be
//! workspace-mutating, and a label-keyed conjunct would silently accept that
//! unsound work.
//!
//! [`compile_execution_program_with_options`]: super::compile_execution_program_with_options

use super::compile_starlark_execution_program;

/// THE `oci` PROFILE GATE: under `oci`, a `model_reuse` stage's mutating-class
/// legs are dropped for an AGENT stage — a capsule hit adopts the source's
/// recorded `/work` delta, so the writes ARE reproduced — while a NON-agent
/// `model_reuse` stage never reaches this guard at all: the profile door
/// (`refuse_program_under_capsule_profile`, run before this loop) refuses the
/// regime on every stage that is not an agent capsule. So the shell variant
/// below hears the profile door's refusal (naming the AGENT capsule the route
/// serves), not clause 4's — the refused set is the same, the arm it comes
/// from is not.
///
/// **Watched red:** with the `capsule_model_reuse` conjunct removed, the agent
/// variant below refuses `cache_policy=model_reuse` under `oci` on the
/// workspace-write leg (clause 4's refusal).
#[test]
fn under_oci_the_mutating_refusal_splits_on_agent_class() {
    kata_types::node_profile::mark_node_installed();
    let refusal = compile_starlark_execution_program(
        r#"
s = stage(
    id = "s",
    agent = "shell",
    run = "make build",
    cache_policy = "model_reuse",
    sandbox = "build",
)
workflow(
    "model-reuse-shell-rw-oci",
    root = [s],
    sandbox_profiles = {"build": sandbox_profile(workspace = "rw", net = "offline")},
)
"#,
        "model_reuse_shell_rw_oci.star",
        &[],
    )
    .expect_err("a shell stage's model_reuse is refused under oci whichever class it derives")
    .to_string();
    assert!(
        refusal.contains("AGENT capsule"),
        "the profile door — not clause 4 — refuses a non-agent's model_reuse \
         under oci: {refusal}"
    );
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([(
        "codex".to_owned(),
        kata_types::config::AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: Some("nanocode_openai".to_owned()),
            credential: Some(kata_types::config::AgentCredentialDecl {
                mode: "subscription".to_owned(),
                source: "kata_login".to_owned(),
            }),
            env: std::collections::BTreeMap::new(),
        },
    )]));
    compile_starlark_execution_program(
        r#"
s = stage(
    id = "s",
    agent = "codex",
    prompt = "edit the tree and report",
    cache_policy = "model_reuse",
    sandbox = "build",
)
workflow(
    "model-reuse-agent-rw-oci",
    root = [s],
    sandbox_profiles = {"build": sandbox_profile(workspace = "rw", net = "offline")},
)
"#,
        "model_reuse_agent_rw_oci.star",
        &[],
    )
    .expect("under oci an agent stage's mutation is carried by the recorded delta");
}
