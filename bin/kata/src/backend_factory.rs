//! Agent-config helpers for the surfaces that still reason about `[agents.*]`
//! on the host: `kata doctor`, `kata config check`, and the supervised node's
//! advertised capability list.
//!
//! There is no host-side backend construction here. Under the OCI capsule
//! route an `agent = "<label>"` stage resolves `[agents.<label>]` through
//! `installed_node_agent` at capsule-assembly time and the embedded harness
//! drives the turn from the worker — so the only host questions this module still
//! answers are config-shape questions: which backend each label declares,
//! which labels exist, and (through
//! [`kata_types::config::AgentBackendConfig::capsule_launch`]) can a declared
//! entry launch a capsule at all.

use kata_types::KataConfig;
use kata_types::config::AgentBackendConfig;
use tracing::warn;

/// The backend an `[agents.<label>]` entry is — `harness` (kata's embedded
/// nanocode harness, the provider named by its `adapter`) or `shell` (the
/// reserved deterministic route) — as `kata config check` and `kata doctor`
/// print it. The entry's label decides it; there is no key to write.
#[must_use]
pub const fn agent_backend_kind(cfg: &AgentBackendConfig) -> &'static str {
    match cfg {
        AgentBackendConfig::Harness { .. } => "harness",
        AgentBackendConfig::Shell { .. } => "shell",
    }
}

/// Does this entry reach a MODEL, as opposed to running a literal command?
///
/// The distinction the operator-facing surfaces need: a project with no
/// model-backed agent still runs every `agent = "shell"` stage (the whole
/// `std.hello` starter and the model-free quickstart path) and cannot run a
/// model stage at all. `kata config check` keys off this, so "model-backed"
/// has one definition rather than one per caller.
#[must_use]
pub const fn is_model_backed(cfg: &AgentBackendConfig) -> bool {
    !matches!(cfg, AgentBackendConfig::Shell { .. })
}

/// The capability labels the supervised node advertises (`crate::supervised_node`
/// renders them into its `node.toml`), plus the default agent label (which the
/// caller discards).
///
/// No host-side agent is built: an
/// `agent = "<label>"` stage resolves `[agents.<label>]` through
/// `installed_node_agent` at capsule-assembly time and the embedded harness
/// drives the turn from the worker, so an advertisement only states which labels
/// the main configured — the `agent:<label>` capability strings — and which of
/// them serves a stage that names none. Nothing gates on them: capsule placement
/// demands no label and the BYO agent-run surface asks placement's question
/// beside the main's own `[agents.<label>]`; they surface in the worker
/// inventory. A label with no `[agents.<label>]`
/// block is `adapter_undeclared` at capsule assembly, so this list advertises
/// exactly the configured keys and nothing more — there is no fallback label a
/// worker could honestly claim.
///
/// Label population:
/// * `shell` is always advertised — every kata install gets
///   `agent = "shell"` without an `[agents.shell]` block;
/// * every `[agents.<label>]` key is advertised, except `workspace_effect`:
///   a workspace-effect or forge-export stage is performed by the main
///   itself and never placed on a worker, so no worker claims that label.
///
/// `default_label` rules: a `"default"` entry wins, a single entry is the
/// default, otherwise none — and a multi-entry config with no `"default"` is
/// warned at boot rather than failing opaquely at dispatch.
pub fn node_capabilities(cfg: &KataConfig) -> (Vec<String>, Option<String>) {
    let mut caps: Vec<String> = vec!["agent:shell".to_string()];
    caps.extend(
        cfg.agents
            .keys()
            .filter(|label| {
                label.as_str() != "shell"
                    && label.as_str() != kata_types::workflow::WORKSPACE_EFFECT_AGENT_LABEL
            })
            .map(|label| format!("agent:{label}")),
    );

    let default_label = if cfg.agents.contains_key("default") {
        Some("default".to_string())
    } else if cfg.agents.len() == 1 {
        cfg.agents.keys().next().cloned()
    } else {
        None
    };
    if default_label.is_none() && cfg.agents.len() > 1 {
        let keys: Vec<&str> = cfg.agents.keys().map(String::as_str).collect();
        warn!(
            agents = ?keys,
            "agents config has multiple entries but none named 'default'; \
             stages without an explicit `agent = \"…\"` selector will fail \
             at dispatch time. Add a `[agents.default]` entry or name one \
             of the existing entries 'default' to avoid this."
        );
    }
    (caps, default_label)
}

// Tests live in `bin/kata/tests/backend_factory_tests.rs`.
