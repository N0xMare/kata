//! Integration tests for `kata::backend_factory`.
//!
//! The module is config-shape helpers only — `agent_backend_kind`,
//! `is_model_backed`,
//! `node_capabilities`. There are no host-side backend constructors:
//! the OCI capsule route launches the vendor inside the node environment, so
//! nothing host-side is built.
//! What is worth pinning here is what the helpers promise their callers.

use std::collections::BTreeMap;

use kata::backend_factory::node_capabilities;
use kata_types::KataConfig;
use kata_types::config::AgentBackendConfig;

fn cfg_with_agents(agents: &[(&str, AgentBackendConfig)]) -> KataConfig {
    let mut cfg: KataConfig = toml::from_str(
        "[node]\nid = \"backend-factory-test\"\ndata_dir = \"/tmp/kata-bf-test\"\n\
         [workers]\ntransports = []\ndispatch_deadline_ms = 1000\n\
         heartbeat_interval_ms = 1000\nheartbeat_grace_ms = 1000\nmax_workers = 1\n\
         [api]\nbind = \"127.0.0.1:0\"\n[api.auth]\ntype = \"disabled\"\n",
    )
    .expect("base config parses");
    cfg.agents = agents
        .iter()
        .map(|(label, cfg)| ((*label).to_string(), cfg.clone()))
        .collect::<BTreeMap<_, _>>();
    cfg
}

fn harness_entry() -> AgentBackendConfig {
    AgentBackendConfig::Harness {
        model: None,
        reasoning_effort: None,
        adapter: Some("nanocode_openai".to_string()),
        credential: None,
        env: BTreeMap::new(),
    }
}

/// `agent_backend_kind` names the backend the entry's LABEL decided at parse:
/// `shell` for each reserved deterministic label, `harness` for every other. The
/// entries are parsed through the one agents parse rather than built in code, so
/// the printed kind is checked against what an operator's block becomes.
#[test]
fn agent_backend_kind_names_the_backend_the_label_parsed_to() {
    use kata::backend_factory::agent_backend_kind;

    #[derive(serde::Deserialize)]
    struct Doc {
        #[serde(deserialize_with = "kata_types::config::deserialize_agents")]
        agents: std::collections::BTreeMap<String, AgentBackendConfig>,
    }
    let doc: Doc = toml::from_str(
        "[agents.default]\nadapter = \"nanocode_openai\"\n[agents.reviewer]\n\
         [agents.shell]\n[agents.workspace_effect]\n",
    )
    .expect("the agents parse");
    let kinds: Vec<(&str, &str)> = doc
        .agents
        .iter()
        .map(|(label, entry)| (label.as_str(), agent_backend_kind(entry)))
        .collect();
    assert_eq!(
        kinds,
        [
            ("default", "harness"),
            ("reviewer", "harness"),
            ("shell", "shell"),
            ("workspace_effect", "shell"),
        ]
    );
}

/// `agent:shell` is the one capability the supervised node owns regardless of
/// config — `agent = "shell"` stages need no `[agents]` block. An empty
/// `[agents]` table must advertise NOTHING more: there is no fallback label a
/// worker could honestly claim, because a stage selecting an undeclared label
/// is `adapter_undeclared` at capsule assembly.
#[test]
fn node_capabilities_with_no_agents_advertises_shell_only() {
    let cfg = cfg_with_agents(&[]);
    let (caps, default) = node_capabilities(&cfg);
    assert_eq!(caps, vec!["agent:shell".to_string()]);
    assert_eq!(default, None, "no configured agent means no default label");
}

/// The advertisement is the configured KEY SET, in the same `agent:<label>`
/// spelling stages select — not a list of host backends. `workspace_effect`
/// is never advertised, even when an
/// `[agents.workspace_effect]` key is configured: the main performs a
/// workspace effect itself, no worker is placed for one, and the capacity
/// preflight demands no label for it.
#[test]
fn node_capabilities_advertise_the_configured_labels() {
    let cfg = cfg_with_agents(&[
        ("default", harness_entry()),
        ("shell", AgentBackendConfig::Shell {}),
        (
            kata_types::workflow::WORKSPACE_EFFECT_AGENT_LABEL,
            AgentBackendConfig::Shell {},
        ),
    ]);
    let (caps, default) = node_capabilities(&cfg);
    assert_eq!(
        caps,
        vec!["agent:shell".to_string(), "agent:default".to_string()]
    );
    assert_eq!(default, Some("default".to_string()));
}

/// The default-label rules are the same ones `kata config check` mirrors: a
/// `"default"` entry wins, a single entry is the default, and several entries
/// without `"default"` leave the dispatcher none.
#[test]
fn node_default_label_resolution() {
    let sole = cfg_with_agents(&[("mypi", harness_entry())]);
    let (_, default) = node_capabilities(&sole);
    assert_eq!(
        default,
        Some("mypi".to_string()),
        "a sole entry is the implicit default"
    );

    let two = cfg_with_agents(&[("a", harness_entry()), ("b", harness_entry())]);
    let (_, default) = node_capabilities(&two);
    assert_eq!(
        default, None,
        "multiple entries with no `default` leave the dispatcher none"
    );

    let named = cfg_with_agents(&[("default", harness_entry()), ("other", harness_entry())]);
    let (_, default) = node_capabilities(&named);
    assert_eq!(
        default,
        Some("default".to_string()),
        "an explicit `default` wins over the sole-entry rule"
    );
}
