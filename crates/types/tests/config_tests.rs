//! Tests for `crates/types/src/config.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use kata_types::config::{
    AgentBackendConfig, ApiAuthConfig, ApiConfig, ContainmentConfig,
    DEFAULT_GIT_VIEW_HISTORY_BYTES_CEILING, DISPATCH_DEADLINE_DISABLED, GitViewConfig,
    HEARTBEAT_GRACE_BELOW_INTERVAL, HEARTBEAT_INTERVAL_DISABLED, KataConfig, KnobStatus,
    MAX_ACTIVE_EXECUTION_BYTES, MAX_ACTIVE_EXECUTIONS, NodeConfig, NormalizePaths, RuntimeConfig,
    TelemetryConfig, VcsConfig, WorkerPoolConfig, WorkerSharedSecret, WorkerTransportConfig,
    agent_backend_knob_registry, api_knob_registry, containment_knob_registry, expand_tilde_with,
    load_config_placeholder, load_worker_config, load_worker_shared_secret, node_knob_registry,
    parse_kata_config, runtime_knob_registry, section_inert_knobs, telemetry_knob_registry,
    vcs_knob_registry, workers_knob_registry,
};
use kata_types::error::KataError;
use kata_types::test_support::json_roundtrip;
use serde::Deserialize;

fn sample_config() -> KataConfig {
    KataConfig {
        node: NodeConfig {
            environment: None,
            output_bytes_ceiling: kata_types::execution_contract::NODE_OUTPUT_BYTES_CEILING,
            work_delta_bytes_ceiling: kata_types::execution_contract::NODE_WORK_DELTA_BYTES_CEILING,
            work_delta_entries_ceiling:
                kata_types::execution_contract::NODE_WORK_DELTA_ENTRIES_CEILING,
            capsule_memory_bytes_ceiling: None,
            capsule_process_count_ceiling: None,
            id: "home-1".into(),
            data_dir: PathBuf::from("/var/lib/kata"),
            work_tree_max_bytes: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_BYTES,
            work_tree_max_entries: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_ENTRIES,
            egress_allow: Vec::new(),
        },
        runtime: RuntimeConfig::default(),
        workers: WorkerPoolConfig {
            transports: vec![WorkerTransportConfig::SupervisedNode {}],
            dispatch_deadline_ms: 5_000,
            assignment_start_deadline_ms: 900_000,
            heartbeat_interval_ms: 2_500,
            heartbeat_grace_ms: 10_000,
            max_workers: 16,
        },
        api: ApiConfig {
            bind: "127.0.0.1:8400".into(),
            auth: ApiAuthConfig::SignedToken {
                verifying_key_env: Some("API_VERIFYING_KEY".into()),
                verifying_key_file: None,
            },
        },
        agents: BTreeMap::new(),
        vcs: VcsConfig::default(),
        telemetry: TelemetryConfig::default(),
        containment: ContainmentConfig::default(),
        git_view: GitViewConfig::default(),
        pricing: kata_types::config::PricingConfig::default(),
    }
}

/// A minimal harness entry: the one agent backend that declares a capsule.
fn harness_backend() -> AgentBackendConfig {
    AgentBackendConfig::Harness {
        model: None,
        reasoning_effort: None,
        adapter: None,
        credential: None,
        env: BTreeMap::new(),
    }
}

#[test]
fn runtime_config_has_defaults() {
    let rc = RuntimeConfig::default();
    assert!(rc.max_concurrent_dispatches > 0);
    assert_eq!(rc.max_active_executions, 1024);
    assert_eq!(rc.max_active_execution_bytes, 512 * 1024 * 1024);
}

#[test]
fn active_execution_residency_config_refuses_zero_and_hard_maxima() {
    for (count, bytes) in [
        (0, 1),
        (MAX_ACTIVE_EXECUTIONS + 1, 1),
        (1, 0),
        (1, MAX_ACTIVE_EXECUTION_BYTES + 1),
    ] {
        let mut cfg = sample_config();
        cfg.runtime.max_active_executions = count;
        cfg.runtime.max_active_execution_bytes = bytes;
        assert!(cfg.validate().is_err(), "count={count} bytes={bytes}");
    }
}

/// `workspace_ttl_secs` defaults to 24h (86400s) via
/// `#[serde(default)]`. This is the hot knob the background
/// workspace sweeper consults.
#[test]
fn runtime_config_workspace_ttl_defaults_to_24h() {
    let rc = RuntimeConfig::default();
    assert_eq!(rc.workspace_ttl_secs, 86_400);
}

/// A `[runtime]` section that omits `workspace_ttl_secs` parses,
/// taking the default.
#[test]
fn runtime_config_legacy_without_workspace_ttl_parses() {
    let toml_text = "
max_concurrent_dispatches = 256
";
    let rc: RuntimeConfig = toml::from_str(toml_text).unwrap();
    assert_eq!(rc.workspace_ttl_secs, 86_400);
}

/// Retention is fail-closed until durable top-level workflow terminality exists:
/// omission and explicit zero both disable the unavailable compactor.
#[test]
fn runtime_config_ledger_ttl_defaults_and_round_trips() {
    assert_eq!(RuntimeConfig::default().ledger_ttl_secs, 0);

    let omitted = "
max_concurrent_dispatches = 256
";
    let rc: RuntimeConfig = toml::from_str(omitted).unwrap();
    assert_eq!(rc.ledger_ttl_secs, 0, "omitted => retained default");

    let explicit: RuntimeConfig =
        toml::from_str(&format!("{omitted}ledger_ttl_secs = 0\n")).unwrap();
    assert_eq!(rc.ledger_ttl_secs.min(explicit.ledger_ttl_secs), 0);
    assert_eq!(explicit.ledger_ttl_secs, 0, "0 keeps retention disabled");
}

/// `[runtime] model_reuse_max_age_secs` has exactly three
/// spellings, and `0` ("I did not choose") and `"unbounded"` ("I chose no bound") are
/// DISTINCT answers. An absent key is `0`'s answer; each spelling survives a TOML
/// round-trip; and the bound each yields is the one the consult applies.
///
/// **Watched red:** with `visit_u64` reading `0` as `Unbounded`, `0` and
/// `"unbounded"` collapse.
#[test]
fn model_reuse_max_age_spellings_are_distinct_and_round_trip() {
    use kata_types::config::{DEFAULT_MODEL_REUSE_MAX_AGE_SECS, ModelReuseMaxAge};

    let parse = |value: &str| -> ModelReuseMaxAge {
        toml::from_str::<RuntimeConfig>(&format!("model_reuse_max_age_secs = {value}\n"))
            .unwrap_or_else(|error| panic!("{value} parses: {error}"))
            .model_reuse_max_age_secs
    };
    let absent: RuntimeConfig = toml::from_str("").unwrap();
    assert_eq!(absent.model_reuse_max_age_secs, ModelReuseMaxAge::Default);
    assert_eq!(parse("0"), ModelReuseMaxAge::Default);
    assert_eq!(parse("\"unbounded\""), ModelReuseMaxAge::Unbounded);
    assert_eq!(parse("3600"), ModelReuseMaxAge::Secs(3_600));
    assert_ne!(
        parse("0"),
        parse("\"unbounded\""),
        "0 and unbounded stay distinct"
    );

    assert_eq!(
        ModelReuseMaxAge::Default.max_age_ms(),
        Some(i64::try_from(DEFAULT_MODEL_REUSE_MAX_AGE_SECS * 1_000).unwrap())
    );
    assert_eq!(
        DEFAULT_MODEL_REUSE_MAX_AGE_SECS,
        7 * 86_400,
        "the 7-day default"
    );
    assert_eq!(ModelReuseMaxAge::Unbounded.max_age_ms(), None);
    assert_eq!(ModelReuseMaxAge::Secs(3_600).max_age_ms(), Some(3_600_000));
    assert_eq!(
        ModelReuseMaxAge::Secs(u64::MAX).max_age_ms(),
        Some(i64::MAX),
        "a nonsense-large bound saturates to effectively unbounded, never a negative floor"
    );

    for bound in [
        ModelReuseMaxAge::Default,
        ModelReuseMaxAge::Unbounded,
        ModelReuseMaxAge::Secs(3_600),
    ] {
        let rc = RuntimeConfig {
            model_reuse_max_age_secs: bound,
            ..RuntimeConfig::default()
        };
        let back: RuntimeConfig = toml::from_str(&toml::to_string(&rc).unwrap()).unwrap();
        assert_eq!(
            back.model_reuse_max_age_secs, bound,
            "{bound:?} round-trips"
        );
    }
}

/// THE BOUNDARY of the memoised-spend bound, to the millisecond: a source exactly as old
/// as the bound is served, one millisecond older is not; unbounded serves any age, and a
/// nonsense-large explicit bound saturates rather than refusing everything.
///
/// **Watched red:** with `admits_age_ms` comparing `<` instead of `<=`, a source exactly
/// at the bound is refused.
#[test]
fn the_memoised_spend_bound_serves_its_own_age_and_refuses_one_millisecond_more() {
    use kata_types::config::{DEFAULT_MODEL_REUSE_MAX_AGE_SECS, ModelReuseMaxAge};

    let week_ms = i64::try_from(DEFAULT_MODEL_REUSE_MAX_AGE_SECS * 1_000).unwrap();
    for (bound, max_age_ms) in [
        (ModelReuseMaxAge::Default, week_ms),
        (ModelReuseMaxAge::Secs(3_600), 3_600_000),
        (ModelReuseMaxAge::Secs(1), 1_000),
    ] {
        assert!(bound.admits_age_ms(0), "{bound:?}: a just-accepted source");
        assert!(
            bound.admits_age_ms(max_age_ms),
            "{bound:?}: a source exactly {max_age_ms} ms old is served"
        );
        assert!(
            !bound.admits_age_ms(max_age_ms + 1),
            "{bound:?}: a source {} ms old is not",
            max_age_ms + 1
        );
    }
    assert!(ModelReuseMaxAge::Unbounded.admits_age_ms(i64::MAX));
    assert!(ModelReuseMaxAge::Secs(u64::MAX).admits_age_ms(i64::MAX));
}

/// The REFUSED set of `[runtime] model_reuse_max_age_secs`: everything but a
/// non-negative integer and the exact word `"unbounded"`, in that exact case. Each
/// refusal names the key.
///
/// **Watched red:** with `visit_str` admitting any word as `Unbounded`, a typo loads;
/// with it matching `"unbounded"` case-insensitively, `"Unbounded"` loads.
#[test]
fn a_malformed_model_reuse_max_age_is_refused_by_name() {
    for value in [
        "-1",
        "1.5",
        "true",
        "\"\"",
        "\"Unbounded\"",
        "\"Unbounded \"",
        "\"7d\"",
        "\"not a duration at all\"",
        "[]",
    ] {
        let error =
            toml::from_str::<RuntimeConfig>(&format!("model_reuse_max_age_secs = {value}\n"))
                .map(|rc| rc.model_reuse_max_age_secs)
                .expect_err(&format!("{value} must be refused"));
        assert!(
            error
                .to_string()
                .contains("runtime.model_reuse_max_age_secs"),
            "{value}: the refusal names the key: {error}"
        );
    }
}

/// An explicit `workspace_ttl_secs` round-trips
/// cleanly through TOML.
#[test]
fn runtime_config_workspace_ttl_roundtrips() {
    let rc = RuntimeConfig {
        workspace_ttl_secs: 3_600,
        ..RuntimeConfig::default()
    };
    let s = toml::to_string(&rc).unwrap();
    let back: RuntimeConfig = toml::from_str(&s).unwrap();
    assert_eq!(back.workspace_ttl_secs, 3_600);
}

/// A MINIMAL `[runtime]` section sets exactly ONE key. Every `RuntimeConfig`
/// field carries a `#[serde(default)]`, so a `[runtime]` section naming only the
/// knob you want must parse — otherwise it would fail on unrelated missing
/// fields and the knob would be effectively UNSETTABLE.
#[test]
fn runtime_section_with_a_single_key_parses() {
    let rc: RuntimeConfig = toml::from_str("max_concurrent_dispatches = 4")
        .expect("a [runtime] section may set one key and default the rest");
    assert_eq!(rc.max_concurrent_dispatches, 4);
    // The other fields the doc's minimal example never mentions.
    assert_eq!(rc.workspace_ttl_secs, 86_400);
}

/// A wholly EMPTY `[runtime]` section is the limiting case of the same
/// property: every runtime knob now has a default, so omitting all of them
/// yields `RuntimeConfig::default()`.
#[test]
fn empty_runtime_section_parses_as_default() {
    let rc: RuntimeConfig = toml::from_str("").expect("an empty [runtime] section must parse");
    assert_eq!(rc, RuntimeConfig::default());
}

/// Serialization emits the current spelling, never the refused one.
#[test]
fn runtime_config_serializes_the_current_spelling_only() {
    let text = toml::to_string(&RuntimeConfig::default()).unwrap();
    assert!(
        text.contains("max_concurrent_dispatches"),
        "serialized runtime config must use the current name, got:\n{text}"
    );
    assert!(
        !text.contains("max_concurrent_tasks"),
        "the refused name must not be emitted, got:\n{text}"
    );
}

/// A minimal installed-main configuration. `validate()` is included because a
/// minimal example must be usable, not merely well-formed TOML.
const DOC_MINIMAL_CONFIG: &str = r#"
[node]
id = "local-kata"
data_dir = "data"

[runtime]
max_concurrent_dispatches = 256

[workers]
max_workers = 4
dispatch_deadline_ms = 30000
heartbeat_interval_ms = 10000
heartbeat_grace_ms = 30000

[[workers.transports]]
type = "supervised_node"

[api]
bind = "127.0.0.1:8400"

[api.auth]
type = "disabled"

[agents.default]

[vcs]
jj_repo = ".."

[telemetry]
enabled = false
"#;

/// "Settable" at whole-config scope: the minimal config must LOAD and VALIDATE,
/// without naming `workspace_ttl_secs` — a field its `[runtime]` section never
/// mentions.
#[test]
fn documented_minimal_config_parses_and_validates() {
    let cfg: KataConfig =
        toml::from_str(DOC_MINIMAL_CONFIG).expect("the minimal config must parse");
    assert_eq!(cfg.runtime.max_concurrent_dispatches, 256);
    assert_eq!(cfg.runtime.workspace_ttl_secs, 86_400, "defaulted, not set");
    cfg.validate()
        .expect("the minimal config must also validate");
}

/// An absent `[git_view]` section means the DOCUMENTED defaults: unlimited
/// depth and the 1 GiB member-byte ceiling. `GitViewConfig` must not spell its
/// absent meaning through `#[derive(Default)]` — the derive knows nothing of
/// the serde `default=` on `history_bytes_ceiling`, so it would answer `0`,
/// and every caller that asks for "the defaults" (`#[serde(default)]` on
/// `KataConfig::git_view`, the executor's own constructor, the MCP surface)
/// would install a ceiling that refuses every agent-stage admission.
#[test]
fn absent_git_view_section_means_the_documented_bounds() {
    assert_eq!(
        GitViewConfig::default().history_bytes_ceiling,
        DEFAULT_GIT_VIEW_HISTORY_BYTES_CEILING,
        "GitViewConfig::default() must be the absent-section meaning, not the derive's"
    );
    assert_eq!(GitViewConfig::default().history_depth, None);

    let cfg: KataConfig =
        toml::from_str(DOC_MINIMAL_CONFIG).expect("the documented minimal config parses");
    assert_eq!(
        cfg.git_view.history_bytes_ceiling, DEFAULT_GIT_VIEW_HISTORY_BYTES_CEILING,
        "an absent [git_view] section must mean the shipped ceiling, not zero"
    );
    assert_eq!(cfg.git_view.history_depth, None);

    let section: GitViewConfig =
        toml::from_str("history_depth = 8\n").expect("a partial [git_view] section parses");
    assert_eq!(section.history_depth, Some(8));
    assert_eq!(
        section.history_bytes_ceiling, DEFAULT_GIT_VIEW_HISTORY_BYTES_CEILING,
        "a [git_view] section that sets depth only keeps the byte ceiling's default"
    );
}

#[test]
fn kata_config_json_roundtrip() {
    json_roundtrip(sample_config());
}

/// **A config naming the removed `in_process` transport is refused by name,
/// with its recourse.** The main hosts no worker: `[[workers.transports]] type
/// = "in_process"` is refused `worker_transport_in_process_removed`, naming
/// both transports that exist and the path of the refused element, through
/// `load_config` — the operator's door — and a bare table, with or without
/// other keys. The refused set is exactly a transport whose `type` is
/// `"in_process"`: the same config with `type = "supervised_node"` loads, and
/// an unknown type is still refused as unknown, its expected list naming only
/// the two types that exist.
///
/// **Would red if:** `in_process` parsed again (watched at the base, where it
/// was the default transport), or the refusal fell through to serde's generic
/// unknown-variant text.
#[test]
fn an_in_process_transport_is_refused_by_name_with_its_recourse() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kata.toml");
    let config =
        DOC_MINIMAL_CONFIG.replace(r#"type = "supervised_node""#, r#"type = "in_process""#);
    assert!(
        config.contains(r#"type = "in_process""#),
        "the fixture names the refused transport"
    );
    std::fs::write(&path, &config).unwrap();
    let error = load_config_placeholder(&path).expect_err("in_process is removed");
    let message = error.to_string();
    for named in [
        "worker_transport_in_process_removed",
        "workers.transports",
        r#"{ type = "supervised_node" }"#,
        r#"type = "local_socket""#,
    ] {
        assert!(
            message.contains(named),
            "the refusal names `{named}`: {message}"
        );
    }
    for table in [
        r#"type = "in_process""#,
        "type = \"in_process\"\nbuffer = 4",
    ] {
        let error = toml::from_str::<WorkerTransportConfig>(table)
            .expect_err("a bare in_process table is refused");
        assert!(
            error
                .to_string()
                .contains("worker_transport_in_process_removed"),
            "{table:?}: {error}"
        );
    }

    std::fs::write(&path, DOC_MINIMAL_CONFIG).unwrap();
    load_config_placeholder(&path).expect("the same config naming supervised_node loads");
    let unknown = toml::from_str::<WorkerTransportConfig>(r#"type = "embedded""#)
        .expect_err("an unknown type stays unknown");
    let unknown = unknown.to_string();
    assert!(
        unknown.contains("unknown variant `embedded`")
            && unknown.contains("supervised_node")
            && unknown.contains("local_socket")
            && !unknown.contains("in_process"),
        "the unknown-type refusal lists exactly the types that exist: {unknown}"
    );
}

#[test]
fn worker_capacity_requires_nonzero_bound_and_one_supervised_node() {
    let mut config = sample_config();
    config.workers.max_workers = 0;
    let error = config.validate().expect_err("zero capacity must fail");
    assert!(error.to_string().contains("max_workers must be greater"));

    config.workers.max_workers = 2;
    config
        .workers
        .transports
        .push(WorkerTransportConfig::SupervisedNode {});
    let error = config
        .validate()
        .expect_err("two supervised nodes must fail");
    assert!(error.to_string().contains("at most one"));

    config.workers.transports = vec![
        WorkerTransportConfig::SupervisedNode {},
        WorkerTransportConfig::LocalSocket {
            path: "/tmp/local.sock".into(),
        },
    ];
    config.workers.max_workers = 1;
    let error = config
        .validate()
        .expect_err("every configured provider needs usable capacity");
    assert!(
        error
            .to_string()
            .contains("every configured provider usable")
    );
}

#[test]
fn validate_rejects_bad_bind() {
    let mut c = sample_config();
    c.api.bind = "not a socket".into();
    assert!(c.validate().is_err());
}

#[test]
fn validate_rejects_disabled_api_auth_on_non_loopback_bind() {
    let mut c = sample_config();
    c.api.auth = ApiAuthConfig::Disabled {};
    c.api.bind = "0.0.0.0:8400".into();
    let err = c
        .validate()
        .expect_err("disabled auth must stay loopback-only");
    assert!(
        matches!(err, KataError::Validation(ref msg) if msg.contains("disabled") && msg.contains("loopback")),
        "error should explain disabled auth loopback boundary, got {err:?}"
    );
}

#[test]
fn validate_rejects_signed_token_auth_on_non_loopback_bind() {
    let mut c = sample_config();
    c.api.auth = ApiAuthConfig::SignedToken {
        verifying_key_env: Some("API_VERIFYING_KEY".into()),
        verifying_key_file: None,
    };
    c.api.bind = "0.0.0.0:8400".into();
    let err = c
        .validate()
        .expect_err("signed_token auth must reject non-loopback API binds");
    assert!(
        matches!(err, KataError::Validation(ref msg)
            if msg.contains("signed_token") && msg.contains("loopback")),
        "error should explain the signed_token loopback boundary, got {err:?}"
    );
}

#[test]
fn validate_rejects_signed_token_auth_without_verifying_key_source() {
    let mut c = sample_config();
    c.api.auth = ApiAuthConfig::SignedToken {
        verifying_key_env: None,
        verifying_key_file: None,
    };
    let err = c
        .validate()
        .expect_err("signed_token auth must require a verifying-key source");
    assert!(
        matches!(err, KataError::Validation(ref msg)
            if msg.contains("signed_token") && msg.contains("exactly one verifying-key source")),
        "error should explain verifying-key source requirement, got {err:?}"
    );
}

#[test]
fn validate_rejects_signed_token_auth_with_two_verifying_key_sources() {
    let mut c = sample_config();
    c.api.auth = ApiAuthConfig::SignedToken {
        verifying_key_env: Some("API_VERIFYING_KEY".into()),
        verifying_key_file: Some(PathBuf::from("/tmp/kata-api-pubkey")),
    };
    let err = c
        .validate()
        .expect_err("signed_token auth must reject ambiguous verifying-key sources");
    assert!(
        matches!(err, KataError::Validation(ref msg)
            if msg.contains("signed_token") && msg.contains("exactly one verifying-key source")),
        "error should explain verifying-key source ambiguity, got {err:?}"
    );
}

#[test]
fn api_auth_rejects_removed_inert_daemon_signing_key_fields() {
    let err = serde_json::from_value::<ApiAuthConfig>(serde_json::json!({
        "type": "signed_token",
        "verifying_key_env": "API_VERIFYING_KEY",
        "signing_key_env": "KATA_API_SIGNING_KEY"
    }))
    .expect_err("daemon auth config must reject the removed inert signing-key field");
    assert!(
        err.to_string().contains("unknown field") && err.to_string().contains("signing_key_env"),
        "removed field must produce an explicit break diagnostic, got {err}"
    );
}

fn full_kata_config_toml_with_auth(auth: &str) -> String {
    format!(
        r#"
[node]
id = "home-1"
data_dir = "/var/lib/kata"

[api]
bind = "127.0.0.1:8400"

[api.auth]
{auth}

[workers]
dispatch_deadline_ms = 30000
heartbeat_interval_ms = 10000
heartbeat_grace_ms = 30000
max_workers = 4

[[workers.transports]]
type = "supervised_node"
"#
    )
}

#[test]
fn kata_config_toml_rejects_removed_daemon_signing_key_fields() {
    for (field, value) in [
        ("signing_key_env", "\"KATA_API_SIGNING_KEY\""),
        ("signing_key_file", "\"/run/secrets/kata-api-signing-key\""),
    ] {
        let text = full_kata_config_toml_with_auth(&format!(
            "type = \"signed_token\"\nverifying_key_env = \"API_VERIFYING_KEY\"\n{field} = {value}"
        ));
        let err = toml::from_str::<KataConfig>(&text)
            .expect_err("full daemon config must reject removed signing-key fields");
        let message = err.to_string();
        assert!(
            message.contains("unknown field") && message.contains(field),
            "removed TOML field {field} must produce an explicit break diagnostic, got {message}"
        );
    }
}

#[test]
fn kata_config_toml_rejects_unknown_disabled_auth_fields() {
    let text = full_kata_config_toml_with_auth(
        "type = \"disabled\"\nunexpected_credential_source = \"must-not-be-ignored\"",
    );
    let err = toml::from_str::<KataConfig>(&text)
        .expect_err("disabled daemon auth must reject unknown fields");
    let message = err.to_string();
    assert!(
        message.contains("unknown field") && message.contains("unexpected_credential_source"),
        "unknown disabled-auth TOML field must produce an explicit diagnostic, got {message}"
    );
}

#[test]
fn validate_rejects_signed_token_auth_with_empty_verifying_key_env() {
    let mut c = sample_config();
    c.api.auth = ApiAuthConfig::SignedToken {
        verifying_key_env: Some("  ".into()),
        verifying_key_file: None,
    };
    let err = c
        .validate()
        .expect_err("signed_token auth must reject empty verifying_key_env");
    assert!(
        matches!(err, KataError::Validation(ref msg) if msg.contains("verifying_key_env")),
        "error should explain verifying_key_env requirement, got {err:?}"
    );
}

/// The verifying key's variable lives outside kata's `KATA_` runtime namespace,
/// the same rule `kata service install` applies to every variable it snapshots,
/// so a config the main accepts is one the installed main can be given.
#[test]
fn validate_rejects_a_verifying_key_env_in_the_kata_namespace() {
    let mut c = sample_config();
    c.api.auth = ApiAuthConfig::SignedToken {
        verifying_key_env: Some("KATA_API_VERIFYING_KEY".into()),
        verifying_key_file: None,
    };
    let err = c
        .validate()
        .expect_err("a KATA_-prefixed verifying_key_env must be refused");
    assert!(
        matches!(err, KataError::Validation(ref msg)
            if msg.contains("api.auth.verifying_key_env")
                && msg.contains("KATA_API_VERIFYING_KEY")
                && msg.contains("KATA_ namespace")),
        "the refusal must name the field, the variable and the namespace, got {err:?}"
    );
}

#[test]
fn validate_ok_for_well_formed() {
    sample_config().validate().unwrap();
}

/// `[node] egress_allow` declares exact `host:port` authorities; an entry the
/// shared `EgressAuthority::from_authority_str` spell refuses is refused at
/// config load, naming the key and the offending entry — never deferred to a
/// stage's CHECK.
#[test]
fn validate_rejects_a_node_egress_allow_entry_the_authority_spell_refuses() {
    for entry in ["*.example.com:443", "example.com", "example.com:0"] {
        let mut c = sample_config();
        c.node.egress_allow = vec![entry.to_string()];
        let err = c
            .validate()
            .expect_err("a malformed egress_allow entry refuses at load");
        assert!(
            matches!(err, KataError::Validation(ref msg)
                if msg.contains("node.egress_allow") && msg.contains(entry)),
            "{entry}: the refusal names the key and the entry, got {err:?}"
        );
    }
    // The well-formed edge admitted: exact `host:port`, bracketed IPv6 and a
    // dotted IPv4 literal all carry.
    let mut c = sample_config();
    c.node.egress_allow = vec![
        "api.example.com:443".to_string(),
        "[::1]:8443".to_string(),
        "127.0.0.1:80".to_string(),
    ];
    c.validate().expect("exact authorities admit");
}

/// `[workers] dispatch_deadline_ms = 0` is refused at load by name: the delivery
/// door joins each capsule send's own task under that deadline, and at 0 the join
/// gives up at the runtime timer's next tick, so a healthy send to an idle worker
/// that has to wait at all is settled PROVEN AMBIGUOUS. One millisecond loads.
#[test]
fn validate_refuses_a_zero_dispatch_deadline_by_name() {
    let mut c = sample_config();
    c.workers.dispatch_deadline_ms = 0;
    let err = c
        .validate()
        .expect_err("a zero dispatch deadline refuses at load");
    assert!(
        matches!(err, KataError::Validation(ref msg)
            if msg.contains(DISPATCH_DEADLINE_DISABLED)
                && msg.contains("dispatch_deadline_ms = 0")),
        "the refusal names its token and the knob, got {err:?}"
    );
    c.workers.dispatch_deadline_ms = 1;
    c.validate().expect("a non-zero dispatch deadline loads");
}

/// `[workers] heartbeat_interval_ms = 0` is refused at load by name: it is the
/// period of the main's heartbeat sweep and of its deadline sweep, and a tokio
/// interval of zero panics inside both spawned tasks, leaving the main with no
/// worker-liveness leg and no deadline leg. One millisecond loads.
#[test]
fn validate_refuses_a_zero_heartbeat_interval_by_name() {
    let mut c = sample_config();
    c.workers.heartbeat_interval_ms = 0;
    let err = c
        .validate()
        .expect_err("a zero heartbeat interval refuses at load");
    assert!(
        matches!(err, KataError::Validation(ref msg)
            if msg.contains(HEARTBEAT_INTERVAL_DISABLED)
                && msg.contains("heartbeat_interval_ms = 0")),
        "the refusal names its token and the knob, got {err:?}"
    );
    c.workers.heartbeat_interval_ms = 1;
    c.validate().expect("a non-zero heartbeat interval loads");
}

/// `[workers] heartbeat_grace_ms` shorter than `heartbeat_interval_ms` is refused at
/// load by name, naming both values: a worker beats every half interval and a stall of
/// the main's sweep counts as at most one interval of its silence, so a shorter grace would
/// settle a live worker for a beat delayed by less than half an interval. A grace
/// equal to the interval loads.
#[test]
fn validate_refuses_a_heartbeat_grace_shorter_than_the_interval_by_name() {
    let mut c = sample_config();
    c.workers.heartbeat_interval_ms = 1_000;
    c.workers.heartbeat_grace_ms = 999;
    let err = c
        .validate()
        .expect_err("a grace shorter than the interval refuses at load");
    assert!(
        matches!(err, KataError::Validation(ref msg)
            if msg.contains(HEARTBEAT_GRACE_BELOW_INTERVAL)
                && msg.contains("heartbeat_grace_ms = 999")
                && msg.contains("heartbeat_interval_ms = 1000")),
        "the refusal names its token and both knobs, got {err:?}"
    );
    c.workers.heartbeat_grace_ms = 1_000;
    c.validate().expect("a grace equal to the interval loads");
}

#[test]
fn validate_rejects_zero_op_log_keep_newer_when_gc_enabled() {
    // Regression: a zero keep-newer floor with GC enabled eradicates the
    // undo horizon and removes the defense-in-depth concurrent-writer guard.
    // `validate()` must reject it.
    let mut c = sample_config();
    c.vcs.op_log_gc_enabled = true;
    c.vcs.op_log_gc_keep_newer_secs = 0;
    let err = c
        .validate()
        .expect_err("zero keep-newer floor with GC enabled must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("op_log_gc_keep_newer_secs"),
        "error should name the offending knob: {msg}"
    );
}

#[test]
fn validate_accepts_zero_op_log_keep_newer_when_gc_disabled() {
    // The floor only matters while GC runs — a zero value is inert (hence
    // harmless) when op-log GC is switched off.
    let mut c = sample_config();
    c.vcs.op_log_gc_enabled = false;
    c.vcs.op_log_gc_keep_newer_secs = 0;
    c.validate()
        .expect("zero keep-newer floor is harmless when GC is disabled");
}

#[test]
fn validate_rejects_reserved_shell_agent_bound_to_non_shell_backend() {
    // Rebinding the reserved deterministic name `shell` to an LLM backend
    // would let validation proof stages self-certify and silently promote.
    // `validate()` must reject it.
    let mut c = sample_config();
    c.agents.insert("shell".into(), harness_backend());
    let err = c
        .validate()
        .expect_err("non-shell `shell` agent must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("shell") && msg.contains("deterministic"),
        "error should name the reserved deterministic requirement: {msg}"
    );
}

/// The converse a config built in code could reach and no parse can: the shell
/// route under a model label is an agent no stage runs, so `validate()` refuses
/// it by the same reserved-label rule.
#[test]
fn validate_rejects_shell_backend_under_a_model_label() {
    let mut c = sample_config();
    c.agents
        .insert("build".into(), AgentBackendConfig::Shell {});
    let msg = c
        .validate()
        .expect_err("a shell entry under `build` must be rejected")
        .to_string();
    assert!(
        msg.contains("agents.build") && msg.contains("deterministic"),
        "{msg}"
    );
}

#[test]
fn validate_accepts_reserved_shell_agent_bound_to_shell_backend() {
    let mut c = sample_config();
    c.agents
        .insert("shell".into(), AgentBackendConfig::Shell {});
    c.validate()
        .expect("an `[agents.shell]` shell backend must validate");
}

#[test]
fn validate_accepts_absent_shell_agent() {
    // The default install auto-registers `shell` with no explicit block;
    // that path must stay unaffected.
    let c = sample_config();
    assert!(!c.agents.contains_key("shell"));
    c.validate()
        .expect("config without `[agents.shell]` must validate");
}

#[test]
fn validate_allows_non_reserved_agent_with_llm_backend() {
    // Only reserved deterministic names are constrained; ordinary agent
    // names may bind to any backend.
    let mut c = sample_config();
    c.agents.insert("planner".into(), harness_backend());
    c.validate()
        .expect("non-reserved agent name with an LLM backend must validate");
}

// ── the consumed-knob rule: the inert-knob guard ──────────────────────────

/// GREEN: every serde field on ALL SIX guard-covered bags is classified
/// consumed, so a healthy config surfaces ZERO inert knobs.
/// This is the fail-closed authority: adding a serde field to any of
/// `NodeConfig` / `RuntimeConfig` / `WorkerPoolConfig` / `ApiConfig` /
/// `TelemetryConfig` / `VcsConfig` / `ContainmentConfig` without a matching
/// registry row makes this list non-empty and FAILS `just test-crate types`.
#[test]
fn inert_knob_registries_cover_every_serde_field() {
    let node = sample_config().node;
    assert!(
        section_inert_knobs("node", &node, node_knob_registry()).is_empty(),
        "NodeConfig has an unclassified (inert) serde field"
    );
    assert!(
        section_inert_knobs(
            "runtime",
            &RuntimeConfig::default(),
            runtime_knob_registry()
        )
        .is_empty(),
        "RuntimeConfig has an unclassified (inert) serde field"
    );
    assert!(
        section_inert_knobs(
            "workers",
            &WorkerPoolConfig::default(),
            workers_knob_registry()
        )
        .is_empty(),
        "WorkerPoolConfig has an unclassified (inert) serde field"
    );
    assert!(
        section_inert_knobs("api", &sample_config().api, api_knob_registry()).is_empty(),
        "ApiConfig has an unclassified (inert) serde field"
    );
    assert!(
        section_inert_knobs(
            "telemetry",
            &TelemetryConfig::default(),
            telemetry_knob_registry()
        )
        .is_empty(),
        "TelemetryConfig has an unclassified (inert) serde field"
    );
    assert!(
        section_inert_knobs("vcs", &VcsConfig::default(), vcs_knob_registry()).is_empty(),
        "VcsConfig has an unclassified (inert) serde field"
    );
    assert!(
        section_inert_knobs(
            "containment",
            &ContainmentConfig::default(),
            containment_knob_registry()
        )
        .is_empty(),
        "ContainmentConfig has an unclassified (inert) serde field"
    );
    assert!(
        sample_config().inert_knobs().is_empty(),
        "a valid KataConfig must surface no inert knobs"
    );
}

/// GREEN: every serde field on EVERY `AgentBackendConfig` backend variant is
/// classified — the harness against its registry, the shell route against none.
/// The exhaustive `match` below forces this test to be revisited (compile error)
/// whenever a variant is added to the enum, so the agents.* coverage cannot rot
/// silently.
#[test]
fn agent_backend_registry_covers_every_variant_field() {
    let samples = [
        AgentBackendConfig::Harness {
            model: Some("gpt-5".into()),
            reasoning_effort: Some("high".into()),
            adapter: None,
            credential: None,
            env: std::collections::BTreeMap::new(),
        },
        AgentBackendConfig::Shell {},
    ];
    for backend in &samples {
        let registry: &[(&str, KnobStatus)] = match backend {
            AgentBackendConfig::Harness { .. } => agent_backend_knob_registry(),
            AgentBackendConfig::Shell { .. } => &[],
        };
        let findings = section_inert_knobs("agents.agent", backend, registry);
        assert!(
            findings.is_empty(),
            "AgentBackendConfig variant {backend:?} has an unclassified (inert) serde field: \
             {findings:?}"
        );
    }
    let mut cfg = sample_config();
    cfg.agents.insert("default".into(), samples[0].clone());
    cfg.agents
        .insert("shell".into(), AgentBackendConfig::Shell {});
    assert!(cfg.inert_knobs().is_empty(), "{:?}", cfg.inert_knobs());
}

/// RED demonstration for a NEW bag (telemetry): an unregistered serde field is
/// flagged, proving the guard is genuinely live for every covered bag — not
/// only the runtime/vcs bags.
#[test]
fn inert_knob_guard_flags_unregistered_telemetry_field() {
    let mut value = serde_json::to_value(TelemetryConfig::default()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("future_dead_knob".to_string(), serde_json::json!(0));

    let findings = section_inert_knobs("telemetry", &value, telemetry_knob_registry());
    assert!(
        findings
            .iter()
            .any(|f| f.contains("telemetry.future_dead_knob")),
        "an unregistered telemetry serde field must be flagged as inert, got {findings:?}"
    );
}

/// RED demonstration for the agents.* bag: an unregistered field planted onto a
/// serialized harness backend is flagged against the harness registry.
#[test]
fn inert_knob_guard_flags_unregistered_agent_field() {
    let backend = harness_backend();
    let mut value = serde_json::to_value(&backend).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("future_dead_knob".to_string(), serde_json::json!(0));

    let findings = section_inert_knobs("agents.default", &value, agent_backend_knob_registry());
    assert!(
        findings
            .iter()
            .any(|f| f.contains("agents.default.future_dead_knob")),
        "an unregistered agent serde field must be flagged as inert, got {findings:?}"
    );
}

/// Counterfactual RED (agents.*): with the harness `model` registry row
/// stripped, a declared harness backend is flagged — proving the agents.* leg of
/// the guard is live and structural (it checks for the PRESENCE of a row,
/// whatever its `KnobStatus`), not a hand-maintained list.
///
/// Note what this does NOT prove, and what nothing in this file can: the
/// guard verifies that every serde field has a row, never that a
/// `Consumed(...)` row's cited consumer is real. A row can lie. The behaviour
/// that backs a `Consumed(...)` row has to be pinned beside its consumer.
#[test]
fn harness_model_row_removal_is_flagged_by_the_guard() {
    let backend = AgentBackendConfig::Harness {
        model: Some("gpt-5".into()),
        reasoning_effort: None,
        adapter: None,
        credential: None,
        env: std::collections::BTreeMap::new(),
    };
    let stripped: Vec<(&str, KnobStatus)> = agent_backend_knob_registry()
        .iter()
        .copied()
        .filter(|(f, _)| *f != "model")
        .collect();
    let findings = section_inert_knobs("agents.build", &backend, &stripped);
    assert!(
        findings.iter().any(|f| f.contains("agents.build.model")),
        "the harness `model` must be flagged inert once its row is removed, got {findings:?}"
    );
}

/// `max_concurrent_dispatches` is CONSUMED — wired to the dispatcher
/// admission-control semaphore. This pins the registry status so a future
/// revert that unwires the limiter must also delete the knob.
#[test]
fn max_concurrent_dispatches_knob_is_consumed() {
    let status = runtime_knob_registry()
        .iter()
        .find(|(name, _)| *name == "max_concurrent_dispatches")
        .map(|(_, status)| *status)
        .expect("max_concurrent_dispatches must be in the runtime knob registry");
    assert!(
        matches!(status, KnobStatus::Consumed(_)),
        "max_concurrent_dispatches is wired to the dispatch limiter; it must be \
         KnobStatus::Consumed, got {status:?}"
    );
}

/// RED demonstration: a struct carrying a serde field that is ABSENT from the
/// registry is flagged. We simulate a future dead knob by injecting an extra
/// key into the serialized `RuntimeConfig` object and asserting the guard
/// reports it — proving the mechanism is demonstrably red for an unlisted knob.
#[test]
fn inert_knob_guard_flags_unregistered_field() {
    let mut value = serde_json::to_value(RuntimeConfig::default()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("future_dead_knob".to_string(), serde_json::json!(0));

    let findings = section_inert_knobs("runtime", &value, runtime_knob_registry());
    assert!(
        findings
            .iter()
            .any(|f| f.contains("runtime.future_dead_knob")),
        "an unregistered serde field must be flagged as inert, got {findings:?}"
    );
}

/// RED demonstration (reverse direction): a registry row with no matching
/// serde field (a stale entry left behind after deleting a knob) is flagged,
/// so registry and struct cannot silently drift apart.
#[test]
fn inert_knob_guard_flags_stale_registry_entry() {
    let stale: &[(&str, KnobStatus)] = &[(
        "removed_knob",
        KnobStatus::Consumed("no longer a serde field"),
    )];
    let findings = section_inert_knobs("vcs", &VcsConfig::default(), stale);
    assert!(
        findings.iter().any(|f| f.contains("vcs.removed_knob")),
        "a stale registry entry must be flagged, got {findings:?}"
    );
}

/// The consumed-knob rule is enforced at load time: a config whose declared knobs are all
/// classified validates OK (the operator-facing mirror of the unit guard).
#[test]
fn valid_config_passes_inert_knob_validation() {
    assert!(sample_config().validate().is_ok());
}

#[test]
fn vcs_config_defaults_the_repository_root_to_the_config_dir() {
    let cfg: VcsConfig = toml::from_str("").unwrap();
    assert_eq!(cfg.jj_repo, PathBuf::from("."));
}

/// A key no section declares is refused by the typed parse — the one door every
/// `kata.toml` loader goes through ([`parse_kata_config`]) — naming the key and the
/// dotted path it sits at, never dropped. The legs are keys an operator could
/// plausibly still type (each one named a setting at some point before 0.0.1) plus
/// the shapes `[workflows]` can take; none has its own refusal, so the generic one
/// is the whole of what stands between each and a silently ignored line. The worker
/// file's top level is closed the same way, at [`load_worker_config`].
///
/// **Watched red:** with `deny_unknown_fields` dropped from `RuntimeConfig`, the four
/// `[runtime]` legs parse and this cell names each one.
#[test]
fn undeclared_keys_are_refused_at_parse_naming_their_path() {
    let mut wrong = Vec::new();
    // (dotted path, key, where the line goes, the line). `""` places a bare key
    // above the first table; `"$"` appends a table after the last.
    for (at, key, after, line) in [
        ("workflows", "workflows", "$", "[workflows]\n"),
        (
            "workflows",
            "workflows",
            "$",
            "[workflows]\nreview = { stages = 3 }\n",
        ),
        ("workflows", "workflows", "", "workflows = 1\n"),
        (
            "node.execution_profile",
            "execution_profile",
            "[node]\n",
            "execution_profile = \"oci\"\n",
        ),
        ("node.role", "role", "[node]\n", "role = \"home\"\n"),
        (
            "node.trust_domain",
            "trust_domain",
            "[node]\n",
            "trust_domain = \"old\"\n",
        ),
        (
            "vcs.execution_workspace_backend",
            "execution_workspace_backend",
            "[vcs]\n",
            "execution_workspace_backend = \"git_worktree\"\n",
        ),
        (
            "vcs.execution_workspace_backend",
            "execution_workspace_backend",
            "[vcs]\n",
            "execution_workspace_backend = \"jj\"\n",
        ),
        (
            "vcs.build_pool_enabled",
            "build_pool_enabled",
            "[vcs]\n",
            "build_pool_enabled = true\n",
        ),
        (
            "agents.default",
            "prompt_timeout_secs",
            "[agents.default]\n",
            "prompt_timeout_secs = 600\n",
        ),
        (
            "runtime.default_stage_timeout_secs",
            "default_stage_timeout_secs",
            "[runtime]\n",
            "default_stage_timeout_secs = 600\n",
        ),
        (
            "runtime.max_concurrent_tasks",
            "max_concurrent_tasks",
            "[runtime]\n",
            "max_concurrent_tasks = 64\n",
        ),
        (
            "runtime.execution_profile",
            "execution_profile",
            "[runtime]\n",
            "execution_profile = \"oci\"\n",
        ),
        (
            "runtime.environment",
            "environment",
            "[runtime]\n",
            "environment = { label = \"x\" }\n",
        ),
        (
            "workers.require_signed_credential",
            "require_signed_credential",
            "[workers]\n",
            "require_signed_credential = true\n",
        ),
        (
            "workers.max_retries_per_stage",
            "max_retries_per_stage",
            "[workers]\n",
            "max_retries_per_stage = 3\n",
        ),
        (
            "workers.max_resumes",
            "max_resumes",
            "[workers]\n",
            "max_resumes = 3\n",
        ),
        (
            "telemetry.cost_tracking",
            "cost_tracking",
            "[telemetry]\n",
            "cost_tracking = false\n",
        ),
        (
            "agents.default",
            "executable",
            "[agents.default]\n",
            "executable = \"/usr/bin/codex\"\n",
        ),
    ] {
        let text = match after {
            "" => format!("{line}{DOC_MINIMAL_CONFIG}"),
            "$" => format!("{DOC_MINIMAL_CONFIG}\n{line}"),
            header => {
                assert!(DOC_MINIMAL_CONFIG.contains(header), "the base has {header}");
                DOC_MINIMAL_CONFIG.replacen(header, &format!("{header}{line}"), 1)
            }
        };
        match parse_kata_config(&text, Path::new("kata.toml")) {
            Ok(_) => wrong.push(format!("admitted `{key}` at `{at}`")),
            Err(error) => {
                let error = error.to_string();
                if !(error.contains(&format!(" at `{at}`"))
                    && error.contains(&format!("unknown field `{key}`")))
                {
                    wrong.push(format!(
                        "refused `{key}` without naming it at `{at}`: {error}"
                    ));
                }
            }
        }
    }
    // NON-VACUITY: the base every leg was planted in loads.
    if let Err(error) = parse_kata_config(DOC_MINIMAL_CONFIG, Path::new("kata.toml")) {
        wrong.push(format!("the control refused: {error}"));
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("worker.toml");
    let worker = "home_node_endpoint = 'unix:///tmp/kata-worker.sock'\ncredential_path = \
                  '/tmp/kata-worker.cred'\nexpected_membrane_id = \
                  '01ARZ3NDEKTSV4RRFFQ69G5FAV'\ncapabilities = []\n";
    std::fs::write(&path, format!("{worker}execution_profile = \"oci\"\n")).unwrap();
    match load_worker_config(&path) {
        Ok(_) => wrong.push("the worker file admitted `execution_profile`".to_owned()),
        Err(error) => {
            let error = error.to_string();
            if !(error.contains(" at `execution_profile`")
                && error.contains("unknown field `execution_profile`"))
            {
                wrong.push(format!(
                    "the worker file refused without naming the key: {error}"
                ));
            }
        }
    }
    std::fs::write(&path, worker).unwrap();
    if let Err(error) = load_worker_config(&path) {
        wrong.push(format!("the worker control refused: {error}"));
    }
    assert!(
        wrong.is_empty(),
        "undeclared keys were not refused by name and path:\n{}",
        wrong.join("\n")
    );
}

/// Parses `[agents.<label>]` blocks the way every loader does — through
/// [`kata_types::config::deserialize_agents`] on the `agents` key.
fn parse_agents(text: &str) -> BTreeMap<String, AgentBackendConfig> {
    #[derive(Deserialize)]
    struct Wrap {
        #[serde(deserialize_with = "kata_types::config::deserialize_agents")]
        agents: BTreeMap<String, AgentBackendConfig>,
    }
    toml::from_str::<Wrap>(text)
        .expect("the agents table parses")
        .agents
}

#[test]
fn agent_backend_config_parses_harness_minimal_reasoning_effort_defaults_none() {
    // A harness block without `reasoning_effort` parses with the serde default
    // (None), and an empty block is a harness entry with every field unset.
    assert_eq!(
        parse_agents("[agents.default]\n")["default"],
        AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: None,
            credential: None,
            env: std::collections::BTreeMap::new(),
        }
    );
}

/// A nanocode-kind block the way an operator writes it, under adapter label
/// `kind`.
fn nanocode_agent(kind: &str) -> AgentBackendConfig {
    AgentBackendConfig::Harness {
        model: Some("gpt-6-luna".to_owned()),
        reasoning_effort: None,
        adapter: Some(kind.to_owned()),
        credential: None,
        env: BTreeMap::new(),
    }
}

/// **`adapter_unqualified` refuses exactly an adapter label that names no
/// kind.** `capsule_launch` (the judgement assembly and `kata doctor` ask)
/// answers every kind's own label with that kind, and answers
/// `AdapterUnqualified` naming the label for spellings that name none — an
/// unknown word, a case variant, a hyphenated init spelling, a kind's prefix,
/// a label with whitespace, a removed vendor adapter's.
///
/// **Would red if:** a kind's own label were refused (watched: a filter
/// dropping `nanocode_anthropic`), or a spelling that names no kind were
/// admitted.
#[test]
fn adapter_unqualified_is_exactly_a_label_that_names_no_kind() {
    use kata_types::agent::AdapterKind;
    use kata_types::config::CapsuleLaunchProblem;
    for kind in AdapterKind::ALL {
        let label = kind.as_label();
        let launched = nanocode_agent(label)
            .capsule_launch()
            .unwrap_or_else(|problem| panic!("{label}: its own label launches: {problem:?}"));
        assert_eq!(launched, kind, "{label}");
    }
    for label in [
        "imaginary_adapter",
        "Codex_App_Server",
        "nanocode-openai",
        "nanocode",
        "nanocode_openai ",
        "codex_app_server",
    ] {
        assert_eq!(
            nanocode_agent(label).capsule_launch(),
            Err(CapsuleLaunchProblem::AdapterUnqualified(label.to_owned())),
            "`{label}` names no kind"
        );
    }
}

/// **An agent block declaring `argv` or `egress_extra` is refused at parse as
/// an unknown field.** Every kind's launch is fixed by the kind (its capsule's
/// init is `kata-toolhost`) and its capsule opens no endpoint of its own (the
/// harness's model traffic leaves from the worker), so neither is a field of a
/// harness block: a config still declaring either — empty or not —
/// fails to load naming the field, never silently accepted, as `[node]
/// host_logins` does. The same block without them loads.
///
/// **Would red if:** either field were parsed again (watched: with both fields
/// on `AgentBackendConfig::Harness`, every one of these configs loaded).
#[test]
fn an_agent_block_declaring_argv_or_egress_extra_is_refused_as_an_unknown_field() {
    let node = full_kata_config_toml_with_auth(
        "type = \"signed_token\"\nverifying_key_env = \"API_VERIFYING_KEY\"",
    );
    let block = "\n[agents.coder]\nadapter = \"nanocode_openai\"\n\
                 credential = { mode = \"api_key\", source = \"env:OPENAI_API_KEY\" }\n";
    toml::from_str::<KataConfig>(&format!("{node}{block}"))
        .expect("the block declaring neither field loads");
    for (field, value) in [
        ("argv", "[\"kata-toolhost\"]"),
        ("argv", "[]"),
        ("egress_extra", "[\"registry.internal:443\"]"),
        ("egress_extra", "[]"),
    ] {
        let message = toml::from_str::<KataConfig>(&format!("{node}{block}{field} = {value}\n"))
            .map(|_| ())
            .expect_err("an agent block declaring a removed field does not load")
            .to_string();
        assert!(
            message.contains("unknown field") && message.contains(&format!("`{field}`")),
            "{field} = {value}: {message}"
        );
    }
}

#[test]
fn agent_backend_config_parses_harness_reasoning_effort() {
    assert_eq!(
        parse_agents("[agents.default]\nmodel = \"gpt-6-luna\"\nreasoning_effort = \"medium\"\n")["default"],
        AgentBackendConfig::Harness {
            model: Some("gpt-6-luna".into()),
            reasoning_effort: Some("medium".into()),
            adapter: None,
            credential: None,
            env: std::collections::BTreeMap::new(),
        }
    );
}

#[test]
fn agents_map_parses_multi_entry_toml() {
    // The full `[agents.foo]` / `[agents.bar]` shape: the label, not a
    // discriminator, decides each entry's backend.
    let agents = parse_agents(
        "[agents.default]\nmodel = \"gpt-6-luna\"\n\n[agents.fallback]\n\n[agents.shell]\n",
    );
    assert_eq!(agents.len(), 3);
    assert!(matches!(
        agents.get("default"),
        Some(AgentBackendConfig::Harness { model: Some(model), .. }) if model == "gpt-6-luna"
    ));
    assert!(matches!(
        agents.get("fallback"),
        Some(AgentBackendConfig::Harness { model: None, .. })
    ));
    assert_eq!(agents.get("shell"), Some(&AgentBackendConfig::Shell {}));
}

#[test]
fn worker_pool_config_defaults_parse() {
    // A `[workers]` section that carries only the required keys still parses
    // and fills every defaulted knob.
    let toml_text = r#"
transports = [{ type = "supervised_node" }]
dispatch_deadline_ms = 5000
heartbeat_interval_ms = 2500
heartbeat_grace_ms = 10000
max_workers = 4
"#;
    let cfg: WorkerPoolConfig = toml::from_str(toml_text).unwrap();
    assert_eq!(cfg.assignment_start_deadline_ms, 900_000);
}

/// Helper for credential tests: builds a unique per-test path
/// under `std::env::temp_dir()`. We don't pull in `tempfile`
/// just for these tests because the `kata-types` crate has no
/// dev-deps beyond the workspace minimum and the operator cost
/// of adding one would outweigh the value.
fn unique_cred_path(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut path = std::env::temp_dir();
    path.push(format!("kata-types-cred-{tag}-{pid}-{nanos}.toml"));
    path
}

fn write_private_cred(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    set_private_file_mode(path);
}

#[cfg(unix)]
fn set_private_file_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn set_private_file_mode(_path: &Path) {}

#[test]
fn worker_shared_secret_toml_roundtrip() {
    let path = unique_cred_path("roundtrip");
    write_private_cred(&path, "secret = \"abc-xyz\"\n");
    let cred = load_worker_shared_secret(&path).expect("credential must load");
    assert_eq!(cred.secret, "abc-xyz");

    // Round-trip via toml::to_string_pretty to pin the serialized shape.
    let rendered = toml::to_string_pretty(&cred).unwrap();
    let back: WorkerSharedSecret = toml::from_str(&rendered).unwrap();
    assert_eq!(back, cred);
    std::fs::remove_file(&path).ok();
}

#[test]
fn worker_shared_secret_rejects_empty_secret() {
    let path = unique_cred_path("empty");
    write_private_cred(&path, "secret = \"\"\n");
    let err = load_worker_shared_secret(&path).expect_err("empty secret must fail");
    assert!(matches!(err, KataError::Validation(_)));
    std::fs::remove_file(&path).ok();
}

#[test]
fn worker_shared_secret_rejects_missing_file() {
    let path = unique_cred_path("missing");
    // Deliberately do NOT create the file.
    let err = load_worker_shared_secret(&path).expect_err("missing file must fail");
    assert!(matches!(err, KataError::Config(_)));
}

/// A credential file holding only the secret's bytes, without the
/// `secret = "..."` TOML wrapper `kata-worker provision` writes, is REFUSED with
/// the TOML parse error naming the file — never read as a secret by a shape
/// guess.
#[test]
fn worker_shared_secret_refuses_a_file_without_the_toml_wrapper() {
    let path = unique_cred_path("unwrapped");
    write_private_cred(&path, "fake-shared-secret-0123456789abc\n");
    let err = load_worker_shared_secret(&path).expect_err("an unwrapped secret must not load");
    assert!(
        matches!(&err, KataError::Config(msg)
            if msg.contains("failed to parse credential") && msg.contains("unwrapped")),
        "the refusal is the TOML parse error naming the file: {err}"
    );
    std::fs::remove_file(&path).ok();
}

/// Malformed TOML surfaces the TOML parse error.
#[test]
fn worker_shared_secret_rejects_malformed_toml() {
    let path = unique_cred_path("malformed");
    write_private_cred(&path, "secret = abc\n"); // unquoted value
    let err = load_worker_shared_secret(&path).expect_err("malformed must fail");
    assert!(matches!(err, KataError::Config(msg) if msg.contains("failed to parse credential")),);
    std::fs::remove_file(&path).ok();
}

/// Multi-line content that isn't TOML is refused.
#[test]
fn worker_shared_secret_rejects_multiline_noisy_content() {
    let path = unique_cred_path("noisy");
    write_private_cred(&path, "not\na\nsecret\n");
    let err = load_worker_shared_secret(&path).expect_err("noisy content must fail");
    assert!(matches!(err, KataError::Config(_)));
    std::fs::remove_file(&path).ok();
}

#[cfg(unix)]
#[test]
fn worker_shared_secret_rejects_group_readable_credential_file() {
    use std::os::unix::fs::PermissionsExt;

    let path = unique_cred_path("group-readable");
    std::fs::write(&path, "secret = \"abc-xyz\"\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let err =
        load_worker_shared_secret(&path).expect_err("group-readable credential must fail closed");
    assert!(
        matches!(err, KataError::Validation(ref msg) if msg.contains("chmod 600")),
        "error should include chmod remediation, got {err:?}"
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn worker_shared_secret_rejects_non_file_credential_path() {
    let path = unique_cred_path("directory");
    std::fs::create_dir(&path).unwrap();
    let err = load_worker_shared_secret(&path).expect_err("directory credential must fail closed");
    assert!(
        matches!(err, KataError::Validation(ref msg) if msg.contains("regular file")),
        "expected regular-file validation error, got {err:?}"
    );
    std::fs::remove_dir(&path).ok();
}

#[cfg(unix)]
#[test]
fn worker_shared_secret_rejects_symlink_credential_path() {
    let target = unique_cred_path("symlink-target");
    let link = unique_cred_path("symlink-link");
    write_private_cred(&target, "secret = \"abc-xyz\"\n");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = load_worker_shared_secret(&link).expect_err("symlink credential must fail closed");
    assert!(
        matches!(err, KataError::Validation(ref msg) if msg.contains("symlink")),
        "expected symlink validation error, got {err:?}"
    );
    std::fs::remove_file(&link).ok();
    std::fs::remove_file(&target).ok();
}

// ───────────────────────────────────────────────────────────
// tilde expansion
// ───────────────────────────────────────────────────────────

/// `~/<rest>` expands to `<home>/<rest>` when an explicit home is
/// supplied. Uses `expand_tilde_with` so the test is independent of
/// the machine's real `$HOME`.
#[test]
fn tilde_expansion_expands_home_prefix() {
    let home = std::ffi::OsString::from("/home/alice");
    let expanded = expand_tilde_with(Path::new("~/.kata/data"), Some(home.as_os_str()));
    assert_eq!(expanded, PathBuf::from("/home/alice/.kata/data"));
}

/// Absolute paths (any leading `/`) are returned verbatim.
#[test]
fn tilde_expansion_noop_on_absolute_path() {
    let home = std::ffi::OsString::from("/home/alice");
    let expanded = expand_tilde_with(Path::new("/etc/kata"), Some(home.as_os_str()));
    assert_eq!(expanded, PathBuf::from("/etc/kata"));
}

/// Relative paths without a leading tilde are returned verbatim.
#[test]
fn tilde_expansion_noop_on_relative_path() {
    let home = std::ffi::OsString::from("/home/alice");
    let expanded = expand_tilde_with(Path::new("./data"), Some(home.as_os_str()));
    assert_eq!(expanded, PathBuf::from("./data"));
    let expanded = expand_tilde_with(Path::new("relative/path"), Some(home.as_os_str()));
    assert_eq!(expanded, PathBuf::from("relative/path"));
}

/// A bare `~` expands to `$HOME` itself, with no trailing slash.
#[test]
fn tilde_expansion_bare_tilde() {
    let home = std::ffi::OsString::from("/home/alice");
    let expanded = expand_tilde_with(Path::new("~"), Some(home.as_os_str()));
    assert_eq!(expanded, PathBuf::from("/home/alice"));
}

/// When `$HOME` is unset (`home = None`), the path is returned
/// unchanged — deterministic fallback, never panics.
#[test]
fn tilde_expansion_no_home_env_leaves_unchanged() {
    let tilde = expand_tilde_with(Path::new("~"), None);
    assert_eq!(tilde, PathBuf::from("~"));
    let tilde_slash = expand_tilde_with(Path::new("~/foo"), None);
    assert_eq!(tilde_slash, PathBuf::from("~/foo"));
}

/// Embedded `~` (not at the start of the path) is left alone —
/// only the *leading* tilde expands, matching POSIX shells.
#[test]
fn tilde_expansion_only_leading_tilde() {
    let home = std::ffi::OsString::from("/home/alice");
    let expanded = expand_tilde_with(Path::new("/opt/~-cache"), Some(home.as_os_str()));
    assert_eq!(expanded, PathBuf::from("/opt/~-cache"));
}

/// `load_config_placeholder` runs `normalize_paths` so a
/// deserialized `data_dir = "~/test-kata-data"` surfaces as the
/// absolute `$HOME/test-kata-data`.
///
/// Skipped when `$HOME` is not set. Every sane Rust test harness
/// (nextest included) has it set; the skip just keeps the test
/// from flaking on exotic runners.
#[test]
fn kata_config_load_expands_data_dir() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "kata-cfg-expand-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let text = r#"
[node]
id = "home-1"
data_dir = "~/test-kata-data"

[api]
bind = "127.0.0.1:8400"
[api.auth]
type = "disabled"

[workers]
dispatch_deadline_ms = 30000
heartbeat_interval_ms = 10000
heartbeat_grace_ms = 30000
max_workers = 4
[[workers.transports]]
type = "supervised_node"
"#;
    std::fs::write(&path, text).unwrap();
    let cfg = load_config_placeholder(&path).expect("config must load");
    let expected = PathBuf::from(&home).join("test-kata-data");
    assert_eq!(
        cfg.node.data_dir, expected,
        "data_dir must be tilde-expanded at load time"
    );
    assert!(
        cfg.node.data_dir.is_absolute(),
        "expanded data_dir must be absolute, got {:?}",
        cfg.node.data_dir
    );
    assert!(
        !cfg.node.data_dir.to_string_lossy().starts_with('~'),
        "expanded data_dir must not start with '~', got {:?}",
        cfg.node.data_dir
    );
    std::fs::remove_file(&path).ok();
}

/// A main config whose only worker transport names the network transport kata
/// does not have, read by `remote_worker_enrollment_is_refused_from_both_ends`.
const MAIN_CONFIG_WITH_WEBSOCKET_TRANSPORT: &str = r#"
[node]
id = "home-1"
data_dir = "/var/lib/kata"

[api]
bind = "127.0.0.1:8400"
[api.auth]
type = "disabled"

[workers]
dispatch_deadline_ms = 30000
heartbeat_interval_ms = 10000
heartbeat_grace_ms = 30000
max_workers = 4
[[workers.transports]]
type = "web_socket"
bind = "0.0.0.0:7743"
[workers.transports.tls]
cert_path = "~/.kata/tls/cert.pem"
key_path  = "~/.kata/tls/key.pem"
ca_path   = "~/.kata/tls/ca.pem"
require_client_auth = true
"#;

#[test]
fn kata_config_load_expands_api_auth_verifying_key_file() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "kata-cfg-api-verifying-key-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let text = r#"
[node]
id = "home-1"
data_dir = "/var/lib/kata"

[api]
bind = "127.0.0.1:8400"
[api.auth]
type = "signed_token"
verifying_key_file = "~/.config/kata/api-verifying-key"

[workers]
dispatch_deadline_ms = 30000
heartbeat_interval_ms = 10000
heartbeat_grace_ms = 30000
max_workers = 4
[[workers.transports]]
type = "supervised_node"
"#;
    std::fs::write(&path, text).unwrap();
    let cfg = load_config_placeholder(&path).expect("config must load");
    let expected = PathBuf::from(&home).join(".config/kata/api-verifying-key");
    match cfg.api.auth {
        ApiAuthConfig::SignedToken {
            verifying_key_file, ..
        } => assert_eq!(verifying_key_file, Some(expected)),
        ApiAuthConfig::Disabled {} => panic!("expected signed_token auth, got disabled auth"),
    }
    std::fs::remove_file(&path).ok();
}

/// `load_worker_config` expands `credential_path` so the worker
/// daemon observes an absolute path.
#[test]
fn worker_config_load_expands_credential_path() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "kata-cfg-worker-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let text = r#"
home_node_endpoint = "unix:///tmp/kata-worker.sock"
credential_path = "~/.kata/worker.cred"
expected_membrane_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
capabilities = []
"#;
    std::fs::write(&path, text).unwrap();
    let cfg = load_worker_config(&path).expect("worker config must load");
    assert_eq!(
        cfg.credential_path,
        PathBuf::from(&home).join(".kata/worker.cred")
    );
    assert!(
        !cfg.credential_path.to_string_lossy().starts_with('~'),
        "expanded credential_path must not start with '~', got {:?}",
        cfg.credential_path
    );
    std::fs::remove_file(&path).ok();
}

#[test]
fn worker_config_requires_provisioned_membrane_identity() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("worker.toml");
    std::fs::write(&path, "home_node_endpoint = 'unix:///tmp/worker.sock'\ncredential_path = '/tmp/worker.cred'\ncapabilities = []\n").unwrap();
    let error = kata_types::config::load_worker_config(&path)
        .unwrap_err()
        .to_string();
    assert!(error.contains("expected_membrane_id"), "{error}");
}

/// **A worker's `home_node_endpoint` socket NAME past 82 bytes is refused at load,
/// naming the limit; its directory's length is not refused at all.** The socket is
/// connected through its parent's descriptor (`/proc/self/fd/<fd>/<name>`), so a
/// 300-byte directory with an 82-byte name loads, and the same directory with an
/// 83-byte name is refused before the daemon dials anything.
#[test]
fn a_worker_endpoint_socket_name_past_the_bound_is_refused_and_a_long_directory_is_not() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("worker.toml");
    let directory = format!("/{}", vec!["d".repeat(60); 5].join("/"));
    let write = |name_len: usize| {
        std::fs::write(
            &path,
            format!(
                "home_node_endpoint = 'unix://{directory}/{name}'\ncredential_path = \
                 '/tmp/kata-worker.cred'\nexpected_membrane_id = '01ARZ3NDEKTSV4RRFFQ69G5FAV'\n\
                 capabilities = []\n",
                name = "w".repeat(name_len),
            ),
        )
        .unwrap();
    };
    write(82);
    load_worker_config(&path).expect("an 82-byte name under a 300-byte directory loads");
    write(83);
    let error = load_worker_config(&path)
        .expect_err("an 83-byte name is refused")
        .to_string();
    assert!(error.contains("home_node_endpoint"), "{error}");
    assert!(error.contains("may be at most 82 bytes"), "{error}");
}

/// **A KEY `worker.toml` DOES NOT DECLARE IS REFUSED AT LOAD, NAMING THE KEY AND WHERE
/// IT SITS** — at the file's top level and in a `capabilities` entry. The daemon's
/// data-plane path (`main_data_dir`) lives in this file, so a misspelling would load as
/// the default — no main data dir — and surface later as a refusal that points
/// somewhere else.
///
/// The control leg (the same file without the misspelling) loads, so each refusal is
/// the misspelling's.
///
/// The refused set exercised: a misspelling at the top level, beside a
/// `capabilities` entry's `kind`, and inside its `data` table; and the network-worker
/// keys no worker reads (`worker_id`, `signed_credential_path`, a `[tls]` table), each
/// an unknown top-level key like any misspelling.
///
/// **Watched red:** with `deny_unknown_fields` off `WorkerNodeConfig`, every
/// top-level leg loaded (`worker_id`, `signed_credential_path` and `tls` included);
/// with it off `WorkerResource`, both `capabilities` legs loaded.
#[test]
fn worker_config_refuses_a_misspelled_key_by_name() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("worker.toml");
    let base = "home_node_endpoint = 'unix:///tmp/kata-worker.sock'\ncredential_path = \
                '/tmp/kata-worker.cred'\nexpected_membrane_id = '01ARZ3NDEKTSV4RRFFQ69G5FAV'\n\
                capabilities = []\n";
    std::fs::write(&path, base).unwrap();
    load_worker_config(&path).expect("the control file loads");

    let mut wrong = Vec::new();
    for (at, key, planted) in [
        ("host_login", "host_login", "host_login = ['codex_login']\n"),
        (
            "main_data_directory",
            "main_data_directory",
            "main_data_directory = '/var/lib/kata'\n",
        ),
        ("worker_id", "worker_id", "worker_id = 'worker-7'\n"),
        (
            "signed_credential_path",
            "signed_credential_path",
            "signed_credential_path = '/tmp/kata-worker.signed.json'\n",
        ),
        (
            "tls",
            "tls",
            "[tls]\ncert_path = '/c.pem'\nkey_path = '/k.pem'\nca_path = '/ca.pem'\n",
        ),
        (
            "capabilities[0].bogus_entry",
            "bogus_entry",
            "capabilities = [{ kind = 'shell', bogus_entry = 2 }]\n",
        ),
        (
            "capabilities[0].data.min_vram_gb",
            "min_vram_gb",
            "capabilities = [{ kind = 'disk', data = { min_gb = 1, min_vram_gb = 2 } }]\n",
        ),
    ] {
        // A `capabilities` leg replaces the base's empty list rather than repeating it.
        let base = if planted.starts_with("capabilities") {
            base.replace("capabilities = []\n", "")
        } else {
            base.to_owned()
        };
        std::fs::write(&path, format!("{base}{planted}")).unwrap();
        match load_worker_config(&path) {
            Ok(_) => wrong.push(format!("admitted `{key}` at `{at}`")),
            Err(error) => {
                let error = error.to_string();
                // serde words a key beside an adjacently tagged enum's `kind`/`data`
                // as an invalid value, not an unknown field; both name the key.
                let names_key = error.contains(&format!("unknown field `{key}`"))
                    || error.contains(&format!("invalid value: string \"{key}\""));
                if !(error.contains(&format!(" at `{at}`")) && names_key) {
                    wrong.push(format!(
                        "refused `{key}` without naming it at `{at}`: {error}"
                    ));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "misspelled worker.toml keys were not refused by name:\n{}",
        wrong.join("\n")
    );
}

/// **A `[[pricing.models]]` RATE OR MULTIPLIER THAT IS NOT A FINITE, NON-NEGATIVE
/// NUMBER IS REFUSED AT LOAD, NAMING THE ROW AND THE FIELD.** A NaN rate prices every
/// call at NaN and, since `KataConfig` compares rows by `f64` equality, makes every
/// reload report `pricing` restart-required against an unchanged row; a negative or
/// infinite one is a meter no provider publishes.
///
/// The refused set exercised: `nan`, `inf` and `-1.0` in each of the four fields. Zero
/// is admitted (the control leg), since an operator may price a free model.
///
/// **Watched red:** with the rate check absent from `KataConfig::validate`, every leg
/// loaded.
#[test]
fn a_pricing_rate_that_is_not_a_finite_non_negative_number_is_refused_at_load() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("kata.toml");
    let base = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal_config.toml"),
    )
    .unwrap();
    let row = |field: &str, value: &str| {
        let mut row = String::from(
            "\n[[pricing.models]]\nbackend = \"anthropic\"\nmodel = \"claude-sonnet-5-5\"\n",
        );
        for name in [
            "input_rate_per_mtok",
            "output_rate_per_mtok",
            "cache_read_multiplier",
            "cache_write_multiplier",
        ] {
            let value = if name == field { value } else { "0.0" };
            writeln!(row, "{name} = {value}").unwrap();
        }
        format!("{base}{row}")
    };
    std::fs::write(&path, row("input_rate_per_mtok", "0.0")).unwrap();
    load_config_placeholder(&path).expect("an all-zero row loads");

    let mut wrong = Vec::new();
    for field in [
        "input_rate_per_mtok",
        "output_rate_per_mtok",
        "cache_read_multiplier",
        "cache_write_multiplier",
    ] {
        for value in ["nan", "inf", "-1.0"] {
            std::fs::write(&path, row(field, value)).unwrap();
            match load_config_placeholder(&path) {
                Ok(_) => wrong.push(format!("admitted {field} = {value}")),
                Err(error) => {
                    let error = error.to_string();
                    if !error.contains(&format!("pricing.models[0].{field}")) {
                        wrong.push(format!(
                            "refused {field} = {value} without naming it: {error}"
                        ));
                    }
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "pricing rates were not refused by name:\n{}",
        wrong.join("\n")
    );
}

/// **A `[[pricing.models]]` ROW THAT OMITS EITHER CACHE MULTIPLIER IS REFUSED AT LOAD,
/// FOR EVERY BACKEND.** The kind kata prices (`nanocode_anthropic`) counts a turn's
/// prompt-cache reads and writes apart from its input, so a row bills each class through its
/// own multiplier alone: a default would bill it nothing, and a dollar bound enforced against
/// the row would under-count every turn that reads or writes cache.
///
/// The refused set exercised: an `anthropic` row with no `cache_read_multiplier` key, and the
/// same row with no `cache_write_multiplier` key, each refused naming the missing field.
/// Admitted (the control legs): the same row stating it — `1.0`, `1.25` (Anthropic's
/// 5-minute write), `0.1` and an explicit `0.0`, which is the operator's own statement.
///
/// **Would red if:** an omitted multiplier defaulted (the row loads, billing that class
/// nothing).
#[test]
fn a_pricing_row_that_omits_a_cache_multiplier_is_refused_at_load() {
    const MULTIPLIERS: [&str; 2] = ["cache_read_multiplier", "cache_write_multiplier"];
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("kata.toml");
    let base = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/minimal_config.toml"),
    )
    .unwrap();
    // A row stating every multiplier but `field`, which is `value` or absent.
    let row = |backend: &str, field: &str, value: Option<&str>| {
        let mut row = format!(
            "\n[[pricing.models]]\nbackend = \"{backend}\"\nmodel = \"m\"\n\
             input_rate_per_mtok = 1.0\noutput_rate_per_mtok = 2.0\n"
        );
        for name in MULTIPLIERS {
            match (name == field, value) {
                (false, _) => writeln!(row, "{name} = 1.0").unwrap(),
                (true, Some(value)) => writeln!(row, "{name} = {value}").unwrap(),
                (true, None) => {}
            }
        }
        format!("{base}{row}")
    };
    let mut wrong = Vec::new();
    for backend in ["anthropic"] {
        for field in MULTIPLIERS {
            std::fs::write(&path, row(backend, field, None)).unwrap();
            match load_config_placeholder(&path) {
                Ok(_) => wrong.push(format!("admitted the {backend} row with no {field}")),
                Err(error) => {
                    let error = error.to_string();
                    if !error.contains(field) {
                        wrong.push(format!(
                            "refused the {backend} row with no {field} without naming it: {error}"
                        ));
                    }
                }
            }
            for value in ["1.0", "1.25", "0.1", "0.0"] {
                std::fs::write(&path, row(backend, field, Some(value))).unwrap();
                if let Err(error) = load_config_placeholder(&path) {
                    wrong.push(format!(
                        "refused a {backend} row stating {field} = {value}: {error}"
                    ));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// `normalize_paths` is idempotent: a second call is a no-op.
#[test]
fn normalize_paths_is_idempotent() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let mut cfg = sample_config();
    cfg.node.data_dir = PathBuf::from("~/.kata/data");
    cfg.normalize_paths();
    let after_first = cfg.clone();
    cfg.normalize_paths();
    assert_eq!(
        cfg, after_first,
        "normalize_paths must be idempotent; got divergent state across two applications"
    );
    assert_eq!(cfg.node.data_dir, PathBuf::from(&home).join(".kata/data"));
}

/// A worker outside the main's host cannot be ENROLLED, from either end.
///
/// | end | refusal | what survives |
/// |---|---|---|
/// | main | `workers.transports` `type = "web_socket"` is an unknown variant | `supervised_node` (a node `kata serve` starts on its own host), `local_socket` (a Unix socket cannot cross a host) |
/// | worker | `home_node_endpoint` must be `unix://` | the same-host socket |
///
/// The main end is the transport enum's own parse refusal: there is no network
/// transport to configure, so the name is refused like any unknown one, naming it
/// and the variants that exist. The worker end cites the attempt protocol — "this
/// build has no versioned network worker protocol". This cell pins both, with a
/// positive control for the surviving scheme.
///
/// **Watched red:** with a `WebSocket { bind: String, tls: serde_json::Value }` variant
/// declared on `WorkerTransportConfig`, the main end's config loaded.
#[test]
fn remote_worker_enrollment_is_refused_from_both_ends() {
    let stamp = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );

    // (1) MAIN END. A network worker transport cannot be configured, so only
    // same-process and same-host workers can ever register.
    let main_path = std::env::temp_dir().join(format!("kata-fsfence-main-{stamp}.toml"));
    std::fs::write(&main_path, MAIN_CONFIG_WITH_WEBSOCKET_TRANSPORT).unwrap();
    let main_error = load_config_placeholder(&main_path)
        .expect_err("a network worker transport must stay unconfigurable");
    std::fs::remove_file(&main_path).ok();
    assert!(
        matches!(main_error, KataError::Config(_)),
        "the refusal is the transport enum's parse refusal: {main_error:?}"
    );
    let message = main_error.to_string();
    for named in [
        "unknown variant `web_socket`",
        "workers.transports",
        "supervised_node",
        "local_socket",
    ] {
        assert!(
            message.contains(named),
            "the parse refusal must name `{named}`; got {message}"
        );
    }

    // (2) WORKER END. Independently refused, so a worker cannot dial out to a
    // main on another host even if a main would take the call.
    let worker_path = std::env::temp_dir().join(format!("kata-fsfence-worker-{stamp}.toml"));
    for endpoint in ["wss://main.internal:7743", "ws://10.0.0.4:7743"] {
        std::fs::write(
            &worker_path,
            format!(
                r#"
home_node_endpoint = "{endpoint}"
credential_path = "/tmp/kata-worker.cred"
expected_membrane_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
capabilities = []
"#
            ),
        )
        .unwrap();
        let Err(worker_error) = load_worker_config(&worker_path) else {
            panic!("endpoint {endpoint} must be refused, but the worker config loaded");
        };
        assert!(
            matches!(worker_error, KataError::Validation(_)),
            "endpoint {endpoint} must be refused as a DECLARATION error: {worker_error:?}"
        );
        let message = worker_error.to_string();
        assert!(
            message.contains("unix://"),
            "the diagnostic must name the one scheme that survives; got {message}"
        );
    }

    // POSITIVE CONTROL: the surviving scheme still loads, so (2) is a fence on
    // remoteness and not a config path that refuses everything.
    std::fs::write(
        &worker_path,
        r#"
home_node_endpoint = "unix:///tmp/kata-worker.sock"
credential_path = "/tmp/kata-worker.cred"
expected_membrane_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
capabilities = []
"#,
    )
    .unwrap();
    let ok = load_worker_config(&worker_path).expect("the same-host socket endpoint still loads");
    assert_eq!(ok.home_node_endpoint, "unix:///tmp/kata-worker.sock");
    std::fs::remove_file(&worker_path).ok();
}
#[test]
fn recovery_remote_credentials_are_refused_before_config_can_be_archived() {
    let mut config = sample_config();
    config.vcs.recovery_remote = Some(kata_types::config::RecoveryRemoteConfig {
        id: "recovery".into(),
        url: "https://fixture-user:fixture-secret@example.invalid/recovery.git".into(),
    });
    let error = config.validate().expect_err(
        "configuration containing remote credentials must refuse before snapshot backup",
    );
    assert!(!error.to_string().contains("fixture-secret"));
}

// ---------------------------------------------------------------------------
// `[node] host_logins`, the host-login credential opt-in, at config load.
// ---------------------------------------------------------------------------

/// A capsule agent whose credential is `mode` + `source` — the shape an
/// operator writes under `[agents.<label>]`.
fn credentialed_agent(mode: &str, source: &str) -> kata_types::config::AgentBackendConfig {
    kata_types::config::AgentBackendConfig::Harness {
        model: None,
        reasoning_effort: None,
        adapter: Some("nanocode_openai".to_owned()),
        credential: Some(kata_types::config::AgentCredentialDecl {
            mode: mode.to_owned(),
            source: source.to_owned(),
        }),
        env: BTreeMap::new(),
    }
}

/// **`kata_login` pairs with either mode.** kata's own login holds an API key
/// or a ChatGPT login, so `api_key` and `subscription` both parse to
/// `CredentialSource::KataLogin`, and a node declaring it loads.
///
/// **Would red if:** the pairing refused `kata_login` under either mode.
#[test]
fn a_kata_login_credential_pairs_with_either_mode_and_needs_no_opt_in() {
    for mode in ["api_key", "subscription"] {
        let mut c = sample_config();
        let agent = credentialed_agent(mode, "kata_login");
        let reference = agent
            .capsule_credential_ref()
            .unwrap_or_else(|error| panic!("{mode}: kata_login parses: {error}"))
            .expect("a declared credential");
        assert_eq!(
            reference.source,
            kata_types::execution_contract::CredentialSource::KataLogin
        );
        assert_eq!(reference.mode.as_label(), mode);
        c.agents.insert("default".to_owned(), agent);
        c.validate()
            .unwrap_or_else(|error| panic!("{mode}: kata_login loads: {error}"));
    }
}

/// **A host login is no credential source, and `[node] host_logins` is no
/// config field.** kata reads no other tool's login: a block declaring
/// `source = "codex_login"` is refused at its credential parse, naming the
/// spellings kata admits, and a node still declaring `host_logins` (the
/// consent list host logins needed) is refused at parse as an unknown field —
/// never silently accepted.
///
/// **Would red if:** a host-login spelling parsed, or the removed field were
/// ignored.
#[test]
fn a_host_login_source_and_the_host_logins_field_are_refused() {
    let refused = credentialed_agent("subscription", "codex_login")
        .capsule_credential_ref()
        .expect_err("a host login is no credential source")
        .to_string();
    assert!(
        refused.contains("source `codex_login`")
            && refused.contains("the admitted spellings are `kata_login` or `env:<VAR>`"),
        "{refused}"
    );
    let text = full_kata_config_toml_with_auth(
        "type = \"signed_token\"\nverifying_key_env = \"API_VERIFYING_KEY\"",
    )
    .replace(
        "data_dir = \"/var/lib/kata\"\n",
        "data_dir = \"/var/lib/kata\"\nhost_logins = [\"codex_login\"]\n",
    );
    let message = toml::from_str::<KataConfig>(&text)
        .expect_err("`[node] host_logins` is no field")
        .to_string();
    assert!(
        message.contains("unknown field") && message.contains("host_logins"),
        "{message}"
    );
}

/// The `[node]`/`[workers]`/`[api]` sections of a loadable `kata.toml`, with no
/// `[agents]` table, so each D-5 cell plants exactly the agent blocks it names.
const D5_NODE: &str = "[node]\nid = \"d5\"\ndata_dir = \"data\"\n\n[workers]\n\
                       transports = [{ type = \"supervised_node\" }]\nmax_workers = 4\n\
                       dispatch_deadline_ms = 30000\nheartbeat_interval_ms = 10000\n\
                       heartbeat_grace_ms = 30000\n\n[api]\n\
                       bind = \"127.0.0.1:8400\"\nauth = { type = \"disabled\" }\n";

/// **An `[agents.<label>]` block still carrying `type` is refused at load,
/// naming `agent_type_removed` and telling the operator to delete the line.**
/// The harness is always kata's embedded one (`adapter` names its provider) and
/// the reserved label `shell` is the shell route, so `type` decides nothing:
/// every spelling it had — `codex`, `shell`, the retired vendor words — is
/// refused the same way, under a model label and under a reserved label alike,
/// and the error names the block.
///
/// **Would red if:** a `type` line loaded (watched: the tagged enum admitted
/// `type = "codex"` and `type = "shell"`), or the refusal did not name the block
/// and the line to delete.
#[test]
fn an_agent_block_carrying_type_is_refused_by_name() {
    for (label, block) in [
        (
            "default",
            "type = \"codex\"\nadapter = \"nanocode_openai\"\n",
        ),
        (
            "default",
            "adapter = \"nanocode_openai\"\ntype = \"codex\"\n",
        ),
        ("reviewer", "type = \"shell\"\n"),
        ("shell", "type = \"shell\"\n"),
        ("default", "type = \"claude_code\"\n"),
        ("extra", "type = \"open_code\"\n"),
        ("extra", "type = \"anthropic\"\n"),
        ("extra", "type = \"open_ai_compat\"\n"),
        ("workspace_effect", "type = \"shell\"\n"),
    ] {
        let text = format!("{D5_NODE}\n[agents.{label}]\n{block}");
        let error = parse_kata_config(&text, Path::new("kata.toml"))
            .map(|_| ())
            .expect_err("a block carrying `type` does not load")
            .to_string();
        assert!(
            error.contains("agent_type_removed")
                && error.contains(&format!("`[agents.{label}]`"))
                && error.contains("delete the `type = ...` line"),
            "[agents.{label}] {block:?}: {error}"
        );
    }
}

/// **A block with no `type` loads to the harness backend, and the reserved
/// `shell` label loads to the shell route.** The label, not a discriminator,
/// decides: `[agents.default]` with an `adapter` is a model agent carrying that
/// adapter; an empty `[agents.shell]` is the deterministic executor; a key under
/// `[agents.shell]` is refused by name, because the shell route takes none.
///
/// **Would red if:** a block with no `type` failed to load (watched: the tagged
/// enum refused it `missing field type`), the shell label loaded a model agent,
/// or `[agents.shell]` admitted a harness key.
#[test]
fn an_agent_block_without_type_loads_by_its_label() {
    let text = format!(
        "{D5_NODE}\n[agents.default]\nadapter = \"nanocode_openai\"\nmodel = \"gpt-6-luna\"\n\
         credential = {{ mode = \"subscription\", source = \"kata_login\" }}\n\n[agents.shell]\n"
    );
    let cfg = parse_kata_config(&text, Path::new("kata.toml")).expect("loads without `type`");
    cfg.validate().expect("validates");
    let default = &cfg.agents["default"];
    assert!(!default.is_deterministic(), "{default:?}");
    assert_eq!(default.capsule_adapter(), Some("nanocode_openai"));
    assert_eq!(default.capsule_model(), Some("gpt-6-luna"));
    assert!(
        cfg.agents["shell"].is_deterministic(),
        "{:?}",
        cfg.agents["shell"]
    );

    let text = format!("{D5_NODE}\n[agents.shell]\nmodel = \"gpt-6-luna\"\n");
    let error = parse_kata_config(&text, Path::new("kata.toml"))
        .map(|_| ())
        .expect_err("the shell route takes no key")
        .to_string();
    assert!(
        error.contains("shell_agent_block_keys") && error.contains("`model`"),
        "{error}"
    );
}

/// **A key no entry declares is refused under `[agents.shell]` as a key the
/// shell route does not take, never with a hint listing keys it also refuses.**
/// Under a model label an unknown key is an unknown field that lists the keys a
/// model agent takes; under a reserved deterministic label (`shell`,
/// `workspace_effect`) every key, known to a model agent or not, is refused
/// `shell_agent_block_keys` at the block's own path, naming each one, and the
/// error offers none of the model agent's keys. (This is the refusal
/// `undeclared_keys_are_refused_at_parse_naming_their_path` leaves to it.)
///
/// **Would red if:** an unknown key under a reserved label were refused with
/// the model agent's expected keys (watched: `unknown field `executable`,
/// expected one of `model`, `reasoning_effort`, `adapter`, `credential`,
/// `env``), or a reserved label's refusal dropped a key it was given.
#[test]
fn an_unknown_key_under_the_shell_label_is_refused_without_a_model_agents_hint() {
    for label in ["shell", "workspace_effect"] {
        for (block, keys) in [
            ("executable = \"sh\"\n", &["`executable`"][..]),
            (
                "model = \"gpt-6-luna\"\ntimeout_ms = 5\n",
                &["`model`", "`timeout_ms`"][..],
            ),
            (
                "timeout_ms = 5\nadapter = \"nanocode_openai\"\n",
                &["`timeout_ms`", "`adapter`"][..],
            ),
        ] {
            let text = format!("{D5_NODE}\n[agents.{label}]\n{block}");
            let error = parse_kata_config(&text, Path::new("kata.toml"))
                .map(|_| ())
                .expect_err("the shell route takes no key")
                .to_string();
            assert!(
                error.contains("shell_agent_block_keys")
                    && error.contains(&format!(" at `agents.{label}`"))
                    && error.contains(&format!("`[agents.{label}]`"))
                    && keys.iter().all(|key| error.contains(key))
                    && !error.contains("expected one of")
                    && !error.contains("`reasoning_effort`"),
                "[agents.{label}] {block:?}: {error}"
            );
        }
    }
    let text = format!("{D5_NODE}\n[agents.default]\nexecutable = \"sh\"\n");
    let error = parse_kata_config(&text, Path::new("kata.toml"))
        .map(|_| ())
        .expect_err("a model agent refuses an unknown key")
        .to_string();
    assert!(
        error.contains("unknown field `executable`") && error.contains("`reasoning_effort`"),
        "{error}"
    );
}
