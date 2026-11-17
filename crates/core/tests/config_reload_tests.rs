//! The runtime reload classifier applies only the log filter live. Every other
//! field is restart-required because installed subsystems retain the boot
//! snapshot rather than the manager's ArcSwap handle.
//!
//! `classify_changes` is the pure seam these tests target; `run_local_main`'s
//! watch closure layers the live log-level reload + logging on top via
//! `apply_reload`.

use std::collections::BTreeMap;

use kata_core::config_reload::{apply_reload, classify_changes};
use kata_types::config::{
    ApiAuthConfig, ApiConfig, KataConfig, NodeConfig, RuntimeConfig, WorkerPoolConfig,
    WorkerTransportConfig,
};

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
            id: "test-node".into(),
            data_dir: "/tmp/kata-test".into(),
            work_tree_max_bytes: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_BYTES,
            work_tree_max_entries: kata_types::tree_artifact::DEFAULT_WORK_TREE_MAX_ENTRIES,
            egress_allow: Vec::new(),
        },
        runtime: RuntimeConfig::default(),
        workers: WorkerPoolConfig {
            transports: vec![WorkerTransportConfig::SupervisedNode {}],
            dispatch_deadline_ms: 5000,
            assignment_start_deadline_ms: 900_000,
            heartbeat_interval_ms: 2500,
            heartbeat_grace_ms: 10000,
            max_workers: 4,
        },
        api: ApiConfig {
            bind: "127.0.0.1:8400".into(),
            auth: ApiAuthConfig::Disabled {},
        },
        agents: BTreeMap::new(),
        vcs: kata_types::config::VcsConfig::default(),
        telemetry: kata_types::config::TelemetryConfig::default(),
        containment: kata_types::config::ContainmentConfig::default(),
        git_view: kata_types::config::GitViewConfig::default(),
        pricing: kata_types::config::PricingConfig::default(),
    }
}

#[test]
fn no_change_is_empty() {
    let a = sample_config();
    let b = sample_config();
    let plan = classify_changes(&a, &b);
    assert!(
        plan.is_empty(),
        "identical configs must produce no change: {plan:?}"
    );
    assert!(!plan.needs_restart());
}

#[test]
fn log_level_is_classified_as_hot_reloadable() {
    let old = sample_config();
    let mut new = sample_config();
    new.telemetry.log_level = "debug".into();

    let plan = classify_changes(&old, &new);
    assert_eq!(plan.hot_reloadable, vec!["telemetry.log_level".to_string()]);
    assert!(
        plan.restart_required.is_empty(),
        "a log_level change must not require a restart: {plan:?}"
    );
    assert!(!plan.needs_restart());
}

/// A `[runtime]` residency knob is classified as boot-snapshot only, so changing
/// `max_active_executions` requires a restart.
#[test]
fn runtime_residency_budget_requires_restart() {
    let old = sample_config();
    let mut new = sample_config();
    new.runtime.max_active_executions += 64;

    let plan = classify_changes(&old, &new);
    assert!(plan.hot_reloadable.is_empty());
    assert_eq!(
        plan.restart_required,
        vec!["runtime.max_active_executions".to_string()]
    );
}

#[test]
fn api_bind_requires_restart() {
    let old = sample_config();
    let mut new = sample_config();
    new.api.bind = "127.0.0.1:9999".into();

    let plan = classify_changes(&old, &new);
    assert_eq!(plan.restart_required, vec!["api.bind".to_string()]);
    assert!(
        plan.hot_reloadable.is_empty(),
        "a cold field must not be reported as hot-reloadable: {plan:?}"
    );
    assert!(plan.needs_restart());
}

#[test]
fn data_dir_requires_restart() {
    let old = sample_config();
    let mut new = sample_config();
    new.node.data_dir = "/tmp/kata-other".into();

    let plan = classify_changes(&old, &new);
    assert_eq!(plan.restart_required, vec!["node.data_dir".to_string()]);
    assert!(plan.hot_reloadable.is_empty());
}

#[test]
fn dispatch_admission_cap_is_cold() {
    let old = sample_config();
    let mut new = sample_config();
    new.runtime.max_concurrent_dispatches += 1;

    let plan = classify_changes(&old, &new);
    assert_eq!(
        plan.restart_required,
        vec!["runtime.max_concurrent_dispatches".to_string()]
    );
    assert!(plan.hot_reloadable.is_empty());
}

/// The load-bearing mixed-change assertion: the one proven live field is
/// applied while an unrelated boot-snapshot field remains restart-required.
#[test]
fn mixed_change_does_not_half_apply_cold_field() {
    let old = sample_config();
    let mut new = sample_config();
    new.telemetry.log_level = "debug".into(); // proven live subscriber handle
    new.api.bind = "127.0.0.1:9001".into(); // cold

    let plan = classify_changes(&old, &new);
    assert_eq!(plan.hot_reloadable, vec!["telemetry.log_level".to_string()]);
    assert_eq!(plan.restart_required, vec!["api.bind".to_string()]);
    assert!(
        !plan.hot_reloadable.iter().any(|f| f == "api.bind"),
        "the cold field must never appear in the hot-reloadable set: {plan:?}"
    );
    assert!(plan.needs_restart());
}

#[test]
fn telemetry_export_bind_is_cold_but_log_level_is_hot() {
    let old = sample_config();
    let mut new = sample_config();
    new.telemetry.log_level = "warn".into(); // hot
    new.telemetry.metrics_bind = "127.0.0.1:9500".into(); // cold

    let plan = classify_changes(&old, &new);
    assert_eq!(plan.hot_reloadable, vec!["telemetry.log_level".to_string()]);
    assert_eq!(
        plan.restart_required,
        vec!["telemetry.metrics_bind".to_string()]
    );
}

#[test]
fn agents_and_worker_tunables_require_restart() {
    use kata_types::config::AgentBackendConfig;

    let old = sample_config();
    let mut new = sample_config();
    new.workers.heartbeat_interval_ms += 1000;
    new.agents
        .insert("default".into(), AgentBackendConfig::Shell {});

    let plan = classify_changes(&old, &new);
    assert!(plan.hot_reloadable.is_empty());
    assert_eq!(
        plan.restart_required,
        vec![
            "agents".to_string(),
            "workers.heartbeat_interval_ms".to_string(),
        ]
    );
}

#[test]
fn uninitialized_live_reload_is_reported_failed_not_applied() {
    let old = sample_config();
    let mut new = sample_config();
    new.telemetry.log_level = "debug".into();

    // This integration-test binary never initializes telemetry, so there is
    // deliberately no live subscriber reload handle.
    let outcome = apply_reload(&old, &new);
    assert!(outcome.applied.is_empty(), "outcome={outcome:?}");
    assert_eq!(outcome.failed, vec!["telemetry.log_level".to_string()]);
    assert!(outcome.restart_required.is_empty());
    assert!(outcome.needs_restart());
}

/// `[node] environment` is installed and bound at boot, so a changed value on
/// reload is REPORTED restart-required, never silently dropped (it was
/// unclassified, while `node_profile`'s docs said "cold").
#[test]
fn node_environment_requires_restart() {
    let old = sample_config();
    let mut new = sample_config();
    new.node.environment = Some(
        toml::from_str(
            "label = \"busybox\"\nsystem = \"x86_64-linux\"\nnixpkgs_attribute = \
             \"nixpkgs#pkgsStatic.busybox\"\nstore_paths = \
             [\"/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0\"]\n\
             path_prepend = \
             [\"/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0/bin\"]\n\
             [integrity_policy]\nverify = \"nar_hash_only\"\nsigs_needed = 0\n\
             required_signers = []\nallow_unsigned_content_addressed = true\n\
             verify_contents_at_declare = true\n",
        )
        .expect("a node environment"),
    );
    let plan = classify_changes(&old, &new);
    assert_eq!(plan.restart_required, vec!["node.environment".to_string()]);
    assert!(plan.hot_reloadable.is_empty());
}

/// `[runtime] model_reuse_max_age_secs` is installed on the stage-cache store
/// once by `BootRig::boot`, so an edit on a running node is REPORTED
/// restart-required. It was unclassified: the reload reported nothing while
/// every runner kept the boot value.
#[test]
fn model_reuse_bound_requires_restart() {
    use kata_types::config::ModelReuseMaxAge;

    let old = sample_config();
    let mut new = sample_config();
    new.runtime.model_reuse_max_age_secs = ModelReuseMaxAge::Unbounded;

    let plan = classify_changes(&old, &new);
    assert_eq!(
        plan.restart_required,
        vec!["runtime.model_reuse_max_age_secs".to_string()],
        "an edit of the bound must be reported restart-required: {plan:?}"
    );
    assert!(plan.hot_reloadable.is_empty());
}

/// Every boot-snapshot field the reload classifier must report. Each is read from the boot
/// snapshot (nothing consults the manager's live handle), so each edit, made
/// alone, is reported restart-required under its own dotted name.
#[test]
fn every_boot_snapshot_field_requires_restart() {
    type Edit = fn(&mut KataConfig);
    let cases: [(&str, Edit); 13] = [
        ("node.output_bytes_ceiling", |c| {
            c.node.output_bytes_ceiling += 1;
        }),
        ("node.work_delta_bytes_ceiling", |c| {
            c.node.work_delta_bytes_ceiling += 1;
        }),
        ("node.work_delta_entries_ceiling", |c| {
            c.node.work_delta_entries_ceiling += 1;
        }),
        ("node.capsule_memory_bytes_ceiling", |c| {
            c.node.capsule_memory_bytes_ceiling = Some(1 << 30);
        }),
        ("node.capsule_process_count_ceiling", |c| {
            c.node.capsule_process_count_ceiling = Some(64);
        }),
        ("node.work_tree_max_bytes", |c| {
            c.node.work_tree_max_bytes += 1;
        }),
        ("node.work_tree_max_entries", |c| {
            c.node.work_tree_max_entries += 1;
        }),
        ("node.egress_allow", |c| {
            c.node.egress_allow = vec!["example.com:443".into()];
        }),
        ("runtime.model_reuse_max_age_secs", |c| {
            c.runtime.model_reuse_max_age_secs = kata_types::config::ModelReuseMaxAge::Secs(60);
        }),
        ("vcs.recovery_remote", |c| {
            c.vcs.recovery_remote = Some(kata_types::config::RecoveryRemoteConfig {
                id: "origin".into(),
                url: "/srv/recovery.git".into(),
            });
        }),
        ("vcs.trunk", |c| c.vcs.trunk = Some("main".into())),
        ("git_view.history_depth", |c| {
            c.git_view.history_depth = Some(1);
        }),
        ("git_view.history_bytes_ceiling", |c| {
            c.git_view.history_bytes_ceiling += 1;
        }),
    ];
    for (field, edit) in cases {
        let old = sample_config();
        let mut new = sample_config();
        edit(&mut new);
        assert_ne!(old, new, "the {field} edit must change the config");

        let plan = classify_changes(&old, &new);
        assert_eq!(
            plan.restart_required,
            vec![field.to_string()],
            "an edit of {field} alone must be reported restart-required: {plan:?}"
        );
        assert!(plan.hot_reloadable.is_empty(), "{field}: {plan:?}");
    }
}

/// `[pricing]` is installed once at boot from the validated config bytes
/// (`kata_worker::pricing::load_overrides_from_snapshot`), so a changed row on
/// reload is REPORTED restart-required — before `KataConfig` declared the table, a
/// watched edit to it was invisible to the classifier.
///
/// **Watched red:** with the `[pricing]` arm deleted from `classify_changes`, the
/// plan is empty.
#[test]
fn pricing_requires_restart() {
    let old = sample_config();
    let mut new = sample_config();
    new.pricing = toml::from_str(
        "[[models]]\nbackend = \"anthropic\"\nmodel = \"claude-sonnet-5-5\"\ninput_rate_per_mtok = 1.25\n\
         output_rate_per_mtok = 10.0\ncache_read_multiplier = 0.1\ncache_write_multiplier = 1.0\n",
    )
    .expect("a pricing table");
    let plan = classify_changes(&old, &new);
    assert_eq!(plan.restart_required, vec!["pricing".to_string()]);
    assert!(plan.hot_reloadable.is_empty());
}
