//! Runtime config hot-reload classification + application.
//!
//! [`ConfigManager::watch`](crate::ConfigManager::watch) re-reads and swaps
//! the whole `KataConfig` on every file event, but not every field is safe
//! to apply to a *running* process: listener sockets, the storage
//! `data_dir`, the residency budgets and the like are bound once at boot and
//! only a restart picks up a new value.
//!
//! This module diffs the previous config against the newly-loaded one and
//! sorts every changed field into one of two buckets. [`classify_changes`] is
//! the classification's only spelling; no architecture doc carries a table:
//!
//! * **hot** — only `telemetry.log_level`, whose active subscriber reload
//!   handle is invoked by [`reload_log_level`](crate::reload_log_level).
//! * **cold** — every other field. The installed runtime constructs its
//!   subsystems from one immutable startup snapshot; publishing a newer value
//!   into `ConfigManager` does not prove that any runtime consumer uses it. A changed cold field
//!   is reported, and [`apply_reload`] logs a `requires restart` warning for
//!   it, rather than silently dropping it or half-applying it.
//!
//! The classification is pure ([`classify_changes`]); [`apply_reload`]
//! layers the live side effects (log-level reload + structured logging) on
//! top, and [`ConfigManager::watch`](crate::ConfigManager::watch) runs it for
//! every accepted edit, so no watcher can skip the contract.

use kata_types::config::{
    ApiConfig, ContainmentConfig, GitViewConfig, KataConfig, NodeConfig, RuntimeConfig,
    TelemetryConfig, VcsConfig, WorkerPoolConfig,
};
use tracing::{info, warn};

use crate::reload_log_level;

/// Outcome of diffing an old config against a freshly-loaded one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigReloadPlan {
    /// Changed fields for which the running process has a live application
    /// mechanism (dotted `section.field` names, sorted and de-duplicated).
    /// Classification alone never claims that the side effect succeeded.
    pub hot_reloadable: Vec<String>,
    /// Cold fields that changed and require a restart to take effect
    /// (dotted `section.field` names, sorted, de-duplicated).
    pub restart_required: Vec<String>,
}

impl ConfigReloadPlan {
    /// True when nothing meaningful changed between the two configs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hot_reloadable.is_empty() && self.restart_required.is_empty()
    }

    /// True when at least one changed field requires a restart.
    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn needs_restart(&self) -> bool {
        !self.restart_required.is_empty()
    }
}

/// Observed result of attempting to apply one classified reload plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigReloadOutcome {
    /// Fields whose live side effect succeeded.
    pub applied: Vec<String>,
    /// Hot-reloadable fields whose live side effect failed. The running
    /// process continues with its previous value.
    pub failed: Vec<String>,
    /// Changed fields that have no live application mechanism.
    pub restart_required: Vec<String>,
}

impl ConfigReloadOutcome {
    /// True when the configs were equal and no application was attempted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.applied.is_empty() && self.failed.is_empty() && self.restart_required.is_empty()
    }

    /// True when at least one changed value is not active in this process.
    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn needs_restart(&self) -> bool {
        !self.failed.is_empty() || !self.restart_required.is_empty()
    }
}

/// Diff `old` against `new` and classify every changed field as hot
/// (eligible for a live application attempt) or cold (restart-required). Pure — performs no side
/// effects, so it is the unit-test seam for the reload contract.
///
/// Every section is destructured WITHOUT `..`: a field added to `KataConfig` or
/// to any of its sections does not compile here until it is classified, and a
/// destructured field nobody compares is an unused binding, denied below.
#[must_use]
#[deny(unused_variables)]
pub fn classify_changes(old: &KataConfig, new: &KataConfig) -> ConfigReloadPlan {
    let mut hot: Vec<String> = Vec::new();
    let mut cold: Vec<String> = Vec::new();

    let KataConfig {
        node,
        runtime,
        workers,
        api,
        agents,
        pricing,
        vcs,
        telemetry,
        containment,
        git_view,
    } = old;

    // ── [node] — every field is structural (cold) ────────────────────
    // `environment` is installed once at boot (`install_node_facts_or_refuse`)
    // and bound to the dispatcher; the ceilings, egress allowance and host
    // logins are read from the boot snapshot at compile and dispatch.
    let NodeConfig {
        id,
        data_dir,
        environment,
        output_bytes_ceiling,
        work_delta_bytes_ceiling,
        work_delta_entries_ceiling,
        capsule_memory_bytes_ceiling,
        capsule_process_count_ceiling,
        work_tree_max_bytes,
        work_tree_max_entries,
        egress_allow,
    } = node;
    let new_node = &new.node;
    note(&mut cold, "node.id", id, &new_node.id);
    note(&mut cold, "node.data_dir", data_dir, &new_node.data_dir);
    note(
        &mut cold,
        "node.environment",
        environment,
        &new_node.environment,
    );
    note(
        &mut cold,
        "node.output_bytes_ceiling",
        output_bytes_ceiling,
        &new_node.output_bytes_ceiling,
    );
    note(
        &mut cold,
        "node.work_delta_bytes_ceiling",
        work_delta_bytes_ceiling,
        &new_node.work_delta_bytes_ceiling,
    );
    note(
        &mut cold,
        "node.work_delta_entries_ceiling",
        work_delta_entries_ceiling,
        &new_node.work_delta_entries_ceiling,
    );
    note(
        &mut cold,
        "node.capsule_memory_bytes_ceiling",
        capsule_memory_bytes_ceiling,
        &new_node.capsule_memory_bytes_ceiling,
    );
    note(
        &mut cold,
        "node.capsule_process_count_ceiling",
        capsule_process_count_ceiling,
        &new_node.capsule_process_count_ceiling,
    );
    note(
        &mut cold,
        "node.work_tree_max_bytes",
        work_tree_max_bytes,
        &new_node.work_tree_max_bytes,
    );
    note(
        &mut cold,
        "node.work_tree_max_entries",
        work_tree_max_entries,
        &new_node.work_tree_max_entries,
    );
    note(
        &mut cold,
        "node.egress_allow",
        egress_allow,
        &new_node.egress_allow,
    );

    // ── [runtime] — boot snapshot only ───────────────────────────────
    // `model_reuse_max_age_secs` is installed on the stage-cache store once by
    // `BootRig::boot`; every runner keeps that value until a restart.
    let RuntimeConfig {
        max_concurrent_dispatches,
        max_active_executions,
        max_active_execution_bytes,
        workspace_ttl_secs,
        model_reuse_max_age_secs,
        ledger_ttl_secs,
        memory_compaction_max_live_per_namespace,
        memory_compaction_write_interval,
    } = runtime;
    let new_runtime = &new.runtime;
    note(
        &mut cold,
        "runtime.max_concurrent_dispatches",
        max_concurrent_dispatches,
        &new_runtime.max_concurrent_dispatches,
    );
    note(
        &mut cold,
        "runtime.max_active_executions",
        max_active_executions,
        &new_runtime.max_active_executions,
    );
    note(
        &mut cold,
        "runtime.max_active_execution_bytes",
        max_active_execution_bytes,
        &new_runtime.max_active_execution_bytes,
    );
    note(
        &mut cold,
        "runtime.workspace_ttl_secs",
        workspace_ttl_secs,
        &new_runtime.workspace_ttl_secs,
    );
    note(
        &mut cold,
        "runtime.model_reuse_max_age_secs",
        model_reuse_max_age_secs,
        &new_runtime.model_reuse_max_age_secs,
    );
    note(
        &mut cold,
        "runtime.ledger_ttl_secs",
        ledger_ttl_secs,
        &new_runtime.ledger_ttl_secs,
    );
    note(
        &mut cold,
        "runtime.memory_compaction_max_live_per_namespace",
        memory_compaction_max_live_per_namespace,
        &new_runtime.memory_compaction_max_live_per_namespace,
    );
    note(
        &mut cold,
        "runtime.memory_compaction_write_interval",
        memory_compaction_write_interval,
        &new_runtime.memory_compaction_write_interval,
    );

    // ── [workers] — constructed from the boot snapshot ───────────────
    let WorkerPoolConfig {
        transports,
        dispatch_deadline_ms,
        assignment_start_deadline_ms,
        heartbeat_interval_ms,
        heartbeat_grace_ms,
        max_workers,
    } = workers;
    let new_workers = &new.workers;
    note(
        &mut cold,
        "workers.transports",
        transports,
        &new_workers.transports,
    );
    note(
        &mut cold,
        "workers.dispatch_deadline_ms",
        dispatch_deadline_ms,
        &new_workers.dispatch_deadline_ms,
    );
    note(
        &mut cold,
        "workers.assignment_start_deadline_ms",
        assignment_start_deadline_ms,
        &new_workers.assignment_start_deadline_ms,
    );
    note(
        &mut cold,
        "workers.heartbeat_interval_ms",
        heartbeat_interval_ms,
        &new_workers.heartbeat_interval_ms,
    );
    note(
        &mut cold,
        "workers.heartbeat_grace_ms",
        heartbeat_grace_ms,
        &new_workers.heartbeat_grace_ms,
    );
    note(
        &mut cold,
        "workers.max_workers",
        max_workers,
        &new_workers.max_workers,
    );

    // ── [api] ────────────────────────────────────────────────────────
    let ApiConfig { bind, auth } = api;
    let new_api = &new.api;
    note(&mut cold, "api.bind", bind, &new_api.bind);
    note(&mut cold, "api.auth", auth, &new_api.auth);

    // ── [agents] — executor boot snapshot ────────────────────────────
    note(&mut cold, "agents", agents, &new.agents);

    // ── [pricing] — installed once from the boot snapshot's bytes ────
    note(&mut cold, "pricing", pricing, &new.pricing);

    // ── [vcs] — boot snapshot ────────────────────────────────────────
    let VcsConfig {
        jj_repo,
        recovery_remote,
        trunk,
        op_log_gc_enabled,
        op_log_max_operations,
        op_log_gc_keep_newer_secs,
        op_log_gc_every_n_lands,
    } = vcs;
    let new_vcs = &new.vcs;
    note(&mut cold, "vcs.jj_repo", jj_repo, &new_vcs.jj_repo);
    note(
        &mut cold,
        "vcs.recovery_remote",
        recovery_remote,
        &new_vcs.recovery_remote,
    );
    note(&mut cold, "vcs.trunk", trunk, &new_vcs.trunk);
    note(
        &mut cold,
        "vcs.op_log_gc_enabled",
        op_log_gc_enabled,
        &new_vcs.op_log_gc_enabled,
    );
    note(
        &mut cold,
        "vcs.op_log_max_operations",
        op_log_max_operations,
        &new_vcs.op_log_max_operations,
    );
    note(
        &mut cold,
        "vcs.op_log_gc_keep_newer_secs",
        op_log_gc_keep_newer_secs,
        &new_vcs.op_log_gc_keep_newer_secs,
    );
    note(
        &mut cold,
        "vcs.op_log_gc_every_n_lands",
        op_log_gc_every_n_lands,
        &new_vcs.op_log_gc_every_n_lands,
    );

    // ── [telemetry] — only log_level has a live reload handle today ──
    // The subscriber/exporter workflow is installed once at boot; every other
    // field cannot swap live and so requires a restart.
    let TelemetryConfig {
        enabled,
        log_level,
        log_json,
        export,
        otlp_endpoint,
        metrics_bind,
    } = telemetry;
    let new_telemetry = &new.telemetry;
    note(
        &mut hot,
        "telemetry.log_level",
        log_level,
        &new_telemetry.log_level,
    );
    note(
        &mut cold,
        "telemetry.enabled",
        enabled,
        &new_telemetry.enabled,
    );
    note(
        &mut cold,
        "telemetry.log_json",
        log_json,
        &new_telemetry.log_json,
    );
    note(&mut cold, "telemetry.export", export, &new_telemetry.export);
    note(
        &mut cold,
        "telemetry.otlp_endpoint",
        otlp_endpoint,
        &new_telemetry.otlp_endpoint,
    );
    note(
        &mut cold,
        "telemetry.metrics_bind",
        metrics_bind,
        &new_telemetry.metrics_bind,
    );

    // ── [containment] — installed once at boot; cold on purpose ──────
    // `BootRig::boot` installs the value into the process-level cell the
    // workflow compiler reads. Swapping it live would let two stages of ONE
    // execution answer to different admission rules — the first compiled under
    // the old policy, a mid-run subworkflow spawn or program re-compile under
    // the new one. A restart is the only coherent application.
    let ContainmentConfig {
        require_contained_model_stages,
    } = containment;
    note(
        &mut cold,
        "containment.require_contained_model_stages",
        require_contained_model_stages,
        &new.containment.require_contained_model_stages,
    );

    // ── [git_view] — the admission-time history producer's boot bound ─
    let GitViewConfig {
        history_depth,
        history_bytes_ceiling,
    } = git_view;
    let new_git_view = &new.git_view;
    note(
        &mut cold,
        "git_view.history_depth",
        history_depth,
        &new_git_view.history_depth,
    );
    note(
        &mut cold,
        "git_view.history_bytes_ceiling",
        history_bytes_ceiling,
        &new_git_view.history_bytes_ceiling,
    );

    hot.sort();
    hot.dedup();
    cold.sort();
    cold.dedup();

    ConfigReloadPlan {
        hot_reloadable: hot,
        restart_required: cold,
    }
}

/// Push `field` into `bucket` when its old and new values differ.
fn note<T: PartialEq>(bucket: &mut Vec<String>, field: &str, old: &T, new: &T) {
    if old != new {
        bucket.push(field.to_owned());
    }
}

/// Classify the change set, apply the live side effects for the hot subset,
/// and log the outcome. Returns a [`ConfigReloadOutcome`] that distinguishes
/// successfully applied fields from failed live side effects so callers can
/// react further (emit events, assert in tests, etc.).
///
/// Live side effects performed here:
/// * `telemetry.log_level` → [`reload_log_level`](crate::reload_log_level)
///   swaps the active tracing directive.
///
/// Every other field is cold because the product runtime retains the immutable
/// boot snapshot, not the manager's `ArcSwap` handle. Cold fields are logged at `warn` with an explicit
/// `change requires restart` message and are otherwise left untouched.
pub fn apply_reload(old: &KataConfig, new: &KataConfig) -> ConfigReloadOutcome {
    let plan = classify_changes(old, new);
    let mut outcome = ConfigReloadOutcome {
        restart_required: plan.restart_required,
        ..ConfigReloadOutcome::default()
    };

    if plan
        .hot_reloadable
        .iter()
        .any(|f| f == "telemetry.log_level")
    {
        // Push the new directive into the live subscriber. A `false`
        // return means telemetry isn't initialized or the directive is
        // invalid; report that the only nominally-live field did not apply.
        if reload_log_level(&new.telemetry.log_level) {
            outcome.applied.push("telemetry.log_level".to_string());
            info!(
                new_level = %new.telemetry.log_level,
                "telemetry.log_level hot-reloaded",
            );
        } else {
            outcome.failed.push("telemetry.log_level".to_string());
            warn!(
                new_level = %new.telemetry.log_level,
                "telemetry.log_level change was observed but the live subscriber \
                 reload did not apply (telemetry uninitialized or \
                 invalid directive)",
            );
        }
    }

    if !outcome.applied.is_empty() {
        info!(
            fields = ?outcome.applied,
            "config hot-reload applied",
        );
    }

    for field in &outcome.restart_required {
        warn!(
            field = %field,
            "config field '{field}' changed but requires restart to take effect; \
             running process continues with the previous value",
        );
    }

    outcome
}
