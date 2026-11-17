//! Boot wiring for the installed durable main.
//!
//! Every local main stands up the same orchestration stack —
//! in-flight ledger, workspace manager, supervisor, heartbeat monitor,
//! dispatcher, and a fan of background tasks (bookkeeper, timing
//! logger, heartbeat sweep, hourly workspace sweep). Execution providers and
//! subordinate capacity compose around this one stack; they never create a
//! second workflow authority.
//!
//! [`BootRig::boot`] performs the construction once and returns a
//! flat struct whose fields the caller can read (to register
//! workers, bring up an API server, run a workflow auto-run task).
//! [`BootRig::start_api_server`] adopts the retained installed-main API listener. The
//! caller decides which local worker capacity to register.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use kata_api::executor::WorkflowExecutor;
use kata_api::server::{ApiServer, ApiServerTask};
use kata_api::state::{AppState, AuthorityStatus};
use kata_core::OperationalDb;
use kata_core::store::{SqliteNativeMemoryStore, SqliteWorkflowStore};
use kata_core::{IdempotencyStore, InFlightLedger, SubsystemHealth, SubsystemId, SystemHealth};
use kata_program::library::WorkflowLibrary;
use kata_transport::WorkerPoolSupervisor;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_types::KataConfig;
use kata_types::config::WorkerPoolConfig;
use kata_vcs::{JjBackend, OpLogGcPolicy, VcsBackend};
use kata_workflow::dispatcher::{Dispatcher, StartupRecoveryGuard};
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use tracing::{error, info, warn};

/// Declare, promote and bind `declaration` through the production verb —
/// [`kata_core::environment::bind_node_environment`], which asks the host's
/// Nix store — except for ONE declaration shape that never reaches Nix: a
/// test-support build whose `[node] environment` names exactly
/// [`kata_workflow::test_harness::FIXTURE_ENVIRONMENT_STORE_PATH`] binds the
/// fixture manifest directly instead.
///
/// The seam is keyed on the PATH, not a flag: the fixture store path exists on
/// no host, so a production declaration cannot collide with it — a real
/// declaration naming that path would be refused by Nix before it ever bound,
/// and under a non-test build it still is. Every other declaration takes the
/// daemon path unconditionally.
fn bind_configured_node_environment(
    db: &OperationalDb,
    cas: &kata_core::store::cas::CasStore,
    data_dir: &Path,
    declaration: &kata_types::config::NodeEnvironmentConfig,
    node_platform: Option<&kata_types::execution_contract::PlatformRef>,
) -> kata_types::error::KataResult<kata_core::environment::NodeEnvironment> {
    #[cfg(any(test, feature = "test-support"))]
    if declaration_names_fixture_environment(declaration) {
        return bind_fixture_node_environment(db, cas, node_platform);
    }
    kata_core::environment::bind_node_environment(
        db,
        cas,
        &kata_core::environment::NixStore::Daemon,
        data_dir,
        declaration,
        node_platform,
    )
}

/// True when `declaration`'s whole closure is the one fixture store path —
/// the only environment a host-free rig may declare. Anything else means the
/// daemon bind.
#[cfg(any(test, feature = "test-support"))]
fn declaration_names_fixture_environment(
    declaration: &kata_types::config::NodeEnvironmentConfig,
) -> bool {
    declaration.store_paths.len() == 1
        && declaration.store_paths[0].as_str()
            == kata_workflow::test_harness::FIXTURE_ENVIRONMENT_STORE_PATH
}

/// Bind the fixture environment a rig declared by its (unrealisable) store
/// path: publish the canonical fixture manifest to the node's CAS, declare the
/// rig's environment id over it, and promote the gc root — the same durable
/// rows the production bind commits, minus the store calls no fixture can
/// answer. Returns the bound fact [`BootRig::boot`] carries into dispatch.
#[cfg(any(test, feature = "test-support"))]
fn bind_fixture_node_environment(
    db: &OperationalDb,
    cas: &kata_core::store::cas::CasStore,
    node_platform: Option<&kata_types::execution_contract::PlatformRef>,
) -> kata_types::error::KataResult<kata_core::environment::NodeEnvironment> {
    let platform = node_platform.ok_or_else(|| {
        kata_types::error::KataError::Validation(
            "node environment refused at boot: node_environment_platform_mismatch: this \
             binary's target has no platform kata qualifies"
                .to_string(),
        )
    })?;
    if db
        .environment(kata_workflow::test_harness::OCI_RIG_ENVIRONMENT_ID)
        .is_ok_and(|row| row.is_some())
    {
        // A re-opened data directory already holds the fixture environment:
        // same declaration, same id — binding it again is a no-op.
        return Ok(kata_core::environment::NodeEnvironment {
            environment: kata_types::execution_contract::EnvironmentId(
                kata_types::primitives::ContentHash::new(
                    kata_workflow::test_harness::OCI_RIG_ENVIRONMENT_ID,
                ),
            ),
            platform: platform.id(),
        });
    }
    let manifest = cas
        .put_durable(&kata_workflow::test_harness::fixture_environment_manifest_bytes())
        .map_err(|error| {
            kata_types::error::KataError::Storage(format!(
                "publish the fixture environment manifest: {error}"
            ))
        })?;
    db.declare_environment(
        &kata_core::operational::EnvironmentDeclaration::for_staged_root(
            kata_workflow::test_harness::OCI_RIG_ENVIRONMENT_ID,
            &manifest,
            [0x5C; 32],
            "fixture-shell",
            platform.id().0.0,
            "01JZZZZZZZZZZZZZZZZZZZZZE1",
        )?,
    )?;
    db.promote_environment_root(
        kata_workflow::test_harness::OCI_RIG_ENVIRONMENT_ID,
        chrono::Utc::now().timestamp_millis(),
    )?;
    Ok(kata_core::environment::NodeEnvironment {
        environment: kata_types::execution_contract::EnvironmentId(
            kata_types::primitives::ContentHash::new(
                kata_workflow::test_harness::OCI_RIG_ENVIRONMENT_ID,
            ),
        ),
        platform: platform.id(),
    })
}

/// Ready-to-use orchestration stack shared by every kata node
/// boot path.
///
/// Construct via [`BootRig::boot`]. Public fields so the caller
/// can:
///
/// * Register workers (`supervisor`, `ledger`, `heartbeat` —
///   needed to spawn a `ResultReactor` per worker).
/// * Spawn an API server with [`BootRig::start_api_server`] (or
///   build one out of the same `dispatcher` + `supervisor` + a
///   workflow library directly).
pub struct BootRig {
    /// Snapshotted typed config the rig was built from.
    pub cfg: Arc<KataConfig>,
    /// Stable source authority for worker enrollment. Persistent rigs use the
    /// validated directory identity, never the operator's display name.
    pub source_main_identity: String,
    /// Worker pool supervisor — register workers with it.
    pub supervisor: Arc<WorkerPoolSupervisor>,
    /// Correlated domain-scoped recovery controls on enrolled transport instances.
    pub recovery_exchange: Arc<kata_workflow::recovery_exchange::RecoveryExchange>,
    /// Heartbeat monitor — pass to `ResultReactor::new`.
    pub heartbeat: Arc<HeartbeatMonitor>,
    /// In-flight ledger — pass to `ResultReactor::new`.
    pub ledger: Arc<InFlightLedger>,
    /// Wired dispatcher with its workspace manager attached.
    pub dispatcher: Arc<Dispatcher>,
    /// Linear construction-time capability for durable startup recovery.
    /// `None` only after the one boot recovery sequence has consumed it.
    startup_recovery_guard: std::sync::Mutex<Option<StartupRecoveryGuard>>,
    /// The membrane identity of this data directory's worker membrane store
    /// (`<data_dir>/idempotency.db`), read once at boot. The store holds that
    /// identity and nothing else — it records no effect: the only per-effect
    /// records kata keeps are a `forge_export`'s push and pull request intents,
    /// in `operational.db`'s `forge_intents` (ADR 0002). The main does not keep
    /// the store open: its one mutable owner is the supervised node
    /// (`crate::supervised_node`), which enrolls under this membrane.
    pub local_membrane: kata_types::identity::WorkerMembraneId,
    /// Per-execution checked-program store, on disk in `operational.db`. Threaded through the
    /// `WorkflowExecutor` so every executable path persists the checked
    /// `ExecutionProgram` before dispatch.
    pub execution_lifecycle: ExecutionLifecycleFace,
    stage_cache: Arc<SqliteWorkflowStore>,
    delivery_service: Arc<kata_workflow::delivery_service::DeliveryService>,
    /// Native memory/context store used by the API/SDK and file bridge.
    /// Always durable for the installed main so long-running factory context
    /// survives process restarts.
    pub native_memory_store: Arc<SqliteNativeMemoryStore>,
    /// Factory-as-loop foundation: the single execution-workspace provider
    /// shared by the executor's workspace-effect gate AND the in-process
    /// `workspace_effect` backend. Built once at boot from the operator repo
    /// root so the effect-stage's provider is the SAME `Arc` (and therefore
    /// the SAME in-memory worktree index) that creates the per-execution
    /// worktree — without this sharing the effect-stage would look up a
    /// worktree a *different* provider instance created and fail. `None` when
    /// provider init failed (worktree-isolated workflows then run un-isolated;
    /// effect stages fail at dispatch with a clear "no backend" error).
    pub workspace_provider: Option<Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider>>,
    /// The canonical `Arc<WorkflowExecutor>` `start_api_server` builds,
    /// retained so the shutdown path can drain its in-flight workflow tasks
    /// before the runtime is dropped (see [`Self::drain_workflow_tasks`]).
    /// `OnceLock` because the executor is built lazily inside
    /// `start_api_server`, after the rig struct already exists; empty on nodes
    /// that never start an engine (nothing to drain).
    workflow_executor: std::sync::OnceLock<Arc<WorkflowExecutor>>,
    recovery_report: std::sync::Mutex<RecoveryReport>,
    background_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

/// Readiness-authoritative summary of boot recovery.
#[derive(Clone, Debug, Default)]
pub struct RecoveryReport {
    pub resumed: usize,
    pub terminalized: usize,
    pub orphaned: usize,
    pub unresolved_claims: usize,
    pub errors: usize,
}

impl RecoveryReport {
    fn state(&self) -> (&'static str, Option<String>) {
        if self.errors > 0 {
            (
                "recovery_failed",
                Some(format!(
                    "inspect durable recovery errors and retry `{} kata serve`",
                    crate::cli::DELEGATED_SCOPE
                )),
            )
        } else if self.unresolved_claims > 0 {
            (
                "degraded",
                Some(format!(
                    "reconcile {} claimed controller application(s) from the operator surface",
                    self.unresolved_claims
                )),
            )
        } else {
            ("ready", None)
        }
    }
}

/// Map the operator's `[vcs]` op-log retention knobs onto the kata-vcs
/// GC policy carried by [`JjBackend`]. Reads `op_log_gc_enabled`,
/// `op_log_max_operations`, `op_log_gc_keep_newer_secs`, and
/// `op_log_gc_every_n_lands` (the four knob-guard-registered fields).
#[must_use]
fn op_log_gc_policy_from_config(cfg: &KataConfig) -> OpLogGcPolicy {
    OpLogGcPolicy {
        enabled: cfg.vcs.op_log_gc_enabled,
        max_operations: cfg.vcs.op_log_max_operations,
        keep_newer: Duration::from_secs(cfg.vcs.op_log_gc_keep_newer_secs),
        every_n_lands: cfg.vcs.op_log_gc_every_n_lands,
    }
}

/// Boot sweep — run one op-log compaction pass at startup, best-effort and
/// non-fatal: a GC failure logs a warning and boot proceeds.
fn boot_sweep_op_log_gc(backend: &JjBackend) {
    let policy = backend.op_log_gc_policy();
    match backend.compact_op_log(&policy) {
        Ok(stats) if stats.ran => info!(
            ops_before = stats.ops_before,
            ops_abandoned = stats.ops_abandoned,
            ops_retained = stats.ops_retained,
            "workspace_provider: op-log GC compacted the jj operation log at boot"
        ),
        Ok(_) => {}
        Err(e) => warn!(
            error = %e,
            "workspace_provider: op-log GC boot sweep failed (non-fatal)"
        ),
    }
}

/// Boot repair — undo what a power loss tore in the repository
/// ([`JjBackend::repair_torn_repository`] states exactly what), non-fatal like
/// the op-log sweep: a repair that fails leaves the torn state for the reads
/// that meet it, which refuse it by name (`repository_torn`) where kata reads
/// a commit the view names. A ref it cannot re-derive is named at WARN as
/// `repository_torn` for the operator.
fn boot_repair_torn_repository(backend: &JjBackend) {
    match backend.repair_torn_repository() {
        Ok(repair) if repair.is_empty() => {}
        Ok(repair) => warn!(
            removed_empty_objects = ?repair.removed_objects,
            rederived_refs = ?repair.rederived_refs,
            deleted_refs = ?repair.deleted_refs,
            unrepaired_refs = ?repair.unrepaired_refs,
            "workspace_provider: repaired what a power loss tore in the repository; \
             an unrepaired ref is repository_torn: no record of kata's or jj's names a \
             target for it — repair or delete it"
        ),
        Err(e) => warn!(
            error = %e,
            "workspace_provider: the torn-repository repair failed (non-fatal)"
        ),
    }
}

/// Build the configured execution-workspace provider, or `None` if init fails.
///
/// Shared source of truth for both the executor's workspace-effect gate
/// provider (attached with the `gh`-CLI forge in
/// [`BootRig::build_workflow_executor`]) and the
/// factory-as-loop `workspace_effect` backend's in-execution provider (injected
/// into the backend registry at boot). It opens kata-vcs's native
/// [`JjBackend`] rooted at `vcs.jj_repo` — the one execution-workspace provider.
///
/// A failure logs a warning and returns `None` — admission then refuses every
/// `worktree_isolated` workflow ("no workspace provider is configured"), and
/// `workspace_effect` stages fail at dispatch with a clear "no provider wired"
/// error rather than silently no-op'ing.
#[must_use]
pub fn build_workspace_provider_from_config(
    cfg: &KataConfig,
) -> Option<Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider>> {
    match JjBackend::open(&cfg.vcs.jj_repo) {
        Ok(backend) => {
            // Carry the operator's op-log GC horizon so the boot
            // sweep below and the per-land cadence bound the jj operation log.
            let backend = backend
                .with_op_log_gc_policy(op_log_gc_policy_from_config(cfg))
                // The operator's trunk binding. `JjBackend::open` carries
                // none, so a construction site that forgets this leaves the
                // provider asking the repository — correct where the answer
                // is unambiguous, a refusal where it is not.
                .with_configured_trunk(cfg.vcs.trunk.clone());
            // What a power loss tore is repaired FIRST, before anything else
            // reads or writes the repository: the op-log GC below walks jj's
            // keep refs, and every later write of an object an empty loose file
            // stands in for would be skipped.
            boot_repair_torn_repository(&backend);
            // Boot sweep — bound the jj operation log at startup.
            // Best-effort + non-fatal: op-log GC must NEVER block boot, and the
            // per-land cadence covers a node that never reboots.
            boot_sweep_op_log_gc(&backend);
            let provider: Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider> =
                Arc::new(backend);
            Some(provider)
        }
        Err(e) => {
            warn!(
                error = %e,
                repo_root = %cfg.vcs.jj_repo.display(),
                "workspace_provider: native jj provider init failed; \
                 admission refuses worktree_isolated workflows for this \
                 process; restart once the repository opens"
            );
            None
        }
    }
}

/// Grace after an execution's terminal transition before its workspace
/// becomes reap-eligible. Guards the STEADY-STATE race where a run older than
/// `workspace_ttl` that only just reached terminal could have its worktree
/// reaped by the hourly sweep during the narrow promote/park teardown window.
/// Comfortably shorter than the hourly cadence and the TTLs, so it never
/// materially delays reclaiming a genuine leak.
const TERMINAL_REAP_GRACE: Duration = Duration::from_secs(300);

/// Reclaim leaked NON-LIVE execution workspaces once.
///
/// The boot seam every long-running node calls at startup and on the hourly
/// cadence (see [`BootRig::build`]). Wired here rather than inside
/// [`build_workspace_provider_from_config`] because the classifier needs the
/// durable execution lifecycle store, which only exists once the boot stack is
/// assembled. The jj provider reaps `agents/<exec-id>`.
///
/// The classifier maps each execution to an [`kata_effects_contract::ExecutionLiveness`]:
/// * TERMINAL (durable terminal lifecycle) → reaped past `terminal_ttl` + grace.
/// * LIVE (`Running` lifecycle) → NEVER reaped, including between-stage windows
///   where every extant assignment happens to be terminal.
/// * LIVE (checked-program authority exists but lifecycle classification is absent)
///   → NEVER reaped before recovery classifies it.
/// * UNKNOWN (no lifecycle or checked-program authority) → reaped past the
///   longer `unknown_ttl`.
///
/// Returns the count reaped.
pub fn reap_terminal_workspaces_once(
    provider: &Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider>,
    policy: kata_effects_contract::TerminalWorkspaceReapPolicy,
    lifecycle_store: &ExecutionLifecycleFace,
) -> kata_types::error::KataResult<usize> {
    provider.reap_terminal_workspaces(policy, &|id| match lifecycle_store.lifecycle(id) {
        Ok(Some(lifecycle)) if lifecycle.state.is_terminal() => {
            kata_effects_contract::ExecutionLiveness::Terminal {
                terminal_since_ms: lifecycle
                    .finished_at_ms
                    .and_then(|value| u64::try_from(value).ok()),
            }
        }
        // A live row or a read error both conservatively classify as live: a
        // read error is not evidence that reaping is safe.
        Ok(Some(_)) | Err(_) => kata_effects_contract::ExecutionLiveness::Live,
        Ok(None) => match lifecycle_store.program_json(id) {
            // Opening an older store leaves current programs without lifecycle
            // unclassified until recovery's replay settles whether they are
            // historical terminal runs or resumable work. Reaping before that
            // replay would destroy the very candidate recovery must inspect.
            Ok(Some(_)) | Err(_) => kata_effects_contract::ExecutionLiveness::Live,
            Ok(None) => kata_effects_contract::ExecutionLiveness::Unknown,
        },
    })
}

/// Sweep the execution TARGET PINS once, as each execution's
/// [`ExecutionLifecycleFace::target_pin_claim`] answers for it.
///
/// A target is resolved and pinned (`refs/kata/targets/<id>/…`) before its
/// admission commits, so a refusal or a crash in between leaves a pin no
/// execution owns; and a terminal execution's pins are released by its cleanup,
/// which leaves them only when that release failed. Boot runs this BEFORE it
/// serves — before any submission can exist — so it cannot race a resolution
/// still on its way to acceptance, which is why it runs only at boot.
///
/// An unowned execution's pins are deleted, intact or torn; an owned one's are
/// kept, and one a power loss tore is re-derived from the recorded target
/// (`ExecutionWorkspaceProvider::sweep_target_pins` states exactly which).
pub fn sweep_target_pins_once(
    provider: &Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider>,
    lifecycle_store: &ExecutionLifecycleFace,
) -> kata_types::error::KataResult<kata_effects_contract::TargetPinSweep> {
    provider.sweep_target_pins(&|id| lifecycle_store.target_pin_claim(id))
}

/// Fire ONE due schedule occurrence through the executor's one submit pipeline —
/// the body of the schedule engine's submit callback.
///
/// The program is the one PINNED at install, decoded and re-validated through
/// the pin chokepoint over the pinned bytes — never recompiled from
/// `submit_pack`, which is provenance only. A pack edited (or deleted) since
/// install cannot change what runs here. A `worktree_isolated` program's target is
/// resolved for THIS fire by the executor, before acceptance, and the firing
/// transaction admits the pin plus that target.
///
/// # Outcomes
///
/// * The claim, the cursor advance and the execution commit together
///   ([`FireReport::Submitted`](kata_workflow::schedule::FireReport::Submitted)),
///   or the claim was already spent
///   ([`FireReport::AlreadyClaimed`](kata_workflow::schedule::FireReport::AlreadyClaimed)).
/// * The fire's TARGET was refused — it did not resolve
///   ([`ExecutorError::TargetUnresolved`](kata_api::executor::ExecutorError::TargetUnresolved)),
///   or did not pass the structural check
///   ([`ExecutorError::InvalidTarget`](kata_api::executor::ExecutorError::InvalidTarget)):
///   the refusal is recorded as the occurrence's firing and the cursor advances
///   ([`FireReport::Refused`](kata_workflow::schedule::FireReport::Refused)), so
///   the occurrence is never retried silently.
/// * Every other pre-acceptance failure leaves no claim and no cursor movement,
///   and the occurrence is retried on the next sweep.
pub(crate) fn fire_pinned_schedule(
    executor: &Arc<kata_api::executor::WorkflowExecutor>,
    face: &kata_workflow::schedule::ScheduleFace,
    fire: &kata_workflow::schedule::ScheduleFire,
) -> kata_types::KataResult<kata_workflow::schedule::FireReport> {
    use kata_api::executor::ExecutorError;
    use kata_workflow::schedule::FireReport;

    let schedule_id = fire.record.id.clone();
    let Some((program, invocation)) = face.revalidated_pin(&schedule_id)? else {
        return Err(kata_types::KataError::Validation(format!(
            "schedule {schedule_id} vanished from the durable table between the sweep and the \
             fire"
        )));
    };
    // The params ride INSIDE the pinned invocation. Handing them back as the
    // supplied set makes the executor's resolver a genuine fixed point over the
    // pinned contract — the same property the pin chokepoint just proved — rather
    // than a re-resolution against whatever the pack says today, which is the
    // drift a pinned schedule exists to close.
    let supplied: serde_json::Map<String, serde_json::Value> = invocation
        .params
        .iter()
        .map(|param| (param.name.to_string(), param.value.clone()))
        .collect();
    let fire_instant = fire.fire_instant;
    let next_cursor_ms = fire.next_cursor_ms;
    // THE FIRING TRANSACTION. The due claim, the cursor advance, and the
    // execution commit together or not at all: this is the eliminated
    // submit/cursor half-commit. The executor hands the acceptance the invocation
    // it admits, whose target is the one this fire resolved.
    let accept_face = face.clone();
    let accept_id = schedule_id.clone();
    let accept =
        move |execution_id: ulid::Ulid,
              _program: &kata_program::execution_program::ExecutionProgram,
              invocation: &kata_workflow::execution_program_store::ExecutionInvocation| {
            match accept_face.fire(
                &accept_id,
                fire_instant,
                execution_id,
                next_cursor_ms,
                invocation.target.as_ref(),
            ) {
                Ok(kata_core::operational::FireOutcome::Fired { .. }) => {
                    Ok(kata_api::executor::Acceptance::Accepted)
                }
                Ok(kata_core::operational::FireOutcome::AlreadyFired) => {
                    Ok(kata_api::executor::Acceptance::ClaimAlreadySpent)
                }
                Err(error) => Err(ExecutorError::DurabilityFailed(format!(
                    "claim the firing of schedule {accept_id} at {fire_instant}: {error}"
                ))),
            }
        };
    let submitted = match executor.submit_pinned_schedule_execution(program, supplied, &accept) {
        Ok(submitted) => submitted,
        Err(refusal @ (ExecutorError::InvalidTarget(_) | ExecutorError::TargetUnresolved(_))) => {
            let recorded = face.refuse_fire(
                &schedule_id,
                fire_instant,
                &refusal.to_string(),
                next_cursor_ms,
            )?;
            warn!(
                schedule = %schedule_id,
                fire_instant,
                ?recorded,
                %refusal,
                "schedule engine: the occurrence's execution target was refused; recorded as its \
                 firing"
            );
            return Ok(FireReport::Refused);
        }
        Err(ExecutorError::AdmissionClosed) => {
            return Err(kata_types::KataError::AdmissionClosed(format!(
                "schedule {schedule_id} remained due while the main stopped"
            )));
        }
        Err(other) => {
            return Err(kata_types::KataError::Internal(format!(
                "schedule {schedule_id}: submit failed: {other}"
            )));
        }
    };
    // `submitted` is the whole difference between a fire and an idempotent no-op,
    // and it must reach the engine: collapsing both into `Ok(())` made `sweep_due`
    // log "schedule fired" and return the id on the REDELIVERY path, asserting a
    // fire that did not happen.
    if let Some(execution_id) = submitted {
        info!(
            schedule = %schedule_id,
            pack = %fire.record.submit_pack,
            %execution_id,
            fire_instant,
            "schedule engine: submitted the pinned program for the due occurrence"
        );
        Ok(FireReport::Submitted)
    } else {
        info!(
            schedule = %schedule_id,
            fire_instant,
            "schedule engine: occurrence was already claimed; idempotent no-op"
        );
        Ok(FireReport::AlreadyClaimed)
    }
}

/// The terminal-workspace reap policy for this node, composed from the
/// operator's `runtime.workspace_ttl_secs` / `runtime.ledger_ttl_secs`. UNKNOWN
/// executions wait `max(workspace_ttl, ledger_ttl)`. Lifecycle records are not
/// currently pruned; the longer unknown TTL remains a conservative guard for
/// pre-lifecycle or externally removed evidence.
fn terminal_reap_policy(cfg: &KataConfig) -> kata_effects_contract::TerminalWorkspaceReapPolicy {
    let workspace_ttl = Duration::from_secs(cfg.runtime.workspace_ttl_secs);
    let ledger_ttl = Duration::from_secs(cfg.runtime.ledger_ttl_secs);
    kata_effects_contract::TerminalWorkspaceReapPolicy {
        terminal_ttl: workspace_ttl,
        unknown_ttl: workspace_ttl.max(ledger_ttl),
        terminal_grace: TERMINAL_REAP_GRACE,
    }
}

impl BootRig {
    /// Build the shared boot stack: ledger, workspace manager, supervisor,
    /// heartbeat monitor, dispatcher, and the four background
    /// tasks (bookkeeper, timing logger, heartbeat sweep, hourly
    /// workspace sweep).
    ///
    /// Every rig is durable: the authority lives in `cfg.node.data_dir`, whose
    /// data-directory lock the caller already holds. The resume/orphan pass is
    /// not run here at all — see [`Self::resume_or_orphan_in_flight_runs`].
    ///
    /// Order: ledger → workspace (with startup sweep) → dispatcher (with
    /// workspace attached) → background tasks. The resume/orphan step that used
    /// to sit between the last two is deferred to
    /// [`Self::resume_or_orphan_in_flight_runs`], which needs the
    /// `WorkflowExecutor` this function does not build. Tests + smokes pin
    /// behavior; deviating here would be a bug.
    ///
    /// The data directory itself is created by the data-directory lock
    /// (`acquire_inner`) and, failing that, by `OperationalDb::open`'s own
    /// `create_dir_all`; boot creates no second cache store beside
    /// `stage_cache.db`.
    #[allow(clippy::too_many_lines)]
    // The body has no top-level `.await`, and it must STAY async regardless:
    // the body calls `tokio::spawn` six times to
    // stand up the background-task fan, and `tokio::spawn` PANICS outside a
    // runtime context. The `async fn` signature is what forces every call site
    // — `cli/solo.rs`, `cli/mcp.rs`, and the recovery
    // test rig — to already be inside one. Desugaring it to a sync `fn` would
    // move that failure from "will not compile" to "panics at startup".
    #[allow(clippy::unused_async)]
    pub async fn boot(cfg: Arc<KataConfig>) -> Result<Self> {
        // ── The node's own answers, installed and refused FIRST ──
        // They run before the ledger opens, before anything can compile or
        // resume a checked program: the ADR-0001 `[containment]` policy (a node
        // may "instead require `Contained` and refuse", so no compile in this
        // process may observe the pre-install default) and the `[node]` facts
        // the CHECK judges against. `BootRig::boot` is the one funnel every node
        // start passes through (`cli/solo.rs`, `cli/mcp.rs`, the recovery rig),
        // so they live here.
        install_node_facts_or_refuse(&cfg)?;
        let source_main_identity = crate::data_dir_lock::inspect_identity(&cfg.node.data_dir)?
            .context("persistent boot requires its locked data-directory identity")?
            .directory_id;
        if cfg.containment.require_contained_model_stages {
            info!(
                "containment policy: model/agent stages MUST be Contained; a stage deriving \
                 host_unconfined is refused at compile"
            );
        }

        // ── Supervisor + heartbeat ────────────────────────────
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_millis(cfg.workers.heartbeat_interval_ms),
            Duration::from_millis(cfg.workers.heartbeat_grace_ms),
        ));

        // ── Ledger ────────────────────────────────────────────
        preflight_clean_engine_stores(&cfg.node.data_dir)
            .context("refuse an incomplete or non-current clean engine store set")?;
        // The cache and authority share one explicitly bound CAS. Open its
        // complete companion set together before either can retain output roots.
        let executor_term = kata_worker::executor_term::node_executor_term()
            .context("derive this build's executor term")?;
        let stage_cache = Arc::new(
            SqliteWorkflowStore::open(cfg.node.data_dir.join("stage_cache.db"))
                .context("open the stage-cache/CAS store set")?
                .with_model_reuse_max_age(cfg.runtime.model_reuse_max_age_secs)
                .with_executor_term(executor_term),
        );
        // The authoritative assignment is `operational.db`'s
        // `attempts.assignment_json`, written by the transaction that records
        // the claiming transition, and a restart reconstructs assignments from
        // operational history in the workflow layer. The ledger keeps no second
        // durable copy to disagree with it.
        //
        // Execution-level EVIDENCE is `operational.db`'s too: this ledger is
        // BOUND to that plane below so its evidence verbs write there.
        //
        // The durable append-only ledger event log lives in a
        // flat top-level `ledger_events.db`, so its
        // monotonic sequence resumes across restart and it is
        // auto-covered by backup discovery. See `ledger_events_path`.
        let events_path = ledger_events_path(&cfg.node.data_dir);
        // The durable latest-STATUS projection is
        // CO-LOCATED inside `ledger_events.db` (same file, same
        // connection, one atomic tx).
        let ledger =
            InFlightLedger::open_at(&events_path).context("InFlightLedger::open_at failed")?;
        info!(
            events_path = %events_path.display(),
            "ledger: opened derived delivery log (status projection co-located in it)"
        );
        // The authoritative execution nucleus (checked
        // program, immutable invocation, coarse lifecycle, transition
        // chain, projections) lives in `operational.db`.
        let operational_path = cfg.node.data_dir.join("operational.db");
        let operational = Arc::new(
            OperationalDb::open_with_cas(&operational_path, stage_cache.shared_cas())
                .with_context(|| {
                    format!(
                        "failed to open the operational nucleus at {}",
                        operational_path.display()
                    )
                })?,
        );

        operational.require_imports_reconciled().with_context(
            || "import reconciliation is pending; ordinary runtime startup is refused",
        )?;
        kata_core::store::backup::verify_import_evidence(
            &cfg.node.data_dir,
            &source_main_identity,
            &operational,
        )
        .context("verify retained import evidence before runtime startup")?;

        info!(
            operational_path = %operational_path.display(),
            "operational nucleus: opened at the clean runtime format"
        );
        // BIND THE EVIDENCE PLANE. Execution-level evidence is durable on
        // `operational.db`, and the bind is what points the
        // ledger's evidence verbs at it AND seeds their in-RAM read projection
        // from the table. It happens HERE — after the nucleus opens and before
        // any recovery pass can publish evidence — because an unbound ledger
        // writes evidence to RAM only, which on a durable node is silent data loss.
        ledger
            .bind_operational(&operational)
            .context("bind the operational plane execution evidence is durable on")?;
        let execution_lifecycle = ExecutionLifecycleFace::new(Arc::clone(&operational));

        // Compatibility membrane. Assignment snapshots cannot prove a
        // workflow terminal: after a predecessor commits, the successor may not
        // yet have an assignment row. Inspect the opaque program of every
        // execution whose lifecycle is not terminal before any current
        // deserialization, and block startup on every one this binary cannot
        // dispatch — the set `kata upgrade` previews.
        refuse_incompatible_execution_programs_at_boot(&execution_lifecycle)?;

        // ── The node's Nix environment ──────
        // DECLARED, VERIFIED, ROOTED and PROMOTED here, before anything can dispatch and
        // before the node reports ready, and bound onto the dispatcher below as the one
        // environment every capsule stage selects. `install_node_facts_or_refuse` has
        // already refused an `oci` node that declares none (`node_environment_undeclared`).
        let node_environment = match cfg.node.environment.as_ref() {
            Some(declaration) => {
                let bound = bind_configured_node_environment(
                    execution_lifecycle.db(),
                    stage_cache.cas(),
                    &cfg.node.data_dir,
                    declaration,
                    kata_types::node_profile::node_platform().as_ref(),
                )
                .context("declare and promote this node's `[node] environment`")?;
                info!(
                    environment_id = %bound.environment.0,
                    platform_id = %bound.platform.0,
                    label = %declaration.label,
                    "node environment: declared and promoted; every capsule stage binds it"
                );
                // The `PATH` program names the `oci` CHECK judges a
                // stage's `sandbox_profile(requires = [..])` against.
                kata_types::node_profile::install_node_environment_programs(Some(
                    kata_core::environment::environment_path_programs(
                        execution_lifecycle.db(),
                        stage_cache.cas(),
                        bound.environment,
                    )
                    .context("list the bound node environment's PATH programs")?,
                ));
                Some(bound)
            }
            None => None,
        };

        // ── Worker membrane ─────────
        // The data directory's durable membrane identity, read and released: the
        // store's one mutable owner is the supervised node, which opens it bound
        // to this identity (`crate::supervised_node`).
        let idempotency_path = cfg.node.data_dir.join("idempotency.db");
        let local_membrane = IdempotencyStore::open(&idempotency_path)
            .and_then(|store| store.membrane_id())
            .with_context(|| {
                format!(
                    "failed to read the worker membrane at {}",
                    idempotency_path.display()
                )
            })?;
        info!(
            path = %idempotency_path.display(),
            membrane = %local_membrane.0,
            "worker membrane: read"
        );

        // ── Native memory/context store ───────────────────────
        let memory_path = cfg.node.data_dir.join("memory.db");
        // Construct the concrete sqlite backend shared by every downstream
        // holder (executor, runner, AppState).
        // Consume the `[runtime]` memory-compaction knobs. `0` on either
        // knob disables that dimension (folding / cadence) — narrowing-logged.
        let memory_max_live = cfg.runtime.memory_compaction_max_live_per_namespace;
        let memory_write_interval = cfg.runtime.memory_compaction_write_interval;
        let native_memory_store: Arc<SqliteNativeMemoryStore> = Arc::new(
            SqliteNativeMemoryStore::open(&memory_path)
                .map(|store| store.with_compaction(memory_max_live, memory_write_interval))
                .with_context(|| {
                    format!(
                        "failed to open native memory store at {}",
                        memory_path.display()
                    )
                })?,
        );
        if memory_max_live == 0 {
            info!(
                "native memory: compaction DISABLED (memory_compaction_max_live_per_namespace = 0) \
                 — per-namespace object growth is unbounded"
            );
        } else if memory_write_interval == 0 {
            // The write-threshold cadence is the ONLY automatic compaction trigger
            // (no scheduled/cron memory pass exists). Zeroing it leaves a live bound
            // that only an explicit `compact()` call enforces — automatic
            // per-namespace growth is unbounded until then. Symmetric narrowing log.
            info!(
                "native memory: compaction cadence DISABLED (memory_compaction_write_interval = 0) \
                 — no automatic pass runs; per-namespace growth is unbounded until an explicit \
                 compact()"
            );
        }
        info!(
            memory_path = %memory_path.display(),
            memory_compaction_max_live_per_namespace = memory_max_live,
            memory_compaction_write_interval = memory_write_interval,
            "native memory: opened durable store"
        );

        // ── Dispatcher ────────────────────────────────────────
        let dispatcher_base = Dispatcher::new(
            Arc::clone(&supervisor),
            Arc::clone(&heartbeat),
            Arc::clone(&ledger),
        )
        .with_execution_lifecycle(execution_lifecycle.clone())
        .with_send_timeout(Duration::from_millis(cfg.workers.dispatch_deadline_ms))
        .with_assignment_start_deadline(assignment_start_deadline_from_worker_pool(&cfg.workers))
        // Admission control: bound concurrent fresh dispatch submissions
        // so a wide fan-out queues gracefully instead of convoying on the ledger
        // connection-mutex.
        .with_max_concurrent_dispatches(cfg.runtime.max_concurrent_dispatches);
        let dispatcher_base = match node_environment {
            Some(bound) => dispatcher_base.with_node_environment(bound),
            None => dispatcher_base,
        };
        let (dispatcher_base, startup_recovery_guard) = dispatcher_base
            .with_startup_recovery_fence()
            .context("arm installed-main startup recovery fence before sharing dispatcher")?;
        let dispatcher = Arc::new(dispatcher_base);

        // ── Resume / orphan from boot ─────────────────────────
        // Defer resume/orphan to [`Self::resume_or_orphan_in_flight_runs`]
        // after the `WorkflowExecutor` has been built. That keeps checked
        // `ExecutionProgram` loading in the API layer and avoids a fallback
        // path that redispatches raw ledger assignments.

        // ── Background tasks ──────────────────────────────────
        let delivery_service = Arc::new(kata_workflow::delivery_service::DeliveryService::new(
            Arc::clone(execution_lifecycle.db()),
            Arc::clone(&ledger),
        ));
        delivery_service
            .catch_up()
            .context("rebuild global delivery before runtime admission")?;
        let mut background_tasks = Vec::new();
        let producer = Arc::clone(&delivery_service);
        background_tasks.push(tokio::spawn(async move {
            producer.run().await;
        }));
        // Bookkeeper keeps `active_assignments` in sync with
        // terminal events so the scheduler's load tie-break
        // works.
        let bg_dispatcher = Arc::clone(&dispatcher);
        background_tasks.push(tokio::spawn(async move {
            bg_dispatcher.run_bookkeeper().await;
        }));
        // Timing logger: the per-stage INFO/WARN timing log.
        let timing_dispatcher = Arc::clone(&dispatcher);
        background_tasks.push(tokio::spawn(async move {
            timing_dispatcher.run_timing_logger().await;
        }));
        // Heartbeat sweep settles the in-flight attempts of a
        // worker that missed too many heartbeats.
        let sweep_dispatcher = Arc::clone(&dispatcher);
        let sweep_heartbeat = Arc::clone(&heartbeat);
        let sweep_interval = Duration::from_millis(cfg.workers.heartbeat_interval_ms);
        background_tasks.push(tokio::spawn(async move {
            sweep_dispatcher
                .run_heartbeat_sweep(sweep_heartbeat, sweep_interval)
                .await;
        }));
        // Assignment deadline sweep fails stages whose checked
        // `timeout_ms` elapsed even if the worker remains alive but
        // never reports a terminal result.
        let deadline_dispatcher = Arc::clone(&dispatcher);
        let deadline_interval = Duration::from_millis(cfg.workers.heartbeat_interval_ms);
        background_tasks.push(tokio::spawn(async move {
            deadline_dispatcher
                .run_assignment_deadline_sweep(deadline_interval)
                .await;
        }));
        // Factory-as-loop foundation: build the single execution-workspace
        // provider shared by the executor's apply-gate and the
        // `workspace_effect` backend. The jj provider uses the config-resolved
        // repository authority; process CWD is never an installed-main input.
        let workspace_provider = build_workspace_provider_from_config(&cfg);

        // Reclaim leaked terminal-execution workspaces. A run
        // that reached a terminal state without promote/park leaves its
        // `exec-<id>` worktree on disk (measured: 10 such leaks, 92G, on one
        // long-lived host when nothing invoked the reaper). A synchronous
        // STARTUP reap reclaims pre-existing leaks
        // immediately, and an hourly task mirrors the workspace sweeper cadence
        // as the standing backstop. The ledger supplies the terminal predicate
        // (protecting live + about-to-be-resumed runs); the provider dispatches
        // to whichever backend's reaper. Best-effort: a failure never blocks boot.
        if let Some(provider) = workspace_provider.as_ref() {
            let reap_policy = terminal_reap_policy(&cfg);
            match reap_terminal_workspaces_once(provider, reap_policy, &execution_lifecycle) {
                Ok(n) if n > 0 => info!(
                    reaped = n,
                    "worktree reaper: startup sweep reclaimed non-live execution workspaces"
                ),
                Ok(_) => {}
                Err(e) => {
                    warn!(error = %e, "worktree reaper: startup sweep failed (non-fatal)");
                }
            }
            match sweep_target_pins_once(provider, &execution_lifecycle) {
                Ok(sweep) => {
                    if sweep.deleted > 0 {
                        info!(
                            executions = sweep.deleted,
                            "target pins: boot sweep deleted the pins no live admission owns"
                        );
                    }
                    if !sweep.rederived.is_empty() {
                        warn!(
                            pins = ?sweep.rederived,
                            "target pins: boot sweep re-derived pins a power loss tore from \
                             their executions' recorded targets"
                        );
                    }
                    if !sweep.head_absent.is_empty() {
                        warn!(
                            pins = ?sweep.head_absent,
                            "target pins: boot sweep deleted torn pins whose recorded commit \
                             the store does not hold either (target_head_absent)"
                        );
                    }
                }
                Err(e) => {
                    warn!(error = %e, "target pins: boot sweep failed (non-fatal)");
                }
            }
            let reap_provider = Arc::clone(provider);
            let reap_lifecycle_store = execution_lifecycle.clone();
            background_tasks.push(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_hours(1));
                // First tick is immediate; consume it — the startup reap above
                // already ran, so the first periodic reap waits a full hour.
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    match reap_terminal_workspaces_once(
                        &reap_provider,
                        reap_policy,
                        &reap_lifecycle_store,
                    ) {
                        Ok(n) if n > 0 => info!(
                            reaped = n,
                            "worktree reaper: reclaimed non-live execution workspaces"
                        ),
                        Ok(_) => {}
                        Err(e) => {
                            warn!(error = %e, "worktree reaper: sweep failed (non-fatal)");
                        }
                    }
                }
            }));
        }

        Ok(Self {
            cfg,
            source_main_identity,
            recovery_exchange: kata_workflow::recovery_exchange::RecoveryExchange::new(Arc::clone(
                &supervisor,
            )),
            supervisor,
            heartbeat,
            ledger,
            dispatcher,
            startup_recovery_guard: std::sync::Mutex::new(Some(startup_recovery_guard)),
            local_membrane,
            execution_lifecycle,
            stage_cache,
            delivery_service,
            native_memory_store,
            workspace_provider,
            workflow_executor: std::sync::OnceLock::new(),
            recovery_report: std::sync::Mutex::new(RecoveryReport::default()),
            background_tasks: std::sync::Mutex::new(background_tasks),
        })
    }

    /// Recover installed-main execution authority before readiness.
    ///
    /// The dispatcher is fenced before it is shared. Recovery first validates
    /// and prepares every lifecycle-owned execution without polling a runner,
    /// then reconciles claimed controller effects and hands the unprotected
    /// remainder to `Dispatcher::orphan_in_flight_runs` — pre-lifecycle ledger
    /// rows, and assignments of executions whose lifecycle already settled
    /// (`recoverable_ids` scans only `admitting`/`running`/`terminalizing`, so a
    /// settled execution is never a candidate and never protected). Only after those
    /// operations succeed does it activate the prepared runners and consume
    /// the affine guard to release dispatch. Failure at any earlier point
    /// aborts startup while the fence remains closed, so a partly validated
    /// batch cannot issue new model, tool, child-workflow, or worker activity.
    pub fn resume_or_orphan_in_flight_runs(
        &self,
        executor: &WorkflowExecutor,
    ) -> Result<RecoveryReport> {
        let startup_guard = self
            .startup_recovery_guard
            .lock()
            .expect("startup recovery guard mutex poisoned")
            .take();
        let Some(startup_guard) = startup_guard else {
            anyhow::bail!("installed-main startup recovery capability was already consumed");
        };
        // Candidate discovery is lifecycle authority. If it cannot be read,
        // abort readiness before the orphan fallback touches any assignment.
        #[cfg(test)]
        if std::env::var("KATA_TEST_STARTUP_FAULT")
            .is_ok_and(|target| target == "installed_main.recovery.scan_failure")
        {
            anyhow::bail!(
                "durable execution lifecycle recovery scan failed: injected storage read failure; repair access to operational.db (or restore it from a verified backup) and retry `{} kata serve`; no lifecycle outcome was inferred",
                crate::cli::DELEGATED_SCOPE
            );
        }
        // The context states the PHASE and the safety property, and leaves the
        // recourse to the nested error, because this call is not one condition.
        // `recover_in_flight_runs` scans candidates, DECODES each durable checked
        // program, compares its identity against the ledger, and builds runners; it
        // fails on an unreadable nucleus, on a program this binary refuses to
        // dispatch (legacy/future schema, a header that does not bind its body, a
        // seven-axis tuple outside today's matrix), and on an identity mismatch.
        // "Repair access to operational.db (or restore it from a verified backup)"
        // is the remedy for exactly one of them — and for a REFUSED PROGRAM it is
        // worse than useless: the bytes are
        // intact and readable, a restore returns the same bytes, and restoring an
        // OLDER snapshot of the lifecycle authority discards durable transitions
        // that were fine, i.e. the advice destroys the state recovery just declined
        // to guess at. What a refused program's operator can do depends on why it
        // is refused — a program at this binary's schema can be finished on the
        // binary that wrote it, a legacy- or future-schema one was written by no
        // binary that opens this directory — and the nested error says which.
        let recovery = executor
            .recover_in_flight_runs(startup_guard)
            .with_context(|| {
                format!(
    "durable execution lifecycle recovery failed before readiness; startup aborted with the dispatch fence still CLOSED, so no lifecycle outcome was inferred, nothing was orphaned, and no model, tool, child-workflow, or worker activity was issued. Resolve the condition named in the nested error and retry `{} kata serve` — repairing access to operational.db, or restoring it from a verified backup, is the remedy ONLY when that error says the nucleus could not be READ; a durable program this binary refuses to dispatch is intact on disk, so a restore returns the same bytes, and the nested error names what can be done about it",
                    crate::cli::DELEGATED_SCOPE
                )
            })?;
        // Reconcile controller-application effects that were durably claimed
        // before the last shutdown but never flipped to applied (an
        // interrupted advance / promote_then_advance / park). Prepared runners
        // are still inert behind the startup fence. This is reconcile-only and
        // fail-closed: an unobservable side effect stays apply_claimed for a
        // later operator-driven retry.
        let reconcile = executor.reconcile_claimed_controller_applications_at_boot();
        if reconcile.scanned > 0 {
            info!(
                scanned = reconcile.scanned,
                reconciled = reconcile.reconciled,
                left_claimed = reconcile.left_claimed,
                errored = reconcile.errored,
                "boot reconcile: claimed controller-application sweep summary"
            );
        }
        self.reconcile_nix_environments_at_boot();
        let protected_set: std::collections::BTreeSet<ulid::Ulid> = recovery
            .outcome()
            .protected_execution_ids
            .iter()
            .copied()
            .collect();
        // Orphan only ledger state that no durable recovery plan owns. Plan
        // preparation already refused readiness if any lifecycle-owned execution
        // could not be recovered.
        //
        // Through `Dispatcher::orphan_in_flight_runs` — the ONE door for this
        // pass — rather than an orphan loop of its own.
        // A bare writer here would be an unpaired orphan writer: a boot orphan
        // would reach the retiring plane alone and the chain would keep a live
        // attempt for work boot had resolved. The door carries the protection
        // filter and the fail-closed polarity, and it owns the retiring-plane
        // read, so this file makes none.
        let orphaned = self
            .dispatcher
            .orphan_in_flight_runs("main restart (no durable checked program)", &protected_set)
            .context("orphan-fallback: marking unresumed non-terminal assignments orphaned")?;
        let report = RecoveryReport {
            resumed: recovery.outcome().resumed_execution_ids.len(),
            terminalized: recovery.outcome().terminalized_execution_ids.len(),
            unresolved_claims: usize::try_from(reconcile.left_claimed).unwrap_or(usize::MAX),
            errors: usize::try_from(reconcile.errored).unwrap_or(usize::MAX),
            orphaned,
        };
        if report.errors > 0 {
            anyhow::bail!(
                "required boot recovery reported {} error(s); refusing readiness",
                report.errors
            );
        }
        let startup_guard = executor
            .activate_recovered_runs(recovery)
            .context("activate recovered workflows after boot orphan reconciliation")?;
        startup_guard
            .release(&self.dispatcher)
            .context("release installed-main startup recovery fence")?;
        Ok(report)
    }

    /// Reconcile the Nix gc-root tree with `operational.db`, in the same boot phase
    /// as cleanup-obligation recovery.
    ///
    /// Finishes unpromoted promotions, sweeps orphan staging generations and
    /// dangling `env/<id>` directories, and reports which
    /// declared environments the store can no longer supply.
    ///
    /// # Failure
    ///
    /// NEVER fails boot, and the reason is where the binding happens: the ONE environment
    /// a capsule can bind — `[node] environment` — is declared, re-verified and promoted
    /// EARLIER in `BootRig::boot` by `bind_node_environment`, which refuses boot by name
    /// if its closure is missing, unverifiable or unrootable. So what this pass can find
    /// unavailable is an environment NOTHING on this node binds (a previous declaration,
    /// already refused `node_environment_superseded` if still live), and refusing
    /// readiness over it would refuse for a reason no execution has. Each one gets a
    /// warning line naming its id, label and missing path.
    ///
    /// A reconcile ERROR (an unreadable nucleus, an absent `nix`, a gc-root link pointing
    /// outside the store) is warned about for the same reason.
    fn reconcile_nix_environments_at_boot(&self) {
        let data_dir = self.cfg.node.data_dir.clone();
        let report = match kata_core::environment::reconcile_environments(
            self.execution_lifecycle.db(),
            &kata_core::environment::NixStore::Daemon,
            &data_dir,
        ) {
            Ok(report) => report,
            Err(error) => {
                warn!(
                    %error,
                    data_dir = %data_dir.display(),
                    "boot reconcile: the Nix environment plane could not be reconciled; declared \
                     environments may hold unswept gc-root residue. The bound node environment \
                     was already verified by bind_node_environment, so readiness is not refused"
                );
                return;
            }
        };
        for unavailable in &report.unavailable {
            warn!(
                environment_id = %unavailable.environment_id,
                label = %unavailable.label,
                reason = %unavailable.reason,
                "boot reconcile: declared Nix environment is UNAVAILABLE; issuance must refuse to \
                 bind it"
            );
        }
        if !report.is_quiet() {
            info!(
                promoted = report.promoted.len(),
                unpromotable = report.unpromotable.len(),
                swept_staging = report.swept_staging.len(),
                swept_environments = report.swept_environments.len(),
                unavailable = report.unavailable.len(),
                available = report.available,
                "boot reconcile: Nix environment plane summary"
            );
        }
    }

    /// Open the workflow store at `<data_dir>/stage_cache.db`.
    ///
    /// The file's whole content is `capsule_reuse_v1` — the reuse-hint table —
    /// beside the co-located CAS authority (`cas.db` + `cas/`). Boot retains this store so output authority and the hint plane share one
    /// CAS handle, and installs two node facts on it once: the memoised-spend bound
    /// (`[runtime] model_reuse_max_age_secs`), so every
    /// runner handed this store applies the operator's value, and this build's
    /// executor term (`kata_worker::executor_term::node_executor_term`),
    /// which every capsule reuse key consulted through it folds.
    pub fn open_stage_cache(&self) -> Result<Arc<SqliteWorkflowStore>> {
        Ok(Arc::clone(&self.stage_cache))
    }

    /// Bring up the installed-main API: `SystemHealth` reports the four
    /// subsystems healthy,
    /// a `WorkflowExecutor` is built over the rig's dispatcher /
    /// supervisor / default library roots, the per-stage cache
    /// store is opened at `<data_dir>/stage_cache.db`, then the already-retained
    /// listener is checked against the resolved runtime address and the server
    /// is spawned in the background. The returned task is the runtime's
    /// owned listener lifecycle and must be monitored until shutdown.
    pub fn start_api_server(
        &self,
        listener: tokio::net::TcpListener,
        mode_label: &'static str,
        directory_id: &str,
        process_generation: &str,
        loaded_binary_digest: &str,
        loaded_config_digest: &str,
        loaded_config_path: &str,
        loaded_service_environment_digest: Option<String>,
    ) -> Result<ApiServerTask> {
        let health = Arc::new(SystemHealth::new());
        health.report(SubsystemId::Storage, SubsystemHealth::Healthy);
        health.report(SubsystemId::WorkerPool, SubsystemHealth::Healthy);
        health.report(SubsystemId::Agent, SubsystemHealth::Healthy);
        health.report(SubsystemId::Workflow, SubsystemHealth::Healthy);
        // `build_workflow_executor` retains the canonical executor in
        // `self.workflow_executor` (so `drain_workflow_tasks` can await its
        // in-flight run teardown at shutdown) — no separate retention needed here.
        let workflow_executor = self.build_workflow_executor()?;
        // Surface build-time provenance via `GET /api/v1/version`
        // so an operator orchestrating waves can verify the
        // running daemon == the binary they just built.
        let report = self
            .recovery_report
            .lock()
            .expect("recovery report mutex poisoned")
            .clone();
        let (recovery_state, next_action) = report.state();
        let control_endpoint = format!("http://{}", self.cfg.api.bind);
        let state = AppState::with_executor(health, workflow_executor)
            .with_memory_store(Arc::clone(&self.native_memory_store))
            .with_version_info(crate::build_info::version_info())
            .with_runtime_status(self.cfg.node.id.clone())
            .with_authority_status(AuthorityStatus {
                process_mode: mode_label.to_string(),
                directory_id: directory_id.to_string(),
                process_generation: process_generation.to_string(),
                attachment_protocol_version: crate::attachment::ATTACHMENT_PROTOCOL_VERSION,
                binary_version: env!("CARGO_PKG_VERSION").to_string(),
                loaded_binary_digest: loaded_binary_digest.to_string(),
                control_endpoint,
                loaded_config_digest: loaded_config_digest.to_string(),
                loaded_config_path: loaded_config_path.to_string(),
                loaded_service_environment_digest,
                recovery_state: recovery_state.to_string(),
                next_action,
            });
        let server = ApiServer::build(&self.cfg.api, state)
            .with_context(|| format!("{mode_label} API server configuration is invalid"))?;
        let addr = listener
            .local_addr()
            .context("reading the retained API listener address")?;
        anyhow::ensure!(
            addr == server.bind_addr(),
            "retained API listener does not match the resolved runtime endpoint"
        );
        let task = server.spawn_on(listener);
        info!(%addr, mode = mode_label, "api server: bound and ready");
        Ok(task)
    }

    /// Build the shared `Arc<WorkflowExecutor>` the API server drives.
    ///
    /// This is the executor construction `start_api_server` uses, factored out
    /// so a test that does NOT want an axum surface can reach the identical
    /// engine the REST `/ops` route, and the CLI and MCP faces through it, reach.
    /// It wires the per-stage cache, native-memory and checked-program stores, the shared
    /// execution-workspace provider, child-execution spawning, boot
    /// resume/orphan, and the input-await + ledger-compaction self-heal sweeps.
    /// The result is the canonical `Arc<WorkflowExecutor>` — pass it straight
    /// into `kata_api::op_dispatch::invoke_operation` to serve every operation the
    /// node serves (not the workstation-local `author`).
    #[allow(clippy::too_many_lines)]
    pub fn build_workflow_executor(&self) -> Result<Arc<WorkflowExecutor>> {
        let library = Arc::new(WorkflowLibrary::default_roots());
        let stage_cache_store = self.open_stage_cache()?;
        let mut executor_builder = WorkflowExecutor::new(
            Arc::clone(&self.dispatcher),
            Arc::clone(&self.supervisor),
            library,
        )
        .with_cache_store(stage_cache_store.clone())
        .with_memory_store(Arc::clone(&self.native_memory_store))
        .with_execution_lifecycle(self.execution_lifecycle.clone())
        // The `/work` INPUT ceiling from `[node]`
        // `work_tree_max_bytes`/`work_tree_max_entries`, enforced by the
        // committed-base-tree conversion an isolated `oci` admission runs.
        .with_work_tree_input_bounds(kata_types::tree_artifact::WorkTreeInputBounds {
            max_bytes: self.cfg.node.work_tree_max_bytes,
            max_entries: self.cfg.node.work_tree_max_entries,
        })
        // The `[git_view]` history bounds, enforced by
        // the committed-base git-history conversion an isolated `oci`
        // admission runs when the program carries an agent stage.
        .with_git_view_config(self.cfg.git_view.clone())
        .with_active_execution_budget(
            self.cfg.runtime.max_active_executions,
            self.cfg.runtime.max_active_execution_bytes,
        )
        .context("active execution residency reconstruction refused readiness")?;
        // Execution workspace provider: factory-as-loop foundation shares the
        // SINGLE provider built at `boot()` (the same `Arc` the
        // `workspace_effect` backend holds), so an effect-stage's park/promote
        // sees the very worktree the executor's apply-gate created.
        if let Some(provider) = self.workspace_provider.as_ref() {
            executor_builder = executor_builder.with_workspace_provider(Arc::clone(provider));
            executor_builder = executor_builder.with_forge(Some(Arc::new(
                kata_vcs::GhCliForge::new(self.cfg.vcs.jj_repo.clone()),
            )));
            info!(
                backend = %provider.backend().as_str(),
                "workspace_provider: shared boot provider attached to executor"
            );
        }
        let workflow_executor = Arc::new(executor_builder);
        // Install child-execution spawning now that the
        // executor lives in its canonical `Arc`. This registers the `Weak`
        // self-reference that lets a subworkflow stage launch its CHILD workflow
        // execution. Must run before `resume_or_orphan_in_flight_runs` so a
        // resumed run that reaches a subworkflow stage for the first time has
        // the spawner wired.
        workflow_executor.install_child_spawning();
        // Drive resume_in_flight_runs + orphan-fallback
        // BEFORE the API server starts accepting requests. A client
        // that polls `GET /executions/{id}` immediately after the
        // server binds must see resumed runs as `Running`, not
        // `Orphaned`, so the resume call has to land first.
        let report = self
            .resume_or_orphan_in_flight_runs(&workflow_executor)
            .context("required installed-main recovery failed before readiness")?;
        *self
            .recovery_report
            .lock()
            .expect("recovery report mutex poisoned") = report;
        // Input-await timeouts resolve inside the dispatcher's due-wait sweep
        // (`sweep_due_waits` wakes a parked `awaiting_input` main attempt with
        // its request's `default_assumption`); no api-side sweep remains.
        // Assignment terminality is not workflow terminality. The explicit
        // lifecycle now proves top-level outcome, but the split stores still
        // lack one atomic deletion contract spanning program, lifecycle,
        // assignments, evidence, candidate/workspace roots, and dependent
        // assets. Keep the compatibility setting visible and report the
        // fail-closed retained posture instead of running a partial compactor.
        let ledger_ttl_secs = self.cfg.runtime.ledger_ttl_secs;
        if ledger_ttl_secs > 0 {
            warn!(
                ttl_secs = ledger_ttl_secs,
                "ledger retention unavailable: assignment and checked-program rows are retained until an atomic dependent-asset retention contract lands"
            );
        }
        // Durable engine-level schedules/cron, authoritative in
        // `operational.db`'s schedule tables. The engine takes the SAME operational
        // handle boot opened, so schedule state lives in the one nucleus beside
        // every execution it fires. Spawned here (not alongside the dispatcher sweeps) because the
        // submit closure needs the `WorkflowExecutor`. An empty table sweeps as a
        // no-op, so this is free on nodes with no schedules.
        let schedule_face =
            kata_workflow::schedule::ScheduleFace::new(Arc::clone(self.execution_lifecycle.db()));
        // Reconcile the durable schedule table to what the workflow library
        // declares (`schedule(id=..,submit=..,cron=..|every_ms=..)` at module
        // scope). Re-installing an unchanged declaration PRESERVES its durable
        // cursor; an EDITED target pack is rebound explicitly; a declaration no
        // longer present is removed so a deleted `schedule(...)` stops firing.
        install_library_schedules(&schedule_face);
        // The SCHEDULE half of the compatibility membrane, read
        // AFTER reconciliation so anything the library rebind healed is gone.
        //
        // What survives is a schedule whose pinned program this binary cannot admit AND
        // whose target no longer compiles, so boot deliberately kept the stale pin. That
        // schedule now fires NOTHING, forever — `checked_admission` refuses the pinned
        // bytes, `revalidated_pin` errors, and the sweep parks the cursor behind one WARN
        // per 30s. Reported at ERROR, once, with the remedy, rather than only as recurring
        // sweep noise. Not a boot refusal: at boot there IS a pin, which is the same
        // asymmetry that makes the cutover fail closed and the reconciliation keep-and-warn.
        report_unfireable_schedule_pins(&schedule_face);
        let submit_executor = Arc::clone(&workflow_executor);
        let submit_face = schedule_face.clone();
        let submit: kata_workflow::schedule::SubmitFn =
            Arc::new(move |fire| fire_pinned_schedule(&submit_executor, &submit_face, fire));
        let engine = Arc::new(kata_workflow::schedule::ScheduleEngine::new(
            schedule_face,
            submit,
        ));
        let sweep_interval = Duration::from_secs(30);
        self.track_background_task(tokio::spawn(engine.run_schedule_sweep(sweep_interval)));
        // Retain the canonical executor so the shutdown path can drain
        // its in-flight workflow tasks (terminal park/teardown) before the
        // runtime is dropped. Done HERE (not only in `start_api_server`) so a
        // caller that builds its executor via this method directly and never
        // starts the API server is also drainable. First build wins; a second
        // call (not expected in an installed main) leaves the first handle in
        // place.
        let _ = self.workflow_executor.set(Arc::clone(&workflow_executor));
        Ok(workflow_executor)
    }

    /// Drain in-flight workflow tasks at shutdown so a completed /
    /// failed run's workspace park/teardown finishes before the tokio runtime
    /// is dropped (which would otherwise abort the detached task mid-teardown
    /// and leak the workspace). The installed main invokes this after its
    /// shutdown signal fires and before returning from the runtime block (an
    /// executor built through `build_workflow_executor` alone is drainable too,
    /// because that method retains it here). Bounded
    /// internally so a stuck task cannot hang shutdown; the
    /// boot reaper backstops anything the budget could not drain. A no-op on a
    /// node that never started an engine (nothing registered).
    pub fn close_admission(&self) {
        if let Some(executor) = self.workflow_executor.get() {
            executor.close_admission();
        }
    }

    /// Wait for operations admitted before the shutdown fence to finish their
    /// durable creation/task-registration critical sections before taking the
    /// workflow-task drain snapshot.
    pub async fn wait_for_admission_quiescence(&self, budget: Duration) -> bool {
        let Some(executor) = self.workflow_executor.get() else {
            return true;
        };
        executor.wait_for_admission_quiescence(budget).await
    }

    /// Resolve when the canonical workflow executor can no longer guarantee
    /// that every durable Running lifecycle has a live driver. Top-level engine
    /// loops must exit on this signal so service restart recovery takes over.
    pub async fn wait_for_executor_fatal(&self) -> Arc<str> {
        self.workflow_executor
            .get()
            .expect("workflow executor must be built before fatal supervision starts")
            .wait_for_fatal()
            .await
    }

    fn track_background_task(&self, handle: tokio::task::JoinHandle<()>) {
        self.background_tasks
            .lock()
            .expect("background task mutex poisoned")
            .push(handle);
    }

    /// Stop every main-owned producer/sweeper before draining executions.  Each
    /// task is abort-safe because its externally visible mutations commit through
    /// the durable ledger/store APIs; restart recovery remains the backstop.
    pub async fn stop_background_tasks(&self, budget: Duration) -> bool {
        let handles = std::mem::take(
            &mut *self
                .background_tasks
                .lock()
                .expect("background task mutex poisoned"),
        );
        for handle in &handles {
            handle.abort();
        }
        tokio::time::timeout(budget, async move {
            for handle in handles {
                let _ = handle.await;
            }
        })
        .await
        .is_ok()
    }

    pub async fn drain_workflow_tasks(&self) -> bool {
        let Some(executor) = self.workflow_executor.get() else {
            return self.delivery_service.catch_up().is_ok();
        };
        let (drained, completed) = executor
            .drain_in_flight_workflow_tasks(Duration::from_secs(10))
            .await;
        if drained > 0 {
            info!(
                drained,
                "workflow task drain: awaited in-flight run teardown before shutdown"
            );
        }
        let projected = match self.delivery_service.catch_up() {
            Ok(_) => true,
            Err(error) => {
                warn!(%error, "shutdown delivery catch-up failed; restart will retry from durable cursor");
                false
            }
        };
        completed && projected
    }

    /// Drain seam for a workflow task spawned outside the
    /// executor's own `submit` path. Registering it here makes
    /// [`Self::drain_workflow_tasks`] await terminal teardown instead of letting
    /// a raw `tokio::spawn` race the runtime drop. A no-op if no engine was
    /// started (the executor OnceLock is empty — nothing to drain against).
    pub fn track_workflow_task(&self, handle: tokio::task::JoinHandle<()>) {
        if let Some(executor) = self.workflow_executor.get() {
            executor.track_workflow_task(handle);
        }
    }
}

/// Classify the clean engine's core store set before any constructor can create
/// a missing authoritative database. A completely absent set is a fresh boot;
/// once any core store exists, both authority files must remain present.
fn preflight_clean_engine_stores(data_dir: &Path) -> anyhow::Result<()> {
    crate::data_dir_lock::preflight_clean_installed_engine(data_dir)
}

/// Scan the default workflow library and reconcile every durable
/// `schedule(...)` declaration into `face` so the boot
/// [`ScheduleEngine`](kata_workflow::schedule::ScheduleEngine) sweep finds real
/// entries. Thin wrapper over [`install_library_schedules_into`] pinned to
/// [`WorkflowLibrary::default_roots`].
fn install_library_schedules(face: &kata_workflow::schedule::ScheduleFace) {
    install_library_schedules_into(face, &WorkflowLibrary::default_roots());
}

/// Reconcile the durable schedule table to the schedules `library` declares (the
/// testable core of [`install_library_schedules`]).
///
/// The library is the DECLARATIVE source of truth for a node's schedules, so this
/// reconciles the durable table to it on every boot. Four cases:
///
/// | Case | Action |
/// |---|---|
/// | id absent | install, PINNING the compiled target; cursor = `trigger.next_after(now)` |
/// | id present, binding identical | idempotent no-op; **cursor preserved** |
/// | id present, binding differs | explicit `rebind`; cursor preserved unless the trigger changed |
/// | id no longer declared | remove, so a deleted `schedule(...)` stops firing |
///
/// ## Activation model / limits
///
/// * **Restart-to-arm.** Schedules are (re)armed ONLY here, at boot, from a
///   library scan. There is no live install-on-submit ingress, so a `schedule()`
///   newly authored or edited in a pack is INERT on a long-running daemon until
///   the next process restart re-runs this scan. The program BINDING is also
///   restart-scoped, because a rebind is an
///   operator act and this scan is where it happens.
/// * **A pack edit takes effect HERE, never at fire time.** An edit may never
///   *silently* alter a scheduled execution. A boot-time library
///   reconciliation is the node operator's declarative act — it is logged and
///   bounded to a restart — whereas a fire is a timer, so rebinding at fire time
///   would be exactly that silent alteration. An execution already
///   fired from the old binding is untouched by construction: the fire copied the
///   pinned program into that execution's own `programs` row.
/// * **Compile-failure is prune-safe AND pin-safe.** An uncompilable pack (e.g. a
///   transient in-progress syntax error) is logged and skipped. Because we then
///   cannot know which ids that pack WOULD have declared, the prune step is SKIPPED
///   for the whole boot when any pack failed to compile — otherwise a
///   transiently-broken scheduled pack would have its durable row (and cursor)
///   pruned, disarming it and dropping a `FireOnceOnBoot` catch-up. Symmetrically, a
///   schedule whose TARGET pack stops compiling KEEPS its existing pin and warns:
///   the pinned program is durable and was valid when pinned, so the schedule keeps
///   working through a transient authoring error, rather than failing at FIRE and
///   silently losing one occurrence per sweep, forever.
/// * **Duplicate id ⇒ last-writer-wins.** Two packs declaring the SAME schedule
///   id collide on the durable key; the later-scanned pack's spec wins. This is
///   logged at WARN so the silent shadowing is observable.
///
/// Best-effort and non-fatal throughout: a per-schedule failure is logged, never
/// propagated — one broken declaration must not stop the others from arming.
fn install_library_schedules_into(
    face: &kata_workflow::schedule::ScheduleFace,
    library: &WorkflowLibrary,
) {
    let now_ms = kata_workflow::schedule::schedule_now_ms();
    // id → the pack name that declared it, so a second declaration of the same
    // id can be flagged as a last-writer-wins collision.
    let mut declared: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut had_compile_failure = false;
    for entry in library.list_effective() {
        let artifact = match kata_program::preflight::build_workflow_compiled_artifact_from_file(
            &entry.path,
            library.roots(),
        ) {
            Ok(artifact) => artifact,
            Err(e) => {
                had_compile_failure = true;
                warn!(
                    workflow = %entry.name,
                    path = %entry.path.display(),
                    error = %e,
                    "schedule install: skipping uncompilable workflow (its schedules, if any, keep their durable cursor and pin this boot)"
                );
                continue;
            }
        };
        for spec in &artifact.schedules {
            if let Some(first_pack) = declared.get(&spec.id)
                && first_pack != &entry.name
            {
                warn!(
                    schedule = %spec.id,
                    first_pack = %first_pack,
                    second_pack = %entry.name,
                    "schedule install: duplicate schedule id declared by two packs; last writer wins"
                );
            }
            declared.insert(spec.id.clone(), entry.name.clone());
            reconcile_one_schedule(face, library, &entry.name, spec, now_ms);
        }
    }
    // Prune any durable row the library no longer declares so a removed
    // `schedule(...)` stops firing across the reboot that dropped it — but ONLY
    // when the scan was CLEAN. If any pack failed to compile we cannot know which
    // ids it would have declared, so pruning could disarm a transiently-broken
    // pack's schedule (losing its cursor). Skip prune this boot and warn instead.
    let installed = match face.all() {
        Ok(installed) => installed,
        Err(e) => {
            warn!(error = %e, "schedule install: cannot read the durable schedule table; skipping prune this boot");
            return;
        }
    };
    if had_compile_failure {
        let undeclared: Vec<String> = installed
            .into_iter()
            .filter(|record| !declared.contains_key(&record.id))
            .map(|record| record.id)
            .collect();
        if !undeclared.is_empty() {
            warn!(
                undeclared = ?undeclared,
                "schedule install: a workflow pack failed to compile; skipping prune of undeclared schedules this boot so a transiently-broken scheduled pack keeps its durable cursor (re-run on the next clean boot)"
            );
        }
        return;
    }
    for record in installed {
        if !declared.contains_key(&record.id) {
            match face.remove(&record.id) {
                Ok(_) => info!(
                    schedule = %record.id,
                    "schedule install: pruned schedule no longer declared by any pack"
                ),
                Err(e) => warn!(
                    schedule = %record.id,
                    error = %e,
                    "schedule install: prune failed (non-fatal)"
                ),
            }
        }
    }
}

/// Install or REBIND one declared schedule, pinning its compiled target.
///
/// The target pack is resolved and compiled HERE — the one place in the product
/// where a schedule's program is chosen. `install` refuses a divergent binding, so a
/// refusal is the signal to `rebind`, which is the ONE function permitted to change
/// a pin. An uncompilable or unresolvable target keeps the EXISTING pin and warns;
/// with no existing pin there is nothing to keep and the schedule is simply not
/// armed.
fn reconcile_one_schedule(
    face: &kata_workflow::schedule::ScheduleFace,
    library: &WorkflowLibrary,
    pack: &str,
    spec: &kata_program::schedule::ScheduleSpec,
    now_ms: u64,
) {
    let already_pinned = matches!(face.get(&spec.id), Ok(Some(_)));
    let program = match library.resolve(&spec.submit_pack).and_then(|path| {
        kata_program::execution_program::compile_execution_program_from_file(&path, library.roots())
    }) {
        Ok(program) => program,
        Err(e) => {
            if already_pinned {
                warn!(
                    workflow = %pack,
                    schedule = %spec.id,
                    submit = %spec.submit_pack,
                    error = %e,
                    "schedule install: submit target does not compile; KEEPING the existing pin so the schedule keeps firing the program it was bound to"
                );
            } else {
                warn!(
                    workflow = %pack,
                    schedule = %spec.id,
                    submit = %spec.submit_pack,
                    error = %e,
                    "schedule install: submit target does not compile and there is no existing pin; schedule NOT armed"
                );
            }
            return;
        }
    };
    match face.install(spec, &program, now_ms) {
        Ok(outcome) => info!(
            workflow = %pack,
            schedule = %spec.id,
            submit = %spec.submit_pack,
            ?outcome,
            program_hash = %program.program_hash,
            "schedule install: armed durable schedule from library pack"
        ),
        // A divergent binding is exactly what `rebind` is for. `install` refusing
        // here is the design: it means only ONE function in the workspace can change
        // a pin, so a source guard has a single symbol to pin its call site to.
        Err(install_error) => match face.rebind(spec, &program, now_ms) {
            Ok(outcome) => info!(
                workflow = %pack,
                schedule = %spec.id,
                submit = %spec.submit_pack,
                ?outcome,
                program_hash = %program.program_hash,
                "schedule install: REBOUND durable schedule to the edited pack (an operator act, bounded to this restart)"
            ),
            Err(rebind_error) => warn!(
                workflow = %pack,
                schedule = %spec.id,
                install_error = %install_error,
                rebind_error = %rebind_error,
                "schedule install: install and rebind both failed (non-fatal); the existing pin is unchanged"
            ),
        },
    }
}

/// Report every installed schedule whose PINNED program this binary cannot admit, at
/// ERROR, once per boot.
///
/// # Failure mode
///
/// Such a schedule is PERMANENTLY unfireable and self-heals only through a rebind, so
/// if the target no longer compiles it stays dead. Without this report the whole
/// operator signal for that state is one WARN per 30s from the sweep, while the same
/// condition on an execution program is a fail-closed boot refusal. An unreadable
/// schedule table is itself only a WARN: this is a report, and the
/// sweep's own `face.all()` arm already fails closed for the tick.
fn report_unfireable_schedule_pins(face: &kata_workflow::schedule::ScheduleFace) {
    match face.incompatible_pinned_programs() {
        Ok(found) => {
            for finding in found {
                error!(
                    schedule = %finding.schedule_id,
                    submit = %finding.submit_pack,
                    pinned_schema_version = ?finding.schema_version,
                    // The DEADLINE, not decoration: this refusal costs an
                    // occurrence at the next due instant, unattended, whereas the
                    // execution-side membrane costs a refused boot the operator is
                    // already watching.
                    next_fire_ms = ?finding.next_fire_ms,
                    reason = %finding.reason,
                    "schedule PERMANENTLY UNFIREABLE: its pinned program cannot be admitted by \
                     this binary, and boot could not rebind it (the submit target must compile \
                     under this binary for a rebind to happen). The occurrence due at \
                     `next_fire_ms` is LOST, as is every one after it, until the target is fixed \
                     with `kata check --all` and the node restarted, or the `schedule(...)` \
                     declaration is removed"
                );
            }
        }
        Err(error) => warn!(
            error = %error,
            "could not inspect durable schedule pins for compatibility (non-fatal)"
        ),
    }
}

fn assignment_start_deadline_from_worker_pool(workers: &WorkerPoolConfig) -> Option<Duration> {
    if workers.assignment_start_deadline_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(workers.assignment_start_deadline_ms))
    }
}

/// The durable file backing the `InFlightLedger`'s append-only event log, a
/// [`kata_core::DurableEventLog`] opened `synchronous=FULL`. The log owns the
/// file's `sequence` PRIMARY KEY, so no other `DurableEventLog` may share it.
/// Keep it a flat top-level `*.db` so `backup::discover_databases` auto-covers it.
pub(crate) fn ledger_events_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("ledger_events.db")
}

fn refuse_incompatible_execution_programs_at_boot(store: &ExecutionLifecycleFace) -> Result<()> {
    let blocking = store
        .incompatible_programs()
        .context("failed to inspect durable checked programs before startup")?;
    if blocking.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "installed main startup refused: {}",
        blocking_programs_refusal(&blocking)
    )
}

/// What boot and `kata upgrade` both say about a non-empty
/// [`blocking_incompatible_programs`](kata_workflow::execution_program_store::blocking_incompatible_programs)
/// set: the per-execution reasons, [`BLOCKING_PROGRAMS_SCOPE`], then
/// [`blocking_programs_recourse`]. The two commands compute ONE set, so they say
/// one thing about it.
pub(crate) fn blocking_programs_refusal(
    blocking: &[kata_workflow::execution_program_store::IncompatibleExecutionProgram],
) -> String {
    let reasons = blocking
        .iter()
        .map(|program| {
            format!(
                "{}: {}",
                program.execution_id,
                program.incompatibility.reason()
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "incompatible checked program(s) remain: {reasons}. {BLOCKING_PROGRAMS_SCOPE} {}",
        blocking_programs_recourse(blocking)
    )
}

/// What an operator can do about `blocking` — the only moves that exist, which
/// depend on who wrote the programs.
///
/// A program at this binary's checked-program schema was written by a binary of this
/// operational schema, which can still open the directory and dispatch it, so
/// finishing its execution there is a move. A schema verdict
/// ([`is_schema_verdict`](kata_workflow::execution_program_store::ExecutionProgramIncompatibility::is_schema_verdict))
/// was written by no binary that opens this directory, so for a set of only those the
/// fresh data directory is the one move, and naming a writing binary would contradict
/// the per-program reason printed beside it.
pub(crate) fn blocking_programs_recourse(
    blocking: &[kata_workflow::execution_program_store::IncompatibleExecutionProgram],
) -> String {
    let moves = if blocking
        .iter()
        .all(|program| program.incompatibility.is_schema_verdict())
    {
        NO_WRITING_BINARY_MOVES
    } else {
        WRITING_BINARY_MOVES
    };
    format!("{BLOCKING_PROGRAMS_NO_REMOVAL} {moves} {BLOCKING_PROGRAMS_NO_FORCING}")
}

/// Which retained programs block, and why the others do not.
pub(crate) const BLOCKING_PROGRAMS_SCOPE: &str = "These are the programs of NON-TERMINAL \
     executions (admitting, running or terminalizing): the execution lifecycle is the \
     top-level terminal authority, and assignment rows are not, because a completed \
     predecessor may have an undispatched successor, so every such execution's program is \
     checked whether or not it holds a live assignment. A terminal execution's program is \
     retained evidence and blocks nothing (an execution record whose program this binary \
     cannot read carries a `checked_program_unreadable:` warning).";

/// The removal that does not exist, whichever moves do.
const BLOCKING_PROGRAMS_NO_REMOVAL: &str = "Kata will not rewrite or dispatch such a program \
     under a different execution boundary, and NO Kata binary has an operation that removes a \
     checked-program row (there is no `kata prune` subcommand and no API route that \
     prunes).";

/// The moves while some blocking program is at this binary's checked-program schema.
const WRITING_BINARY_MOVES: &str = "Finishing or cancelling these executions with the binary \
     that wrote them clears this refusal: that binary stamps this binary's operational schema \
     (a data directory any other schema stamped is refused before this check, at its version, \
     so no binary of an earlier schema can finish them here). The two supported moves are (1) \
     finish or cancel these executions with the Kata binary that wrote these programs, which \
     can still dispatch them, then run this one — a move that exists only for a program at \
     this binary's checked-program schema, because one whose header names another schema, or \
     none, was written by no binary that opens this directory — or (2) run this binary \
     against a different `[node] data_dir` — a fresh `kata init` project is the shortest \
     route — leaving this directory intact as evidence.";

/// The moves when every blocking program is a schema verdict.
const NO_WRITING_BINARY_MOVES: &str = "Every program named here has a header that names \
     another checked-program schema, or none, so no binary that opens this directory wrote \
     it: every checked-program schema bump moves the operational schema, and a data \
     directory another one stamped is refused before this check. The one supported move is \
     to run this binary against a different `[node] data_dir` — a fresh `kata init` project \
     is the shortest route — leaving this directory intact as evidence.";

/// What not to do, and where the detail is.
const BLOCKING_PROGRAMS_NO_FORCING: &str = "Do not hand-edit or delete rows to force it. Run \
     `kata upgrade --dry-run --data-dir <dir>` for the per-execution reasons; see \
     docs/architecture/0001-replacement-architecture.md";

#[cfg(test)]
mod tests {
    use super::*;

    /// **Would red if:** the `recovery_failed` recourse printed `kata serve` without the
    /// delegated scope an undelegated login shell needs before it will boot.
    #[test]
    fn a_failed_recovery_names_kata_serve_under_a_delegated_scope() {
        let (state, recourse) = RecoveryReport {
            errors: 1,
            ..RecoveryReport::default()
        }
        .state();
        assert_eq!(state, "recovery_failed");
        let recourse = recourse.expect("a failed recovery carries a recourse");
        assert!(
            recourse.contains("`systemd-run --user --scope -p Delegate=yes -- kata serve`"),
            "{recourse}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const INSTALLED_MAIN_CHILD_CONFIG: &str = "KATA_TEST_INSTALLED_MAIN_CHILD_CONFIG";

    /// Register `transport` straight onto the supervisor — a test double with no
    /// Hello — under the executor term boot installed on the stage cache, the
    /// term a production node of this build states on enrollment.
    fn register_test_double(
        rig: &BootRig,
        id: smol_str::SmolStr,
        transport: Arc<dyn kata_transport::WorkerTransport>,
        capabilities: Vec<String>,
        containment: kata_types::containment_claim::ClaimedContainment,
        domain: kata_types::identity::WorkerEffectDomain,
    ) -> kata_transport::supervisor::WorkerRecoveryPeer {
        let term = *rig
            .open_stage_cache()
            .expect("the booted stage cache")
            .executor_term()
            .expect("boot installs this build's executor term")
            .digest();
        rig.supervisor.register_worker_with_effect_domain(
            id,
            transport,
            capabilities,
            containment,
            term,
            domain,
        )
    }

    /// Run `root` on the runtime every main runs inside, started the way the mains
    /// start it.
    fn start_runtime<Fut: std::future::Future>(root: Fut) -> Fut::Output {
        crate::runtime_start::Runtime::build()
            .expect("build the main's runtime")
            .run(root)
    }

    async fn boot_durable_recovery_test_rig() -> (tempfile::TempDir, BootRig) {
        boot_durable_recovery_test_rig_with(|_| {}).await
    }

    /// The rig above, with one hook to perturb the node config BEFORE boot —
    /// the seam a test needs when the thing under test is what `BootRig::boot`
    /// does with a config value.
    async fn boot_durable_recovery_test_rig_with(
        mutate: impl FnOnce(&mut KataConfig),
    ) -> (tempfile::TempDir, BootRig) {
        let (root, data_dir, booted) = try_boot_durable_recovery_test_rig_with(mutate).await;
        let rig = booted.expect("boot durable rig behind recovery fence");
        let identity: serde_json::Value =
            serde_json::from_slice(&std::fs::read(data_dir.join("main-identity.json")).unwrap())
                .unwrap();
        assert_eq!(
            rig.source_main_identity,
            identity["directory_id"].as_str().unwrap(),
            "worker enrollment must use the persisted main authority"
        );
        (root, rig)
    }

    /// [`boot_durable_recovery_test_rig_with`], returning boot's own verdict so a cell can
    /// observe a boot REFUSAL.
    async fn try_boot_durable_recovery_test_rig_with(
        mutate: impl FnOnce(&mut KataConfig),
    ) -> (tempfile::TempDir, std::path::PathBuf, Result<BootRig>) {
        use kata_test_utils::live::{CapacityTopology, VcsSpec, render_node_config};

        let root = tempfile::tempdir().expect("installed-main recovery root");
        let data_dir = root.path().join("data");
        std::fs::create_dir(&data_dir).expect("create data directory");
        drop(
            crate::data_dir_lock::DataDirLock::acquire(
                &data_dir,
                crate::data_dir_lock::MainMode::Installed,
                None,
            )
            .expect("initialize clean installed-engine store set"),
        );
        let repo = root.path().join("repo");
        std::fs::create_dir(&repo).expect("create repository");
        kata_test_utils::git::init_git_repo_at(&repo);

        let rendered = render_node_config(
            CapacityTopology::LocalSocket,
            &data_dir,
            // `BootRig::boot` binds no API listener: the address only fills
            // the config.
            "127.0.0.1:0".parse().expect("a loopback socket address"),
            Some(&data_dir.join("worker.sock")),
            &kata_test_utils::live::NodeConfigOptions {
                vcs: Some(VcsSpec::native_jj(repo)),
                ..kata_test_utils::live::NodeConfigOptions::default()
            },
        );
        let mut cfg: KataConfig = toml::from_str(&rendered).expect("parse test config");
        cfg.vcs.op_log_gc_enabled = false;
        // The rig boots the capsule arm over the fixture environment: the
        // declaration names the one store path that exists on no host, which
        // `bind_configured_node_environment` keys on to bind the fixture
        // manifest instead of asking Nix. `mutate` still overrides (a cell
        // asserting `node_environment_undeclared` sets `environment = None`).
        cfg.node.environment = Some(kata_workflow::test_harness::fixture_environment_declaration());
        mutate(&mut cfg);
        let booted = BootRig::boot(Arc::new(cfg)).await;
        (root, data_dir, booted)
    }

    /// A node that declares no `[node] environment` is refused at BOOT, by
    /// name, rather than at its first dispatch. Reads the verdict off boot itself.
    #[test]
    fn a_node_without_an_environment_is_refused_at_boot() {
        start_runtime(async move {
            let (_root, _data_dir, booted) = try_boot_durable_recovery_test_rig_with(|cfg| {
                cfg.node.environment = None;
            })
            .await;
            let refusal = format!("{:#}", booted.err().expect("boot must refuse"));
            assert!(
                refusal.contains(kata_types::config::NODE_ENVIRONMENT_UNDECLARED),
                "refused by name: {refusal}"
            );
        });
    }

    /// Re-executed by `installed_main_startup_faults_fail_closed_and_repair`.
    /// The fault controls in `data_dir_lock` and `BootRig` exist only in this
    /// cfg(test) library, so the child drives the real installed-main entrypoint
    /// without putting a fault API into a production binary.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn installed_main_fault_child() {
        let Some(config) = std::env::var_os(INSTALLED_MAIN_CHILD_CONFIG) else {
            return;
        };
        let result = crate::cli::run(crate::cli::Cli {
            api_url: crate::attachment::DEFAULT_API_URL.to_string(),
            format: crate::cli::OutputFormat::Human,
            command: crate::cli::Command::Serve {
                config: config.into(),
            },
        });
        if std::env::var_os("KATA_TEST_INSTALLED_MAIN_EXPECT_FAILURE").is_some() {
            match result {
                Err(error) => {
                    eprintln!("installed-main startup failed as expected: {error:#}");
                    std::process::exit(73);
                }
                Ok(()) => panic!("installed main unexpectedly reached and left readiness"),
            }
        }
        result.expect("installed main should become ready and stop cleanly on SIGTERM");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn installed_main_startup_faults_fail_closed_and_repair() {
        use std::ffi::OsStr;
        use std::io::Read as _;
        use std::net::{SocketAddr, TcpStream};
        use std::path::PathBuf;
        use std::process::{Child, Command, Output, Stdio};
        use std::time::{Duration, Instant};

        use kata_test_utils::held_port::HeldPort;
        use kata_test_utils::live::{CapacityTopology, VcsSpec, render_node_config};

        struct Case {
            root: tempfile::TempDir,
            harness_binary: PathBuf,
            data_dir: PathBuf,
            config: PathBuf,
            attachment: PathBuf,
            api: SocketAddr,
            /// `api`, held for the case's life: each child main binds it, and
            /// no other process's `:0` bind is handed it, so a connect that
            /// succeeds reached this case's main.
            _api_port: HeldPort,
        }

        fn new_case(name: &str, harness_binary: &Path) -> Case {
            let root = tempfile::tempdir().expect("fault case tempdir");
            std::fs::set_permissions(
                root.path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .expect("make fault case tempdir owner-private");
            let data_dir = root.path().join("data");
            std::fs::create_dir(&data_dir).expect("create data dir");
            let api_port = HeldPort::new().expect("hold API port");
            let api = api_port.addr();
            let worker_socket = data_dir.join("worker.sock");
            let config = root.path().join("kata.toml");
            let repo = root.path().join("repo");
            std::fs::create_dir(&repo).expect("create test repository");
            kata_test_utils::git::init_git_repo_at(&repo);
            let vcs = VcsSpec::native_jj(repo);
            let rendered = render_node_config(
                CapacityTopology::LocalSocket,
                &data_dir,
                api,
                Some(&worker_socket),
                &kata_test_utils::live::NodeConfigOptions {
                    vcs: Some(vcs),
                    ..kata_test_utils::live::NodeConfigOptions::default()
                },
            )
            .replace("dispatch_deadline_ms = 30000", "dispatch_deadline_ms = 500");
            // The child's `kata serve` boots the capsule arm; render_node_config
            // emits the LIVE store pins, which only a host with the Nix closures
            // realised can bind. Rebind onto the fixture environment — the one
            // declaration `bind_configured_node_environment` serves without
            // asking the host's store.
            let mut parsed: KataConfig = toml::from_str(&rendered).expect("parse rendered config");
            parsed.node.environment =
                Some(kata_workflow::test_harness::fixture_environment_declaration());
            let rendered = toml::to_string(&parsed).expect("re-serialize fixture config");
            std::fs::write(&config, rendered).expect("write installed-main config");
            Case {
                attachment: root.path().join(format!("{name}-attachment.json")),
                root,
                harness_binary: harness_binary.to_path_buf(),
                data_dir,
                config,
                api,
                _api_port: api_port,
            }
        }

        fn child_command(case: &Case) -> Command {
            let mut command = Command::new(&case.harness_binary);
            command
                .arg("--exact")
                .arg("boot::tests::installed_main_fault_child")
                .arg("--nocapture")
                .env(INSTALLED_MAIN_CHILD_CONFIG, &case.config)
                .env("KATA_TEST_MAIN_ATTACHMENT", &case.attachment)
                .env(
                    "KATA_TEST_INSTALLED_MAIN_DISCOVERY_LEASE",
                    case.root.path().join("discovery/lease.lock"),
                )
                // Installed-main startup deliberately rejects an ambient HOME
                // that diverges from the effective account's NSS home. Keep
                // test isolation in explicit config/data/lease paths rather
                // than forging the process authority root.
                .env(
                    "HOME",
                    kata_worker::owner_home::effective_owner_home()
                        .expect("resolve effective owner home for fault child"),
                )
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command
        }

        fn run_fault(case: &Case, fault: &str) -> Output {
            let output = child_command(case)
                .env("KATA_TEST_STARTUP_FAULT", fault)
                .env("KATA_TEST_INSTALLED_MAIN_EXPECT_FAILURE", "1")
                .output()
                .expect("run faulted installed main");
            assert!(
                !output.status.success(),
                "fault {fault} unexpectedly succeeded"
            );
            assert_eq!(
                output.status.code(),
                Some(73),
                "fault child must return the stable startup-failure code; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !case.attachment.exists(),
                "fault {fault} must fail before publishing installed-main readiness"
            );
            assert!(
                TcpStream::connect_timeout(&case.api, Duration::from_millis(100)).is_err(),
                "fault {fault} must leave no accepting API listener"
            );
            output
        }

        fn stop_ready_child(mut child: Child, case: &Case, graceful_stop: bool) -> Output {
            // This is a state poll, not a latency assertion. A debug installed
            // main can spend tens of seconds in SQLite fsyncs under a parallel
            // workspace build, so preserve the repository-wide 30s minimum and
            // give cold startup a generous diagnostic budget.
            //
            // The budget lives INSIDE the test, so no nextest `slow-timeout`
            // override can reach it. The fault matrix drives SEVEN real
            // debug-daemon boots inside a parallel suite of thousands of tests,
            // and a budget that is too tight fails exactly like a durability
            // regression rather than contention. Measured boot times:
            //
            //   full gate (load 60-96)     TIMEOUT 177.6s  FAIL
            //   standalone   (load 28)     FAIL     126.1s
            //   standalone   (IDLE, 3.6)   PASS      68.3s
            //
            // Note the middle row: reproducing it standalone is NOT the control,
            // because a busy host stays busy. Only the idle run distinguishes a
            // starved boot from a wedged one.
            //
            // A deadline set close to a single observed sample (177.6s) is not a
            // hang detector, it is a coin flip re-tossed on every gate: the load
            // that produced 177.6s is the NORMAL condition of the full suite, not
            // the worst case.
            //
            // 600s is chosen to be uninteresting rather than tuned: it is far
            // enough above every measured boot that no amount of contention
            // reaches it, matching the `recovery_100k` precedent that a cap sized
            // to survive suite contention is a symptom. What is LOST is bounded and
            // stated: a genuinely wedged daemon reports in ten minutes. Nothing
            // about the durability assertions changes — a daemon
            // that never listens still fails, which is the whole job of this bound.
            let deadline = Instant::now() + Duration::from_secs(600);
            loop {
                if case.attachment.is_file()
                    && TcpStream::connect_timeout(&case.api, Duration::from_millis(100)).is_ok()
                {
                    break;
                }
                if let Some(status) = child.try_wait().expect("poll installed main") {
                    let mut stdout = String::new();
                    let mut stderr = String::new();
                    if let Some(mut pipe) = child.stdout.take() {
                        let _ = pipe.read_to_string(&mut stdout);
                    }
                    if let Some(mut pipe) = child.stderr.take() {
                        let _ = pipe.read_to_string(&mut stderr);
                    }
                    panic!(
                        "installed main exited before readiness: {status}; stdout={stdout}; stderr={stderr}"
                    );
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let output = child
                        .wait_with_output()
                        .expect("collect timed-out installed-main output");
                    panic!(
                        "installed-main readiness timed out; stdout={} stderr={}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if !graceful_stop {
                child.kill().expect("SIGKILL ready installed main");
                return child
                    .wait_with_output()
                    .expect("collect SIGKILLed installed-main output");
            }
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(child.id()).expect("child pid fits i32")),
                nix::sys::signal::Signal::SIGTERM,
            )
            .expect("SIGTERM ready installed main");
            // Production shutdown has several sequential bounded phases whose
            // configured ceilings exceed 20 seconds before filesystem sync
            // cost. Keep this an eventual-state poll under the repository's
            // outer nextest hang bound, not a load-sensitive latency claim.
            let stop_deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if child.try_wait().expect("poll graceful stop").is_some() {
                    break;
                }
                if Instant::now() >= stop_deadline {
                    let _ = child.kill();
                    let output = child
                        .wait_with_output()
                        .expect("collect graceful-stop timeout output");
                    panic!(
                        "installed main did not stop within the graceful deadline; stdout={} stderr={}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            child
                .wait_with_output()
                .expect("collect installed-main output")
        }

        fn prove_retry_reaches_readiness(
            case: &Case,
            graceful_stop: bool,
            pause_after_readiness: bool,
        ) {
            let _ = std::fs::remove_file(&case.attachment);
            let mut command = child_command(case);
            if pause_after_readiness {
                // Deterministically signal after attachment/API readiness but
                // before the shutdown future is first polled. The pre-armed
                // self-pipe must retain that signal for the later select.
                command.env("KATA_TEST_POST_READY_SIGNAL_PAUSE_MS", "2000");
            }
            let child = command.spawn().expect("spawn repaired installed main");
            let output = stop_ready_child(child, case, graceful_stop);
            if graceful_stop {
                assert!(
                    output.status.success(),
                    "repaired startup did not stop cleanly: stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    !case.attachment.exists(),
                    "graceful stop must withdraw the attachment descriptor"
                );
            } else {
                assert!(
                    !output.status.success(),
                    "SIGKILLed recovery proof child unexpectedly exited successfully"
                );
                // Crash leaves diagnostic discovery stale by design; authority
                // still rests on the kernel-released data-dir lock. This path is
                // only used after readiness has already been observed.
                std::fs::remove_file(&case.attachment)
                    .expect("remove stale test attachment after SIGKILL");
            }
        }

        fn assert_no_durable_store_opened(case: &Case) {
            let databases = std::fs::read_dir(&case.data_dir)
                .expect("read data dir")
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| {
                    Path::new(name).extension() == Some(OsStr::new("db")) || name.contains(".db-")
                })
                .collect::<Vec<_>>();
            assert!(
                databases.is_empty(),
                "authority-boundary failure opened durable stores: {databases:?}"
            );
        }

        fn assert_only_clean_initial_store_set_exists(case: &Case) {
            let mut databases = std::fs::read_dir(&case.data_dir)
                .expect("read data dir")
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| Path::new(name).extension() == Some(OsStr::new("db")))
                .collect::<Vec<_>>();
            databases.sort();
            let mut expected = vec![
                "cas.db".to_string(),
                "idempotency.db".to_string(),
                "ledger_events.db".to_string(),
                "memory.db".to_string(),
                "operational.db".to_string(),
                "stage_cache.db".to_string(),
            ];
            expected.sort();
            assert_eq!(
                databases, expected,
                "pre-runtime metadata failure may leave only the identity-last clean initializer's fixed store set"
            );
        }

        // Cargo may replace a hashed test binary while sibling agent builds are
        // active. Keep one executable snapshot for every child in this matrix;
        // this is also closer to an installed service, whose executable identity
        // remains fixed for one boot/recovery proof.
        let harness_root = tempfile::tempdir().expect("stable harness tempdir");
        let harness_binary = harness_root
            .path()
            .join("kata-installed-main-fault-harness");
        std::fs::copy(
            std::env::current_exe().expect("current test binary"),
            &harness_binary,
        )
        .expect("snapshot installed-main test harness");

        // Unsupported advisory-lock semantics fail before identity or store
        // initialization. The unavoidable empty lock inode is diagnostic only.
        let unsupported = new_case("unsupported-lock", &harness_binary);
        let output = run_fault(&unsupported, "data_dir_lock.unsupported_lock_semantics");
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostic
                .contains("refusing to run an authoritative main on unsupported lock semantics")
                && diagnostic.contains("local filesystem with working flock(2) semantics"),
            "unsupported-lock diagnostic was not stable/actionable: {diagnostic}"
        );
        assert!(!unsupported.data_dir.join("main-identity.json").exists());
        assert_no_durable_store_opened(&unsupported);
        prove_retry_reaches_readiness(&unsupported, true, true);

        // ENOSPC is injected at the real lock-metadata write after the fixed store
        // set and immutable identity are durably published. Runtime boot has not
        // begun; the next start repairs diagnostics under the same identity and
        // reaches readiness.
        let enospc = new_case("enospc", &harness_binary);
        let output = run_fault(&enospc, "data_dir_lock.enospc.lock_metadata");
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostic.contains("no space left on device (ENOSPC)")
                && diagnostic.contains("free space on the filesystem")
                && diagnostic.contains("did not enter runtime boot or publish readiness"),
            "ENOSPC diagnostic was not stable/actionable: {diagnostic}"
        );
        let identity_before_retry =
            std::fs::read(enospc.data_dir.join("main-identity.json")).expect("retained identity");
        assert_only_clean_initial_store_set_exists(&enospc);
        prove_retry_reaches_readiness(&enospc, true, false);
        assert_eq!(
            std::fs::read(enospc.data_dir.join("main-identity.json")).unwrap(),
            identity_before_retry,
            "ENOSPC repair must retain the immutable directory identity"
        );

        // Build a healthy durable directory, then fail from inside BootRig's
        // lifecycle recovery phase. Logical lifecycle authority is unchanged,
        // no listener/attachment is published, and a clean retry is ready.
        let recovery = new_case("recovery", &harness_binary);
        prove_retry_reaches_readiness(&recovery, true, false);
        let identity_before_fault =
            std::fs::read(recovery.data_dir.join("main-identity.json")).unwrap();
        let program_store = kata_workflow::execution_lifecycle::ExecutionLifecycleFace::open(
            recovery.data_dir.join("operational.db"),
        )
        .expect("inspect lifecycle authority before fault");
        let running_id = ulid::Ulid::new();
        let running_program = kata_program::execution_program::compile_starlark_execution_program(
            r#"one = stage(id = "one", agent = "shell", prompt = "printf ready")
workflow("startup-recovery-running", root = one)
"#,
            "startup-recovery-running.star",
            &[],
        )
        .expect("compile recoverable Running program");
        program_store
            .put_current_program(running_id, &running_program)
            .expect("seed durable Running lifecycle");
        let lifecycle_before = program_store.lifecycle_execution_ids().unwrap();
        assert_eq!(
            program_store.lifecycle(running_id).unwrap().unwrap().state,
            kata_workflow::execution_program_store::ExecutionLifecycleState::Running
        );
        drop(program_store);
        let output = run_fault(&recovery, "installed_main.recovery.scan_failure");
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostic.contains("required installed-main recovery failed before readiness")
                && diagnostic.contains("repair access to operational.db")
                && diagnostic.contains("no lifecycle outcome was inferred"),
            "recovery diagnostic was not stable/actionable: {diagnostic}"
        );
        assert_eq!(
            std::fs::read(recovery.data_dir.join("main-identity.json")).unwrap(),
            identity_before_fault
        );
        let program_store = kata_workflow::execution_lifecycle::ExecutionLifecycleFace::open(
            recovery.data_dir.join("operational.db"),
        )
        .expect("inspect lifecycle authority after fault");
        assert_eq!(
            program_store.lifecycle_execution_ids().unwrap(),
            lifecycle_before,
            "recovery failure must not invent a terminal lifecycle or delete authority"
        );
        assert_eq!(
            program_store.lifecycle(running_id).unwrap().unwrap().state,
            kata_workflow::execution_program_store::ExecutionLifecycleState::Running,
            "a failed recovery scan must never infer completion from absence of assignment rows"
        );
        drop(program_store);
        // The seeded run intentionally has no worker and remains Running; after
        // proving the clean retry published readiness, use a hard stop so this
        // fault test does not wait for an unrelated dispatch deadline/drain.
        prove_retry_reaches_readiness(&recovery, false, false);
    }

    /// ADR-0001's installed containment policy is only real if BOOTING a node
    /// installs it. `BootRig::boot` is the one funnel every node start passes
    /// through, so this asserts the config value crosses that funnel into the
    /// process cell the workflow compiler reads.
    ///
    /// It observes the cell BEFORE and AFTER the boot, so it cannot pass on a
    /// value that was already there: the pre-boot read must be the OFF default
    /// and the post-boot read must be the config's ON value. Deleting the
    /// `install_node_containment_policy` line in `BootRig::boot` turns this RED.
    #[test]
    fn boot_installs_the_nodes_containment_policy() {
        start_runtime(async move {
            let before = kata_types::containment_policy::installed_node_containment_policy();
            assert!(
                !before.require_contained_model_stages,
                "a process that has not booted a node observes the ADR-0001 conservative \
                     default; this test's post-boot assertion is meaningless otherwise"
            );

            let (_root, _rig) = boot_durable_recovery_test_rig_with(|cfg| {
                cfg.containment.require_contained_model_stages = true;
            })
            .await;

            assert!(
                kata_types::containment_policy::installed_node_containment_policy()
                    .require_contained_model_stages,
                "BootRig::boot must install the node's [containment] policy — without it the \
                     kata.toml key is decorative and the compiler never sees it"
            );
            kata_types::containment_policy::install_node_containment_policy(before);
        });
    }

    /// `BootRig::boot` installs the operator's `[runtime] model_reuse_max_age_secs` on
    /// the stage-cache store every runner is handed — the one link between the key and
    /// the consult that applies it. The consult's verdicts are
    /// pinned against raw SQLite in `kata-workflow`'s `model_reuse_oci`; this cell pins
    /// only that the node's value, not the default, reaches the store. Two nodes are
    /// booted, one carrying a bound no constant plausibly equals and one carrying
    /// `"unbounded"`, so no single value boot could hard-code passes both.
    ///
    /// **Watched red:** with `.with_model_reuse_max_age(..)` removed from boot's store
    /// open, the store carries `ModelReuseMaxAge::Default`; with boot hard-coding
    /// `ModelReuseMaxAge::Unbounded`, the `Secs(12_345)` node reads back `Unbounded`.
    #[test]
    fn boot_installs_the_nodes_memoised_spend_bound_on_the_stage_cache() {
        use kata_types::config::ModelReuseMaxAge;

        start_runtime(async move {
            for bound in [ModelReuseMaxAge::Secs(12_345), ModelReuseMaxAge::Unbounded] {
                let (_root, rig) = boot_durable_recovery_test_rig_with(|cfg| {
                    cfg.runtime.model_reuse_max_age_secs = bound;
                })
                .await;
                assert_eq!(
                    rig.open_stage_cache().unwrap().model_reuse_max_age(),
                    bound,
                    "the node's bound, not the default, reaches the store runners consult"
                );
            }
        });
    }

    /// **AN ORPHAN TARGET PIN IS SWEPT AT BOOT.** A target is resolved and pinned
    /// (`refs/kata/targets/<id>/…`) BEFORE its admission commits, so a refusal or a
    /// crash in between leaves a pin no admitted execution owns. Boot deletes every
    /// such pin before it serves. Planted with git before boot and read back with
    /// `git for-each-ref` after it — never through kata's own answer.
    #[test]
    fn boot_sweeps_a_target_pin_no_admitted_execution_owns() {
        start_runtime(async move {
            let orphan = ulid::Ulid::new();
            let mut planted_in = None;
            let (_root, _rig) = boot_durable_recovery_test_rig_with(|cfg| {
                let repo = cfg.vcs.jj_repo.clone();
                kata_test_utils::git::run_git(
                    &repo,
                    &[
                        "update-ref",
                        &format!("refs/kata/targets/{orphan}/head"),
                        "HEAD",
                    ],
                );
                planted_in = Some(repo);
            })
            .await;
            let repo = planted_in.expect("the pin was planted before boot");
            let listed = kata_test_utils::git::hermetic_git_in(&repo)
                .args(["for-each-ref", "--format=%(refname)", "refs/kata/targets/"])
                .output()
                .expect("git for-each-ref runs");
            assert!(listed.status.success(), "{listed:?}");
            assert_eq!(
                String::from_utf8_lossy(&listed.stdout).trim(),
                "",
                "boot swept the orphan pin of {orphan}"
            );
        });
    }

    /// The isolated shell pack the schedule-target cells install: ONE shell
    /// stage on an isolated `/work`.
    const ISOLATED_SCHEDULED_PACK: &str = "only = stage(id = \"only\", run = \"true\", \
         agent = \"shell\")\n\
         workflow(\"scheduled-isolated\", root = only, worktree_isolated = True)\n";

    /// Install `ISOLATED_SCHEDULED_PACK` as schedule `nightly` (every second,
    /// cursor at 1 000) on `rig`, returning the face.
    fn install_isolated_schedule(rig: &BootRig) -> kata_workflow::schedule::ScheduleFace {
        use kata_program::schedule::ScheduleSpec;
        use kata_program::schedule::ScheduleTrigger;
        use kata_workflow::schedule::ScheduleFace;

        let face = ScheduleFace::new(Arc::clone(rig.execution_lifecycle.db()));
        let program = kata_program::execution_program::compile_starlark_execution_program(
            ISOLATED_SCHEDULED_PACK,
            "scheduled-isolated.star",
            &[],
        )
        .expect("compile the isolated pinned target");
        face.install(
            &ScheduleSpec {
                id: "nightly".to_string(),
                submit_pack: "scheduled-isolated".to_string(),
                trigger: ScheduleTrigger::Interval { every_ms: 1_000 },
                on_missed: kata_program::schedule::MissedPolicy::FireOnceOnBoot,
                params: serde_json::Map::new(),
            },
            &program,
            0,
        )
        .expect("an isolated program's schedule installs: its pin carries no target");
        face
    }

    /// The due occurrence of schedule `nightly` the sweep would hand the
    /// engine's submit callback.
    fn due_fire(
        face: &kata_workflow::schedule::ScheduleFace,
    ) -> kata_workflow::schedule::ScheduleFire {
        let record = face.get("nightly").unwrap().expect("installed");
        kata_workflow::schedule::ScheduleFire {
            fire_instant: record.next_fire_ms,
            next_cursor_ms: record.next_fire_ms + 1_000,
            record,
        }
    }

    /// A SCHEDULE FIRE OF AN ISOLATED PROGRAM ADMITS THE PIN PLUS THAT FIRE'S
    /// TARGET. A schedule's target is resolved at every fire, never pinned: the
    /// pin installs with none, and the execution the production fire callback
    /// (`fire_pinned_schedule`) admits durably carries the trunk target THAT
    /// fire resolved — read raw out of `invocations` against `git rev-parse
    /// main` — linked to the instant's firing row.
    #[test]
    fn a_schedule_fire_of_an_isolated_program_admits_the_pin_plus_its_fired_target() {
        start_runtime(async move {
            let (_root, rig) = boot_durable_recovery_test_rig().await;
            let executor = rig
                .build_workflow_executor()
                .expect("build the workflow executor");
            let face = install_isolated_schedule(&rig);
            let (home, worker) = kata_transport::InProcessTransport::pair(64);
            let home: Arc<dyn kata_transport::transport::WorkerTransport> = Arc::new(home);
            register_test_double(
                &rig,
                smol_str::SmolStr::new("schedule-fire"),
                home,
                vec!["agent:shell".to_string()],
                kata_workflow::test_harness::rig_worker_containment(),
                rig.execution_lifecycle
                    .db()
                    .enroll_worker_domain(&rig.source_main_identity, rig.local_membrane)
                    .unwrap(),
            );
            let cas = kata_core::store::cas::CasStore::open(
                rig.cfg.node.data_dir.join("cas.db"),
                rig.cfg.node.data_dir.join("cas"),
            )
            .expect("the rig's content store re-opens");
            let (_scripted, _pump) = kata_workflow::test_harness::OciNodeRig::scripted_worker_on(
                std::sync::Arc::new(worker),
                std::sync::Arc::clone(rig.execution_lifecycle.db()),
                cas,
                kata_test_utils::MockAgentBackend::new(),
                std::sync::Arc::new(tempfile::tempdir().expect("worker node dir")),
            );
            let main = String::from_utf8(
                kata_test_utils::git::hermetic_git_in(&rig.cfg.vcs.jj_repo)
                    .args(["rev-parse", "refs/heads/main"])
                    .output()
                    .expect("git rev-parse runs")
                    .stdout,
            )
            .unwrap()
            .trim()
            .to_owned();

            let fire = due_fire(&face);
            let report = fire_pinned_schedule(&executor, &face, &fire).expect("the fire runs");
            assert_eq!(report, kata_workflow::schedule::FireReport::Submitted);

            let firings = face.firings("nightly").expect("read firings");
            assert_eq!(firings.len(), 1);
            let execution = firings[0].execution_id().expect("the fire submitted");
            let conn = rusqlite::Connection::open_with_flags(
                rig.cfg.node.data_dir.join("operational.db"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .expect("a second read-only handle");
            let stored: Vec<u8> = conn
                .query_row(
                    "SELECT invocation_json FROM invocations WHERE execution_id = ?1",
                    [execution.to_bytes().as_slice()],
                    |row| row.get(0),
                )
                .expect("the fired execution's invocation row");
            let stored_bytes = stored.clone();
            let stored: serde_json::Value = serde_json::from_slice(&stored).unwrap();
            assert_eq!(
                stored["target"]["head"]["commit"],
                serde_json::json!(main),
                "the fired execution froze trunk as git names it at the fire: {stored}"
            );
            // The bytes the operational plane spliced are the bytes the typed
            // chokepoint derives for the pin plus that target.
            let (program, pinned) = face.revalidated_pin("nightly").unwrap().unwrap();
            let target: kata_types::target::ExecutionTarget =
                serde_json::from_value(stored["target"].clone()).unwrap();
            let derived = kata_workflow::admission::checked_admission(
                &program,
                &pinned.with_target(Some(target)),
            )
            .expect("the pin plus the fired target admits");
            assert_eq!(derived.invocation_json(), stored_bytes.as_slice());
            let pinned: Vec<u8> = conn
                .query_row(
                    "SELECT invocation_json FROM schedules WHERE schedule_id = 'nightly'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let pinned: serde_json::Value = serde_json::from_slice(&pinned).unwrap();
            assert!(
                pinned.get("target").is_none(),
                "the pin carries no target: {pinned}"
            );
        });
    }

    /// A SCHEDULE FIRE WHOSE TARGET IS REFUSED IS RECORDED, NEVER RETRIED
    /// SILENTLY. The repository holds two branches and names no trunk, so the
    /// fire's trunk target cannot resolve. Each due instant handed to the
    /// production fire callback is recorded as ONE refused firing — no
    /// execution, the refusal text kept — and the cursor moves past it, read raw
    /// through a second read-only handle; nothing is admitted.
    #[test]
    fn a_schedule_fire_whose_target_is_refused_records_one_refused_firing_per_instant() {
        start_runtime(async move {
            let (_root, rig) = boot_durable_recovery_test_rig_with(|cfg| {
                kata_test_utils::git::run_git(&cfg.vcs.jj_repo, &["branch", "dev"]);
            })
            .await;
            let executor = rig
                .build_workflow_executor()
                .expect("build the workflow executor");
            let face = install_isolated_schedule(&rig);

            for _ in 0..2 {
                let fire = due_fire(&face);
                let report = fire_pinned_schedule(&executor, &face, &fire)
                    .expect("a refused target is an answer, not a failed fire");
                assert_eq!(report, kata_workflow::schedule::FireReport::Refused);
            }

            let conn = rusqlite::Connection::open_with_flags(
                rig.cfg.node.data_dir.join("operational.db"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .expect("a second read-only handle");
            let mut rows = conn
                .prepare(
                    "SELECT fire_instant, execution_id IS NULL, refusal FROM schedule_firings \
                     WHERE schedule_id = 'nightly' ORDER BY fire_instant",
                )
                .unwrap();
            let rows: Vec<(i64, bool, String)> = rows
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(
                rows.iter()
                    .map(|(instant, no_execution, _)| (*instant, *no_execution))
                    .collect::<Vec<_>>(),
                [(1_000, true), (2_000, true)],
                "one refused firing per due instant, and no execution: {rows:?}"
            );
            for (_, _, refusal) in &rows {
                assert!(
                    refusal.contains("cannot tell which branch is this repository's trunk"),
                    "the trunk resolver's refusal is recorded: {refusal}"
                );
            }
            let cursor: i64 = conn
                .query_row(
                    "SELECT cursor_ms FROM schedules WHERE schedule_id = 'nightly'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(cursor, 3_000, "the cursor moved past both refused instants");
            let programs: i64 = conn
                .query_row("SELECT count(*) FROM programs", [], |row| row.get(0))
                .unwrap();
            assert_eq!(programs, 0, "nothing was admitted");
        });
    }

    /// `BootRig::boot` installs THIS BUILD's executor term on the stage-cache
    /// store every runner is handed — the one link between the derivation and the
    /// capsule reuse consult that folds it. A store without one serves no hint, so a
    /// boot that dropped the install would silently turn the content cache off; one
    /// that installed some other term would key every node alike.
    ///
    /// **Watched red:** with `.with_executor_term(..)` removed from boot's store open,
    /// the store carries `None`.
    #[test]
    fn boot_installs_this_builds_executor_term_on_the_stage_cache() {
        start_runtime(async move {
            let (_root, rig) = boot_durable_recovery_test_rig().await;
            assert_eq!(
                rig.open_stage_cache().unwrap().executor_term(),
                Some(&kata_worker::executor_term::node_executor_term().unwrap()),
                "the build's executor term reaches the store runners consult"
            );
        });
    }

    #[test]
    fn installed_main_recovery_protects_current_authority_and_ignores_prototype_rows() {
        use kata_workflow::execution_program_store::ExecutionInvocation;

        start_runtime(async move {
            let (_root, rig) = boot_durable_recovery_test_rig().await;

            let protected_execution = ulid::Ulid::new();
            let _legacy_execution = ulid::Ulid::new();
            let program = kata_program::execution_program::compile_starlark_execution_program(
                // `agent = "shell"`, like the other fixtures on this rig, and
                // now deliberately rather than incidentally: this rig BOOTS a
                // node, so it installs the default containment policy, and a
                // model stage with no sandbox would be refused at compile.
                // Shell is the honest choice here — what this test is about
                // is lifecycle authority over an in-flight attempt, which is
                // executor-agnostic.
                r#"one = stage(id = "one", agent = "shell", prompt = "already decided")
workflow("boot-protected", root = one)
"#,
                "boot-protected.star",
                &[],
            )
            .expect("compile protected program");
            rig.execution_lifecycle
                .admit_current_execution(
                    protected_execution,
                    &program,
                    &ExecutionInvocation::workflow(Vec::new()),
                )
                .expect("admit lifecycle-owned execution");
            rig.execution_lifecycle
                .mark_running_after_admission(protected_execution)
                .expect("authorize lifecycle-owned execution");

            // The current-authority in-flight row is a DISPATCHED
            // CAPSULE ATTEMPT in the lifecycle `attempts` table — settled
            // PROVEN AMBIGUOUS at restart (capsule re-delivery is not
            // implemented), and folded into the execution's terminal by the
            // resumed runner.
            let _protected_attempt = kata_workflow::test_harness::seed_dispatched_capsule_attempt(
                rig.execution_lifecycle.db(),
                rig.stage_cache.cas(),
                protected_execution,
                program.program_hash,
                "one",
                "crashed-worker",
                None,
            );

            let executor = WorkflowExecutor::new(
                Arc::clone(&rig.dispatcher),
                Arc::clone(&rig.supervisor),
                Arc::new(WorkflowLibrary::new(vec![])),
            )
            .with_execution_lifecycle(rig.execution_lifecycle.clone());
            let report = rig
                .resume_or_orphan_in_flight_runs(&executor)
                .expect("run the production BootRig recovery sequence");

            assert_eq!(report.resumed, 1);
            assert_eq!(report.terminalized, 0);
            assert_eq!(
                report.orphaned, 0,
                "prototype rows are not admitted execution authority"
            );
            assert_eq!(report.errors, 0);
            assert!(rig.dispatcher.startup_recovery_dispatch_is_open());

            // Recovery returns with the protected execution OWNED BY ITS RESUMED
            // RUNNER, already activated on this multi-thread runtime by the fence
            // release: from here its lifecycle row may read running, terminalizing
            // or settled at any instant, so the state at return pins nothing. What
            // recovery guarantees is WHO settles it — the runner, from the restart
            // settlement, never boot's orphan pass. Await that runner (the bound is
            // a hang detector) and read the settlement raw.
            let (_, joined) = executor
                .drain_in_flight_workflow_tasks(Duration::from_secs(60))
                .await;
            assert!(joined, "the resumed runner must finish");
            let (state, reason): (String, Option<Vec<u8>>) = rusqlite::Connection::open_with_flags(
                rig.cfg.node.data_dir.join("operational.db"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .expect("a second read-only handle")
            .query_row(
                "SELECT state, terminal_reason_json FROM execution_lifecycle \
                 WHERE execution_id = ?1",
                [protected_execution.to_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("the protected lifecycle row remains");
            let reason = String::from_utf8(reason.unwrap_or_default()).expect("a JSON reason");
            assert_eq!(state, "failed", "the resumed runner settles it: {reason}");
            assert!(
                reason.contains("the main restarted. PROVEN AMBIGUOUS")
                    && !reason.contains("no durable checked program"),
                "the resumed runner settles the execution from the restart \
                 settlement, and boot's orphan pass never touches it: {reason}"
            );
            assert!(
                // a hang detector, not an acceptance bound: the tasks must
                // stop, but asserting they stop inside wall time is a flake
                // source under suite load — measured 13.8s under gate load
                // against 0.2s standalone
                rig.stop_background_tasks(Duration::from_secs(30)).await,
                "boot background tasks should stop cleanly"
            );
            Ok::<(), anyhow::Error>(())
        })
        .expect("installed-main recovery proof runtime");
    }

    /// The boot pass must settle an abandoned attempt on the AUTHORITY CHAIN —
    /// an attempt left non-terminal for an execution whose lifecycle has
    /// already settled must not survive recovery as live work.
    ///
    /// `recoverable_ids` selects `admitting`/`running`/`terminalizing`, so an
    /// execution whose lifecycle has SETTLED is not a recovery candidate and
    /// its attempt is unprotected. Since the capsule settlement legs moved into
    /// `prepare_in_flight_recovery`, that attempt is owned by
    /// `Dispatcher::settle_capsule_attempts_after_restart`, which runs before the
    /// candidate census: a claim no dispatch ever reached is recorded `failed`
    /// PROVEN NOT PERFORMED on the chain, so the orphan pass that follows
    /// legitimately counts nothing for it.
    #[test]
    fn installed_main_boot_orphan_reaches_the_authority_chain() {
        use kata_workflow::execution_program_store::{
            ExecutionInvocation, ExecutionLifecycleState, ExecutionTerminalReason,
        };

        start_runtime(async move {
            let (_root, rig) = boot_durable_recovery_test_rig().await;

            let settled_execution = ulid::Ulid::new();
            let program = kata_program::execution_program::compile_starlark_execution_program(
                // `agent = "shell"` — see the note on the `boot-protected`
                // fixture above; orphan folding is executor-agnostic.
                r#"one = stage(id = "one", agent = "shell", prompt = "left in flight")
workflow("boot-chain-orphan", root = one)
"#,
                "boot-chain-orphan.star",
                &[],
            )
            .expect("compile settled program");
            rig.execution_lifecycle
                .admit_current_execution(
                    settled_execution,
                    &program,
                    &ExecutionInvocation::workflow(Vec::new()),
                )
                .expect("admit lifecycle-owned execution");
            rig.execution_lifecycle
                .mark_running_after_admission(settled_execution)
                .expect("authorize lifecycle-owned execution");

            // Through the production claim door, so the assertions below
            // observe a real attempt row rather than a hand-built one.
            let (assignment_id, frame_json) =
                kata_workflow::test_harness::seed_claimed_capsule_attempt(
                    rig.execution_lifecycle.db(),
                    rig.stage_cache.cas(),
                    settled_execution,
                    program.program_hash,
                    "one",
                );
            let _ = frame_json;

            // The execution's lifecycle settles while its assignment does not.
            rig.execution_lifecycle
                .begin_terminalization(
                    settled_execution,
                    ExecutionLifecycleState::Completed,
                    &ExecutionTerminalReason::new("completed", "execution closed out"),
                )
                .expect("latch terminal intent");
            rig.execution_lifecycle
                .complete_cleanup(settled_execution)
                .expect("discharge absent-workspace cleanup");
            rig.execution_lifecycle
                .finish_terminalization(settled_execution)
                .expect("publish the terminal outcome");

            // NON-VACUITY, asserted BEFORE the behavior under test: the chain
            // really holds this attempt and it is not already terminal, so a
            // pass below cannot come from a fixture the chain never saw.
            assert_eq!(
                rig.execution_lifecycle
                    .db()
                    .attempt_state(assignment_id)
                    .expect("read chain attempt state"),
                Some("pending".to_string()),
                "PRECONDITION: the chain holds this attempt, non-terminal"
            );

            let executor = WorkflowExecutor::new(
                Arc::clone(&rig.dispatcher),
                Arc::clone(&rig.supervisor),
                Arc::new(WorkflowLibrary::new(vec![])),
            )
            .with_execution_lifecycle(rig.execution_lifecycle.clone());
            let report = rig
                .resume_or_orphan_in_flight_runs(&executor)
                .expect("run the production BootRig recovery sequence");
            assert_eq!(
                report.orphaned, 0,
                "the capsule settlement leg owns this attempt; the orphan pass \
                     has no victim left to count"
            );

            assert_eq!(
                rig.execution_lifecycle
                    .db()
                    .attempt_state(assignment_id)
                    .expect("read chain attempt state"),
                Some("failed".to_string()),
                "the abandoned claim must reach a terminal state on the AUTHORITY \
                     chain — `failed` PROVEN NOT PERFORMED — not stay live for work \
                     boot already resolved"
            );
            assert!(
                // a hang detector, not an acceptance bound: the tasks must
                // stop, but asserting they stop inside wall time is a flake
                // source under suite load — measured 13.8s under gate load
                // against 0.2s standalone
                rig.stop_background_tasks(Duration::from_secs(30)).await,
                "boot background tasks should stop cleanly"
            );
            Ok::<(), anyhow::Error>(())
        })
        .expect("boot chain-orphan proof runtime");
    }

    /// A `Completed` closeout may not open readiness on an
    /// authority chain that holds NO stage for the execution.
    ///
    /// # The shape
    ///
    /// The fixture is a terminal intent latched over an EMPTY chain: admitted,
    /// running, `begin_terminalization` — and not one stage admitted under it.
    /// Clean-format product boot does not create or import this state, but
    /// recovery must still fail closed if a damaged current store presents it.
    /// The chain answers EMPTY for an execution that really does have a live
    /// non-terminal stage.
    ///
    /// A closeout that read that empty answer as "every stage is terminal"
    /// would REPORT SUCCESS (`terminalized: 1`), leaving live work beside a
    /// `Completed` execution with nothing able to notice. The refusal fires on
    /// the ABSENCE itself.
    #[test]
    fn installed_main_recovery_refuses_terminal_closeout_with_non_terminal_assignment() {
        use kata_workflow::execution_program_store::{
            ExecutionInvocation, ExecutionLifecycleState, ExecutionTerminalReason,
        };

        start_runtime(async move {
            let (_root, rig) = boot_durable_recovery_test_rig().await;
            let execution_id = ulid::Ulid::new();
            let program = kata_program::execution_program::compile_starlark_execution_program(
                // `agent = "shell"` — see the note on the `boot-protected`
                // fixture above; the terminal/assignment contradiction this
                // test pins is executor-agnostic.
                r#"one = stage(id = "one", agent = "shell", prompt = "contradictory closeout")
workflow("boot-terminal-contradiction", root = one)
"#,
                "boot-terminal-contradiction.star",
                &[],
            )
            .expect("compile contradictory closeout program");
            rig.execution_lifecycle
                .admit_current_execution(
                    execution_id,
                    &program,
                    &ExecutionInvocation::workflow(Vec::new()),
                )
                .expect("admit lifecycle-owned execution");
            rig.execution_lifecycle
                .mark_running_after_admission(execution_id)
                .expect("authorize lifecycle-owned execution");
            rig.execution_lifecycle
                .begin_terminalization(
                    execution_id,
                    ExecutionLifecycleState::Completed,
                    &ExecutionTerminalReason::new(
                        "completed",
                        "terminal intent conflicts with live stage authority",
                    ),
                )
                .expect("latch terminal intent");
            // NON-VACUITY, asserted BEFORE the behavior under test: the chain
            // must hold NO stage here — this test's whole subject is the empty
            // answer being read as 'every stage is terminal'.
            assert!(
                rig.dispatcher
                    .execution_stage_states(execution_id)
                    .expect("the nucleus holds this execution, so the chain read succeeds")
                    .is_empty(),
                "the chain must hold NO stage here"
            );

            let executor = WorkflowExecutor::new(
                Arc::clone(&rig.dispatcher),
                Arc::clone(&rig.supervisor),
                Arc::new(WorkflowLibrary::new(vec![])),
            )
            .with_execution_lifecycle(rig.execution_lifecycle.clone());
            let error = rig
                .resume_or_orphan_in_flight_runs(&executor)
                .expect_err("contradictory terminal closeout must refuse readiness");
            let message = format!("{error:#}");
            assert!(
                message.contains("holds NO stage for it")
                    && message.contains("an absent stage history is not a terminal one")
                    && message.contains(&execution_id.to_string()),
                "unexpected contradiction diagnostic: {message}"
            );
            assert_eq!(
                rig.execution_lifecycle
                    .lifecycle(execution_id)
                    .expect("read retained lifecycle")
                    .expect("lifecycle remains")
                    .state,
                ExecutionLifecycleState::Terminalizing
            );
            assert!(
                !rig.dispatcher.startup_recovery_dispatch_is_open(),
                "failed closeout must retain the startup fence"
            );
            assert!(
                // a hang detector, not an acceptance bound: the tasks must
                // stop, but asserting they stop inside wall time is a flake
                // source under suite load — measured 13.8s under gate load
                // against 0.2s standalone
                rig.stop_background_tasks(Duration::from_secs(30)).await,
                "boot background tasks should stop cleanly"
            );
            Ok::<(), anyhow::Error>(())
        })
        .expect("installed-main contradiction proof runtime");
    }

    #[test]
    fn a_restart_missing_an_authoritative_engine_file_refuses_without_recreating_it() {
        let root = tempfile::tempdir().unwrap();
        drop(
            crate::data_dir_lock::DataDirLock::acquire(
                root.path(),
                crate::data_dir_lock::MainMode::Installed,
                None,
            )
            .unwrap(),
        );
        // The SURVIVING sibling whose bytes must not be touched by the refusal.
        let survivor = root.path().join("ledger_events.db");
        let before = std::fs::read(&survivor).unwrap();
        std::fs::remove_file(root.path().join("operational.db")).unwrap();

        let error = preflight_clean_engine_stores(root.path())
            .expect_err("a partial store set must not be interpreted as a fresh engine");
        let message = format!("{error:#}");
        assert!(message.contains("operational.db"), "{message}");
        assert_eq!(std::fs::read(&survivor).unwrap(), before);
        assert!(!root.path().join("operational.db").exists());
        assert!(root.path().join("ledger_events.db").exists());
    }

    /// A booted data directory holds only entries the durable-asset map classifies,
    /// proven by BOOTING rather than by grepping: this drives the real
    /// `BootRig::boot` — the same call `kata serve`, the workflow runner, and the MCP
    /// engine make — against a fresh data directory and reads back what the boot
    /// actually put on disk. A store a boot creates without a map row fails here,
    /// whatever its name.
    #[test]
    fn a_booted_data_dir_holds_only_entries_the_asset_map_classifies() {
        start_runtime(async move {
            let (root, rig) = boot_durable_recovery_test_rig().await;
            let data_dir = root.path().join("data");
            // Exercise the stage-cache open too: it is the `SqliteWorkflowStore`
            // user, and its co-located `cas.db` must appear.
            let _stage_cache = rig.open_stage_cache().expect("open stage cache");

            let observed: Vec<String> = std::fs::read_dir(&data_dir)
                .expect("read booted data dir")
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();

            let unclassified: Vec<&String> = observed
                .iter()
                .filter(|name| kata_core::durable_assets::classify_data_dir_entry(name).is_none())
                .collect();
            assert!(
                unclassified.is_empty(),
                "a live boot created entries the durable-asset map does not classify: \
                     {unclassified:?} (observed: {observed:?})"
            );
            // Non-vacuity: the same listing must still show the planes the
            // boot really owns, or the assertion above would pass on an empty
            // directory.
            for live in [
                "ledger_events.db",
                "operational.db",
                "stage_cache.db",
                "cas.db",
            ] {
                assert!(
                    observed.iter().any(|name| name == live),
                    "the fixture did not actually boot: `{live}` is missing from \
                         {observed:?}"
                );
            }
        });
    }

    #[test]
    fn boot_blocks_incompatible_program_in_between_stages_window() {
        let store = ExecutionLifecycleFace::in_memory().expect("program store");
        let execution_id = ulid::Ulid::new();
        let terminal_history = ulid::Ulid::new();
        let legacy = br#"{"schema_version":1,"workflow_name":"between-stages","stages":{"predecessor":{},"successor":{}},"edges":[{"from":"predecessor","to":"successor"}]}"#;
        store
            .put_raw_active_program_json(terminal_history, legacy)
            .expect("seed terminal historical program");
        store
            .mark_terminal(
                terminal_history,
                kata_workflow::execution_program_store::ExecutionLifecycleState::Completed,
            )
            .expect("terminalize historical program");
        store
            .put_raw_active_program_json(execution_id, legacy)
            .expect("seed legacy checked program");

        let error = refuse_incompatible_execution_programs_at_boot(&store)
            .expect_err("assignment-free successor window must still block startup");
        let message = format!("{error:#}");
        assert!(
            message.contains(&execution_id.to_string()),
            "error={message}"
        );
        assert!(
            !message.contains(&terminal_history.to_string()),
            "error={message}"
        );
        assert!(
            message.contains("unsupported checked-program schema 1"),
            "error={message}"
        );
        assert!(
            message.contains("undispatched successor"),
            "error={message}"
        );
        assert_eq!(
            store.program_json(execution_id).unwrap().unwrap(),
            br#"{"schema_version":1,"workflow_name":"between-stages","stages":{"predecessor":{},"successor":{}},"edges":[{"from":"predecessor","to":"successor"}]}"#,
            "boot refusal must retain the exact evidence bytes"
        );
    }

    /// A checked program a DIFFERENT binary would have persisted: an
    /// `exec = "host"` sandbox that still declares `workspace-ro`, carrying the
    /// class the PRODUCTION derivation computes for that declaration. The derivation
    /// keys containment on the exec brand, so the tuple is `HostUnconfined + ReadOnly`,
    /// which today's closed-world matrix refuses at R6 (`HostUnconfined` admits only
    /// workspace `None` or `MutableCandidate`) — an unenforced read-only label is a
    /// lie. Both hashes are re-stamped, so the fixture is exactly as
    /// self-consistent as that binary's own output and every OTHER guard (schema,
    /// `program_hash` binding, contract-hash drift) passes it. Nothing here is
    /// hand-authored: the tuple's provenance is `derive_execution_class` itself.
    fn program_carrying_an_unhonourable_execution_class()
    -> kata_program::execution_program::ExecutionProgram {
        use kata_program::execution_program::{derive_execution_class, rederive_program_hash};

        let mut program = kata_program::execution_program::compile_starlark_execution_program(
            "only = stage(id = \"only\", agent = \"shell\", run = \"true\", sandbox = \"ro\")\n\
             workflow(\"unhonourable\", root = [only], sandbox_profiles = {\n\
                \"ro\": sandbox_profile(net = \"offline\"),\n\
             })\n",
            "unhonourable.star",
            &[],
        )
        .expect("the confined form of the pack compiles");
        program
            .sandbox_profiles
            .get_mut("ro")
            .expect("the pack declares the profile")
            .exec = kata_types::sandbox::ExecBackend::Host;
        let stage_id = program.stages.keys().next().expect("one stage").clone();
        let derived = derive_execution_class(&program.stages[&stage_id], &program.sandbox_profiles)
            .expect("a compiled process stage always carries a sandbox");
        assert!(
            derived.validate().is_err(),
            "the fixture is only interesting because THIS derivation is refused today"
        );
        let stage = program.stages.get_mut(&stage_id).expect("one stage");
        stage.execution_class = derived.class;
        stage.restamp_contract_hash_for_tests();
        program.program_hash = rederive_program_hash(&program);
        program
    }

    /// Boot side. A durable program whose CARRIED seven-axis tuple this
    /// binary cannot honour is a COMPATIBILITY finding, and the membrane at
    /// `BootRig::boot` must name it as one.
    ///
    /// # The defect
    ///
    /// A membrane that classified a stored program by SCHEMA VERSION alone would
    /// pass this program, and the refusal would surface later from inside
    /// lifecycle recovery — wrapped in advice to repair or RESTORE
    /// `operational.db`. The bytes are intact and
    /// readable; a restore returns the same bytes, and an older snapshot of the
    /// lifecycle authority discards durable transitions that were fine.
    #[test]
    fn boot_blocks_a_durable_program_this_binary_cannot_honour() {
        let store = ExecutionLifecycleFace::in_memory().expect("program store");
        let unhonourable = ulid::Ulid::new();
        let honourable = ulid::Ulid::new();
        let forged = program_carrying_an_unhonourable_execution_class();

        // Non-vacuity: an honourable program is admitted into the SAME store, so a
        // membrane that blocked every program would fail here rather than pass.
        store
            .put_raw_active_program_json(
                honourable,
                &serde_json::to_vec(
                    &kata_program::execution_program::compile_starlark_execution_program(
                        "one = stage(id = \"one\", prompt = \"ok\", agent = \"shell\")\n\
                         workflow(\"honourable\", root = one)\n",
                        "honourable.star",
                        &[],
                    )
                    .expect("compile the honourable program"),
                )
                .expect("serialize"),
            )
            .expect("seed an honourable checked program");
        refuse_incompatible_execution_programs_at_boot(&store)
            .expect("PRECONDITION: an honourable program does not block startup");

        store
            .put_raw_active_program_json(
                unhonourable,
                &serde_json::to_vec(&forged).expect("serialize"),
            )
            .expect("seed the unhonourable checked program");
        let error = refuse_incompatible_execution_programs_at_boot(&store)
            .expect_err("a program this binary cannot honour must block startup");
        let message = format!("{error:#}");
        assert!(
            message.contains(&unhonourable.to_string()),
            "the refusal must name the execution: {message}"
        );
        assert!(
            !message.contains(&honourable.to_string()),
            "and must not sweep in the honourable one: {message}"
        );
        assert!(
            message.contains("invalid checked execution class") && message.contains("[R6]"),
            "the refusal must be the class refusal, with its stable rule code: {message}"
        );
        assert!(
            message.contains("finish/cancel the execution with the binary that wrote them"),
            "an operator cannot re-author durable bytes, so the recourse must be the durable \
             one: {message}"
        );
        // A binary of an earlier operational schema never reaches this check: the
        // directory's stamp is refused first. So the recourse names the binary that
        // wrote the programs, never "the previous" one.
        assert!(
            !message.contains("previous Kata binary"),
            "an earlier binary cannot open a directory this one admits: {message}"
        );
        assert!(
            message.contains("with the Kata binary that wrote these programs"),
            "the recourse names the writing binary: {message}"
        );
        assert!(
            !message.contains("backup"),
            "these bytes are intact and readable; restoring a database is not the remedy and \
             an older snapshot would discard lifecycle transitions that were fine: {message}"
        );
        assert_eq!(
            store.program_json(unhonourable).unwrap().unwrap(),
            serde_json::to_vec(&forged).unwrap(),
            "boot refusal must retain the exact evidence bytes"
        );
    }

    /// The misattribution itself, at the surface that carried it.
    ///
    /// `resume_or_orphan_in_flight_runs` wraps EVERY `recover_in_flight_runs`
    /// failure in one context, and that context read "repair access to
    /// operational.db (or restore it from a verified backup)". `recover_in_flight_runs`
    /// does not fail on one condition: it also decodes every durable checked program
    /// and compares its identity against the ledger. This drives the non-storage arm
    /// — a program the decode door refuses — and asserts the operator is told what
    /// actually happened.
    ///
    /// The membrane above normally catches this at `BootRig::boot`; the program is
    /// seeded AFTER boot so the recovery arm is reached directly, which is also the
    /// real shape of an execution admitted by a peer binary mid-life.
    #[test]
    fn recovery_failure_on_a_refused_program_is_not_diagnosed_as_a_storage_fault() {
        use kata_workflow::execution_program_store::ExecutionInvocation;

        start_runtime(async move {
            let (_root, rig) = boot_durable_recovery_test_rig().await;
            let execution_id = ulid::Ulid::new();
            let forged = program_carrying_an_unhonourable_execution_class();
            rig.execution_lifecycle
                .admit_current_execution(
                    execution_id,
                    &forged,
                    &ExecutionInvocation::workflow(Vec::new()),
                )
                .expect("its admission is coherent — only its axes are unhonourable");
            rig.execution_lifecycle
                .mark_running_after_admission(execution_id)
                .expect("make it a recovery candidate");

            let executor = WorkflowExecutor::new(
                Arc::clone(&rig.dispatcher),
                Arc::clone(&rig.supervisor),
                Arc::new(WorkflowLibrary::new(vec![])),
            )
            .with_execution_lifecycle(rig.execution_lifecycle.clone());
            let error = rig
                .resume_or_orphan_in_flight_runs(&executor)
                .expect_err("recovery must refuse a program it cannot dispatch");
            let message = format!("{error:#}");
            assert!(
                message.contains("invalid checked execution class"),
                "the nested refusal must survive the context: {message}"
            );
            assert!(
                message.contains("no lifecycle outcome was inferred")
                    && message.contains("nothing was orphaned"),
                "the safety property is the part of the old context that was TRUE and must \
                     be kept: {message}"
            );
            assert!(
                message.contains("ONLY when that error says the nucleus could not be READ"),
                "the storage remedy must be stated as conditional on the nested error, not \
                     prescribed for every recovery failure: {message}"
            );
            assert!(
                !message.contains("recovery scan failed"),
                "decoding programs and comparing ledger identity is not a 'scan': {message}"
            );
        });
    }

    /// The same context around a LEGACY-schema program. Its nested refusal says no
    /// binary that opens this directory wrote it and nothing can dispatch it here (every
    /// checked-program schema bump moves the operational stamp). The context leaves the
    /// recourse to that nested error, so the chain may not then send the operator to
    /// finish or cancel the execution on the binary that wrote it: the two halves of
    /// one error would contradict each other.
    #[test]
    fn recovery_failure_on_a_legacy_schema_program_offers_no_writing_binary() {
        start_runtime(async move {
            let (_root, rig) = boot_durable_recovery_test_rig().await;
            let execution_id = ulid::Ulid::new();
            rig.execution_lifecycle
                .put_raw_active_program_json(
                    execution_id,
                    br#"{"schema_version":7,"workflow_name":"older","stages":{}}"#,
                )
                .expect("seed a legacy-schema checked program");
            rig.execution_lifecycle
                .mark_running_after_admission(execution_id)
                .expect("make it a recovery candidate");

            let executor = WorkflowExecutor::new(
                Arc::clone(&rig.dispatcher),
                Arc::clone(&rig.supervisor),
                Arc::new(WorkflowLibrary::new(vec![])),
            )
            .with_execution_lifecycle(rig.execution_lifecycle.clone());
            let error = rig
                .resume_or_orphan_in_flight_runs(&executor)
                .expect_err("recovery must refuse a program it cannot dispatch");
            let message = format!("{error:#}");
            assert!(
                message.contains("unsupported schema 7")
                    && message.contains(kata_types::execution_contract::EARLIER_SCHEMA_RECOURSE),
                "premise: the nested refusal is the earlier-schema one: {message}"
            );
            let lowered = message.to_lowercase();
            for offer in ["finish", "cancel", "binary that wrote"] {
                assert!(
                    !lowered.contains(offer),
                    "no binary that opens this directory wrote the program ({offer:?}): \
                         {message}"
                );
            }
        });
    }

    #[test]
    fn assignment_start_deadline_from_worker_pool_honors_zero_disable() {
        let workers = WorkerPoolConfig {
            assignment_start_deadline_ms: 1234,
            ..WorkerPoolConfig::default()
        };
        assert_eq!(
            assignment_start_deadline_from_worker_pool(&workers),
            Some(Duration::from_millis(1234))
        );

        let disabled_workers = WorkerPoolConfig {
            assignment_start_deadline_ms: 0,
            ..WorkerPoolConfig::default()
        };
        assert_eq!(
            assignment_start_deadline_from_worker_pool(&disabled_workers),
            None
        );
    }

    /// Write a valid scheduled `.star` pack into `root`, returning nothing (the
    /// caller drives the library scan). Shared by the boot-reconcile tests.
    fn write_scheduled_pack(root: &Path, file: &str, schedule_id: &str, submit: &str) {
        std::fs::write(
            root.join(file),
            format!(
                r#"
only = stage(id = "only", agent = "default", prompt = "go")
schedule(id = "{schedule_id}", submit = "{submit}", every_ms = 1000)
workflow("{stem}", root = [only])
"#,
                stem = file.strip_suffix(".star").unwrap_or(file),
            ),
        )
        .expect("write scheduled pack");
    }

    /// Write a plain (unscheduled) pack a `submit=` target can resolve to. The
    /// reconciler compiles the TARGET at install now, so a scheduled pack whose
    /// target does not exist arms nothing — which is the point.
    fn write_target_pack(root: &Path, name: &str, marker: &str) {
        std::fs::write(
            root.join(format!("{name}.star")),
            format!(
                "only = stage(id = \"only\", agent = \"default\", prompt = \"{marker}\")\n\
                 workflow(\"{name}\", root = [only])\n"
            ),
        )
        .expect("write target pack");
    }

    fn schedule_face_in(dir: &Path) -> kata_workflow::schedule::ScheduleFace {
        kata_workflow::schedule::ScheduleFace::new(Arc::new(
            kata_core::OperationalDb::open(dir.join("operational.db")).expect("open operational"),
        ))
    }

    /// The ACTUAL boot reconcile seam over the
    /// durable table — install PINNING the compiled target, preserve the cursor
    /// across reboot, keep a transiently-uncompilable DECLARING pack's schedule armed
    /// (prune-safety), keep the existing PIN when the TARGET pack stops compiling,
    /// and prune a schedule genuinely no longer declared.
    #[test]
    fn install_library_schedules_into_reconciles_the_durable_table() {
        let tmp = kata_test_utils::fixtures::tempdir();
        let root = tmp.path().join("workflows");
        std::fs::create_dir_all(&root).expect("mkdir root");
        write_scheduled_pack(&root, "deps-pack.star", "nightly", "deps");
        write_target_pack(&root, "deps", "as pinned");
        let library = WorkflowLibrary::new(vec![root.clone()]);
        let face = schedule_face_in(tmp.path());

        // ---- Boot 1: the declared schedule installs, PINNING the target. ----
        let record = {
            install_library_schedules_into(&face, &library);
            let record = face
                .get("nightly")
                .expect("read")
                .expect("declared schedule installed");
            assert_eq!(record.submit_pack, "deps");
            record
        };
        let cursor = record.next_fire_ms;
        let pinned_hash = face
            .revalidated_pin("nightly")
            .expect("the pin re-validates")
            .expect("pinned")
            .0
            .program_hash;

        // ---- Boot 2: re-reconcile PRESERVES the durable cursor and the pin. ----
        install_library_schedules_into(&face, &library);
        assert_eq!(
            face.get("nightly").unwrap().unwrap().next_fire_ms,
            cursor,
            "re-reconciling on the next boot preserves the durable next-fire cursor"
        );
        assert_eq!(
            face.revalidated_pin("nightly")
                .unwrap()
                .unwrap()
                .0
                .program_hash,
            pinned_hash,
            "an unchanged declaration does not rebind"
        );

        // ---- Boot 3: the TARGET pack is edited → an explicit REBIND, cursor
        // preserved because the trigger did not change. ----
        write_target_pack(&root, "deps", "as EDITED between boots");
        install_library_schedules_into(&face, &library);
        let rebound = face
            .revalidated_pin("nightly")
            .unwrap()
            .unwrap()
            .0
            .program_hash;
        assert_ne!(
            rebound, pinned_hash,
            "a pack edit takes effect at the next boot reconciliation, as an explicit rebind"
        );
        assert_eq!(
            face.get("nightly").unwrap().unwrap().next_fire_ms,
            cursor,
            "a rebind under an unchanged trigger preserves the cursor"
        );

        // ---- Boot 4: the TARGET pack stops compiling → the EXISTING pin is kept
        // and the schedule keeps firing what it was bound to. ----
        std::fs::write(root.join("deps.star"), "this is ( not valid starlark").expect("break");
        install_library_schedules_into(&face, &library);
        assert_eq!(
            face.revalidated_pin("nightly")
                .unwrap()
                .unwrap()
                .0
                .program_hash,
            rebound,
            "an uncompilable TARGET keeps the existing pin rather than losing the occurrence"
        );
        write_target_pack(&root, "deps", "as EDITED between boots");

        // ---- Boot 5: the DECLARING pack has a syntax error → compile fails → the
        // schedule is NOT pruned and keeps its cursor (prune-safety). ----
        std::fs::write(root.join("deps-pack.star"), "this is ( not valid starlark")
            .expect("break pack");
        install_library_schedules_into(&face, &library);
        assert_eq!(
            face.get("nightly")
                .unwrap()
                .expect("a transiently-uncompilable pack must NOT disarm its schedule")
                .next_fire_ms,
            cursor,
            "cursor preserved across the broken-pack boot"
        );

        // ---- Boot 6: the declaring pack is DELETED (cleanly no longer declared) →
        // the schedule is pruned so it stops firing. ----
        std::fs::remove_file(root.join("deps-pack.star")).expect("remove pack");
        install_library_schedules_into(&face, &library);
        assert!(
            face.get("nightly").unwrap().is_none(),
            "a schedule no longer declared by any pack is pruned on a clean boot"
        );
    }

    /// A declared schedule whose `submit=` target does not resolve arms NOTHING, and
    /// says so, rather than installing silently and losing one occurrence per
    /// sweep, forever, once the fire tried to compile a name that was not there.
    #[test]
    fn a_declared_schedule_with_an_unresolvable_target_arms_nothing() {
        let tmp = kata_test_utils::fixtures::tempdir();
        let root = tmp.path().join("workflows");
        std::fs::create_dir_all(&root).expect("mkdir root");
        write_scheduled_pack(&root, "ghost-pack.star", "ghost", "not-a-pack");
        let face = schedule_face_in(tmp.path());

        install_library_schedules_into(&face, &WorkflowLibrary::new(vec![root]));
        assert!(
            face.get("ghost").unwrap().is_none(),
            "there is no program to pin, so nothing is armed"
        );
    }

    /// The EXECUTOR ACCEPTANCE SEAM, driven end-to-end through the REAL
    /// `WorkflowExecutor` on a real durable boot.
    ///
    /// The substrate tests prove the firing transaction and the workflow tests prove
    /// the pin. Neither reaches the piece that eliminates the half-commit in
    /// PRODUCTION: that a schedule fire runs the ONE submit pipeline — shutdown fence,
    /// live-worker requirements, worktree-isolation, `WorkflowRunner::new_from_program`,
    /// then the acceptance commit, then evidence / workspace / mark-running / spawn —
    /// with the firing claim and the cursor advance substituted into that single
    /// acceptance point.
    ///
    /// A pipeline that hand-rolls its own resolver → admit → evidence →
    /// terminalize sequence can bypass a chokepoint while every test passes; a
    /// second pipeline for schedules would be exactly that. This asserts there
    /// is one.
    #[test]
    fn a_schedule_fire_commits_claim_cursor_and_execution_through_the_one_submit_pipeline() {
        use kata_api::executor::Acceptance;
        use kata_core::operational::FireOutcome;
        use kata_program::schedule::ScheduleSpec;
        use kata_program::schedule::ScheduleTrigger;
        use kata_workflow::schedule::ScheduleFace;

        start_runtime(async move {
            let (_root, rig) = boot_durable_recovery_test_rig().await;
            let executor = rig
                .build_workflow_executor()
                .expect("build the workflow executor");
            let face = ScheduleFace::new(Arc::clone(rig.execution_lifecycle.db()));

            let program = kata_program::execution_program::compile_starlark_execution_program(
                "only = stage(id = \"only\", run = \"echo '{\\\"ok\\\":true}'\", \
                         agent = \"shell\", outputs = {\"ok\": \"bool\"})\n\
                         workflow(\"scheduled-shell\", root = only)\n",
                "scheduled-shell.star",
                &[],
            )
            .expect("compile the pinned shell target");
            let spec = ScheduleSpec {
                id: "nightly".to_string(),
                submit_pack: "scheduled-shell".to_string(),
                trigger: ScheduleTrigger::Interval { every_ms: 1_000 },
                on_missed: kata_program::schedule::MissedPolicy::FireOnceOnBoot,
                params: serde_json::Map::new(),
            };
            face.install(&spec, &program, 0).expect("install + pin");
            let due = face.get("nightly").unwrap().unwrap().next_fire_ms;
            assert_eq!(due, 1_000);

            let accept_face = face.clone();
            let accept = move |execution_id: ulid::Ulid,
                                   _program: &kata_program::execution_program::ExecutionProgram,
                                   _invocation: &kata_workflow::execution_program_store::ExecutionInvocation| {
                    match accept_face.fire("nightly", due, execution_id, due + 1_000, None) {
                        Ok(FireOutcome::Fired { .. }) => Ok(Acceptance::Accepted),
                        Ok(FireOutcome::AlreadyFired) => Ok(Acceptance::ClaimAlreadySpent),
                        Err(error) => Err(
                            kata_api::executor::ExecutorError::DurabilityFailed(error.to_string()),
                        ),
                    }
                };

            // PHASE 1: PRE-ACCEPTANCE validation runs AHEAD of the claim. The
            // rig has no live worker yet, so `require_live_workers_for_execution_program`
            // refuses — and because that happens before the acceptance point, the
            // occurrence is left completely intact for the next sweep. This is the
            // property that makes "a failed submit does not consume the occurrence"
            // true for validation failures as well as for durability ones.
            let (pinned_program, pinned_invocation) = face
                .revalidated_pin("nightly")
                .expect("the pin re-validates")
                .expect("pinned");
            let supplied: serde_json::Map<String, serde_json::Value> = pinned_invocation
                .params
                .iter()
                .map(|param| (param.name.to_string(), param.value.clone()))
                .collect();
            let refused = executor
                .submit_pinned_schedule_execution(pinned_program, supplied, &accept)
                .expect_err("no live worker must refuse BEFORE the claim");
            assert!(
                matches!(refused, kata_api::executor::ExecutorError::NoWorkers),
                "{refused:?}"
            );
            assert!(
                face.firings("nightly").unwrap().is_empty(),
                "a pre-acceptance refusal must claim NOTHING"
            );
            assert_eq!(
                face.get("nightly").unwrap().unwrap().next_fire_ms,
                due,
                "a pre-acceptance refusal must not move the cursor: the occurrence is \
                     retried on the next sweep"
            );

            // PHASE 2: with capacity present the same call runs the whole
            // pipeline and its acceptance point commits the firing transaction.
            let (home, worker) = kata_transport::InProcessTransport::pair(64);
            let home: Arc<dyn kata_transport::transport::WorkerTransport> = Arc::new(home);
            register_test_double(
                &rig,
                smol_str::SmolStr::new("schedule-fire"),
                home,
                vec!["agent:shell".to_string()],
                kata_workflow::test_harness::rig_worker_containment(),
                rig.execution_lifecycle
                    .db()
                    .enroll_worker_domain(&rig.source_main_identity, rig.local_membrane)
                    .unwrap(),
            );
            let cas = kata_core::store::cas::CasStore::open(
                rig.cfg.node.data_dir.join("cas.db"),
                rig.cfg.node.data_dir.join("cas"),
            )
            .expect("the rig's content store re-opens");
            let (_scripted, _pump) = kata_workflow::test_harness::OciNodeRig::scripted_worker_on(
                std::sync::Arc::new(worker),
                std::sync::Arc::clone(rig.execution_lifecycle.db()),
                cas,
                kata_test_utils::MockAgentBackend::new(),
                std::sync::Arc::new(tempfile::tempdir().expect("worker node dir")),
            );

            let (pinned_program, pinned_invocation) = face
                .revalidated_pin("nightly")
                .expect("the pin re-validates")
                .expect("pinned");
            let supplied: serde_json::Map<String, serde_json::Value> = pinned_invocation
                .params
                .iter()
                .map(|param| (param.name.to_string(), param.value.clone()))
                .collect();
            let submitted = executor
                .submit_pinned_schedule_execution(pinned_program, supplied, &accept)
                .expect("the pinned schedule submit must succeed")
                .expect("a fresh claim submits an execution");
            let execution_id: ulid::Ulid = submitted.parse().expect("an execution id");

            // The FIRING TRANSACTION's three facts, durable together.
            let firings = face.firings("nightly").expect("read firings");
            assert_eq!(firings.len(), 1, "exactly one claim for the due instant");
            assert_eq!(firings[0].fire_instant, i64::try_from(due).unwrap());
            assert_eq!(firings[0].execution_id(), Some(execution_id));
            assert_eq!(
                face.get("nightly").unwrap().unwrap().next_fire_ms,
                due + 1_000,
                "the cursor advanced in the SAME transaction as the execution"
            );
            assert!(
                rig.execution_lifecycle
                    .lifecycle(execution_id)
                    .expect("read the lifecycle")
                    .is_some(),
                "the fire admitted a durable execution through the real pipeline"
            );
            // The execution holds its own immutable copy of the PINNED program.
            let stored: kata_program::execution_program::ExecutionProgram = serde_json::from_slice(
                &rig.execution_lifecycle
                    .program_json(execution_id)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(stored.program_hash, program.program_hash);

            // A REDELIVERY at the same due instant short-circuits the WHOLE submit.
            let before = rig
                .execution_lifecycle
                .lifecycle_execution_ids()
                .unwrap()
                .len();
            let (pinned_program, pinned_invocation) =
                face.revalidated_pin("nightly").unwrap().unwrap();
            let supplied: serde_json::Map<String, serde_json::Value> = pinned_invocation
                .params
                .iter()
                .map(|param| (param.name.to_string(), param.value.clone()))
                .collect();
            assert!(
                executor
                    .submit_pinned_schedule_execution(pinned_program, supplied, &accept)
                    .expect("a redelivery is not an error")
                    .is_none(),
                "the already-claimed instant must short-circuit the whole submit"
            );
            assert_eq!(
                rig.execution_lifecycle
                    .lifecycle_execution_ids()
                    .unwrap()
                    .len(),
                before,
                "a redelivered fire admits NOTHING"
            );
            assert_eq!(face.firings("nightly").unwrap().len(), 1);

            rig.close_admission();
            rig.drain_workflow_tasks().await;
        });
    }

    /// The end-to-end restart proof at the BOOT
    /// seam — reconcile from a library scan, then REOPEN the durable operational
    /// database (a restart) and confirm the reloaded, DSL-declared schedule fires
    /// when due, carrying the pinned program.
    #[test]
    fn installed_library_schedule_fires_from_a_reopened_durable_table() {
        use std::sync::Mutex;

        use kata_workflow::schedule::{FireReport, ScheduleEngine, ScheduleFire, SubmitFn};

        let tmp = kata_test_utils::fixtures::tempdir();
        let root = tmp.path().join("workflows");
        std::fs::create_dir_all(&root).expect("mkdir root");
        write_scheduled_pack(&root, "poll.star", "poller", "poll-target");
        write_target_pack(&root, "poll-target", "poll");

        // First boot: scan the library and reconcile into the durable table.
        let cursor = {
            let face = schedule_face_in(tmp.path());
            install_library_schedules_into(&face, &WorkflowLibrary::new(vec![root.clone()]));
            face.get("poller").unwrap().expect("installed").next_fire_ms
        };

        // Restart: a completely fresh handle over the SAME durable file.
        let log: Arc<Mutex<Vec<(String, u64)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let submit: SubmitFn = Arc::new(move |fire: &ScheduleFire| {
            sink.lock()
                .unwrap()
                .push((fire.record.submit_pack.clone(), fire.fire_instant));
            Ok(FireReport::Submitted)
        });
        let face = schedule_face_in(tmp.path());
        let engine = ScheduleEngine::new(face, submit);
        assert!(
            engine.sweep_due(cursor - 1).is_empty(),
            "pre-due after restart: nothing fires"
        );
        assert_eq!(
            engine.sweep_due(cursor),
            vec!["poller".to_owned()],
            "the reloaded, library-declared schedule fires post-restart"
        );
        assert_eq!(
            log.lock().unwrap().as_slice(),
            [("poll-target".to_owned(), cursor)],
            "the firing intent carries the DUE cursor as its instant, never `now`"
        );
    }
}

/// **THE NODE'S OWN ANSWERS, INSTALLED AND REFUSED AT BOOT** — the ADR-0001
/// containment policy and the `[node]` facts the CHECK and the capsule assembler
/// judge against.
///
/// # Why they are one call
///
/// They are the same KIND of fact and they have the same ordering requirement:
/// each is *what this node has decided*, each must be settled before anything
/// can compile, resume or dispatch a checked program, and each is read from the
/// process rather than from the rig. Statements at the top of [`BootRig::boot`]
/// would be things a later edit can separate; one call cannot be half-made.
///
/// # The refused set, stated exactly
///
/// The installs REFUSE NOTHING of their own — `require_contained_model_stages`
/// and the CHECK do their refusing later, at compile. This function refuses
/// exactly: a `[node] egress_allow` entry that does not parse (a config that
/// skipped `KataConfig::validate`), and a node with no declared `[node]
/// environment` (`required_environment`).
// AT THE FILE FOOT ON PURPOSE, and the lint is allowed rather than obeyed: a new
// item in this file APPENDS rather than shifts, so `path:line` coordinates that
// resolve into this file keep naming the code they cite.
#[allow(clippy::items_after_test_module)]
fn install_node_facts_or_refuse(cfg: &KataConfig) -> Result<()> {
    kata_types::containment_policy::install_node_containment_policy(cfg.containment);
    // The node's facts funnel: a process that reached here boots a node, and
    // the CHECK's node-dependent arms stop deferring.
    kata_types::node_profile::mark_node_installed();
    // The `[node] *_ceiling` family installs beside it, so the
    // admission check reads what the node declared rather than the shipped defaults
    // an uninstalled process would answer with.
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::NodeBudgetCeilings {
            output_bytes: cfg.node.output_bytes_ceiling,
            work_delta_bytes: cfg.node.work_delta_bytes_ceiling,
            work_delta_entries: cfg.node.work_delta_entries_ceiling,
            capsule_memory_bytes: cfg.node.capsule_memory_bytes_ceiling,
            capsule_process_count: cfg.node.capsule_process_count_ceiling,
        },
    );
    // The `[agents]` map installs beside them: the `oci` CHECK
    // (`adapter_undeclared`/`adapter_unqualified`) and the capsule assembler
    // resolve a stage's agent label against the same installed map, so a pack
    // checked on this node is dispatched under the declarations it was
    // checked with.
    kata_types::node_profile::install_node_agents(cfg.agents.clone());
    // `[node] egress_allow` installs beside them, ALREADY PARSED:
    // `KataConfig::validate` proved every spelling at load, and a failure here
    // would mean a config that skipped validate — refused rather than
    // installed partially, because a `net = "host"` stage's allowlist is this
    // set and a partial set egresses less than the node declared.
    let egress_allow = cfg
        .node
        .egress_allow
        .iter()
        .map(|spelling| {
            kata_types::execution_contract::EgressAuthority::from_authority_str(spelling)
                .with_context(|| {
                    format!("node.egress_allow entry `{spelling}` failed to parse at install")
                })
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    kata_types::node_profile::install_node_egress_allow(egress_allow);
    // An `oci` node with no `[node] environment` is refused HERE, at
    // boot, rather than at its first dispatch: the closure is a node fact no pack names.
    cfg.node
        .required_environment()
        .context("this node requires a declared Nix environment")?;
    Ok(())
}
