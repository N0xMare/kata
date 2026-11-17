//! Shared application state threaded through all axum handlers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use kata_core::SystemHealth;
use kata_core::store::SqliteNativeMemoryStore;

use crate::executor::WorkflowExecutor;
use crate::version::VersionInfo;

/// Application state shared across all handlers via
/// `axum::extract::State`. Clone-cheap: every field is an `Arc`.
#[derive(Clone)]
pub struct AppState {
    /// Aggregated subsystem health. Read by the health endpoint.
    pub health: Arc<SystemHealth>,
    /// Workflow submission executor. `None` on nodes that do not
    /// own a `WorkerPoolSupervisor` (for example, a standalone
    /// worker process). Handlers that need to submit workflows
    /// should return `503 Service Unavailable` when this is `None`.
    pub workflow_executor: Option<Arc<WorkflowExecutor>>,
    /// Native memory/context store. `None` on stateless worker-only
    /// API fixtures; the installed main wires this to `<data_dir>/memory.db`.
    pub memory_store: Option<Arc<SqliteNativeMemoryStore>>,
    /// Build-time provenance of the running kata daemon.
    /// Populated by `kata-bin::boot` from compile-time constants;
    /// surfaced by `GET /api/v1/version`. `None` only in test
    /// fixtures that don't set it explicitly — the endpoint
    /// returns `503` in that case.
    pub version_info: Option<Arc<VersionInfo>>,
    /// Node identity and API-process start time surfaced by
    /// `GET /api/v1/system/status`.
    pub runtime: Arc<RuntimeStatus>,
}

/// Runtime identity for the API process.
#[derive(Clone, Debug)]
pub struct RuntimeStatus {
    /// Stable node identifier from `[node].id`.
    pub node_id: String,
    /// Monotonic process-local start time for uptime calculation.
    pub started_at: Instant,
    /// Product process mode (`installed`, `scratch`, or `unknown`).
    pub process_mode: String,
    /// Immutable installed/scratch data-directory identity when this process
    /// owns workflow authority.
    pub directory_id: Option<String>,
    /// Per-boot authority generation when this process owns workflow authority.
    pub process_generation: Option<String>,
    /// Live installed-main discovery protocol and binary identity.
    pub attachment_protocol_version: Option<u32>,
    pub binary_version: Option<String>,
    /// Digest of the executable bytes loaded by this process at service launch.
    pub loaded_binary_digest: Option<String>,
    pub control_endpoint: Option<String>,
    /// Digest of the config bytes this process loaded at boot. This remains
    /// stable so service status can prove when an install requires a restart.
    pub loaded_config_digest: Option<String>,
    /// Canonical path whose bytes produced `loaded_config_digest`.
    pub loaded_config_path: Option<String>,
    /// Digest of the exact owner-only environment snapshot loaded by the
    /// native-service trampoline. `None` for direct foreground starts.
    pub loaded_service_environment_digest: Option<String>,
    /// Recovery classification and exact remediation exposed to service status.
    pub recovery_state: String,
    pub next_action: Option<String>,
    /// Whether this API process is currently accepting new work. The server
    /// owns transitions: false before listener admission opens, true while the
    /// listener is serving, and false before graceful shutdown closes it.
    readiness: Arc<AtomicBool>,
}

/// Identity and recovery facts for the workflow authority owned by this API
/// process.
///
/// Keeping these related values in one named carrier makes boot wiring
/// reviewable at call sites and prevents positional argument drift between
/// executable, configuration, attachment, and recovery identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityStatus {
    /// Product process mode (`installed` or `scratch`).
    pub process_mode: String,
    /// Immutable identity of the authority's data directory.
    pub directory_id: String,
    /// Per-boot authority generation.
    pub process_generation: String,
    /// Installed-main attachment protocol understood by this process.
    pub attachment_protocol_version: u32,
    /// Semantic version of the running Kata binary.
    pub binary_version: String,
    /// Digest of the executable bytes accepted at launch.
    pub loaded_binary_digest: String,
    /// API endpoint published for attached clients.
    pub control_endpoint: String,
    /// Digest of the exact configuration snapshot accepted at boot.
    pub loaded_config_digest: String,
    /// Canonical path from which that configuration snapshot was loaded.
    pub loaded_config_path: String,
    /// Digest of the installed service environment, when service-managed.
    pub loaded_service_environment_digest: Option<String>,
    /// Durable recovery classification reported after boot reconciliation.
    pub recovery_state: String,
    /// Exact operator remediation when recovery is not ready.
    pub next_action: Option<String>,
}

impl RuntimeStatus {
    #[must_use]
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            started_at: Instant::now(),
            process_mode: "unknown".to_string(),
            directory_id: None,
            process_generation: None,
            attachment_protocol_version: None,
            binary_version: None,
            loaded_binary_digest: None,
            control_endpoint: None,
            loaded_config_digest: None,
            loaded_config_path: None,
            loaded_service_environment_digest: None,
            recovery_state: "initializing".to_string(),
            next_action: None,
            readiness: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub fn unknown() -> Self {
        Self::new("unknown")
    }

    #[must_use]
    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Return the live API readiness state.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.readiness.load(Ordering::Acquire)
    }

    /// Transition API readiness. This is public for the server lifecycle and
    /// embedders that drive the same router without [`crate::server::ApiServer`].
    pub fn set_ready(&self, ready: bool) {
        self.readiness.store(ready, Ordering::Release);
    }
}

impl AppState {
    /// Create a new `AppState` with just the health handle. The
    /// workflow executor is omitted — use [`AppState::with_executor`]
    /// to wire one in.
    #[must_use]
    pub fn new(health: Arc<SystemHealth>) -> Self {
        Self {
            health,
            workflow_executor: None,
            memory_store: None,
            version_info: None,
            runtime: Arc::new(RuntimeStatus::unknown()),
        }
    }

    /// Convenience constructor for an installed or scratch main where the
    /// health handle and workflow executor are both available at boot.
    #[must_use]
    pub fn with_executor(
        health: Arc<SystemHealth>,
        workflow_executor: Arc<WorkflowExecutor>,
    ) -> Self {
        Self {
            health,
            workflow_executor: Some(workflow_executor),
            memory_store: None,
            version_info: None,
            runtime: Arc::new(RuntimeStatus::unknown()),
        }
    }

    /// Attach the native memory/context store after construction.
    #[must_use]
    pub fn with_memory_store(mut self, store: Arc<SqliteNativeMemoryStore>) -> Self {
        self.memory_store = Some(store);
        self
    }

    /// Attach build-time provenance after construction. kata-bin
    /// calls this at boot with a [`VersionInfo`] built from its
    /// `build_info` constants.
    #[must_use]
    pub fn with_version_info(mut self, info: VersionInfo) -> Self {
        self.version_info = Some(Arc::new(info));
        self
    }

    /// Attach the node identity that should be reported by the API.
    #[must_use]
    pub fn with_runtime_status(mut self, node_id: impl Into<String>) -> Self {
        self.runtime = Arc::new(RuntimeStatus::new(node_id));
        self
    }

    /// Attach installed/scratch authority identity after the data-directory
    /// kernel lock is held and before readiness is published.
    #[must_use]
    pub fn with_authority_status(mut self, status: AuthorityStatus) -> Self {
        let mut runtime = (*self.runtime).clone();
        runtime.process_mode = status.process_mode;
        runtime.directory_id = Some(status.directory_id);
        runtime.process_generation = Some(status.process_generation);
        runtime.attachment_protocol_version = Some(status.attachment_protocol_version);
        runtime.binary_version = Some(status.binary_version);
        runtime.loaded_binary_digest = Some(status.loaded_binary_digest);
        runtime.control_endpoint = Some(status.control_endpoint);
        runtime.loaded_config_digest = Some(status.loaded_config_digest);
        runtime.loaded_config_path = Some(status.loaded_config_path);
        runtime.loaded_service_environment_digest = status.loaded_service_environment_digest;
        runtime.recovery_state = status.recovery_state;
        runtime.next_action = status.next_action;
        self.runtime = Arc::new(runtime);
        self
    }
}
