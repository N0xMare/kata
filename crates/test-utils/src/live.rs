//! `live` — spawn/teardown handles for the real `kata` and
//! `kata-worker` binaries.
//!
//! The smoke tests are written on top of [`NodeHandle`] / [`WorkerHandle`].
//!
//! ## Design
//!
//! Each handle owns:
//!   * a `tempfile::TempDir` data directory (`<tmp>`),
//!   * a generated TOML config file (`<tmp>/kata-main-*.toml`),
//!   * a `std::process::Child` running `target/release/kata` (or
//!     `target/release/kata-worker`),
//!   * a clone of the `kata_client::KataClient` pointed at the
//!     spawned API socket (NodeHandle only — workers don't bind a
//!     REST surface).
//!
//! Drop teardown sends `SIGTERM` to the recorded pid, waits up to
//! 15 s for the process to exit, then escalates to `SIGKILL`. The
//! struct fields are declared with `child` BEFORE `data_dir` so the
//! field-drop order (top-down) reaps the child before the tempdir
//! disappears underneath it.
//! Failed post-spawn construction, health waits, shutdowns, and panic unwinding
//! retain their private harness config/log directory after teardown. Errors name
//! the log path; they never dump
//! its contents. Callers clean retained diagnostics explicitly; owned durable data
//! still follows its normal cleanup policy.
//!
//! ## What this module is NOT
//!
//! * NOT a binary discovery service. We look in
//!   `KATA_LIVE_BIN_DIR` (env override) → workspace
//!   `target/release/`. Missing binary returns
//!   [`LiveError::BinaryMissing`] — there is no debug fallback,
//!   because a `cargo build` (debug) of the kata workspace burns
//!   enough tempdir space + RAM to make CI flaky. Tests that need live binaries must `just
//!   build` first.
//! * NOT a process supervisor. If `await_healthy` times out, the
//!   handle is still valid — the caller should `shutdown().await`
//!   to clean up. Drop is the safety net, not the primary path.
//! * NOT a config templater. The TOML written here is the
//!   minimal installed-main shape needed to bring kata up; tests
//!   that need richer config should fork this module.
//!
//! ## The API port
//!
//! The spawned main binds a [`HeldPort`] the handle keeps for the main's
//! whole life: no other process's `:0` bind is handed that port before the
//! main binds it, while it serves, or after it exits. See
//! [`crate::held_port`] for what a hold does and does not refuse.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kata_client::{KataClient, KataClientError};
use kata_types::identity::WorkerResource;

use crate::held_port::HeldPort;

/// A failed local-socket node construction may spend this long waiting for the
/// enrollment secret before the construction guard begins bounded teardown.
const ENROLLMENT_SECRET_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum graceful teardown time while a spawned node is still being built.
/// The post-spawn failure path is therefore bounded by 45 seconds total:
/// [`ENROLLMENT_SECRET_TIMEOUT`] plus this grace period before SIGKILL.
const NODE_TERMINATION_GRACE: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every failure mode the `live` scaffolding can surface.
///
/// Variants are deliberately granular so smoke tests can match on
/// the expected failure (e.g. assert that an offline-mode probe
/// times out at the health check, not at binary discovery).
#[derive(Debug, thiserror::Error)]
pub enum LiveError {
    /// Holding a loopback port ([`HeldPort::new`]) failed. Surfaced via
    /// `#[from]` so the underlying `io::Error` is preserved.
    #[error("port allocation failed: {0}")]
    PortAlloc(#[from] std::io::Error),
    /// `target/release/kata` (or `kata-worker`) was not on the
    /// resolved binary path. Carries the path the resolver looked
    /// in so the operator can `just build` and retry.
    #[error(
        "kata binary not found at {0}; run `cargo build --release -p kata` or set KATA_LIVE_BIN_DIR"
    )]
    BinaryMissing(PathBuf),
    /// Generated TOML failed to write or `kata config check`
    /// rejected it.
    #[error("config write failed: {0}")]
    ConfigWrite(String),
    /// `Command::spawn` failed (binary not executable, runtime
    /// missing, etc).
    #[error("spawn failed: {0}")]
    Spawn(String),
    /// `await_healthy` exceeded its budget without seeing every
    /// subsystem report `healthy`.
    #[error(
        "health check exceeded {timeout:?} budget; last observation: {last_observation}; retained private log: {log_path:?}"
    )]
    HealthTimeout {
        /// Caller-owned budget, covering requests and poll delays.
        timeout: Duration,
        /// Subsystem states or error category, excluding free-form server data.
        last_observation: String,
        /// Private harness log, retained after the child is reaped on Drop.
        log_path: PathBuf,
    },
    /// `await_healthy` observed the main's own process exit before it reported
    /// healthy — e.g. a boot refusal. This ends the wait immediately: a dead
    /// main cannot become healthy, so spending the caller's budget would only
    /// delay the verdict the log already holds.
    #[error("main exited during health wait: {status}; retained private log: {log_path:?}")]
    MainExited {
        /// The child's exit status (`exit status: N` or `signal: …`).
        status: std::process::ExitStatus,
        /// Private harness log, retained after the child is reaped on Drop.
        log_path: PathBuf,
    },
    /// Post-spawn initialization failed; teardown completed before retaining logs.
    #[error("node initialization failed: {source}; retained private log: {log_path:?}")]
    Initialization {
        /// Original typed initialization failure.
        #[source]
        source: Box<LiveError>,
        /// Harness artifacts remain private and require explicit caller cleanup.
        log_path: PathBuf,
    },
    /// `<data_dir>/local-worker.secret` did not appear during main boot.
    #[error("local-worker enrollment secret not found at {path:?} after {elapsed:?}")]
    SecretMissing {
        /// How long we waited for the file to appear.
        elapsed: Duration,
        /// The path we polled.
        path: PathBuf,
    },
    /// `kata-worker provision` returned a non-zero exit status.
    #[error("provision failed: {0}")]
    ProvisionFailed(String),
    /// `shutdown()` waited for the recorded pid past its budget
    /// and escalated to SIGKILL.
    #[error("shutdown timed out after {0:?}; SIGKILL'd")]
    ShutdownTimeout(Duration),
    /// Underlying SDK error from `KataClient::*`.
    #[error("client error: {0}")]
    Client(#[from] KataClientError),
}

// ---------------------------------------------------------------------------
// NodeHandle
// ---------------------------------------------------------------------------

/// Worker-capacity topology exposed by an installed main.
///
/// This is placement capacity, not an authority or node role: both variants
/// boot the same durable installed main via `kata serve --config`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityTopology {
    /// The installed main starts and supervises its node: a `kata-worker`
    /// beside it on `<data_dir>/node.sock` (`type = "supervised_node"`).
    SupervisedNode,
    /// The installed main exposes a local socket for an external worker.
    LocalSocket,
}

/// Optional `[telemetry]` block injected into the generated TOML
/// by [`NodeHandle::spawn_supervised_main_with_telemetry`]. Maps 1:1 onto
/// the flat `kata_types::config::TelemetryConfig` table.
///
/// The smoke at `crates/test-utils/tests/smokes.rs`'s
/// `smoke_metrics_endpoint_reflects_workflow_run` builds one with
/// `export = "prometheus"` and an ephemeral `metrics_bind`, then
/// asserts against the resulting `/metrics` scrape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TelemetrySpec {
    /// Matches `cfg.telemetry.export` in `KataConfig`.
    pub export: String,
    /// Matches `cfg.telemetry.metrics_bind`. For tests this is
    /// almost always a [`HeldPort`]'s address, held for the main's life.
    pub metrics_bind: SocketAddr,
    /// Matches `cfg.telemetry.otlp_endpoint`. Empty string =
    /// disabled; the default for Prometheus-only smokes.
    pub otlp_endpoint: String,
}

/// Optional `[vcs]` block injected into the generated TOML by live tests that
/// point the jj execution-workspace provider at a repository of their own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VcsSpec {
    /// Matches `cfg.vcs.jj_repo`.
    pub jj_repo: PathBuf,
}

impl VcsSpec {
    /// The jj execution-workspace provider rooted at `jj_repo`.
    #[must_use]
    pub fn native_jj(jj_repo: PathBuf) -> Self {
        Self { jj_repo }
    }
}

/// The statically-linked busybox closure every live `oci` node's
/// `[node] environment` binds — the same pin `oci_stage_live.rs`'s `BUSYBOX`
/// and `bin/kata/tests/oci_main_live.rs` name.
/// Realised on the reference host; a host without it sees the environment bind
/// refuse by name at boot, which is the behaviour under test.
const LIVE_BUSYBOX_STORE_PATH: &str =
    "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";

/// The statically-linked NetBSD `getent` closure — busybox has no such applet,
/// and the offline-DNS smoke invokes it by name.
const LIVE_GETENT_STORE_PATH: &str = "/nix/store/shwr4cipfr4ypvi7vjr20y4k6ziyzkqy-getent-getent-netbsd-static-x86_64-unknown-linux-musl-9.2";

/// The `git-minimal` closure — the git-history smoke's stage execs `git`
/// inside its capsule, so the environment must provide it
/// (`capsule_program_not_in_environment` otherwise).
const LIVE_GIT_STORE_PATH: &str = "/nix/store/3ba67bl61l0dxp1x4m9waqnvm5n5bkcs-git-minimal-2.55.0";

/// The store paths every live `oci` config this module renders declares, in
/// declaration order.
const LIVE_ENVIRONMENT_STORE_PATHS: &[&str] = &[
    LIVE_BUSYBOX_STORE_PATH,
    LIVE_GETENT_STORE_PATH,
    LIVE_GIT_STORE_PATH,
];

/// The `[node]` `environment = { .. }` line [`render_node_config`] writes,
/// exposed for smokes that patch a `kata init`-generated config: those must
/// declare the same pinned live environment — an `oci` node without it
/// refuses `node_environment_undeclared` at boot — instead of duplicating the
/// pin list.
///
/// ONE line, like the inline table it emits: TOML inline tables cannot span
/// lines, and the generated config is re-parsed (`toml::from_str`,
/// `ConfigManager::load`).
#[doc(hidden)]
#[must_use]
pub fn live_environment_block(id_label: &str) -> String {
    environment_line(
        id_label,
        "nixpkgs#pkgsStatic.busybox",
        &LIVE_ENVIRONMENT_STORE_PATHS
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<Vec<_>>(),
        &LIVE_ENVIRONMENT_STORE_PATHS
            .iter()
            .map(|path| format!("{path}/bin"))
            .collect::<Vec<_>>(),
    )
}

/// One `[node] environment = { .. }` line over `store_paths` (the roots the
/// node declares; kata binds their closure) with `path_prepend` on the
/// capsule's `PATH`.
fn environment_line(
    label: &str,
    nixpkgs_attribute: &str,
    store_paths: &[String],
    path_prepend: &[String],
) -> String {
    let quoted = |paths: &[String]| {
        paths
            .iter()
            .map(|path| format!("\"{path}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "environment = {{ label = \"{label}\", system = \"x86_64-linux\", nixpkgs_attribute = \"{nixpkgs_attribute}\", store_paths = [{}], path_prepend = [{}], integrity_policy = {{ verify = \"nar_hash_only\", sigs_needed = 0, required_signers = [], allow_unsigned_content_addressed = true, verify_contents_at_declare = true }} }}\n",
        quoted(store_paths),
        quoted(path_prepend),
    )
}

/// Optional knobs [`render_node_config`] folds into the generated TOML.
///
/// Everything absent from here is fixed: the `oci` execution profile is not an
/// option because a node without it cannot boot under the shipped profile, and
/// the node environment is always the live pins.
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
pub struct NodeConfigOptions {
    /// `[telemetry]` block — see [`TelemetrySpec`].
    pub telemetry: Option<TelemetrySpec>,
    /// `[vcs]` block — see [`VcsSpec`].
    pub vcs: Option<VcsSpec>,
    /// Extra environment variables set on the spawned daemon process — e.g.
    /// `KATA_FAULT_INJECT=operational.after_accept_event` to arm a
    /// deterministic, env-gated crash point at a precise code boundary.
    pub extra_env: Vec<(String, String)>,
    /// `[node] egress_allow` authorities (`host:port`) the node's `net =
    /// "host"` stages may reach. Empty by default: kata never invents an
    /// operator's authority set, and a cell that needs egress declares it.
    pub egress_allow: Vec<String>,
    /// `[agents.*]` TOML fragment rendered verbatim, REPLACING the default
    /// declaration (the empty `[agents.shell]` on a supervising main,
    /// empty `[agents]` on local-socket). A cell whose pack selects a real
    /// model agent declares its adapter/credential here.
    pub agents_block: Option<String>,
}

impl CapacityTopology {
    /// Stable suffix used for the generated test identity and config name.
    fn id_suffix(self) -> &'static str {
        match self {
            CapacityTopology::SupervisedNode => "supervised",
            CapacityTopology::LocalSocket => "local-socket",
        }
    }
}

/// How a [`NodeHandle`] owns its data directory.
///
/// The `spawn_*_with_data_dir` constructors let the
/// "boot, drop, rebind to the same data_dir" restart-survival
/// smoke rebuild a node against an already-existing path. The
/// owned variant wraps a `tempfile::TempDir` (deletes on Drop, the
/// default); the borrowed variant just remembers the
/// path so `data_dir()` keeps working. Borrowed-mode handles
/// skip cleanup — the caller is on the hook for unlinking the
/// directory (typically by holding their own `TempDir` for the
/// outer lifetime of the test).
enum DataDirOwnership {
    /// Tempdir we allocated and will unlink on Drop.
    Owned(tempfile::TempDir),
    /// Caller-supplied path; we remember it but do not unlink it.
    Borrowed(PathBuf),
}

impl DataDirOwnership {
    /// Filesystem path of the data directory, regardless of who
    /// owns it.
    fn path(&self) -> &Path {
        match self {
            Self::Owned(t) => t.path(),
            Self::Borrowed(p) => p.as_path(),
        }
    }
}

/// Live-spawned installed Kata main.
///
/// Construct via [`NodeHandle::spawn_supervised_main`] or
/// [`NodeHandle::spawn_main_with_local_socket`]. Both helpers:
///   1. Allocate a `tempfile::TempDir` for `data_dir`.
///   2. Pick a free TCP port for the API.
///   3. Optionally allocate a Unix socket for external local worker capacity.
///   4. Render a minimal TOML config in a separate harness tempdir.
///   5. Validate the config via `kata config check --config <p>`.
///   6. Spawn `kata serve --config <p>` with stdout +
///      stderr captured beside the harness config.
///
/// The `*_with_data_dir` variants accept a caller-supplied
/// `PathBuf` instead of allocating a fresh tempdir; cleanup is
/// then the caller's problem (drop a `tempfile::TempDir` of your
/// own to unlink). The restart-survival smoke uses this to
/// rebuild a node against the same on-disk data directory.
///
/// Field declaration order matters: `child` is declared **before**
/// `data_dir` so the implicit field-drop order (top-down) reaps
/// the child before the tempdir vanishes underneath it. Reversing
/// these would race the child against `unlink(<data_dir>/...)` and
/// leak SQLite WAL files.
pub struct NodeHandle {
    capacity_topology: CapacityTopology,
    /// Spawned `kata` child. Declared first so Drop reaps it
    /// before any other field (in particular `data_dir`) is
    /// destroyed.
    ///
    /// Behind a `Mutex` so `await_healthy(&self)` can ask `try_wait` whether
    /// the main is still alive mid-poll — a refused boot exits before any
    /// health reply, and the wait must stop on that fact rather than spend the
    /// caller's deadline. Ownership semantics are unchanged: the handle still
    /// owns and reaps the process.
    child: Mutex<Child>,
    /// Backing `[node].data_dir`. Owned by the handle in the
    /// default constructors (deleted on Drop) or borrowed from
    /// the caller in the `*_with_data_dir` constructors (caller
    /// owns cleanup).
    data_dir: DataDirOwnership,
    /// Config and process logs must not make a fresh durable data directory
    /// appear to contain unadopted pre-existing state before the main acquires its
    /// authority lock and writes the immutable directory identity.
    harness_dir: tempfile::TempDir,
    /// A failed health wait or shutdown must not lose its diagnostic path on Drop.
    retain_harness_on_drop: AtomicBool,
    /// How long `shutdown`, `interrupt` and Drop wait for the child after
    /// signalling it before escalating: [`NODE_TERMINATION_GRACE`] for a real
    /// main, shorter for a unit fixture whose child is a stand-in.
    termination_grace: Duration,
    /// REST surface base URL (e.g. `http://127.0.0.1:43219`).
    api_url: String,
    /// The API port, held for as long as the handle: the main binds it, and no
    /// other process's `:0` bind is handed it. `None` only for a unit-test
    /// fixture handle pointed at a socket its test owns.
    _api_port: Option<HeldPort>,
    /// Local-worker enrollment secret. `None` for a supervised node.
    enrollment_secret: Option<String>,
    /// Unix socket an external worker dials. `None` for a supervised node,
    /// whose socket is the main's own.
    worker_socket: Option<PathBuf>,
    /// Pre-built SDK client pointed at `api_url`. Cloning is cheap.
    client: KataClient,
}

impl NodeHandle {
    /// Spawn an installed main that starts and supervises its node.
    ///
    /// The returned handle is ready to receive
    /// `client().submit_*()` calls once `await_healthy` returns.
    pub fn spawn_supervised_main() -> Result<Self, LiveError> {
        Self::spawn_supervised_main_with_env(Vec::new())
    }

    /// Spawn a supervising main with explicit subprocess-only environment overrides.
    pub fn spawn_supervised_main_with_env(
        extra_env: Vec<(String, String)>,
    ) -> Result<Self, LiveError> {
        let data_dir = tempfile::TempDir::new()
            .map_err(|e| LiveError::Spawn(format!("data_dir tempdir: {e}")))?;
        spawn_node(
            CapacityTopology::SupervisedNode,
            DataDirOwnership::Owned(data_dir),
            NodeConfigOptions {
                extra_env,
                ..NodeConfigOptions::default()
            },
        )
    }

    /// Spawn a supervising main under an explicit [`NodeConfigOptions`] — the
    /// door for cells whose node must carry a knob the named constructors do
    /// not expose: `[node] egress_allow` for a `net = "host"` stage (whose
    /// allowlist is declaration-empty without it) or a `[vcs]` backend the
    /// default door does not select.
    pub fn spawn_supervised_main_with_options(
        options: NodeConfigOptions,
    ) -> Result<Self, LiveError> {
        let data_dir = tempfile::TempDir::new()
            .map_err(|e| LiveError::Spawn(format!("data_dir tempdir: {e}")))?;
        spawn_node(
            CapacityTopology::SupervisedNode,
            DataDirOwnership::Owned(data_dir),
            options,
        )
    }

    /// Spawn an installed main with external local-socket worker capacity.
    ///
    /// `[agents]` is empty; the worker pool advertises a
    /// local_socket transport at `<data_dir>/worker.sock` that
    /// external [`WorkerHandle`]s provision against.
    pub fn spawn_main_with_local_socket() -> Result<Self, LiveError> {
        let data_dir = tempfile::TempDir::new()
            .map_err(|e| LiveError::Spawn(format!("data_dir tempdir: {e}")))?;
        spawn_node(
            CapacityTopology::LocalSocket,
            DataDirOwnership::Owned(data_dir),
            NodeConfigOptions::default(),
        )
    }

    /// Spawn an installed main supervising its node with telemetry and explicit
    /// subprocess-only environment overrides.
    ///
    /// The metrics smoke uses this to boot the main with Prometheus export
    /// wired on an ephemeral port, then curl `/metrics` after a workflow
    /// run to verify the full observability stack end-to-end.
    pub fn spawn_supervised_main_with_telemetry(
        spec: TelemetrySpec,
        extra_env: Vec<(String, String)>,
    ) -> Result<Self, LiveError> {
        let data_dir = tempfile::TempDir::new()
            .map_err(|e| LiveError::Spawn(format!("data_dir tempdir: {e}")))?;
        spawn_node(
            CapacityTopology::SupervisedNode,
            DataDirOwnership::Owned(data_dir),
            NodeConfigOptions {
                telemetry: Some(spec),
                extra_env,
                ..NodeConfigOptions::default()
            },
        )
    }

    /// Spawn an installed main supervising its node with native jj workspaces.
    ///
    /// The caller owns `jj_repo`'s lifetime. Live smokes should usually pass a
    /// tempdir path so the daemon initializes and mutates an isolated jj repo
    /// rather than the operator checkout.
    pub fn spawn_supervised_main_with_native_jj(jj_repo: PathBuf) -> Result<Self, LiveError> {
        Self::spawn_supervised_main_with_native_jj_and_env(jj_repo, Vec::new())
    }

    /// Spawn a native-jj fixture with explicit subprocess-only environment overrides.
    pub fn spawn_supervised_main_with_native_jj_and_env(
        jj_repo: PathBuf,
        extra_env: Vec<(String, String)>,
    ) -> Result<Self, LiveError> {
        let data_dir = tempfile::TempDir::new()
            .map_err(|e| LiveError::Spawn(format!("data_dir tempdir: {e}")))?;
        spawn_node(
            CapacityTopology::SupervisedNode,
            DataDirOwnership::Owned(data_dir),
            NodeConfigOptions {
                vcs: Some(VcsSpec::native_jj(jj_repo)),
                extra_env,
                ..NodeConfigOptions::default()
            },
        )
    }

    /// Spawn a local-socket-capacity installed main with extra environment.
    ///
    /// The multi-worker smokes use this to set
    /// `KATA_STDLIB_DIR=<empty dir>`, which points the main's workflow
    /// library at an empty root. Those smokes submit
    /// their workflows inline via `run_starlark`, so an empty library
    /// costs them nothing.
    pub fn spawn_main_with_local_socket_and_env(
        extra_env: Vec<(String, String)>,
    ) -> Result<Self, LiveError> {
        let data_dir = tempfile::TempDir::new()
            .map_err(|e| LiveError::Spawn(format!("data_dir tempdir: {e}")))?;
        spawn_node(
            CapacityTopology::LocalSocket,
            DataDirOwnership::Owned(data_dir),
            NodeConfigOptions {
                extra_env,
                ..NodeConfigOptions::default()
            },
        )
    }

    /// Spawn a local-socket-capacity installed main bound to a caller-supplied
    /// `data_dir`. Cleanup is the caller's problem; hold a
    /// `tempfile::TempDir` of your own and pass `td.path().to_path_buf()`
    /// if you want unlink-on-drop.
    pub fn spawn_main_with_local_socket_and_data_dir(dir: PathBuf) -> Result<Self, LiveError> {
        spawn_node(
            CapacityTopology::LocalSocket,
            DataDirOwnership::Borrowed(dir),
            NodeConfigOptions::default(),
        )
    }

    /// Spawn an installed main supervising its node with its durable SQLite state
    /// bound to a
    /// caller-supplied `data_dir`, plus extra environment variables on the
    /// daemon process.
    ///
    /// This is the constructor the crash-recovery matrix's real-process smoke
    /// uses. Installed-main state survives a crash and reboot against the same
    /// `data_dir`; `extra_env` carries the deterministic
    /// `KATA_FAULT_INJECT` crash point that aborts the daemon at a precise
    /// ledger boundary. Cleanup is the caller's problem; hold a
    /// `tempfile::TempDir` of your own and pass `td.path().to_path_buf()`
    /// if you want unlink-on-drop.
    pub fn spawn_supervised_main_with_data_dir_and_env(
        dir: PathBuf,
        extra_env: Vec<(String, String)>,
    ) -> Result<Self, LiveError> {
        spawn_node(
            CapacityTopology::SupervisedNode,
            DataDirOwnership::Borrowed(dir),
            NodeConfigOptions {
                extra_env,
                ..NodeConfigOptions::default()
            },
        )
    }

    /// SDK client pointed at this node's REST surface.
    #[must_use]
    pub fn client(&self) -> &KataClient {
        &self.client
    }

    /// Configured base URL (e.g. `http://127.0.0.1:43219`).
    #[must_use]
    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    /// `[node].data_dir` — path to the directory that backs this
    /// node's durable stores, immutable directory identity, and workspaces.
    /// Whether the directory is owned (default constructors) or
    /// borrowed (`*_with_data_dir` constructors) is invisible at
    /// this layer.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        self.data_dir.path()
    }

    /// Captured stdout/stderr for the installed-main process.
    #[must_use]
    pub fn log_path(&self) -> PathBuf {
        self.harness_dir.path().join("kata.log")
    }

    /// Local-worker enrollment secret. `None` for a supervised node.
    #[must_use]
    pub fn enrollment_secret(&self) -> Option<&str> {
        self.enrollment_secret.as_deref()
    }

    /// External worker transport socket. `None` for a supervised node.
    #[must_use]
    pub fn worker_socket(&self) -> Option<&Path> {
        self.worker_socket.as_deref()
    }

    /// Pid of the spawned kata process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.lock().expect("live child lock").id()
    }

    /// Worker-capacity topology configured for this installed main.
    #[must_use]
    pub fn capacity_topology(&self) -> CapacityTopology {
        self.capacity_topology
    }

    /// Poll `client().health()` every 250 ms until every
    /// subsystem reports `Healthy`, the child exits, or `timeout` elapses.
    ///
    /// Returns [`LiveError::MainExited`] the moment `try_wait` reports the
    /// child's exit — a dead main cannot become healthy, so the wait stops
    /// rather than spending the caller's budget; [`LiveError::HealthTimeout`]
    /// still covers the alive-but-not-healthy case. The handle
    /// remains valid; the caller should `shutdown().await` to
    /// reap it. The private harness log survives teardown for diagnosis. The
    /// deadline covers both HTTP requests and poll delays; a late healthy reply
    /// cannot turn an expired wait into success.
    pub async fn await_healthy(&self, timeout: Duration) -> Result<(), LiveError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_observation = "no completed health probe".to_string();
        loop {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            // A boot refusal exits the process before any health reply —
            // asking again would only burn the caller's deadline on a corpse.
            // `Ok(None)` means still running; `Err` means the wait syscall
            // itself failed, which is an observation to keep polling through,
            // not a terminal fact.
            match self.child.lock().expect("live child lock").try_wait() {
                Ok(Some(status)) => {
                    self.retain_harness_on_drop.store(true, Ordering::Relaxed);
                    return Err(LiveError::MainExited {
                        status,
                        log_path: self.log_path(),
                    });
                }
                Ok(None) => {}
                Err(error) => {
                    last_observation = format!("child wait probe failed: {error}");
                }
            }
            match tokio::time::timeout_at(deadline, self.client.health()).await {
                Ok(Ok(health)) => {
                    // A ready response may win the timeout future's poll even
                    // after the deadline; elapsed budgets cannot become success.
                    if health.is_healthy() && tokio::time::Instant::now() < deadline {
                        return Ok(());
                    }
                    last_observation = health
                        .subsystems
                        .iter()
                        .map(|(id, state)| {
                            let state = match state {
                                kata_client::SubsystemHealth::Healthy => "healthy",
                                kata_client::SubsystemHealth::Degraded { .. } => "degraded",
                                kata_client::SubsystemHealth::Unavailable { .. } => "unavailable",
                            };
                            format!("{id:?}={state}")
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                }
                Ok(Err(error)) => {
                    // API bodies and health reasons may contain private data.
                    last_observation = match error {
                        KataClientError::Api { status, .. } => format!("HTTP status {status}"),
                        KataClientError::Http(error) if error.is_connect() => {
                            "transport connection failed".into()
                        }
                        KataClientError::Http(_) => "HTTP transport failed".into(),
                        KataClientError::TransportStalled { .. } => {
                            "HTTP transport timed out".into()
                        }
                        KataClientError::InvalidBody(_) => "invalid health response body".into(),
                        _ => "health client request failed".into(),
                    };
                }
                Err(_) => {
                    last_observation.push_str("; health request incomplete at deadline");
                    break;
                }
            }
            tokio::time::sleep_until(
                deadline.min(tokio::time::Instant::now() + Duration::from_millis(250)),
            )
            .await;
        }
        self.retain_harness_on_drop.store(true, Ordering::Relaxed);
        Err(LiveError::HealthTimeout {
            timeout,
            last_observation,
            log_path: self.log_path(),
        })
    }

    /// Send `SIGTERM` to the kata process, wait up to its termination grace
    /// ([`NODE_TERMINATION_GRACE`] for a real main) for exit, escalate to
    /// `SIGKILL` if the deadline elapses.
    ///
    /// Consumes `self` so Drop does not double-fire. Returns
    /// [`LiveError::ShutdownTimeout`] if the SIGKILL escalation
    /// path was taken.
    ///
    /// `async` even though the body is currently sync — the
    /// public surface stays async so future implementations can `tokio::task::spawn_blocking`
    /// the wait loop without breaking callers.
    #[allow(clippy::unused_async)]
    pub async fn shutdown(mut self) -> Result<(), LiveError> {
        let result = terminate_child(
            self.child.get_mut().expect("live child lock"),
            self.termination_grace,
        );
        if result.is_err() {
            self.retain_harness_on_drop.store(true, Ordering::Relaxed);
        }
        result
    }

    /// Exercise the interactive SIGINT path while retaining the same bounded
    /// reap contract as service SIGTERM shutdown.
    #[allow(clippy::unused_async)]
    pub async fn interrupt(mut self) -> Result<(), LiveError> {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(
                i32::try_from(self.child.get_mut().expect("live child lock").id())
                    .unwrap_or(i32::MAX),
            ),
            nix::sys::signal::Signal::SIGINT,
        )
        .map_err(|error| LiveError::Spawn(format!("SIGINT installed main: {error}")))?;
        wait_for_exit(
            self.child.get_mut().expect("live child lock"),
            self.termination_grace,
        )
    }

    /// Simulate abrupt host/process loss. No graceful handler or destructor in
    /// the child runs; the kernel must release authority locks and restart
    /// recovery must supersede stale attachment metadata and reacquire the
    /// persistent per-owner discovery inode's released kernel lock.
    #[allow(clippy::unused_async)]
    pub async fn kill_now(mut self) -> Result<(), LiveError> {
        self.child
            .get_mut()
            .expect("live child lock")
            .kill()
            .map_err(|error| LiveError::Spawn(format!("SIGKILL installed main: {error}")))?;
        self.child
            .get_mut()
            .expect("live child lock")
            .wait()
            .map_err(|error| LiveError::Spawn(format!("reap SIGKILLed installed main: {error}")))?;
        Ok(())
    }
}

impl Drop for NodeHandle {
    /// SIGTERM-then-SIGKILL teardown. Failures are logged via
    /// `eprintln!` (no `tracing` setup is guaranteed in test
    /// processes). The tempdir Drop runs after this method
    /// returns, freeing the `data_dir`.
    fn drop(&mut self) {
        let mut retain =
            self.retain_harness_on_drop.load(Ordering::Relaxed) || std::thread::panicking();
        if let Err(e) = terminate_child(
            self.child.get_mut().expect("live child lock"),
            self.termination_grace,
        ) {
            retain = true;
            eprintln!(
                "live: NodeHandle drop teardown failed for pid {}: {e}",
                self.child.get_mut().expect("live child lock").id()
            );
        }
        // The supervised topology provisioned a sealed provider store under the
        // harness dir; lift the seal so the removal (or a later manual one, on a
        // retained dir) can get through it.
        unseal_live_provider_store(self.harness_dir.path());
        if retain {
            self.harness_dir.disable_cleanup(true);
            eprintln!(
                "live: retained private harness log: {}",
                self.log_path().display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// WorkerHandle
// ---------------------------------------------------------------------------

/// Live-spawned `kata-worker` process connected to a
/// [`NodeHandle::spawn_main_with_local_socket`] node.
///
/// Construction:
///   1. Take a tempdir for the worker's `data_dir` (separate from
///      main — the Kata data-directory lock would otherwise reject it).
///   2. Run `kata-worker provision --main unix://<sock> --secret-file
///      <owner-only-file> --out <tmp>/worker.toml --capability ...` to write
///      the worker config + 0600 credential file.
///   3. Spawn `kata-worker run --config <tmp>/worker.toml`.
///
/// Same field-drop ordering invariant as [`NodeHandle`]: `child`
/// before `data_dir`.
pub struct WorkerHandle {
    /// Spawned `kata-worker` child. First field for the Drop
    /// ordering invariant.
    child: Child,
    /// Tempdir backing the worker's `KATA_DATA_DIR` (so the
    /// pidfile lands somewhere we control) and holding the
    /// generated `worker.toml` + credential.
    data_dir: tempfile::TempDir,
    /// Cached pid (== `child.id()`).
    pid: u32,
}

impl WorkerHandle {
    /// Provision and spawn a worker pointed at `main`.
    ///
    /// `caps` are passed verbatim through `kata-worker provision
    /// --capability <spec>` flags. The mapping from
    /// [`WorkerResource`] to spec string is the inverse of
    /// `<WorkerResource as FromStr>::from_str` (see
    /// `crates/types/src/identity.rs`):
    ///
    /// | Variant | Spec written |
    /// |---|---|
    /// | `Shell` | `shell` |
    /// | `Network` | `network` |
    /// | `AgentBackend(bt)` | `agent_backend=<bt.label()>` |
    /// | `Disk { min_gb }` | `disk=<min_gb>` |
    /// | `Gpu { min_vram_gb }` | `gpu=<min_vram_gb>` |
    /// | `Custom(s)` | `custom=<s>` |
    pub fn spawn(main: &NodeHandle, caps: &[WorkerResource]) -> Result<Self, LiveError> {
        Self::spawn_with_secret(main, caps, None)
    }

    /// Provision and spawn a worker pointed at an installed main, optionally
    /// overriding the shared secret written into its credential file.
    ///
    /// `secret_override = None` uses the main's real secret (the
    /// [`WorkerHandle::spawn`] happy path). `Some(bogus)` provisions the
    /// worker with a WRONG secret so the main's handshake
    /// (`kata_transport::enrollment::authenticate_main`) rejects it — the
    /// credential-refusal negative the multi-worker proof asserts: a worker that
    /// cannot authenticate never registers with the supervisor.
    ///
    /// The worker process still *spawns* (its retry loop dials the socket and
    /// starts the handshake); the main finds that the worker cannot prove
    /// possession of the secret and closes the connection without registering. The
    /// returned handle is therefore a live-but-unregistered child; the
    /// caller asserts against the main's worker inventory, then reaps it
    /// via [`WorkerHandle::shutdown`] / Drop.
    pub fn spawn_with_secret(
        main: &NodeHandle,
        caps: &[WorkerResource],
        secret_override: Option<&str>,
    ) -> Result<Self, LiveError> {
        // External worker provisioning requires local-socket capacity and its
        // enrollment secret. A supervised node's main exposes neither.
        let secret = match secret_override {
            Some(s) => s,
            None => main.enrollment_secret().ok_or_else(|| {
                LiveError::ProvisionFailed(
                    "installed main has no local-socket worker enrollment secret".to_string(),
                )
            })?,
        };
        let sock = main
            .worker_socket()
            .ok_or_else(|| {
                LiveError::ProvisionFailed(
                    "installed main has no local-socket worker capacity".to_string(),
                )
            })?
            .to_path_buf();

        let data_dir = tempfile::TempDir::new()
            .map_err(|e| LiveError::Spawn(format!("worker data_dir tempdir: {e}")))?;
        let config_path = data_dir.path().join("worker.toml");
        let secret_path = data_dir.path().join("provision.secret");
        std::fs::write(&secret_path, secret)
            .map_err(|e| LiveError::ProvisionFailed(format!("write secret file: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| LiveError::ProvisionFailed(format!("protect secret file: {e}")))?;
        }

        // ── provision ─────────────────────────────────────────
        let bin = worker_bin_path()?;
        let main_endpoint = format!("unix://{}", sock.display());
        let mut prov = Command::new(&bin);
        prov.arg("provision")
            .arg("--main")
            .arg(&main_endpoint)
            .arg("--secret-file")
            .arg(&secret_path)
            .arg("--out")
            .arg(&config_path)
            // The provisioned worker admits the `oci` capsule arm, whose route
            // resolves a capsule's environment and input trees through the
            // main's planes read-only — the emitted `worker.toml` refuses to
            // start without it (`worker_main_data_dir_undeclared`).
            .arg("--main-data-dir")
            .arg(main.data_dir());
        for cap in caps {
            prov.arg("--capability").arg(capability_to_spec(cap));
        }
        prov.stdin(Stdio::null());
        let prov_out = prov
            .output()
            .map_err(|e| LiveError::ProvisionFailed(format!("spawn provision: {e}")))?;
        if !prov_out.status.success() {
            let stderr = String::from_utf8_lossy(&prov_out.stderr).into_owned();
            return Err(LiveError::ProvisionFailed(format!(
                "kata-worker provision exited {:?}: {stderr}",
                prov_out.status.code()
            )));
        }

        // ── spawn ─────────────────────────────────────────────
        // The worker HOSTS the capsule route for this topology: it needs its
        // own provider store (by-hash stores are per-rig scratch) and a
        // delegated scope so its rootless youki containers own a cgroup —
        // `systemd-run --scope` makes the worker the unit's first process, so
        // killing `child` reaps the worker AND its containers.
        let provider_env = provision_live_provider(data_dir.path())?;
        let log_path = data_dir.path().join("kata-worker.log");
        let log_file = std::fs::File::create(&log_path)
            .map_err(|e| LiveError::Spawn(format!("create log {}: {e}", log_path.display())))?;
        let log_err = log_file
            .try_clone()
            .map_err(|e| LiveError::Spawn(format!("clone log handle: {e}")))?;

        let mut cmd = Command::new("systemd-run");
        cmd.args(crate::delegated_scope::systemd_run_args());
        cmd.arg(&bin);
        cmd.arg("run")
            .arg("--config")
            .arg(&config_path)
            .env("KATA_DATA_DIR", data_dir.path())
            .envs(
                provider_env
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_err));

        let child = cmd
            .spawn()
            .map_err(|e| LiveError::Spawn(format!("spawn kata-worker: {e}")))?;
        let pid = child.id();

        Ok(WorkerHandle {
            child,
            data_dir,
            pid,
        })
    }

    /// Pid of the spawned worker process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// `KATA_DATA_DIR` of the worker — the tempdir that holds
    /// its config, credential file, and pidfile.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        self.data_dir.path()
    }

    /// SIGTERM-then-SIGKILL teardown. See [`NodeHandle::shutdown`].
    /// Same `async`-but-sync-body rationale as
    /// [`NodeHandle::shutdown`].
    #[allow(clippy::unused_async)]
    pub async fn shutdown(mut self) -> Result<(), LiveError> {
        terminate_child(&mut self.child, Duration::from_secs(15))
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        if let Err(e) = terminate_child(&mut self.child, Duration::from_secs(15)) {
            eprintln!(
                "live: WorkerHandle drop teardown failed for pid {}: {e}",
                self.pid
            );
        }
        // The worker hosts the capsule route, so its data dir holds a sealed
        // provider store; `data_dir`'s removal runs after this body.
        unseal_live_provider_store(self.data_dir.path());
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn create_harness_dir() -> std::io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("kata-live-harness-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir()
}

/// Owns a freshly spawned main until every fallible construction step has
/// succeeded. `std::process::Child` does not terminate or reap on Drop, so a
/// raw child in this window would otherwise survive an early `?` return.
struct NodeConstructionGuard {
    child: Option<Child>,
}

impl NodeConstructionGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn release(mut self) -> Child {
        self.child
            .take()
            .expect("node construction guard must own its child until release")
    }
}

impl Drop for NodeConstructionGuard {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if let Err(error) = terminate_child(child, NODE_TERMINATION_GRACE) {
            eprintln!(
                "live: failed node construction teardown escalated for pid {}: {error}",
                child.id()
            );
        }
    }
}

/// Run every fallible post-spawn initialization step while the child remains
/// under synchronous teardown ownership. No fallible work may be added between
/// this function's success and moving the returned child into `NodeHandle`.
/// On failure, reap first and retain the private harness directory named by the
/// error. Its log bytes are never copied into the error or test output.
fn initialize_spawned_node<T>(
    child: Child,
    harness_dir: tempfile::TempDir,
    initialize: impl FnOnce() -> Result<T, LiveError>,
) -> Result<(Child, T, tempfile::TempDir), LiveError> {
    let guard = NodeConstructionGuard::new(child);
    match initialize() {
        Ok(initialized) => Ok((guard.release(), initialized, harness_dir)),
        Err(source) => {
            drop(guard);
            let log_path = harness_dir.keep().join("kata.log");
            Err(LiveError::Initialization {
                source: Box::new(source),
                log_path,
            })
        }
    }
}

/// Spawn an installed main with the requested worker-capacity topology. Shared body of
/// `spawn_supervised_main` / `spawn_main_with_local_socket` and the `*_with_data_dir`
/// variants — keeps the capacity-conditional branches explicit at
/// the top. Data-dir ownership is decided by the caller (owned
/// tempdir vs caller-supplied path); see [`DataDirOwnership`].
///
/// When `data_dir` is `Borrowed` the directory may already contain durable
/// stores and identity from a prior boot. Installed-main bootstrap reuses that
/// authority after acquiring the kernel-held discovery and data-directory
/// locks; the harness log remains per-process and external to the data dir.
fn spawn_node(
    capacity_topology: CapacityTopology,
    data_dir: DataDirOwnership,
    options: NodeConfigOptions,
) -> Result<NodeHandle, LiveError> {
    let bin = kata_bin_path()?;
    let harness_dir =
        create_harness_dir().map_err(|e| LiveError::Spawn(format!("main harness tempdir: {e}")))?;

    // Caller-supplied paths may not exist yet (the restart smoke
    // creates a fresh tempdir then passes its path here on the
    // first boot). Make sure the directory is in place so kata's
    // bootstrap helper doesn't ENOENT writing durable state.
    std::fs::create_dir_all(data_dir.path()).map_err(|e| {
        LiveError::ConfigWrite(format!(
            "create data_dir {}: {e}",
            data_dir.path().display()
        ))
    })?;

    let api_port = HeldPort::new()?;
    let api_socket = api_port.addr();
    let worker_socket = match capacity_topology {
        CapacityTopology::LocalSocket => Some(data_dir.path().join("worker.sock")),
        CapacityTopology::SupervisedNode => None,
    };

    let config_path = harness_dir.path().join(match capacity_topology {
        CapacityTopology::SupervisedNode => "kata-main-supervised.toml",
        CapacityTopology::LocalSocket => "kata-main-local-socket.toml",
    });
    let toml = render_node_config(
        capacity_topology,
        data_dir.path(),
        api_socket,
        worker_socket.as_deref(),
        &options,
    );
    std::fs::write(&config_path, toml)
        .map_err(|e| LiveError::ConfigWrite(format!("write {}: {e}", config_path.display())))?;

    // Validate via `kata config check` so a config bug surfaces
    // here, not as a half-spawned daemon. The check is fast (it
    // just deserialises + validates).
    let check = Command::new(&bin)
        .arg("config")
        .arg("check")
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| LiveError::ConfigWrite(format!("spawn config check: {e}")))?;
    if !check.status.success() {
        let stderr = String::from_utf8_lossy(&check.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&check.stdout).into_owned();
        return Err(LiveError::ConfigWrite(format!(
            "kata config check failed: stdout={stdout} stderr={stderr}"
        )));
    }

    // Keep harness artifacts outside the durable directory. The installed
    // main must be the first writer there so identity initialization can
    // distinguish a fresh directory from unadopted pre-existing state.
    let log_path = harness_dir.path().join("kata.log");
    let log_file = std::fs::File::create(&log_path)
        .map_err(|e| LiveError::Spawn(format!("create log {}: {e}", log_path.display())))?;
    let log_err = log_file
        .try_clone()
        .map_err(|e| LiveError::Spawn(format!("clone log handle: {e}")))?;

    // The supervised node is the main's child: it inherits the main's
    // environment and cgroup, so the main carries the provider exports and the
    // delegated cgroup the rootless runtime writes into (the main moves itself
    // into a leaf and places the node in a sibling) — the same wrap
    // `bin/kata/tests/oci_main_live.rs` puts its oci main under. A
    // local-socket main only DISPATCHES capsule frames; the external
    // `kata-worker` brings its own provider env and scope.
    let provider_env = match capacity_topology {
        CapacityTopology::SupervisedNode => provision_live_provider(harness_dir.path())?,
        CapacityTopology::LocalSocket => Vec::new(),
    };

    let mut cmd = match capacity_topology {
        CapacityTopology::SupervisedNode => {
            let mut cmd = Command::new("systemd-run");
            cmd.args(crate::delegated_scope::systemd_run_args());
            cmd.arg(&bin);
            cmd
        }
        CapacityTopology::LocalSocket => Command::new(&bin),
    };
    cmd.arg("serve").arg("--config").arg(&config_path);
    cmd.envs(
        provider_env
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    )
    .stdin(Stdio::null())
    .stdout(Stdio::from(log_file))
    .stderr(Stdio::from(log_err));
    // The smokes submit `workflows/smoke` rigs by name, and neither a bundle nor
    // a checkout build resolves those: the checkout's explicit stdlib dir opens
    // its `smoke` sibling. A caller's `extra_env` (an empty library) still wins.
    cmd.env("KATA_STDLIB_DIR", checkout_stdlib_dir());
    // Extra per-process env (e.g. the deterministic crash point
    // `KATA_FAULT_INJECT`). Layered last so callers can override defaults.
    for (key, value) in &options.extra_env {
        cmd.env(key, value);
    }

    let child = cmd
        .spawn()
        .map_err(|e| LiveError::Spawn(format!("spawn kata: {e}")))?;

    let api_url = format!("http://{api_socket}");
    let (child, (client, enrollment_secret), harness_dir) =
        initialize_spawned_node(child, harness_dir, || {
            let client = KataClient::new(api_url.clone()).map_err(LiveError::Client)?;

            // Local-socket capacity needs the worker enrollment secret before the
            // harness can provision a child. The supervised node is the main's own.
            let enrollment_secret = match capacity_topology {
                CapacityTopology::LocalSocket => Some(wait_for_enrollment_secret(
                    data_dir.path(),
                    ENROLLMENT_SECRET_TIMEOUT,
                )?),
                CapacityTopology::SupervisedNode => None,
            };
            Ok((client, enrollment_secret))
        })?;

    Ok(NodeHandle {
        capacity_topology,
        child: Mutex::new(child),
        data_dir,
        harness_dir,
        retain_harness_on_drop: AtomicBool::new(false),
        termination_grace: NODE_TERMINATION_GRACE,
        api_url,
        _api_port: Some(api_port),
        enrollment_secret,
        worker_socket,
        client,
    })
}

/// Resolve the path to the `kata` binary.
///
/// Order:
///   1. `$KATA_LIVE_BIN_DIR/kata` if `KATA_LIVE_BIN_DIR` is set.
///   2. `<workspace_root>/target/release/kata`.
fn kata_bin_path() -> Result<PathBuf, LiveError> {
    bin_path("kata")
}

/// Lift the seal [`provision_live_provider`] leaves on `<dir>/provider-store`.
///
/// `kata sandbox install-external-provider` seals each store entry `0500`, and a
/// `TempDir`'s removal cannot unlink the children of a `0500` directory — it
/// discards the `EACCES` and the tree stays in the temp root for good. This runs
/// the recourse the store's own refusals name, `chmod -R u+w`, as a process,
/// the way the harness drives every other operator step: this crate does not
/// link `kata-worker`, whose `UnsealOnDrop` is the in-process twin for rigs
/// that do. Best-effort, because a destructor has nowhere to report to; an
/// absent store is nothing to do.
fn unseal_live_provider_store(dir: &Path) {
    let store = dir.join("provider-store");
    if store.exists() {
        let _ = Command::new("chmod")
            .args(["-R", "u+w", "--"])
            .arg(&store)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Unseals [`provision_live_provider`]'s store under a directory when dropped,
/// for a caller that owns that directory itself: bind it AFTER the `TempDir`,
/// so it drops BEFORE it — on a panic too.
#[doc(hidden)]
pub struct UnsealLiveProviderStore {
    dir: PathBuf,
}

impl UnsealLiveProviderStore {
    /// Guard `dir`'s `provider-store`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

impl Drop for UnsealLiveProviderStore {
    fn drop(&mut self) {
        unseal_live_provider_store(&self.dir);
    }
}

/// Provision `kata-provider-youki` (and the `kata-oci-hook` / `ip` members an
/// `Egress` capsule's provider entry execs) into a scratch by-hash provider
/// store under `harness_dir`, returning the three `KATA_EXTERNAL_*` exports a
/// capsule-hosting process resolves its provider through.
///
/// The worker transport is not an execution provider — the
/// provider routing has no PATH fallback, so the env exports are the
/// only door. Same mechanism `bin/kata/tests/oci_main_live.rs`'s
/// `provision_provider` drives; the harness drives it through the shipped
/// `kata sandbox install-external-provider` verb rather than the
/// `ProviderStore` API because a test that asks kata whether kata worked
/// asserts nothing — the provisioning CLI is the operator path being proven.
///
/// The provider + hook binaries must already be built where [`bin_path`]
/// resolves (`cargo build -p kata-provider-youki -p kata-oci-hook` — the live
/// recipes build both). `ip` is copied when the host has one: an
/// `Egress`-free capsule never opens it, and an `Egress` capsule without it
/// refuses `provider_unresolved` by name at admission.
///
/// The store is SEALED (`0500` directories), which a `TempDir`'s own removal
/// cannot get through: whoever owns `harness_dir` lifts the seal before removing
/// it — [`NodeHandle`] and [`WorkerHandle`] do in their `Drop`, and a caller that
/// owns the directory itself holds an [`UnsealLiveProviderStore`].
#[doc(hidden)]
pub fn provision_live_provider(harness_dir: &Path) -> Result<Vec<(String, String)>, LiveError> {
    let bin = kata_bin_path()?;
    let source = harness_dir.join("provider-src");
    std::fs::create_dir_all(&source)
        .map_err(|e| LiveError::Spawn(format!("provider source dir: {e}")))?;
    for name in ["kata-provider-youki", "kata-oci-hook"] {
        let built = bin_path(name)?;
        std::fs::copy(&built, source.join(name))
            .map_err(|e| LiveError::Spawn(format!("copy {name} into provider source: {e}")))?;
    }
    // `loopback-up` execs the host's iproute2 by absolute path — the same
    // lookup `oci_stage_live.rs`'s `host_ip` performs. Absent is not fatal at
    // provision time: only `Egress` capsules open the member.
    for candidate in ["/usr/bin/ip", "/usr/sbin/ip", "/bin/ip", "/sbin/ip"] {
        if Path::new(candidate).is_file() {
            std::fs::copy(candidate, source.join("ip"))
                .map_err(|e| LiveError::Spawn(format!("copy host ip into provider: {e}")))?;
            break;
        }
    }
    let store = harness_dir.join("provider-store");
    let output = Command::new(&bin)
        .env("KATA_EXTERNAL_PROVIDER_STORE", &store)
        .args(["sandbox", "install-external-provider", "--name", "youki"])
        .arg(&source)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| LiveError::Spawn(format!("spawn install-external-provider: {e}")))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(LiveError::Spawn(format!(
            "install-external-provider failed: stdout={stdout} stderr={stderr}"
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let address = stdout
        .lines()
        .find_map(|line| line.strip_prefix("export KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS="))
        .ok_or_else(|| {
            LiveError::Spawn(format!(
                "install-external-provider printed no content address: {stdout}"
            ))
        })?
        .to_owned();
    Ok(vec![
        (
            "KATA_EXTERNAL_PROVIDER_STORE".to_owned(),
            store.display().to_string(),
        ),
        (
            "KATA_EXTERNAL_EXECUTION_PROVIDER".to_owned(),
            "youki".to_owned(),
        ),
        (
            "KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS".to_owned(),
            address,
        ),
    ])
}

/// Resolve the path to the `kata-worker` binary. Same lookup
/// order as [`kata_bin_path`].
fn worker_bin_path() -> Result<PathBuf, LiveError> {
    bin_path("kata-worker")
}

/// Internal binary-path resolver. Exposed via the [`testing`] module
/// so the unit tests can pin the missing-binary error path.
#[doc(hidden)]
pub fn bin_path(name: &str) -> Result<PathBuf, LiveError> {
    let candidate = if let Some(dir) = std::env::var_os("KATA_LIVE_BIN_DIR") {
        PathBuf::from(dir).join(name)
    } else {
        workspace_target_release().join(name)
    };
    if candidate.exists() {
        Ok(candidate)
    } else {
        Err(LiveError::BinaryMissing(candidate))
    }
}

/// Walk up from `CARGO_MANIFEST_DIR` (the test-utils crate root)
/// to the workspace root and return `<root>/target/release`.
///
/// `CARGO_MANIFEST_DIR` is `crates/test-utils`; the workspace
/// root is two `parent()` calls above. We don't trust the
/// presence of a `Cargo.toml` at the parent (the worktree layout
/// is identical to the root, but a future restructure shouldn't
/// break this resolver) — we just resolve relative.
#[doc(hidden)]
pub fn workspace_target_release() -> PathBuf {
    // CARGO_MANIFEST_DIR is the directory of the *consuming*
    // crate's Cargo.toml at *compile* time, which for this file
    // is always `crates/test-utils`. So `../../target/release`
    // is the workspace target dir.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest.parent().and_then(Path::parent) {
        Some(root) => root.join("target").join("release"),
        None => PathBuf::from("target/release"),
    }
}

/// The checkout's `workflows/std`, resolved like [`workspace_target_release`]:
/// as an explicit `KATA_STDLIB_DIR` it adds the `kata-factory`, `examples` and
/// `smoke` siblings to a main's library.
fn checkout_stdlib_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest.parent().and_then(Path::parent) {
        Some(root) => root.join("workflows").join("std"),
        None => PathBuf::from("workflows/std"),
    }
}

/// Render a minimal installed-main TOML for one capacity topology.
///
/// Every rendered node is an `oci` node: the harness boots real mains, and a
/// main without a declared `[node] environment` refuses at boot under the
/// shipped profile (`node_environment_undeclared`). The environment pins the
/// same closures `oci_stage_live.rs` and the differential rig bind — busybox,
/// `getent`, `git-minimal` — so a capsule stage resolves the same programs the
/// host does. The worker transport is not an execution provider:
/// the capsule provider itself is provisioned out-of-band by
/// [`NodeHandle::spawn_*`](NodeHandle) via `kata sandbox
/// install-external-provider` plus the `KATA_EXTERNAL_*` exports, exactly as
/// `bin/kata/tests/oci_main_live.rs`'s `provision_provider` does.
///
/// Modelled after `config/kata.example.toml`. A supervised node's main
/// declares a default `shell` agent so its node advertises at least one
/// backend; local-socket capacity is `[agents]` empty by design.
#[doc(hidden)]
pub fn render_node_config(
    capacity_topology: CapacityTopology,
    data_dir: &Path,
    api: SocketAddr,
    worker_sock: Option<&Path>,
    options: &NodeConfigOptions,
) -> String {
    let capacity_label = capacity_topology.id_suffix();
    let id_label = format!("kata-live-{capacity_label}");
    let data_dir_str = data_dir.display();
    let NodeConfigOptions {
        telemetry,
        vcs,
        extra_env: _,
        egress_allow,
        agents_block: agents_override,
    } = options;

    // Worker transport:
    //   * SupervisedNode gets supervised_node (the main starts its node on
    //     `<data_dir>/node.sock`).
    //   * LocalSocket gets local_socket pointed at <data_dir>/worker.sock
    //     so an external WorkerHandle can dial it.
    let workers_block = match worker_sock {
        Some(sock) => format!(
            "[[workers.transports]]\ntype = \"local_socket\"\npath = \"{}\"\n",
            sock.display()
        ),
        None => "[[workers.transports]]\ntype = \"supervised_node\"\n".to_string(),
    };

    // Agents:
    //   * SupervisedNode declares the one `[agents.shell]` entry — the only
    //     backend that needs no model on the host, and the sole entry, so the
    //     node's default — so the supervised node registers `agent:shell`
    //     capability without a model credential. The shell route takes no key;
    //     `adapter` belongs to a model agent's block.
    //   * LocalSocket keeps `[agents]` empty; capabilities come from
    //     external workers.
    let agents_block: &str = agents_override
        .as_deref()
        .unwrap_or(match capacity_topology {
            CapacityTopology::SupervisedNode => "[agents.shell]\n",
            CapacityTopology::LocalSocket => "[agents]\n",
        });

    // The node environment is mandatory under `oci` and never optional here:
    // `kata` refuses to boot a capsule node without one. The pins are the same
    // store paths the live OCI cells declare (`oci_stage_live.rs`,
    // `oci_main_live.rs`); `path_prepend` puts each
    // closure's `bin/` on the environment PATH so a stage that execs `git` or
    // `getent` resolves the bound program.
    let environment_block = live_environment_block(&id_label);

    let egress_block = if egress_allow.is_empty() {
        String::new()
    } else {
        let list = egress_allow
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!("egress_allow = [{list}]\n")
    };

    let telemetry_block = telemetry.as_ref().map_or_else(String::new, |t| {
        format!(
            "\n[telemetry]\n\
             enabled = true\n\
             log_level = \"info\"\n\
             log_json = false\n\
             export = \"{export}\"\n\
             otlp_endpoint = \"{otlp}\"\n\
             metrics_bind = \"{bind}\"\n",
            export = t.export,
            otlp = t.otlp_endpoint,
            bind = t.metrics_bind,
        )
    });
    let vcs_block = vcs.as_ref().map_or_else(String::new, |v| {
        format!(
            "\n[vcs]\n\
             jj_repo = \"{jj_repo}\"\n",
            jj_repo = toml_escape(v.jj_repo.display()),
        )
    });

    format!(
        "[node]\n\
         id = \"{id_label}\"\n\
         data_dir = \"{data_dir_str}\"\n\
         {environment_block}\
         {egress_block}\
         \n\
         [runtime]\n\
         max_concurrent_dispatches = 64\n\
         \n\
         [workers]\n\
         dispatch_deadline_ms = 30000\n\
         heartbeat_interval_ms = 10000\n\
         heartbeat_grace_ms = 30000\n\
         max_workers = 4\n\
         \n\
         {workers_block}\n\
         [api]\n\
         bind = \"{api}\"\n\
         \n\
         [api.auth]\n\
         type = \"disabled\"\n\
         \n\
         {agents_block}\n\
         {telemetry_block}\
         {vcs_block}",
    )
}

fn toml_escape(value: impl std::fmt::Display) -> String {
    value.to_string().replace('\\', "\\\\").replace('"', "\\\"")
}

/// Inverse of `<WorkerResource as FromStr>::from_str`. Renders
/// a capability into the spec string `kata-worker provision
/// --capability <spec>` accepts.
#[doc(hidden)]
pub fn capability_to_spec(cap: &WorkerResource) -> String {
    match cap {
        WorkerResource::Shell => "shell".to_string(),
        WorkerResource::Network => "network".to_string(),
        WorkerResource::AgentBackend(bt) => format!("agent_backend={}", bt.label()),
        WorkerResource::Disk { min_gb } => format!("disk={min_gb}"),
        WorkerResource::Gpu { min_vram_gb } => format!("gpu={min_vram_gb}"),
        WorkerResource::Custom(s) => format!("custom={s}"),
    }
}

/// Poll `<data_dir>/local-worker.secret` every 100 ms up to `timeout`.
///
/// Returns the trimmed file contents on success,
/// [`LiveError::SecretMissing`] on timeout. Empty files are
/// treated as "still being written" — the kata bootstrap helper
/// writes the secret in one `fs::write` call but the kernel
/// does not guarantee atomicity for our reads, so we re-poll.
fn wait_for_enrollment_secret(data_dir: &Path, timeout: Duration) -> Result<String, LiveError> {
    let path = data_dir.join("local-worker.secret");
    let started = Instant::now();
    loop {
        if let Ok(s) = std::fs::read_to_string(&path) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
        if started.elapsed() >= timeout {
            return Err(LiveError::SecretMissing {
                elapsed: started.elapsed(),
                path,
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// SIGTERM the child, wait up to `grace`, escalate to SIGKILL.
///
/// Sync function so it can be called from `Drop` (which has no
/// async context). Async `shutdown()` callers go through here
/// too — the wait loop is a small `thread::sleep` cadence which
/// is acceptable in test code.
///
/// Reaps the child either way to avoid a zombie.
fn terminate_child(child: &mut Child, grace: Duration) -> Result<(), LiveError> {
    // try_wait already exited?
    if let Ok(Some(_)) = child.try_wait() {
        return Ok(());
    }

    let pid_raw = child.id();
    // Linux pids fit in an i32 (PID_MAX_LIMIT is 2^22), so the
    // truncation case is unreachable on a real kernel — but
    // `i32::try_from` keeps clippy::cast_possible_wrap quiet
    // and traps the impossible case as a benign no-op (skip
    // the kill, fall through to escalation, which also no-ops).
    let pid = match i32::try_from(pid_raw) {
        Ok(p) => nix::unistd::Pid::from_raw(p),
        Err(_) => return Ok(()),
    };
    // SIGTERM via `nix::sys::signal::kill` — wraps the libc
    // syscall in a safe API so we don't need `unsafe_code` in
    // this crate. ESRCH (process gone) is non-fatal: the child
    // may have exited between `try_wait` and here.
    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);

    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Escalate. SIGKILL is the only signal that cannot be
    // caught or blocked.
    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    let _ = child.wait();
    Err(LiveError::ShutdownTimeout(grace))
}

fn wait_for_exit(child: &mut Child, grace: Duration) -> Result<(), LiveError> {
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(LiveError::ShutdownTimeout(grace))
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;

    use nix::errno::Errno;
    use nix::fcntl::{Flock, FlockArg};

    use super::*;

    const CHILD_LOCK_PATH: &str = "KATA_TEST_NODE_CONSTRUCTION_LOCK_PATH";
    const CHILD_READY_PATH: &str = "KATA_TEST_NODE_CONSTRUCTION_READY_PATH";

    /// The fixture's termination grace: its children are `sleep`/`sh` stand-ins
    /// that either exit on `SIGTERM` at once or ignore it by design, so a real
    /// main's 15 s would only be waited out in full.
    const FIXTURE_TERMINATION_GRACE: Duration = Duration::from_millis(250);

    /// A fixture node whose health probes answer on `socket`. The child is a
    /// long-lived sleeper by default — `await_healthy` now watches the process
    /// itself, so a fixture that is supposed to stay alive-but-unhealthy needs
    /// a child that is; the `MainExited` test hands in a child that exits.
    /// The sleeper is spawned directly, never under a shell: `sh -c "sleep N"`
    /// forks the sleep as a grandchild, which survives `terminate_child`'s
    /// direct-child kill and orphans onto pid 1 (which the commit-tier gate's
    /// `pgrep-stale-final` catches as leaked `sleep 600` processes).
    fn health_test_node(socket: SocketAddr) -> NodeHandle {
        health_test_node_with_child(socket, Command::new("/bin/sleep").arg("600"))
    }

    fn health_test_node_with_child(socket: SocketAddr, child: &mut Command) -> NodeHandle {
        let harness_dir = create_harness_dir().expect("health fixture harness");
        std::fs::write(harness_dir.path().join("kata.log"), b"private-log-canary")
            .expect("fixture log");
        let api_url = format!("http://{socket}");
        NodeHandle {
            capacity_topology: CapacityTopology::SupervisedNode,
            child: Mutex::new(child.spawn().expect("fixture child")),
            data_dir: DataDirOwnership::Owned(tempfile::tempdir().expect("health fixture data")),
            harness_dir,
            retain_harness_on_drop: AtomicBool::new(false),
            termination_grace: FIXTURE_TERMINATION_GRACE,
            client: KataClient::new(api_url.clone()).expect("fixture client"),
            api_url,
            _api_port: None,
            enrollment_secret: None,
            worker_socket: None,
        }
    }

    /// A main whose process has already exited can never report healthy —
    /// `await_healthy` must answer [`LiveError::MainExited`] at the first poll,
    /// not spend the caller's whole budget on a corpse. Refused boots once each
    /// burned the full 20 s deadline here.
    #[tokio::test]
    async fn await_healthy_answers_main_exited_as_soon_as_the_child_dies() {
        let node = health_test_node_with_child(
            "127.0.0.1:1".parse().unwrap(),
            &mut Command::new("/bin/true"),
        );
        // The child is exiting, if not already exited; a loopback `127.0.0.1:1`
        // health probe would answer connect-refused if it ever ran again.
        let started = Instant::now();
        let result = node.await_healthy(Duration::from_secs(60)).await;
        let error = result.expect_err("a dead main cannot become healthy");
        assert!(
            matches!(error, LiveError::MainExited { .. }),
            "a dead main must end the wait as MainExited, not burn the budget: {error:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the exit must end the wait immediately; took {:?} against a 60 s budget",
            started.elapsed()
        );
        let retained = node.harness_dir.path().to_path_buf();
        drop(node);
        assert!(retained.join("kata.log").is_file());
        std::fs::remove_dir_all(retained).expect("remove only retained exited fixture");
    }

    /// The fixture child must be killed AND reaped when the handle drops, and
    /// must be a leaf process: `terminate_child` reaches only the direct
    /// child, so a shell wrapper's grandchild outlives it and orphans onto
    /// pid 1 — the commit-tier gate's `pgrep-stale-final` catches the
    /// `sleep 600` survivors of a `sh -c "sleep 600"` fixture.
    #[test]
    fn dropped_health_fixture_leaves_no_process_survivor() {
        fn descendants_of(pid: u32) -> Vec<i32> {
            let mut out = Vec::new();
            if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
                for task in tasks.flatten() {
                    if let Ok(children) = std::fs::read_to_string(task.path().join("children")) {
                        out.extend(
                            children
                                .split_whitespace()
                                .filter_map(|p| p.parse::<i32>().ok()),
                        );
                    }
                }
            }
            out
        }
        let node = health_test_node("127.0.0.1:1".parse().unwrap());
        let pid = node.pid();
        // A wrapper's grandchild takes an instant to appear; poll so the
        // check cannot race the fork.
        let mut descendants = descendants_of(pid);
        let deadline = Instant::now() + Duration::from_secs(2);
        while descendants.is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
            descendants = descendants_of(pid);
        }
        drop(node);
        // A red run must still sweep what the fixture left behind — the
        // defect under test is exactly that Drop cannot reach it.
        for grandchild in &descendants {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(*grandchild),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        assert!(
            descendants.is_empty(),
            "fixture child {pid} spawned descendants that Drop cannot reach: {descendants:?}"
        );
        assert!(
            matches!(
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap()),
                    None
                ),
                Err(Errno::ESRCH)
            ),
            "fixture child {pid} survived the handle's drop"
        );
    }

    #[tokio::test]
    async fn health_deadline_refuses_a_late_healthy_response() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let node = health_test_node(listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            tokio::time::sleep(Duration::from_secs(1)).await;
            let body = r#"{"last_updated_millis":1,"subsystems":[["api",{"state":"healthy"}]]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });
        let started = Instant::now();
        let result = node.await_healthy(Duration::from_millis(30)).await;
        server.abort();
        assert!(
            result.is_err(),
            "health success received after deadline was accepted"
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "health request exceeded caller budget by more than scheduling tolerance"
        );
        let retained = node.harness_dir.path().to_path_buf();
        drop(node);
        assert!(retained.join("kata.log").is_file());
        std::fs::remove_dir_all(retained).expect("remove only retained health fixture");
    }

    #[test]
    fn panic_drop_retains_private_harness_log_but_removes_owned_data() {
        let node = health_test_node("127.0.0.1:1".parse().unwrap());
        let retained = node.harness_dir.path().to_path_buf();
        let data_dir = node.data_dir().to_path_buf();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _node = node;
            panic!("injected assertion failure after successful startup");
        }));
        assert!(outcome.is_err());
        assert_eq!(
            std::fs::read(retained.join("kata.log")).expect("panic drop erased diagnostic log"),
            b"private-log-canary"
        );
        assert!(!data_dir.exists(), "panic drop retained owned durable data");
        std::fs::remove_dir_all(retained).expect("remove only retained panic fixture");
    }

    #[tokio::test]
    async fn shutdown_failure_retains_log_after_reaping_a_sigterm_ignoring_child() {
        let mut node = health_test_node("127.0.0.1:1".parse().unwrap());
        {
            let child = node.child.get_mut().expect("live child lock");
            child.kill().expect("kill sleeper fixture child");
            child.wait().expect("reap sleeper fixture child");
        }
        let ready = node.data_dir().join("signal-handler.ready");
        *node.child.get_mut().expect("live child lock") = Command::new("/bin/sh")
            .args([
                "-c",
                "trap '' TERM; printf ready > \"$1\"; exec sleep 60",
                "fixture",
            ])
            .arg(&ready)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn SIGTERM-ignoring child");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ready.exists(), "child did not install SIGTERM ignore");
        let pid = nix::unistd::Pid::from_raw(i32::try_from(node.pid()).unwrap());
        let retained = node.harness_dir.path().to_path_buf();
        let data_dir = node.data_dir().to_path_buf();
        let error = node
            .shutdown()
            .await
            .expect_err("SIGKILL escalation must surface");
        assert!(matches!(
            error,
            LiveError::ShutdownTimeout(FIXTURE_TERMINATION_GRACE)
        ));
        assert!(matches!(
            nix::sys::signal::kill(pid, None),
            Err(Errno::ESRCH)
        ));
        assert_eq!(
            std::fs::read(retained.join("kata.log")).expect("shutdown error erased log"),
            b"private-log-canary"
        );
        assert!(
            !data_dir.exists(),
            "shutdown failure retained owned durable data"
        );
        std::fs::remove_dir_all(retained).expect("remove only retained shutdown fixture");
    }

    /// On a health TIMEOUT the error keeps the last subsystem state kata
    /// observed and the log location, never the private health reason, and the
    /// harness keeps the log while deleting durable data.
    ///
    /// "The last observed state" needs at least one COMPLETED poll inside the
    /// budget. With a 100 ms budget against a fake server that answers ONE
    /// connection, that single poll may not complete under gate load, and the
    /// error honestly reports "no completed health probe" — a red that proves
    /// nothing about the harness. So the fake main answers 503 on EVERY
    /// connection, as a stuck main does, and the budget is
    /// `UNHEALTHY_MAIN_BUDGET`: a single loopback request-response has ample time
    /// to finish, and
    /// the test still ends only by the deadline, never by a healthy answer.
    #[tokio::test]
    async fn health_timeout_keeps_safe_last_state_and_log_location() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        const UNHEALTHY_MAIN_BUDGET: Duration = Duration::from_secs(5);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let node = health_test_node(listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let body = r#"{"last_updated_millis":1,"subsystems":[["storage",{"state":"unavailable","since":1,"reason":"private-health-canary"}]]}"#;
            let response = format!(
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            // A request the client abandoned at the deadline must not end
            // the server: every later poll would then read a refused
            // connection instead of the unhealthy state.
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    continue;
                };
                let mut request = [0; 4096];
                if matches!(socket.read(&mut request).await, Ok(read) if read > 0) {
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            }
        });
        let started = Instant::now();
        let error = node
            .await_healthy(UNHEALTHY_MAIN_BUDGET)
            .await
            .expect_err("unhealthy");
        let waited = started.elapsed();
        server.abort();
        assert!(
            matches!(error, LiveError::HealthTimeout { .. }),
            "an unhealthy main must end in a health timeout: {error:?}"
        );
        assert!(
            waited >= UNHEALTHY_MAIN_BUDGET,
            "the wait ended after {waited:?}, before the {UNHEALTHY_MAIN_BUDGET:?} budget"
        );
        let message = error.to_string();
        assert!(
            message.contains("Storage=unavailable"),
            "last subsystem state lost: {message}"
        );
        assert!(message.contains(&node.log_path().display().to_string()));
        assert!(!format!("{error:?}").contains("private-health-canary"));
        let retained = node.harness_dir.path().to_path_buf();
        let data_dir = node.data_dir().to_path_buf();
        drop(node);
        assert_eq!(
            std::fs::read(retained.join("kata.log")).unwrap(),
            b"private-log-canary"
        );
        assert!(!data_dir.exists(), "health failure retained durable data");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&retained).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        std::fs::remove_dir_all(retained).expect("remove only retained health fixture");
    }

    /// Subprocess entrypoint for the construction-guard regression. The parent
    /// runs only this ignored test in a fresh copy of the unit-test binary.
    #[test]
    #[ignore = "subprocess fixture; invoked by post_spawn_secret_failure_reaps_child_and_releases_authority_lock"]
    fn node_construction_lock_holder_child() {
        let Some(lock_path) = std::env::var_os(CHILD_LOCK_PATH) else {
            return;
        };
        let ready_path = std::env::var_os(CHILD_READY_PATH)
            .expect("construction lock-holder child requires a ready path");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .expect("open construction authority lock");
        let _lock = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .unwrap_or_else(|(_, error)| panic!("acquire construction authority lock: {error}"));
        std::fs::write(ready_path, b"locked\n").expect("publish lock-holder readiness");
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    #[test]
    fn post_spawn_secret_failure_reaps_child_and_releases_authority_lock() {
        let temp = tempfile::tempdir().expect("construction regression tempdir");
        let lock_path = temp.path().join("main.lock");
        let ready_path = temp.path().join("child.ready");
        let child = Command::new(std::env::current_exe().expect("current unit-test binary"))
            .arg("--exact")
            .arg("live::tests::node_construction_lock_holder_child")
            .arg("--ignored")
            .arg("--nocapture")
            .env(CHILD_LOCK_PATH, &lock_path)
            .env(CHILD_READY_PATH, &ready_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn construction lock-holder child");
        let pid = child.id();

        let harness_dir = create_harness_dir().expect("private harness fixture");
        let retained = harness_dir.path().to_path_buf();
        let diagnostic_log = harness_dir.path().join("kata.log");
        std::fs::write(&diagnostic_log, b"private-log-canary").expect("fixture log");
        let result = initialize_spawned_node(child, harness_dir, || -> Result<(), LiveError> {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !ready_path.is_file() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(25));
            }
            assert!(
                ready_path.is_file(),
                "construction lock-holder child did not become ready"
            );

            let contender = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .expect("open authority-lock contender");
            match Flock::lock(contender, FlockArg::LockExclusiveNonblock) {
                Err((_file, Errno::EWOULDBLOCK)) => {}
                Err((_file, error)) => panic!("authority-lock contender failed: {error}"),
                Ok(lock) => {
                    drop(lock);
                    panic!("child did not hold the authority lock")
                }
            }

            Err(LiveError::SecretMissing {
                elapsed: Duration::ZERO,
                path: temp.path().join("injected-local-worker.secret"),
            })
        });
        let error = match result {
            Err(error) => error,
            Ok((mut child, (), _harness_dir)) => {
                let _ = terminate_child(&mut child, NODE_TERMINATION_GRACE);
                panic!("injected post-spawn initialization failure was accepted")
            }
        };
        assert!(
            diagnostic_log.is_file(),
            "constructor failure deleted its diagnostic log"
        );
        assert!(
            error
                .to_string()
                .contains(&diagnostic_log.display().to_string())
        );
        assert!(!format!("{error:?}").contains("private-log-canary"));
        let LiveError::Initialization { source, .. } = &error else {
            panic!("initialization error lost its typed source: {error}");
        };
        assert!(matches!(source.as_ref(), LiveError::SecretMissing { .. }));

        let pid = nix::unistd::Pid::from_raw(i32::try_from(pid).expect("child pid fits i32"));
        assert!(
            matches!(nix::sys::signal::kill(pid, None), Err(Errno::ESRCH)),
            "post-spawn failure returned before child pid {pid} was reaped"
        );

        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .expect("reopen authority lock after cleanup");
        let reacquired = Flock::lock(contender, FlockArg::LockExclusiveNonblock)
            .unwrap_or_else(|(_, error)| panic!("authority lock was not released: {error}"));
        drop(reacquired);
        std::fs::remove_dir_all(retained).expect("remove only retained constructor fixture");
    }
}

/// Test-only re-exports of internal helpers. Hidden from rustdoc and
/// not part of the stable public API — downstream crates must not
/// depend on items here. Exists so `tests/live_tests.rs` can pin the
/// private port-picker, binary-resolver, capability-spec, and
/// config-renderer helpers without leaking them into the public
/// surface.
#[doc(hidden)]
pub mod testing {
    pub use super::{
        NodeConfigOptions, bin_path, capability_to_spec, provision_live_provider,
        render_node_config, workspace_target_release,
    };
}
