//! Configuration types surfaced to the `kata` binary and to every
//! subsystem that needs to read configuration.
//!
//! ## Path expansion
//!
//! Every `PathBuf` field is run through [`expand_tilde`] at load time so
//! operator configs like `data_dir = "~/.kata/data"` resolve against
//! `$HOME` before any subsystem tries to use them. After
//! [`NormalizePaths::normalize_paths`] has run, downstream code may
//! assume **every path in `KataConfig` / `WorkerNodeConfig` is
//! tilde-free and ready to be joined directly**. Only the leading
//! `~/` or a bare `~` is expanded — `$VAR` references are
//! intentionally left literal to avoid leaking env-var semantics into
//! the config schema (recursive expansion + escaping rules are a pit
//! of snakes and out of scope).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{KataError, KataResult};
use crate::identity::WorkerResource;

pub const DEFAULT_MAX_ACTIVE_EXECUTIONS: usize = 1_024;
pub const DEFAULT_MAX_ACTIVE_EXECUTION_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_ACTIVE_EXECUTIONS: usize = 16_384;
pub const MAX_ACTIVE_EXECUTION_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Presence-only process marker that disables ancestor `.env` discovery.
///
/// Set this in the launching environment, not inside `.env`: both production
/// entrypoints consult it before calling `dotenvy` and ignore its value.
pub const KATA_NO_DOTENV: &str = "KATA_NO_DOTENV";

/// Whether an ordinary Kata process may load an operator-local `.env`.
#[must_use]
pub fn operator_dotenv_enabled() -> bool {
    std::env::var_os(KATA_NO_DOTENV).is_none()
}

/// Expand a leading `~/` or a bare `~` to `$HOME`.
///
/// Returns the input unchanged when:
/// - the path does not begin with `~`,
/// - `$HOME` is unset or empty (deterministic fallback; never panics),
/// - the `~` is embedded mid-path (e.g. `/opt/~-dir`) — only leading
///   tildes are expanded, matching POSIX shell behavior.
///
/// Env-var expansion (`$VAR`, `${VAR}`) is intentionally out of scope.
#[must_use]
pub fn expand_tilde(path: &Path) -> PathBuf {
    expand_tilde_with(path, home_dir_os().as_deref())
}

/// Like [`expand_tilde`] but with an explicit `home` override. Exposed
/// primarily for tests that need to exercise the "no HOME" path
/// without mutating process-wide env vars (the crate
/// `#![forbid(unsafe_code)]`s, and `std::env::set_var` is unsafe in
/// Rust 2024). Pass `None` to simulate `$HOME` being unset.
#[must_use]
pub fn expand_tilde_with(path: &Path, home: Option<&std::ffi::OsStr>) -> PathBuf {
    let s = path.to_string_lossy();
    if s == "~" {
        if let Some(h) = home {
            return PathBuf::from(h);
        }
        return path.to_path_buf();
    }
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(h) = home
    {
        return PathBuf::from(h).join(rest);
    }
    path.to_path_buf()
}

fn home_dir_os() -> Option<std::ffi::OsString> {
    std::env::var_os("HOME").filter(|h| !h.is_empty())
}

/// In-place tilde expansion on every path field of a config section.
///
/// This runs at [`load_config_placeholder`] /
/// [`load_worker_config`] — and, at the binary-crate edge, in
/// `ConfigManager::load` — so every subsystem observes tilde-free
/// paths. Downstream code (the capsule route, the worker daemon) may assume
/// this contract without re-checking.
pub trait NormalizePaths {
    /// Replace every `PathBuf` / path-shaped string in `self` with its
    /// tilde-expanded form. Idempotent: a second call is a no-op
    /// because [`expand_tilde`] is the identity on absolute / relative
    /// paths that don't begin with `~`.
    fn normalize_paths(&mut self);
}

/// The node's identity, data root and declared runtime environment.
///
/// Every stage on this node is a capsule: the dispatcher authorizes an
/// occurrence, publishes a capsule and hands the worker a reference to it, and
/// the worker runs that capsule in a rootless container. A node without its
/// declared `[node] environment` refuses to boot by name
/// (`node_environment_undeclared`) — see [`Self::required_environment`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Stable node identifier. Free-form string; operators pick it.
    pub id: String,
    /// Root directory for persistent state (storage, identity keys,
    /// per-agent worktrees).
    pub data_dir: PathBuf,
    /// The ONE Nix closure every capsule stage on this node runs in.
    /// See [`NodeEnvironmentConfig`].
    ///
    /// **Consumed:** `bin/kata` boot declares and promotes it through
    /// `kata_core::environment::bind_node_environment` before the node reports ready,
    /// and hands the bound id to `Dispatcher::with_node_environment`, which is what the
    /// capsule submit path selects for every stage. REQUIRED on every node —
    /// [`Self::required_environment`] refuses boot without it.
    #[serde(default)]
    pub environment: Option<NodeEnvironmentConfig>,
    /// `[node] output_bytes_ceiling` — the largest `output_bytes=` an authored
    /// stage may name on this node. Default 1 GiB
    /// ([`crate::execution_contract::NODE_OUTPUT_BYTES_CEILING`]); a stage over
    /// it is refused at admission, naming the stage, field, value and ceiling.
    #[serde(default = "default_output_bytes_ceiling")]
    pub output_bytes_ceiling: u64,
    /// `[node] work_delta_bytes_ceiling` — the largest authored
    /// `work_delta_bytes=`. Default 1 GiB.
    #[serde(default = "default_work_delta_bytes_ceiling")]
    pub work_delta_bytes_ceiling: u64,
    /// `[node] work_delta_entries_ceiling` — the largest authored
    /// `work_delta_entries=`. Default 100_000.
    #[serde(default = "default_work_delta_entries_ceiling")]
    pub work_delta_entries_ceiling: u32,
    /// `[node] capsule_memory_bytes_ceiling` — this node's bound on the
    /// memory box a capsule may RECORD: the authored `memory_mb` or the
    /// assembly's 512 MiB default, which is exactly what `capsule_assembly`
    /// writes into the capsule.
    /// Admission refuses an exceeding stage by name
    /// (`capsule_budget_over_node_ceiling`), naming which of the two exceeds,
    /// the bound and this knob. ABSENT (the default) declares no ceiling: a
    /// 1.5 GiB shipped default would refuse an ordinary 4 GiB build stage, and
    /// kata never invents an operator bound.
    #[serde(default)]
    pub capsule_memory_bytes_ceiling: Option<u64>,
    /// `[node] capsule_process_count_ceiling` — the same bound on the
    /// `pids.max` a capsule may record. Nothing authors a process bound, so
    /// the recorded bound is always the assembly's 64-process default, and a
    /// ceiling under it refuses every capsule stage
    /// (`capsule_budget_over_node_ceiling`). ABSENT (the default) declares no
    /// ceiling.
    #[serde(default)]
    pub capsule_process_count_ceiling: Option<u32>,
    /// The `/work` INPUT ceiling in member bytes. The committed
    /// base tree an isolated `oci` execution publishes at admission is refused
    /// (`work_tree_base_bound_exceeded`) when its members total more than this.
    ///
    /// **Consumed:** `bin/kata` boot hands it (with `work_tree_max_entries`) to
    /// `WorkflowExecutor::with_work_tree_input_bounds`, and the admission-time base-tree
    /// publication enforces it. INPUT bound only — capsule RESULT budgets
    /// (`result_bytes`/`result_entries`) and their author-overridable deltas are a
    /// separate class and do not read this.
    ///
    /// Default 1 GiB ([`crate::tree_artifact::DEFAULT_WORK_TREE_MAX_BYTES`]).
    #[serde(default = "default_work_tree_max_bytes")]
    pub work_tree_max_bytes: u64,
    /// The `/work` INPUT ceiling in manifest entries — the other half of the input bound.
    /// A committed base tree holding more entries is refused at admission.
    ///
    /// **Consumed:** same wiring as [`Self::work_tree_max_bytes`].
    ///
    /// Default 100 000 ([`crate::tree_artifact::DEFAULT_WORK_TREE_MAX_ENTRIES`]) — and
    /// `TreeManifest::MAXIMUM_ENCODED_BYTES` is sized so the largest entry-admitted tree
    /// still encodes inside it (proved by
    /// `a_hundred_thousand_entry_manifest_stays_under_the_encoding_ceiling`).
    #[serde(default = "default_work_tree_max_entries")]
    pub work_tree_max_entries: u64,
    /// `[node] egress_allow` — the EXACT `host:port` authorities a stage's
    /// authored `net = "host"` may reach through the worker-owned proxy under
    /// the `oci` profile. Under `oci` `net = "host"` is NOT unrestricted host
    /// networking: the capsule's only route out is the worker's allowlisting
    /// CONNECT proxy, and this list is what an authored `host` posture names.
    /// A stage's allowlist is exactly this set, an agent stage's included: an
    /// agent's model calls leave from the process hosting the worker, never
    /// from its capsule. A `net = "host"` stage whose effective allowlist is
    /// EMPTY is refused at CHECK (`egress_undeclared`) — `net = "offline"` is
    /// the spelling for no egress, and an empty allowlist is `Offline` by
    /// construction, never `Egress{∅}`.
    ///
    /// Every entry is parsed through
    /// [`crate::execution_contract::EgressAuthority::from_authority_str`] at
    /// config load ([`KataConfig::validate`]), so a misspelled authority is a
    /// boot refusal, not a silently-absent allowlist entry.
    ///
    /// **Consumed:** `bin/kata` boot installs the parsed set through
    /// `kata_types::node_profile::install_node_egress_allow`; the `oci` CHECK
    /// (`egress_undeclared` on an empty effective allowlist) and capsule
    /// assembly (`CapsuleNetwork::Egress`) read it from there.
    #[serde(default)]
    pub egress_allow: Vec<String>,
}

fn default_work_tree_max_bytes() -> u64 {
    crate::tree_artifact::DEFAULT_WORK_TREE_MAX_BYTES
}

fn default_work_tree_max_entries() -> u64 {
    crate::tree_artifact::DEFAULT_WORK_TREE_MAX_ENTRIES
}

fn default_output_bytes_ceiling() -> u64 {
    crate::execution_contract::NODE_OUTPUT_BYTES_CEILING
}

fn default_work_delta_bytes_ceiling() -> u64 {
    crate::execution_contract::NODE_WORK_DELTA_BYTES_CEILING
}

fn default_work_delta_entries_ceiling() -> u32 {
    crate::execution_contract::NODE_WORK_DELTA_ENTRIES_CEILING
}

/// The refusal token for an `oci` node whose `[workers] assignment_start_deadline_ms` is
/// `0`: the start deadline is the only settlement leg for a capsule that is delivered and
/// never starts, so the `oci` profile refuses to run with it disabled.
pub const CAPSULE_START_DEADLINE_DISABLED: &str = "capsule_start_deadline_disabled";

/// The refusal token for a config whose `[workers] dispatch_deadline_ms` is `0`: the
/// delivery door joins each capsule send's own task under that deadline, and at `0` the
/// join gives up at the runtime timer's next tick, so a healthy send to an idle worker
/// that has to wait at all is settled PROVEN AMBIGUOUS.
pub const DISPATCH_DEADLINE_DISABLED: &str = "dispatch_deadline_disabled";

/// The refusal token for a config whose `[workers] heartbeat_interval_ms` is `0`: the
/// main's heartbeat sweep and its deadline sweep both tick at that interval, and a tokio
/// interval of zero panics inside their spawned tasks, so the main would run with no
/// worker-liveness leg and no deadline leg at all.
pub const HEARTBEAT_INTERVAL_DISABLED: &str = "heartbeat_interval_disabled";

/// The refusal token for a config whose `[workers] heartbeat_grace_ms` is shorter than its
/// `heartbeat_interval_ms`. A worker beats every half interval, and a stall of the main's
/// sweep is charged to it as at most one interval of silence; a grace of at least one
/// interval is what leaves every beat half an interval of its own delay on top of such a
/// stall before a live worker would be settled dead (`kata_transport::heartbeat`).
pub const HEARTBEAT_GRACE_BELOW_INTERVAL: &str = "heartbeat_grace_below_interval";

/// The refusal token for an `oci` node that declares no `[node] environment`.
pub const NODE_ENVIRONMENT_UNDECLARED: &str = "node_environment_undeclared";

/// The prefix that starts a command in a cgroup delegated to the operator.
///
/// kata places each container's cgroup inside the one it runs in, so `kata host
/// setup` and `kata serve` refuse from an undelegated login shell. Every recourse
/// kata prints that tells an operator to run either carries this in front.
pub const DELEGATED_SCOPE: &str = "systemd-run --user --scope -p Delegate=yes --";

impl NodeConfig {
    /// The node environment this node REQUIRES, or a refusal at boot.
    ///
    /// # Refused set
    ///
    /// Exactly one case: no `environment` declared
    /// ([`NODE_ENVIRONMENT_UNDECLARED`]). A capsule binds a closure by id, and a pack may
    /// not name a machine's facts, so the only author of "which closure do this node's
    /// stages run in" is this key; refusing at BOOT rather than at the first dispatch
    /// means an operator meets it before any execution is admitted.
    ///
    /// # Errors
    ///
    /// [`KataError::Config`] naming [`NODE_ENVIRONMENT_UNDECLARED`].
    pub fn required_environment(&self) -> crate::error::KataResult<&NodeEnvironmentConfig> {
        self.environment.as_ref().ok_or_else(|| {
            crate::error::KataError::Config(format!(
                // kata-spacing: intentional
                "{NODE_ENVIRONMENT_UNDECLARED}: this node runs every \
                 stage as a capsule bound to ONE declared Nix closure, and it \
                 declares none — kata will not invent one. Declare a `[node.environment]` \
                 table with label, system, nixpkgs_attribute, store_paths, and \
                 integrity_policy — the operator guide's `Execution profiles` section \
                 walks the declaration, and `{DELEGATED_SCOPE} kata host setup` writes \
                 one end to end"
            ))
        })
    }
}

/// `[node] environment` — the Nix closure this node DECLARES at boot.
///
/// # Why store paths and not a flake reference
///
/// The environment plane's own rule (`kata_types::nix_environment::Provenance`): a
/// flake reference is resolved to store paths BEFORE a declaration exists. Resolving one
/// at boot would make a node's start depend on a registry and a network, and would make
/// the environment id a function of WHEN the node booted (a flake ref moves), which is
/// the opposite of "idempotent re-boot, same id". The operator realises the closure
/// (`nix build --no-link --print-out-paths <ref>`) and declares the paths; kata inherits
/// that answer and refuses a path the store does not hold.
///
/// Every field folds into the environment id through the manifest, so changing any of
/// them is a NEW environment — which a node with a live previous one refuses at boot
/// (`node_environment_superseded`) rather than choosing between.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEnvironmentConfig {
    /// The operator-facing label, recorded in the manifest.
    pub label: String,
    /// The Nix system double the closure was realised for (`x86_64-linux`). Refused at
    /// boot unless it is this node's own (`node_environment_platform_mismatch`).
    pub system: String,
    /// The nixpkgs attribute the paths were realised from — provenance, recorded.
    pub nixpkgs_attribute: smol_str::SmolStr,
    /// The closure's ROOTS. Each must already be valid in the node's Nix store.
    pub store_paths: Vec<crate::nix_environment::StorePath>,
    /// `PATH` entries inside the closure, in order.
    #[serde(default)]
    pub path_prepend: Vec<crate::execution_contract::GuestPath>,
    /// What kata requires before it binds the closure's bytes.
    pub integrity_policy: crate::nix_environment::IntegrityPolicy,
}

impl NormalizePaths for NodeConfig {
    fn normalize_paths(&mut self) {
        self.data_dir = expand_tilde(&self.data_dir);
    }
}

/// Runtime tunables. Every field has a conservative default and every field is
/// `#[serde(default)]`, so a `[runtime]` section may set ONE key and omit the
/// rest; see `docs/architecture/0001-replacement-architecture.md` for the canonical definitions.
///
/// Any field added here MUST carry `#[serde(default = "…")]`: a required field
/// would make the documented minimal `[runtime]` example fail to parse on a key it
/// never mentions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Maximum number of fresh worker-dispatch SUBMISSIONS the main runs
    /// concurrently (admission control).
    ///
    /// **Consumed**: wired to the dispatcher's admission-control
    /// semaphore via `Dispatcher::with_max_concurrent_dispatches` at boot. Once
    /// this many submissions are in flight the next one QUEUES on the semaphore
    /// (graceful backpressure) rather than convoying on the ledger
    /// connection-mutex under a wide fan-out. Tracked in the
    /// [`runtime_knob_registry`] with a matching [`KnobStatus::Consumed`] marker.
    /// Saturation is observable as the `kata_dispatch_permits_available` gauge.
    ///
    /// # What this does NOT bound
    ///
    /// It does **not** bound concurrently RUNNING stages. The permit is held
    /// only across the dispatcher's insert+dispatch critical section and is
    /// released when that call returns; the worker then runs the stage
    /// asynchronously, off the permit. A worker also executes strictly one
    /// assignment at a time, so on the default single-worker topology the
    /// number of running stages is 1 regardless of this value.
    ///
    /// The mechanism that bounds running stages is `workflow(max_concurrency=N)`
    /// in Starlark — per-execution, author-time, and resume-safe because it
    /// recounts the durable chain each pass rather than trusting an in-memory
    /// counter. There is no operator-level running-stage ceiling.
    #[serde(default = "default_max_concurrent_dispatches")]
    pub max_concurrent_dispatches: usize,
    /// Maximum number of non-terminal workflow executions resident on this main.
    #[serde(default = "default_max_active_executions")]
    pub max_active_executions: usize,
    /// Maximum aggregate canonical checked-program plus invocation bytes held by
    /// non-terminal workflow executions. This does not claim to bound runner
    /// graphs or process RSS.
    #[serde(default = "default_max_active_execution_bytes")]
    pub max_active_execution_bytes: u64,
    /// Age (seconds) after which a terminal execution's jj execution workspace
    /// (`<repo>/agents/<exec_id>`) becomes eligible for reclaim by the main's
    /// terminal-workspace reaper (`kata_effects_contract::TerminalWorkspaceReapPolicy`'s
    /// `terminal_ttl`; an execution with no lifecycle record waits
    /// `max(workspace_ttl_secs, ledger_ttl_secs)`). Omitting the field yields the
    /// default 24h. The reaper runs at startup and once per hour and never
    /// reclaims a live execution's workspace.
    #[serde(default = "default_workspace_ttl_secs")]
    pub workspace_ttl_secs: u64,
    /// This node's MEMOISED-SPEND bound: the maximum AGE of
    /// a model-reuse SOURCE kata will SERVE.
    ///
    /// **Consumed:** `bin/kata` boot installs it on the stage-cache store
    /// (`SqliteWorkflowStore::with_model_reuse_max_age`), and the capsule reuse
    /// consult (`WorkflowRunner::consult_capsule_reuse`) applies it to a stage
    /// that authored `cache_policy = "model_reuse"`: a source occurrence whose
    /// ACCEPTANCE (`occurrences.accepted_at_ms`) is older than the bound is not
    /// adopted, and the stage runs its own turn.
    ///
    /// Model reuse is MEMOISED SPEND, not a content cache: it claims *"this exact
    /// question was already paid for"* and never *"this would produce the same
    /// output"*. Half of an agent's behaviour surface is REMOTE — a vendor's
    /// feature flags and model endpoint — and kata cannot key it. An input that
    /// cannot be keyed is bounded in TIME instead, which is what this knob is.
    /// The age is the source's own, so re-recording the hint never restarts it.
    ///
    /// PER-NODE and not per-backend: the exposure is a remote
    /// surface that no backend label partitions.
    ///
    /// Spellings: a positive number of seconds; `0` (or an absent key) for the
    /// engine default of 7 days; the string `"unbounded"` to serve a source of
    /// any age. Anything else refuses the config at load. It bounds only what is
    /// SERVED — nothing is deleted, because a durable engine does not destroy
    /// evidence a replay may need — and only the model-reuse regime: a
    /// `content_cache` source of any age is still served, because its key
    /// commits to the bytes that produced it and its age carries no information.
    #[serde(default)]
    pub model_reuse_max_age_secs: ModelReuseMaxAge,
    /// Ledger-retention age in seconds. kata deletes no ledger rows: there is no
    /// atomic retention contract across a run's dependent assets yet, so a
    /// nonzero value emits a retained-state warning at boot rather than arming a
    /// compactor. It also bounds terminal-workspace reaping: an execution whose
    /// liveness is unknown waits `max(workspace_ttl_secs, ledger_ttl_secs)`.
    #[serde(default = "default_ledger_ttl_secs")]
    pub ledger_ttl_secs: u64,
    /// Per-namespace live-object bound for the native memory plane's
    /// deterministic compaction processor. When a namespace (memory scope)
    /// accumulates more than this many live (non-terminal) objects, the oldest
    /// overflow entries are folded into a single per-namespace `Summary` object
    /// and evicted, so a long factory run keeps bounded per-namespace memory
    /// growth. Omitting the field yields the default 512. Setting to 0 DISABLES
    /// folding (unbounded growth — not recommended).
    #[serde(default = "default_memory_compaction_max_live_per_namespace")]
    pub memory_compaction_max_live_per_namespace: usize,
    /// Write-threshold cadence for the memory compaction processor. The
    /// native memory store runs a compaction pass automatically after this many
    /// successful writes. Omitting the field yields the default 256. Setting to 0
    /// DISABLES the automatic cadence.
    #[serde(default = "default_memory_compaction_write_interval")]
    pub memory_compaction_write_interval: usize,
}

/// The single reconciled default for the dispatch admission cap.
///
/// 256 is the value every config that omits the key receives, and the section it
/// bounds is a short non-blocking insert+dispatch: a high cap costs nothing
/// while a low one needlessly serializes a wide fan-out's SUBMISSION. The cap
/// exists to stop the ledger connection-mutex convoy, not to ration execution.
fn default_max_concurrent_dispatches() -> usize {
    256
}

fn default_max_active_executions() -> usize {
    DEFAULT_MAX_ACTIVE_EXECUTIONS
}

fn default_max_active_execution_bytes() -> u64 {
    DEFAULT_MAX_ACTIVE_EXECUTION_BYTES
}

fn default_memory_compaction_max_live_per_namespace() -> usize {
    512
}

fn default_memory_compaction_write_interval() -> usize {
    256
}

fn default_workspace_ttl_secs() -> u64 {
    86_400 // 24 hours
}

/// The node's memoised-spend bound, as an operator writes
/// it in `[runtime]`.
///
/// Three spellings, because `0` and `"unbounded"` are DIFFERENT answers and a
/// bare integer cannot carry both: `0` means *"I did not choose"* and takes the
/// engine default, while `"unbounded"` means *"I chose no bound"*. Collapsing
/// them would make an operator's explicit decision indistinguishable from an
/// unset key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ModelReuseMaxAge {
    /// No value, or `0` — take [`DEFAULT_MODEL_REUSE_MAX_AGE_SECS`].
    #[default]
    Default,
    /// `"unbounded"` — serve a model-reuse source of any age.
    Unbounded,
    /// An explicit positive number of seconds.
    Secs(u64),
}

/// Stated as a JUDGEMENT: nothing has measured how long a memoised entry stays
/// useful. Seven days is the shortest window that spans a working week.
pub const DEFAULT_MODEL_REUSE_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

impl ModelReuseMaxAge {
    /// The bound in MILLISECONDS, or `None` for unbounded.
    #[must_use]
    pub fn max_age_ms(self) -> Option<i64> {
        let secs = match self {
            Self::Unbounded => return None,
            Self::Default => DEFAULT_MODEL_REUSE_MAX_AGE_SECS,
            Self::Secs(secs) => secs,
        };
        // Saturating on both hops: an operator who writes a nonsense-large
        // seconds value gets "effectively unbounded", never a wrapped negative
        // bound that would refuse every source.
        Some(i64::try_from(secs.saturating_mul(1_000)).unwrap_or(i64::MAX))
    }

    /// Whether a source `age_ms` old may still be served: its age is AT MOST the bound
    /// (a source exactly as old as the bound is served), and any age is served when
    /// unbounded.
    #[must_use]
    pub fn admits_age_ms(self, age_ms: i64) -> bool {
        self.max_age_ms()
            .is_none_or(|max_age_ms| age_ms <= max_age_ms)
    }
}

impl Serialize for ModelReuseMaxAge {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Default => ser.serialize_u64(0),
            Self::Unbounded => ser.serialize_str(MODEL_REUSE_UNBOUNDED),
            Self::Secs(secs) => ser.serialize_u64(*secs),
        }
    }
}

/// The one word `[runtime] model_reuse_max_age_secs` accepts.
const MODEL_REUSE_UNBOUNDED: &str = "unbounded";

impl<'de> Deserialize<'de> for ModelReuseMaxAge {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = ModelReuseMaxAge;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "runtime.model_reuse_max_age_secs: a non-negative whole number of seconds \
                     (0 for the {DEFAULT_MODEL_REUSE_MAX_AGE_SECS}s default) or the string \
                     \"{MODEL_REUSE_UNBOUNDED}\""
                )
            }

            fn visit_u64<E: serde::de::Error>(self, secs: u64) -> Result<Self::Value, E> {
                Ok(match secs {
                    0 => ModelReuseMaxAge::Default,
                    secs => ModelReuseMaxAge::Secs(secs),
                })
            }

            fn visit_i64<E: serde::de::Error>(self, secs: i64) -> Result<Self::Value, E> {
                u64::try_from(secs)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Signed(secs), &self))
                    .and_then(|secs| self.visit_u64(secs))
            }

            fn visit_str<E: serde::de::Error>(self, word: &str) -> Result<Self::Value, E> {
                if word == MODEL_REUSE_UNBOUNDED {
                    Ok(ModelReuseMaxAge::Unbounded)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Str(word), &self))
                }
            }
        }
        de.deserialize_any(Visitor)
    }
}

fn default_ledger_ttl_secs() -> u64 {
    0 // retention unavailable until durable top-level workflow terminality exists
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_concurrent_dispatches: default_max_concurrent_dispatches(),
            max_active_executions: default_max_active_executions(),
            max_active_execution_bytes: default_max_active_execution_bytes(),
            workspace_ttl_secs: default_workspace_ttl_secs(),
            model_reuse_max_age_secs: ModelReuseMaxAge::Default,
            ledger_ttl_secs: default_ledger_ttl_secs(),
            memory_compaction_max_live_per_namespace:
                default_memory_compaction_max_live_per_namespace(),
            memory_compaction_write_interval: default_memory_compaction_write_interval(),
        }
    }
}

/// Per-worker-transport configuration: how the main obtains execution
/// capacity. A worker is always a separate process; the main hosts none.
///
/// Deserialized through [`WorkerTransportSpelling`], so a `type = "in_process"`
/// table is refused by name with its recourse
/// ([`WORKER_TRANSPORT_IN_PROCESS_REMOVED`]) rather than told it is unknown, and
/// an unknown type's refusal lists only the two types that exist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerTransportConfig {
    /// A `kata-worker` the main starts beside itself and starts again when it
    /// ends, dialing the main-owned socket `<data_dir>/node.sock`.
    SupervisedNode {},
    /// Unix domain socket the main listens on for `kata-worker` daemons the
    /// operator starts. Same-machine only.
    LocalSocket {
        /// Path to the Unix socket.
        path: PathBuf,
    },
}

/// The two transport types a config may spell, closed.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerTransportSpelling {
    SupervisedNode {},
    LocalSocket { path: PathBuf },
}

/// The refusal of a `type = "in_process"` transport, with its recourse.
pub const WORKER_TRANSPORT_IN_PROCESS_REMOVED: &str = "worker_transport_in_process_removed: \
     `type = \"in_process\"` is removed: the main hosts no worker, a worker is always a \
     separate `kata-worker` process. Declare `{ type = \"supervised_node\" }` for `kata serve` \
     to start and supervise one beside it, or `{ type = \"local_socket\", path = \
     \"<data_dir>/<name>\" }` for `kata-worker` daemons you start yourself";

/// Refused set: exactly a transport table whose `type` is the string
/// `"in_process"`, whatever else it holds. Every other table is decoded by
/// [`WorkerTransportSpelling`], which refuses an unknown type or key by name.
impl<'de> Deserialize<'de> for WorkerTransportConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let table = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        if table.get("type").and_then(serde_json::Value::as_str) == Some("in_process") {
            return Err(serde::de::Error::custom(
                WORKER_TRANSPORT_IN_PROCESS_REMOVED,
            ));
        }
        match WorkerTransportSpelling::deserialize(serde_json::Value::Object(table))
            .map_err(serde::de::Error::custom)?
        {
            WorkerTransportSpelling::SupervisedNode {} => Ok(Self::SupervisedNode {}),
            WorkerTransportSpelling::LocalSocket { path } => Ok(Self::LocalSocket { path }),
        }
    }
}

impl NormalizePaths for WorkerTransportConfig {
    fn normalize_paths(&mut self) {
        match self {
            WorkerTransportConfig::SupervisedNode {} => {}
            WorkerTransportConfig::LocalSocket { path } => {
                *path = expand_tilde(path);
            }
        }
    }
}

/// Worker-pool configuration owned by the main.
///
/// **This section is where a per-worker in-flight cap would go, and there
/// deliberately is not one.** Concurrency is a CONFIG surface, not an authoring
/// surface: DEPLOYMENT, never contract. So a cap,
/// if one is ever adopted, is a key here or on [`RuntimeConfig`] beside
/// `max_concurrent_dispatches` — never a `.star`
/// attribute, because a workflow pulled off a shelf must not carry the
/// concurrency of the box it was written on.
///
/// That settles WHERE a cap would live, not that one ships. The backlog a cap
/// would bound is countable per worker, split by whether the worker has
/// acknowledged the work, as `kata_worker_inflight_depth` — see
/// `Dispatcher::record_queue_plane_metrics` in `kata-workflow` — so a ceiling
/// proposed on this struct could be tuned against a reading that exists. That
/// gauge is not a decision to ship one.
///
/// # Which shapes the consumed-knob rule below actually reaches
///
/// An untunable cap landing HERE — a new top-level serde field on this struct —
/// is refused by the consumed-knob guard: this bag has a
/// [`workers_knob_registry`] cross-checked against its serde surface, so an
/// UNCLASSIFIED field fails `just test-crate types` AND `kata config check` via
/// [`KataConfig::validate`]. The same holds for [`RuntimeConfig`].
///
/// It does NOT hold for a PER-TRANSPORT cap — the two shipped transports
/// backpressure at wildly different depths, so the natural
/// place for a ceiling is inside a [`WorkerTransportConfig`] variant. [`KnobStatus`]
/// says so in its own doc: the guard is **non-recursive**, and
/// `WorkerTransportConfig` fields are named there as explicitly out of scope. A
/// cap added there would be inert and silent, and the guard would not say a
/// word. That
/// is an argument for putting one here if it ever ships — not evidence that the
/// guard already forbids the alternative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPoolConfig {
    /// Enabled transports.
    pub transports: Vec<WorkerTransportConfig>,
    /// Send-side dispatch deadline: how long the main waits for the
    /// selected worker transport to take a capsule frame. A send still pending at
    /// the deadline on a worker that holds no started attempt settles its attempt
    /// PROVEN AMBIGUOUS (the write is not cancelled, so the frame may still reach
    /// the worker); a send queued behind a running attempt keeps waiting without
    /// holding up the dispatcher. 0 is refused at load ([`DISPATCH_DEADLINE_DISABLED`]).
    pub dispatch_deadline_ms: u64,
    /// Queue/start deadline: how long a dispatched attempt may
    /// remain accepted by a worker but not yet started. 0 is REFUSED
    /// ([`CAPSULE_START_DEADLINE_DISABLED`]). This is intentionally separate from per-stage
    /// `timeout_ms`, which counts execution time after a start
    /// checkpoint.
    #[serde(default = "default_assignment_start_deadline_ms")]
    pub assignment_start_deadline_ms: u64,
    /// Heartbeat interval: the period of the main's heartbeat sweep and of its
    /// deadline sweep, and twice the period every worker of this main heartbeats
    /// at (`kata_transport::heartbeat::worker_send_period`, bound into a daemon's
    /// enrollment). 0 is refused at load ([`HEARTBEAT_INTERVAL_DISABLED`]).
    pub heartbeat_interval_ms: u64,
    /// How much observed silence past `heartbeat_interval_ms` before a worker is
    /// marked dead and its in-flight attempts settled. Shorter than
    /// `heartbeat_interval_ms` is refused at load
    /// ([`HEARTBEAT_GRACE_BELOW_INTERVAL`]).
    pub heartbeat_grace_ms: u64,
    /// Maximum workers this main will admit. With a `supervised_node`
    /// transport one slot is the node's own, admitted only through
    /// `node.sock`; every `local_socket` path shares the rest.
    pub max_workers: u32,
}

fn default_assignment_start_deadline_ms() -> u64 {
    900_000
}

fn default_dispatch_deadline_ms() -> u64 {
    30_000
}

/// Explicit recovery source. Authentication remains in the operator's Git
/// credential helper/SSH agent; neither this URL nor its identity is a secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRemoteConfig {
    pub id: String,
    pub url: String,
}

/// Shared by configuration admission and isolated Git recovery. Refuse embedded
/// credentials before even an ordinary config-bundling snapshot can copy them.
pub fn validate_recovery_remote_binding(id: &str, url: &str) -> KataResult<()> {
    let refuse = || {
        KataError::Validation("invalid recovery remote binding; use a bounded non-secret identity and explicit URL without embedded credentials".into())
    };
    if id.is_empty()
        || id.len() > 256
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || url.is_empty()
        || url.len() > 8192
        || url.starts_with('-')
        || url.bytes().any(|b| b.is_ascii_control())
        || url.contains('?')
        || url.contains('#')
    {
        return Err(refuse());
    }
    if let Some((scheme, rest)) = url.split_once("://") {
        if !matches!(scheme, "file" | "https" | "http" | "ssh" | "git")
            || rest.split('/').next().is_some_and(|authority| {
                authority
                    .split_once('@')
                    .is_some_and(|(user, _)| scheme != "ssh" || user.contains(':'))
            })
        {
            return Err(refuse());
        }
    } else if !Path::new(url).is_absolute()
        && !url.split_once(':').is_some_and(|(host, path)| {
            !host.is_empty()
                && !host.contains('/')
                && !host.contains(':')
                && !path.is_empty()
                && !path.starts_with(':')
        })
    {
        return Err(refuse());
    }
    Ok(())
}

impl std::fmt::Debug for RecoveryRemoteConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryRemoteConfig")
            .field("id", &self.id)
            .field("url", &"<operator binding>")
            .finish()
    }
}

/// VCS and execution-workspace configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VcsConfig {
    /// Config-relative root of the repository the jj execution-workspace
    /// provider adopts — the installed main's repository authority; process CWD
    /// is never consulted. jj is the only execution-workspace backend.
    pub jj_repo: PathBuf,
    /// Recovery uses only this explicitly selected Git-backed remote, never
    /// ambient `origin` or a local repository object-cache fallback.
    pub recovery_remote: Option<RecoveryRemoteConfig>,
    /// The branch kata forks execution workspaces from and lands them onto —
    /// THE OPERATOR'S ANSWER, and rank 1 of `kata_vcs::trunk::resolve_trunk`'s
    /// precedence.
    ///
    /// Absent by default and there is NO fallback literal: absent means "ask
    /// this repository", never "assume `main`". When the repository answers
    /// unambiguously (its remote's `HEAD` names a default, or it holds exactly
    /// one branch kata did not create) kata inherits that and this key is
    /// unnecessary. When it does not, kata REFUSES and names this key —
    /// forking an agent from the wrong base spends real budget before anything
    /// notices, so guessing is not a degraded mode.
    ///
    /// Set it on any repository with several long-lived branches and no
    /// `refs/remotes/origin/HEAD`.
    #[serde(default)]
    pub trunk: Option<String>,
    /// Master switch for kata-triggered jj op-log GC. ON by default.
    ///
    /// HEAD-move imports, fork churn, and land/promote traffic each publish a
    /// jj operation-log entry, so a long-lived adopted repo grows the op-log
    /// (and its transitively-reachable commit/tree objects) unboundedly. With
    /// this ON, kata bounds the op-log at a safe cadence (boot sweep + every N
    /// landed executions): it abandons operations older than the safe horizon
    /// that nothing live still references, then GCs the now-unreachable
    /// operations and store objects. Set `false` to leave the op-log to jj's
    /// own `jj util gc` / operator cadence.
    pub op_log_gc_enabled: bool,
    /// Op-log ceiling — the newest `op_log_max_operations` operations are
    /// ALWAYS retained (the undo horizon + any recently-touched workspace's
    /// op). Compaction only abandons operations BEYOND this count AND older than
    /// [`Self::op_log_gc_keep_newer_secs`], so the retained set is
    /// `max(this count, the keep-newer window)` — both finite, so the log stays
    /// bounded. `0` disables the count bound (keep-newer window only).
    pub op_log_max_operations: u64,
    /// Safety floor — never abandon or collect an operation/object newer
    /// than this many seconds. Protects (a) any live workspace, undo horizon, or
    /// parked candidate whose backing operation is recent, and (b) an object a
    /// concurrent kata process just created (jj's own gc `keep_newer` guard).
    /// Parked candidates and live workspace commits are additionally protected
    /// unconditionally by commit reachability (they sit in the current view), so
    /// this floor governs only the operation-log undo horizon and the
    /// concurrent-writer race window.
    pub op_log_gc_keep_newer_secs: u64,
    /// Land-cadence — run an op-log compaction pass after every N landed
    /// executions on a long-lived node (which may never reboot to hit the boot
    /// sweep). `0` disables the land cadence (boot sweep only).
    pub op_log_gc_every_n_lands: u64,
}

impl Default for VcsConfig {
    fn default() -> Self {
        Self {
            jj_repo: PathBuf::from("."),
            recovery_remote: None,
            // NO DEFAULT. See the field doc: absent means "ask the repository".
            trunk: None,
            op_log_gc_enabled: true,
            op_log_max_operations: 1_000,
            op_log_gc_keep_newer_secs: 600,
            op_log_gc_every_n_lands: 100,
        }
    }
}

impl NormalizePaths for VcsConfig {
    fn normalize_paths(&mut self) {
        self.jj_repo = expand_tilde(&self.jj_repo);
    }
}

impl Default for WorkerPoolConfig {
    fn default() -> Self {
        Self {
            transports: Vec::new(),
            dispatch_deadline_ms: default_dispatch_deadline_ms(),
            assignment_start_deadline_ms: default_assignment_start_deadline_ms(),
            heartbeat_interval_ms: 10_000,
            heartbeat_grace_ms: 30_000,
            max_workers: 4,
        }
    }
}

impl NormalizePaths for WorkerPoolConfig {
    fn normalize_paths(&mut self) {
        for t in &mut self.transports {
            t.normalize_paths();
        }
    }
}

/// One `[agents.<label>]` entry. The LABEL decides what it declares, and the
/// table carries no discriminator: a reserved deterministic label
/// ([`crate::agent::is_deterministic_agent_label`] — `shell`, and
/// `workspace_effect`, the main's in-process effects) is [`Self::Shell`] and
/// takes no key; every other label is [`Self::Harness`], kata's embedded
/// nanocode harness, whose `adapter` names the provider. [`deserialize_agents`]
/// is the one parse; it refuses a `type` key by name (`agent_type_removed`). Under
/// the `oci` route the only fields a stage can consume are the `Harness`
/// variant's capsule bag (`adapter`/`credential`/`env`/`model`/`reasoning_effort`).
///
/// Serialized untagged, so a serialized config reads back through the same
/// parse: `Harness` as its fields, `Shell` as an empty table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AgentBackendConfig {
    /// A capsule agent: the embedded nanocode harness under one of its kinds.
    Harness {
        /// Optional model override carried on the turn spec
        /// (`AgentTurnSpec.model`) when a stage authors no `model =`
        /// hint — the node's machine default. `None` leaves the harness's
        /// own default.
        #[serde(default)]
        model: Option<String>,
        /// Optional reasoning-effort override carried on the turn spec
        /// (`AgentTurnSpec.reasoning_effort`) and delivered through the
        /// harness's own reasoning setting. `None` leaves the harness's
        /// default.
        #[serde(default)]
        reasoning_effort: Option<String>,
        /// The capsule adapter this agent's stages dispatch under —
        /// an [`AdapterKind`](crate::agent::AdapterKind) label
        /// (`"nanocode_openai"` or `"nanocode_anthropic"`). Required before any
        /// stage selecting this agent is admitted under the `oci` execution
        /// profile (`adapter_undeclared`), and refused unless the label names
        /// an `AdapterKind` (`adapter_unqualified`). A machine fact: which
        /// provider this node runs a pack's agents against is the operator's
        /// to declare, never the pack's.
        #[serde(default)]
        adapter: Option<String>,
        /// The credential the worker loads for this agent's turns, e.g.
        /// `credential = { mode = "subscription", source = "kata_login" }`
        /// or `{ mode = "api_key", source = "env:OPENAI_API_KEY" }`. The
        /// capsule identity carries the REFERENCE (mode + source kind); the
        /// value is read on the worker at dispatch and carried to the harness
        /// in-process — never durable, never in CAS, never in the capsule.
        /// `None` is refused `credential_undeclared`: the harness runs on the
        /// credential its block declares and nothing else.
        #[serde(default)]
        credential: Option<AgentCredentialDecl>,
        /// The NON-SECRET environment the capsule's tool processes run under,
        /// e.g. `env = { TERM = "dumb" }` — identity-hashed on the capsule, so
        /// a node's env is part of WHAT the stage is, not where it runs.
        /// `Capsule::new` (and CHECK's agent-stage arm, through the same
        /// `refuse_declared_agent_env` door) refuses every name kata itself
        /// renders — `PATH`, the egress plumbing's eight
        /// (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY`, both casings)
        /// and the toolhost init's `HOME` — and the reserved `XDG_RUNTIME_DIR`,
        /// plus credential-shaped names (`*_KEY`, `*_TOKEN`,
        /// `*_SECRET`, `*_PASSWORD`, `AUTH_*`) — secrets never ride this arm;
        /// `credential` is their door.
        #[serde(default)]
        env: std::collections::BTreeMap<String, String>,
    },
    /// Shell backend — the reserved deterministic route: `agent =
    /// "shell"` stages run `sh` inside the node's environment. The label
    /// is always available even without an `[agents.shell]` block, and the
    /// block, when written, is empty. It carries NO timeout key: a shell
    /// stage's wall clock is its own hashed `stage(timeout_ms = ..)`, and
    /// nothing in `kata.toml` raises or lowers it. The in-capsule `sh` comes from the node's environment.
    Shell {},
}

impl AgentBackendConfig {
    /// True if this backend config declares a deterministic, non-LLM command
    /// executor (today only [`AgentBackendConfig::Shell`]).
    ///
    /// [`KataConfig::validate`] uses this to enforce that the reserved
    /// deterministic agent name `shell` (see
    /// [`kata_types::agent::is_deterministic_agent_label`]) cannot be rebound
    /// to an LLM backend, which is what keeps the promotion trust gate's
    /// label-based determinism check sound.
    #[must_use]
    pub const fn is_deterministic(&self) -> bool {
        matches!(self, Self::Shell { .. })
    }

    /// The declared capsule adapter label (`[agents.<name>] adapter = "…"`), or
    /// `None` where the variant declares none.
    ///
    /// Exhaustive over the variants: `Shell` declares no adapter and answers
    /// `None`, which the CHECK reads as `adapter_undeclared`, and a new variant
    /// does not compile until it says what it answers.
    #[must_use]
    pub fn capsule_adapter(&self) -> Option<&str> {
        match self {
            Self::Harness { adapter, .. } => adapter.as_deref(),
            Self::Shell { .. } => None,
        }
    }

    /// The declared credential block (`[agents.<name>] credential = { … }`),
    /// or `None` — same totality rule as [`Self::capsule_adapter`].
    #[must_use]
    pub const fn capsule_credential(&self) -> Option<&AgentCredentialDecl> {
        match self {
            Self::Harness { credential, .. } => credential.as_ref(),
            Self::Shell { .. } => None,
        }
    }

    /// The declared non-secret env (`[agents.<name>] env = { … }`), or an
    /// empty map — same totality rule as [`Self::capsule_adapter`].
    #[must_use]
    pub fn capsule_env(&self) -> &std::collections::BTreeMap<String, String> {
        static EMPTY: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        match self {
            Self::Harness { env, .. } => env,
            Self::Shell { .. } => &EMPTY,
        }
    }

    /// The declared model override (`[agents.<name>] model`) for the capsule
    /// arm — consulted only when the stage authors no `model =` hint of its
    /// own: a pack's authored selection wins over the node's machine default.
    #[must_use]
    pub fn capsule_model(&self) -> Option<&str> {
        match self {
            Self::Harness { model, .. } => model.as_deref(),
            Self::Shell { .. } => None,
        }
    }

    /// The declared reasoning-effort override (`[agents.<name>]
    /// reasoning_effort`) for the capsule arm — same totality rule as
    /// [`Self::capsule_model`]: the `Harness` capsule bag carries the field,
    /// every other variant answers `None`. Under `oci` the value reaches the
    /// turn through [`AgentTurnSpec::reasoning_effort`] and the harness's own
    /// reasoning setting.
    ///
    /// [`AgentTurnSpec::reasoning_effort`]: crate::execution_contract::AgentTurnSpec::reasoning_effort
    #[must_use]
    pub fn capsule_reasoning_effort(&self) -> Option<&str> {
        match self {
            Self::Harness {
                reasoning_effort, ..
            } => reasoning_effort.as_deref(),
            Self::Shell { .. } => None,
        }
    }

    /// The declared credential parsed to the turn's durable reference —
    /// mode + source kind, never a value. `Ok(None)` when the variant
    /// declares none; `Err` names the bad spelling for the caller to wrap in
    /// its own refusal name (`credential_undeclared`), so the CHECK and the
    /// assembly judge the same parse rather than two copies of it.
    ///
    /// # Errors
    /// [`KataError::Validation`] naming the bad `mode` or `source` spelling.
    pub fn capsule_credential_ref(
        &self,
    ) -> KataResult<Option<crate::execution_contract::TurnCredentialRef>> {
        let Some(declared) = self.capsule_credential() else {
            return Ok(None);
        };
        let Some(mode) = crate::metering::CredentialMode::from_label(&declared.mode) else {
            return Err(KataError::Validation(format!(
                "mode `{}` — the admitted spellings are `api_key` and `subscription`",
                declared.mode,
            )));
        };
        let Some(source) =
            crate::execution_contract::CredentialSource::from_declared(&declared.source)
        else {
            // An `env:` spelling that failed parses to its name-level reason —
            // the invalid or plumbing-reserved variable — rather than the
            // generic "not one of the spellings" line.
            let detail = declared
                .source
                .strip_prefix("env:")
                .and_then(crate::execution_contract::credential_env_refusal)
                .unwrap_or_else(|| {
                    "the admitted spellings are `kata_login` or `env:<VAR>`".to_owned()
                });
            return Err(KataError::Validation(format!(
                "source `{source}` — {detail}",
                source = declared.source,
            )));
        };
        // The pairing, judged with the spellings: `env:` carries an API key and
        // nothing else; kata's own login holds either (an API key it was given,
        // or a ChatGPT login), so it pairs with both. A `subscription` on an
        // `env:` key is not a credential the worker can lift —
        // `credential_undeclared`, same as a misspelled word.
        use crate::execution_contract::CredentialSource;
        use crate::metering::CredentialMode;
        let pairing = matches!(
            (&mode, &source),
            (CredentialMode::ApiKey, CredentialSource::EnvVar { .. })
                | (_, CredentialSource::KataLogin)
        );
        if !pairing {
            return Err(KataError::Validation(format!(
                "mode `{mode}` against source `{source}` — `api_key` pairs with `env:<VAR>`, \
                 `kata_login` pairs with either; crossing them is a declaration the worker \
                 cannot lift",
                mode = declared.mode,
                source = declared.source,
            )));
        }
        Ok(Some(crate::execution_contract::TurnCredentialRef {
            mode,
            source,
        }))
    }

    /// The capsule kind this entry declares, or the single reason it declares
    /// none.
    ///
    /// ONE judgement for the three doors that ask it: the `oci` CHECK
    /// (`kata_program`'s `refuse_agent_block`, which `kata config check` asks
    /// for every declared harness block too) and `agent_turn_spec`
    /// (capsule assembly) refuse the returned [`CapsuleLaunchProblem`] under
    /// its door name, and `kata doctor`'s `agent_backends` row renders the
    /// same judgement as readiness — so the three name one block alike. A
    /// variant that cannot carry `adapter` answers `AdapterUndeclared` by the
    /// same totality rule [`Self::capsule_adapter`] documents, and a label
    /// that names no kind is `AdapterUnqualified`. The block carries no launch
    /// of its own: every kind's capsule init is `kata-toolhost`, fixed by the
    /// kind, and its capsule opens no endpoint of its own (the harness's model
    /// traffic leaves from the worker), so a block has no `argv` and no
    /// `egress_extra` to declare — either is an unknown field at parse.
    ///
    /// # Errors
    /// [`CapsuleLaunchProblem`] naming the adapter declaration the block
    /// lacks, or the label that names no kind.
    pub fn capsule_launch(&self) -> Result<crate::agent::AdapterKind, CapsuleLaunchProblem> {
        let label = self
            .capsule_adapter()
            .ok_or(CapsuleLaunchProblem::AdapterUndeclared)?;
        crate::agent::AdapterKind::from_label(label)
            .ok_or_else(|| CapsuleLaunchProblem::AdapterUnqualified(label.to_string()))
    }
}

/// One `[agents.<label>]` table as written, read under its label. A `type` key
/// is recorded only to be refused by name, with the label, in
/// [`deserialize_agents`]; it is no field, so an unknown key's error never lists
/// it among the expected ones. Under a reserved deterministic label every other
/// key is recorded, value unread, in `shell_keys`, and [`AgentEntrySeed`]
/// refuses it `shell_agent_block_keys` at the entry's path — the shell route
/// takes no key, so its refusal never offers a model agent's keys as the
/// expected ones.
#[derive(Default)]
struct AgentEntryText {
    carries_type: bool,
    shell_keys: Vec<String>,
    model: Option<String>,
    reasoning_effort: Option<String>,
    adapter: Option<String>,
    credential: Option<AgentCredentialDecl>,
    env: Option<std::collections::BTreeMap<String, String>>,
}

/// Reads the [`AgentEntryText`] of `[agents.<label>]`; `shell` is whether
/// `label` is a reserved deterministic one.
struct AgentEntrySeed<'a> {
    label: &'a str,
    shell: bool,
}

impl<'de> serde::de::DeserializeSeed<'de> for AgentEntrySeed<'_> {
    type Value = AgentEntryText;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> serde::de::Visitor<'de> for AgentEntrySeed<'_> {
    type Value = AgentEntryText;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an `[agents.<label>]` table")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> Result<AgentEntryText, A::Error> {
        use serde::de::Error as _;
        const FIELDS: &[&str] = &["model", "reasoning_effort", "adapter", "credential", "env"];
        let mut entry = AgentEntryText::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "type" => {
                    map.next_value::<serde::de::IgnoredAny>()?;
                    entry.carries_type = true;
                }
                _ if self.shell => {
                    map.next_value::<serde::de::IgnoredAny>()?;
                    entry.shell_keys.push(key);
                }
                "model" => entry.model = map.next_value()?,
                "reasoning_effort" => entry.reasoning_effort = map.next_value()?,
                "adapter" => entry.adapter = map.next_value()?,
                "credential" => entry.credential = map.next_value()?,
                "env" => entry.env = map.next_value()?,
                other => return Err(A::Error::unknown_field(other, FIELDS)),
            }
        }
        // A `type` is refused by name first, in `agent_backend`; any other key
        // under the shell route is refused here, at the entry's own path.
        if !entry.carries_type && !entry.shell_keys.is_empty() {
            return Err(A::Error::custom(format!(
                "shell_agent_block_keys: `[agents.{}]` is the reserved shell route and \
                 takes no key, but declares `{}`; delete them, or declare the model agent \
                 under another label",
                self.label,
                entry.shell_keys.join("`, `"),
            )));
        }
        Ok(entry)
    }
}

/// The `[agents]` table's one parse: each entry's label decides its
/// [`AgentBackendConfig`] variant.
///
/// Refuses, by name:
/// * `agent_type_removed` — an entry under any label that carries `type`. The
///   key decided nothing kata ships: the harness is always the embedded one,
///   `adapter` names its provider, and the label `shell` is the shell route.
/// * `shell_agent_block_keys` — any other key under a reserved deterministic
///   label (`shell`, `workspace_effect`), a model agent's or not, whose entry is
///   the shell route and takes none.
///
/// Under any other label, a key no model agent declares is refused as an
/// unknown field.
///
/// # Errors
/// The deserializer's error carrying one of the refusals above.
pub fn deserialize_agents<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, AgentBackendConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Agents;
    impl<'de> serde::de::Visitor<'de> for Agents {
        type Value = BTreeMap<String, AgentBackendConfig>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an `[agents]` table of `[agents.<label>]` tables")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut agents = BTreeMap::new();
            while let Some(label) = map.next_key::<String>()? {
                let shell = crate::agent::is_deterministic_agent_label(&label);
                let entry = map.next_value_seed(AgentEntrySeed {
                    label: &label,
                    shell,
                })?;
                let backend = agent_backend::<A::Error>(&label, entry)?;
                agents.insert(label, backend);
            }
            Ok(agents)
        }
    }
    deserializer.deserialize_map(Agents)
}

/// The backend one `[agents.<label>]` entry declares, or its refusal by name
/// ([`deserialize_agents`]).
fn agent_backend<E: serde::de::Error>(
    label: &str,
    entry: AgentEntryText,
) -> Result<AgentBackendConfig, E> {
    let AgentEntryText {
        carries_type,
        shell_keys: _,
        model,
        reasoning_effort,
        adapter,
        credential,
        env,
    } = entry;
    if carries_type {
        return Err(E::custom(format!(
            "agent_type_removed: `[agents.{label}]` declares `type`, a key this build \
             removed — every model agent is kata's embedded harness, whose `adapter` names \
             the provider, and the reserved label `shell` is the shell route; delete the \
             `type = ...` line"
        )));
    }
    if !crate::agent::is_deterministic_agent_label(label) {
        return Ok(AgentBackendConfig::Harness {
            model,
            reasoning_effort,
            adapter,
            credential,
            env: env.unwrap_or_default(),
        });
    }
    Ok(AgentBackendConfig::Shell {})
}

/// Why an [`AgentBackendConfig`] cannot launch a capsule — each variant names
/// the refusal door the `oci` CHECK and the capsule assembler answer under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapsuleLaunchProblem {
    /// No `adapter` is declared (or the variant carries no adapter field):
    /// `adapter_undeclared`.
    AdapterUndeclared,
    /// The declared adapter string names no
    /// [`AdapterKind`](crate::agent::AdapterKind): `adapter_unqualified`. The
    /// refused set is exactly that: every kind's own label is admitted.
    AdapterUnqualified(String),
}

impl CapsuleLaunchProblem {
    /// The refusal name the `oci` CHECK reports for this problem — the same
    /// door `agent_turn_spec` refuses under at assembly.
    #[must_use]
    pub const fn door(&self) -> &'static str {
        match self {
            Self::AdapterUndeclared => "adapter_undeclared",
            Self::AdapterUnqualified(_) => "adapter_unqualified",
        }
    }

    /// What is missing, spelled the way the refusal does.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::AdapterUndeclared => "declares no capsule `adapter`".to_string(),
            Self::AdapterUnqualified(label) => {
                format!(
                    "declares adapter `{label}`, which names no adapter kind this build carries"
                )
            }
        }
    }
}

impl std::fmt::Display for CapsuleLaunchProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe())
    }
}

/// Worker-binary configuration. Lives in a separate file from
/// `KataConfig` in production.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerNodeConfig {
    /// Endpoint the worker uses to reach the main.
    pub home_node_endpoint: String,
    /// Path to the worker credential file.
    pub credential_path: PathBuf,
    /// Provisioned lifetime of the worker's authoritative idempotency database.
    /// Required: an old config cannot turn missing authority into a fresh store.
    pub expected_membrane_id: crate::identity::WorkerMembraneId,
    /// Capabilities the operator declares for this worker.
    pub capabilities: Vec<WorkerResource>,
    /// The MAIN's data directory, whose planes (`operational.db`, `cas.db`, `cas/`) this
    /// worker resolves a capsule's environment and input trees through, READ-ONLY, and
    /// publishes its `/out` result into.
    ///
    /// A path and not a protocol because the initial profile is local subordinate workers
    /// sharing the main's disk; remote enrollment stays refused. REQUIRED —
    /// `kata_worker::capsule_route` refuses the daemon's start with
    /// `worker_main_data_dir_undeclared`.
    #[serde(default)]
    pub main_data_dir: Option<PathBuf>,
}

impl NormalizePaths for WorkerNodeConfig {
    fn normalize_paths(&mut self) {
        self.credential_path = expand_tilde(&self.credential_path);
    }
}

/// Symmetric pre-shared key used by the local worker handshake. Stored on the
/// worker side in a 0600 TOML
/// file (`~/.kata/worker.cred` by default) and matched against
/// the main's `<data_dir>/local-worker.secret` during the handshake. It is the
/// only worker credential: the local Unix-socket boundary authenticates this
/// enrollment secret (an owner-only file) and nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerSharedSecret {
    /// The secret string itself. Treat as sensitive — never log
    /// or render in UIs. Expected length: 32 URL-safe base64 chars.
    pub secret: String,
}

/// Load a `WorkerSharedSecret` from a credential file.
///
/// The one accepted form is the TOML `secret = "..."` that
/// `kata-worker provision` writes, with a non-empty secret. Anything else —
/// including the bare secret without its wrapper — is refused with the TOML
/// parse error, so operators can see what went wrong.
pub fn load_worker_shared_secret(path: &Path) -> KataResult<WorkerSharedSecret> {
    validate_shared_secret_file_permissions(path, "worker credential")?;
    let text = std::fs::read_to_string(path).map_err(|e| {
        KataError::Config(format!(
            "failed to read credential at {}: {e}",
            path.display()
        ))
    })?;

    match toml::from_str::<WorkerSharedSecret>(&text) {
        Ok(cred) if !cred.secret.is_empty() => Ok(cred),
        Ok(_) => Err(KataError::Validation(format!(
            "credential at {} has an empty secret",
            path.display()
        ))),
        Err(toml_err) => Err(KataError::Config(format!(
            "failed to parse credential at {}: {toml_err}",
            path.display()
        ))),
    }
}

#[cfg(unix)]
pub fn validate_shared_secret_file_permissions(path: &Path, kind: &str) -> KataResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path).map_err(|e| {
        KataError::Config(format!(
            "failed to inspect {kind} at {}: {e}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(KataError::Validation(format!(
            "{kind} at {} must be a regular file, not a symlink",
            path.display()
        )));
    }
    if !metadata.file_type().is_file() {
        return Err(KataError::Validation(format!(
            "{kind} at {} must be a regular file",
            path.display()
        )));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KataError::Validation(format!(
            "{kind} at {} must not be group/world-readable or writable \
             (mode {mode:o}); run `chmod 600 {}`",
            path.display(),
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn validate_shared_secret_file_permissions(_path: &Path, _kind: &str) -> KataResult<()> {
    Ok(())
}

/// API authentication configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApiAuthConfig {
    /// Scoped, Ed25519-signed bearer-token auth for a loopback socket.
    /// The API verifies each presented token's signature against the
    /// configured **verifying key** (the main's ed25519 public key) and
    /// reads the token's [`crate::identity::ApiScope`] to authorize per
    /// route-group — unlike a single flat shared bearer secret, under which
    /// any holder (including the workload) could authorize every route.
    ///
    /// Exactly one verifying-key source (`verifying_key_env` /
    /// `verifying_key_file`) is required. Token minting is a separate operator
    /// CLI action whose signing-key input is not daemon configuration.
    SignedToken {
        /// Environment variable holding the hex-encoded ed25519 **public**
        /// verifying key the API checks token signatures against.
        /// Named outside kata's reserved `KATA_` namespace; validation refuses
        /// a `KATA_` name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        verifying_key_env: Option<String>,
        /// File holding the hex-encoded ed25519 **public** verifying key. The
        /// verifying key is public, so it carries no secret-file permission
        /// requirement.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        verifying_key_file: Option<PathBuf>,
    },
    /// Disable authentication entirely (loopback dev only).
    Disabled {},
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ApiAuthConfigWire {
    SignedToken(SignedTokenAuthFields),
    Disabled(DisabledAuthFields),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedTokenAuthFields {
    #[serde(default)]
    verifying_key_env: Option<String>,
    #[serde(default)]
    verifying_key_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisabledAuthFields {}

impl<'de> Deserialize<'de> for ApiAuthConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match ApiAuthConfigWire::deserialize(deserializer)? {
            ApiAuthConfigWire::SignedToken(fields) => Self::SignedToken {
                verifying_key_env: fields.verifying_key_env,
                verifying_key_file: fields.verifying_key_file,
            },
            ApiAuthConfigWire::Disabled(DisabledAuthFields {}) => Self::Disabled {},
        })
    }
}

impl ApiAuthConfig {
    fn normalize_paths(&mut self) {
        if let Self::SignedToken {
            verifying_key_file, ..
        } = self
            && let Some(path) = verifying_key_file.as_ref()
        {
            *verifying_key_file = Some(expand_tilde(path));
        }
    }

    /// Count of configured verifying-key sources (env + file). Exactly one is
    /// required for [`ApiAuthConfig::SignedToken`].
    fn verifying_key_source_count(&self) -> usize {
        match self {
            Self::SignedToken {
                verifying_key_env,
                verifying_key_file,
                ..
            } => {
                usize::from(verifying_key_env.is_some()) + usize::from(verifying_key_file.is_some())
            }
            Self::Disabled {} => 0,
        }
    }
}

/// REST API configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Bind address for the API server.
    pub bind: String,
    /// Authentication mode.
    pub auth: ApiAuthConfig,
}

impl NormalizePaths for ApiConfig {
    fn normalize_paths(&mut self) {
        self.auth.normalize_paths();
    }
}

/// Telemetry configuration — the flat `[telemetry]` shape.
///
/// Every field is honored: `enabled`, `log_level`, `log_json`, `export`,
/// `otlp_endpoint`, `metrics_bind` (see [`telemetry_knob_registry`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Master switch. When `false`, `init_telemetry` is a no-op
    /// (no tracing subscriber, no metrics recorder, no exporters).
    pub enabled: bool,
    /// Tracing subscriber filter. Overridden by `KATA_LOG` env var
    /// when present.
    pub log_level: String,
    /// If `true`, emit structured JSON log lines; otherwise use the
    /// human-friendly text formatter.
    pub log_json: bool,
    /// Which extra exporter to wire alongside the stdout subscriber.
    /// `Stdout` installs no extras; `Prometheus` binds a pull-scrape
    /// listener at [`Self::metrics_bind`]; `Otlp` wires a
    /// batch-exporting OTLP trace workflow at [`Self::otlp_endpoint`].
    pub export: TelemetryExport,
    /// OTLP collector endpoint, only consulted when
    /// `export = "otlp"`. Empty string = disabled.
    pub otlp_endpoint: String,
    /// Socket address for the Prometheus `/metrics` pull endpoint.
    /// Bound at init when `export = "prometheus"`; ignored otherwise.
    pub metrics_bind: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: "info".into(),
            log_json: false,
            export: TelemetryExport::Stdout,
            otlp_endpoint: String::new(),
            metrics_bind: "127.0.0.1:9400".into(),
        }
    }
}

/// Extra-exporter mode for [`TelemetryConfig::export`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TelemetryExport {
    /// Subscriber only — no metrics listener, no OTLP traces. Default.
    #[default]
    Stdout,
    /// Subscriber + Prometheus pull-scrape listener on `metrics_bind`.
    Prometheus,
    /// Subscriber + OTLP trace-push workflow at `otlp_endpoint`.
    Otlp,
}

/// The `[containment]` section — the node's **installed containment policy**.
///
/// An omitted containment declaration resolves conservatively to
/// `HostUnconfined`, and an installed policy may instead require `Contained`
/// and refuse. This bag IS that installed policy.
/// It is a node-level admission rule, not a per-workflow knob: kata's product
/// boundary is one operator running one authoritative main (ADR-0001
/// § "Product and authority"), so there is exactly one
/// policy per main and a workflow author cannot opt out of it.
///
/// It lives in its own section rather than under `[runtime]` because it is not a
/// tunable: every `[runtime]` field trades throughput against latency or disk,
/// while this one decides whether a checked program is ACCEPTED AT ALL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentConfig {
    /// Refuse, at compile, any stage whose executor is an opaque **model/agent**
    /// call and whose derived containment axis is `HostUnconfined`.
    ///
    /// **Default `true`.** A model/agent stage runs in a certified container,
    /// so the refusal's precision is pinned by authored fixtures:
    /// `bin/kata/tests/containment_policy_operator_door.rs` walks the key from
    /// a parsed `kata.toml` to a compile refusal.
    ///
    /// # Exactly what it covers, and what it deliberately does not
    ///
    /// It covers a stage whose resolved executor is a model/agent backend — the
    /// case where kata runs opaque third-party code it did not author. It does
    /// NOT cover a `shell` stage (its command is authored in the pack and visible
    /// to the reviewer) and it does NOT cover the in-process main-owned
    /// `workspace_effect` backend (which is `InProcess`, never a host child). A
    /// node-wide "nothing may be `HostUnconfined`" rule would refuse most
    /// shipped packs, which is why this policy is scoped to opaque third-party
    /// code.
    ///
    /// Declaring a sandbox is not sufficient: `stage(sandbox = "host")` certifies
    /// no containment and still derives `HostUnconfined`, so it is refused too.
    /// `sandbox_profile(workspace = "scratch")` derives `Contained` and satisfies
    /// this policy.
    ///
    /// # An omitted section takes this default
    ///
    /// A `kata.toml` with no `[containment]` section takes this default, so the
    /// refusal applies without the operator editing anything — a safety default
    /// an operator had to opt into would protect nobody — and that is why the
    /// refusal names the key and the value that turns it off.
    #[serde(default = "default_require_contained_model_stages")]
    pub require_contained_model_stages: bool,
}

/// The default for [`ContainmentConfig::require_contained_model_stages`].
///
/// Named rather than `bool::default()`-derived because the two must not be able
/// to drift: serde reads THIS for an omitted key, and [`Default`] below reads it
/// for a programmatically-constructed config. A `#[derive(Default)]` here would
/// silently mean `false` and only the serde path would carry the `true` default.
const fn default_require_contained_model_stages() -> bool {
    true
}

impl Default for ContainmentConfig {
    fn default() -> Self {
        Self {
            require_contained_model_stages: default_require_contained_model_stages(),
        }
    }
}

/// `[git_view]` — the bound the admission-time history
/// producer carries for an agent capsule's disposable `/work` repository.
///
/// The section is a NODE answer, never an authored one: the history artifact
/// is produced once per execution at admission on the `oci` profile, and the
/// knobs say how much of the base commit's reachable object graph the node is
/// willing to carry into CAS. A program cannot name either value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitViewConfig {
    /// `[git_view] history_depth` — the most commits the history artifact may
    /// hold, counted newest-first from the base commit. `None` (the default)
    /// is the whole reachable history; a present count truncates the walk and
    /// writes a `shallow` member marking the boundary commits. `0` is refused
    /// by [`KataConfig::validate`] — a zero-commit history cannot hold the
    /// base commit the view is rooted at, so the declaration would make every
    /// agent-stage admission fail.
    #[serde(default)]
    pub history_depth: Option<u32>,
    /// `[git_view] history_bytes_ceiling` — the most member bytes the history
    /// artifact's packs may total. Over it, admission is refused
    /// (`git_view_history_over_ceiling`) rather than truncated. Default 1 GiB
    /// ([`DEFAULT_GIT_VIEW_HISTORY_BYTES_CEILING`]) — the same order as the
    /// `/work` input ceiling, since the artifact carries the same repository.
    ///
    /// **Consumed:** `bin/kata` boot hands the section to
    /// `WorkflowExecutor::with_git_view_config`, whose admission drive passes
    /// it to the jj backend's history producer.
    #[serde(default = "default_git_view_history_bytes_ceiling")]
    pub history_bytes_ceiling: u64,
}

/// The absent-section meaning, spelled by hand: `#[derive(Default)]` cannot
/// see the serde `default=` on `history_bytes_ceiling` and would answer `0`,
/// a ceiling that refuses every agent-stage admission. `Default` here IS the
/// documented posture — unlimited depth, the shipped 1 GiB member bound.
impl Default for GitViewConfig {
    fn default() -> Self {
        Self {
            history_depth: None,
            history_bytes_ceiling: DEFAULT_GIT_VIEW_HISTORY_BYTES_CEILING,
        }
    }
}

/// Default `[git_view] history_bytes_ceiling`: 1 GiB.
pub const DEFAULT_GIT_VIEW_HISTORY_BYTES_CEILING: u64 = 1024 * 1024 * 1024;

fn default_git_view_history_bytes_ceiling() -> u64 {
    DEFAULT_GIT_VIEW_HISTORY_BYTES_CEILING
}

/// Knob registry for [`GitViewConfig`]. Every serde field MUST appear here
/// or the `types` inert-knob test fails.
#[must_use]
pub fn git_view_knob_registry() -> &'static [(&'static str, KnobStatus)] {
    &[
        (
            "history_depth",
            KnobStatus::Consumed(
                "bin/kata boot -> WorkflowExecutor::with_git_view_config -> kata-vcs \
                 committed_base_git_history (bounded commit walk + shallow marker)",
            ),
        ),
        (
            "history_bytes_ceiling",
            KnobStatus::Consumed(
                "bin/kata boot -> WorkflowExecutor::with_git_view_config -> kata-vcs \
                 committed_base_git_history (the git_view_history_over_ceiling admission \
                 refusal)",
            ),
        ),
    ]
}

/// Knob registry for [`ContainmentConfig`]. Every serde field MUST appear here
/// or the `types` inert-knob test fails.
#[must_use]
pub fn containment_knob_registry() -> &'static [(&'static str, KnobStatus)] {
    &[(
        "require_contained_model_stages",
        KnobStatus::Consumed(
            "bin/kata boot install_node_containment_policy -> kata-workflow \
             compile_execution_program_with_options model-stage containment refusal",
        ),
    )]
}

/// Top-level kata configuration. `PartialEq` without `Eq`: `[pricing]` rates are
/// `f64`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KataConfig {
    /// Node identity.
    pub node: NodeConfig,
    /// Runtime tunables.
    #[serde(default)]
    pub runtime: RuntimeConfig,
    /// Worker pool configuration.
    pub workers: WorkerPoolConfig,
    /// API server configuration.
    pub api: ApiConfig,
    /// Per-agent backend configuration. The key is the agent name
    /// (e.g. "default", "main", "fallback") and the value is the
    /// backend the label decides ([`deserialize_agents`]). Uses `BTreeMap` so
    /// iteration order is deterministic.
    #[serde(default, deserialize_with = "deserialize_agents")]
    pub agents: BTreeMap<String, AgentBackendConfig>,
    /// VCS and execution-workspace configuration.
    #[serde(default)]
    pub vcs: VcsConfig,
    /// Telemetry / observability configuration. See
    /// [`TelemetryConfig`]. Defaults to the subscriber-only baseline
    /// so a config without the section parses.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// The node's installed containment policy. See [`ContainmentConfig`] for
    /// what it refuses and its default; a config without the section parses.
    #[serde(default)]
    pub containment: ContainmentConfig,
    /// The admission-time bound on an agent capsule's git history view. See
    /// [`GitViewConfig`]; the absent section means unlimited depth at the
    /// shipped byte ceiling.
    #[serde(default)]
    pub git_view: GitViewConfig,
    /// `[[pricing.models]]` — operator price overrides. See [`PricingConfig`].
    #[serde(default)]
    pub pricing: PricingConfig,
}

/// `[pricing]` — the operator's price overrides for the cost meter: each
/// `[[pricing.models]]` row replaces the built-in rate for one `(backend, model)`.
///
/// Declared here so the closed `kata.toml` door admits the table and refuses a
/// misspelled row key, and every key of a row is required, so neither a
/// misspelled nor an omitted multiplier can price cache tokens at `0.0` without
/// a word. The rows are CONSUMED by
/// `kata_worker::pricing`, which reads them from the exact bytes `ConfigManager`
/// validated (`load_overrides_from_snapshot`) with this same type, so the two
/// parses cannot disagree about a row. Restart-required.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PricingConfig {
    /// The override rows, in file order; the first row matching a call wins.
    #[serde(default)]
    pub models: Vec<PriceOverride>,
}

impl PricingConfig {
    /// Refuse a row whose rate or multiplier is not a finite, non-negative number —
    /// NaN, an infinity, or below zero. Zero is admitted: a free model is priced at
    /// zero. A NaN rate would price every call it matches at NaN, and, since rows
    /// compare by `f64` equality, make every reload report `pricing` changed against
    /// an unchanged row. Run by [`KataConfig::validate`] and by `kata_worker::pricing`'s
    /// own loader, so no door installs such a row.
    ///
    /// # Errors
    /// [`KataError::Validation`] naming the row and field (`pricing.models[0].<field>`).
    pub fn validate(&self) -> KataResult<()> {
        for (index, row) in self.models.iter().enumerate() {
            for (field, value) in [
                ("input_rate_per_mtok", row.input_rate_per_mtok),
                ("output_rate_per_mtok", row.output_rate_per_mtok),
                ("cache_read_multiplier", row.cache_read_multiplier),
                ("cache_write_multiplier", row.cache_write_multiplier),
            ] {
                if !(value.is_finite() && value >= 0.0) {
                    return Err(KataError::Validation(format!(
                        "pricing.models[{index}].{field} = {value} must be a finite, \
                         non-negative number (the `{}` row for `{}`)",
                        row.backend.label(),
                        row.model
                    )));
                }
            }
        }
        Ok(())
    }
}

/// One `[[pricing.models]]` row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceOverride {
    pub backend: crate::agent::BillingBackend,
    /// The model string exactly as the turn reports it. Case-sensitive.
    pub model: String,
    /// USD per million input tokens.
    pub input_rate_per_mtok: f64,
    /// USD per million output tokens.
    pub output_rate_per_mtok: f64,
    /// Factor on `input_rate_per_mtok` for prompt-cache reads. REQUIRED, for the
    /// reason `cache_write_multiplier` is: both priced kinds count a turn's
    /// cache reads apart from `input`, so a row bills them through this alone,
    /// and a default would bill them nothing — a row that omits it is refused
    /// at load. `0.5` is OpenAI's cached-input rate; Anthropic's is `0.05` or `0.025` by model.
    pub cache_read_multiplier: f64,
    /// Factor on `input_rate_per_mtok` for prompt-cache writes. REQUIRED: both
    /// priced kinds count a turn's cache writes apart from `input`, so a row
    /// bills them through this alone, and a default would bill them nothing —
    /// a row that omits it is refused at load. `1.0` bills them at the input
    /// rate (OpenAI's); `1.25` is Anthropic's
    /// 5-minute write.
    pub cache_write_multiplier: f64,
}

#[must_use]
pub fn pricing_knob_registry() -> &'static [(&'static str, KnobStatus)] {
    &[(
        "models",
        KnobStatus::Consumed(
            "bin/kata serve/mcp boot -> kata-worker \
             pricing::load_overrides_from_snapshot (the validated config bytes) -> \
             rate_row_with_origin, ahead of the built-in PRICE_TABLE",
        ),
    )]
}

impl NormalizePaths for KataConfig {
    fn normalize_paths(&mut self) {
        self.node.normalize_paths();
        self.workers.normalize_paths();
        self.api.normalize_paths();
        self.vcs.normalize_paths();
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The consumed-knob rule — the inert-knob guard
// ─────────────────────────────────────────────────────────────────────────

/// Classification for a declared config knob.
///
/// The consumed-knob rule made mechanical: every **top-level** serde field on a
/// tunable config struct covered by the inert-knob guard must have a live
/// consumer that reads it and changes runtime behavior ([`Consumed`]). A field
/// without one is *inert* — a dead knob that silently accepts operator input
/// and does nothing — and is rejected by [`KataConfig::validate`] (hence by
/// `kata config check`). The registries below are exhaustively cross-checked against
/// the structs' serde surface by the `types` crate's `inert_knob_*` tests, so
/// adding a top-level serde field to a covered struct without classifying it
/// FAILS `just test-crate types`.
///
/// Coverage: the top-level serde surface of all seven [`KataConfig`]
/// bags — [`NodeConfig`], [`RuntimeConfig`], [`WorkerPoolConfig`],
/// [`ApiConfig`], [`TelemetryConfig`], [`VcsConfig`], [`ContainmentConfig`] —
/// plus every
/// `[agents.<name>] credential = { mode, source }` — the credential
/// declaration a capsule-capable agent variant carries, verbatim. Parsing it
/// into a [`TurnCredentialRef`] is the CHECK/assembly's job — a node config
/// holds spellings, the contract holds kinds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCredentialDecl {
    /// `api_key` | `subscription`.
    pub mode: String,
    /// `kata_login` | `env:<VAR>`.
    pub source: String,
}

/// `[agents.<name>]` backend variant ([`AgentBackendConfig`], via
/// [`agent_backend_knob_registry`]). Each bag has a `*_knob_registry()`
/// cross-checked against its serde surface by the `types` inert-knob tests, so
/// adding a serde field to ANY of them without a classification FAILS
/// `just test-crate types` (and `kata config check`).
///
/// Deliberately **out of scope** (each an explicit non-goal, not a silent gap):
/// - The guard is **non-recursive**: it enumerates only each bag's top-level
///   serde keys, not fields of nested objects — [`ApiAuthConfig`] sub-fields
///   (`verifying_key_env`/`file`), and any
///   [`WorkerTransportConfig`] fields. Those nested fields are
///   validated separately in [`KataConfig::validate`] and are all consumed
///   today; an inert field added *inside* a nested struct is NOT caught by
///   this guard.
/// - [`WorkerNodeConfig`] (the separate `worker.toml` surface) — not one of the
///   six [`KataConfig`] bags and has no `validate()`/registry equivalent, so
///   this guard does not cover `worker.toml`.
///
/// [`Consumed`]: KnobStatus::Consumed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnobStatus {
    /// Read by a live consumer that changes runtime behavior. The string
    /// names one representative consumer for auditability.
    Consumed(&'static str),
}

/// Knob registry for [`RuntimeConfig`]. Every serde field MUST appear here or
/// the `types` inert-knob test fails.
#[must_use]
pub fn runtime_knob_registry() -> &'static [(&'static str, KnobStatus)] {
    &[
        (
            "max_concurrent_dispatches",
            KnobStatus::Consumed(
                "bin/kata boot Dispatcher::with_max_concurrent_dispatches (admission cap)",
            ),
        ),
        (
            "max_active_executions",
            KnobStatus::Consumed("bin/kata boot WorkflowExecutor active residency budget"),
        ),
        (
            "max_active_execution_bytes",
            KnobStatus::Consumed("bin/kata boot WorkflowExecutor active residency budget"),
        ),
        (
            "workspace_ttl_secs",
            KnobStatus::Consumed(
                "bin/kata boot terminal-workspace reaper (TerminalWorkspaceReapPolicy)",
            ),
        ),
        (
            "model_reuse_max_age_secs",
            KnobStatus::Consumed(
                "bin/kata boot SqliteWorkflowStore::with_model_reuse_max_age, applied by \
                 WorkflowRunner::consult_capsule_reuse (the memoised-spend bound, read at \
                 LOOKUP off the source occurrence's acceptance)",
            ),
        ),
        (
            "ledger_ttl_secs",
            KnobStatus::Consumed("bin/kata boot terminal_reap_policy (unknown-liveness TTL)"),
        ),
        (
            "memory_compaction_max_live_per_namespace",
            KnobStatus::Consumed(
                "bin/kata boot SqliteNativeMemoryStore::with_compaction (per-namespace fold bound)",
            ),
        ),
        (
            "memory_compaction_write_interval",
            KnobStatus::Consumed(
                "bin/kata boot SqliteNativeMemoryStore::with_compaction (write-threshold cadence)",
            ),
        ),
    ]
}

/// Knob registry for [`VcsConfig`]. Every serde field MUST appear here or the
/// `types` inert-knob test fails.
#[must_use]
pub fn vcs_knob_registry() -> &'static [(&'static str, KnobStatus)] {
    &[
        (
            "jj_repo",
            KnobStatus::Consumed("bin/kata boot JjBackend::open"),
        ),
        (
            "recovery_remote",
            KnobStatus::Consumed("cli::recovery_capture::run_backup_recoverable_cmd"),
        ),
        (
            "trunk",
            KnobStatus::Consumed(
                "bin/kata boot JjBackend::with_configured_trunk \
                 (rank 1 of kata_vcs::trunk::resolve_trunk)",
            ),
        ),
        (
            "op_log_gc_enabled",
            KnobStatus::Consumed("kata-vcs JjBackend::compact_op_log (boot sweep + land cadence)"),
        ),
        (
            "op_log_max_operations",
            KnobStatus::Consumed("kata-vcs JjBackend op-log abandon boundary"),
        ),
        (
            "op_log_gc_keep_newer_secs",
            KnobStatus::Consumed("kata-vcs JjBackend op-log/store gc keep-newer floor"),
        ),
        (
            "op_log_gc_every_n_lands",
            KnobStatus::Consumed(
                "kata-vcs JjBackend::land_committed_candidate post-land cadence trigger",
            ),
        ),
    ]
}

/// Knob registry for [`NodeConfig`]. Every serde field MUST appear here or the
/// `types` inert-knob test fails.
#[must_use]
pub fn node_knob_registry() -> &'static [(&'static str, KnobStatus)] {
    &[
        (
            "id",
            KnobStatus::Consumed(
                "bin/kata main identity (ledger, local credentials, and evidence)",
            ),
        ),
        (
            "data_dir",
            KnobStatus::Consumed(
                "bin/kata main persistent-state root (storage, identity keys, worktrees)",
            ),
        ),
        (
            "environment",
            KnobStatus::Consumed(
                "bin/kata boot -> kata_core::environment::bind_node_environment (declared and \
                 promoted before readiness) -> Dispatcher::with_node_environment, which the \
                 capsule submit path selects for every stage",
            ),
        ),
        (
            "output_bytes_ceiling",
            KnobStatus::Consumed(
                "bin/kata boot -> node_profile::install_node_budget_ceilings -> kata-workflow \
                 compile.rs refuse_authored_budgets_over_node_ceilings (the \
                 capsule_budget_over_node_ceiling admission refusal)",
            ),
        ),
        (
            "work_delta_bytes_ceiling",
            KnobStatus::Consumed(
                "bin/kata boot -> node_profile::install_node_budget_ceilings -> kata-workflow \
                 compile.rs refuse_authored_budgets_over_node_ceilings (the \
                 capsule_budget_over_node_ceiling admission refusal)",
            ),
        ),
        (
            "work_delta_entries_ceiling",
            KnobStatus::Consumed(
                "bin/kata boot -> node_profile::install_node_budget_ceilings -> kata-workflow \
                 compile.rs refuse_authored_budgets_over_node_ceilings (the \
                 capsule_budget_over_node_ceiling admission refusal)",
            ),
        ),
        (
            "capsule_memory_bytes_ceiling",
            KnobStatus::Consumed(
                "bin/kata boot -> node_profile::install_node_budget_ceilings -> kata-workflow \
                 compile.rs the recorded-bound check at admission (capsule_budget_over_node_ceiling \
                 on an authored or default bound)",
            ),
        ),
        (
            "capsule_process_count_ceiling",
            KnobStatus::Consumed(
                "bin/kata boot -> node_profile::install_node_budget_ceilings -> kata-workflow \
                 compile.rs the recorded-bound check at admission (capsule_budget_over_node_ceiling \
                 on the process-count default)",
            ),
        ),
        (
            "work_tree_max_bytes",
            KnobStatus::Consumed(
                "bin/kata boot -> WorkflowExecutor::with_work_tree_input_bounds -> the \
                 admission-time committed-base-tree publication's total-member-bytes bound \
                 (/work input ceiling)",
            ),
        ),
        (
            "work_tree_max_entries",
            KnobStatus::Consumed(
                "bin/kata boot -> WorkflowExecutor::with_work_tree_input_bounds -> the \
                 admission-time committed-base-tree publication's entry-count bound \
                 (/work input ceiling)",
            ),
        ),
        (
            "egress_allow",
            KnobStatus::Consumed(
                "bin/kata boot -> node_profile::install_node_egress_allow -> kata-workflow \
                 compile.rs egress_undeclared (a `net = \"host\"` stage's empty effective \
                 allowlist refused at CHECK) and capsule_assembly capsule_network (the \
                 CapsuleNetwork::Egress allowlist the worker's CONNECT proxy enforces)",
            ),
        ),
    ]
}

/// Knob registry for [`WorkerPoolConfig`]. Every serde field MUST appear here
/// or the `types` inert-knob test fails.
#[must_use]
pub fn workers_knob_registry() -> &'static [(&'static str, KnobStatus)] {
    &[
        (
            "transports",
            KnobStatus::Consumed(
                "bin/kata boot: local-socket listeners and the supervised node (cli::solo)",
            ),
        ),
        (
            "dispatch_deadline_ms",
            KnobStatus::Consumed(
                "bin/kata boot Dispatcher::with_send_timeout (bounds each capsule dispatch send)",
            ),
        ),
        (
            "assignment_start_deadline_ms",
            KnobStatus::Consumed("bin/kata boot start-deadline reaper"),
        ),
        (
            "heartbeat_interval_ms",
            KnobStatus::Consumed("bin/kata boot heartbeat-monitor interval"),
        ),
        (
            "heartbeat_grace_ms",
            KnobStatus::Consumed("bin/kata boot heartbeat disconnect grace"),
        ),
        (
            "max_workers",
            KnobStatus::Consumed("bin/kata main worker admission cap"),
        ),
    ]
}

/// Knob registry for [`ApiConfig`]. Every serde field MUST appear here or the
/// `types` inert-knob test fails. The nested `auth` object's sub-fields
/// (`verifying_key_env`, `verifying_key_file`) are validated separately in
/// [`KataConfig::validate`]; the guard covers the top-level `auth` key.
#[must_use]
pub fn api_knob_registry() -> &'static [(&'static str, KnobStatus)] {
    &[
        (
            "bind",
            KnobStatus::Consumed("bin/kata boot API server bind + validate() socket-address check"),
        ),
        (
            "auth",
            KnobStatus::Consumed(
                "crates/api signed-token middleware (ApiAuthConfig sub-fields \
                 additionally validated in KataConfig::validate)",
            ),
        ),
    ]
}

/// Knob registry for [`TelemetryConfig`]. Every serde field MUST appear here or
/// the `types` inert-knob test fails.
#[must_use]
pub fn telemetry_knob_registry() -> &'static [(&'static str, KnobStatus)] {
    &[
        (
            "enabled",
            KnobStatus::Consumed("kata-core init_telemetry master switch"),
        ),
        (
            "log_level",
            KnobStatus::Consumed(
                "kata-core init_telemetry subscriber filter + workflow-runner hot-reload",
            ),
        ),
        (
            "log_json",
            KnobStatus::Consumed("kata-core init_telemetry JSON-vs-text formatter"),
        ),
        (
            "export",
            KnobStatus::Consumed("kata-core init_telemetry extra-exporter selection"),
        ),
        (
            "otlp_endpoint",
            KnobStatus::Consumed(
                "kata-core init_telemetry OTLP trace-exporter endpoint (export = otlp)",
            ),
        ),
        (
            "metrics_bind",
            KnobStatus::Consumed(
                "kata-core init_telemetry Prometheus pull listener (export = prometheus)",
            ),
        ),
    ]
}

/// Knob registry for the [`AgentBackendConfig::Harness`] bag (an
/// `[agents.<label>]` block under any label but a reserved deterministic one).
/// [`AgentBackendConfig::Shell`] carries no field, so its registry is empty and
/// [`KataConfig::inert_knobs`] flags any field it grows.
#[must_use]
pub fn agent_backend_knob_registry() -> &'static [(&'static str, KnobStatus)] {
    // Under the `oci` route the only consumers of `[agents.*]` fields are the `capsule_*`
    // accessors the CHECK and capsule assembly read. A field with no consumer is deleted
    // — do NOT mark a dead knob `Consumed` just to keep this list uniform.
    use KnobStatus::Consumed;
    &[
        (
            "model",
            Consumed(
                "capsule_assembly AgentTurnSpec.model — the node's machine default when the stage authors no `model =`",
            ),
        ),
        (
            "reasoning_effort",
            Consumed(
                "capsule_assembly AgentTurnSpec.reasoning_effort — delivered through the adapter's own channel",
            ),
        ),
        (
            "adapter",
            Consumed(
                "oci CHECK adapter_unqualified/adapter_undeclared + capsule_assembly AgentTurnSpec.adapter",
            ),
        ),
        (
            "credential",
            Consumed(
                "oci CHECK credential_undeclared + capsule_assembly AgentTurnSpec.credential (mode + source reference)",
            ),
        ),
        (
            "env",
            Consumed(
                "capsule_assembly AgentTurnSpec.env (the tool processes' declared non-secret environment, identity-hashed)",
            ),
        ),
    ]
}

/// Return the fully-qualified paths of serde fields on `section` that violate
/// the consumed-knob rule.
///
/// `section` is serialized to a JSON object so the check enumerates the ACTUAL
/// serde surface — a newly-added field appears as a new key with no registry
/// entry and is reported, making the guard fail-closed against future dead
/// knobs. The reverse direction is also checked: a registry entry with no
/// matching serde field (a stale row left behind after a knob deletion) is
/// reported too, keeping registry and struct in lockstep.
#[must_use]
pub fn section_inert_knobs<T: Serialize>(
    prefix: &str,
    section: &T,
    registry: &[(&'static str, KnobStatus)],
) -> Vec<String> {
    let value = serde_json::to_value(section)
        .expect("config section must serialize to JSON for the inert-knob guard");
    let mut findings = Vec::new();
    let keys: std::collections::BTreeSet<String> = match value.as_object() {
        Some(map) => map.keys().cloned().collect(),
        // A non-object section has no enumerable knobs; nothing to check.
        None => return findings,
    };
    for key in &keys {
        if !registry.iter().any(|(name, _)| name == key) {
            findings.push(format!(
                "{prefix}.{key} (declared serde field with no consumer — dead knob)"
            ));
        }
    }
    for (name, _) in registry {
        if !keys.contains(*name) {
            findings.push(format!(
                "{prefix}.{name} (registry entry has no matching serde field — \
                 prune this stale row)"
            ));
        }
    }
    findings.sort();
    findings
}

impl KataConfig {
    /// Fully-qualified paths of every config knob that violates the
    /// consumed-knob rule (see [`KnobStatus`]). Empty in a healthy
    /// build; [`KataConfig::validate`] turns a non-empty result into a
    /// [`KataError::Validation`] so `kata config check` fails closed.
    #[must_use]
    pub fn inert_knobs(&self) -> Vec<String> {
        let mut out = section_inert_knobs("node", &self.node, node_knob_registry());
        out.extend(section_inert_knobs(
            "runtime",
            &self.runtime,
            runtime_knob_registry(),
        ));
        out.extend(section_inert_knobs(
            "workers",
            &self.workers,
            workers_knob_registry(),
        ));
        out.extend(section_inert_knobs("api", &self.api, api_knob_registry()));
        out.extend(section_inert_knobs("vcs", &self.vcs, vcs_knob_registry()));
        out.extend(section_inert_knobs(
            "telemetry",
            &self.telemetry,
            telemetry_knob_registry(),
        ));
        out.extend(section_inert_knobs(
            "containment",
            &self.containment,
            containment_knob_registry(),
        ));
        out.extend(section_inert_knobs(
            "git_view",
            &self.git_view,
            git_view_knob_registry(),
        ));
        out.extend(section_inert_knobs(
            "pricing",
            &self.pricing,
            pricing_knob_registry(),
        ));
        for (name, backend) in &self.agents {
            let registry = match backend {
                AgentBackendConfig::Harness { .. } => agent_backend_knob_registry(),
                AgentBackendConfig::Shell {} => &[],
            };
            out.extend(section_inert_knobs(
                &format!("agents.{name}"),
                backend,
                registry,
            ));
        }
        out
    }

    /// Validate the config.
    ///
    /// Among other checks:
    ///
    /// * `node.data_dir` is not empty.
    /// * `api.bind` parses as a `SocketAddr`.
    /// * `workers.transports` is non-empty for a local main.
    pub fn validate(&self) -> KataResult<()> {
        if self.runtime.max_active_executions == 0
            || self.runtime.max_active_executions > MAX_ACTIVE_EXECUTIONS
        {
            return Err(KataError::Validation(format!(
                "runtime.max_active_executions must be in 1..={MAX_ACTIVE_EXECUTIONS}"
            )));
        }
        if self.runtime.max_active_execution_bytes == 0
            || self.runtime.max_active_execution_bytes > MAX_ACTIVE_EXECUTION_BYTES
            || usize::try_from(self.runtime.max_active_execution_bytes).is_err()
        {
            return Err(KataError::Validation(format!(
                "runtime.max_active_execution_bytes must fit usize and be in 1..={MAX_ACTIVE_EXECUTION_BYTES}"
            )));
        }
        self.pricing.validate()?;
        if self.git_view.history_depth == Some(0) {
            return Err(KataError::Validation(
                "git_view.history_depth must be at least 1 when declared — a zero-commit history \
                 cannot hold the base commit the agent's view is rooted at, so every agent-stage \
                 admission would fail. Omit the key for the whole reachable history"
                    .into(),
            ));
        }
        if self.node.data_dir.as_os_str().is_empty() {
            return Err(KataError::Validation(
                "node.data_dir must be a non-empty path".into(),
            ));
        }
        if self.node.work_tree_max_bytes == 0 || self.node.work_tree_max_entries == 0 {
            return Err(KataError::Validation(
                "node.work_tree_max_bytes and node.work_tree_max_entries must be non-zero: a \
                 zeroed /work input ceiling would refuse every isolated execution's base tree \
                 at admission"
                    .into(),
            ));
        }
        // `[node] egress_allow` — every entry is an `EgressAuthority` spelling,
        // parsed HERE at load so a misspelled authority is a boot refusal
        // rather than an allowlist entry that silently never matches.
        for spelling in &self.node.egress_allow {
            crate::execution_contract::EgressAuthority::from_authority_str(spelling).map_err(
                |error| {
                    KataError::Validation(format!(
                        "node.egress_allow entry `{spelling}` is not a `host:port` the egress \
                         allowlist can name: {error}"
                    ))
                },
            )?;
        }
        if self.workers.assignment_start_deadline_ms == 0 {
            return Err(KataError::Validation(format!(
                "{CAPSULE_START_DEADLINE_DISABLED}: `[workers] assignment_start_deadline_ms = 0` \
                 disables the start deadline, and that deadline is the main's ONLY leg for a \
                 capsule delivered and never started — a frame lost after the transport \
                 accepted it, or a start the main never folded. A capsule's wall-time leg \
                 measures from its start, so without this one such an attempt would stay \
                 live forever. Set a non-zero deadline (the default is {} ms)",
                default_assignment_start_deadline_ms()
            )));
        }
        if self.workers.heartbeat_interval_ms == 0 {
            return Err(KataError::Validation(format!(
                "{HEARTBEAT_INTERVAL_DISABLED}: `[workers] heartbeat_interval_ms = 0` is the \
                 period of the main's heartbeat sweep and of its deadline sweep, and neither \
                 can tick at zero: the main would run with no worker-liveness leg and no \
                 deadline leg. Set a non-zero interval (the default is {} ms)",
                WorkerPoolConfig::default().heartbeat_interval_ms
            )));
        }
        if self.workers.heartbeat_grace_ms < self.workers.heartbeat_interval_ms {
            return Err(KataError::Validation(format!(
                "{HEARTBEAT_GRACE_BELOW_INTERVAL}: `[workers] heartbeat_grace_ms = {}` is shorter \
                 than `heartbeat_interval_ms = {}`. A worker beats every half interval and a stall \
                 of the main's sweep counts as at most one interval of its silence, so a shorter \
                 grace would settle a live worker dead for a heartbeat delayed by less than half \
                 an interval. Set the grace to at least the interval",
                self.workers.heartbeat_grace_ms, self.workers.heartbeat_interval_ms
            )));
        }
        if self.workers.dispatch_deadline_ms == 0 {
            return Err(KataError::Validation(format!(
                "{DISPATCH_DEADLINE_DISABLED}: `[workers] dispatch_deadline_ms = 0` bounds a \
                 capsule send by nothing but the runtime timer's next tick: a healthy delivery \
                 to an idle worker whose send has to wait at all would be settled PROVEN \
                 AMBIGUOUS. Set a non-zero deadline (the default is {} ms)",
                default_dispatch_deadline_ms()
            )));
        }
        let sock: SocketAddr = self.api.bind.parse().map_err(|e| {
            KataError::Validation(format!(
                "api.bind '{}' is not a valid socket address: {e}",
                self.api.bind
            ))
        })?;
        match &self.api.auth {
            ApiAuthConfig::Disabled {} if !sock.ip().is_loopback() => {
                return Err(KataError::Validation(format!(
                    "api.auth.type = \"disabled\" is allowed only on loopback binds; \
                     api.bind '{}' would expose an unauthenticated API",
                    self.api.bind
                )));
            }
            ApiAuthConfig::SignedToken {
                verifying_key_env,
                verifying_key_file,
                ..
            } if self.api.auth.verifying_key_source_count() != 1 => {
                return Err(KataError::Validation(format!(
                    "api.auth.type = \"signed_token\" must configure exactly one verifying-key \
                     source; got verifying_key_env={has_env} verifying_key_file={has_file}",
                    has_env = verifying_key_env.is_some(),
                    has_file = verifying_key_file.is_some()
                )));
            }
            ApiAuthConfig::SignedToken {
                verifying_key_env: Some(name),
                ..
            } if name.trim().is_empty() => {
                return Err(KataError::Validation(
                    "api.auth.verifying_key_env must not be empty".into(),
                ));
            }
            // `kata service install` snapshots this variable into the installed
            // main's environment and refuses any `KATA_` name there, so the main
            // refuses it too: a config is installable exactly when it is valid.
            ApiAuthConfig::SignedToken {
                verifying_key_env: Some(name),
                ..
            } if name.starts_with("KATA_") => {
                return Err(KataError::Validation(format!(
                    "api.auth.verifying_key_env names {name:?}, inside kata's reserved KATA_ \
                     namespace; choose an operator-owned name such as API_VERIFYING_KEY"
                )));
            }
            ApiAuthConfig::SignedToken {
                verifying_key_file: Some(path),
                ..
            } if path.as_os_str().is_empty() => {
                return Err(KataError::Validation(
                    "api.auth.verifying_key_file must not be empty".into(),
                ));
            }
            ApiAuthConfig::SignedToken { .. } if !sock.ip().is_loopback() => {
                return Err(KataError::Validation(format!(
                    "api.auth.type = \"signed_token\" is currently supported only on a \
                     loopback API listener; api.bind '{}' is non-loopback. Keep the main API \
                     local and use an operator-managed authenticated tunnel or reverse proxy",
                    self.api.bind
                )));
            }
            _ => {}
        }
        if self.workers.transports.is_empty() {
            return Err(KataError::Validation(
                "workers.transports must be non-empty for a local main".into(),
            ));
        }
        if self.workers.max_workers == 0 {
            return Err(KataError::Validation(
                "workers.max_workers must be greater than zero: configured capacity providers are mandatory and each admitted worker consumes one slot"
                    .into(),
            ));
        }
        let supervised_count = self
            .workers
            .transports
            .iter()
            .filter(|transport| matches!(transport, WorkerTransportConfig::SupervisedNode {}))
            .count();
        if supervised_count > 1 {
            return Err(KataError::Validation(
                "workers.transports may contain at most one type = \"supervised_node\" entry; kata serve starts exactly one node for it"
                    .into(),
            ));
        }
        let has_local_socket = self
            .workers
            .transports
            .iter()
            .any(|transport| matches!(transport, WorkerTransportConfig::LocalSocket { .. }));
        let minimum_workers = supervised_count + usize::from(has_local_socket);
        if (self.workers.max_workers as usize) < minimum_workers {
            return Err(KataError::Validation(format!(
                "workers.max_workers={} cannot make every configured provider usable: require at least {minimum_workers} — one slot for the supervised node and one local-socket admission slot",
                self.workers.max_workers
            )));
        }
        if self.vcs.jj_repo.as_os_str().is_empty() {
            return Err(KataError::Validation(
                "vcs.jj_repo must be a non-empty path".into(),
            ));
        }
        if let Some(remote) = &self.vcs.recovery_remote {
            validate_recovery_remote_binding(&remote.id, &remote.url)?;
        }
        // The keep-newer floor is the undo-horizon + defense-in-depth
        // concurrent-writer safety guard (nothing newer than `now - keep_newer` is
        // ever abandoned or collected). Compaction is now made race-safe
        // independently by re-reading the op-heads under the same lock jj's own
        // publish takes, but a zero floor still eradicates the entire `jj undo`
        // horizon on the first pass and removes the second, independent guard —
        // reject it when GC is enabled rather than let a legal knob value open
        // that door. Disable GC (op_log_gc_enabled = false) if you truly want no
        // retention floor.
        if self.vcs.op_log_gc_enabled && self.vcs.op_log_gc_keep_newer_secs == 0 {
            return Err(KataError::Validation(
                "vcs.op_log_gc_keep_newer_secs must be > 0 when vcs.op_log_gc_enabled is true: \
                 it is the undo-horizon and concurrent-writer safety floor (nothing newer than \
                 `now - keep_newer` is ever abandoned or collected). Set a nonzero number of \
                 seconds (default 600), or disable op-log GC with vcs.op_log_gc_enabled = false"
                    .into(),
            ));
        }
        // A reserved deterministic label (`shell`, `workspace_effect`) is the
        // deterministic executor's and nothing else's, and the executor sits under
        // no other label. The promotion trust gate keys validation-proof-stage
        // determinism on the routing label, so a model agent under `shell` would
        // route required-criterion proof stages to a self-certifying agent, and a
        // shell entry under a model label would be an agent no stage can run.
        // [`deserialize_agents`] decides the variant by the label, so a parsed
        // config always holds this; a config built in code is held to it here.
        for (name, cfg) in &self.agents {
            if crate::agent::is_deterministic_agent_label(name) != cfg.is_deterministic() {
                return Err(KataError::Validation(format!(
                    "agents.{name}: the reserved deterministic labels (`shell`, \
                     `workspace_effect`) are the shell route and nothing else is — a model \
                     agent under one would let validation proof stages self-certify and \
                     silently promote"
                )));
            }
        }
        // The consumed-knob rule: reject any declared config knob that has no
        // live consumer. This is the operator-facing mirror of the fail-closed
        // `types` inert-knob unit test.
        let inert = self.inert_knobs();
        if !inert.is_empty() {
            return Err(KataError::Validation(format!(
                "inert config knob(s) violate the consumed-knob rule: {}. \
                 Delete the knob or wire a consumer in crates/types/src/config.rs",
                inert.join("; ")
            )));
        }
        Ok(())
    }
}

/// Parse a `kata.toml` text into a [`KataConfig`] — the one text-to-config door
/// every loader goes through (`ConfigManager`'s load, snapshot, reload and hot
/// reload, and [`load_config_placeholder`]). It neither normalizes nor validates.
///
/// The typed parse refuses every key no section declares — every section type is
/// `deny_unknown_fields` — naming the dotted path it sits at (`runtime.<key>`, or
/// the `agents.<label>` / `workers.transports[0]` entry an agent block's or a
/// `type =`-tagged table's key sits in).
///
/// What this does not close are the maps whose keys are the operator's own names:
/// the `[agents]` labels and an agent's `env` variable names. Every table nested in a
/// section is closed, `[node] environment`'s `integrity_policy` included.
///
/// # Errors
/// [`KataError::Config`] naming `source` and the refused key.
pub fn parse_kata_config(text: &str, source: &Path) -> KataResult<KataConfig> {
    parse_config_toml(text, source)
}

/// Deserialize a TOML file's text as `T`, naming the dotted key path an error sits at
/// — `runtime.<key>` for an undeclared key in a plain table, the entry
/// (`agents.<label>`, `workers.transports[0]`) for one inside an agent block or a
/// `type =`-tagged table, whose own text names the key. toml's error alone carries a line and
/// column, not the section the key was written under.
fn parse_config_toml<T: serde::de::DeserializeOwned>(text: &str, source: &Path) -> KataResult<T> {
    serde_path_to_error::deserialize(toml::Deserializer::new(text)).map_err(|error| {
        let at = error.path().to_string();
        let error = error.into_inner();
        KataError::Config(if at == "." {
            format!("failed to parse {}: {error}", source.display())
        } else {
            format!("failed to parse {} at `{at}`: {error}", source.display())
        })
    })
}

/// Synchronously load a `KataConfig` from a TOML file at `path`.
///
/// A one-shot read + normalize + validate. The binary loads through
/// `kata_core::ConfigManager::load`, which shares [`parse_kata_config`].
///
/// Tilde-expansion runs after deserialization and before
/// `validate()` so both the validator and every downstream subsystem
/// observe absolute, tilde-free paths.
pub fn load_config_placeholder(path: &Path) -> KataResult<KataConfig> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| KataError::Config(format!("failed to read {}: {e}", path.display())))?;
    let mut cfg = parse_kata_config(&text, path)?;
    cfg.normalize_paths();
    cfg.validate()?;
    Ok(cfg)
}

/// Synchronously load a `WorkerNodeConfig` from a TOML file at `path`.
///
/// Worker binaries use a separate, smaller config file that tells them
/// where the main lives and what capabilities to advertise.
///
/// `credential_path` has `~/` expanded to `$HOME/` before the
/// config returns to the caller.
pub fn load_worker_config(path: &Path) -> KataResult<WorkerNodeConfig> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| KataError::Config(format!("failed to read {}: {e}", path.display())))?;
    // Every key the file does not declare — top level, a `capabilities` entry —
    // is refused here, naming its path.
    let mut cfg: WorkerNodeConfig = parse_config_toml(&text, path)?;
    if cfg.expected_membrane_id.0 == ulid::Ulid::nil() {
        return Err(KataError::Validation(
            "expected_membrane_id must identify a provisioned worker store".into(),
        ));
    }
    cfg.normalize_paths();
    if cfg.home_node_endpoint.is_empty() {
        return Err(KataError::Validation(
            "home_node_endpoint must not be empty".into(),
        ));
    }
    if !cfg.home_node_endpoint.starts_with("unix://") {
        return Err(KataError::Validation(format!(
            "remote worker endpoint '{}' is not supported: a worker reaches its main over \
             a unix:// local-worker endpoint; this build has no versioned network worker \
             protocol",
            cfg.home_node_endpoint
        )));
    }
    if let Some(path) = cfg.home_node_endpoint.strip_prefix("unix://") {
        crate::unix_socket_name::socket_file_name(std::path::Path::new(path))
            .map_err(|refusal| KataError::Validation(format!("home_node_endpoint: {refusal}")))?;
    }
    Ok(cfg)
}
