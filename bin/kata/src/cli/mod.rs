//! Kata CLI surface.
//!
//! The production surface has one installed durable main (`kata serve` or the
//! native user service). Operator commands and `kata mcp` attach to it; a
//! workflow runs only there.
//!
//! The module is split into one file per subcommand group:
//!
//! * `types` — clap subcommand enums
//! * `workflows` — `kata workflows list` / `inspect`
//! * `solo` — foreground installed-main boot
//! * `config_check` — `kata config check` and the typed-summary
//!   printer used by `solo` boot

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

mod api_token;
mod backup;
mod config_check;
pub(crate) mod doctor;
mod evidence;
mod execution_provider;
pub(crate) mod init;
mod login;
pub mod mcp;
mod node_environment;
mod operator;
mod output;
mod recovery_artifact_verifier;
mod recovery_capture;
mod recovery_references;
mod recovery_restore;
mod repair_nucleus;
mod repo_ignore;
mod service;
mod skill;
mod solo;
mod syscall_probe;
mod types;
mod upgrade;
mod workflows;

pub use output::OutputFormat;

pub(crate) use kata_types::config::DELEGATED_SCOPE;
pub use types::{
    ApiTokenCmd, CliApiScope, ConfigCmd, EvidenceCmd, ExecutionProviderCmd, FactoryCmd, HostCmd,
    LoginCmd, LoginProviderArg, MemoryCmd, NodeCmd, NodeEnvironmentCmd, RunCmd, SandboxCmd,
    ServiceCmd, SkillCmd, SkillHost, SteerCmd, WorkflowsCmd,
};

/// Test-only helpers — re-exports gated through `cli::testing` so that
/// integration tests under `bin/kata/tests/` can reach internals
/// without those internals appearing in shipped builds. The crate's self
/// dev-dependency enables `test-support` for integration-test binaries.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod testing {
    /// Initialize the current fixed persistent-engine store set for CLI
    /// integration fixtures through the same identity-last path as production.
    pub fn initialize_clean_data_dir_for_test(path: &std::path::Path) -> anyhow::Result<()> {
        drop(crate::data_dir_lock::DataDirLock::initialize_installed_for_test(path)?);
        Ok(())
    }

    pub use super::backup::run_restore_cmd_with_lease_paths;
    pub use super::config_check::{
        config_check, render_agent_listing, render_stdlib_roots, render_vcs_preflight,
    };
    pub use super::doctor::{DoctorStatus, doctor_report_with_logins_dir};

    /// A logins directory that holds no kata login, for
    /// [`doctor_report_with_logins_dir`]: `no-kata-logins` beside `config`,
    /// which nothing creates. A doctor cell plants it so its `kata_login` row
    /// never reads the effective owner's own logins.
    #[must_use]
    pub fn no_kata_logins(config: &std::path::Path) -> Result<std::path::PathBuf, String> {
        Ok(config
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("no-kata-logins"))
    }
    pub use super::node_environment::{
        RELEASE_REQUIRES_STOPPED_MAIN, run_release_cmd_with_lease_paths,
    };
    pub use super::repair_nucleus::{
        run_repair_nucleus_cmd, run_repair_nucleus_cmd_with_lease_paths,
    };
    pub use super::upgrade::{
        execution_program_compatibility_plan, resolve_data_dir, run_upgrade_cmd,
        run_upgrade_cmd_with_lease_paths,
    };
}

use crate::host_setup;
use crate::provider_install;

/// Top-level Kata CLI.
#[derive(Debug, Parser)]
#[command(name = "kata", version, about = "Kata coordination binary")]
pub struct Cli {
    /// Base URL of the installed Kata main. Used by operator-facing
    /// commands such as `kata watch` and `kata run list`. When the API
    /// is token-protected, set `KATA_API_TOKEN` for the bearer token.
    #[arg(
        long,
        env = "KATA_API_URL",
        default_value = "http://127.0.0.1:8400",
        global = true
    )]
    pub api_url: String,

    /// Global output format for the commands that HAVE a human text
    /// renderer. Defaults to human-readable text.
    ///
    /// `json` makes `check` — the `check` operation's own CLI face — emit the
    /// schema'd, versioned `OpEnvelope` (`{op, schema_version, ok, data}`)
    /// whose `data` is that operation's response, the document the MCP `check`
    /// tool and REST `/ops/check` return. Every other such command emits its
    /// own JSON document bare, with no envelope, because it is no operation's
    /// response: build, doctor, workflows list/inspect/check/schema,
    /// sandbox install-external-provider, host setup/apparmor-install,
    /// execution-provider, explain, report, factory report, timeline, diff,
    /// usage. None of these takes a per-command `--json`.
    ///
    /// It does NOT wrap the operator read commands. Those emit bare
    /// records in every format and always have — one JSON document
    /// (`run show`, `run output`, `run current`, `run wait`, `status`,
    /// `health`, `version`, `workspace`, `execution-workspace`) or
    /// newline-delimited JSON, one record per line (`run list` under
    /// `--json`/`--format json`, `workers`, `approvals`,
    /// `steer`). `run list`'s raw NDJSON is deliberate: enveloping it
    /// would break every consumer that parses that stream. The `factory`
    /// subcommands likewise emit bare JSON in every format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human, global = true)]
    pub format: OutputFormat,

    #[command(subcommand)]
    pub command: Command,
}

/// Whether an error from this invocation needs the native-service diagnostic
/// fallback before the normal tracing subscriber exists.
#[doc(hidden)]
#[must_use]
pub fn is_native_service_invocation(cli: &Cli) -> bool {
    matches!(&cli.command, Command::ServiceExec { .. })
        || matches!(&cli.command, Command::Serve { .. })
            && std::env::var_os(crate::attachment::SERVICE_DISCOVERY_LEASE_FD_ENV).is_some()
}

/// Detect the native manager/trampoline boundary before Clap can reject argv.
/// The installed definition places `__service-exec` exactly at argv[1]; the
/// exec'd `serve` image carries at least one reserved descriptor marker even
/// when a malformed partial handoff must later fail closed.
#[doc(hidden)]
#[must_use]
pub fn is_raw_native_service_invocation() -> bool {
    raw_native_service_invocation_from(
        std::env::args_os().nth(1).as_deref(),
        std::env::var_os(crate::attachment::SERVICE_DISCOVERY_LEASE_FD_ENV).is_some(),
        std::env::var_os(crate::authority_file::SERVICE_CONFIG_SNAPSHOT_FD_ENV).is_some(),
    )
}

fn raw_native_service_invocation_from(
    first_argument: Option<&std::ffi::OsStr>,
    discovery_handoff: bool,
    config_handoff: bool,
) -> bool {
    first_argument == Some(std::ffi::OsStr::new("__service-exec"))
        || discovery_handoff
        || config_handoff
}

/// Load an operator-local `.env` only for an ordinary CLI process.
///
/// The installed-service trampoline clears the environment and execs `serve`
/// with an immutable, digest-bound snapshot plus two reserved descriptor
/// markers. Neither the manager-launched trampoline nor that second image may
/// read `.env`: the former has an exact hidden argv and the latter would add
/// post-install values outside the snapshot digest. Either marker suppresses
/// dotenv loading; malformed partial handoffs fail later without consulting
/// ambient working-directory state. The presence-only `KATA_NO_DOTENV`
/// process marker provides the same suppression for any ordinary invocation.
///
/// `.env` never overrides a launch value. dotenvy judges a variable present
/// with `std::env::var`, which errs on a value that is not UTF-8 as on an
/// unset one, so such a launch value is put back after the load: a worker
/// refuses that key by name instead of lifting the file's.
///
/// Called first in `main`, before any thread exists: it writes the process
/// environment.
#[doc(hidden)]
pub fn load_operator_dotenv() {
    let service_trampoline =
        std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("__service-exec"));
    let native_service_handoff = service_trampoline
        || std::env::var_os(crate::attachment::SERVICE_DISCOVERY_LEASE_FD_ENV).is_some()
        || std::env::var_os(crate::authority_file::SERVICE_CONFIG_SNAPSHOT_FD_ENV).is_some();
    if should_load_operator_dotenv(
        native_service_handoff,
        !kata_types::operator_dotenv_enabled(),
    ) {
        let _ = LAUNCH_ENV_NAMES.set(std::env::vars_os().map(|(name, _)| name).collect());
        let undecodable: Vec<_> = std::env::vars_os()
            .filter(|(_, value)| value.to_str().is_none())
            .collect();
        let _ = dotenvy::dotenv();
        restore_launch_values(undecodable);
    }
}

/// Put back each launch value `.env` replaced — only a value that is not UTF-8
/// can be, since dotenvy leaves every variable `std::env::var` reads.
#[allow(unsafe_code)]
fn restore_launch_values(launch: Vec<(std::ffi::OsString, std::ffi::OsString)>) {
    for (name, value) in launch {
        if std::env::var_os(&name).as_ref() != Some(&value) {
            // SAFETY: `load_operator_dotenv` runs first in `main`, before any
            // thread exists, so nothing reads or writes the environment
            // concurrently — the same boundary dotenvy's own `set_var` relies on.
            unsafe { std::env::set_var(&name, &value) };
        }
    }
}

/// A variable of the environment this process was LAUNCHED with — `None` for
/// one only `.env` supplied. `.env` never overrides a launch value, so a
/// launch value is the one a rewritten `.env` cannot change.
pub(crate) fn launch_env_var(key: &str) -> Option<String> {
    let value = std::env::var(key).ok()?;
    match LAUNCH_ENV_NAMES.get() {
        Some(names) if !names.contains(std::ffi::OsStr::new(key)) => None,
        _ => Some(value),
    }
}

/// The variable names this process was launched with, captured just before
/// [`load_operator_dotenv`] loads `.env`. Unset when no `.env` load ran, and
/// then every variable is a launch value.
static LAUNCH_ENV_NAMES: std::sync::OnceLock<std::collections::BTreeSet<std::ffi::OsString>> =
    std::sync::OnceLock::new();

fn should_load_operator_dotenv(native_service_handoff: bool, dotenv_disabled: bool) -> bool {
    !native_service_handoff && !dotenv_disabled
}

/// Mirror unexpected native-service panics into the macOS unified log before
/// invoking Rust's default panic hook. Launchd intentionally has no fixed
/// stdout/stderr files, so the unified event is the bounded durable diagnostic
/// path for a panic that bypasses `main`'s normal `Result` handling.
#[doc(hidden)]
pub fn install_native_service_panic_hook(native_service: bool) {
    #[cfg(target_os = "macos")]
    if native_service {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let payload = info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
                .unwrap_or("non-string panic payload");
            let location = info.location().map_or_else(
                || "unknown location".to_owned(),
                |location| {
                    format!(
                        "{}:{}:{}",
                        location.file(),
                        location.line(),
                        location.column()
                    )
                },
            );
            let _ = crate::macos_unified_log::write_startup_error(&format!(
                "native Kata service panic at {location}: {payload}"
            ));
            default_hook(info);
        }));
    }
    #[cfg(not(target_os = "macos"))]
    let _ = native_service;
}

/// Preserve startup failures that occur before the service process can install
/// its telemetry subscriber. On macOS the launchd plist intentionally has no
/// unbounded stdout/stderr files, so these errors go directly to the same
/// exact unified-log subsystem/category as normal service events.
#[doc(hidden)]
pub fn report_native_service_startup_error(native_service: bool, message: &str) {
    if !native_service {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        let _ = crate::macos_unified_log::write_startup_error(message);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = message;
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the one installed durable main in the foreground.
    ///
    /// User service managers invoke this exact entrypoint; Kata never
    /// daemonizes itself or creates a second supervisory control plane.
    Serve {
        /// Installed-main node configuration.
        #[arg(long)]
        config: PathBuf,
    },
    /// Manage the native per-user service for the one installed main.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Internal native-service trampoline. Loads the owner-only environment
    /// source, then execs the same binary's installed-main entrypoint.
    #[command(name = "__service-exec", hide = true)]
    ServiceExec {
        #[arg(long)]
        definition: PathBuf,
        #[arg(long)]
        environment: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        expected_binary_digest: String,
        #[arg(long)]
        expected_config_digest: String,
        #[arg(long)]
        expected_environment_digest: String,
        #[arg(long)]
        expected_data_directory: PathBuf,
        #[arg(long)]
        expected_directory_id: String,
    },
    /// Initialize project-local Kata config and workflow override dirs.
    Init {
        /// Config file to create. Defaults to `./.kata/kata.toml`.
        #[arg(long, default_value = ".kata/kata.toml")]
        config: PathBuf,
        /// Replace an existing config after writing a timestamped backup.
        #[arg(long)]
        force: bool,
        /// Print the generated TOML and do not touch the filesystem.
        #[arg(long)]
        print: bool,
    },
    /// Validate local first-run project readiness without booting a node.
    Doctor {
        /// Config file to validate. Defaults to `./.kata/kata.toml`.
        #[arg(long, default_value = ".kata/kata.toml")]
        config: PathBuf,
        /// Additional workflow name or `.star` path to compile-check.
        #[arg(long = "workflow")]
        workflow: Vec<String>,
        /// Also query the configured `--api-url` for live health/status.
        #[arg(long)]
        online: bool,
    },
    /// Subsystem health snapshot from a running API node.
    Health,
    /// Top-level system status from a running API node.
    Status,
    /// Running daemon build provenance.
    Version {
        /// Also compare the daemon build SHA against local `git rev-parse HEAD`.
        #[arg(long)]
        compare: bool,
    },
    /// Build a workflow into the checked execution IR without running it.
    Build {
        /// Workflow library name or path to a `.star` workflow file.
        workflow: String,
        /// Write the portable build JSON projection, including checked IR, to
        /// this path.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Exit nonzero when the checked execution program has warnings.
        #[arg(long)]
        deny_warnings: bool,
        /// Node config (`kata.toml`) whose `[node]` facts this judgment
        /// installs — without it, the build judges the pack alone and names
        /// every node fact class it did not judge (`agents`, `ceilings`,
        /// `egress`, `environment`); with it, all but `environment`, which only
        /// a booted node binds. `KATA_CONFIG` is the same door spelled in the environment —
        /// how a pack-authored `kata build` validation command inherits the
        /// profile of the node its stage runs inside.
        #[arg(long, env = "KATA_CONFIG")]
        config: Option<PathBuf>,
    },
    /// Check a workflow without running it.
    Check {
        /// Workflow library name or path to a `.star` workflow file.
        workflow: Option<String>,
        /// Check every effective workflow in the layered library.
        #[arg(long)]
        all: bool,
        /// Exit nonzero when the checked execution program has warnings.
        #[arg(long)]
        deny_warnings: bool,
        /// Node config (`kata.toml`) whose `[node]` facts this judgment
        /// installs — without it, the check judges the pack alone and names
        /// every node fact class it did not judge (`agents`, `ceilings`,
        /// `egress`, `environment`); with it, all but `environment`, which only
        /// a booted node binds. `KATA_CONFIG` is the same door spelled in the environment —
        /// how a pack-authored `kata check` validation command inherits the
        /// profile of the node its stage runs inside.
        #[arg(long, env = "KATA_CONFIG")]
        config: Option<PathBuf>,
    },
    /// Inspect preserved workflow/factory evidence packets without booting Kata.
    Evidence {
        #[command(subcommand)]
        cmd: EvidenceCmd,
    },
    /// Submit, inspect, or control a workflow on the installed main.
    #[command(subcommand_precedence_over_arg = true)]
    Run {
        /// Inspect or control executions through a running API node.
        #[command(subcommand)]
        cmd: Option<RunCmd>,
        /// Workflow library NAME or path to a `.star` workflow file.
        ///
        /// A value that names an existing file, contains a path separator, or
        /// ends in `.star` is treated as a PATH: this command reads the file
        /// and submits its source. Anything else is a library NAME, sent to
        /// the main as it is: the MAIN resolves it, against the workflow roots
        /// it took from its own working directory and `HOME` when it started,
        /// highest priority first: `./.kata/workflows/` (project) →
        /// `~/.kata/workflows/` (user) → the bundled stdlib → the bundled
        /// `kata-factory` workflows → the bundled examples, and, when the
        /// main's `KATA_STDLIB_DIR` names the stdlib, that directory's `smoke`
        /// sibling last. `kata check` and
        /// `kata workflows list` resolve a name where they run instead, so from
        /// a directory other than the one the main started in, pass the PATH.
        /// Starlark (`.star`) is the sole workflow frontend; TOML is only the
        /// node config (`kata.toml`).
        workflow: Option<String>,
        /// Submit the workflow to the running API node and print its execution id.
        #[arg(long)]
        submit: bool,
        /// Submit the workflow to the running API node and stream it until terminal.
        #[arg(long, conflicts_with = "wait")]
        watch: bool,
        /// Submit the workflow to the running API node and poll until terminal.
        #[arg(long, conflicts_with = "watch")]
        wait: bool,
        /// Include full execution outputs in `--watch` snapshot lines.
        #[arg(long)]
        include_outputs: bool,
        /// Maximum seconds for `--wait`.
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        /// Poll interval in milliseconds for `--wait`.
        #[arg(long, default_value_t = 500)]
        poll_ms: u64,
        /// A typed invocation param `name=value` (repeatable). The value
        /// is parsed as JSON when it parses (`3`, `true`, `"x"`, `[1,2]`),
        /// otherwise taken as a bare string. Resolved against the workflow's
        /// declared `workflow(params=..)` contract at admission.
        #[arg(long = "param", value_name = "NAME=VALUE")]
        param: Vec<String>,
        /// A JSON file of `{name: value}` invocation params. Merged UNDER
        /// `--param` (an explicit `--param` overrides the same key in the file).
        #[arg(long = "params-file", value_name = "PATH")]
        params_file: Option<PathBuf>,
        /// What an isolated workflow works on: `trunk` (the default) or
        /// `pr:<N>`, the forge's pull request N (read through `gh`, its head
        /// and base fetched). Resolved and frozen when the run is admitted, so
        /// the run's base does not move with the branch afterwards. Refused for
        /// a workflow that forks no isolated workspace.
        #[arg(long = "target", value_name = "SPEC")]
        target: Option<String>,
    },
    /// Follow one execution with live snapshots and ledger/progress events.
    Watch {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
        /// Include full execution outputs in snapshot lines.
        #[arg(long)]
        include_outputs: bool,
        /// Stop following after N seconds and exit non-zero, naming the last
        /// status seen and how many frames arrived.
        ///
        /// `0` (the default) follows until the execution is terminal, which is
        /// what an operator watching a long workflow wants and why this is not
        /// bounded by default — a four-hour run is not a hang. Scripts and
        /// non-interactive callers, which have nobody to press Ctrl-C, should
        /// always pass a bound. A stalled *connection* is bounded regardless,
        /// by the SDK's own read deadline.
        #[arg(long, default_value_t = 0)]
        timeout_secs: u64,
    },
    /// Tail the global ledger SSE event stream (`GET /events`). One JSON
    /// `LedgerEvent` per line. Streams forever until SIGINT or the
    /// transport closes; `--filter-execution` narrows to a single
    /// execution. `--since`/`--status` are pushed down as server-side
    /// filters. Without `--exit-on` this does NOT auto-stop on terminal
    /// status (use `kata run wait` for that); with `--exit-on` it stops
    /// at the first matching event.
    Events {
        /// Only show events whose `execution_id` matches this id.
        #[arg(long)]
        filter_execution: Option<String>,
        /// Server-side status filter (repeatable, or comma-separated),
        /// e.g. `--status completed --status failed`. Unknown status
        /// strings are rejected by the server (HTTP 400).
        #[arg(long, value_delimiter = ',')]
        status: Vec<String>,
        /// Resume from durable-log sequence number `<seq> + 1` instead
        /// of streaming from the current tail. A `<seq>` past the
        /// server's current ledger head fails with exit code 66
        /// (`kata` maps `KataClientError::CursorStale`).
        #[arg(long)]
        since: Option<u64>,
        /// Print the first event whose status is in this set (repeatable,
        /// or comma-separated; `--status`'s values) and exit 0. This set is
        /// the server-side status filter of the wait, so `--status` beside
        /// it is refused. If the stream ends before a match arrives — it
        /// closes, or ends on an SSE error, a lagged subscription or a
        /// malformed frame, stated on stderr — exit with code 65
        /// (`KataClientError::SseClosedWithoutMatch`); resume with `--since`.
        #[arg(long, value_delimiter = ',', conflicts_with = "status")]
        exit_on: Vec<String>,
    },
    /// Print an operator replay packet for one execution.
    Replay {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
        /// Include full stage outputs and per-invocation output payloads.
        #[arg(long)]
        include_outputs: bool,
    },
    /// Print a compact native operator run summary for one execution.
    RunSummary {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
    },
    /// Explain the current run state and safest next operator action.
    Explain {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
    },
    /// Print a unified operator closeout report for one execution.
    Report {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
        /// Emit an export-ready report bundle JSON packet.
        #[arg(long)]
        bundle: bool,
        /// Write an export-ready report bundle directory.
        #[arg(long, value_name = "DIR", conflicts_with = "bundle")]
        bundle_dir: Option<PathBuf>,
    },
    /// Render a chronological, human-readable timeline of one execution.
    ///
    /// Reconstructs the run's lifecycle from the ledger/evidence the API
    /// already exposes (`GET /executions/{id}`): submitted → running →
    /// per-stage dispatch/start/finish with durations → retries/parks →
    /// terminal. One line per event, absolute UTC timestamp + delta from
    /// the previous event. `--format json` emits the structured timeline
    /// packet instead of text.
    Timeline {
        /// Execution id (Ulid as a string).
        #[arg(required_unless_present = "current", conflicts_with = "current")]
        execution_id: Option<String>,
        /// Resolve the newest execution from the API node.
        #[arg(long)]
        current: bool,
        /// With `--current`, restrict to non-terminal executions.
        #[arg(long, requires = "current")]
        active: bool,
    },
    /// Show one stage's INPUT vs OUTPUT delta for an execution.
    ///
    /// INPUT is the parsed outputs of upstream stages the stage consumed
    /// (per the evidence chain) plus any stage-scoped external inputs.
    /// OUTPUT is the stage's completed envelope (content, parsed, exit_code,
    /// cost) from `GET /executions/{id}/stages/{stage}/output`, alongside the
    /// workspace-effect summary (files touched) when the stage carried one.
    /// `--format json` emits the structured diff packet.
    Diff {
        /// Execution id (Ulid as a string).
        execution_id: String,
        /// Stage name to diff.
        stage: String,
    },
    /// Normalized provider spend report over a time window.
    ///
    /// SPEND is aggregated from the node's own ledger (per backend and model:
    /// runs, tokens, cost). kata runs no vendor CLI for it and reads no
    /// vendor's plan or rate-limit answer.
    Usage {
        /// Spend window: a duration like `7d`, `24h`, `30m`, `90s`, or `all`.
        #[arg(long, default_value = "7d")]
        since: String,
    },
    /// List parked human gates waiting for operator review.
    Approvals,
    /// List registered workers from the live supervisor inventory.
    Workers,
    /// Print the compact workspace awareness snapshot.
    Workspace,
    /// Print execution-scoped workspace detail.
    ExecutionWorkspace {
        /// Execution id (Ulid as a string).
        execution_id: String,
    },
    /// Inspect the containment trust model: which execution providers this build
    /// ships, and what this host actually delivers.
    ExecutionProvider {
        #[command(subcommand)]
        cmd: ExecutionProviderCmd,
    },
    /// Inspect or provide steering inputs for running workflows.
    Steer {
        #[command(subcommand)]
        cmd: SteerCmd,
    },
    /// Inspect or propose native workflow/factory memory.
    Memory {
        #[command(subcommand)]
        cmd: MemoryCmd,
    },
    /// Inspect and apply checked factory controller decisions.
    Factory {
        #[command(subcommand)]
        cmd: FactoryCmd,
    },
    /// Inspect, list, and resolve workflows in the standard library.
    Workflows {
        #[command(subcommand)]
        cmd: WorkflowsCmd,
    },
    /// Config utilities.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Mint scoped, ed25519-signed API bearer tokens.
    ///
    /// `SignedToken` API auth (`[api.auth].type = "signed_token"`) is
    /// un-deployable without this: it produces the `Authorization: Bearer
    /// <token>` values the API verifies. `kata api-token mint --scope
    /// operate|approve|admin` signs a token with the main's PRIVATE key
    /// (from `--signing-key-file` or `KATA_API_SIGNING_KEY`) and prints the
    /// base64url wire form to stdout.
    ApiToken {
        #[command(subcommand)]
        cmd: ApiTokenCmd,
    },
    /// Back up the durable stores under `node.data_dir` into an artifact
    /// directory (ledger + memory + workflow state + config). Consistent
    /// even while a node is live; see `just backup`.
    Backup {
        /// Config file naming the `node.data_dir` to back up.
        #[arg(long, default_value = ".kata/kata.toml")]
        config: PathBuf,
        /// Output artifact directory (created if absent).
        #[arg(long)]
        out: PathBuf,
        /// Capture a complete source-fenced recovery artifact; requires a stopped main.
        #[arg(long)]
        recoverable: bool,
    },
    /// Extract a data-snapshot artifact into an identity-less offline target.
    /// Refuses runtime-format targets and live mains; see `just restore`.
    Restore {
        /// Backup artifact directory produced by `kata backup`.
        #[arg(long)]
        from: PathBuf,
        /// Config file naming the `node.data_dir` to restore into.
        #[arg(long, default_value = ".kata/kata.toml")]
        config: PathBuf,
        /// Also restore the bundled config copy over `--config`.
        #[arg(long)]
        restore_config: bool,
        /// Verify and activate a fresh clone with explicit target bindings and checkpoint decisions.
        #[arg(long, conflicts_with = "restore_config")]
        recoverable: bool,
        /// Exact artifact-bound operator approvals for checkpointed executions.
        #[arg(long, requires = "recoverable")]
        recovery_decisions: Option<PathBuf>,
    },
    /// Preview durable-store compatibility or validate a current data dir.
    ///
    /// kata NEVER migrates silently at open — opening a data dir whose ledger
    /// schema predates this binary fails closed with a typed error. This
    /// command is a read-only diagnostic: `--dry-run` (the default) reports
    /// whether the directory is at this binary's format, and what boot would
    /// refuse on it, without mutating; `--apply` only validates a directory
    /// that is already at the current format.
    Upgrade {
        /// Data directory to inspect or validate (the dir holding `operational.db`).
        /// Takes precedence over `--config`.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Config file naming the `node.data_dir` (used when `--data-dir` is
        /// omitted).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Preview only; make no changes. This is the default.
        #[arg(long, conflicts_with = "apply")]
        dry_run: bool,
        /// Validate an already-current clean-format directory under authority.
        #[arg(long)]
        apply: bool,
    },
    /// Report — and, with `--apply`, repair — a current-format data dir whose
    /// operational projection has drifted from its authoritative chain.
    /// Refuses to run while a node is live against the data dir.
    RepairNucleus {
        /// Data directory to inspect/repair (the dir holding `operational.db`).
        /// Takes precedence over `--config`.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Config file naming the `node.data_dir` when `--data-dir` is omitted.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Rebuild every repairable projection in place. Without it the
        /// command reports and changes nothing.
        #[arg(long)]
        apply: bool,
    },
    /// Sandbox provider management.
    ///
    /// `install-external-provider` provisions an external provider the
    /// capsule route spawns into this node's by-hash provider store and prints
    /// the three exports that route the node to it.
    Sandbox {
        #[command(subcommand)]
        cmd: SandboxCmd,
    },
    /// Node-level administration. Offline: refuses while the installed main runs.
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// Prepare this host for the rootless-youki `oci` execution profile.
    ///
    /// Owns the shipped containment plane's host policy: the pinned youki's
    /// exact-path AppArmor profile (`apparmor-install`).
    Host {
        #[command(subcommand)]
        cmd: HostCmd,
    },
    /// Log kata's embedded agent harness in to a model provider.
    ///
    /// The login is kata's OWN: an owner-only file under
    /// `~/.config/kata/logins/` that an `[agents.<label>]` block reads with
    /// `credential = { mode = .., source = "kata_login" }`. kata refreshes it
    /// and never shares it with, or reads it from, another tool. Offline.
    Login {
        #[command(subcommand)]
        cmd: LoginCmd,
    },
    /// Remove kata's own login files for a provider. The issuer is not told:
    /// the removed tokens stay valid there until they expire. Offline.
    Logout {
        /// The provider whose login files are removed.
        #[arg(value_enum)]
        provider: LoginProviderArg,
    },
    /// Wire kata into a host coding agent.
    ///
    /// `kata skill install --host claude-code [--dir <project>]` registers kata
    /// as an MCP server for the host (an ADDITIVE `mcpServers.kata` merge into
    /// `<dir>/.mcp.json`, launching `kata mcp`) AND installs a kata skill
    /// (`<dir>/.claude/skills/kata/SKILL.md`) that teaches the host the
    /// author → check → run → observe loop through the kata MCP tools. Both
    /// writes are idempotent. `--host codex` prints the manual registration
    /// steps (Codex has no project-local MCP/skill file — a documented
    /// narrowing).
    Skill {
        #[command(subcommand)]
        cmd: SkillCmd,
    },
    /// Run the agent-native MCP server.
    ///
    /// Speaks line-delimited JSON-RPC 2.0 over stdin/stdout, exposing kata's
    /// shared operation contract as MCP tools (`initialize` / `tools/list` /
    /// `tools/call`). stdio is its one transport, tokenless: only the process
    /// that spawned it holds its pipes, and it listens on no socket.
    ///
    /// By default this is an attached client of the installed main selected by
    /// `--api-url`. It never creates workflow authority and boots no engine;
    /// `--no-engine` keeps only the local `author`/`check` bindings.
    Mcp {
        /// Override the installed main URL the node-dependent operations are
        /// proxied to (its `/ops` route). Set `KATA_API_TOKEN` if the main is
        /// token-protected.
        #[arg(long, conflicts_with = "no_engine")]
        connect: Option<String>,
        /// Do not boot an engine: `author`/`check` bind locally and the
        /// node-dependent operations return the structured "requires a running
        /// node" error.
        #[arg(long)]
        no_engine: bool,
    },
    /// Hidden: the kata-floor syscall self-probe.
    ///
    /// Reports `/proc/self/status` before and after an optional
    /// `unshare(CLONE_NEWUSER)`, then attempts every
    /// `FloorEligibility::KataFloor` entry of
    /// [`kata_types::sandbox_seccomp::DENIED_SYSCALLS`] with deliberately
    /// inert arguments, emitting one NDJSON row each. It installs nothing: the
    /// floor is loaded by `kata_worker::process::attach_kata_floor` in this
    /// process's `pre_exec`, before `main` runs, so the identical invocation
    /// with and without `CommandPrefix::kata_floor_bpf` is the proof's
    /// containment/control pair. Not an operator command; hidden from `--help`.
    #[command(name = "__syscall-probe", hide = true)]
    SyscallProbe {
        /// Enter a NEW user namespace before probing, and report the
        /// capability regain the seccomp floor must survive.
        #[arg(long)]
        unshare_userns: bool,
    },
}

/// Dispatch a parsed CLI invocation.
pub fn run(cli: Cli) -> Result<()> {
    let Cli {
        mut api_url,
        format,
        command,
    } = cli;
    if command_uses_attached_main(&command) {
        api_url = crate::attachment::resolve_verified_attached_endpoint(&api_url)?;
    }
    match command {
        Command::Serve { config } => solo::run_installed_main(config),
        Command::Service { cmd } => service::run_service_cmd(cmd),
        Command::ServiceExec {
            definition,
            environment,
            config,
            expected_binary_digest,
            expected_config_digest,
            expected_environment_digest,
            expected_data_directory,
            expected_directory_id,
        } => service::run_service_exec(
            definition,
            environment,
            config,
            expected_binary_digest,
            expected_config_digest,
            expected_environment_digest,
            expected_data_directory,
            expected_directory_id,
        ),
        Command::Init {
            config,
            force,
            print,
        } => init::run_init_cmd(config, force, print),
        Command::Doctor {
            config,
            workflow,
            online,
        } => doctor::run_doctor_cmd(&api_url, config, workflow, online, format),
        Command::Health => operator::run_health_cmd(&api_url),
        Command::Status => operator::run_status_cmd(&api_url),
        Command::Version { compare } => operator::run_version_cmd(&api_url, compare),
        Command::Build {
            workflow,
            out,
            deny_warnings,
            config,
        } => workflows::run_build_cmd(
            &workflow,
            out.as_deref(),
            deny_warnings,
            config.as_deref(),
            format,
        ),
        Command::Check {
            workflow,
            all,
            deny_warnings,
            config,
        } => workflows::run_check_cmd(
            workflow.as_deref(),
            all,
            deny_warnings,
            config.as_deref(),
            format,
        ),
        Command::Evidence { cmd } => evidence::run_evidence_cmd(cmd),
        Command::Login { cmd } => login::run_login_cmd(cmd),
        Command::Logout { provider } => login::run_logout_cmd(provider),
        Command::Run {
            cmd,
            workflow,
            submit,
            watch,
            wait,
            include_outputs,
            timeout_secs,
            poll_ms,
            param,
            params_file,
            target,
        } => run_or_boot(
            &api_url,
            RunOrBoot {
                cmd,
                format,
                workflow,
                params: operator::parse_cli_params(&param, params_file.as_deref())?,
                target: target
                    .as_deref()
                    .map(kata_types::target::TargetSpec::parse)
                    .transpose()
                    .map_err(|refusal| anyhow::anyhow!("--target refused: {refusal}"))?,
                workflow_mode: workflow_run_mode(submit, watch, wait, include_outputs),
                timeout_secs,
                poll_ms,
            },
        ),
        Command::Watch {
            execution_id,
            current,
            active,
            include_outputs,
            timeout_secs,
        } => operator::run_watch_cmd(
            &api_url,
            execution_id,
            current,
            active,
            include_outputs,
            timeout_secs,
        ),
        Command::Events {
            filter_execution,
            status,
            since,
            exit_on,
        } => operator::run_events_cmd(&api_url, filter_execution, status, since, exit_on),
        Command::Replay {
            execution_id,
            current,
            active,
            include_outputs,
        } => operator::run_replay_cmd(&api_url, execution_id, current, active, include_outputs),
        Command::RunSummary {
            execution_id,
            current,
            active,
        } => operator::run_run_summary_cmd(&api_url, execution_id, current, active),
        Command::Explain {
            execution_id,
            current,
            active,
        } => operator::run_explain_cmd(&api_url, execution_id, current, active, format),
        Command::Report {
            execution_id,
            current,
            active,
            bundle,
            bundle_dir,
        } => operator::run_report_cmd(
            &api_url,
            execution_id,
            current,
            active,
            operator::ReportOutputMode::from_flags(bundle, bundle_dir),
            format,
        ),
        Command::Timeline {
            execution_id,
            current,
            active,
        } => operator::run_timeline_cmd(&api_url, execution_id, current, active, format),
        Command::Diff {
            execution_id,
            stage,
        } => operator::run_diff_cmd(&api_url, execution_id, stage, format),
        Command::Usage { since } => operator::run_usage_cmd(&api_url, &since, format),
        Command::Approvals => operator::run_approvals_cmd(&api_url),
        Command::Workers => operator::run_workers_cmd(&api_url),
        Command::Workspace => operator::run_workspace_cmd(&api_url),
        Command::ExecutionWorkspace { execution_id } => {
            operator::run_execution_workspace_cmd(&api_url, execution_id)
        }
        Command::ExecutionProvider { cmd } => {
            execution_provider::run_execution_provider_cmd(cmd, format)
        }
        Command::Steer { cmd } => operator::run_steer_cmd(&api_url, cmd),
        Command::Memory { cmd } => operator::run_memory_cmd(&api_url, cmd),
        Command::Factory { cmd } => operator::run_factory_cmd(&api_url, cmd, format),
        Command::Workflows { cmd } => workflows::run_workflows_cmd(cmd, format),
        Command::Config {
            cmd: ConfigCmd::Check { config },
        } => config_check::config_check(&config),
        Command::ApiToken { cmd } => api_token::run_api_token_cmd(cmd),
        Command::Backup {
            config,
            out,
            recoverable,
        } => {
            if recoverable {
                recovery_capture::run_backup_recoverable_cmd(config, out)
            } else {
                backup::run_backup_cmd(config, out)
            }
        }
        Command::Restore {
            from,
            config,
            restore_config,
            recoverable,
            recovery_decisions,
        } => {
            if recoverable {
                recovery_restore::run_restore_recoverable_cmd(from, config, recovery_decisions)
            } else {
                backup::run_restore_cmd(from, config, restore_config)
            }
        }
        Command::Upgrade {
            data_dir,
            config,
            dry_run,
            apply,
        } => upgrade::run_upgrade_cmd(data_dir, config, dry_run, apply),
        Command::RepairNucleus {
            data_dir,
            config,
            apply,
        } => repair_nucleus::run_repair_nucleus_cmd(data_dir, config, apply),
        Command::Node {
            cmd:
                NodeCmd::Environment {
                    cmd:
                        NodeEnvironmentCmd::Release {
                            id,
                            data_dir,
                            config,
                        },
                },
        } => node_environment::run_release_cmd(&id, data_dir, config, format),
        Command::Sandbox {
            cmd:
                SandboxCmd::InstallExternalProvider {
                    name,
                    source,
                    store,
                },
        } => {
            let report =
                provider_install::run_install_external_provider(&name, &source, store.as_deref())?;
            // `--format json` is honoured rather than accepted and dropped —
            // an operator scripting a provision needs the address the run
            // minted. The report is no operation's response, so it is bare.
            match format {
                output::OutputFormat::Json => {
                    output::emit_record(&report)?;
                }
                output::OutputFormat::Human => {
                    print!("{}", provider_install::render_provider_install(&report));
                }
            }
            Ok(())
        }
        Command::Host {
            cmd: HostCmd::ApparmorInstall,
        } => {
            let report = host_setup::run_apparmor_install()?;
            // The same bare `--format json` report the provider install emits.
            match format {
                output::OutputFormat::Json => {
                    output::emit_record(&report)?;
                }
                output::OutputFormat::Human => {
                    print!("{}", host_setup::render_apparmor_install(&report));
                }
            }
            Ok(())
        }
        Command::Host {
            cmd:
                HostCmd::Setup {
                    config,
                    install_apparmor,
                    environment_file,
                    provider_source,
                    provider_ip,
                },
        } => {
            let report = host_setup::run_setup(&host_setup::HostSetupArgs {
                config,
                install_apparmor,
                environment_file,
                provider_source,
                provider_ip,
            })?;
            match format {
                output::OutputFormat::Json => {
                    output::emit_record(&report)?;
                }
                output::OutputFormat::Human => {
                    print!("{}", host_setup::render_setup(&report));
                }
            }
            // The report always reaches the operator first; the nonzero exit
            // then names what held — the refusal row's own text, or the
            // deferred action(s) when nothing refused — so a script keys on
            // the same token the human saw.
            anyhow::ensure!(
                report.complete,
                "kata host setup incomplete: {}",
                report
                    .steps
                    .iter()
                    .rev()
                    .find(|row| row.status == host_setup::StepStatus::Refused)
                    .map_or_else(
                        || {
                            if report.actions.is_empty() {
                                "kata doctor reported failures".to_string()
                            } else {
                                format!(
                                    "operator action(s) outstanding: {}",
                                    report.actions.join("; ")
                                )
                            }
                        },
                        |row| row.detail.clone(),
                    ),
            );
            Ok(())
        }
        Command::Skill {
            cmd: SkillCmd::Install { host, dir },
        } => skill::run_skill_install_cmd(host, dir),
        Command::Mcp { connect, no_engine } => mcp::run_mcp_cmd(connect, no_engine, &api_url),
        Command::SyscallProbe { unshare_userns } => {
            syscall_probe::run_syscall_probe(unshare_userns)
        }
    }
}

fn command_uses_attached_main(command: &Command) -> bool {
    match command {
        Command::Doctor { online, .. } => *online,
        Command::Run { .. }
        | Command::Health
        | Command::Status
        | Command::Version { .. }
        | Command::Watch { .. }
        | Command::Events { .. }
        | Command::Replay { .. }
        | Command::RunSummary { .. }
        | Command::Explain { .. }
        | Command::Report { .. }
        | Command::Timeline { .. }
        | Command::Diff { .. }
        | Command::Usage { .. }
        | Command::Approvals
        | Command::Workers
        | Command::Workspace
        | Command::ExecutionWorkspace { .. }
        | Command::Steer { .. }
        | Command::Memory { .. }
        | Command::Factory { .. } => true,
        Command::Serve { .. }
        | Command::Service { .. }
        | Command::ServiceExec { .. }
        | Command::Init { .. }
        | Command::Build { .. }
        | Command::Check { .. }
        | Command::Evidence { .. }
        | Command::Workflows { .. }
        | Command::Config { .. }
        | Command::ApiToken { .. }
        | Command::Backup { .. }
        | Command::Restore { .. }
        | Command::Upgrade { .. }
        | Command::RepairNucleus { .. }
        | Command::Node { .. }
        | Command::Sandbox { .. }
        // `host` verbs are OFFLINE by construction — a host being prepared has
        // no main to attach to, and `apparmor-install` must run before any
        // main could contain anything.
        | Command::Host { .. }
        // kata's own login is a file on this host; `login status` reads it
        // offline (`--check` reaches the providers, never a main), and a login
        // must be possible before any main exists.
        | Command::Login { .. }
        | Command::Logout { .. }
        // `execution-provider` is OFFLINE by construction. Every fact it
        // reports is a property of this binary or of this host, measured in this
        // process — so an operator diagnosing why their node will not contain
        // anything can run it before, and without, a live main.
        | Command::ExecutionProvider { .. }
        | Command::Skill { .. }
        | Command::Mcp { .. }
        // The syscall self-probe reports what THIS process's
        // kernel says about itself. It has no main to attach to and must not
        // acquire one — an attachment handshake before the report would put
        // network syscalls between the floor and the observation.
        | Command::SyscallProbe { .. } => false,
    }
}

/// Resolve the process exit code for a top-level command error.
///
/// Checks, in order: the sysexits-style `kata-client` SSE/cursor
/// variants surfaced by `kata events --exit-on`/`--since`
/// (`KataClientError::SseClosedWithoutMatch` → 65,
/// `KataClientError::CursorStale` → 66), a refusal the main ANSWERED — an
/// `/ops` refusal's own code, or a REST status's class
/// ([`kata_client::KataClientError::op_error_code`]: the class the `/ops`
/// face gives the same refusal) — then the generic `OpError` contract
/// (2..=7), falling back to a flat `1` for untyped errors (the transport's
/// and the SDK's own failures among them).
///
/// Exposed from the library crate (rather than living inline in
/// `src/main.rs`) so it is exercised directly by
/// `tests/cli_parse_operator_tests.rs` without a subprocess harness —
/// `main`'s `ExitCode`-returning body itself is not unit-testable from
/// `tests/`.
#[must_use]
pub fn exit_code_for_error(err: &anyhow::Error) -> i32 {
    use kata_client::KataClientError;
    use kata_op_contract::OpError;

    if let Some(client_err) = err.downcast_ref::<KataClientError>() {
        match client_err {
            KataClientError::SseClosedWithoutMatch { .. } => return 65,
            KataClientError::CursorStale => return 66,
            _ => {}
        }
        if let Some(code) = client_err.op_error_code() {
            return code.exit_code();
        }
    }
    err.downcast_ref::<OpError>().map_or(1, OpError::exit_code)
}

/// The construction of "an execution reached a `Failed` terminal".
///
/// kata's exit-code contract ([`kata_op_contract::OpError::exit_code`]) gives a
/// *Failed* execution exit `5`, **engine**, so this is an `OpError::engine` — never
/// an untyped `anyhow` wrap, which [`exit_code_for_error`] cannot downcast and lands
/// on the flat `1`.
///
/// `reason` carries the engine's own message and the error is NOT wrapped: `main`
/// renders `Error: {err:?}`, i.e. anyhow's full chain, and the caller already
/// interpolates the underlying error into `reason`, so a source arm would print the
/// same sentence twice, once as the message and once as `Caused by:`.
pub(crate) fn failed_execution_is_an_engine_error(
    execution_id: impl std::fmt::Display,
    reason: &str,
) -> anyhow::Error {
    kata_op_contract::OpError::engine(format!("execution {execution_id} failed: {reason}")).into()
}

/// The CANCELLED sibling of [`failed_execution_is_an_engine_error`]: an
/// operator stop is a non-success terminal, so it takes
/// the same engine-class typed error — same exit code, deterministic mapping —
/// but says `was cancelled`, not `failed`. One constructor family keeps the two
/// terminals distinguishable in prose and identical in class.
pub(crate) fn cancelled_execution_is_an_engine_error(
    execution_id: impl std::fmt::Display,
) -> anyhow::Error {
    kata_op_contract::OpError::engine(format!("execution {execution_id} was cancelled")).into()
}

struct RunOrBoot {
    cmd: Option<RunCmd>,
    format: OutputFormat,
    workflow: Option<String>,
    /// Parsed `--param`/`--params-file` invocation params.
    params: serde_json::Map<String, serde_json::Value>,
    /// Parsed `--target`.
    target: Option<kata_types::target::TargetSpec>,
    workflow_mode: WorkflowRunMode,
    timeout_secs: u64,
    poll_ms: u64,
}

enum WorkflowRunMode {
    Submit,
    Watch { include_outputs: bool },
    Wait,
    InvalidIncludeOutputs,
}

/// Which face `kata run <workflow>` takes for a given flag combination.
///
/// Named rather than inlined at the dispatch site because the LAST arm is
/// load-bearing and invisible: with no mode flag at all the command is
/// `Submit` — fire-and-forget to the installed main.
#[allow(
    clippy::fn_params_excessive_bools,
    reason = "these ARE the four clap flags, verbatim and in dispatch order; folding them into \
              an enum here would relocate the very branch chain this function exists to name"
)]
const fn workflow_run_mode(
    submit: bool,
    watch: bool,
    wait: bool,
    include_outputs: bool,
) -> WorkflowRunMode {
    if watch {
        WorkflowRunMode::Watch { include_outputs }
    } else if wait {
        WorkflowRunMode::Wait
    } else if submit {
        WorkflowRunMode::Submit
    } else if include_outputs {
        WorkflowRunMode::InvalidIncludeOutputs
    } else {
        WorkflowRunMode::Submit
    }
}

fn run_or_boot(api_url: &str, args: RunOrBoot) -> Result<()> {
    let RunOrBoot {
        cmd,
        format,
        workflow,
        params,
        target,
        workflow_mode,
        timeout_secs,
        poll_ms,
    } = args;

    if let Some(cmd) = cmd {
        if workflow.is_some() {
            bail!(
                "`kata run` accepts either an operator subcommand or a workflow target, not both"
            );
        }
        if !params.is_empty() {
            bail!("`kata run <operator-subcommand>` does not accept --param/--params-file");
        }
        if target.is_some() {
            bail!("`kata run <operator-subcommand>` does not accept --target");
        }
        return operator::run_run_cmd(api_url, cmd, format);
    }

    let (watch, wait, include_outputs) = match workflow_mode {
        WorkflowRunMode::Submit => (false, false, false),
        WorkflowRunMode::Watch { include_outputs } => (true, false, include_outputs),
        WorkflowRunMode::Wait => (false, true, false),
        WorkflowRunMode::InvalidIncludeOutputs => {
            bail!("`kata run --include-outputs` is only supported with --watch")
        }
    };
    let workflow = workflow.ok_or_else(|| {
        anyhow::anyhow!("`kata run --submit|--watch|--wait` requires a workflow target")
    })?;
    operator::run_workflow_cmd(
        api_url,
        workflow,
        params,
        target,
        watch,
        wait,
        include_outputs,
        timeout_secs,
        poll_ms,
    )
}

/// Canonical heuristic for deciding whether a CLI workflow/workflow argument
/// addresses a filesystem path (vs. a library reference to resolve by name).
///
/// Uses the superset separator set (`MAIN_SEPARATOR` plus explicit `/` and
/// `\\`) so the answer is platform-independent, and treats a `.toml`/`.star`
/// extension (case-insensitive) as path-addressed.
pub(crate) fn looks_like_path(target: &str) -> bool {
    let has_workflow_extension = Path::new(target)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(extension.to_ascii_lowercase().as_str(), "toml" | "star")
        });

    target.contains(std::path::MAIN_SEPARATOR)
        || target.contains('/')
        || target.contains('\\')
        || has_workflow_extension
}

/// Install the node facts a `kata.toml` declares for any local command that
/// judges packs or agent blocks (`doctor`, `config check`, `check --config`,
/// `build --config`, `restore --recoverable`) — the same set
/// `BootRig::boot` installs at the one funnel, so the check answers what the
/// node that owns this config would answer rather than the shipped default.
/// The bound environment's `PATH` programs stay uninstalled (they are
/// resolved from the store at boot, unresolvable here), and the `oci`
/// environment arm treats an absent list as unjudged.
pub(crate) fn install_node_facts_from_config(cfg: &kata_types::config::KataConfig) {
    kata_types::containment_policy::install_node_containment_policy(cfg.containment);
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_budget_ceilings(
        kata_types::node_profile::NodeBudgetCeilings {
            output_bytes: cfg.node.output_bytes_ceiling,
            work_delta_bytes: cfg.node.work_delta_bytes_ceiling,
            work_delta_entries: cfg.node.work_delta_entries_ceiling,
            capsule_memory_bytes: cfg.node.capsule_memory_bytes_ceiling,
            capsule_process_count: cfg.node.capsule_process_count_ceiling,
        },
    );
    kata_types::node_profile::install_node_agents(cfg.agents.clone());
    kata_types::node_profile::install_node_egress_allow(
        cfg.node
            .egress_allow
            .iter()
            .map(|spelling| {
                kata_types::execution_contract::EgressAuthority::from_authority_str(spelling)
            })
            .collect::<Result<std::collections::BTreeSet<_>, _>>()
            .expect("node.egress_allow entries were proved at config load"),
    );
}

/// Canonical relative-path normalizer: leaves absolute paths untouched and
/// prefixes relative paths with `./` so they render/anchor explicitly.
pub(crate) fn normalize_relative_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        PathBuf::from(".").join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_service_handoff_does_not_reload_dotenv() {
        const CHILD: &str = "KATA_DOTENV_HANDOFF_TEST_CHILD";
        const EXPECT_LOAD: &str = "KATA_DOTENV_HANDOFF_TEST_EXPECT_LOAD";
        const AMBIENT: &str = "KATA_DOTENV_HANDOFF_REGRESSION";

        if std::env::var_os(CHILD).is_some() {
            load_operator_dotenv();
            let expected = std::env::var_os(EXPECT_LOAD).as_deref() == Some("yes".as_ref());
            assert_eq!(
                std::env::var_os(AMBIENT).is_some(),
                expected,
                "dotenv load decision diverged for service handoff"
            );
            return;
        }

        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".env"), format!("{AMBIENT}=drifted\n")).unwrap();
        let descendant = root.path().join("nested/descendant");
        std::fs::create_dir_all(&descendant).unwrap();
        for marker_case in 0_u8..=7 {
            let should_load = marker_case == 0;
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("cli::tests::installed_service_handoff_does_not_reload_dotenv")
                .arg("--nocapture")
                .current_dir(&descendant)
                .env_clear()
                .env(CHILD, "1")
                .env(EXPECT_LOAD, if should_load { "yes" } else { "no" });
            if marker_case & 1 != 0 {
                command.env(crate::attachment::SERVICE_DISCOVERY_LEASE_FD_ENV, "91");
            }
            if marker_case & 2 != 0 {
                command.env(crate::authority_file::SERVICE_CONFIG_SNAPSHOT_FD_ENV, "92");
            }
            if marker_case & 4 != 0 {
                command.env(kata_types::KATA_NO_DOTENV, "");
            }
            let output = command.output().expect("run dotenv decision child");
            assert!(
                output.status.success(),
                "dotenv decision child failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// `.env` is loaded from the real cwd-ancestor search: a key only `.env`
    /// declares is not a launch value, and a key the launch environment
    /// declares stays one — with the launch value, which `.env` never
    /// overrides.
    #[test]
    fn launch_env_var_tells_a_launch_value_from_a_dotenv_one() {
        const CHILD: &str = "KATA_LAUNCH_ENV_TEST_CHILD";
        const FROM_FILE: &str = "KATA_LAUNCH_ENV_FROM_FILE";
        const LAUNCHED: &str = "KATA_LAUNCH_ENV_LAUNCHED";

        if std::env::var_os(CHILD).is_some() {
            load_operator_dotenv();
            assert_eq!(std::env::var(FROM_FILE).as_deref(), Ok("file"));
            assert_eq!(launch_env_var(FROM_FILE), None, "only `.env` declared it");
            assert_eq!(launch_env_var(LAUNCHED).as_deref(), Some("launch"));
            return;
        }

        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".env"),
            format!("{FROM_FILE}=file\n{LAUNCHED}=file\n"),
        )
        .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("cli::tests::launch_env_var_tells_a_launch_value_from_a_dotenv_one")
            .arg("--nocapture")
            .current_dir(root.path())
            .env_clear()
            .env(CHILD, "1")
            .env(LAUNCHED, "launch")
            .output()
            .expect("run launch-env child");
        assert!(
            output.status.success(),
            "launch-env child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("1 passed"),
            "the child ran the cell: {stdout}"
        );
    }

    /// **`.env` never overrides a launch value that is not UTF-8.** dotenvy
    /// judges a variable present with `std::env::var`, which errs on such a
    /// value as on an unset one, so a `.env` line of the same name would replace
    /// it — and a worker would lift the file's key instead of refusing the
    /// launch one. The child is launched with a non-UTF-8 value and a `.env`
    /// naming it plus a second variable; after the load the launch bytes are
    /// still the variable's, read with `var_os`, and the second variable loaded.
    ///
    /// **Would red if:** the load handed presence to dotenvy's `env::var` check
    /// alone (the variable read `file`).
    #[test]
    fn dotenv_never_overrides_a_launch_value_that_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt as _;
        const CHILD: &str = "KATA_LAUNCH_UTF8_TEST_CHILD";
        const KEY: &str = "KATA_LAUNCH_UTF8_TEST_KEY";
        const LOADED: &str = "KATA_LAUNCH_UTF8_TEST_LOADED";
        const LAUNCH_VALUE: &[u8] = b"sk-launch\xff";

        if std::env::var_os(CHILD).is_some() {
            load_operator_dotenv();
            assert_eq!(
                std::env::var_os(KEY)
                    .as_deref()
                    .map(std::ffi::OsStr::as_bytes),
                Some(LAUNCH_VALUE),
                "the launch value, not `.env`'s"
            );
            assert_eq!(std::env::var(LOADED).as_deref(), Ok("file"));
            return;
        }

        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".env"),
            format!("{KEY}=file\n{LOADED}=file\n"),
        )
        .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("cli::tests::dotenv_never_overrides_a_launch_value_that_is_not_utf8")
            .arg("--nocapture")
            .current_dir(root.path())
            .env_clear()
            .env(CHILD, "1")
            .env(KEY, std::ffi::OsStr::from_bytes(LAUNCH_VALUE))
            .output()
            .expect("run launch-utf8 child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "launch-utf8 child failed: stdout={stdout} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn manager_launched_service_trampoline_does_not_load_dotenv() {
        assert!(should_load_operator_dotenv(false, false));
        assert!(!should_load_operator_dotenv(true, false));
        assert!(!should_load_operator_dotenv(false, true));
        assert!(!should_load_operator_dotenv(true, true));
    }

    #[test]
    fn malformed_native_service_argv_is_detected_before_clap_rejects_it() {
        assert!(raw_native_service_invocation_from(
            Some(std::ffi::OsStr::new("__service-exec")),
            false,
            false,
        ));
        let error = Cli::try_parse_from(["kata", "__service-exec"])
            .expect_err("missing definition-bound arguments must fail parsing");
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("required arguments were not provided"));
        assert!(diagnostic.contains("--definition"));
    }
}
