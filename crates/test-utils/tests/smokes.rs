//! Live-binary smoke tests.
//!
//! Live counterparts to in-process regression tests. Each smoke boots a real `kata` binary (release
//! build) under a tempdir, drives it through the typed `kata-client` SDK, asserts end-to-end
//! behavior, and reaps the child cleanly via the `NodeHandle::shutdown` SIGTERM path.
//!
//! ## Gate
//!
//! Every smoke is `#[ignore]`-by-default + `KATA_LIVE_SMOKE=1`
//! env-checked at entry. Run via `just smoke` (which sets the env
//! var, passes `--run-ignored all`, and selects the `live-smoke`
//! nextest profile from `.config/nextest.toml`).
//!
//! The `just smoke` recipe constrains both its default
//! and caller-supplied filters to this `smokes` binary (plus the sibling
//! `live_smoke` binary), so a focused invocation cannot escape into an
//! unrelated ignored workspace test.
//!
//! ## Why one file
//!
//! Each `tests/<name>.rs` under a Cargo crate compiles to its own
//! integration-test binary; three smokes in three files means
//! three `cargo build` artifacts and three nextest discovery
//! passes. The smokes share zero state, so module-level isolation
//! is moot — collapsing them into a single binary halves compile
//! time and gives nextest a single artifact to fan out from.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use kata_client::Execution;
use kata_client::types::ExecutionStatus;
use kata_test_utils::held_port::HeldPort;
use kata_test_utils::live::{NodeHandle, WorkerHandle, bin_path};
use kata_types::agent::BackendType;
use kata_types::identity::WorkerResource;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

fn spawn_shell_node() -> NodeHandle {
    NodeHandle::spawn_supervised_main().expect("spawn shell fixture node")
}

/// A `net = "host"` stage's egress allowlist is `[node] egress_allow` —
/// declaration-EMPTY without it, and CHECK refuses `egress_undeclared`. The
/// cells that author `host` for its posture (not to reach a host) declare this
/// NEVER-DIALED authority: the property under test is that the declaration
/// reaches the worker's CONNECT proxy, never a dialed address.
const NEVER_DIALED_EGRESS_AUTHORITY: &str = "127.0.0.1:9";

/// The model smoke's `[agents.default]` — the embedded nanocode harness on
/// OpenAI under kata's own ChatGPT login (`kata login openai`, once per host),
/// at the model and effort `kata init` writes. Converted cells declare this so
/// `agent = "default"` resolves to a model turn, never the shell binding. The
/// toolhost init renders the turn's `HOME`, so `env` declares only `TERM`.
const NANOCODE_DEFAULT_AGENT_DECL: &str = "[agents.default]\nadapter = \"nanocode_openai\"\ncredential = { mode = \"subscription\", source = \"kata_login\" }\nmodel = \"gpt-6-luna\"\nreasoning_effort = \"medium\"\nenv = { TERM = \"dumb\" }\n";

/// [`spawn_shell_node`], plus the node's `[node] egress_allow` carrying
/// [`NEVER_DIALED_EGRESS_AUTHORITY`] — for smokes whose pack authors
/// `net = "host"` on a SHELL stage.
fn spawn_shell_node_with_egress() -> NodeHandle {
    NodeHandle::spawn_supervised_main_with_options(kata_test_utils::live::NodeConfigOptions {
        egress_allow: vec![NEVER_DIALED_EGRESS_AUTHORITY.to_string()],
        ..kata_test_utils::live::NodeConfigOptions::default()
    })
    .expect("spawn shell fixture node with egress")
}

fn spawn_native_jj_node(repo: &Path) -> NodeHandle {
    NodeHandle::spawn_supervised_main_with_native_jj(repo.to_path_buf())
        .expect("spawn native-jj fixture node")
}

/// [`spawn_native_jj_node`], plus `[node] egress_allow` carrying
/// [`NEVER_DIALED_EGRESS_AUTHORITY`] — the gold-loop / parked-promote packs
/// author `net = "host"` on their `edit` stages.
fn spawn_native_jj_node_with_egress(repo: &Path) -> NodeHandle {
    NodeHandle::spawn_supervised_main_with_options(kata_test_utils::live::NodeConfigOptions {
        vcs: Some(kata_test_utils::live::VcsSpec::native_jj(
            repo.to_path_buf(),
        )),
        egress_allow: vec![NEVER_DIALED_EGRESS_AUTHORITY.to_string()],
        ..kata_test_utils::live::NodeConfigOptions::default()
    })
    .expect("spawn native-jj fixture node with egress")
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child
            .as_mut()
            .and_then(|child| child.try_wait().expect("checking child status"))
    }

    async fn shutdown(mut self) {
        if let Some(mut child) = self.child.take() {
            if let Ok(pid) = i32::try_from(child.id()) {
                let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            }
            for _ in 0..30 {
                if child.try_wait().expect("checking child status").is_some() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Per-invocation ceiling for a product CLI command driven by this file.
///
/// Derived, not picked. The slowest legitimate invocation here is `kata run
/// wait --timeout-secs 10`, which may spend its full ten seconds polling and
/// whose LAST poll can itself sit for one whole `KataClient::DEFAULT_READ_TIMEOUT`
/// (31s) against a peer that stalls mid-answer — so 41s is the largest duration
/// a correct command can take. Four seconds on top covers spawning a release
/// binary, parsing config, and exiting on a host running three concurrent builds.
///
/// The ladder this sits in is what makes a failure attributable, and every step
/// must be strictly ordered: SDK read bound (31s) < this (45s) < the test's own
/// `#[kata_timeout]` (90s) < nextest's `terminate-after` (5 x 60s). Whichever
/// trips first is the most specific one that could, and every one of them names
/// its subject.
const KATA_COMMAND_DEADLINE: Duration = Duration::from_secs(45);

/// Run a subprocess to completion under a deadline, without blocking the
/// runtime.
///
/// `std::process::Command::output()` blocks the calling thread. On the
/// `current_thread` runtime every `#[tokio::test]` in this file uses, that
/// thread is the ONLY thread, so a blocked child means the timer wheel is never
/// polled and no per-command deadline can fire: a hang would end only at the
/// test's `#[kata_timeout]` watchdog, which names the test, not the command.
///
/// `tokio::process` keeps the runtime live: the wait is a future, so the
/// deadline is enforceable, and
/// `kill_on_drop` reaps the child when it trips instead of leaking a `kata`
/// process into the next smoke (which `just pgrep-kata` would then flag against
/// whoever ran next).
async fn run_bounded(
    bin: &Path,
    cwd: &Path,
    args: &[&str],
    deadline: Duration,
) -> Result<std::process::Output, String> {
    let display = format!("{} {args:?}", bin.display());
    let child = tokio::process::Command::new(bin)
        .current_dir(cwd)
        .args(args)
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(deadline, child).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(err)) => Err(format!("spawning `{display}` in {}: {err}", cwd.display())),
        Err(_) => Err(format!(
            "SMOKE_COMMAND_DEADLINE: `{display}` did not exit within {deadline:?} (cwd {}). \
             The child was killed. This is the innermost bound in the smoke stack, so the \
             command named here is the one that hung — not the test, and not the runner.",
            cwd.display(),
        )),
    }
}

/// Run a product CLI command, assert it succeeded, and return its stdout.
///
/// Async so the per-command deadline can fire — see [`run_bounded`].
async fn run_kata(bin: &Path, cwd: &Path, args: &[&str]) -> String {
    let output = match run_bounded(bin, cwd, args, KATA_COMMAND_DEADLINE).await {
        Ok(output) => output,
        Err(message) => panic!("{message}"),
    };
    assert!(
        output.status.success(),
        "kata {args:?} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("kata stdout must be utf-8")
}

fn json_stdout(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).expect("stdout must be one JSON document")
}

// EVERY COMMAND A SMOKE RUNS IS BOUNDED BY ITS OWN NAMED DEADLINE.
//
// `#[kata_timeout]` is a real-time watchdog thread, so it fires on every smoke
// here whatever the body does; what it names is the TEST. Every test here uses
// plain `#[tokio::test]`, i.e. a CURRENT_THREAD runtime, so a blocking call on
// the only thread would stop the timer wheel and with it any tighter deadline.
//
// Switching the smokes to `multi_thread` is not the fix: it changes how often
// they contend on the per-uid `/tmp/kata-installed-main-<uid>` singleton. The
// fix is that no call here blocks: `run_kata` is async over `tokio::process`
// (see `run_bounded`), so the runtime stays live under a running child and the
// per-command deadline can fire on a CURRENT_THREAD runtime. The usual outcome
// is the most specific message available: the command that hung, by name,
// rather than the test that contained it.

/// Guard: the fix above is a property of `run_bounded`, and a future edit that
/// reintroduces a blocking spawn would silently restore the hole — the suite
/// would still pass, and only a hang would reveal it. So prove the property directly: on a
/// CURRENT_THREAD runtime (exactly what every smoke here uses), with a child
/// that will not exit for a minute, the deadline must still fire.
///
/// `/bin/sleep`, not `kata`: the subject is the runtime blocking, not the
/// product, and this way the guard runs in the ordinary `just test` suite
/// instead of only under `KATA_LIVE_SMOKE`.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn a_blocked_child_cannot_starve_the_deadline_on_a_current_thread_runtime() {
    let started = std::time::Instant::now();
    let err = run_bounded(
        Path::new("/bin/sleep"),
        Path::new("/"),
        &["60"],
        Duration::from_millis(300),
    )
    .await
    .expect_err("a 60s child must not satisfy a 300ms deadline");
    let elapsed = started.elapsed();

    assert!(
        err.contains("SMOKE_COMMAND_DEADLINE"),
        "the trip must be greppable and self-identifying: {err}"
    );
    assert!(
        err.contains("/bin/sleep"),
        "the message must name the COMMAND that hung — the whole point of this layer: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the deadline must fire at 300ms, not be starved until the runner kills us; took \
         {elapsed:?} — which means the runtime is blocked again"
    );
}

/// Parse an NDJSON listing — one JSON document per line.
///
/// `kata workers`, `kata run list` and `kata approvals` all emit through
/// `emit_list`, whose contract is "one record per line" (see
/// `bin/kata/src/cli/operator/status.rs`). A listing is NOT a JSON array,
/// so `json_stdout(..).as_array()` on one of them is always `None` — which reads
/// as "the listing was empty" rather than "you parsed the wrong shape".
fn json_lines(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).expect("each listing line must be one JSON document")
        })
        .collect()
}

fn last_json_line(stdout: &str) -> serde_json::Value {
    let line = stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .expect("stdout must include at least one JSON line");
    serde_json::from_str(line).expect("last stdout line must be JSON")
}

fn replace_config_value(config: &str, key: &str, value: &str) -> String {
    let needle = format!("{key} = ");
    config
        .lines()
        .map(|line| {
            if line.trim_start().starts_with(&needle) {
                format!("{key} = \"{value}\"")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Drop SGR escape sequences from a captured log line.
///
/// A log a smoke ASSERTS ON is a machine-read surface, and the main's `tracing`
/// fmt layer colours field values by default — so the bytes on disk are
/// `field=<ESC>[3m"value"<ESC>[0m` and any needle spanning the `=` fails against
/// a line that says exactly the right thing. Handled here rather than worked
/// around at one call site, because every log assertion in this file has the
/// same hazard.
///
/// Deliberately narrow: it strips `ESC [ … <final byte>` and leaves everything
/// else, so a line carrying no escapes comes back byte-identical.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // CSI: `ESC [` params… final byte in 0x40..=0x7E.
        if chars.next() != Some('[') {
            continue;
        }
        for c in chars.by_ref() {
            if ('\u{40}'..='\u{7e}').contains(&c) {
                break;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Product CLI path: init + installed main + Starlark operator surfaces
// ---------------------------------------------------------------------------

/// The `serve` spawn under the `oci` profile: the capsule route needs a
/// certified provider in `KATA_EXTERNAL_*` exports (provisioned by
/// [`kata_test_utils::live::provision_live_provider`]) and rootless youki
/// containers own a cgroup only inside a delegated scope, so `systemd-run`
/// is the process the smoke actually spawns — the same wrap
/// [`NodeHandle`](kata_test_utils::live::NodeHandle) gives every other
/// fixture. Provider provisioning returns the env pairs this command carries.
fn product_cli_main_command(
    kata: &Path,
    project: &Path,
    provider_env: &[(String, String)],
) -> Command {
    let mut command = Command::new("systemd-run");
    command
        .args(kata_test_utils::delegated_scope::systemd_run_args())
        .arg(kata)
        .current_dir(project)
        .envs(provider_env.iter().map(|(key, value)| (key, value)))
        .args(["serve", "--config", ".kata/kata.toml"]);
    command
}

#[test]
fn product_cli_main_command_carries_the_provider_exports_in_a_delegated_scope() {
    let project = Path::new("/fixture-project");
    let provider_env = vec![(
        "KATA_EXTERNAL_EXECUTION_PROVIDER".to_owned(),
        "youki".to_owned(),
    )];
    let command = product_cli_main_command(Path::new("/fixture-bin/kata"), project, &provider_env);
    assert_eq!(
        command
            .get_envs()
            .find(|(key, _)| *key == "KATA_EXTERNAL_EXECUTION_PROVIDER")
            .and_then(|(_, value)| value),
        Some(std::ffi::OsStr::new("youki")),
        "the capsule route resolves its provider from these exports only"
    );
    assert_eq!(command.get_current_dir(), Some(project));
    assert_eq!(command.get_program(), std::ffi::OsStr::new("systemd-run"));
    let args = command.get_args().collect::<Vec<_>>();
    assert!(
        args.windows(2).any(|pair| pair == ["serve", "--config"]),
        "the wrapped argv still serves the init'd config: {args:?}"
    );
}

/// Live product-surface smoke. Boots from `kata init`, submits a `.star`
/// workflow through `kata run <path> --submit`, then proves the top-level
/// operator views used in the installed single-operator loop.
#[kata_test_utils::kata_timeout(secs = 90)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_product_cli_init_main_submit_watch_wait_output_shutdown"]
async fn smoke_product_cli_init_main_submit_watch_wait_output_shutdown() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let kata = bin_path("kata").expect("kata binary");
    let dir = tempfile::tempdir().expect("tempdir");
    // Declared AFTER `dir` so it drops BEFORE it: the provider store below is sealed.
    let _unseal = kata_test_utils::live::UnsealLiveProviderStore::new(dir.path());
    let project = dir.path();

    run_kata(&kata, project, &["init", "--config", ".kata/kata.toml"]).await;

    // The init'd config boots under the shipped `oci` profile, which needs two
    // facts the scaffold cannot invent and the operator declares afterwards:
    // the `[node] environment` closure (boot refuses `node_environment_undeclared`
    // without it) and the certified capsule provider (route refuses
    // `oci_provider_undeclared` without `KATA_EXTERNAL_*`). The smoke declares
    // the same pinned live environment every live OCI rig binds and provisions
    // the provider the operator path provisions.
    let provider_env =
        kata_test_utils::live::provision_live_provider(dir.path()).expect("provision provider");
    // Both held until the smoke returns, after `main` below is gone: the main
    // binds them, and no other process's `:0` bind is handed either.
    let api_port = HeldPort::new().expect("api port");
    let metrics_port = HeldPort::new().expect("metrics port");
    let api_socket = api_port.addr();
    let metrics_socket = metrics_port.addr();
    let api_url = format!("http://{api_socket}");
    let config_path = project.join(".kata/kata.toml");
    let mut config = std::fs::read_to_string(&config_path).expect("read generated config");
    config = replace_config_value(&config, "bind", &api_socket.to_string());
    config = replace_config_value(&config, "metrics_bind", &metrics_socket.to_string());
    config = config.replacen(
        "[node]\n",
        &format!(
            "[node]\n{}",
            kata_test_utils::live::live_environment_block("kata-live-product-cli")
        ),
        1,
    );
    std::fs::write(&config_path, config).expect("write patched config");

    let star_path = project.join("product-cli-smoke.star");
    std::fs::write(
        &star_path,
        r#"
probe = stage(
    id = "probe",
    agent = "shell",
    prompt = "printf '{\"ok\":true,\"source\":\"starlark_api\"}\\n'",
    outputs = {
        "ok": "bool",
        "source": "string",
    },
)
workflow("product-cli-starlark-smoke", root = [probe])
"#,
    )
    .expect("write smoke starlark");
    let star = star_path.to_str().expect("star path must be utf-8");
    run_kata(&kata, project, &["check", star]).await;

    let log_path = project.join("main.log");
    let log = std::fs::File::create(&log_path).expect("create main log");
    let mut main = ChildGuard::new(
        product_cli_main_command(&kata, project, &provider_env)
            .stdout(Stdio::from(log.try_clone().expect("clone main log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn installed main"),
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut ready = false;
    let mut last_probe_error = String::new();
    while std::time::Instant::now() < deadline {
        // Bounded per attempt, and bounded WELL BELOW the 30s readiness budget:
        // a probe that hangs must not consume the budget it is being measured
        // against, or "the API never became ready" reports a stalled probe as a
        // dead main. Five seconds is generous for one `run list` against a
        // loopback socket and leaves room for at least five more attempts.
        match run_bounded(
            &kata,
            project,
            &["--api-url", &api_url, "run", "list"],
            Duration::from_secs(5),
        )
        .await
        {
            Ok(probe) if probe.status.success() => {
                ready = true;
                break;
            }
            Ok(probe) => {
                last_probe_error = format!(
                    "exit {:?}; stderr: {}",
                    probe.status,
                    String::from_utf8_lossy(&probe.stderr).trim()
                );
            }
            Err(message) => last_probe_error = message,
        }
        if let Some(status) = main.try_wait() {
            panic!(
                "installed main exited before API became ready: {status:?}\nlog:\n{}",
                std::fs::read_to_string(&log_path).unwrap_or_default()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        ready,
        "API did not become ready at {api_url}; last probe: {last_probe_error}\nlog:\n{}",
        std::fs::read_to_string(&log_path).unwrap_or_default()
    );

    // `kata workers` is NDJSON, one record per line — not a JSON array;
    // `.as_array()` is `None` for a listing.
    let workers = json_lines(&run_kata(&kata, project, &["--api-url", &api_url, "workers"]).await);
    assert!(
        !workers.is_empty(),
        "worker inventory should include the main's supervised node: {workers:?}"
    );
    run_kata(&kata, project, &["--api-url", &api_url, "approvals"]).await;

    let submitted = json_stdout(
        &run_kata(
            &kata,
            project,
            &["--api-url", &api_url, "run", star, "--submit"],
        )
        .await,
    );
    let id = submitted["id"]
        .as_str()
        .expect("submit response id")
        .to_string();
    assert_eq!(submitted["status"].as_str(), Some("pending"));

    // `--timeout-secs`: the streaming face is unbounded by default because an
    // operator watching a long workflow is not hung. A SCRIPT has nobody to
    // press Ctrl-C, so it passes a bound and gets `kata watch: execution ... did
    // not reach a terminal status within ...` instead of a silent wait. 30s is
    // well past the ~200ms shell stage this smoke submits, and below the
    // `run_kata` per-command deadline so the more specific message wins.
    let watch = run_kata(
        &kata,
        project,
        &[
            "--api-url",
            &api_url,
            "watch",
            &id,
            "--include-outputs",
            "--timeout-secs",
            "30",
        ],
    )
    .await;
    let watch_last = last_json_line(&watch);
    // WHICH FRAME KIND ENDS THE STREAM IS A RACE. `watch_execution`
    // (`bin/kata/src/cli/operator/watch.rs`) emits ONE `snapshot` up
    // front from `observe`, then one `ledger` line per event, and returns
    // from whichever of the two first observes `is_terminal()`. So the last line
    // is `snapshot` only when the run finished before `kata watch` attached, and
    // `ledger` when it did not — and this smoke submits a ~200ms shell stage and
    // then pays a process spawn before attaching, so both orders are reachable.
    // Pinning either kind would pin a coin flip, not a contract.
    //
    // The contract `kata watch` actually keeps is the two assertions below: the
    // LAST line carries the TERMINAL execution. Both `WatchLine::Snapshot` and
    // `WatchLine::Ledger` carry that `execution` field (`kind` is the serde tag
    // on `kata_client::operator_projection::WatchLine`), and neither `progress`
    // nor `progress_lagged` does — so requiring one of the two execution-bearing
    // kinds is the real invariant, and it still fails if watch ever ends on a
    // progress frame or exits before terminal.
    let last_kind = watch_last["kind"].as_str();
    assert!(
        matches!(last_kind, Some("snapshot" | "ledger")),
        "kata watch must end on an execution-bearing frame, got kind={last_kind:?}; \
         full line: {watch_last}"
    );
    assert_eq!(
        watch_last["execution"]["status"].as_str(),
        Some("completed")
    );
    assert_eq!(
        watch_last["execution"]["operator_packet"]["terminal"].as_bool(),
        Some(true)
    );

    let waited = json_stdout(
        &run_kata(
            &kata,
            project,
            &[
                "--api-url",
                &api_url,
                "run",
                "wait",
                &id,
                "--timeout-secs",
                "10",
                "--poll-ms",
                "50",
            ],
        )
        .await,
    );
    assert_eq!(waited["id"].as_str(), Some(id.as_str()));
    assert_eq!(waited["status"].as_str(), Some("completed"));
    assert_eq!(
        waited["workflow_name"].as_str(),
        Some("product-cli-starlark-smoke")
    );

    let replay =
        json_stdout(&run_kata(&kata, project, &["--api-url", &api_url, "replay", &id]).await);
    assert_eq!(replay["status"].as_str(), Some("completed"));
    assert_eq!(replay["operator_packet"]["terminal"].as_bool(), Some(true));

    let run_summary =
        json_stdout(&run_kata(&kata, project, &["--api-url", &api_url, "run-summary", &id]).await);
    assert_eq!(
        run_summary["summary_kind"].as_str(),
        Some("operator_run_summary")
    );
    assert_eq!(run_summary["status"].as_str(), Some("completed"));
    assert_eq!(run_summary["terminal"].as_bool(), Some(true));

    let output = json_stdout(
        &run_kata(
            &kata,
            project,
            &["--api-url", &api_url, "run", "output", &id, "probe"],
        )
        .await,
    );
    assert_eq!(output["parsed"]["ok"], serde_json::Value::Bool(true));
    assert_eq!(output["parsed"]["source"].as_str(), Some("starlark_api"));

    let workspace =
        json_stdout(&run_kata(&kata, project, &["--api-url", &api_url, "workspace"]).await);
    // The shipped CLI emits the version this build stamps; the SDK it decodes
    // through refuses any other (`refuse_foreign_workspace_schema`).
    let stamped = u64::from(kata_types::workspace_awareness::WORKSPACE_AWARENESS_SCHEMA_VERSION);
    assert_eq!(workspace["schema_version"].as_u64(), Some(stamped));
    assert!(workspace["workers"]["total"].as_u64().unwrap_or_default() >= 1);
    assert!(
        workspace["executions"]["total"]
            .as_u64()
            .unwrap_or_default()
            >= 1
    );

    let execution_workspace = json_stdout(
        &run_kata(
            &kata,
            project,
            &["--api-url", &api_url, "execution-workspace", &id],
        )
        .await,
    );
    assert_eq!(
        execution_workspace["schema_version"].as_u64(),
        Some(stamped)
    );
    assert_eq!(
        execution_workspace["execution_id"].as_str(),
        Some(id.as_str())
    );

    main.shutdown().await;
}

// ---------------------------------------------------------------------------
// B/C. Installed main + subordinate local-socket worker shell dispatch
// ---------------------------------------------------------------------------

/// Live smoke for subordinate local-process capacity. Boots an installed main
/// node with no supervised node, provisions a dedicated `kata-worker` over the
/// local-socket transport, submits the shell-only `local-worker-ping` workflow,
/// and asserts the terminal record is attributed to the external worker. This
/// exercises the local-process dispatch shape without a network boundary
/// hop and remote host dependency.
#[kata_test_utils::kata_timeout(secs = 90)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_main_local_socket_worker_dispatches_a_ping"]
async fn smoke_main_local_socket_worker_dispatches_a_ping() {
    // NOTE for anyone "verifying" this smoke: without KATA_LIVE_SMOKE the body
    // below never runs and the test reports PASS. An isolated `cargo nextest`
    // run is not evidence this smoke is healthy; it is the early return. Run it
    // through `just smoke`, which sets the variable.
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let home = NodeHandle::spawn_main_with_local_socket().expect("spawn home");
    home.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let caps = vec![WorkerResource::Shell];
    let worker = WorkerHandle::spawn(&home, &caps).expect("spawn local-socket worker");
    assert!(worker.pid() > 0, "worker pid should be non-zero");

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut inventory = Vec::new();
    while std::time::Instant::now() < deadline {
        inventory = home.client().list_workers().await.unwrap_or_default();
        if inventory
            .iter()
            .any(|worker| worker.alive && worker.transport == "local_socket")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        inventory
            .iter()
            .any(|worker| worker.alive && worker.transport == "local_socket"),
        "local-socket worker did not register within 30s; inventory={inventory:?}"
    );

    let exec = home
        .client()
        .run("local-worker-ping")
        .await
        .expect("submit local-worker-ping");
    let record = exec
        .wait_for_terminal(Duration::from_secs(30))
        .await
        .expect("wait for terminal");

    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "expected completed, got {:?} (error={:?})",
        record.status,
        record.error
    );
    // The product names EVERY worker that connects over the local socket
    // `local-worker-{seq}` (`bin/kata/src/local_capacity.rs`, after
    // `verify_local_worker_hello`). The prefix is read from the emitter's own
    // crate (`LOCAL_WORKER_ID_PREFIX`), never re-spelled as a literal here.
    //
    // The attribution is worth asserting: the main also runs its own
    // capacity, so a record attributed to nothing external would mean the
    // external worker never received the dispatch. What it may NOT do is invent a
    // name the product does not use.
    assert!(
        record
            .worker_id
            .starts_with(kata_types::worker::LOCAL_WORKER_ID_PREFIX),
        "expected external local-socket worker attribution, got {:?}",
        record.worker_id
    );

    let ping = record
        .outputs
        .as_ref()
        .and_then(|outputs| outputs.get("ping"))
        .expect("ping output");
    let parsed = ping.get("parsed").expect("parsed JSON");
    assert_eq!(parsed.get("ok"), Some(&serde_json::Value::Bool(true)));
    // `workflows/smoke/local-worker-ping.star:23` emits
    // `{"ok": true, "pong": "local-worker", "arch": "$ARCH"}`.
    assert_eq!(
        parsed.get("pong"),
        Some(&serde_json::Value::String("local-worker".into())),
        "the pong value is the workflow's, not this test's: see workflows/smoke/local-worker-ping.star"
    );
    // The stage is CONFINED and reports `uname -m`, which the bind-mounted `/usr`
    // toolchain answers inside the guest, and the value is compared against the
    // architecture THIS BINARY was compiled for. `std::env::consts::ARCH` is a
    // compiler constant, so the oracle shares no implementation with the pack,
    // the worker, or the sandbox: a guest that reported a different machine, or
    // an empty string, or a stale cached output, fails here.
    assert_eq!(
        parsed.get("arch").and_then(|arch| arch.as_str()),
        Some(std::env::consts::ARCH),
        "the confined guest's `uname -m` must be this build's target arch: {parsed:?}"
    );

    // The containment ADVERTISE half, over a REAL socket between two REAL
    // processes.
    //
    // Everything in-tree about this claim is exercised in-process; what only a
    // live smoke can show is that a separately-provisioned `kata-worker` really
    // puts the key on the wire, that the main's strict decoder ACCEPTS it (a
    // malformed claim rejects the handshake, so the assertions above would
    // already have failed), and that the value the main recorded is a MEASURED
    // verdict rather than the fail-closed `unstated` a non-advertising worker produces.
    //
    // Read from the main's own log line at registration, because that is the
    // only surface the value reaches — `WorkerSnapshot` carries no field for it.
    let main_log = std::fs::read_to_string(home.log_path()).unwrap_or_default();
    let registration = main_log
        .lines()
        .find(|line| line.contains("local worker registered"))
        .unwrap_or_else(|| {
            panic!("the main must log the local worker's registration; log:\n{main_log}")
        });
    // ANSI is STRIPPED before matching, and that is not defensive tidying. The
    // main's `tracing` fmt layer colours field VALUES, so the redirected log holds
    // `containment=<ESC>[3m"available"<ESC>[0m` and any needle spanning
    // `containment=` and its value can never match. The failure messages below
    // print the DEBUG form, so the next reader sees the escapes rather than a
    // rendering of them.
    let plain = strip_ansi(registration);
    assert!(
        plain.contains(r#"containment="available""#)
            || plain.contains(r#"containment="unavailable""#),
        "the main must record a MEASURED containment verdict decoded from this worker's Hello; \
         `unstated` here would mean the worker never advertised and the whole advertise half is \
         inert on the product path. got: {plain:?}"
    );
    assert!(
        plain.contains("containment_evidence=\"") && plain.contains("youki"),
        "the claim must carry the worker's own MEASUREMENT — the placement refusal quotes it back \
         to the operator, so a claim with no evidence is a refusal that names no cause. The \
         provider named is the certified rootless-OCI route's pinned youki, in the `CERTIFIED` \
         wording on the `available` arm and in every `OciPrerequisiteRefusal` on the other: \
         {plain:?}"
    );

    worker.shutdown().await.expect("worker shutdown");
    home.shutdown().await.expect("home shutdown");
}

// ---------------------------------------------------------------------------
// An operator's CANCEL, over a real Unix socket, between two real
// processes — and the durable stop it leaves behind actually discharged.
// ---------------------------------------------------------------------------

/// Is any process running the sleeper this smoke minted?
///
/// THE MARKER IS THE SLEEP DURATION ITSELF: a bare `sleep 600` would be
/// satisfied by ANOTHER test run's sleeper on a host running several at once,
/// and readiness that another process can satisfy proves nothing about this one.
fn sleeper_alive(marker: &str) -> bool {
    Command::new("pgrep")
        .arg("-f")
        .arg(format!("sleep {marker}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `kata run cancel` on a LOCAL-SOCKET worker reaches the worker, ends
/// the stage, and DISCHARGES the durable stop it wrote first.
///
/// # Why this smoke exists, and why no in-process rig can replace it
///
/// `WorkflowExecutor::cancel` writes the durable `attempt_stop_requests` row
/// BEFORE it asks the transport to deliver, deliberately and with no rollback.
/// If `LocalSocketTransport::send_control` refused, every operator cancel on the
/// only supported multi-process transport would fail AND leave a durable row
/// naming an attempt that no frame would ever discharge. That row is a LATCH: while
/// `evidence.worker_stops[].awaiting_worker_acknowledgement` is true it blocks
/// the workspace reclaim (`kata run park`), and the only exit is a manual
/// `kata run discharge-stop` with an operator attribution.
///
/// A single-process cancel proof never sends the frame across a socket. This
/// smoke is the same proof over the multi-process transport: two real
/// processes, a real `kata-worker`, a real `AF_UNIX` stream.
///
/// It asserts three things:
///   1. the cancel is ACCEPTED (`assignments_asked_to_stop >= 1`);
///   2. the stage really ends — the sleeper process is GONE, not just the record
///      terminal, and it ends in well under the 600s the sleep would take;
///   3. the durable stop is DISCHARGED — `awaiting_worker_acknowledgement` is
///      false on every `worker_stops` row, which is only true if the worker's own
///      fenced attempt-terminal came back over that socket.
///
/// No model budget: `agent = "shell"`.
#[kata_test_utils::kata_timeout(secs = 180)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_main_local_socket_cancel_reaches_worker_and_discharges_the_stop"]
async fn smoke_main_local_socket_cancel_reaches_worker_and_discharges_the_stop() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    // A duration no other test run can be running. `sleep` accepts a fractional
    // argument, so the pid rides in the decimals and `pgrep -f` matches only us.
    let marker = format!("600.{}", std::process::id());
    let workflow = format!(
        r#"
slow = stage(
    id = "slow",
    agent = "shell",
    prompt = "set -eu\nsleep {marker}\nprintf '{{\"never\": true}}\\n'\n",
    outputs = {{"never": "bool"}},
)

workflow(
    "local-socket-cancel",
    description = "Live proof: a cancel issued to a LOCAL-SOCKET worker reaches it, ends the stage, and discharges the durable stop.",
    root = [slow],
)
"#
    );

    let (home, _stdlib) = spawn_isolated_main();
    home.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let worker =
        WorkerHandle::spawn(&home, &[WorkerResource::Shell]).expect("spawn local-socket worker");
    let worker_ids = await_live_ls_workers(&home, 1, Duration::from_secs(30)).await;
    assert_eq!(worker_ids.len(), 1, "one external worker expected");

    let exec = home
        .client()
        .run_starlark(&workflow, Some("local-socket-cancel.star"))
        .await
        .expect("submit cancel workflow");

    // The stage must be dispatched to the EXTERNAL worker — a cancel of work the
    // main ran itself would prove nothing about the socket.
    let pinned = await_pinned_worker(&exec, Duration::from_secs(60)).await;
    assert_eq!(
        pinned, worker_ids[0],
        "the stage must run on the external local-socket worker"
    );

    // And it must be RUNNING. Cancelling a dispatched-but-not-started attempt
    // degrades this to "we stopped something that had not begun", which the
    // engine satisfies without ever reaching a worker.
    let start_deadline = std::time::Instant::now() + Duration::from_secs(60);
    while !sleeper_alive(&marker) {
        assert!(
            std::time::Instant::now() < start_deadline,
            "the sleeper never started, so a cancel would prove nothing"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let t0 = std::time::Instant::now();
    let asked = home
        .client()
        .cancel(exec.id(), "p3-b2 local-socket cancel proof")
        .await
        .expect("cancel must be ACCEPTED over the local-socket transport")
        .assignments_asked_to_stop;
    assert!(
        asked >= 1,
        "cancel must ask at least one attempt to stop, got {asked}"
    );

    let record = exec
        .wait_for_terminal(Duration::from_secs(90))
        .await
        .expect("the cancelled execution must reach a terminal");
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "terminal took {elapsed:?} against a 600s sleep — the stop did not reach the worker"
    );
    assert_eq!(
        record.status,
        ExecutionStatus::Cancelled,
        "a cancelled execution projects onto Cancelled; got {:?} (error={:?})",
        record.status,
        record.error
    );

    // The stage really ended. A terminal record with the sleeper still running
    // would be the engine reporting a stop it never performed.
    let gone_deadline = std::time::Instant::now() + Duration::from_secs(30);
    while sleeper_alive(&marker) {
        assert!(
            std::time::Instant::now() < gone_deadline,
            "the record went terminal but the worker's `sleep {marker}` is STILL RUNNING"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // THE LATCH. Poll rather than read once: the stop is discharged by the
    // worker's attempt-terminal frame, which the reactor acknowledges around the
    // same moment the execution projects terminal.
    let latch_deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let rec = exec.record().await.expect("execution record");
        let stops = &rec.evidence.worker_stops;
        assert!(
            !stops.is_empty(),
            "cancel recorded no durable stop at all — the evidence surface is inert"
        );
        if stops.iter().all(|s| !s.awaiting_worker_acknowledgement) {
            break;
        }
        assert!(
            std::time::Instant::now() < latch_deadline,
            "the durable stop is STILL awaiting worker acknowledgement — this is the \
             undischargeable latch; it blocks the workspace reclaim (`kata run park`) \
             until a manual `kata run discharge-stop`. \
             rows={stops:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    worker.shutdown().await.expect("worker shutdown");
    home.shutdown().await.expect("home shutdown");
}

// ---------------------------------------------------------------------------
// Local-socket MULTI-worker: dispatch spread + kill-redispatch +
// credential refusal, all over TWO real `kata-worker` processes.
// ---------------------------------------------------------------------------

/// Inline single long shell stage for the dispatch-spread proof. Submitted
/// twice; because `work` stays in flight for ~6s, the second submission's
/// least-loaded placement must land on the other worker.
const LOCAL_SOCKET_SPREAD_WF: &str = r#"
work = stage(
    id = "work",
    agent = "shell",
    prompt = "set -eu\nsleep 6\nprintf '{\"done\": true}\\n'\n",
    outputs = {"done": "bool"},
)

workflow(
    "local-socket-spread",
    description = "Dispatch-spread proof: one long shell stage submitted twice concurrently must land on two different workers.",
    root = [work],
)
"#;

/// Boot an installed main with an isolated, empty workflow library
/// (`KATA_STDLIB_DIR` → an empty dir). Kata owns no proxy listener or privileged
/// egress ports, so these multi-worker smokes can run in parallel with other
/// Kata nodes on the same host. They submit workflows inline via
/// `run_starlark`, so the empty library is invisible to them.
///
/// Returns the main handle plus the tempdir backing the empty library; hold
/// the tempdir for the installed main's lifetime.
fn spawn_isolated_main() -> (NodeHandle, tempfile::TempDir) {
    let stdlib = tempfile::tempdir().expect("stdlib tempdir");
    let stdlib_dir = stdlib.path().join("stdlib");
    std::fs::create_dir_all(&stdlib_dir).expect("create empty stdlib dir");
    let home = NodeHandle::spawn_main_with_local_socket_and_env(vec![(
        "KATA_STDLIB_DIR".to_string(),
        stdlib_dir.to_string_lossy().into_owned(),
    )])
    .expect("spawn home");
    (home, stdlib)
}

/// Poll the installed main's worker inventory until exactly `want` live
/// local-socket workers are registered, returning their ids. Panics at the
/// deadline. Used to register two external workers *sequentially* so the
/// id↔process map is unambiguous.
async fn await_live_ls_workers(home: &NodeHandle, want: usize, timeout: Duration) -> Vec<String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let ids: Vec<String> = home
            .client()
            .list_workers()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|w| w.alive && w.transport == "local_socket")
            .map(|w| w.id)
            .collect();
        if ids.len() == want {
            return ids;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expected {want} live local_socket workers within {timeout:?}; last saw {ids:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Poll an execution until its stage has been dispatched to a concrete
/// `local-worker-N` (the `worker_id` the runner pinned to leaves `"pending"`).
///
/// The prefix is `kata_types::worker::LOCAL_WORKER_ID_PREFIX`, not a literal:
/// a re-spelled prefix that drifts from the emitter would time out on a stage
/// that HAD been dispatched, with a failure message that denies the attribution
/// in the same breath as printing it. Reading the constant makes the drift a
/// compile error instead.
async fn await_pinned_worker(exec: &Execution, timeout: Duration) -> String {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let rec = exec.record().await.expect("execution record");
        if rec
            .worker_id
            .starts_with(kata_types::worker::LOCAL_WORKER_ID_PREFIX)
        {
            return rec.worker_id;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "execution {} never pinned to a worker; last worker_id={:?}",
            exec.id(),
            rec.worker_id
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Poll a fixture process's captured log until it contains `needle`, returning the
/// full log text. Panics at the deadline with the log tail. Lets a smoke wait
/// on a synchronous main-side event (e.g. a handshake rejection) without a
/// fixed sleep, shrinking the flake window on a loaded host.
async fn await_log_contains(log_path: &std::path::Path, needle: &str, timeout: Duration) -> String {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let log = std::fs::read_to_string(log_path).unwrap_or_default();
        if log.contains(needle) {
            return log;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "fixture log never contained {needle:?} within {timeout:?}; tail:\n{}",
            log_tail(&log)
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Last 40 lines of a captured daemon log, for assertion failure context.
fn log_tail(log: &str) -> String {
    let lines: Vec<&str> = log.lines().collect();
    let start = lines.len().saturating_sub(40);
    lines[start..].join("\n")
}

/// Live proof, CROSS-PROCESS: boot an installed main with no supervised node,
/// register TWO real `kata-worker` processes over the local socket, run a
/// two-stage workflow, SIGKILL the worker the first stage's capsule was
/// dispatched to, and assert the main detects the death and SETTLES the
/// orphaned capsule attempt — PROVEN AMBIGUOUS, terminal, NEVER re-delivered —
/// failing the run with the ambiguity named rather than performing the effect
/// a second time.
///
/// # The `oci` settlement
///
/// `capsule_settlement`'s door is a durable classification: a capsule attempt whose worker died
/// mid-run is PROVEN AMBIGUOUS ("the main cannot observe whether this capsule's container ran") and
/// settled terminal with "NOT re-delivered (capsule re-delivery is not implemented)" — the
/// at-most-once answer, named at the settlement boundary rather than at a retry decision. The
/// `finish` stage depending on `work` still never runs, because the graph stops on the unobserved
/// effect.
///
/// # What this proves that no in-process test can
///
/// Two REAL worker processes and a real SIGKILL, so the only thing standing
/// between an ambiguous capsule attempt and a second container of the effect
/// is the main plane's settlement. This is that check on the live path,
/// through real sockets and a real kill.
#[kata_test_utils::kata_timeout(secs = 120)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_main_local_socket_two_workers_kill_refuses_ambiguous_redelivery"]
async fn smoke_main_local_socket_two_workers_kill_refuses_ambiguous_redelivery() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let (home, _stdlib) = spawn_isolated_main();
    home.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let caps = vec![WorkerResource::Shell];

    // Register the two workers SEQUENTIALLY: worker_a connects first, so the
    // id captured after it is unambiguously worker_a's; worker_b second.
    let worker_a = WorkerHandle::spawn(&home, &caps).expect("spawn worker a");
    let id_a = await_live_ls_workers(&home, 1, Duration::from_secs(30)).await[0].clone();
    let pid_a = worker_a.pid();

    let worker_b = WorkerHandle::spawn(&home, &caps).expect("spawn worker b");
    let id_b = await_live_ls_workers(&home, 2, Duration::from_secs(30))
        .await
        .into_iter()
        .find(|id| *id != id_a)
        .expect("second worker id");
    let pid_b = worker_b.pid();

    // Submit the two-stage long workflow and wait until `work` is dispatched.
    let exec = home
        .client()
        .run_starlark(
            kata_test_utils::KILL_MID_RUN_WF,
            Some("kill-redispatch.star"),
        )
        .await
        .expect("submit kill-redispatch workflow");
    let victim_id = await_pinned_worker(&exec, Duration::from_secs(30)).await;
    let victim_pid = if victim_id == id_a {
        pid_a
    } else if victim_id == id_b {
        pid_b
    } else {
        panic!("dispatched worker {victim_id} is neither {id_a} nor {id_b}");
    };
    let survivor_id = if victim_id == id_a { &id_b } else { &id_a };

    // HARD kill (SIGKILL, not the graceful shutdown path) so the installed main
    // observes a transport EOF from a dead peer — the death-detection trigger.
    kill(
        Pid::from_raw(i32::try_from(victim_pid).expect("worker pid fits i32")),
        Signal::SIGKILL,
    )
    .expect("sigkill the worker running the stage");

    // The run must reach a TERMINAL state — killing a worker mid-stage may never
    // wedge the execution, whatever the settlement decides afterwards.
    let record = exec
        .wait_for_terminal(Duration::from_secs(60))
        .await
        .expect("wait for terminal after worker kill");
    assert_eq!(
        record.status,
        ExecutionStatus::Failed,
        "an orphaned checked stage must FAIL closed, not be re-invoked and not hang; \
         got {:?} (error={:?})",
        record.status,
        record.error
    );

    // AT-MOST-ONCE, NAMED. The refusal must be the capsule settlement's, and it
    // must say why: a bare `Failed` is also what a crashed main or a broken
    // socket produces, and neither of those proves anything about re-delivery.
    let error = record.error.clone().unwrap_or_default();
    assert!(
        error.contains("AMBIGUOUS") && error.contains("re-deliver"),
        "the failure must be the capsule settlement naming the ambiguity and its \
         no-redelivery answer — a bare `Failed` is also what a crashed main or a \
         broken socket produces, and neither proves the attempt was settled \
         rather than silently re-run; got {error:?}"
    );
    assert!(
        error.contains("work"),
        "the refusal must name the orphaned stage; got {error:?}"
    );

    // The downstream stage must NOT have run: `finish` depends on `work`, and
    // `work` never produced an observed outcome, so the graph must stop rather
    // than advance on an unobserved effect.
    let downstream_outputs = record
        .outputs
        .as_ref()
        .is_some_and(|outputs| outputs.contains_key("finish"));
    assert!(
        !downstream_outputs,
        "downstream `finish` ran on an unobserved upstream effect; outputs={:?}",
        record.outputs
    );

    // Corroborating hop trace from the main log. The POSITIVE assertion is that
    // the reactor noticed the death at all — without it a `Failed` run would be
    // consistent with the main never reacting, and every assertion above would
    // pass for the wrong reason.
    let home_log = std::fs::read_to_string(home.log_path()).unwrap_or_default();
    assert!(
        home_log.contains("triggering worker-death handling"),
        "main log must show the reactor firing worker-death handling; tail:\n{}",
        log_tail(&home_log)
    );
    // And the NEGATIVE, which only means something because the positive above
    // pins that the death WAS handled: nothing was re-delivered. `reactor.rs`
    // logs `redispatched assignments after transport death` only when
    // `handle_worker_death` returns a NON-EMPTY set, so its absence here is the
    // at-most-once property written in the main's own trace. Requiring the
    // redispatch would be requiring the double-delivery.
    assert!(
        !home_log.contains("redispatched assignments after transport death"),
        "an ambiguous, non-re-executable effect was RE-DELIVERED after the worker \
         died — the attempt-level settlement did not hold; tail:\n{}",
        log_tail(&home_log)
    );

    // The survivor is still live in the pool after the kill.
    let final_inv = home.client().list_workers().await.unwrap_or_default();
    assert!(
        final_inv.iter().any(|w| &w.id == survivor_id && w.alive),
        "survivor {survivor_id} must remain alive; inventory={final_inv:?}"
    );

    // Reap: worker_a/worker_b Drop reaps the (possibly already-dead) children.
    drop(worker_a);
    drop(worker_b);
    home.shutdown().await.expect("home shutdown");
}

/// Dispatch-spread proof: two real workers, two concurrent submissions, one
/// per worker. The second submission arrives while the first's `work` stage is
/// still in flight, so the least-loaded scheduler must place it on the OTHER
/// worker — deterministic spread rather than piling both onto one worker.
#[kata_test_utils::kata_timeout(secs = 120)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_main_local_socket_dispatch_spreads_across_two_workers"]
async fn smoke_main_local_socket_dispatch_spreads_across_two_workers() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let (home, _stdlib) = spawn_isolated_main();
    home.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let caps = vec![WorkerResource::Shell];
    let worker_a = WorkerHandle::spawn(&home, &caps).expect("spawn worker a");
    await_live_ls_workers(&home, 1, Duration::from_secs(30)).await;
    let worker_b = WorkerHandle::spawn(&home, &caps).expect("spawn worker b");
    await_live_ls_workers(&home, 2, Duration::from_secs(30)).await;

    // exec1 pins to some worker; its `work` stage stays in flight ~6s.
    let exec1 = home
        .client()
        .run_starlark(LOCAL_SOCKET_SPREAD_WF, Some("local-socket-spread-1.star"))
        .await
        .expect("submit exec1");
    let w1 = await_pinned_worker(&exec1, Duration::from_secs(30)).await;

    // exec2 submits while exec1 is still running → least-loaded picks the peer.
    let exec2 = home
        .client()
        .run_starlark(LOCAL_SOCKET_SPREAD_WF, Some("local-socket-spread-2.star"))
        .await
        .expect("submit exec2");
    let w2 = await_pinned_worker(&exec2, Duration::from_secs(30)).await;

    assert_ne!(
        w1, w2,
        "two concurrent submissions must spread across both workers; both landed on {w1}"
    );

    let r1 = exec1
        .wait_for_terminal(Duration::from_secs(60))
        .await
        .expect("terminal exec1");
    let r2 = exec2
        .wait_for_terminal(Duration::from_secs(60))
        .await
        .expect("terminal exec2");
    assert_eq!(
        r1.status,
        ExecutionStatus::Completed,
        "exec1 {:?}",
        r1.status
    );
    assert_eq!(
        r2.status,
        ExecutionStatus::Completed,
        "exec2 {:?}",
        r2.status
    );

    worker_a.shutdown().await.expect("worker a shutdown");
    worker_b.shutdown().await.expect("worker b shutdown");
    home.shutdown().await.expect("home shutdown");
}

/// Credential-refusal negative: a `kata-worker` provisioned with the WRONG
/// shared secret rejects the main's authenticated challenge before sending a
/// worker proof. The main closes that unauthenticated exchange without creating
/// an enrollment — it never appears in the worker inventory. A correctly
/// provisioned worker over the SAME socket does register, proving the home is
/// admitting good workers and refusing only the bad credential.
#[kata_test_utils::kata_timeout(secs = 60)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_main_local_socket_rejects_worker_with_wrong_secret"]
async fn smoke_main_local_socket_rejects_worker_with_wrong_secret() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let (home, _stdlib) = spawn_isolated_main();
    home.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let caps = vec![WorkerResource::Shell];

    // Bad secret → handshake rejected → never registers.
    let bad = WorkerHandle::spawn_with_secret(&home, &caps, Some("not-the-home-secret"))
        .expect("spawn bad-secret worker");

    // With mutual authentication the bad worker rejects the main challenge
    // first; the main observes the resulting closed connection, not a raw-secret
    // Hello mismatch. Require both sides' actual boundary evidence.
    await_log_contains(
        &bad.data_dir().join("kata-worker.log"),
        "local worker mutual enrollment authentication refused",
        Duration::from_secs(30),
    )
    .await;
    await_log_contains(
        &home.log_path(),
        "local worker mutual enrollment refused",
        Duration::from_secs(30),
    )
    .await;

    let enrolled_domains = || {
        rusqlite::Connection::open_with_flags(
            home.data_dir().join("operational.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open enrollment authority read-only")
        .query_row("SELECT COUNT(*) FROM worker_effect_domains", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("read independently persisted enrollment count")
    };
    assert_eq!(enrolled_domains(), 0, "bad credential must not enroll");
    let inv = home
        .client()
        .list_workers()
        .await
        .expect("worker inventory");
    let live_ls = inv
        .iter()
        .filter(|w| w.alive && w.transport == "local_socket")
        .count();
    assert_eq!(
        live_ls, 0,
        "a worker with the wrong secret must never register; inventory={inv:?}"
    );

    // Contrast: the correctly-provisioned worker DOES register over the same socket.
    let good = WorkerHandle::spawn(&home, &caps).expect("spawn good worker");
    await_live_ls_workers(&home, 1, Duration::from_secs(30)).await;
    assert_eq!(
        enrolled_domains(),
        1,
        "valid credential must enroll exactly once"
    );

    good.shutdown().await.expect("good worker shutdown");
    drop(bad);
    home.shutdown().await.expect("home shutdown");
}

// The shell smokes filter. `just smoke shell_` selects every test
// name containing `shell_` — no model cost. The count is SIX
// (`smoke_shell_workspace_ro_sub_second`,
// `smoke_shell_native_jj_workspace_provider_parks_dirty_candidate`,
// `smoke_shell_offline_dns_blocked`,
// `smoke_shell_contained_stage_reads_git_history`,
// `smoke_shell_declared_read_closure_enforced`,
// `smoke_shell_declared_write_closure_enforced`).
//
// `just smoke shell_` is NOT the step `gate-containment` runs: its
// product-path step is `just smoke-no-budget` — an UNNARROWED
// `(binary(smokes) or binary(live_smoke))` include minus the model-budget
// smoke by name (`bin/kata-eval/tests/gate_exclusion.rs`, `IGNORED_TESTS_OUTSIDE_THE_LANE`).
// So a new live smoke need not carry `shell_` in its name to be run by the
// required gate; name a smoke for what it proves, not for the filter.
//
// The LLM smoke (`smoke_workspace_ro_outputs`) stays in the default `just
// smoke` set because it also catches LLM ↔ sandbox integration drift the pure
// shell probes can't; it is run manually, being the only `#[ignore]`d smoke
// that spends real model budget.

// ---------------------------------------------------------------------------
// 4a. Workspace-ro: fs = "workspace-ro" exposes /workspace read-only
// ---------------------------------------------------------------------------

/// Live smoke for `workflows/smoke/sandbox-smoke-workspace-ro.star`.
/// Boots an installed main with a supervised node and the embedded nanocode
/// harness declared on `default`, submits the workflow, asserts the OCI truth: the
/// probe's `touch` lands inside the capsule (`/work` is writable there), and
/// `judge_work_delta_scope` refuses the delta `work_delta_out_of_scope` —
/// the read-only workspace enforced at adoption.
#[kata_test_utils::kata_timeout(secs = 60)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_workspace_ro_outputs"]
async fn smoke_workspace_ro_outputs() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    // `[agents.default]` binds the embedded harness — the pack's `agent =
    // "default"` is a model turn, and a shell binding would run its English
    // prompt as `sh -c`.
    let node =
        NodeHandle::spawn_supervised_main_with_options(kata_test_utils::live::NodeConfigOptions {
            agents_block: Some(NANOCODE_DEFAULT_AGENT_DECL.to_string()),
            ..kata_test_utils::live::NodeConfigOptions::default()
        })
        .expect("spawn installed main with the nanocode agent declared");
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let exec = node
        .client()
        .run("sandbox-smoke-workspace-ro")
        .await
        .expect("submit");
    let record = exec
        .wait_for_terminal(Duration::from_mins(2))
        .await
        .expect("wait for terminal");

    assert_eq!(
        record.status,
        ExecutionStatus::Failed,
        "the ro stage's `/work` delta must be adoption-refused — a `Completed` here \
         means `.kata-ro-probe` was adopted, the regression the adoption refusal exists for; \
         got {:?} (error={:?}, outputs={:?})",
        record.status,
        record.error,
        record.outputs
    );

    let error = record.error.as_deref().unwrap_or_default();
    assert!(
        error.contains("work_delta_out_of_scope"),
        "the failure must be the delta-scope refusal BY NAME, not a model or \
         transport error; got {error:?}"
    );
    assert!(
        error.contains(".kata-ro-probe"),
        "the refusal must name the path the probe wrote; got {error:?}"
    );

    node.shutdown().await.expect("clean shutdown");
}

// ---------------------------------------------------------------------------
// 4c. Pre-dispatch failure survives installed-main restart
// ---------------------------------------------------------------------------

/// Boot installed main + worker, submit a workflow that errors
/// pre-dispatch (template render against an undefined upstream
/// under strict-undefined — see
/// `crates/test-utils/tests/fixtures/smoke_pre_dispatch_failure.star`
/// for the trigger), capture the execution id + error, drop the
/// installed main, spawn a NEW installed main bound to the SAME data_dir,
/// query the same execution id, assert the failure (status +
/// byte-identical error string) survived the restart.
///
/// Local-socket capacity is used because boot 1 needs an explicit worker;
/// authority and persistence still belong to the same installed main and its
/// `data_dir`.
///
/// The worker is needed only on boot 1 so the submit passes the
/// up-front liveness check (`ExecutorError::NoWorkers` when no transport
/// is alive). Boot 2 doesn't dispatch anything — `observe` is a pure
/// durable read — so the worker is omitted there.
#[kata_test_utils::kata_timeout(secs = 60)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_workflow_failure_survives_restart"]
async fn smoke_workflow_failure_survives_restart() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    // Outer tempdir owns cleanup. Both NodeHandles below borrow
    // its path via `spawn_main_with_local_socket_and_data_dir`, so the second
    // boot reads the same on-disk data directory the first boot
    // wrote into.
    let dir = tempfile::tempdir().expect("tempdir");
    let dir_path = dir.path().to_path_buf();

    // === Boot 1 ===
    let home1 = NodeHandle::spawn_main_with_local_socket_and_data_dir(dir_path.clone())
        .expect("spawn home 1");
    home1
        .await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy home 1");

    // Worker registration is mandatory for `submit` to clear
    // the NoWorkers liveness check; the worker itself never
    // dispatches anything (the failure fires inside
    // `submit_stage` before any assignment lands on a worker).
    let caps = vec![
        WorkerResource::Shell,
        WorkerResource::AgentBackend(BackendType::Harness),
    ];
    let worker1 = WorkerHandle::spawn(&home1, &caps).expect("spawn worker 1");

    // Wait for the worker to actually register with home before
    // submitting — otherwise the submit races the registration
    // and may fail with NoWorkers.
    //
    // Poll the TYPED inventory, never a log line: a log needle that drifts
    // from what the main actually writes burns the full deadline and prints the
    // registration inside the message denying it, and
    // `live_smoke.rs::main_plus_local_worker_registration` notes that "a generic
    // log match can false-pass on a supervised node". The inventory is
    // strictly stronger than any log grep: this main is `CapacityTopology::
    // LocalSocket`, so requiring a live `local_socket` transport proves the
    // EXTERNAL worker cleared the handshake, not merely that some line appeared.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut inventory = Vec::new();
    while std::time::Instant::now() < deadline {
        inventory = home1.client().list_workers().await.unwrap_or_default();
        if inventory
            .iter()
            .any(|worker| worker.alive && worker.transport == "local_socket")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        inventory
            .iter()
            .any(|worker| worker.alive && worker.transport == "local_socket"),
        "external local-socket worker did not register within 30s; inventory={inventory:?}; main log:\n{}",
        std::fs::read_to_string(home1.log_path()).unwrap_or_default()
    );

    let bad_star = include_str!("fixtures/smoke_pre_dispatch_failure.star");
    let exec = home1
        .client()
        .run_starlark(bad_star, Some("smoke_pre_dispatch_failure.star"))
        .await
        .expect("submit");
    let exec_id = exec.id().to_string();
    let record1 = exec
        .wait_for_terminal(Duration::from_secs(30))
        .await
        .expect("wait 1");
    assert_eq!(
        record1.status,
        ExecutionStatus::Failed,
        "boot 1 must observe Failed (template render against an undefined upstream \
         fails pre-dispatch under strict-undefined); got {:?} error={:?}",
        record1.status,
        record1.error
    );
    let err1 = record1.error.clone();
    let err1_text = err1.as_deref().unwrap_or("");
    // The runner returns `KataError::Validation("template render failed for
    // stage broken: ...")`; the executor wraps the stringified error into the
    // synthetic `__workflow__` assignment which the aggregator surfaces
    // verbatim on `ExecutionRecord.error`.
    assert!(
        err1_text.contains("render failed") && err1_text.contains("broken"),
        "boot 1 error must mention 'render failed' for stage 'broken', got {:?}",
        err1_text
    );
    worker1.shutdown().await.expect("worker1 shutdown");
    home1.shutdown().await.expect("home1 shutdown");

    // === Boot 2: same data_dir, no worker ===
    //
    // `observe` only reads the ledger — no worker needed.
    // Skipping the worker also avoids the boot-2 home having to
    // accept a re-registration, which would race the
    // `await_healthy` poll loop.
    let home2 = NodeHandle::spawn_main_with_local_socket_and_data_dir(dir_path.clone())
        .expect("spawn home 2");
    home2
        .await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy home 2");

    let record2 = home2.client().observe(&exec_id).await.expect("observe");
    assert_eq!(
        record2.status,
        ExecutionStatus::Failed,
        "failure must survive home-node restart"
    );
    assert_eq!(
        record2.error, err1,
        "error string must be byte-identical across restart"
    );
    home2.shutdown().await.expect("home2 shutdown");
}

// ---------------------------------------------------------------------------
// 4d. Shell-stage workspace-ro probe (sub-second, no LLM cost)
// ---------------------------------------------------------------------------

/// Live smoke for `workflows/smoke/sandbox-smoke-shell-workspace-ro.star`.
/// Boots an installed main with a supervised node, submits the shell-stage
/// workflow, asserts the OCI truth: the `touch` SUCCEEDS inside the capsule
/// (`/work` mounts writable there — the filesystem posture is the capsule's
/// contract, not the write itself), and `judge_work_delta_scope` REFUSES the
/// delta at adoption — `work_delta_out_of_scope` naming the probe's path —
/// performing but failing the stage. The refusal IS the read-only workspace:
/// under `oci` a `workspace = "ro"` stage's `/work` delta may never land.
///
/// The stage runs `sh -c <prompt>` inside the capsule. Total agent time should
/// land well under 1s; the wait gives generous slack for boot + dispatch
/// overhead. The post-terminal `get_stage_output` fallback is covered by
/// `workflow_execution.rs::get_stage_output_works_post_terminal` — this run's
/// stage never completes, so there is nothing to read back here.
#[kata_test_utils::kata_timeout(secs = 60)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_shell_workspace_ro_sub_second"]
async fn smoke_shell_workspace_ro_sub_second() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let node = spawn_shell_node();
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let exec = node
        .client()
        .run("sandbox-smoke-shell-workspace-ro")
        .await
        .expect("submit");
    let record = exec
        .wait_for_terminal(Duration::from_secs(15))
        .await
        .expect("wait for terminal");

    assert_eq!(
        record.status,
        ExecutionStatus::Failed,
        "the ro stage's `/work` delta must be adoption-refused — a `Completed` here \
         means `.kata-shell-ro-probe` was adopted, the regression the adoption refusal exists for; \
         got {:?} (error={:?}, outputs={:?})",
        record.status,
        record.error,
        record.outputs
    );
    let error = record.error.as_deref().unwrap_or_default();
    assert!(
        error.contains("work_delta_out_of_scope"),
        "the failure must be the delta-scope refusal BY NAME — a bare `Failed` \
         is also what a crashed worker or a broken capsule produces, and neither \
         proves the read-only posture held; got {error:?}"
    );
    assert!(
        error.contains(".kata-shell-ro-probe"),
        "the refusal must name the undeclared path it caught; got {error:?}"
    );

    node.shutdown().await.expect("clean shutdown");
}

// ---------------------------------------------------------------------------
// Native jj execution-workspace provider — shell-only live proof
// ---------------------------------------------------------------------------

/// Live smoke for the first-class jj execution workspace provider. Boots an installed main with a supervised node
/// with `[vcs] jj_repo` pointed at a temp jj repo,
/// submits a shell-only `worktree_isolated` workflow, and asserts the
/// execution-scoped workspace endpoint reports backend `jj` — the stage's
/// marker write having been ADOPTED into the candidate (the workspace reads
/// clean under `oci`). It then parks that candidate and verifies the marker
/// landed in the parked commit via the colocated `.git`,
/// proving the same live path snapshots the workspace into a durable jj
/// bookmark, records replayable parked-candidate evidence, and tears down the
/// execution worktree.
#[kata_test_utils::kata_timeout(secs = 60)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_shell_native_jj_workspace_provider"]
async fn smoke_shell_native_jj_workspace_provider_parks_dirty_candidate() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let jj_root = tempfile::tempdir().expect("jj root tempdir");
    let jj_repo = jj_root.path().join("jj-repo");
    let node = spawn_native_jj_node(&jj_repo);
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let star = r#"
probe = stage(
    id = "probe",
    agent = "shell",
    # This stage WRITES the candidate; the default view is read-only.
    sandbox = sandbox_profile(workspace = "rw"),
    prompt = """set -eu
mkdir -p .kata-smoke
printf 'native-jj-workspace-provider\n' > .kata-smoke/native-jj.txt
printf '{"marker_exists":true}\n'
""",
    outputs = {
        "marker_exists": "bool",
    },
)

workflow(
    "native-jj-workspace-provider-smoke",
    description = "Live shell-only proof for native jj execution workspace provider.",
    root = [probe],
    worktree_isolated = True,
)
"#;

    let exec = node
        .client()
        .run_starlark(star, Some("native-jj-workspace-provider-smoke.star"))
        .await
        .expect("submit");
    let record = exec
        .wait_for_terminal(Duration::from_secs(20))
        .await
        .expect("wait for terminal");

    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "expected completed, got {:?} (error={:?})",
        record.status,
        record.error
    );
    let probe = record
        .outputs
        .as_ref()
        .and_then(|o| o.get("probe"))
        .expect("probe output");
    assert_eq!(
        probe
            .get("parsed")
            .and_then(|parsed| parsed.get("marker_exists")),
        Some(&serde_json::Value::Bool(true)),
        "probe output must confirm the marker was written"
    );

    let workspace = node
        .client()
        .execution_workspace(exec.id())
        .await
        .expect("execution workspace snapshot");
    assert!(
        workspace.workspace_provider_attached,
        "native jj provider should be attached"
    );
    assert_eq!(
        workspace.workspace_provider_backend.as_deref(),
        Some("jj"),
        "execution workspace should report the jj backend"
    );
    let worktree = workspace
        .worktree
        .as_ref()
        .expect("execution worktree should be registered");
    assert!(worktree.exists, "execution worktree should exist");
    assert!(
        std::path::Path::new(&worktree.path).starts_with(&jj_repo),
        "worktree {} should live under temp jj repo {}",
        worktree.path,
        jj_repo.display()
    );
    // Under `oci` the capsule's `/work` write is ADOPTED — committed onto the
    // execution candidate by the `#apply` sweep — so the workspace reports
    // clean, not dirty: the marker is a committed record, not pending dirt.
    // Its landing on the candidate is verified on the parked commit below.
    assert_eq!(
        worktree.dirty,
        Some(false),
        "the marker write is adopted into the candidate, so the jj execution worktree reads clean"
    );

    let parked = node
        .client()
        .park(exec.id(), Some("native-jj-smoke"))
        .await
        .expect("park native jj candidate");
    assert_eq!(parked.status, "parked");
    assert_eq!(parked.parked_ref, "parked/native-jj-smoke");
    assert!(!parked.commit_sha.is_empty(), "parked commit must be set");

    // The adopted delta, read out of the parked commit through git — the jj
    // provider colocates `.git` at `jj_repo` when it opens the store, so the
    // marker's landing is measured on the repository, not kata's bookkeeping.
    assert_eq!(
        git_stdout(
            &jj_repo,
            &[
                "show",
                &format!("{}:.kata-smoke/native-jj.txt", parked.commit_sha)
            ]
        )
        .trim(),
        "native-jj-workspace-provider",
        "the adopted marker must be IN the parked candidate commit"
    );

    let record_after_park = node
        .client()
        .observe(exec.id())
        .await
        .expect("replayable execution record after park");
    assert_eq!(
        record_after_park.evidence.parked_candidate,
        Some(parked.clone()),
        "parked candidate evidence should replay from the execution record"
    );
    assert!(
        !record_after_park.evidence.auto_parked,
        "explicit operator park should not be marked as auto-parked"
    );

    let workspace_after_park = node
        .client()
        .execution_workspace(exec.id())
        .await
        .expect("execution workspace snapshot after park");
    assert!(
        workspace_after_park.workspace_provider_attached,
        "provider remains attached after parking"
    );
    assert_eq!(
        workspace_after_park.workspace_provider_backend.as_deref(),
        Some("jj")
    );
    assert!(
        workspace_after_park.worktree.is_none(),
        "parking should tear down the execution worktree"
    );
    assert!(workspace_after_park.parking.parked);
    assert_eq!(workspace_after_park.parking.status, "parked");
    assert_eq!(workspace_after_park.parking.candidate, Some(parked));

    node.shutdown().await.expect("clean shutdown");
}

// ---------------------------------------------------------------------------
// jj OP-LOG CONTENTION posture under N parallel workspaces
// ---------------------------------------------------------------------------

/// Manually-run smoke (`just jj-parallel-smoke`). Boots ONE installed main with a supervised node
/// with the native jj execution-workspace provider against a SINGLE shared jj repo, then submits N
/// file-producing shell workflows CONCURRENTLY. Each execution gets its own execution-scoped jj
/// workspace (`agents/<exec-id>`) sharing that repo's operation log, so the N submissions drive N
/// concurrent jj workspace create / snapshot / status operations against one shared op-log.
///
/// This is the read of jj's optimistic-concurrency op-log posture that the jj
/// default backend rests on: does jj absorb N concurrent workspace ops WITHOUT
/// corrupting or wedging the shared op-log? The smoke asserts the observable
/// proof — every one of the N executions reaches `Completed`, each stage wrote
/// and re-read its distinct marker file, and each execution's candidate carries
/// exactly its own marker content (under `oci` the capsule's write is ADOPTED
/// into the candidate commit — the workspace reads clean, and the landed marker
/// is verified on disk in the materialized checkout). A wedge shows up as a
/// `WaitTimeout`; a corruption shows up as a non-`Completed` status or a
/// wrong/missing marker.
///
/// N defaults to 6, overridable via `KATA_JJ_SMOKE_N` (clamped to 2..=16).
/// Shell agent only — no model, no Claude API cost. The stage is intentionally
/// non-isolated of models but IS jj-worktree-isolated (`worktree_isolated`).
#[kata_test_utils::kata_timeout(secs = 120)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just jj-parallel-smoke"]
async fn smoke_jj_parallel_workspaces_op_log_contention() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let n: usize = std::env::var("KATA_JJ_SMOKE_N")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(6)
        .clamp(2, 16);

    let jj_root = tempfile::tempdir().expect("jj root tempdir");
    let jj_repo = jj_root.path().join("jj-repo");
    // These concurrent mkdir/printf/test stages need no Rust toolchain or package
    // cache contents. Keep operator-home audits out of the op-log contention proof.
    let node = spawn_native_jj_node(&jj_repo);
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    // Submit all N workflows CONCURRENTLY: clone the client into N tasks so the
    // node fields the submissions in parallel and the provider drives N jj
    // workspace ops against the one shared op-log at once.
    let mut submit_tasks = Vec::with_capacity(n);
    for idx in 0..n {
        let client = node.client().clone();
        submit_tasks.push(tokio::spawn(async move {
            let marker = format!(".kata-smoke/parallel-{idx}.txt");
            let star = format!(
                r#"
probe = stage(
    id = "probe",
    agent = "shell",
    # This stage WRITES the candidate; the default view is read-only.
    sandbox = sandbox_profile(workspace = "rw"),
    prompt = """set -eu
mkdir -p .kata-smoke
printf 'jj-parallel-{idx}\n' > {marker}
test -f {marker}
printf '{{"marker_exists":true,"idx":{idx}}}\n'
""",
    outputs = {{
        "marker_exists": "bool",
        "idx": "int",
    }},
)

workflow(
    "jj-parallel-smoke-{idx}",
    description = "Parallel jj op-log contention probe.",
    root = [probe],
    worktree_isolated = True,
)
"#
            );
            let exec = client
                .run_starlark(&star, Some(&format!("jj-parallel-smoke-{idx}.star")))
                .await
                .unwrap_or_else(|err| panic!("submit {idx} failed: {err}"));
            let record = exec
                .wait_for_terminal(Duration::from_secs(90))
                .await
                .unwrap_or_else(|err| panic!("wait {idx} failed (op-log wedge?): {err}"));
            (idx, marker, exec.id().to_string(), record)
        }));
    }

    let mut results = Vec::with_capacity(n);
    for task in submit_tasks {
        results.push(task.await.expect("join submission task"));
    }

    // Every concurrent execution completed: the shared op-log absorbed N
    // concurrent workspace ops without wedging.
    for (idx, marker, exec_id, record) in &results {
        assert_eq!(
            record.status,
            ExecutionStatus::Completed,
            "execution {idx} ({exec_id}) must complete under op-log contention, \
             got {:?} (error={:?})",
            record.status,
            record.error
        );
        let parsed = record
            .outputs
            .as_ref()
            .and_then(|o| o.get("probe"))
            .and_then(|probe| probe.get("parsed"))
            .unwrap_or_else(|| panic!("execution {idx} missing probe.parsed output"));
        assert_eq!(
            parsed.get("marker_exists"),
            Some(&serde_json::Value::Bool(true)),
            "execution {idx} probe must confirm its marker was written",
        );
        assert_eq!(
            parsed.get("idx").and_then(serde_json::Value::as_u64),
            Some(*idx as u64),
            "execution {idx} probe must carry its own index (no cross-workspace bleed)",
        );

        // Under `oci` the capsule's write is ADOPTED — committed onto the
        // execution's candidate by the `#apply` sweep — so each jj workspace
        // reads CLEAN rather than dirty. The contention property is what the
        // sweep exercised: N concurrent workspace ops against one shared
        // op-log, each landing exactly its own marker on its own candidate —
        // measured on the workspace's recorded status, not a worktree scan.
        let workspace = node
            .client()
            .execution_workspace(exec_id)
            .await
            .unwrap_or_else(|err| panic!("execution {idx} workspace snapshot: {err}"));
        assert_eq!(
            workspace.workspace_provider_backend.as_deref(),
            Some("jj"),
            "execution {idx} must run on the jj backend",
        );
        let worktree = workspace
            .worktree
            .as_ref()
            .unwrap_or_else(|| panic!("execution {idx} worktree should be registered"));
        assert_eq!(
            worktree.dirty,
            Some(false),
            "execution {idx}'s marker write is adopted into its candidate — \
             committed, not worktree dirt",
        );
        // The marker DID land: `apply_work_delta`'s checkout materializes the
        // committed candidate into the workspace dir, so the file on disk IS
        // the adopted record — read there, not off kata's status fields.
        let marker_path = std::path::Path::new(&worktree.path).join(marker);
        assert_eq!(
            std::fs::read_to_string(&marker_path)
                .unwrap_or_else(|err| panic!(
                    "execution {idx} adopted marker must exist at {marker_path:?}: {err}"
                ))
                .trim(),
            &format!("jj-parallel-{idx}"),
            "execution {idx}'s candidate carries its own marker content",
        );
    }

    eprintln!(
        "jj-parallel-smoke: PASS — N={n} concurrent jj-backed execution workspaces \
         all reached Completed; shared op-log absorbed {n} concurrent workspace \
         create/snapshot/status ops with no wedge, no corruption, no cross-workspace bleed"
    );

    node.shutdown().await.expect("clean shutdown");
}

// ---------------------------------------------------------------------------
// 4e. Shell-stage offline DNS probe (sub-second, no LLM cost)
// ---------------------------------------------------------------------------

/// Live smoke for `workflows/smoke/sandbox-smoke-shell-offline.star`.
/// Boots an installed main with a supervised node, submits the shell-stage workflow, asserts the probe's
/// `dns_failed = true` output. The stage itself succeeds (exit 0,
/// valid JSON emitted); the failure being asserted is the *probe's*
/// observation that DNS is dead inside the offline capsule, not a stage
/// failure.
///
/// A SHELL capsule under `net = "offline"` is truly offline on every node.
/// `getent hosts` fails instantly in it. Total agent time well under 1s.
#[kata_test_utils::kata_timeout(secs = 60)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_shell_offline_dns_blocked"]
async fn smoke_shell_offline_dns_blocked() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let node = spawn_shell_node();
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let exec = node
        .client()
        .run("sandbox-smoke-shell-offline")
        .await
        .expect("submit");
    let record = exec
        .wait_for_terminal(Duration::from_secs(15))
        .await
        .expect("wait for terminal");

    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "shell stage must succeed; the assertion is on its parsed \
         output, not on stage failure (got {:?}, error={:?})",
        record.status,
        record.error
    );

    let probe = record
        .outputs
        .as_ref()
        .and_then(|o| o.get("probe"))
        .expect("probe output");
    let parsed = probe.get("parsed").expect("parsed JSON");

    assert_eq!(
        parsed.get("dns_failed"),
        Some(&serde_json::Value::Bool(true)),
        "DNS resolution must fail in an offline capsule"
    );
    let resolve_rc = parsed
        .get("resolve_rc")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    assert!(
        resolve_rc != 0,
        "resolve_rc must be non-zero on DNS failure, got {resolve_rc}"
    );

    node.shutdown().await.expect("clean shutdown");
}

// ---------------------------------------------------------------------------
// 4g. The DECLARED WRITE CLOSURE, enforced (shell, no LLM)
// ---------------------------------------------------------------------------

/// Live smoke for `workflows/smoke/sandbox-smoke-shell-write-closure.star` —
/// **the product-path proof that a declared `produces_files=` closure BOUNDS
/// what a stage may write.**
///
/// `smoke_shell_declared_read_closure_enforced` proves the READ half. This is
/// the WRITE half. Under `oci` the enforcement is
/// `Dispatcher::judge_work_delta_scope` — the durable answer, at delta
/// adoption.
///
/// # Why this smoke exists
///
/// A capability that is reachable but exercised by nothing is "documented
/// durable and constructed by nothing". The pack is the constructor; this is
/// the observer.
///
/// # What it asserts, and which half of the mechanism each one covers
///
/// * `eligible.marked = true` — the LOAD-TIME half. That stage authors
///   `cache_policy = "content_cache"`, and `kata_workflow`'s determinism
///   boundary (clause 4, `crates/program/src/execution_program/compile.rs`)
///   REFUSES a `content_cache` stage whose class is not
///   `is_content_cache_eligible`. A `workspace-rw` stage reaches eligibility
///   only through `Workspace::DeclaredOutputs`, which is minted only when the
///   stage declares a non-empty closure AND an enforcement answers for it — so
///   the pack SUBMITTING AT ALL is the assertion that the class derives
///   `DeclaredOutputs` and is content-cache eligible. Without the enforcement,
///   `just workflows-check sandbox-smoke-shell-write-closure` prints:
///
///   ```text
///   validation error: stage "eligible" sets cache_policy=content_cache
///   (content-addressed cache) but NOTHING BOUNDS ITS WRITE SET: ...
///   so the stage derives workspace=mutable_candidate ...
///   ```
///
/// * `fence` FAILS `work_delta_out_of_scope` — under `oci` the write closure
///   is judged at DELTA ADOPTION (`Dispatcher::judge_work_delta_scope`): the capsule's `/work` is
///   writable whole inside the container, both writes land there, and the judge refuses the ENTIRE
///   delta for the undeclared `undeclared.txt` — nothing is applied, the stage is
///   performed-but-failed, its `/out` not adopted. That is a STRONGER bound than a per-write
///   EACCES: the undeclared write not only never lands, it takes the declared sibling down with it,
///   atomically. The assertions are therefore on the stage's REFUSAL, not its parsed output — which
///   is also why the pack keeps no `set -e`: the refusal is durable and named, and needs nothing
///   from the stage's stdout.
///
/// # What it does NOT assert
///
/// That the refusal is the declared FILE's exact boundary. It is not: the
/// judge covers the EFFECTIVE closure (`produces_files`), so a sibling inside
/// `out/` would be in-scope; and the fence is post-hoc — the container's
/// `/work` sees the write happen, and the delta is refused at adoption. The
/// property this pins is the durable one: nothing outside the declared
/// closure reaches the run's tree, ever.
///
/// Model-free (`agent = "shell"`), no Claude API cost — it rides
/// `just smoke-no-budget`, which is the containment gate's product-path step,
/// via the unnarrowed `(binary(smokes) or binary(live_smoke))` include.
/// `eligible` SUCCEEDS on its declared write; `fence` must FAIL, and the
/// failure is the assertion — a green-looking `Completed` here means the
/// undeclared write was adopted, which is the regression this cell exists for.
#[kata_test_utils::kata_timeout(secs = 90)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_shell_declared_write_closure_enforced"]
async fn smoke_shell_declared_write_closure_enforced() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let node = spawn_shell_node();
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let exec = node
        .client()
        .run("sandbox-smoke-shell-write-closure")
        .await
        .expect("submit");
    let record = exec
        .wait_for_terminal(Duration::from_secs(30))
        .await
        .expect("wait for terminal");

    // THE RUNTIME HALF, FIRST — the terminal shape IS the assertion. Under
    // `oci` the write closure is judged at DELTA ADOPTION: `fence` wrote its
    // declared `out/artifact.txt` AND the undeclared `undeclared.txt` inside
    // the capsule's writable `/work`, and `judge_work_delta_scope` refused the
    // WHOLE delta `work_delta_out_of_scope` — the stage is performed but
    // failed, its /out is not adopted, and the run cannot complete.
    assert_eq!(
        record.status,
        ExecutionStatus::Failed,
        "the fence stage's undeclared write must fail the run at delta adoption \
         — a `Completed` here means `undeclared.txt` was adopted, the exact \
         regression this cell exists for; got {:?} (error={:?}, outputs={:?})",
        record.status,
        record.error,
        record.outputs
    );
    let error = record.error.as_deref().unwrap_or_default();
    assert!(
        error.contains("work_delta_out_of_scope"),
        "the failure must be the delta-scope refusal, BY NAME — a bare `Failed` \
         is also what a crashed worker or a prompt bug produces, and neither \
         proves the closure held; got {error:?}"
    );
    assert!(
        error.contains("undeclared.txt"),
        "the refusal must name the undeclared path it caught; got {error:?}"
    );

    // THE LOAD-TIME HALF. Reaching this line at all means the pack compiled,
    // which means clause 4 admitted a `content_cache` stage on a `workspace-rw`
    // sandbox — see the doc above for why that is exactly
    // `Workspace::DeclaredOutputs` + `is_content_cache_eligible`. `eligible`
    // completed BEFORE `fence`'s refusal, so its output is present on the
    // failed run — and `marked` is the positive arm: the DECLARED output was
    // writable inside the same capsule shape the fence got refused on, which
    // is what separates "the declared bound" from "a fence that denies
    // everything".
    let outputs = record.outputs.as_ref().expect("execution outputs");
    let eligible = outputs
        .get("eligible")
        .expect("the content-cache-eligible stage must have produced output");
    let eligible_parsed = eligible.get("parsed").expect("parsed JSON");
    assert_eq!(
        eligible_parsed.get("marked"),
        Some(&serde_json::Value::Bool(true)),
        "the content-cache-eligible stage must have written its declared output; \
         got {eligible_parsed:?}"
    );

    node.shutdown().await.expect("clean shutdown");
}

// ---------------------------------------------------------------------------
// 4h. The DECLARED READ CLOSURE, enforced (shell, no LLM)
// ---------------------------------------------------------------------------

/// Live smoke for `workflows/smoke/hermetic-build-closure.star` — **the
/// product-path proof that a declared `reads=` closure BOUNDS what a stage may
/// read.**
///
/// `smoke_shell_declared_write_closure_enforced` is the WRITE twin, and this is
/// modelled on it line for line. Both ride `just smoke-no-budget` — the
/// containment gate's product-path step — through its unnarrowed
/// `(binary(smokes) or binary(live_smoke))` include, so neither needs a filter
/// edit anywhere to be run by a required gate.
///
/// # Why the READ half needs its own smoke
///
/// A closure enforced only in rigs that spawn differently from production can
/// be unreachable through the shipped spawn path while every in-process test
/// stays green: a witness that SUBTRACTS a production flag cannot see a defect
/// in where the production flag is placed. Each closure therefore has its own
/// product-path witness.
///
/// # What it asserts, and which half of the mechanism each one covers
///
/// * `seed.undeclared_seeded = true`, `build.undeclared_present = false` — the
///   PREMISE, asserted from both ends of the edge. The undeclared file is
///   really written, and under `oci` it is really ABSENT from the fenced
///   stage's materialized view — the `reads=` closure is the set of paths
///   bound into the capsule's `/work`, so the undeclared file is not
///   stat-visible at all — a stronger answer than a Landlock bound, which
///   does not confine `stat(2)`; the `seed`-side row is what makes the `false` a closure answer
///   rather than an empty workspace.
/// * `build.declared_read_ok = true` / `declared_rc = 0` /
///   `declared_inputs_read = 2` — the DECLARED reads SUCCEED. Without this the
///   smoke would pass on a view that mounts nothing, which is a bound but
///   not the DECLARED bound, and a green here is what tells the two apart.
/// * `build.undeclared_rc != 0` / `undeclared_empty = true` — an UNDECLARED
///   in-tree read FAILS and yields no bytes. This is the enforcement
///   assertion.
/// * `build.artifact_digest != ""` — the pack's own headline row: the build
///   action's artifact is the digest on stdout, and a declared environment
///   that cannot run the `cksum | cut` pipeline would report it empty. Inside
///   the capsule `PATH` resolves only through the declared environment's
///   `path_prepend`, so a tool that environment lacks does not resolve.
///
/// # No runtime claim to report
///
/// Under `oci` there is no runtime enforcement claim — the declared `reads=` ARE the materialized
/// view (a path outside the set is simply not bound into the capsule's
/// `/work`), and the capsule identity covers the mount set itself, so no
/// cache disposition hangs on a stage's own report. What this smoke still
/// asserts is the product-path half the capsule cannot fake: the seeded file
/// is durable, the declared reads resolve, and the undeclared path is absent.
///
/// # What this smoke does NOT prove
///
/// * **Not that the bound is exactly the declared PATHS.** The `reads=`
///   view is subtree-shaped: `reads = ["src", ...]` mounts the whole `src`
///   SUBTREE, so a sibling inside `src/` is readable. The declaration is a
///   bound on the read set, not a spelling of it.
/// * **Nothing about metadata confinement** — under `oci` the answer is
///   stronger: `undeclared_present = false` records that the fenced stage
///   cannot even `stat` the undeclared file, because it is never bound into
///   the materialized view.
///
/// Model-free (`agent = "shell"`), no Claude API cost. Both stages SUCCEED; the
/// assertions are on the parsed output, NOT on stage failure.
#[kata_test_utils::kata_timeout(secs = 90)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_shell_declared_read_closure_enforced"]
async fn smoke_shell_declared_read_closure_enforced() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let node = spawn_shell_node();
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let exec = node
        .client()
        .run("hermetic-build-closure")
        .await
        .expect("submit");
    let record = exec
        .wait_for_terminal(Duration::from_secs(60))
        .await
        .expect("wait for terminal");

    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "both stages must succeed; the assertions are on their parsed output, \
         not on stage failure (got {:?}, error={:?}, outputs={:?})",
        record.status,
        record.error,
        record.outputs
    );

    let outputs = record.outputs.as_ref().expect("execution outputs");
    let seed = outputs.get("seed").expect("seed stage output");
    let build = outputs.get("build").expect("build stage output");
    let seed_parsed = seed.get("parsed").expect("seed parsed JSON");
    let parsed = build.get("parsed").expect("build parsed JSON");

    // THE PREMISE, from the seeder's end.
    assert_eq!(
        seed_parsed.get("undeclared_seeded"),
        Some(&serde_json::Value::Bool(true)),
        "`/workspace/secret.txt` must really exist before the fenced stage tries \
         to read it — otherwise the refusal below is an ENOENT and proves \
         nothing about the closure; got {seed_parsed:?}"
    );
    assert_eq!(
        seed_parsed
            .get("src_files")
            .and_then(serde_json::Value::as_i64),
        Some(2),
        "the seeder must lay down both declared source files; got {seed_parsed:?}"
    );

    // THE PREMISE, from the fenced stage's end. Under `oci` the `reads=`
    // closure is the capsule's MATERIALIZED VIEW: only the declared paths are
    // bound into `/work`, so the undeclared file is not merely unreadable — it
    // is ABSENT, which is a strictly stronger answer than a stat-visible
    // EACCES. `undeclared_rc != 0` below is then an ENOENT by
    // construction; what the `false` still proves is that the seed's write is
    // genuinely outside the declared view (the `seed.undeclared_seeded`
    // premise above is what makes that a closure answer and not an empty
    // workspace).
    assert_eq!(
        parsed.get("undeclared_present"),
        Some(&serde_json::Value::Bool(false)),
        "the undeclared file must be ABSENT from the capsule's materialized \
         view — `true` would mean `reads=` leaked a path outside the declared \
         closure; got {parsed:?}"
    );

    // THE DECLARED HALF. A fence that denies everything is a bound, but it is
    // not the DECLARED bound, and a green here is what tells the two apart.
    assert_eq!(
        parsed.get("declared_read_ok"),
        Some(&serde_json::Value::Bool(true)),
        "a DECLARED read (`/workspace/src/lib.txt`) must SUCCEED; got {parsed:?}"
    );
    assert_eq!(
        parsed
            .get("declared_rc")
            .and_then(serde_json::Value::as_i64),
        Some(0),
        "and it must not merely return bytes — it must succeed; got {parsed:?}"
    );
    assert_eq!(
        parsed
            .get("declared_inputs_read")
            .and_then(serde_json::Value::as_i64),
        Some(2),
        "the closure grants the `src` SUBTREE, so listing it inside the fence \
         must see both declared source files; got {parsed:?}"
    );

    // THE ENFORCEMENT HALF.
    let undeclared_rc = parsed
        .get("undeclared_rc")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    assert!(
        undeclared_rc != 0,
        "an UNDECLARED in-tree read (`/workspace/secret.txt`) must FAIL: the \
         resolved closure grants `src` and `build.config` and nothing else, so \
         no rule in the Landlock domain covers the tree root. rc=0 means the \
         read fence did not install and this stage read whatever it liked while \
         the main narrowed its content-cache key to the declaration; got \
         {parsed:?}"
    );
    assert_eq!(
        parsed.get("undeclared_empty"),
        Some(&serde_json::Value::Bool(true)),
        "and the undeclared read must yield NO BYTES — a non-zero rc with \
         content captured would mean the read partially landed, which is the \
         same unsound narrowing by a slower route; got {parsed:?}"
    );

    // No confinement bit is reported: the declared paths are THE materialized
    // view, and `undeclared_present` + `undeclared_rc` above are the direct
    // observation of it. The build-vs-seed contrast — `build`'s view lacks
    // `secret.txt` while `seed`'s rw view wrote it — is carried by the parsed
    // rows.

    // THE PACK'S OWN HEADLINE ROW. The build action's artifact is the digest
    // on stdout; the acceptance contract says `artifact_digest != ""`, so an
    // environment that cannot run the pipeline fails here rather than shipping
    // an empty artifact.
    let digest = parsed
        .get("artifact_digest")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert!(
        !digest.is_empty(),
        "the hermetic build action's ARTIFACT is the digest on stdout, so an \
         empty one means the pack produced nothing while reporting success; \
         got {parsed:?}"
    );
    node.shutdown().await.expect("clean shutdown");
}

// ---------------------------------------------------------------------------
// Telemetry — /metrics endpoint reflects workflow run
// ---------------------------------------------------------------------------

/// Live smoke for observability. Boots an installed main with a supervised node with
/// `telemetry.export = "prometheus"` on an ephemeral port, runs the
/// shell-workspace-ro probe (zero LLM cost), then curls `/metrics`
/// and asserts that the starter metrics are present and coherent
/// with the run that just happened.
///
/// Covers end-to-end: `[telemetry]` parsing → `init_telemetry`'s
/// Prometheus exporter install → per-site metric emissions →
/// `metrics-exporter-prometheus` HTTP endpoint → client scrape.
#[kata_test_utils::kata_timeout(secs = 60)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_metrics_endpoint_reflects_workflow_run"]
async fn smoke_metrics_endpoint_reflects_workflow_run() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    use kata_test_utils::live::TelemetrySpec;

    // The Prometheus port, held until the smoke returns, after `node` below is
    // gone: the main binds it, and no other process's `:0` bind is handed it,
    // so the scrape reaches this main's listener or nothing.
    let metrics_port = HeldPort::new().expect("metrics port");
    let metrics_socket = metrics_port.addr();

    let spec = TelemetrySpec {
        export: "prometheus".into(),
        metrics_bind: metrics_socket,
        otlp_endpoint: String::new(),
    };

    let node = NodeHandle::spawn_supervised_main_with_telemetry(spec, Vec::new())
        .expect("spawn installed main w/ telemetry");
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    let exec = node
        .client()
        // A COMPLETING pack — the smoke's assertion is the metrics, not the
        // outcome. (`sandbox-smoke-shell-workspace-ro` is adoption-refused
        // under `oci` by design — `work_delta_out_of_scope` — and would
        // starve the success counter this cell reads.)
        .run("sandbox-smoke-shell-offline")
        .await
        .expect("submit");
    let record = exec
        .wait_for_terminal(Duration::from_secs(15))
        .await
        .expect("wait for terminal");

    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "workflow must complete; assertion is on emitted metrics, \
         not workflow outcome (got {:?}, error={:?})",
        record.status,
        record.error
    );

    // Scrape /metrics. The Prometheus exporter binds eagerly during
    // init_telemetry, so a short retry is only needed to ride out
    // the kata subprocess's own startup + batch-metric flush.
    let metrics_url = format!("http://{metrics_socket}/metrics");
    let client = kata_client::KataClient::http_builder()
        .build()
        .expect("metrics http client");
    let mut body = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Ok(resp) = client.get(&metrics_url).send().await
            && resp.status().is_success()
        {
            body = resp.text().await.expect("metrics body");
            if body.contains("kata_workflow_executions_total")
                && body.contains("kata_workflow_stages_total")
            {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        !body.is_empty(),
        "no response from {metrics_url} within the timeout",
    );

    // Gate: every starter metric must appear in the exposition. We don't
    // pin exact values (the workers_connected gauge can be 0, 1, or
    // 2 depending on whether the supervised node has re-registered
    // across the tiny race window — the shape is what matters here).
    for required in [
        "kata_workflow_executions_total",
        "kata_workflow_stages_total",
        "kata_workflow_duration_seconds",
        "kata_worker_dispatch_duration_seconds",
        "kata_workers_connected",
    ] {
        assert!(
            body.contains(required),
            "/metrics missing `{required}`; scrape body:\n{body}",
        );
    }

    // Tighter: after a success run, the success counter must be at
    // least 1.
    let success_line = body
        .lines()
        .find(|l| {
            l.starts_with("kata_workflow_executions_total") && l.contains("status=\"success\"")
        })
        .unwrap_or_else(|| panic!("missing success line in /metrics:\n{body}"));
    let count: u64 = success_line
        .split_whitespace()
        .last()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert!(
        count >= 1,
        "executions_total{{status=success}} should be >= 1, got {count} (line: {success_line})",
    );

    // The transport-labeled metrics must carry a `transport="local_socket"`
    // label for the supervised node, which dials the main's own socket.
    assert!(
        body.lines()
            .any(|l| l.starts_with("kata_workers_connected")
                && l.contains("transport=\"local_socket\"")),
        "kata_workers_connected is missing its transport label:\n{body}",
    );

    // The overview dashboard's five latency panels query
    // `histogram_quantile(rate(kata_*_seconds_bucket[..]))`. Those panels are
    // empty unless the exporter renders the `*_seconds` duration families as
    // true Prometheus HISTOGRAMS (emitting `_bucket` series), not the default
    // SUMMARY. `init_telemetry` configures duration buckets, so after a run
    // that dispatched a stage the dispatch-latency family MUST expose buckets.
    assert!(
        body.contains("kata_worker_dispatch_to_start_seconds_bucket"),
        "/metrics has no `_bucket` series for kata_worker_dispatch_to_start_seconds — \
         the exporter is rendering summaries, so the dashboard's histogram_quantile \
         latency panels are empty. scrape body:\n{body}",
    );
    assert!(
        body.lines()
            .any(|l| l == "# TYPE kata_worker_dispatch_to_start_seconds histogram"),
        "kata_worker_dispatch_to_start_seconds must be TYPE histogram (not summary):\n{body}",
    );
    // The whole-workflow duration family rides the same bucket config.
    assert!(
        body.contains("kata_workflow_duration_seconds_bucket"),
        "/metrics has no `_bucket` series for kata_workflow_duration_seconds:\n{body}",
    );

    node.shutdown().await.expect("clean shutdown");
}

// ---------------------------------------------------------------------------
// Crash-safety matrix — real-process tier (opt-in)
// ---------------------------------------------------------------------------

/// Poll the harness-captured `kata.log` for `needle`, returning true once it appears.
/// Deterministic crash detection for the fault-injection smoke: the daemon
/// prints `[kata-fault-inject] crash point reached: ...` to stderr (captured
/// into kata.log) the instant before it `abort()`s, so observing the line is
/// proof the crash fired at the intended boundary — no timing/sleep race.
async fn wait_for_log_line(log_path: &Path, needle: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(log_path)
            && s.contains(needle)
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Crash-safety proof, real-process tier: prove that kata recovers from a
/// real mid-run process crash at the persist-before-broadcast boundary, against
/// real binaries — not a drop+reopen simulation.
///
/// Boundary covered: **crash AFTER the stage's `Completed` durably persists,
/// BEFORE the accepting handler returns** (`KATA_FAULT_INJECT=operational.after_accept_event`).
///
/// Flow:
///   1. Boot an installed main with a supervised node and durable SQLite state,
///      armed with the
///      env-gated crash point. Submit a single shell stage whose observable
///      side effect is `echo applied >> marker` (a durable file in the test's
///      tempdir, so a double-apply would be directly visible as a second line)
///      plus a `{"applied":true}` structured output.
///   2. The supervised node runs the side effect, reports completion, and the
///      main atomically accepts the typed completion and effect outcome. The
///      fault point fires after that operational transaction commits, before
///      handler return — `std::process::abort()` (SIGABRT, no Drop /
///      flush) crashes the daemon. This is deterministic: the crash is keyed to
///      accepted input, not to a timer.
///   3. Restart the installed main against the SAME data_dir (no crash env).
///   4. Assert recovery: the execution reads `Completed` (reconstructed from the
///      operational chain via WAL replay), and the marker file has EXACTLY ONE line
///      — the terminal latch kept the stage completed, so it was never
///      re-dispatched and the side effect was never double-applied.
///
/// This is NOT in the default gate: it is `#[ignore]` + `KATA_LIVE_SMOKE`-gated
/// and spawns release binaries. Run via
/// `KATA_LIVE_SMOKE=1 just smoke smoke_crash_recovery_after_persist_latches_no_reapply`.
/// It tears down both daemons (the first is already dead from the abort; the
/// second via `shutdown()`), leaving no zombies.
#[kata_test_utils::kata_timeout(secs = 120)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_crash_recovery_after_persist_latches_no_reapply"]
async fn smoke_crash_recovery_after_persist_latches_no_reapply() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    // Outer tempdir owns cleanup. Both boots borrow its data_dir, so boot 2
    // reopens the same on-disk SQLite ledger boot 1 wrote into.
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("node");
    std::fs::create_dir_all(&data_dir).expect("create data_dir");

    // Single confined shell stage: append one line to `/work` — the durable
    // head under `oci`, whose adoption the delta-scope judge owns — then emit
    // the structured output on stdout. A crash-induced re-run would mint a
    // SECOND attempt: observable in `attempt_projection`, the durable answer
    // the assertions below read raw.
    let workflow_star = r#"
apply = stage(
    id = "apply",
    agent = "shell",
    sandbox = "iso",
    prompt = "echo applied >> /work/marker.txt; echo '{\"applied\":true}'",
    outputs = {
        "applied": "bool",
    },
)

workflow(
    "crash-recovery-side-effect",
    description = "Single confined shell stage with an observable append side effect for the crash-recovery smoke.",
    root = [apply],
    sandbox_profiles = {
        "iso": sandbox_profile(workspace = "rw", net = "offline"),
    },
)
"#;

    // === Boot 1: durable installed main, armed with the deterministic crash point. ===
    let boot1 = NodeHandle::spawn_supervised_main_with_data_dir_and_env(
        data_dir.clone(),
        vec![(
            "KATA_FAULT_INJECT".to_string(),
            "operational.after_accept_event".to_string(),
        )],
    )
    .expect("spawn durable installed main (boot 1)");
    boot1
        .await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy boot 1");

    let exec = boot1
        .client()
        .run_starlark(workflow_star, Some("crash-recovery-side-effect.star"))
        .await
        .expect("submit crash-recovery workflow");
    let exec_id = exec.id().to_string();

    // The crash is deterministic: wait for the fault-point marker in the log.
    let log_path = boot1.log_path();
    let crashed = wait_for_log_line(
        &log_path,
        "[kata-fault-inject] crash point reached",
        Duration::from_secs(45),
    )
    .await;
    assert!(
        crashed,
        "daemon did not hit operational.after_accept_event within 45s; log:\n{}",
        std::fs::read_to_string(&log_path).unwrap_or_default()
    );

    // The capsule ran exactly once on boot 1 — its completion was accepted
    // before the crash point. The durable proof is one minted attempt, read
    // raw below; there is no host-side file to count under `oci`.

    // Reap the (already-aborted) boot-1 daemon. `shutdown()` sees the dead
    // child via try_wait and returns cleanly — this also releases the SQLite
    // file locks before boot 2 reopens the ledger.
    boot1.shutdown().await.expect("reap crashed boot 1");

    // Independent storage oracle before any restart reader can repair or project.
    let raw = rusqlite::Connection::open_with_flags(
        data_dir.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("read crashed operational authority");
    let execution = exec_id.parse::<ulid::Ulid>().expect("execution identity");
    let accepted: i64 = raw.query_row(
        "SELECT count(*) FROM event_inbox WHERE execution_id=?1 AND accepted=1 AND json_extract(payload_json,'$.kind')='worker_completion'",
        [execution.to_bytes().as_slice()], |row| row.get(0),
    ).unwrap();
    assert_eq!(
        accepted, 1,
        "K7 must follow durable typed completion acceptance"
    );
    let completed: i64 = raw
        .query_row(
            "SELECT count(*) FROM attempt_projection WHERE execution_id=?1 AND state='completed'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        completed, 1,
        "completion projection commits with acceptance"
    );
    // Under `oci` the stage's durable side effect is the ADOPTED `/work` delta:
    // the committed fact is the stage's
    // OCCURRENCE naming its accepted attempt (the adoption transaction bound
    // it before `after_accept_event` fired).
    let adopted: i64 = raw
        .query_row(
            "SELECT count(*) FROM occurrences o
               JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
              WHERE o.execution_id=?1 AND a.stage_id='apply'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        adopted, 1,
        "the delta's adoption — the occurrence naming its accepted attempt — \
         commits before the crash boundary"
    );
    drop(raw);

    // === Boot 2: same data_dir, no crash env. Recover. ===
    let boot2 =
        NodeHandle::spawn_supervised_main_with_data_dir_and_env(data_dir.clone(), Vec::new())
            .expect("spawn durable installed main (boot 2)");
    boot2
        .await_healthy(Duration::from_secs(30))
        .await
        .unwrap_or_else(|error| {
            panic!(
                "await healthy boot 2: {error:?}; main log tail:\n{}",
                log_tail(&std::fs::read_to_string(boot2.log_path()).unwrap_or_default())
            )
        });

    let record = boot2
        .client()
        .observe(&exec_id)
        .await
        .expect("observe after restart");
    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "the durably-persisted Completed must survive a real crash + reboot \
         (WAL replay), got {:?} error={:?}",
        record.status,
        record.error
    );

    // The terminal latch kept the stage completed across the crash: recovery
    // did NOT re-dispatch it — the durable proof is that the execution still
    // holds exactly ONE attempt for THE STAGE, read out of the same ledger.
    // (The `#apply/apply` work-apply occurrence mints its own projection row —
    // the predicate names the stage, so it cannot miscount that bookkeeping.)
    let raw_after = rusqlite::Connection::open_with_flags(
        data_dir.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("read operational authority after restart");
    let attempt_count: i64 = raw_after
        .query_row(
            "SELECT count(*) FROM attempt_projection WHERE execution_id=?1 AND stage_id='apply'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        attempt_count, 1,
        "crash-after-persist recovery must NOT mint a second attempt; \
         the projection must still hold exactly one (no double-apply)"
    );

    boot2.shutdown().await.expect("clean shutdown boot 2");
}

// ---------------------------------------------------------------------------
// A CONTAINED stage reads REAL git history through the product path
// ---------------------------------------------------------------------------

/// Build a real git repository with two commits at `root`, and return the
/// subject line of `HEAD`. A plain git repository: the jj provider ADOPTS its
/// `.git` as its store at open, so the fixture's history is what the capsule's
/// git view carries.
fn init_git_repo_with_history(root: &Path) -> String {
    // `hermetic_git` rather than a bare `Command::new("git")`: this fixture must
    // not inherit the operator's git configuration. See `kata_test_utils::git`
    // for the settings and why each is there.
    let run = |args: &[&str]| {
        let out = kata_test_utils::git::hermetic_git()
            .args(args)
            .current_dir(root)
            .output()
            .unwrap_or_else(|e| panic!("spawn git {args:?}: {e}"));
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let head_subject = "second commit: extend tracked.txt";
    run(&["init", "-q", "-b", "main", "."]);
    // Repo-LOCAL too: the CONTAINED stage runs a real `git` against this repo
    // inside the wrap — a child we do not spawn, so it never sees our `-c`
    // prefix and can only read the settings out of the repo itself.
    kata_test_utils::git::write_hermetic_config(root);
    std::fs::write(root.join("tracked.txt"), "one\n").expect("write tracked.txt");
    run(&["add", "tracked.txt"]);
    run(&["commit", "-q", "-m", "first commit: add tracked.txt"]);
    std::fs::write(root.join("tracked.txt"), "one\ntwo\n").expect("extend tracked.txt");
    run(&["add", "tracked.txt"]);
    run(&["commit", "-q", "-m", head_subject]);
    head_subject.to_string()
}

/// The host repository's `HEAD`, read outside the sandbox.
fn host_head(root: &Path) -> String {
    let out = kata_test_utils::git::hermetic_git()
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .expect("rev-parse HEAD");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// **The live acceptance proof that a contained shell stage reads the run's
/// real git history on its disposable view — through the product path.**
///
/// Boots a real installed main on the jj execution-workspace provider against a
/// real repository with real commits, submits a workflow whose
/// stage declares `requires = ["git"]`, and asserts the capsule's `/work`
/// carried the run's git view: the repository's actual history, committed-to
/// on a scratch branch, with the host's checkout provably untouched.
///
/// `agent = "shell"`, so it costs no model/API budget and the agent runs it
/// rather than deferring it.
///
/// # Why no assertion here can be satisfied by observing nothing
///
/// * `toplevel` must be `/work` — the capsule's own view — so the work tree
///   git reports is the run's candidate, never the host's checkout.
/// * `head_subject` and `parent_subject` are the fixture's own commit messages,
///   and reaching the parent needs the carried OBJECT DATABASE, not just a ref.
/// * `stat_names_file` asks `git show --stat` for the changed filename — the
///   diff shape this pack class exists to read.
/// * `commit_ok` is the git view's boundary measured rather than assumed: the view is a
///   scratch the stage MAY commit on, and `host_head` outside the capsule is
///   compared before and after — a scratch commit that escaped would move
///   nothing there anyway.
///
#[kata_test_utils::kata_timeout(secs = 120)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_shell_contained_stage_reads_git_history"]
async fn smoke_shell_contained_stage_reads_git_history() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let repo_root = tempfile::tempdir().expect("repo tempdir");
    let head_subject = init_git_repo_with_history(repo_root.path());
    let head_before = host_head(repo_root.path());

    // `contained` authors `net = "host"`: the node's `egress_allow` declares
    // a never-dialed authority so the stage's union is non-empty.
    // A worktree-isolated execution is served by the jj provider, which
    // ADOPTS this plain git repo's `.git` as its store at open, so the
    // fixture's history is unchanged. `requires = ["git"]` on the stage's
    // profile is what still carries the disposable git view into the capsule.
    let node =
        NodeHandle::spawn_supervised_main_with_options(kata_test_utils::live::NodeConfigOptions {
            vcs: Some(kata_test_utils::live::VcsSpec::native_jj(
                repo_root.path().to_path_buf(),
            )),
            egress_allow: vec![NEVER_DIALED_EGRESS_AUTHORITY.to_string()],
            ..kata_test_utils::live::NodeConfigOptions::default()
        })
        .expect("spawn installed main on the jj backend");
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    // `net = "host"` is load-bearing rather than lazy: with `net = "offline"`
    // this deterministic shell stage would derive CONTENT-CACHE ELIGIBLE, and a
    // content-cacheable directive is refused the grant — its result is keyed as
    // a function of its declared inputs, which a repository is not. The rule is
    // "a stage may read git history, or have its result reused, never both".
    // `requires = ["git"]` is what carries the run's disposable GIT VIEW to
    // the capsule's `/work`: the run's own history to its
    // base commit, a scratch the stage may commit on, never the host's
    // checkout. Without it the capsule has no repository at all.
    let star = r#"
probe = stage(
    id = "probe",
    agent = "shell",
    sandbox = "contained",
    prompt = """set -u
# `tr` collapses newlines: git's failure text is MULTI-LINE, and a raw
# interpolation of it produces invalid JSON — which would make the
# without-the-bind counterfactual fail as a parse error instead of reporting
# the diagnostic that says WHY.
one_line() { tr '\n\r"' '   ' | sed 's/  */ /g;s/ *$//'; }
toplevel=$(git rev-parse --show-toplevel 2>&1 | one_line)
head_subject=$(git log -1 --pretty=%s 2>&1 | one_line)
parent_subject=$(git log -1 --pretty=%s HEAD~1 2>&1 | one_line)
stat_names_file=false
git show --stat --pretty=format: HEAD 2>/dev/null | grep -q tracked.txt && stat_names_file=true

# The git view is a scratch the stage MAY commit on — a commit succeeding
# here proves the view is writable; the host-repo HEAD check outside the
# capsule proves nothing of it escapes.
commit_ok=false
git -c user.email=p@invalid -c user.name=p commit --allow-empty -m scratch >/dev/null 2>&1 && commit_ok=true

printf '{"toplevel":"%s","head_subject":"%s","parent_subject":"%s","stat_names_file":%s,"commit_ok":%s}\n' \
  "$toplevel" "$head_subject" "$parent_subject" "$stat_names_file" "$commit_ok"
""",
    outputs = {
        "toplevel": "string",
        "head_subject": "string",
        "parent_subject": "string",
        "stat_names_file": "bool",
        "commit_ok": "bool",
    },
)

workflow(
    "git-history-grant-smoke",
    description = "Live proof: a contained stage reads the run's real git history on its disposable view.",
    root = [probe],
    worktree_isolated = True,
    sandbox_profiles = {
        "contained": sandbox_profile(workspace = "rw", net = "host", requires = ["git"]),
    },
)
"#;

    let exec = node
        .client()
        .run_starlark(star, Some("git-history-grant-smoke.star"))
        .await
        .expect("submit");
    let record = exec
        .wait_for_terminal(Duration::from_secs(60))
        .await
        .expect("wait for terminal");
    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "expected completed, got {:?} (error={:?})",
        record.status,
        record.error
    );

    let parsed = record
        .outputs
        .as_ref()
        .and_then(|o| o.get("probe"))
        .and_then(|p| p.get("parsed"))
        .cloned()
        .expect("probe parsed output");

    assert_eq!(
        parsed.get("toplevel").and_then(serde_json::Value::as_str),
        Some("/work"),
        "the work tree must be the capsule's `/work` git view — the CANDIDATE, \
         not the parent repo — the distinction that makes `git status`/`git diff` \
         answer about what this execution is editing. full={parsed:?}"
    );
    assert_eq!(
        parsed
            .get("head_subject")
            .and_then(serde_json::Value::as_str),
        Some(head_subject.as_str()),
        "the stage must read the repository's REAL HEAD commit message. full={parsed:?}"
    );
    assert_eq!(
        parsed
            .get("parent_subject")
            .and_then(serde_json::Value::as_str),
        Some("first commit: add tracked.txt"),
        "reaching HEAD~1 needs the shared OBJECT DATABASE, not just a ref file. full={parsed:?}"
    );
    assert_eq!(
        parsed.get("stat_names_file"),
        Some(&serde_json::Value::Bool(true)),
        "`git show --stat HEAD` must name the changed file — the diff this pack class exists \
         to read. full={parsed:?}"
    );
    assert_eq!(
        parsed.get("commit_ok"),
        Some(&serde_json::Value::Bool(true)),
        "the disposable git view is a scratch the stage may commit on — \
         a refused commit here means the view is not the capsule's own. \
         full={parsed:?}"
    );

    assert_eq!(
        host_head(repo_root.path()),
        head_before,
        "the host repository's HEAD must not have moved — the refusal messages are evidence, \
         an unchanged ref is proof"
    );

    node.shutdown().await.expect("clean shutdown");
}

// ---------------------------------------------------------------------------
// THE $0 COMPOSITION SMOKE — gold-loop-nobudget-smoke
// ---------------------------------------------------------------------------
//
// A composition of stage kinds can be broken under a green suite whenever no
// test composes stage KINDS and then observes state OUTSIDE kata's own
// database. The pack that composes them (`workflows/examples/gold-loop.star`)
// rides no required gate because its `implement` stage bills a real provider.
//
// This is that pack's $0 twin, driven from a `#[test]` rather than a recipe
// because the gate's selector — `(binary(smokes) or binary(live_smoke))` minus
// two names — can only ever reach a test function inside these two binaries.
//
// ── THE ORACLE DISCIPLINE ───────────────────────────────────────────
//
// **The oracle does not share an implementation with the thing under test.**
// Every defect in this class has had the shape "kata's own records say it
// worked", so every assertion below is made with **git** against the fixture
// repository on disk — `git rev-parse`, `git show`, `git diff`, `git ls-tree` —
// or by `scripts/materialize-gold-fixture.sh --verify-landed`, which runs the
// FIXTURE's own suite on the landed tree. `kata_client` is used to DRIVE the
// run and to read the two effect envelopes whose CLAIMS are then checked
// against the repository; it is never the authority on what happened.
//
// Each assertion names the failure it would trip on. An assertion nobody can
// point a failure at does not belong here.

/// The workspace root (`crates/test-utils` is two levels below it).
fn kata_repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root is two levels above crates/test-utils")
        .to_path_buf()
}

/// `git -C <repo> <args…>` under [`kata_test_utils::git`]'s hermetic prefix.
///
/// Hermetic because the ORACLE must not inherit the operator's git
/// configuration either: an `includeIf`-scoped `user.email` or a global
/// `core.hooksPath` changes what these commands answer.
fn fixture_git(repo: &Path, args: &[&str]) -> std::process::Output {
    kata_test_utils::git::hermetic_git()
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn git {args:?} in {}: {e}", repo.display()))
}

/// Trimmed stdout of a git invocation that must succeed.
fn git_stdout(repo: &Path, args: &[&str]) -> String {
    let out = fixture_git(repo, args);
    assert!(
        out.status.success(),
        "git {args:?} failed in {}: {}",
        repo.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// RAW stdout bytes of a git invocation that must succeed — `git show
/// <rev>:<path>` is a blob and trimming it would compare something the
/// repository does not contain.
fn git_bytes(repo: &Path, args: &[&str]) -> Vec<u8> {
    let out = fixture_git(repo, args);
    assert!(
        out.status.success(),
        "git {args:?} failed in {}: {}",
        repo.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// The commit `rev` resolves to, or `None` when the repository does not have it.
fn git_resolve(repo: &Path, rev: &str) -> Option<String> {
    let out = fixture_git(
        repo,
        &["rev-parse", "--verify", &format!("{rev}^{{commit}}")],
    );
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Extract a commit's tree into a fresh directory and run the fixture's own
/// `sh tests/check.sh` there, returning `(exit code, last stdout line)`.
///
/// READ FROM THE COMMIT, NOT THE CHECKOUT: moving a ref does not update a
/// working tree, so running the suite in the repository would test whatever was
/// checked out when the run started and report green or red for reasons
/// unrelated to what landed.
fn fixture_suite_at(repo: &Path, commit: &str) -> (i32, String) {
    let work = tempfile::tempdir().expect("suite tempdir");
    let archive = fixture_git(repo, &["archive", "--format=tar", commit]);
    assert!(
        archive.status.success(),
        "git archive {commit} failed: {}",
        String::from_utf8_lossy(&archive.stderr)
    );
    let tar_path = work.path().join("tree.tar");
    std::fs::write(&tar_path, &archive.stdout).expect("write tree.tar");
    let tree = work.path().join("tree");
    std::fs::create_dir_all(&tree).expect("mkdir tree");
    let untar = Command::new("tar")
        .arg("-xf")
        .arg(&tar_path)
        .arg("-C")
        .arg(&tree)
        .output()
        .expect("spawn tar");
    assert!(
        untar.status.success(),
        "tar -xf failed: {}",
        String::from_utf8_lossy(&untar.stderr)
    );
    let out = Command::new("sh")
        .arg("tests/check.sh")
        .current_dir(&tree)
        .output()
        .expect("spawn sh tests/check.sh");
    let verdict = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next_back()
        .unwrap_or_default()
        .to_owned();
    (out.status.code().unwrap_or(-1), verdict)
}

/// The recorded envelope of a `workspace_effect` stage, decoded from the
/// execution record.
///
/// A `workspace_effect` stage declares no `produces=`/`outputs=`, so its value
/// is the effect's raw `.content` string rather than a `parsed` object.
fn effect_envelope(record: &kata_client::types::ExecutionRecord, stage: &str) -> serde_json::Value {
    let outputs = record
        .outputs
        .as_ref()
        .unwrap_or_else(|| panic!("execution recorded NO stage outputs at all: {record:?}"));
    let value = outputs.get(stage).unwrap_or_else(|| {
        let seen: Vec<&String> = outputs.keys().collect();
        panic!(
            "stage `{stage}` recorded no output; stages that did: {seen:?}. On the `failed` \
             route `approve` and `land` are SKIPPED, so a missing `land` here means the \
             deterministic fix did not make the fixture suite pass."
        )
    });
    if let Some(parsed) = value.get("parsed").filter(|p| !p.is_null()) {
        return parsed.clone();
    }
    let content = value
        .get("content")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| {
            panic!("stage `{stage}` output has neither `parsed` nor a string `content`: {value:?}")
        });
    serde_json::from_str(content).unwrap_or_else(|e| {
        panic!("stage `{stage}` content is not JSON ({e}); the effect envelope is `{content}`")
    })
}

/// A string field of an effect envelope.
fn envelope_str(envelope: &serde_json::Value, field: &str) -> String {
    envelope
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("effect envelope has no string `{field}`: {envelope}"))
        .to_owned()
}

/// Wait for the pack's durable human gate to park, failing with the run's own
/// evidence if the execution reaches a terminal state first.
///
/// `ExecutionStatus` has NO `awaiting_approval` variant — a parked gate is still
/// `running` — so polling `status` alone would sit here until the test timeout
/// killed a run that was waiting correctly. The park is visible only through
/// `/approvals`.
async fn await_gold_loop_gate(
    node: &NodeHandle,
    exec: &Execution,
    stage: &str,
    timeout: Duration,
) -> kata_client::types::PendingApproval {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(approvals) = node.client().list_approvals().await
            && let Some(pending) = approvals
                .into_iter()
                .find(|a| a.execution_id == exec.id() && a.stage_name == stage)
        {
            return pending;
        }
        // `is_terminal()` rather than a hand-written `matches!` over the
        // variants: the enum's own predicate cannot go stale when a variant is
        // added, and a poll loop that misses a new terminal state hangs until
        // the test timeout and blames the gate.
        if let Ok(record) = exec.record().await
            && record.status.is_terminal()
        {
            panic!(
                "the run reached {:?} WITHOUT ever parking on the `{stage}` gate.\n\
                 error: {:?}\n\
                 stage outputs: {:?}\n\
                 A terminal run with a `halt` output means `validate` reported \
                 status=failed and the route took the non-landing arm; a terminal run \
                 with a `land` output means the promote ran with NO human gate, which \
                 is the gate not gating.",
                record.status, record.error, record.outputs
            );
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the `{stage}` gate never parked within {timeout:?}. main log tail:\n{}",
            log_tail(&std::fs::read_to_string(node.log_path()).unwrap_or_default())
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// **The $0 composition proof.** `context` -> `implement` -> `record` (commit
/// effect) -> `validate` -> `route` -> `approve` (durable human gate) -> `land`
/// (promote effect), driven through the shipped product path against a real
/// repository, with every verdict read out of that repository with `git`.
///
/// Model-free by construction: every stage is `agent = "shell"` or
/// `agent = "workspace_effect"`, so this spends NO model/API budget and rides
/// `just gate-containment`'s `smoke-no-budget` step.
///
/// # The host-binding axis — SWEPT BY THE GATE
///
/// The trunk is a PARAMETER of this function, and the three `#[tokio::test]`
/// wrappers below are the matrix. Each names its trunk and hands it to
/// `scripts/materialize-gold-fixture.sh` through `KATA_GOLD_FIXTURE_TRUNK` **on
/// the child's environment**, so a run is reproducible from the test name alone
/// and two trunks can never race over one process-global variable.
///
/// The wrappers are the variable's only setter, and they ride the gate for
/// free: `just smoke-no-budget`'s include is UNNARROWED
/// (`binary(smokes) or binary(live_smoke)` minus two named model-budget smokes),
/// so a `#[test]` added to this file is in the gate on the day it lands. A
/// justfile loop would be strictly worse here: the gate selects by nextest
/// binary, so a loop would have to live inside
/// `smoke-no-budget` itself, would add `cargo nextest run` lines that
/// `bin/kata-eval/tests/gate_exclusion.rs` has to re-parse, and would be invisible
/// to the ignored-test census that proves the gate reaches what it selects.
///
/// **One trunk per test process, deliberately.** Folding the sweep into one
/// `#[test]` would put every fixture materialization, every installed main and
/// every composed run under ONE budget, and `[profile.live-smoke]`'s
/// `terminate-after = 5 x 60s` SIGKILLs at 300s — a single trunk already spends
/// a large fraction of that. Separate tests each get their own 300s, and
/// `test-threads = 1` in that profile serializes them, which is what the per-uid
/// `/tmp/kata-installed-main-<uid>` singleton needs anyway.
///
/// **Three of the four `TRUNK_NAMES`, and the omission is argued.** The names
/// fall into three classes, not four: the common default (`main`), a plain non-default (`master`),
/// and a SLASHED name (`release/next`), which is the only one that makes `refs/heads/` a directory
/// and the only one whose jj bookmark carries a `/`. `develop` is a second instance of `master`'s
/// class and buys the gate nothing a second time; it stays swept at the PROVIDER level by
/// `crates/vcs/tests/host_binding_known_red.rs`, which loops over the full `TRUNK_NAMES`.
///
/// # Cost
///
/// Measured on the reference host (128 cores, one NVMe): the matrix is about
/// **20s** of a whole `just smoke-no-budget` — `main` ~11s (the first cell pays
/// the installed-main lock and a cold fixture), `master` ~4s, `release/next` ~4s.
/// Under three concurrent builds the first cell measured ~60s and the other two
/// were unchanged, so the cost beyond `main` is bounded by the two cheap cells. **Cost is therefore
/// not the reason `develop` is left out** — the equivalence-class argument above is, and putting it
/// back is a four-line edit that buys a second instance of an already-covered class.
///
/// # Falsified, run rather than asserted
///
/// TWO neuterings, each rebuilt and run, each restored from a `cp` backup
/// verified with `sha256sum -c`:
///
/// * `kata_vcs::trunk::resolve_trunk` made to return `main` unconditionally —
///   a hard-coded base bookmark. `…_on_trunk_main` PASSED; `…_on_trunk_master` and
///   `…_on_trunk_release_next` both FAILED with *"the resolved trunk bookmark
///   `main` is absent or conflicted in this repository"*. That is the whole
///   reason the matrix exists: the `main` cell cannot see this defect.
/// * the `.env("KATA_GOLD_FIXTURE_TRUNK", trunk)` below deleted, so the variable
///   has no setter. `main` PASSED; the other two FAILED at the fixture-trunk assertion
///   with *"the materialized fixture's trunk is `main` but this run asked for
///   `master`"*. Without that one line the sweep measures three `main`
///   repositories and reports three greens for an axis it never varied.
///
/// The trunk is `VcsConfig::trunk` resolved by `kata_vcs::trunk::resolve_trunk`;
/// nothing hard-codes `main`.
///
/// The sweep matters because it covers the one intersection nothing else does.
/// `crates/vcs/tests/host_binding_known_red.rs` proves the binding at the PROVIDER
/// level; this proves it through the RUNNER and the product path — and a binding
/// right in the provider and wrong in the runner shows provider-level green over
/// a broken composition.
async fn gold_loop_nobudget_lands_the_fixture_fix_on(trunk: &str) {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let root = kata_repo_root();
    let scratch = tempfile::tempdir().expect("scratch tempdir");
    let fixture = scratch.path().join("tally");
    let patch = root.join("test/fixtures/gold-loop/known-fix.patch");

    // ── 1. THE FIXTURE, through the shipped materializer ────────────
    //
    // Not hand-built: the script REFUSES rather than half-produces (it re-reads
    // every byte, mode and repo-local git setting it wrote, and checks that
    // `known-fix.patch` still applies — i.e. that this is the UNFIXED tree).
    //
    // The trunk travels on the CHILD's environment, never through
    // `std::env::set_var`: the matrix wrappers below run in separate processes
    // today, but a process-global write inside a `#[tokio::test]` is unsound the
    // moment two of them share one, and this is the only consumer.
    let materialize = Command::new("bash")
        .arg(root.join("scripts/materialize-gold-fixture.sh"))
        .arg(&fixture)
        .env("KATA_GOLD_FIXTURE_TRUNK", trunk)
        .current_dir(&root)
        .output()
        .expect("run scripts/materialize-gold-fixture.sh");
    assert!(
        materialize.status.success(),
        "materialize-gold-fixture.sh failed for trunk `{trunk}` ({}):\n{}",
        materialize.status,
        String::from_utf8_lossy(&materialize.stderr)
    );

    // ── 2. THE HOST BINDING, READ RATHER THAN ASSUMED ───────────────
    // Every assertion below reads the trunk rather than assuming it, and this is
    // where the READ is checked against the ASK: the materializer verifies its own
    // `git init -b`, and this re-verifies it from outside the script, because a
    // sweep that silently measured four `main` repositories would report four
    // greens for the axis it exists to vary.
    let materialized_trunk = git_stdout(&fixture, &["rev-parse", "--abbrev-ref", "HEAD"]);
    assert_eq!(
        materialized_trunk, trunk,
        "the materialized fixture's trunk is `{materialized_trunk}` but this run asked \
         for `{trunk}` — the fixture is not the repository under test"
    );
    let trunk_ref = format!("refs/heads/{trunk}");
    let base_sha = git_stdout(&fixture, &["rev-parse", &trunk_ref]);

    // POSITIVE CONTROL, and it is not ceremony. Assertion (9) below is "the
    // fixture's suite is GREEN on the landed tree". If the base tree were
    // already green that assertion would be satisfiable by landing NOTHING,
    // which is the failure it exists to catch.
    let (base_rc, base_verdict) = fixture_suite_at(&fixture, &base_sha);
    assert_eq!(
        base_rc, 1,
        "the fixture's suite must be RED at the trunk base (rc 1 = a test failed; rc 2 = \
         the suite could not RUN, which is a host problem). got rc={base_rc} \
         verdict={base_verdict}. A green base makes the landed-tree assertion vacuous."
    );

    // ── 3. THE NODE, on the DEFAULT (jj) execution-workspace provider ──
    // `edit` authors `net = "host"`: `egress_allow` carries a never-dialed
    // authority so the stage's declared union is non-empty.
    let node = spawn_native_jj_node_with_egress(&fixture);
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    // ── 4. SUBMIT THE PACK SOURCE ───────────────────────────────────
    //
    // BY SOURCE, not by library name: the name form resolves against
    // `./.kata/workflows/`, which would mean writing an untracked `.kata/` INTO
    // the fixture repository — and an untracked file in the tree is exactly
    // what a promote's clean-workspace precondition refuses. Reading the file
    // here also means the checked-in rig is what compiles, not a copy in this
    // test.
    let pack_path = root.join("workflows/smoke/gold-loop-nobudget-smoke.star");
    let star = std::fs::read_to_string(&pack_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", pack_path.display()));
    let exec = node
        .client()
        .run_starlark(&star, Some("gold-loop-nobudget-smoke.star"))
        .await
        .expect("submit gold-loop-nobudget-smoke");
    let exec_id = exec.id().to_owned();

    // ── 5. THE DURABLE HUMAN GATE ───────────────────────────────────
    let pending = await_gold_loop_gate(&node, &exec, "approve", Duration::from_secs(150)).await;
    assert_eq!(
        pending.stage_name, "approve",
        "the gate must park on the stage that declares `approval = True`"
    );
    assert!(
        pending
            .reason
            .contains("Land the validated candidate on trunk"),
        "the operator-visible reason must be the pack's authored `approval_reason`, which \
         is what an operator decides from; got {:?}",
        pending.reason
    );

    // ── ASSERTION (10): THE GATE ACTUALLY GATES ─────────────────────
    // CATCHES: an in-graph `promote` that runs without consulting the gate, and
    // a `route()` that took the landing arm early. The trunk ref is the only
    // witness that cannot be faked by a stage's own report.
    assert_eq!(
        git_stdout(&fixture, &["rev-parse", &trunk_ref]),
        base_sha,
        "`{trunk_ref}` MOVED while the run was still parked on the human gate — the \
         promote did not wait for the approval it is authored behind"
    );

    node.client()
        .approve(&exec_id, &pending.assignment_id)
        .await
        .expect("approve the gate");

    let record = exec
        .wait_for_terminal(Duration::from_secs(90))
        .await
        .expect("wait for terminal after approving the gate");
    assert_eq!(
        record.status,
        ExecutionStatus::Completed,
        "expected Completed, got {:?} (error={:?})\nmain log tail:\n{}",
        record.status,
        record.error,
        log_tail(&std::fs::read_to_string(node.log_path()).unwrap_or_default())
    );

    // ── THE TWO EFFECT ENVELOPES — CLAIMS, to be checked against git ──
    let record_env = effect_envelope(&record, "record");
    let land_env = effect_envelope(&record, "land");
    assert_eq!(envelope_str(&record_env, "operation"), "commit");
    assert_eq!(
        envelope_str(&land_env, "operation"),
        "promote",
        "the `land` stage must record a PROMOTE; a park envelope checked against trunk \
         would report confident nonsense"
    );
    // The `oci` promote envelope names the moved ref `ref_moved`; the commit
    // effect's is still `ref_name` — the fields' shapes differ by verb.
    let claimed_ref = envelope_str(&land_env, "ref_moved");
    let claimed_sha = envelope_str(&land_env, "commit_sha");
    let recorded_ref = envelope_str(&record_env, "ref_name");
    let recorded_sha = envelope_str(&record_env, "commit_sha");

    // ══ THE ORACLE: git, against the repository on disk ═════════════

    // (1) THE NAMED REF RESOLVES AT ALL.
    // CATCHES: an envelope that names a ref the repository does not have — every
    // reader downstream of it can then only report noise.
    let landed_sha = git_resolve(&fixture, &claimed_ref).unwrap_or_else(|| {
        panic!(
            "the `land` envelope reported ref_name `{claimed_ref}`, which resolves to \
             NOTHING in {}. Refs present: {:?}",
            fixture.display(),
            git_stdout(
                &fixture,
                &["for-each-ref", "--format=%(refname)", "refs/heads/"]
            )
        )
    });
    // The NAME, not just the sha. Comparing `git_resolve(claimed_ref)` to
    // `rev-parse(trunk_ref)` is satisfied by ANY ref pointing at the landed commit —
    // `exec-<id>` included — so it cannot see a promote that published the right
    // commit under the wrong name.
    // Compare by NAME, normalising both sides: the envelope carries the SHORT name
    // (`main`) while `trunk_ref` is fully qualified (`refs/heads/main`).
    assert_eq!(
        claimed_ref.trim_start_matches("refs/heads/"),
        trunk,
        "the `land` envelope named `{claimed_ref}`, which is not this repository's trunk \
         `{trunk_ref}` — kata landed somewhere the operator did not ask for"
    );
    assert_eq!(
        landed_sha,
        git_stdout(&fixture, &["rev-parse", &trunk_ref]),
        "`{claimed_ref}` and `{trunk_ref}` disagree about the landed commit"
    );

    // (2) THE BASE REF ACTUALLY ADVANCED.
    // CATCHES `refs/heads/main` still holding the trunk base after a `promote`
    // that reported success — e.g. an "already holds the candidate" shortcut
    // firing vacuously on a WORKLESS candidate and skipping the mutation.
    assert_ne!(
        landed_sha, base_sha,
        "`{claimed_ref}` still points at the trunk base {base_sha} — NOTHING was \
         promoted, however the `land` stage described itself (envelope: {land_env})"
    );

    // (3) THE ENVELOPE'S CLAIM IS THE REPOSITORY'S STATE.
    // CATCHES an envelope whose `commit_sha` names a commit while the ref
    // resolves to the base — a stage envelope believed over the disk.
    assert_eq!(
        claimed_sha, landed_sha,
        "the `land` stage claimed commit_sha {claimed_sha} but `{claimed_ref}` resolves \
         to {landed_sha} — the envelope's CLAIM does not match the repository's STATE"
    );

    // (4) THE LANDED DIFF IS EXACTLY THE FIX, AND NOTHING ELSE.
    // CATCHES TWO failures at once:
    //   * the EMPTY promoted diff — a `commit` effect whose commit holds the
    //     BASE tree rather than the candidate's work, so the promoted commit
    //     contains the BASE tree and the candidate worktree holding the real work
    //     is then torn down;
    //   * a landing of `.jj/` and `agents/` internals into the operator's trunk,
    //     which happens when the target repository does not ignore kata's own
    //     state. Pinning the set (not just asserting it
    //     is non-empty) is what makes that unrepresentable here.
    let changed: Vec<String> =
        git_stdout(&fixture, &["diff", "--name-only", &base_sha, &landed_sha])
            .lines()
            .map(str::to_owned)
            .collect();
    assert_eq!(
        changed,
        vec!["kata-out/check.log".to_owned(), "src/tally.sh".to_owned()],
        "the landed commit's diff against the base must be EXACTLY the fixture fix and \
         the declared evidence log. An empty list means a promote that changed nothing; \
         extra paths mean kata's own state (`.jj/`, `agents/`) leaked into the operator's \
         trunk. `kata-out/check.log` is the pack's declared `produces_files` — under `oci` \
         a declared workspace output lands in the candidate, and the evidence contract \
         names it there."
    );

    // (5) THE LANDED BYTES ARE THE KNOWN ANSWER.
    // CATCHES a candidate forked from the WRONG BASE — the trunk-binding defect,
    // where the workspace is created off the empty root and the landed tree is
    // not this repository's tree at all — and any landing of a tree that is not
    // the one validation approved. Derived from `known-fix.patch` with `git
    // apply`, never re-spelled here.
    let expected = expected_fixed_blob(&fixture, &base_sha, &patch);
    let landed_blob = git_bytes(&fixture, &["show", &format!("{landed_sha}:src/tally.sh")]);
    assert_eq!(
        String::from_utf8_lossy(&landed_blob),
        String::from_utf8_lossy(&expected),
        "the landed `src/tally.sh` is not what `known-fix.patch` produces from the base. \
         The pack's deterministic `implement` stage and that patch are two spellings of \
         one answer; they must move together."
    );

    // (6) THE `commit` EFFECT'S REF AND SHA ARE REAL, AND LEAD TO THE LANDING.
    // CATCHES a `commit` effect that returns a sha the repository does not
    // have, or publishes no ref for it (a ref nothing reads proves nothing; this
    // check reads it), and a promote that landed something with no
    // relationship to what `record` named.
    let recorded_commit = git_resolve(&fixture, &recorded_sha).unwrap_or_else(|| {
        panic!(
            "the `record` (commit) effect claimed commit_sha {recorded_sha}, which does \
             not resolve in the repository at all (envelope: {record_env})"
        )
    });
    // TARGET, not existence. An `.is_some()` check passes a `commit` effect that
    // publishes `exec-<id>` at the trunk BASE while the envelope names the candidate
    // (falsified by injection). The `exec-` ref's
    // stated purpose is to keep the published commit durably reachable, which is exactly
    // what a wrong-target publication destroys — silently.
    let recorded_ref_target = git_resolve(&fixture, &recorded_ref).unwrap_or_else(|| {
        panic!(
            "the `record` effect claimed ref_name `{recorded_ref}`, which resolves to \
             nothing in the repository — the commit was reported but the ref was never \
             published"
        )
    });
    assert_eq!(
        recorded_ref_target, recorded_commit,
        "the `record` effect published `{recorded_ref}` at {recorded_ref_target} while its \
         envelope claimed commit_sha {recorded_commit} — the ref does not keep the \
         published commit reachable, so nothing does"
    );
    let ancestry = fixture_git(
        &fixture,
        &["merge-base", "--is-ancestor", &recorded_commit, &landed_sha],
    );
    assert!(
        ancestry.status.success(),
        "the commit `record` named ({recorded_commit}) is NOT an ancestor of what landed \
         ({landed_sha}) — the candidate that was committed and the candidate that was \
         promoted are different histories, so the validation evidence binds to neither"
    );

    // (7) THE TERMINAL EFFECT TORE THE WORKSPACE DOWN, ON DISK.
    // CATCHES a `promote` that reports terminal and leaves the candidate
    // workspace standing — which matters because on the default jj provider
    // `reap_terminal_workspaces` is a permanent no-op, so nothing else would
    // ever reclaim it.
    let candidate_dir = fixture.join("agents").join(&exec_id);
    assert!(
        !candidate_dir.exists(),
        "the candidate workspace {} still exists after a TERMINAL promote",
        candidate_dir.display()
    );

    // (8) THE INDEPENDENT SCRIPT ORACLE — including the fixture's own suite.
    // Same four properties by a DIFFERENT implementation, plus the one this test
    // cannot cheaply repeat: `sh tests/check.sh` GREEN on the landed tree. That
    // is the outcome oracle and it does not care HOW the fix was made.
    let verify = Command::new("bash")
        .arg(root.join("scripts/materialize-gold-fixture.sh"))
        .arg("--verify-landed")
        .arg(&fixture)
        .arg(&base_sha)
        .arg(&claimed_ref)
        .arg(&claimed_sha)
        .current_dir(&root)
        .output()
        .expect("run materialize-gold-fixture.sh --verify-landed");
    assert!(
        verify.status.success(),
        "--verify-landed FAILED ({}):\nstdout:\n{}\nstderr:\n{}",
        verify.status,
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );

    // (9) …and stated directly, so a failure here names the suite rather than
    // the script. CATCHES "landed something that does not fix the defect".
    let (landed_rc, landed_verdict) = fixture_suite_at(&fixture, &landed_sha);
    assert_eq!(
        landed_rc, 0,
        "the fixture's own suite is not GREEN on the landed tree (rc={landed_rc} \
         verdict={landed_verdict}); the base was RED at rc=1, so this is the loop having \
         landed something that does not fix what it was asked to fix"
    );

    // ── (11) A SECOND EXECUTION CAN LAND IN THE SAME REPOSITORY ─────
    //
    // CATCHES kata landing exactly ONE workflow per repository: a
    // `create_workspace` that forked `repo.view().git_head()` while the landing
    // ladder lands against the trunk LOCAL BOOKMARK, given that kata's OWN first
    // promote detaches the colocated `.git/HEAD` (jj-lib's `check_and_detach_head`
    // runs inside every export that moves the bookmark HEAD points at). Every
    // candidate after the first would be born on a base that had "already
    // advanced" and park needs-revalidation forever — a defect INVISIBLE to any
    // single-execution test.
    //
    // `crates/vcs/tests/jj_sequential_executions.rs` owns this at the PROVIDER
    // level. It is asserted again HERE because provider-green is precisely the
    // state all eight broken compositions were in: this second landing is driven
    // through submit -> dispatch -> effect, like the first.
    //
    // THE GRAPH IS INLINE AND DELIBERATELY THE SMALLEST THING THAT LANDS. Its
    // job is to ask whether the REPOSITORY admits a second landing, not to
    // exercise an authored composition — and the gold-loop pack could not be
    // re-used for it anyway: its `implement` stage REFUSES once the fix it
    // applies is already on trunk, which is the anchor check working.
    const SECOND_LANDING_PACK: &str = r#"
second = stage(
    id = "second",
    agent = "shell",
    # This stage WRITES the candidate; the default view is read-only.
    sandbox = sandbox_profile(workspace = "rw"),
    run = """set -eu
printf 'second landing\n' > SECOND.txt
test -f SECOND.txt
printf '{"wrote": true, "status": "passed", "commands": ["test -f SECOND.txt"], "criteria": [{"criterion_id": "wrote-the-file", "status": "passed", "evidence": ["SECOND.txt"]}]}\n'
""",
    outputs = {"wrote": "bool"},
)

land2 = stage(
    id = "land2",
    agent = "workspace_effect",
    op = "promote",
    depends_on = ["second"],
)

workflow(
    "second-landing-probe",
    description = "Smallest graph that lands: write one file in the candidate, promote it.",
    root = [second, land2],
    worktree_isolated = True,
    # Not what this probe measures — it is what a graph carrying a `promote` must
    # declare (`validate_in_graph_promote_declares_a_criterion`),
    # and the probe would be REFUSED at submit without it. `second` is `agent =
    # "shell"`, the only backend a criterion may name.
    #
    # It must also PASS, and `second` prints the validation report that proves
    # it: `WorkflowRunner::authorize_promote_dispatch` refuses a graph whose
    # criterion nothing produced evidence for, with
    # `validation_criterion:wrote-the-file:missing`. The extra keys beyond `outputs=` are admitted by the structured-output
    # validator (presence + type check only), so the flat contract is unchanged.
    validation_criteria = [
        validation_criterion(
            "wrote-the-file",
            description = "The candidate stage wrote its file.",
            stage = "second",
            commands = ["test -f SECOND.txt"],
            required = True,
        ),
    ],
)
"#;

    let second_exec = node
        .client()
        .run_starlark(SECOND_LANDING_PACK, Some("second-landing-probe.star"))
        .await
        .expect("submit the second-landing probe");
    let second_record = second_exec
        .wait_for_terminal(Duration::from_secs(90))
        .await
        .expect("wait for the second execution");
    assert_eq!(
        second_record.status,
        ExecutionStatus::Completed,
        "the SECOND execution in this repository did not complete: {:?} (error={:?}). \
         `promote parked candidate … base advanced` here is the one-landing-per-repository \
         defect: the fork base and the landing base must be the SAME ref.",
        second_record.status,
        second_record.error
    );

    let second_land = effect_envelope(&second_record, "land2");
    let second_claimed = envelope_str(&second_land, "commit_sha");
    let trunk_after_second = git_stdout(&fixture, &["rev-parse", &trunk_ref]);
    assert_ne!(
        trunk_after_second, landed_sha,
        "`{trunk_ref}` did not move for the SECOND execution — the first landing is the \
         only one this repository accepted (envelope: {second_land})"
    );
    assert_eq!(
        trunk_after_second, second_claimed,
        "the second `land2` envelope claimed {second_claimed} but `{trunk_ref}` resolves \
         to {trunk_after_second}"
    );
    let descends = fixture_git(
        &fixture,
        &[
            "merge-base",
            "--is-ancestor",
            &landed_sha,
            &trunk_after_second,
        ],
    );
    assert!(
        descends.status.success(),
        "the second landing {trunk_after_second} is NOT a descendant of the first \
         {landed_sha} — the second execution forked a stale base and its landing REWOUND \
         trunk over work that was already on it"
    );
    assert_eq!(
        git_stdout(
            &fixture,
            &["diff", "--name-only", &landed_sha, &trunk_after_second]
        ),
        "SECOND.txt",
        "the second landing must add exactly its own file on top of the first"
    );
    let (second_rc, second_verdict) = fixture_suite_at(&fixture, &trunk_after_second);
    assert_eq!(
        second_rc, 0,
        "the fixture's suite is no longer GREEN after the second landing (rc={second_rc} \
         verdict={second_verdict}) — the second execution undid the first"
    );

    node.shutdown().await.expect("clean shutdown");
}

// ── THE TRUNK MATRIX ────────────────────────────────────────────────
//
// Three tests, one body, one trunk each. The shared prefix is deliberate:
// `just smoke smoke_gold_loop_nobudget_lands_the_fixture_fix_on_trunk` is a test-NAME
// SUBSTRING, so the name the docs have always spelled out now selects the whole
// matrix, and each cell is still individually addressable by its suffix.
//
// 280s, not more: `[profile.live-smoke]` in `.config/nextest.toml` carries
// `slow-timeout = { period = "60s", terminate-after = 5 }`, so nextest SIGKILLs at
// 300s. A `kata_timeout` above that never fires and the smoke dies as an opaque
// signal instead of as a message naming the step it was waiting on.

/// The matrix cell for kata's historical hard-coded trunk. See
/// [`gold_loop_nobudget_lands_the_fixture_fix_on`].
#[kata_test_utils::kata_timeout(secs = 280)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_gold_loop_nobudget_lands_the_fixture_fix_on_trunk_main"]
async fn smoke_gold_loop_nobudget_lands_the_fixture_fix_on_trunk_main() {
    gold_loop_nobudget_lands_the_fixture_fix_on(kata_test_utils::host_repo::default_trunk()).await;
}

/// The matrix cell for a plain non-default trunk — the shape that forked from the
/// EMPTY ROOT for months. See [`gold_loop_nobudget_lands_the_fixture_fix_on`].
#[kata_test_utils::kata_timeout(secs = 280)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_gold_loop_nobudget_lands_the_fixture_fix_on_trunk_master"]
async fn smoke_gold_loop_nobudget_lands_the_fixture_fix_on_trunk_master() {
    gold_loop_nobudget_lands_the_fixture_fix_on("master").await;
}

/// The matrix cell for a SLASHED trunk — the only class in
/// `kata_test_utils::host_repo::TRUNK_NAMES` that makes `refs/heads/` a directory
/// and gives the jj bookmark a `/`. See
/// [`gold_loop_nobudget_lands_the_fixture_fix_on`].
#[kata_test_utils::kata_timeout(secs = 280)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_gold_loop_nobudget_lands_the_fixture_fix_on_trunk_release_next"]
async fn smoke_gold_loop_nobudget_lands_the_fixture_fix_on_trunk_release_next() {
    gold_loop_nobudget_lands_the_fixture_fix_on("release/next").await;
}

/// Every trunk this matrix names must be one the workspace's host-binding axis
/// declares, and the omission must be the one the doc argues.
///
/// A pure check, so it runs in `just test` too: the matrix above is three string
/// literals, and a literal that drifts out of
/// `kata_test_utils::host_repo::TRUNK_NAMES` would make the sweep measure a name
/// no other host-binding proof sweeps. It also PINS the omission — if `develop`
/// were quietly dropped from `TRUNK_NAMES`, or a fifth name added, this names it,
/// so the "three of four, and here is why" argument cannot rot into "three of
/// five, nobody looked".
#[test]
fn the_gold_loop_trunk_matrix_names_declared_trunks_and_omits_exactly_develop() {
    use kata_test_utils::host_repo::{TRUNK_NAMES, default_trunk};

    let swept = [default_trunk(), "master", "release/next"];
    for trunk in swept {
        assert!(
            TRUNK_NAMES.contains(&trunk),
            "the gold-loop matrix sweeps `{trunk}`, which is not in TRUNK_NAMES \
             ({TRUNK_NAMES:?}) — the composition smoke would be varying a trunk no \
             provider-level proof varies"
        );
    }
    let omitted: Vec<&str> = TRUNK_NAMES
        .iter()
        .copied()
        .filter(|name| !swept.contains(name))
        .collect();
    assert_eq!(
        omitted,
        vec!["develop"],
        "the gold-loop matrix omits {omitted:?} from TRUNK_NAMES ({TRUNK_NAMES:?}). \
         Exactly one omission is argued in the doc comment on \
         `gold_loop_nobudget_lands_the_fixture_fix_on`: `develop` is a second instance \
         of `master`'s class (a plain non-default name) and buys the required gate \
         nothing a second time, while the PROVIDER-level sweeps still cover it. Any \
         other omission — or any new name — needs its own argument before it is left \
         out of the only composition proof that observes state outside kata."
    );
}

// ── THE PROMOTION GATE'S NEGATIVE, COMPOSED ─────────────────────────

/// One promoting pack, one substitution point, TWO runs.
///
/// `__CRITERION_STATUS__` is replaced with `failed` for the negative and
/// `passed` for the control, and NOTHING else differs between the two — not the
/// stage, not the file it writes, not the criterion, not the graph. That is the
/// whole design: a "trunk did not move" assertion is satisfied by a run that
/// failed for ANY reason (a pack that no longer compiles, a node that never came
/// up, a stage that died), so the negative is worthless without a twin that
/// proves everything else about the composition still lands. Two spellings of
/// one pack would let the twins drift apart and quietly stop being twins.
///
/// The proof stage EXITS 0 while reporting a red criterion, deliberately: a
/// stage that failed would stop the graph before `land` ever became ready, and
/// the refusal under test would never be reached. What must be refused here is a
/// promote that is READY, in a run that is HEALTHY, behind a verdict that is RED.
const PROMOTION_GATE_PROBE_PACK: &str = r#"
proof = stage(
    id = "proof",
    agent = "shell",
    # This stage WRITES the candidate; the default view is read-only.
    sandbox = sandbox_profile(workspace = "rw"),
    run = """set -eu
printf 'gate probe\n' > GATE_PROBE.txt
test -f GATE_PROBE.txt
printf '{"wrote": true, "status": "__CRITERION_STATUS__", "commands": ["test -f GATE_PROBE.txt"], "criteria": [{"criterion_id": "gate-probe-wrote-the-file", "status": "__CRITERION_STATUS__", "evidence": ["GATE_PROBE.txt"]}]}\n'
""",
    outputs = {"wrote": "bool"},
)

land = stage(
    id = "land",
    agent = "workspace_effect",
    op = "promote",
    depends_on = ["proof"],
)

workflow(
    "promotion-gate-probe",
    description = "Smallest graph that reaches an in-graph promote: write one file, report a criterion verdict, promote.",
    root = [proof],
    worktree_isolated = True,
    # `stage = "proof"` is checked FAIL-CLOSED by `validation_proof_stage_determinism`:
    # only a backend for which `ExecutionProgramStage::is_validation_proof_eligible`
    # holds (today `shell`) may carry a promotion verdict, so this could not be an
    # agent stage even if the pack wanted one.
    validation_criteria = [
        validation_criterion(
            "gate-probe-wrote-the-file",
            description = "The candidate stage wrote its file.",
            stage = "proof",
            commands = ["test -f GATE_PROBE.txt"],
            required = True,
        ),
    ],
)
"#;

/// [`PROMOTION_GATE_PROBE_PACK`] with its one substitution point resolved.
/// Required proofs must describe the candidate actually published to trunk.
/// The negative variants differ from the positive only in the first tree or
/// whether the second proof is required. Git is the landing oracle.
#[kata_test_utils::kata_timeout(secs = 180)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_promotion_requires_all_proofs_on_the_landed_tree"]
async fn smoke_promotion_requires_all_proofs_on_the_landed_tree() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }
    let root = kata_repo_root();
    let scratch = tempfile::tempdir().expect("scratch");
    let fixture = scratch.path().join("candidate");
    let materialize = Command::new("bash")
        .arg(root.join("scripts/materialize-gold-fixture.sh"))
        .arg(&fixture)
        .env(
            "KATA_GOLD_FIXTURE_TRUNK",
            kata_test_utils::host_repo::default_trunk(),
        )
        .output()
        .expect("materialize fixture");
    assert!(
        materialize.status.success(),
        "{}",
        String::from_utf8_lossy(&materialize.stderr)
    );
    let trunk_ref = format!("refs/heads/{}", kata_test_utils::host_repo::default_trunk());
    let base = git_stdout(&fixture, &["rev-parse", &trunk_ref]);
    let node = spawn_native_jj_node(&fixture);
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("healthy");
    let pack = r#"
first = stage(id = "first", agent = "shell", sandbox = sandbox_profile(workspace = "rw"),
    run = "set -eu\nprintf '__FIRST_TREE__' > COHERENCE.txt\ntest $(cat COHERENCE.txt) = __FIRST_TREE__\nprintf '{\"criteria\":[{\"criterion_id\":\"first\",\"status\":\"passed\"}]}'",
    outputs = {"criteria": "array"})
edit = stage(id = "edit", agent = "shell", sandbox = sandbox_profile(workspace = "rw"),
    run = "set -eu\nprintf 'B' > COHERENCE.txt\nprintf '{\"edited\":true}'", depends_on = [first])
second = stage(id = "second", agent = "shell", depends_on = [edit],
    run = "set -eu\ntest $(cat COHERENCE.txt) = B\nprintf '{\"criteria\":[{\"criterion_id\":\"second\",\"status\":\"passed\"}]}'",
    outputs = {"criteria": "array"})
land = stage(id = "land", agent = "workspace_effect", op = "promote", depends_on = [second])
workflow("proof-coherence", root = first, worktree_isolated = True, validation_criteria = [
    validation_criterion("first", description = "first tree proof", stage = "first"),
    validation_criterion("second", description = "second tree proof", stage = "second", required = __SECOND_REQUIRED__),
])
"#;
    for (first_tree, second_required, allowed) in [
        ("A", "True", false),
        ("A", "False", false),
        ("B", "True", true),
    ] {
        let source = pack
            .replace("__FIRST_TREE__", first_tree)
            .replace("__SECOND_REQUIRED__", second_required);
        let execution = node
            .client()
            .run_starlark(&source, Some("proof-coherence.star"))
            .await
            .expect("authorable graph");
        let record = execution
            .wait_for_terminal(Duration::from_secs(35))
            .await
            .expect("terminal");
        let observed = git_stdout(&fixture, &["rev-parse", &trunk_ref]);
        if allowed {
            assert_ne!(observed, base, "same-tree proofs must land a real change");
            assert_eq!(
                git_stdout(&fixture, &["show", &format!("{trunk_ref}:COHERENCE.txt")]),
                "B"
            );
            assert_eq!(
                git_stdout(&fixture, &["diff", "--name-only", &base, &observed]),
                "COHERENCE.txt"
            );
            assert_eq!(
                record.status,
                ExecutionStatus::Completed,
                "{:?}",
                record.error
            );
        } else {
            assert_eq!(
                observed, base,
                "mixed-tree proofs moved trunk; second_required={second_required}"
            );
            assert_eq!(record.status, ExecutionStatus::Failed, "{:?}", record.error);
            assert!(
                record
                    .error
                    .as_deref()
                    .unwrap_or_default()
                    .contains("candidate"),
                "refusal must concern candidate proof: {:?}",
                record.error
            );
            let parked = format!("refs/heads/parked/{}", record.id);
            assert_eq!(
                git_stdout(&fixture, &["show", &format!("{parked}:COHERENCE.txt")]),
                "B",
                "refused work must remain recoverable"
            );
        }
    }
    node.shutdown().await.expect("shutdown");
}

fn promotion_gate_probe_pack(criterion_status: &str) -> String {
    assert!(
        PROMOTION_GATE_PROBE_PACK.contains("__CRITERION_STATUS__"),
        "the promotion-gate probe pack lost its substitution point, so both twins would \
         report the SAME verdict and the negative would be vacuous"
    );
    PROMOTION_GATE_PROBE_PACK.replace("__CRITERION_STATUS__", criterion_status)
}

/// Every ref in a repository as `<name> <sha>` lines, sorted — the git-side
/// inventory of everything this repository has published.
///
/// Stronger than reading trunk alone: a promote that landed the right commit
/// under the WRONG name moves no trunk and is invisible to a `rev-parse` check,
/// and so is a candidate published somewhere nothing reads.
fn repo_ref_inventory(repo: &Path) -> String {
    git_stdout(
        repo,
        &[
            "for-each-ref",
            "--sort=refname",
            "--format=%(refname) %(objectname)",
        ],
    )
}

/// **The promotion gate's NEGATIVE, composed.** A pack whose REQUIRED validation
/// criterion reports `failed` reaches a ready in-graph `promote`, is refused
/// before dispatch, and the run terminalizes — with the verdict read out of the
/// repository with `git`, not out of kata.
///
/// # Why this exists when the gate already has tests
///
/// The gate's POSITIVE is composed and lands
/// (`gold_loop_nobudget_lands_the_fixture_fix_on`). Its NEGATIVE also has an
/// in-process cell —
/// `a_promote_whose_required_criterion_failed_is_refused_and_the_trunk_never_moves`
/// in `crates/workflow/tests/oci_expansion.rs` — which builds the runner inside
/// the test process. That cell is worth keeping (it is fast), but it does not
/// cross the shipped node's CLI and API faces, which is where compositions break
/// under a green suite.
///
/// # The oracle, and why the twin is part of it
///
/// The primary oracle is `git`: trunk must resolve to the same commit it did
/// before the run; every commit the run DID publish must be unreachable from
/// trunk; and no ref outside kata's own `refs/jj/` and `refs/heads/parked/`
/// namespaces may have appeared or moved. A run that never started satisfies
/// every one of those, so the SECOND half of this smoke submits the same pack
/// with the criterion flipped to `passed` into the SAME repository through the
/// SAME node, and requires it to land. The negative means something only because
/// the twin lands; the twin proves the difference is the verdict and nothing
/// else.
///
/// Kata's own record is consulted for exactly one thing the repository cannot
/// answer — that the execution TERMINALIZED rather than hanging — plus a
/// secondary attribution check on the refusal's reason, which is belt-and-braces
/// and is marked as such below.
///
/// # Refused set
///
/// This smoke refuses a promote reached with a red REQUIRED criterion. It does
/// NOT claim to refuse a missing criterion, an unbound proof stage, a spoofed
/// `stage_name` or an unpinned candidate — those arms live in
/// `kata_workflow::promotion_gate`'s refused set and are covered by the in-crate
/// rig.
/// What is composed here is the one arm an operator's trunk is actually exposed
/// to when validation says no.
///
/// # MEASURED and FALSIFIED
///
/// About 2.4s inside a full `just smoke-no-budget`, about 13s under three
/// concurrent builds — both runs include the landing twin. Falsified by neutering the refusal in
/// `WorkflowRunner::authorize_promote_dispatch` (`if false && !(gate.active &&
/// gate.passed)`), rebuilding, and re-running: the red-criterion pack DISPATCHED
/// `land`, the promote ran, the execution reported `Completed`, and this smoke
/// REDDED with *"`refs/heads/main` MOVED for a run whose REQUIRED validation
/// criterion reported `failed` — the promotion gate did not gate"*.
/// `crates/workflow/src/runner/dispatch/submit.rs` was restored from a `cp`
/// backup verified with `sha256sum -c`.
#[kata_test_utils::kata_timeout(secs = 280)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_promotion_gate_refuses_a_failed_criterion_and_trunk_never_moves"]
async fn smoke_promotion_gate_refuses_a_failed_criterion_and_trunk_never_moves() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let root = kata_repo_root();
    let scratch = tempfile::tempdir().expect("scratch tempdir");
    let fixture = scratch.path().join("tally");

    // ── 1. A REAL REPOSITORY, through the shipped materializer ──────
    // The gold fixture, reused: it is the only tree in this workspace that
    // already ignores `.jj/` and `/agents/`, which is a REQUIREMENT kata places
    // on any repository it is pointed at (without it a promote lands kata's
    // own state into the trunk).
    let materialize = Command::new("bash")
        .arg(root.join("scripts/materialize-gold-fixture.sh"))
        .arg(&fixture)
        .env(
            "KATA_GOLD_FIXTURE_TRUNK",
            kata_test_utils::host_repo::default_trunk(),
        )
        .current_dir(&root)
        .output()
        .expect("run scripts/materialize-gold-fixture.sh");
    assert!(
        materialize.status.success(),
        "materialize-gold-fixture.sh failed ({}):\n{}",
        materialize.status,
        String::from_utf8_lossy(&materialize.stderr)
    );

    let trunk = kata_test_utils::host_repo::default_trunk();
    let trunk_ref = format!("refs/heads/{trunk}");
    let base_sha = git_stdout(&fixture, &["rev-parse", &trunk_ref]);
    let refs_before = repo_ref_inventory(&fixture);
    assert!(
        !refs_before.is_empty(),
        "the fixture published no refs at all, so the inventory oracle below would be \
         comparing two empty strings"
    );

    let node = spawn_native_jj_node(&fixture);
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    // ── 2. THE NEGATIVE — a ready promote behind a RED verdict ──────
    let refused = node
        .client()
        .run_starlark(
            &promotion_gate_probe_pack("failed"),
            Some("promotion-gate-probe.star"),
        )
        .await
        .expect("submit the red-criterion probe");
    let refused_record = refused
        .wait_for_terminal(Duration::from_secs(90))
        .await
        .expect("the refused run must reach a terminal state, not hang");

    // ══ THE ORACLE: git, against the repository on disk ═════════════
    //
    // THE REPOSITORY IS ASKED FIRST, and the order is not cosmetic. Kata's own
    // `ExecutionStatus` is also wrong when the gate is neutered, so an
    // `assert_eq!(status, Failed)` placed above would short-circuit and the
    // falsification would read `left: Completed, right: Failed` — a message about
    // kata's bookkeeping for a defect whose whole content is that a red verdict
    // reached the operator's trunk. MEASURED both ways: with the
    // refusal in `WorkflowRunner::authorize_promote_dispatch` neutered, the
    // status-first ordering said `Completed != Failed` and this ordering says
    // "`refs/heads/main` MOVED".

    // (1) TRUNK DID NOT MOVE.
    assert_eq!(
        git_stdout(&fixture, &["rev-parse", &trunk_ref]),
        base_sha,
        "`{trunk_ref}` MOVED for a run whose REQUIRED validation criterion reported \
         `failed` — the promotion gate did not gate. This is the whole property: a red \
         verdict must not reach the operator's trunk."
    );

    // (2) THE CANDIDATE WAS PRESERVED — OUTSIDE trunk.
    //
    // MEASURED, and it is why "nothing was published" is the WRONG claim here:
    // a refused run parks its candidate. `WorkflowExecutor`'s terminal closeout
    // (`park_candidate_at_closeout`) publishes
    // `refs/heads/parked/<execution-id>` and tears the worktree down, precisely so
    // a rejected candidate's work is recoverable rather than destroyed. jj adds
    // its own `refs/jj/keep/<sha>` anchors on top. Asserting an unchanged ref
    // inventory REDs on all of that, and would be a check refusing something it
    // never claimed to refuse.
    //
    // So the property is stated as it actually is: work exists, and NONE of it is
    // in trunk's history.
    let parked_ref = format!("refs/heads/parked/{}", refused.id());
    let parked_sha = git_resolve(&fixture, &parked_ref).unwrap_or_else(|| {
        panic!(
            "the refused run published no `{parked_ref}`, so its candidate was DESTROYED \
             rather than parked — and assertion (3) below has nothing to be non-vacuous \
             about. Refs present: {:?}",
            repo_ref_inventory(&fixture)
        )
    });

    // (3) NOTHING THE REFUSED RUN PRODUCED IS REACHABLE FROM TRUNK.
    // Ref-NAME independent, which is what makes it stronger than (1): a promote
    // that landed the candidate under some other name would move no trunk and pass
    // (1), and is caught here and in (4).
    let published: Vec<String> = git_stdout(&fixture, &["rev-list", "--all", "--not", &base_sha])
        .lines()
        .map(str::to_owned)
        .collect();
    assert!(
        published.contains(&parked_sha),
        "the parked candidate {parked_sha} is not among the commits outside the trunk \
         base's history ({published:?}) — the rev-list oracle is not seeing this run's \
         work, so its verdict below is about nothing"
    );
    for sha in &published {
        let reachable = fixture_git(&fixture, &["merge-base", "--is-ancestor", sha, &trunk_ref]);
        assert!(
            !reachable.status.success(),
            "commit {sha}, published by a run whose REQUIRED criterion reported `failed`, \
             IS an ancestor of `{trunk_ref}` — a red verdict reached the operator's trunk \
             under some ref name. Trunk's own sha is unchanged, which is exactly why \
             assertion (1) alone is not enough."
        );
    }

    // (4) NO REF OUTSIDE KATA'S OWN NAMESPACES APPEARED OR MOVED.
    // The two namespaces are spelled out rather than taken from
    // `kata_vcs::trunk::{PARKED_REF_PREFIX, is_kata_owned_ref}` on purpose: this is
    // the ORACLE, and an oracle that imports the predicate under test moves with
    // it. Widening what kata may publish must be a deliberate edit HERE.
    let operator_visible = |inventory: &str| -> Vec<String> {
        inventory
            .lines()
            .filter(|line| !line.starts_with("refs/jj/") && !line.starts_with("refs/heads/parked/"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        operator_visible(&repo_ref_inventory(&fixture)),
        operator_visible(&refs_before),
        "a ref OUTSIDE kata's own `refs/jj/` and `refs/heads/parked/` namespaces appeared \
         or moved across a refused promote. Trunk itself may be untouched and this still \
         means the refused candidate was published where an operator's tooling reads."
    );

    // ══ KATA'S RECORD, for what the repository cannot answer ════════

    // (5) THE RUN ENDED. A gate that refused by wedging the drive loop would
    // leave trunk untouched too, and every git assertion above would pass while
    // the operator's execution never finished. This is the one question only
    // kata can answer, and it is asked AFTER the repository has already spoken.
    assert_eq!(
        refused_record.status,
        ExecutionStatus::Failed,
        "a promote refused before dispatch must terminalize the execution Failed; got \
         {:?} (error={:?})\nmain log tail:\n{}",
        refused_record.status,
        refused_record.error,
        log_tail(&std::fs::read_to_string(node.log_path()).unwrap_or_default())
    );

    // (6) THE PROMOTE NEVER RAN.
    // No `land` output, because there was no attempt: the refusal is BEFORE
    // dispatch, so there is no worker involvement and nothing to reconcile.
    if let Some(outputs) = refused_record.outputs.as_ref() {
        assert!(
            !outputs.contains_key("land"),
            "the refused run recorded a `land` output, so the promote DISPATCHED and the \
             refusal happened somewhere later than it claims: {:?}",
            outputs.get("land")
        );
    }

    // (7) ATTRIBUTION, secondary and marked as such. Everything above is
    // satisfied by a run that failed for an unrelated reason; the twin in step 3
    // is what rules that out structurally. This assertion is the cheap version of
    // the same question and it names the criterion, so a failure here reads as
    // "refused, but not for this" instead of sending a reader to the log.
    let refusal = refused_record.error.clone().unwrap_or_default();
    assert!(
        refusal.contains("validation_criterion:gate-probe-wrote-the-file:failed"),
        "the execution failed, but its recorded error does not name the red criterion, so \
         this smoke would be green for a refusal it is not testing. error={refusal:?}"
    );

    // ── 3. THE TWIN — non-vacuity, and it is the load-bearing half ──
    //
    // Same pack, same node, same repository, ONE token different. If this does
    // not land, every assertion above is satisfiable by "nothing works", and the
    // negative proves nothing.
    let allowed = node
        .client()
        .run_starlark(
            &promotion_gate_probe_pack("passed"),
            Some("promotion-gate-probe.star"),
        )
        .await
        .expect("submit the green-criterion twin");
    let allowed_record = allowed
        .wait_for_terminal(Duration::from_secs(90))
        .await
        .expect("wait for the twin");
    assert_eq!(
        allowed_record.status,
        ExecutionStatus::Completed,
        "the GREEN twin of the refused pack did not complete: {:?} (error={:?}). The \
         negative above is only meaningful if this identical graph lands, so this failing \
         means the smoke proves nothing — fix this first.\nmain log tail:\n{}",
        allowed_record.status,
        allowed_record.error,
        log_tail(&std::fs::read_to_string(node.log_path()).unwrap_or_default())
    );

    let land_env = effect_envelope(&allowed_record, "land");
    assert_eq!(envelope_str(&land_env, "operation"), "promote");
    let claimed_sha = envelope_str(&land_env, "commit_sha");
    let trunk_now = git_stdout(&fixture, &["rev-parse", &trunk_ref]);
    assert_ne!(
        trunk_now, base_sha,
        "`{trunk_ref}` did not move for the GREEN twin either — this repository accepts no \
         landing at all, so the refusal above was not the gate (envelope: {land_env})"
    );
    assert_eq!(
        trunk_now, claimed_sha,
        "the twin's `land` envelope claimed {claimed_sha} but `{trunk_ref}` resolves to \
         {trunk_now}"
    );
    assert_eq!(
        git_stdout(&fixture, &["diff", "--name-only", &base_sha, &trunk_now]),
        "GATE_PROBE.txt",
        "the twin's landed diff must be exactly the one file its proof stage wrote — an \
         empty diff means a promote that changed nothing, and extra paths mean kata's own \
         state leaked into trunk"
    );

    node.shutdown().await.expect("clean shutdown");
}

/// `src/tally.sh` as `known-fix.patch` produces it from `base` — the fixture's
/// ORACLE ANSWER, derived by running `git apply`, never transcribed.
///
/// The base tree is extracted with `git archive` into a scratch directory and
/// patched there, so the repository under test is never touched.
fn expected_fixed_blob(repo: &Path, base: &str, patch: &Path) -> Vec<u8> {
    let work = tempfile::tempdir().expect("known-fix tempdir");
    let archive = fixture_git(repo, &["archive", "--format=tar", base]);
    assert!(archive.status.success(), "git archive {base} failed");
    let tar_path = work.path().join("base.tar");
    std::fs::write(&tar_path, &archive.stdout).expect("write base.tar");
    let tree = work.path().join("base");
    std::fs::create_dir_all(&tree).expect("mkdir base");
    let untar = Command::new("tar")
        .arg("-xf")
        .arg(&tar_path)
        .arg("-C")
        .arg(&tree)
        .output()
        .expect("spawn tar");
    assert!(
        untar.status.success(),
        "tar -xf failed: {}",
        String::from_utf8_lossy(&untar.stderr)
    );
    // `git apply` works OUTSIDE a repository — it is a patch tool, and this
    // directory is deliberately not one, so nothing here can touch the fixture's
    // refs or index.
    let apply = kata_test_utils::git::hermetic_git()
        .arg("apply")
        .arg(patch)
        .current_dir(&tree)
        .output()
        .expect("spawn git apply");
    assert!(
        apply.status.success(),
        "git apply {} failed on the base tree: {}",
        patch.display(),
        String::from_utf8_lossy(&apply.stderr)
    );
    std::fs::read(tree.join("src/tally.sh")).expect("read patched src/tally.sh")
}

/// **THE COMPOSED PROOF that a parked promote keeps its candidate tree pin**,
/// read out of git and not out of kata.
///
/// # The property
///
/// `WorkflowRunner::authorize_promote_dispatch` stamps `CandidateTreePin` onto a
/// `workspace_effect op = "promote"` directive at dispatch, and
/// `CandidateTreePin::require_tree` compares it against the SETTLED candidate
/// inside `promote_workspace`, before the land and before the teardown. A promote
/// parked on `approval = True` is parked carrying that pinned directive, and
/// nothing between the park and the approval may replace it: a directive
/// re-rendered from `checked_stage.op.prompt_template` carries an `Unpinned`
/// pin, `require_tree` ADMITS `Unpinned`, and the approval's checked-command
/// comparison (`program_hash`, `stage_contract_hash`) cannot see the prompt.
/// A capsule's prompt is frozen at admission, so appending an input to a parked
/// execution (an UNSCOPED channel is visible to every stage) reaches only a later
/// dispatch's render and must leave the parked directive as it is.
///
/// So: park a promote behind a gate, append to a side channel, approve — and the
/// tree that lands must be the tree that was judged.
///
/// # Why the assertion is a REFUSAL and not a landing
///
/// With the pin intact, approving a promote whose candidate is unchanged lands
/// exactly as `smoke_gold_loop_nobudget_lands_the_fixture_fix_on_trunk` proves.
/// That outcome does NOT discriminate: dropping the pin produces the same
/// landing. The discriminator needs the candidate to MOVE after validation, so
/// this smoke writes an unvalidated file into the parked candidate worktree
/// (`<repo>/agents/<execution-id>/`, `JjBackend::workspace_path`) and then asserts
/// the two things only a correct refuse path can produce:
///
///   * trunk did NOT move — the whole point, read with `git rev-parse`; and
///   * the refusal is `oci_candidate_disk_diverged`, the `oci` recorded-candidate
///     fence's named answer for a checkout carrying edits `/work` never recorded —
///     a POSITIVE observation that the promote's precondition refused the foreign
///     content before anything could land it, not an absence many causes explain.
///
/// Without the fence the land would perform on the moved candidate and this smoke
/// fails on the first of those: `implement` applies the fixture's real edit, so an
/// admitted promote genuinely advances trunk.
///
/// Model-free by construction — every stage is `agent = "shell"` or
/// `agent = "workspace_effect"` — so it spends NO budget and rides
/// `just gate-containment`'s `smoke-no-budget` step.
// 280s for the reason the gold-loop twin states: `[profile.live-smoke]` SIGKILLs
// at 300s, so a `kata_timeout` above that never fires.
#[kata_test_utils::kata_timeout(secs = 280)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_a_parked_promote_still_refuses_an_unvalidated_tree"]
async fn smoke_a_parked_promote_still_refuses_an_unvalidated_tree() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let root = kata_repo_root();
    let scratch = tempfile::tempdir().expect("scratch tempdir");
    let fixture = scratch.path().join("tally");

    // ── 1. THE FIXTURE, through the shipped materializer ────────────
    let materialize = Command::new("bash")
        .arg(root.join("scripts/materialize-gold-fixture.sh"))
        .arg(&fixture)
        .current_dir(&root)
        .output()
        .expect("run scripts/materialize-gold-fixture.sh");
    assert!(
        materialize.status.success(),
        "materialize-gold-fixture.sh failed ({}):\n{}",
        materialize.status,
        String::from_utf8_lossy(&materialize.stderr)
    );
    let trunk = git_stdout(&fixture, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let trunk_ref = format!("refs/heads/{trunk}");
    let base_sha = git_stdout(&fixture, &["rev-parse", &trunk_ref]);

    // ── 2. THE NODE, on the DEFAULT (jj) execution-workspace provider ──
    // The pack's `edit` stage authors `net = "host"`: `egress_allow` carries a
    // never-dialed authority so the declared union is non-empty.
    let node = spawn_native_jj_node_with_egress(&fixture);
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    // ── 3. SUBMIT THE PACK BY SOURCE ────────────────────────────────
    // By SOURCE, not by library name: the name form resolves against
    // `./.kata/workflows/`, which would write an untracked `.kata/` INTO the
    // fixture repository — and an untracked file in the tree is precisely what
    // this smoke goes on to inject deliberately.
    let pack_path = root.join("workflows/smoke/promote-pin-parked-nobudget-smoke.star");
    let star = std::fs::read_to_string(&pack_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", pack_path.display()));
    let exec = node
        .client()
        .run_starlark(&star, Some("promote-pin-parked-nobudget-smoke.star"))
        .await
        .expect("submit promote-pin-parked-nobudget-smoke");
    let exec_id = exec.id().to_owned();

    // ── 4. THE GATE, ON THE PROMOTE ITSELF ──────────────────────────
    let pending = await_gold_loop_gate(&node, &exec, "land", Duration::from_secs(150)).await;
    assert_eq!(
        pending.stage_name, "land",
        "the parked assignment must be the PROMOTE; if the gate parks on anything else \
         this smoke parks the wrong work unit and proves nothing"
    );
    assert_eq!(
        git_stdout(&fixture, &["rev-parse", &trunk_ref]),
        base_sha,
        "`{trunk_ref}` MOVED while the promote was still parked on its own gate"
    );

    // ── 5. THE UNVALIDATED WRITE, INTO THE PARKED CANDIDATE ─────────
    //
    // `JjBackend::workspace_path` puts an execution's candidate worktree at
    // `<repo>/agents/<execution-id>/`. `validate` has already stamped the tree it
    // judged; this file is tracked content that appeared afterwards, which is
    // exactly the state the fence exists to refuse.
    let candidate = fixture.join("agents").join(&exec_id);
    assert!(
        candidate.join(".jj").is_dir(),
        "the parked execution's candidate worktree is not at {} — this smoke wrote its \
         unvalidated file nowhere and every assertion after it would be vacuous",
        candidate.display()
    );
    std::fs::write(
        candidate.join("UNVALIDATED.txt"),
        "content that no validation criterion ever judged\n",
    )
    .expect("write the unvalidated file into the candidate worktree");

    // ── 6. AN ORDINARY OPERATOR APPEND, WHILE THE PROMOTE IS PARKED ──
    //
    // An append on a channel with NO `stage` scope, which every stage of the
    // execution sees, the parked promote included. It must not reach the
    // promote's pinned directive.
    let appended = node
        .client()
        .append_external_input(
            &exec_id,
            &kata_client::types::ExecutionExternalInputAppendRequest {
                channel: "operator_steering".to_string(),
                text: "note for the record while the gate is parked".to_string(),
                input_id: Some("ei-parked-note".to_string()),
                source: None,
                target_stage: None,
                payload: None,
            },
        )
        .await
        .expect("append an external input while the promote is parked");
    assert_eq!(
        appended.status, "appended",
        "NON-VACUITY: the append must actually have landed a NEW row, or the parked \
         promote never sees an append and this smoke measures nothing. got {:?}",
        appended.status
    );

    // ── 7. APPROVE, AND READ THE OUTCOME OUT OF GIT ─────────────────
    node.client()
        .approve(&exec_id, &pending.assignment_id)
        .await
        .expect("approve the parked promote");

    let record = exec
        .wait_for_terminal(Duration::from_secs(90))
        .await
        .expect("wait for terminal after approving the gate");

    // (1) TRUNK DID NOT MOVE. The only witness that cannot be faked by a stage's
    //     own report. A re-render that replaced the pinned directive with an
    //     `Unpinned` one would let the fence return `Ok(())` without comparing,
    //     and the tree carrying `UNVALIDATED.txt` would land on the operator's
    //     trunk: this is where the smoke goes red.
    assert_eq!(
        git_stdout(&fixture, &["rev-parse", &trunk_ref]),
        base_sha,
        "`{trunk_ref}` ADVANCED. A tree carrying `UNVALIDATED.txt` — content no \
         validation criterion ever judged — landed on the operator's trunk after an \
         append to a side channel re-rendered the parked promote's directive and dropped \
         its candidate tree pin.\nstatus={:?} error={:?}\nmain log tail:\n{}",
        record.status,
        record.error,
        log_tail(&std::fs::read_to_string(node.log_path()).unwrap_or_default())
    );

    // (2) THE REFUSAL IS THE WORKSPACE'S OWN PRECONDITION, NAMED. Under `oci`
    //     the promote's `require_clean_recorded_candidate` answers
    //     `oci_candidate_disk_diverged` for a checkout carrying edits the
    //     recorded `/work` never named — `UNVALIDATED.txt` is exactly that —
    //     and the fence refuses BEFORE any tree the run produced can land.
    //     That is the positive observation this cell exists for: the promote
    //     never performed on a tree carrying unvalidated content.
    assert_eq!(
        record.status,
        ExecutionStatus::Failed,
        "the promote had to REFUSE; got {:?} (error={:?})",
        record.status,
        record.error
    );
    let error = record.error.clone().unwrap_or_default();
    assert!(
        error.contains("oci_candidate_disk_diverged"),
        "the run failed for some OTHER reason than the recorded-candidate fence, so \
         this smoke proves nothing about the refuse path. error={error:?}\nmain log tail:\n{}",
        log_tail(&std::fs::read_to_string(node.log_path()).unwrap_or_default())
    );

    // (3) THE REFUSED WORKSPACE STANDS FOR INSPECTION — it is not parked, and
    //     it is not removed. `oci_candidate_disk_diverged` refuses the
    //     closeout park by the same fence (parking would publish the foreign
    //     tree as `parked/<exec>`), and the closeout's honest answer is the
    //     live workspace left standing: the foreign file is still on disk for
    //     the operator, and no parked ref pretends it was validated.
    assert!(
        candidate.join(".jj").is_dir() && candidate.join("UNVALIDATED.txt").is_file(),
        "the refused promote destroyed the workspace it stood on — the operator has \
         nothing to inspect: {}",
        candidate.display()
    );

    node.shutdown().await.expect("clean shutdown");
}
async fn submit_pack(
    node: &NodeHandle,
    source: &str,
    filename: &str,
) -> (String, kata_client::types::ExecutionRecord) {
    let exec = node
        .client()
        .run_starlark(source, Some(filename))
        .await
        .expect("submit the pack");
    let id = exec.id().to_string();
    let record = exec
        .wait_for_terminal(Duration::from_secs(120))
        .await
        .expect("wait for terminal");
    (id, record)
}

// ---------------------------------------------------------------------------
// The DEFAULT exit policy terminalizes, and `content` is the declared opt-out
// ---------------------------------------------------------------------------

/// A scenario generated rather than shipped: one `run=` shell stage on a
/// `workspace-ro` view whose body prints a marker on stderr and exits 2, with
/// stdout empty.
///
/// The stage authors NO `exit_policy=`, which is the whole subject: under a
/// `content` default this would COMPLETE — a confinement failure wearing a green.
///
/// `sandbox = "ro"` + `sandbox_profile(net = "host")` is copied from the rig
/// `workflows/smoke/sandbox-smoke-shell-workspace-ro.star` on purpose: it reaches
/// `workspace-ro` on a plain `spawn_supervised_main` node, with no operator root
/// and no toolchain store to provision, so this witness measures the EXIT plane
/// and nothing else.
const DEFAULT_EXIT_POLICY_PACK: &str = r#"
probe = stage(
    id = "probe",
    agent = "shell",
    sandbox = "ro",
    # Under `oci` the exit-policy question is the EXIT STATUS alone — an ro
    # stage's /work write is adoption-refused (`work_delta_out_of_scope`),
    # never a nonzero exit, so this body fails on a plain `exit`
    # with a stderr tail the refusal must name.
    run = "printf 'the-exit-policy-marker\\n' >&2\nexit 2",
)

workflow(
    "exit-policy-default-terminalizes",
    description = "A contained stage exits nonzero: default exit_policy terminalizes it.",
    root = [probe],
    sandbox_profiles = {"ro": sandbox_profile(net = "host")},
)
"#;

/// The SAME pack with the one declared opt-out. DERIVED from
/// [`DEFAULT_EXIT_POLICY_PACK`] by substitution rather than written out, because a
/// second copy is a second thing to keep in step and the claim is precisely that
/// the two differ by ONE kwarg.
fn exit_policy_opt_out_pack() -> String {
    let derived = DEFAULT_EXIT_POLICY_PACK.replace(
        "    run = \"printf 'the-exit-policy-marker\\\\n' >&2\\nexit 2\",\n",
        "    run = \"printf 'the-exit-policy-marker\\\\n' >&2\\nexit 2\",\n    exit_policy = \"content\",\n",
    );
    assert_ne!(
        derived, DEFAULT_EXIT_POLICY_PACK,
        "NON-VACUITY: the opt-out pack must actually differ from the default pack"
    );
    derived.replace(
        "\"exit-policy-default-terminalizes\"",
        "\"exit-policy-content-opt-out\"",
    )
}

/// **LIVE THROUGH THE PRODUCT PATH: a nonzero shell exit
/// FAILS a stage that authored no `exit_policy=`, and a stage that DECLARES
/// `exit_policy = "content"` still completes on the identical body.**
///
/// # Why the default terminalizes
///
/// A body that fails exits nonzero with its reason on stderr and `content`
/// EMPTY (here `exit_code = 2`). A write to the default `workspace-ro` `/work`
/// is not such a failure under `oci` — the mount is writable, and a delta the
/// write leaves is refused at adoption as `work_delta_out_of_scope` whatever
/// the exit status.
/// Under an `exit_policy = "content"` default the failing stage would COMPLETE,
/// and what surfaces downstream is *"content is not valid JSON: EOF while
/// parsing a value at line 1 column 0"*: a message about JSON for a cause that
/// is the command's own failure. **A stage with no `outputs=` schema would
/// complete silently with nothing at all** — which is how a failing command
/// hides under a green suite.
///
/// # Why BOTH arms, and why they are one body
///
/// A default that only makes things fail could be satisfied by breaking the
/// exit plane outright. ARM 2 is the refutation: the SAME body, the SAME view, the
/// same nonzero exit, one added kwarg, and it completes with the nonzero code
/// recorded at its output's root `exit_code`. The
/// opt-out pack is DERIVED from the subject pack by substitution
/// ([`exit_policy_opt_out_pack`]), so the two cannot drift apart into a comparison
/// that proves nothing.
///
/// # What is asserted, and what is NOT
///
/// ARM 1 reads the FAILURE REASON, not a status alone: the refusal must name the exit code, the
/// stderr tail and the policy, so a `Failed` carrying a bare "internal error" would satisfy the
/// status assertion and not the contract. ARM 2 reads the nonzero exit code back OUT of the
/// completed record's root `exit_code`, which is the positive half — completing is not enough; it
/// must complete having actually failed the write.
///
/// **The honest limit:** this is one kernel, one rootless OCI container under
/// the pinned youki, one shell. It proves the exit code meets the policy at the
/// capsule settlement's `ShellExitPolicy::judge_exit` on the product path; it does not prove the population of shipped packs is free
/// of stages that WANT a nonzero exit swallowed — that is a census, taken separately
/// against `workflows/**`, and it found none.
#[kata_test_utils::kata_timeout(secs = 120)]
#[tokio::test]
#[ignore = "live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_default_exit_policy_terminalizes"]
async fn smoke_default_exit_policy_terminalizes() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    // `sandbox = "ro"` materializes `net = "host"` — the node's egress union
    // must be non-empty, so the node declares a never-dialed authority.
    let node = spawn_shell_node_with_egress();
    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await healthy");

    // ---- ARM 1: SUBJECT — no `exit_policy=` authored, and it must FAIL ----
    let (_subject_id, subject) = submit_pack(
        &node,
        DEFAULT_EXIT_POLICY_PACK,
        "exit-policy-default-terminalizes.star",
    )
    .await;
    assert_eq!(
        subject.status,
        ExecutionStatus::Failed,
        "THE CLAIM: a contained stage that exits nonzero must FAIL, not complete \
         with empty content. Under a `content` default this run would COMPLETE; \
         under `oci` the in-capsule exit IS the judgement (no wrap writes \
         EROFS — `work_delta_out_of_scope` owns the ro-write half). \
         error={:?} outputs={:?}",
        subject.error,
        subject.outputs
    );
    let reason = subject.error.clone().unwrap_or_default();
    for needle in [
        kata_types::workflow::SHELL_NONZERO_EXIT_ERROR_PREFIX,
        "exit_code=",
        "exit_policy=",
        "the-exit-policy-marker",
    ] {
        assert!(
            reason.contains(needle),
            "the default exit policy requires the refusal to NAME the exit code, the stderr tail and the \
             policy — {needle:?} is missing from: {reason}"
        );
    }

    // ---- ARM 2: OPT-OUT — one kwarg, same body, and it COMPLETES ----
    let opt_out = exit_policy_opt_out_pack();
    let (_opt_out_id, completed) =
        submit_pack(&node, &opt_out, "exit-policy-content-opt-out.star").await;
    assert_eq!(
        completed.status,
        ExecutionStatus::Completed,
        "THE REFUTATION: the identical body declaring `exit_policy = \"content\"` must still \
         complete — only the DEFAULT terminalizes; an explicit `content` policy still \
         completes on a nonzero exit. \
         (Under `oci` this arm writes nothing to `/work`: an ro-view write is \
         `work_delta_out_of_scope`, a posture refusal \
         that no exit policy reaches — exercised separately by \
         `smoke_shell_workspace_ro_sub_second`.) error={:?}",
        completed.error
    );
    // Under `oci` the exit code is the root `exit_code` of the stage's
    // `capsule_result` envelope (`kata_core::operational::capsule_result_output`),
    // the engine-owned judge's output.
    let probe_output = completed
        .outputs
        .as_ref()
        .and_then(|o| o.get("probe"))
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "the opt-out record must carry a probe output; got {:?}",
                completed.outputs
            )
        });
    let exit_code = probe_output
        .get("exit_code")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_else(|| {
            panic!(
                "the completed opt-out record must carry the capsule_result envelope's exit_code; \
             probe output={probe_output:?}"
            )
        });
    assert_ne!(
        exit_code, 0,
        "POSITIVE HALF: completing is not the claim — completing having ACTUALLY exited nonzero \
         is. A zero here would mean the write succeeded and this arm compares nothing."
    );

    node.shutdown().await.expect("clean shutdown");
}
