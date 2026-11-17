//! Live binary smoke tests for the `live` module.
//!
//! These tests are `#[ignore]`'d by default — they spawn real
//! `kata` and `kata-worker` processes from
//! `target/release/`, and would fail any developer who hasn't
//! run the canonical smoke recipe. The `live-smoke` nextest profile
//! serializes every installed-main smoke against the production uid-scoped
//! discovery lease and fixed owner-home attachment descriptor.
//!
//! For now, run them locally via:
//!
//! ```sh
//! just smoke
//! ```
//!
//! The `KATA_LIVE_SMOKE` env gate is belt-and-braces. `--run-ignored
//! all` already opts ignored tests in; the env check makes the test
//! a no-op when nextest decides to run an ignored test in some other
//! context (`-E test(...)` filters, future CI configs, etc.).

use std::process::Stdio;
use std::time::Duration;

use kata_client::KataClient;
use kata_test_utils::live::{CapacityTopology, NodeHandle, WorkerHandle};
use kata_types::agent::BackendType;
use kata_types::execution::ExecutionStatus;
use kata_types::identity::WorkerResource;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Value, json};

use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use ulid::Ulid;

/// How long one JSON-RPC round trip to an attached `kata mcp` may take.
///
/// The MCP server answers `initialize`, `tools/call run` and `tools/call
/// observe` against an already-healthy installed main, so a reply is a local
/// socket round trip plus a ledger write — tens of milliseconds. 20s is three
/// orders of magnitude of headroom for a loaded host while still being an order
/// of magnitude below the 90s `#[kata_timeout]` on the smoke that uses it, so a
/// stuck MCP names ITSELF instead of consuming the whole test budget.
const MCP_CALL_DEADLINE: Duration = Duration::from_secs(20);

/// An attached `kata mcp` process, driven over JSON-RPC on stdio.
///
/// **Async on purpose.** A blocking read on the CURRENT_THREAD runtime that
/// `#[tokio::test]` builds stops the timer wheel, so an MCP that never replied
/// would hang until this smoke's `#[kata_timeout(secs = 90)]` watchdog, which
/// names the test and not the MCP. Every wait here is a future under a deadline
/// that names its own subject.
struct AttachedMcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl AttachedMcp {
    fn spawn() -> Self {
        let bin_dir = std::env::var_os("KATA_LIVE_BIN_DIR").map_or_else(
            kata_test_utils::live::testing::workspace_target_release,
            std::path::PathBuf::from,
        );
        let mut child = tokio::process::Command::new(bin_dir.join("kata"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn attached kata mcp");
        let stdin = child.stdin.take().expect("mcp stdin");
        let stdout = BufReader::new(child.stdout.take().expect("mcp stdout"));
        Self {
            child,
            stdin: Some(stdin),
            stdout,
        }
    }

    async fn call(&mut self, request: Value) -> Value {
        let stdin = self.stdin.as_mut().expect("MCP stdin is open");
        let round_trip = async {
            stdin
                .write_all(format!("{request}\n").as_bytes())
                .await
                .expect("write MCP request");
            stdin.flush().await.expect("flush MCP request");
            let mut line = String::new();
            self.stdout
                .read_line(&mut line)
                .await
                .expect("read MCP reply");
            line
        };
        let Ok(line) = tokio::time::timeout(MCP_CALL_DEADLINE, round_trip).await else {
            panic!(
                "MCP_CALL_DEADLINE: attached `kata mcp` did not answer within \
                 {MCP_CALL_DEADLINE:?}. Unanswered request: {request}"
            )
        };
        assert!(!line.is_empty(), "MCP exited before replying to {request}");
        serde_json::from_str(&line).expect("MCP stdout is JSON-RPC")
    }

    async fn shutdown(mut self) {
        // Closing stdin is the shutdown signal; the process must then exit on
        // its own. Bounded, because "must exit" is the assertion and an
        // unbounded wait cannot distinguish a slow exit from a refusal.
        drop(self.stdin.take());
        let Ok(status) = tokio::time::timeout(MCP_CALL_DEADLINE, self.child.wait()).await else {
            panic!(
                "MCP_CALL_DEADLINE: attached `kata mcp` did not exit within \
                 {MCP_CALL_DEADLINE:?} of its stdin closing"
            )
        };
        let status = status.expect("wait for MCP");
        assert!(status.success(), "attached kata mcp exited {status:?}");
    }
}

/// Mirror the product's fixed effective-owner attachment location without
/// linking the test-utils crate back to the `kata` binary crate. Real release
/// smokes exercise this path exactly; only cfg(test) unit-harness children have
/// an isolated descriptor seam.
fn fixed_installed_attachment_path() -> std::path::PathBuf {
    let uid = nix::unistd::Uid::effective();
    let owner = nix::unistd::User::from_uid(uid)
        .expect("resolve effective owner account")
        .unwrap_or_else(|| panic!("effective owner uid {uid} has no account record"));
    #[cfg(target_os = "macos")]
    {
        owner
            .dir
            .join("Library")
            .join("Application Support")
            .join("Kata")
            .join("main-attachment.json")
    }
    #[cfg(not(target_os = "macos"))]
    {
        owner
            .dir
            .join(".local")
            .join("state")
            .join("kata")
            .join("main-attachment.json")
    }
}

fn require_fixed_attachment_absent(path: &std::path::Path, phase: &str) {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!(
            "cannot inspect fixed installed-main attachment {} {phase}: {error}",
            path.display()
        ),
        Ok(_) => panic!(
            "fixed installed-main attachment {} exists {phase}; stop Kata and remove only verified stale owner state before running real installed-main smokes",
            path.display()
        ),
    }
}

/// Read one stage's latest status from the authoritative transition chain without
/// opening any kata writer or recovery machinery. The live restart receipt uses
/// this narrow probe to prove SIGINT lands after the durable sleep transition,
/// rather than relying on a timing delay after its predecessor completes.
fn durable_stage_status(
    data_dir: &std::path::Path,
    execution_id: &str,
    stage_name: &str,
) -> Option<String> {
    let execution_id = execution_id
        .parse::<Ulid>()
        .expect("execution id is a ULID");
    let connection = Connection::open_with_flags(
        data_dir.join("operational.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open authoritative operational chain read-only");
    // `attempt_projection`, not raw `transitions`: the projection is the durable
    // answer on BOTH arms — under `oci` a stage's terminal frames may not carry
    // `folds_projection`, but the projected attempt state is the same
    // stamped vocabulary either way.
    connection
        .query_row(
            "SELECT state FROM attempt_projection \
             WHERE execution_id = ?1 AND stage_id = ?2 \
             ORDER BY attempt_ordinal DESC LIMIT 1",
            params![execution_id.to_bytes().as_ref(), stage_name],
            |row| row.get::<_, String>(0),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .expect("read authoritative stage status")
}

/// Installed main supervising its node: spawn → health → shutdown. Validates
/// the simplest live path. Catches:
///   * binary discovery (`KATA_LIVE_BIN_DIR` / `target/release`),
///   * config gen + `kata config check`,
///   * SDK client construction against the assigned port,
///   * `await_healthy` polling cadence,
///   * graceful shutdown (no leftover pidfile).
#[kata_test_utils::kata_timeout(secs = 60)]
#[tokio::test]
#[ignore = "live binary smoke; run with `just smoke node_handle_spawn_health_shutdown`"]
async fn node_handle_spawn_health_shutdown() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let node = NodeHandle::spawn_supervised_main().expect("spawn installed main");
    assert_eq!(node.capacity_topology(), CapacityTopology::SupervisedNode);
    assert!(
        node.api_url().starts_with("http://127.0.0.1:"),
        "api_url should be loopback: {}",
        node.api_url()
    );

    node.await_healthy(Duration::from_secs(30))
        .await
        .expect("await_healthy");

    let h = node.client().health().await.expect("health");
    assert!(
        !h.subsystems.is_empty(),
        "installed main must report at least one subsystem"
    );
    assert!(h.is_healthy(), "main subsystems must be healthy: {h:?}");

    node.shutdown().await.expect("clean shutdown");
}

/// Installed main + external local worker: spawn the main, provision a worker
/// pointed at it, assert the worker registers via the main's
/// health snapshot (worker count > 0 once the worker pool
/// supervisor sees the registration). Pin for the multi-process
/// dance.
#[kata_test_utils::kata_timeout(secs = 60)]
#[tokio::test]
#[ignore = "live binary smoke; run with `just smoke main_plus_local_worker_registration`"]
async fn main_plus_local_worker_registration() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let main = NodeHandle::spawn_main_with_local_socket().expect("spawn installed main");
    assert_eq!(main.capacity_topology(), CapacityTopology::LocalSocket);
    assert!(
        main.enrollment_secret().is_some(),
        "local-socket capacity must expose an enrollment secret"
    );
    assert!(
        main.worker_socket().is_some(),
        "local-socket capacity must expose a worker socket"
    );

    let caps = vec![
        WorkerResource::Shell,
        WorkerResource::AgentBackend(BackendType::Harness),
    ];
    let worker = WorkerHandle::spawn(&main, &caps).expect("spawn shell-only worker");
    assert!(worker.pid() > 0, "worker pid should be non-zero");

    main.await_healthy(Duration::from_secs(30))
        .await
        .expect("main healthy after external local capacity registered");

    // Prove the exact external transport registered. A generic log match can
    // false-pass on a supervised node, so use the typed inventory and require
    // that the one live worker is the external one.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut inventory = Vec::new();
    while std::time::Instant::now() < deadline {
        inventory = main.client().list_workers().await.unwrap_or_default();
        if inventory
            .iter()
            .any(|worker| worker.alive && worker.transport == "local_socket")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        inventory
            .iter()
            .any(|worker| worker.alive && worker.transport == "local_socket"),
        "external local-socket worker did not register: {inventory:?}"
    );
    assert_eq!(
        inventory.iter().filter(|worker| worker.alive).count(),
        1,
        "a local-socket-only config must start no supervised node beside the external \
         worker: {inventory:?}"
    );

    // Registration alone is not enough: dispatch a checked stage and require
    // terminal attribution to the external worker identity.
    let execution = main
        .client()
        .run_starlark(
            r#"
probe = stage(
    id = "probe",
    agent = "shell",
    prompt = "printf '{\"ok\":true}\\n'",
    outputs = {"ok": "bool"},
)
workflow("local-capacity-live-proof", root = [probe])
"#,
            Some("local-capacity-live-proof.star"),
        )
        .await
        .expect("submit checked local-capacity workflow");
    let record = execution
        .wait_for_terminal(Duration::from_secs(30))
        .await
        .expect("local-capacity workflow reaches terminal state");
    assert_eq!(record.status, ExecutionStatus::Completed, "{record:?}");
    assert!(
        record.worker_id.starts_with("local-worker-"),
        "execution must be attributed to external local capacity: {record:?}"
    );

    worker.shutdown().await.expect("worker shutdown");

    // A real peer close (not a main-side explicit transport shutdown) must free
    // the configured slot and admit replacement capacity.
    let replacement = WorkerHandle::spawn(&main, &caps).expect("replacement shell-only worker");
    // A state-poll loop gets >=30s unless the tight bound IS the assertion. It
    // is not here — the assertion is that a peer close frees the slot at all,
    // not that it does so inside ten seconds — and this smoke can run beside
    // several concurrent builds, so a tight bound only converts host load into
    // a red that says nothing about slot reclamation.
    let replacement_deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let workers = main.client().list_workers().await.unwrap_or_default();
        if workers
            .iter()
            .any(|worker| worker.alive && worker.id == "local-worker-1")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < replacement_deadline,
            "peer-close slot was not reclaimed for replacement: {workers:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let replacement_run = main
        .client()
        .run_starlark(
            r#"
probe = stage(
    id = "probe",
    agent = "shell",
    prompt = "printf '{\"replacement\":true}\\n'",
    outputs = {"replacement": "bool"},
)
workflow("local-capacity-replacement-proof", root = [probe])
"#,
            Some("local-capacity-replacement-proof.star"),
        )
        .await
        .expect("submit through replacement worker");
    let replacement_record = replacement_run
        .wait_for_terminal(Duration::from_secs(30))
        .await
        .expect("replacement workflow terminal");
    assert_eq!(
        replacement_record.status,
        ExecutionStatus::Completed,
        "replacement shell-only workflow failed: {replacement_record:?}"
    );
    assert_eq!(replacement_record.worker_id, "local-worker-1");
    replacement.shutdown().await.expect("replacement shutdown");
    main.shutdown().await.expect("main shutdown");
}

/// Two independently constructed clients attach to one
/// installed main and observe one execution identity. Rebooting the main on the
/// same data directory preserves both the directory authority and execution;
/// only the per-process generation changes. The workflow is model-free.
#[kata_test_utils::kata_timeout(secs = 90)]
#[tokio::test]
#[ignore = "live binary smoke; run with `just smoke installed_main_two_clients_share_execution_across_restart`"]
async fn installed_main_two_clients_share_execution_across_restart() {
    if std::env::var("KATA_LIVE_SMOKE").is_err() {
        return;
    }

    let data_dir = tempfile::tempdir().expect("data dir");
    let path = data_dir.path().to_path_buf();
    let attachment = fixed_installed_attachment_path();
    require_fixed_attachment_absent(&attachment, "before the smoke");
    let main = NodeHandle::spawn_supervised_main_with_data_dir_and_env(path.clone(), Vec::new())
        .expect("spawn installed main");
    if let Err(error) = main.await_healthy(Duration::from_secs(30)).await {
        let log = std::fs::read_to_string(main.log_path())
            .unwrap_or_else(|read_error| format!("<failed to read kata.log: {read_error}>"));
        panic!("main healthy: {error}; kata.log:\n{log}");
    }
    // 30s, not 5s. The descriptor is published SECONDS AFTER the port opens,
    // so this poll is measuring exactly the gap a tight bound is worst at, and
    // the assertion is that publication happens, not that it happens fast.
    let attachment_deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !attachment.exists() && std::time::Instant::now() < attachment_deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        attachment.exists(),
        "installed-main attachment was not published at {} within 30s of the main reporting \
         healthy",
        attachment.display()
    );

    let contender =
        NodeHandle::spawn_supervised_main_with_data_dir_and_env(path.clone(), Vec::new())
            .expect("spawn lock contender process");
    let lock_before =
        std::fs::read(path.join("main.lock")).expect("read authoritative lock metadata");
    assert!(
        contender
            .await_healthy(Duration::from_secs(2))
            .await
            .is_err(),
        "a second installed main must lose before opening the shared authority"
    );
    let contender_log = std::fs::read_to_string(contender.log_path()).unwrap_or_default();
    assert!(
        contender_log.contains("already locked") || contender_log.contains("discovery lease"),
        "contender must lose at an authority lock, not an unrelated boot error: {contender_log}"
    );
    assert_eq!(
        std::fs::read(path.join("main.lock")).expect("re-read authoritative lock metadata"),
        lock_before,
        "losing contender must not rewrite shared authority metadata"
    );
    contender
        .shutdown()
        .await
        .expect("reap rejected main contender");

    let client_a = KataClient::new(main.api_url()).expect("client A");
    let client_b = KataClient::new(main.api_url()).expect("client B");
    let status_a = client_a.system_status().await.expect("client A status");
    let status_b = client_b.system_status().await.expect("client B status");
    assert_eq!(status_a.node_id, status_b.node_id);
    assert_eq!(status_a.directory_id, status_b.directory_id);
    assert_eq!(status_a.process_generation, status_b.process_generation);
    assert_eq!(status_a.process_mode, "installed");

    // Under `oci` a host-side marker file is not readable from inside the
    // capsule — "before must not re-run during recovery" is the durable
    // question, so the assertion after the restart counts the stage's minted
    // attempts in `attempt_projection` instead of lines in a host file.
    let workflow = r#"
before = stage(
    id = "before",
    agent = "shell",
    prompt = "printf '{\"ok\":true}\\n'",
    outputs = {"ok": "bool"},
)
pause = sleep(id = "pause", for_ms = 5000, depends_on = [before])
after = stage(
    id = "after",
    agent = "shell",
    prompt = "printf '{\"resumed\":true}\\n'",
    depends_on = [pause],
    outputs = {"resumed": "bool"},
)
workflow("two-client-restart", root = [after])
"#;
    let mut mcp_a = AttachedMcp::spawn();
    let mut mcp_b = AttachedMcp::spawn();
    for (id, mcp) in [(1, &mut mcp_a), (2, &mut mcp_b)] {
        let init = mcp
            .call(json!({
                "jsonrpc": "2.0", "id": id, "method": "initialize", "params": {}
            }))
            .await;
        assert_eq!(init["result"]["serverInfo"]["name"], "kata-mcp");
    }
    let run = mcp_a
        .call(json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "run", "arguments": {
                "workflow_starlark": workflow,
                "workflow_filename": "two-client-restart.star"
            }}
        }))
        .await;
    let execution_id = run["result"]["structuredContent"]["data"]["execution_id"]
        .as_str()
        .unwrap_or_else(|| panic!("MCP A returned an execution id: {run}"))
        .to_string();
    let observed = mcp_b
        .call(json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "observe", "arguments": {"execution_id": execution_id.clone()}}
        }))
        .await;
    assert_eq!(
        observed["result"]["structuredContent"]["data"]["execution_id"],
        execution_id
    );
    // 30s, not 10s. The workflow's `before` stage has to be dispatched, run a
    // real shell, and be durably recorded before `pause` can park at all, so
    // this budget is covering a whole dispatch round-trip on a host that may be
    // running several concurrent builds — and the assertion is that the sleep parks
    // DURABLY, never that it parks within ten seconds.
    let park_deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        // The durable sleep parks as `awaiting_timer` in the stamped
        // vocabulary: the capsule arm's main-resolved timer stamps the timer
        // spelling.
        if durable_stage_status(&path, &execution_id, "pause").as_deref() == Some("awaiting_timer")
        {
            break;
        }
        assert!(
            std::time::Instant::now() < park_deadline,
            "sleep stage never reached its durable AwaitingTimer park; before output: {:?}",
            client_b.get_stage_output(&execution_id, "before").await
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    mcp_a.shutdown().await;
    mcp_b.shutdown().await;

    let directory_id = status_a.directory_id.expect("installed directory id");
    let first_generation = status_a
        .process_generation
        .expect("installed process generation");
    main.interrupt().await.expect("first main SIGINT shutdown");
    assert!(
        !attachment.exists(),
        "graceful SIGINT must remove installed attachment before releasing authority"
    );

    let restarted =
        NodeHandle::spawn_supervised_main_with_data_dir_and_env(path.clone(), Vec::new())
            .expect("restart installed main");
    restarted
        .await_healthy(Duration::from_secs(30))
        .await
        .expect("restarted main healthy");
    let client_after_restart = KataClient::new(restarted.api_url()).expect("post-restart client");
    let restarted_status = client_after_restart
        .system_status()
        .await
        .expect("restarted status");
    assert_eq!(restarted_status.node_id, status_b.node_id);
    assert_eq!(
        restarted_status.directory_id.as_deref(),
        Some(directory_id.as_str())
    );
    assert_ne!(
        restarted_status.process_generation.as_deref(),
        Some(first_generation.as_str())
    );
    let recovered = client_after_restart
        .observe(&execution_id)
        .await
        .expect("execution remains visible after restart");
    assert_eq!(recovered.id, execution_id);
    // 30s, not 15s. The assertion is that the durable sleep is REARMED across a
    // restart and eventually fires — a property, not a latency — and the
    // remaining `after` stage still has to dispatch and complete behind it.
    let terminal_deadline = std::time::Instant::now() + Duration::from_secs(30);
    let terminal = loop {
        let record = client_after_restart
            .observe(&execution_id)
            .await
            .expect("poll recovered durable sleep");
        if record.status.is_terminal() {
            break record;
        }
        assert!(
            std::time::Instant::now() < terminal_deadline,
            "rearmed durable sleep did not fire after restart: {record:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(
        terminal.status,
        ExecutionStatus::Completed,
        "recovered durable sleep terminalized unexpectedly: {terminal:?}; restarted kata.log:\n{}",
        std::fs::read_to_string(restarted.log_path())
            .unwrap_or_else(|error| format!("<failed to read kata.log: {error}>"))
    );
    assert!(
        terminal
            .outputs
            .as_ref()
            .is_some_and(|outputs| outputs.contains_key("after"))
    );
    let before_ulid = execution_id
        .parse::<Ulid>()
        .expect("execution id is a ULID");
    let before_attempts: i64 = Connection::open_with_flags(
        path.join("operational.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("read operational authority")
    .query_row(
        "SELECT count(*) FROM attempt_projection \
         WHERE execution_id = ?1 AND stage_id = 'before'",
        params![before_ulid.to_bytes().as_ref()],
        |row| row.get(0),
    )
    .expect("count before's minted attempts");
    assert_eq!(
        before_attempts, 1,
        "the pre-sleep stage must not re-run during recovery — exactly one minted attempt"
    );

    let second_generation = restarted_status
        .process_generation
        .expect("second process generation");
    restarted.kill_now().await.expect("SIGKILL restarted main");
    assert!(
        attachment.exists(),
        "SIGKILL leaves stale attachment metadata; it is not kernel authority"
    );

    let after_host_loss = NodeHandle::spawn_supervised_main_with_data_dir_and_env(path, Vec::new())
        .expect("restart after abrupt host loss");
    after_host_loss
        .await_healthy(Duration::from_secs(30))
        .await
        .expect("main healthy after SIGKILL recovery");
    let host_loss_status = after_host_loss
        .client()
        .system_status()
        .await
        .expect("status after SIGKILL recovery");
    assert_eq!(
        host_loss_status.directory_id.as_deref(),
        Some(directory_id.as_str())
    );
    assert_ne!(
        host_loss_status.process_generation.as_deref(),
        Some(second_generation.as_str())
    );
    assert_eq!(
        after_host_loss
            .client()
            .observe(&execution_id)
            .await
            .expect("terminal execution survives SIGKILL")
            .status,
        ExecutionStatus::Completed
    );
    after_host_loss
        .shutdown()
        .await
        .expect("final main shutdown");
    require_fixed_attachment_absent(&attachment, "after the smoke");
}
