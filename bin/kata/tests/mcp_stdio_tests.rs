//! Acceptance: the `kata mcp` stdio JSON-RPC server.
//!
//! These drive the REAL `kata` binary (`CARGO_BIN_EXE_kata`) over piped
//! stdin/stdout, so the assertions cover the full spawn → parse → dispatch →
//! frame path an agent driver exercises — not just an internal helper.
//!
//! Two shapes:
//! * The transport/parse tests run `kata mcp --no-engine` (author/check bind
//!   locally; node-dependent ops return the structured "requires a running
//!   node" error). The server exits at stdin EOF, so they write all requests,
//!   drop stdin, and read stdout to completion — no poll loop can hang.
//! * `kata mcp` boots no engine of its own: the deleted scratch flags are
//!   refused at parse. The DEFAULT attached binding is driven by
//!   `contract_parity::attached_kata_mcp_serves_every_form_the_skill_advertises`
//!   (`kata mcp --connect` against a loopback installed-mode rig); driving
//!   `run`/`observe` to terminal against an installed main is a live-host
//!   property, exercised by the OCI live cells.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use kata_op_contract::Operation;
use serde_json::{Value, json};

/// A bundled stdlib workflow that compiles cleanly through preflight, resolved
/// via the workflow crate's compile-time manifest fallback regardless of CWD.
/// The pack must CHECK under the shipped `oci` default a node-less
/// `kata check` reads — `kata-work-item` is confined; the `sandbox = "host"`
/// packs (kata-loop-lite) are refused by name there until the deletion ports
/// them.
const BUNDLED_WORKFLOW: &str = "kata-work-item";

/// `kata mcp`, run in `project` — never in the directory this test inherited.
///
/// nextest runs this binary with the package directory (`bin/kata`) as its
/// working directory; every spawn goes through here so each child starts in an
/// empty, test-owned directory that test can inspect, never in the source tree.
fn kata_mcp(project: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kata"));
    command.arg("mcp").current_dir(project);
    command
}

/// Spawn `kata mcp`, feed it `requests` (one JSON object per line), close
/// stdin, and return `(stdout_frames, stderr_text)`. Every non-empty stdout
/// line is parsed as JSON — a parse failure fails the test, which is itself the
/// "stdout is protocol-only" assertion.
fn drive_mcp(requests: &[Value]) -> (Vec<Value>, String) {
    let project = tempfile::tempdir().expect("project directory for `kata mcp`");
    let mut child = kata_mcp(project.path())
        // These tests pin the engine-free local behaviour.
        .arg("--no-engine")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn `kata mcp`");

    {
        let mut stdin = child.stdin.take().expect("child stdin");
        for request in requests {
            writeln!(stdin, "{request}").expect("write request line");
        }
        // Drop stdin → EOF → the server drains its loop and exits.
    }

    let output = child.wait_with_output().expect("wait for `kata mcp`");
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf8");

    let frames = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap_or_else(|e| {
                panic!("stdout carried a non-JSON-RPC line (must be protocol-only): {e}\n{line}")
            })
        })
        .collect::<Vec<_>>();
    (frames, stderr)
}

fn frame_by_id(frames: &[Value], id: i64) -> &Value {
    frames
        .iter()
        .find(|frame| frame["id"] == json!(id))
        .unwrap_or_else(|| panic!("no response frame with id {id}; frames: {frames:?}"))
}

#[test]
fn stdio_server_drives_initialize_list_and_call() {
    let requests = vec![
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
        // A notification (no id) MUST NOT produce a response frame.
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "check", "arguments": { "workflow": BUNDLED_WORKFLOW } }
        }),
        // Node-dependent op → structured JSON-RPC error carrying the OpError.
        json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": { "name": "observe", "arguments": { "execution_id": "01H" } }
        }),
        // Malformed frame is emitted raw (not valid JSON) to prove the parser
        // recovers with a JSON-RPC error instead of panicking.
    ];

    // Build the input with an extra malformed line appended after the batch.
    let project = tempfile::tempdir().expect("project directory for `kata mcp`");
    let mut child = kata_mcp(project.path())
        .arg("--no-engine")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn `kata mcp`");
    {
        let mut stdin = child.stdin.take().expect("child stdin");
        for request in &requests {
            writeln!(stdin, "{request}").expect("write request");
        }
        writeln!(stdin, "{{ this is not json").expect("write malformed line");
    }
    let output = child.wait_with_output().expect("wait");
    assert!(
        output.status.success(),
        "server exits cleanly at EOF; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let frames: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("non-protocol stdout: {e}\n{l}"))
        })
        .collect();

    // Every stdout frame is a JSON-RPC 2.0 message — stdout is protocol-only.
    for frame in &frames {
        assert_eq!(
            frame["jsonrpc"], "2.0",
            "every stdout frame is JSON-RPC 2.0"
        );
    }

    // initialize → capabilities.tools + serverInfo.
    let init = frame_by_id(&frames, 1);
    assert_eq!(init["result"]["serverInfo"]["name"], "kata-mcp");
    assert!(init["result"]["capabilities"]["tools"].is_object());

    // tools/list → every OPERATE-callable Operation with a non-empty
    // inputSchema. The six ops above the ceiling are not advertised, so
    // this is the REAL-BINARY proof that an agent's list is its capability.
    let list = frame_by_id(&frames, 2);
    let tools = list["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        ["author", "check", "run", "observe", "list"],
        "the stdio surface advertises exactly the tools it can call"
    );
    assert!(
        tools.len() < Operation::ALL.len(),
        "the contract still has {} operations; the surface advertises fewer",
        Operation::ALL.len()
    );
    for tool in tools {
        assert!(
            tool["inputSchema"].is_object(),
            "{} inputSchema is a non-empty object",
            tool["name"]
        );
    }

    // tools/call check → a valid ok OpEnvelope.
    let check = frame_by_id(&frames, 3);
    let structured = &check["result"]["structuredContent"];
    assert_eq!(structured["op"], "check");
    assert_eq!(structured["ok"], true);
    assert_eq!(structured["schema_version"], 1);
    assert_eq!(structured["data"]["name"], BUNDLED_WORKFLOW);
    assert_eq!(structured["data"]["passed"], true);
    assert_eq!(check["result"]["isError"], false);

    // tools/call observe → JSON-RPC error carrying the typed OpError.
    let observe = frame_by_id(&frames, 4);
    assert_eq!(observe["error"]["data"]["code"], "network");
    assert_eq!(observe["error"]["data"]["retryable"], true);
    assert_eq!(observe["error"]["data"]["exit_code"], 6);

    // The malformed trailing line → a parse error with null id, no panic.
    let parse_error = frames
        .iter()
        .find(|f| f["id"] == Value::Null && f.get("error").is_some())
        .expect("malformed line yields a null-id parse error");
    assert_eq!(parse_error["error"]["code"], -32700);

    // No notification response leaked: exactly the 4 id'd responses + 1 parse
    // error frame, and none carries id 0 or a notification method echo.
    assert_eq!(
        frames.len(),
        5,
        "4 request replies + 1 parse error; frames: {frames:?}"
    );
}

#[test]
fn unknown_method_and_tool_are_graceful_errors() {
    let (frames, _stderr) = drive_mcp(&[
        json!({ "jsonrpc": "2.0", "id": 10, "method": "does/not/exist", "params": {} }),
        json!({
            "jsonrpc": "2.0", "id": 11, "method": "tools/call",
            "params": { "name": "no-such-tool", "arguments": {} }
        }),
    ]);
    assert_eq!(frame_by_id(&frames, 10)["error"]["code"], -32601);
    assert_eq!(frame_by_id(&frames, 11)["error"]["code"], -32602);
}

// ---------------------------------------------------------------------------
// No engine of its own
// ---------------------------------------------------------------------------

/// **`kata mcp` boots no engine: its deleted scratch flags are refused at
/// parse.** A stage runs on the installed main's node, a separate
/// `kata-worker` process; `kata mcp` attaches to that main or binds none. Each
/// of `--scratch`, `--config <path>` and `--data-dir <path>` is refused by
/// clap's unknown-argument usage error (exit 2) naming the flag, no JSON-RPC
/// frame is answered, and the directory the server was started in, and the
/// named data directory, are left exactly as they were.
///
/// **Would red if:** any of the three flags were accepted again (watched at
/// the base, where `--scratch` booted an engine and refused only later, with
/// `node_environment_undeclared`).
#[test]
fn kata_mcp_refuses_its_deleted_scratch_flags_at_parse() {
    let project = tempfile::tempdir().expect("project directory for `kata mcp`");
    let named = project.path().join("named-data");
    for (flag, args) in [
        ("--scratch", vec!["--scratch".to_owned()]),
        (
            "--config",
            vec!["--config".to_owned(), "kata.toml".to_owned()],
        ),
        (
            "--data-dir",
            vec![
                "--data-dir".to_owned(),
                named.to_string_lossy().into_owned(),
            ],
        ),
    ] {
        let output = kata_mcp(project.path())
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn `kata mcp`");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(2),
            "`kata mcp {flag}` is a usage error: {stderr}"
        );
        assert!(
            stderr.contains(&format!("unexpected argument '{flag}'")),
            "the refusal names {flag}: {stderr}"
        );
        assert!(
            output.stdout.is_empty(),
            "no JSON-RPC frame is answered: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            std::fs::read_dir(project.path()).unwrap().count(),
            0,
            "`kata mcp {flag}` created nothing where it started"
        );
    }
}

/// Spawn `kata mcp --no-engine` with an explicit extra environment, feed it one
/// `initialize`, close stdin, and return the child's STDERR.
///
/// `--no-engine` is the same body as the DEFAULT attached mode
/// (`run_mcp_lightweight`), reached by the arm that binds no engine — so it
/// exercises the subscriber install on the attached path without needing a live
/// installed main, which no host-independent test may assume.
///
/// `wait_with_output` reads both pipes concurrently, so a child that logs more
/// than a pipe buffer's worth cannot deadlock this helper.
fn lightweight_mcp_stderr(env: &[(&str, &str)]) -> String {
    let project = tempfile::tempdir().expect("project directory for `kata mcp`");
    let mut command = kata_mcp(project.path());
    command
        .arg("--no-engine")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn `kata mcp --no-engine`");
    {
        let mut stdin = child.stdin.take().expect("child stdin");
        writeln!(
            stdin,
            "{}",
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} })
        )
        .expect("write initialize");
        // Drop stdin → EOF → the server drains and exits.
    }
    let output = child.wait_with_output().expect("wait for `kata mcp`");
    assert!(
        output.status.success(),
        "`kata mcp --no-engine` exited uncleanly: {:?}",
        output.status
    );
    String::from_utf8(output.stderr).expect("stderr is utf8")
}

/// **The attached-half subscriber acceptance, through the product.**
///
/// `run_mcp_lightweight` — the body of BOTH the default attached mode and
/// `--no-engine` — must install a stderr subscriber too; without one every
/// `info!`/`warn!` on that path is formatted into the no-op global and
/// dropped. Its two `eprintln!`s would hide the gap: the process would not be
/// silent, it would be silent about everything a subscriber carries.
///
/// TWO ARMS, because either alone is satisfiable by the broken world.
///
/// * The DEFAULT arm asserts a real tracing RECORD: the level and the module
///   target. A bare `eprintln!` carries neither, so this arm is exactly the
///   counterfactual — under a bare print the message text is on stderr and
///   `INFO` / `kata::cli::mcp` are not.
/// * The `KATA_LOG=error` arm asserts the same record is GONE. That is what
///   distinguishes an installed, filter-driven subscriber from a print: a
///   `println` cannot be turned off by a filter directive, so a print FAILS this
///   arm in the opposite direction. It is also the property an
///   operator actually needs — this server shares stderr with a JSON-RPC peer's
///   own diagnostics, so the volume must be theirs to choose.
///
/// Host-independent by construction: `--no-engine` binds no engine, resolves no
/// installed main, opens no port, and writes no state.
#[test]
fn attached_mcp_installs_a_stderr_subscriber_that_honours_kata_log() {
    let default_level = lightweight_mcp_stderr(&[]);
    let record = default_level
        .lines()
        .find(|line| line.contains("kata mcp: --no-engine"))
        .unwrap_or_else(|| {
            panic!(
                "a `kata mcp` that boots no engine must still say which binding it is serving. \
                 stderr:\n{default_level}"
            )
        });
    assert!(
        record.contains("INFO"),
        "the mode line must arrive as a LEVELLED tracing record, not a bare print — that \
         distinction is the property, because a no-op global drops records and prints nothing. \
         line: {record:?}"
    );
    assert!(
        record.contains("kata::cli::mcp"),
        "…and it must carry its module target, or an operator reading a shared stderr cannot \
         tell kata's records from their agent driver's. line: {record:?}"
    );

    // The same invocation with the operator's own directive: the subscriber is
    // real, so the record is filtered out at `error`.
    let quiet = lightweight_mcp_stderr(&[("KATA_LOG", "error")]);
    assert!(
        !quiet.contains("kata mcp: --no-engine"),
        "an INFO record must obey `KATA_LOG=error`; a line that survives it is an `eprintln!` \
         wearing a subscriber's clothes. stderr:\n{quiet}"
    );
}
