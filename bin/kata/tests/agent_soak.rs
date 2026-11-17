//! The MCP surface a sub-agent is handed, checked honest.
//!
//! Tier 1 (`agent_acceptance.rs`) is the deterministic gate: a SCRIPTED driver
//! proves each invariant HOLDS through the surface, mock-backed. This binary is
//! the dry run a real sub-agent would start from:
//!
//! * [`agent_soak_mcp_surface_handshake`] spawns the real `kata mcp` binary
//!   (engine-free, so it stays a fast handshake), does the `initialize` +
//!   `tools/list` handshake, and asserts the surface a sub-agent would be handed
//!   is HONEST: one tool per OPERATE-callable operation (author / check / run /
//!   observe / list), each with an input schema, and STRICTLY NARROWER than
//!   [`Operation::ALL`]. The six human-gate mutations are above this surface's
//!   ceiling, so advertising them would be a trap the sub-agent could only
//!   discover by spending a turn on the refusal. Do NOT "fix" the five-name
//!   literal back to `Operation::ALL`: that literal is the assertion, and
//!   widening it is the regression. `check` serves locally; a node-dependent op
//!   WITHOUT an engine returns the machine "requires a running node" error —
//!   the structured fallback the surface guarantees. No live model,
//!   deterministic.
//!
//! The live cheap-model soak that once drove `kata mcp --scratch` is gone with
//! that flag: `kata mcp` boots no engine of its own, so a model-driven soak runs
//! against an installed main, attached.

use std::io::Write as _;
use std::process::{Command, Stdio};

use kata_op_contract::Operation;
use serde_json::{Value, json};

/// Spawn the real `kata mcp` stdio server, feed it `requests` (one JSON-RPC
/// object per line), close stdin (→ EOF → clean exit), and return the parsed
/// stdout frames. Mirrors `mcp_stdio_tests.rs::drive_mcp`; this is exactly the
/// spawn→handshake path a Claude-Code sub-agent's MCP client performs.
///
/// Runs `--no-engine` so this stays a fast, deterministic SURFACE handshake — it
/// pins the tool set + the engine-free structured-error fallback.
fn drive_mcp(requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kata"))
        .arg("mcp")
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
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|e| panic!("non-JSON-RPC stdout line (must be protocol-only): {e}"))
        })
        .collect()
}

fn frame_by_id(frames: &[Value], id: i64) -> &Value {
    frames
        .iter()
        .find(|frame| frame["id"] == json!(id))
        .unwrap_or_else(|| panic!("no response frame with id {id}; frames: {frames:?}"))
}

/// GATING-SAFE dry-run: establish the exact MCP
/// surface a sub-agent is handed, without any live model. Proves the surface is
/// complete and pins the current node-op boundary the live soak is blocked on.
#[test]
fn agent_soak_mcp_surface_handshake() {
    let frames = drive_mcp(&[
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
        // A locally-servable op: the sub-agent can `check` a bundled workflow.
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "check", "arguments": { "workflow": "kata-loop-lite" } }
        }),
        // A node-dependent op with NO engine bound (`--no-engine`): the surface
        // returns the machine "requires a running node" error — the structured
        // fallback a sub-agent branches on. (With explicit `--scratch` this
        // same op reaches the real dispatch; see `mcp_stdio_tests`.)
        json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": { "name": "observe", "arguments": { "execution_id": "01H" } }
        }),
    ]);

    // initialize → the MCP server identity a sub-agent connects to.
    let init = frame_by_id(&frames, 1);
    assert_eq!(init["result"]["serverInfo"]["name"], "kata-mcp");
    assert!(init["result"]["capabilities"]["tools"].is_object());

    // tools/list → the sub-agent is handed every operation it can CALL, each
    // with a schema. An offered tool it would be refused is not a
    // complete surface, it is a trap the sub-agent can only discover by
    // spending a turn on the error.
    let list = frame_by_id(&frames, 2);
    let tools = list["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        ["author", "check", "run", "observe", "list"],
        "the sub-agent is handed one MCP tool per OPERATE-callable operation"
    );
    assert!(
        tools.len() < Operation::ALL.len(),
        "the contract still has {} operations; the sub-agent's surface is narrower",
        Operation::ALL.len()
    );
    for tool in tools {
        assert!(
            tool["inputSchema"].is_object(),
            "{} carries an input schema the sub-agent can call against",
            tool["name"]
        );
    }

    // check → locally servable through MCP today.
    let check = frame_by_id(&frames, 3);
    assert_eq!(check["result"]["structuredContent"]["op"], "check");
    assert_eq!(check["result"]["structuredContent"]["ok"], true);
    assert_eq!(check["result"]["isError"], false);

    // observe → the engine-free fallback boundary: without a bound engine a
    // node-dependent op is rejected with a machine-classified error (NOT a crash,
    // NOT a fake success). Attached to an installed main the op is proxied to
    // its `/ops` route; here `--no-engine` pins the structured fallback
    // guaranteed when no node is attached.
    let observe = frame_by_id(&frames, 4);
    assert!(
        observe["error"].is_object(),
        "a node-dependent op with no engine bound is a structured error"
    );
    assert!(
        observe["error"]["data"]["code"].is_string(),
        "the rejection carries a machine code the sub-agent can branch on: {observe}"
    );
}
