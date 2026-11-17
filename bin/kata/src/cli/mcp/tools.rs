//! The MCP tool registry: one tool per class-A [`Operation`] this surface can
//! call, plus the `tools/call` dispatch that reaches the engine binding for
//! each op.
//!
//! `tools/list` is derived directly from [`kata_op_contract::descriptors`], so
//! the published tool set and its `inputSchema`s stay in lockstep with the
//! shared operation contract — the same schemas the CLI `--format json` and the
//! REST/client faces are anchored to. No tool is hand-declared here, and
//! no tool is hand-EXCLUDED here either: the one filter is the same
//! capability predicate the call-time ceiling refuses with.
//!
//! Engine binding: [`invoke`] is the LOCAL binding — `Author` and `Check`
//! need no running kata node, so they are bound in-process against the same
//! code paths `kata init` / `kata check` use (minus their stdout side effects).
//! The node-dependent operations require a live engine. By default `kata mcp`
//! attaches to the installed main and proxies them — and a `check` by library
//! name — to its `/ops` route (`McpBinding::invoke` states the split); it
//! boots no engine of its own. When NO engine is bound (`--no-engine`) they
//! return a
//! structured, machine-readable [`OpErrorCode::Network`] "requires a running
//! node" error rather than a stub success (a green skeleton is a lie). The
//! ones within the surface's capability appear in `tools/list` with their real
//! schemas regardless of engine availability — engine reachability is a runtime
//! condition and must not shrink the advertised surface, which is exactly why
//! it stays a structured error and not an omission. Capability is different: a
//! tool this surface can never call is not advertised at all.

use kata_op_contract::{OpError, Operation, descriptors};
use serde_json::{Value, json};

use crate::cli::{init, workflows};

/// Build the MCP `tools/list` array: one tool object per [`Operation`] this
/// surface can actually CALL, with `inputSchema` set to the operation's request
/// JSON Schema.
///
/// The filter is [`crate::cli::mcp::surface_permits`] — the identical
/// predicate the call-time refusal reads — so an advertised tool and a callable
/// tool are the same boolean by construction, not two lists that happen to
/// agree. The contract operations that exceed the surface's OPERATE ceiling
/// are not advertised here at all; they remain resolvable
/// by name in [`operation_for_tool`] so a client holding a stale list gets the
/// explanatory refusal instead of `unknown tool`.
pub(super) fn tools_list() -> Vec<Value> {
    descriptors()
        .into_iter()
        .filter(|descriptor| crate::cli::mcp::surface_permits(descriptor.op))
        .map(|descriptor| {
            json!({
                "name": descriptor.name,
                "description": operation_description(descriptor.op),
                "inputSchema": descriptor.request_schema,
            })
        })
        .collect()
}

/// Resolve an MCP tool name to its [`Operation`], reusing the contract's
/// snake_case serde representation so the mapping cannot drift from the tool
/// names published in `tools/list`.
pub(super) fn operation_for_tool(name: &str) -> Option<Operation> {
    serde_json::from_value(Value::String(name.to_string())).ok()
}

/// Invoke the engine binding for `op` with the raw `tools/call` arguments,
/// returning the typed response payload as a JSON value (the caller wraps it in
/// an `OpEnvelope`). A machine-classified [`OpError`] is returned for a bad
/// request, a not-found / conflicting resource, or a node-dependent operation
/// that has no engine bound yet.
pub(super) fn invoke(op: Operation, arguments: Value) -> Result<Value, OpError> {
    match op {
        Operation::Author => {
            let req = deserialize_request(arguments)?;
            let resp = init::author_for_contract(&req)?;
            to_value(resp)
        }
        Operation::Check => {
            let req = deserialize_request(arguments)?;
            let resp = workflows::check_for_contract(&req)?;
            to_value(resp)
        }
        Operation::Run
        | Operation::Observe
        | Operation::List
        | Operation::Approve
        | Operation::Reject
        | Operation::Cancel
        | Operation::Promote
        | Operation::DischargeStop
        | Operation::ForgeReconcile => Err(requires_running_node(op)),
    }
}

/// Deserialize the `tools/call` `arguments` object into a typed request struct.
/// A shape mismatch is a caller/usage error (exit 2), never an engine failure.
pub(super) fn deserialize_request<T: serde::de::DeserializeOwned>(
    arguments: Value,
) -> Result<T, OpError> {
    serde_json::from_value(arguments)
        .map_err(|e| OpError::usage(format!("invalid arguments for tool: {e}")))
}

/// Serialize a typed response into the JSON payload carried as the envelope's
/// `data`. A serialization failure is an internal engine fault (exit 5).
fn to_value<T: serde::Serialize>(resp: T) -> Result<Value, OpError> {
    serde_json::to_value(resp).map_err(|e| OpError::engine(format!("serializing response: {e}")))
}

/// The structured error a node-dependent operation returns while the stdio MCP
/// server has no engine bound. `Network` (retryable, exit 6) is the
/// closest class: the operation has no engine/node to reach.
fn requires_running_node(op: Operation) -> OpError {
    OpError::network(format!(
        "operation '{op}' requires a running kata node; the `kata mcp` stdio \
         server binds `author` and `check` locally, but `{op}` has no engine \
         bound yet. Use the CLI or REST face against a running node meanwhile."
    ))
}

/// A short, human-readable description per operation for `tools/list`. Not
/// load-bearing for machine dispatch (the `inputSchema` and op name are), but
/// helps an agent driver pick the right tool.
fn operation_description(op: Operation) -> &'static str {
    match op {
        Operation::Author => {
            "Scaffold a project-local kata config and workflow library (like `kata init`)."
        }
        Operation::Check => {
            "Compile and verify a workflow into the checked execution IR without running it."
        }
        Operation::Run => {
            "Submit a workflow for execution on a running kata node. Returns immediately with the \
             new execution_id unless `wait` is set, which polls for up to `wait_timeout_secs` \
             (default 30s, max 50s). A wait that runs out is still a success: the response carries \
             `wait_timed_out: true` with `terminal: false`, and you resume with `observe`."
        }
        Operation::Observe => {
            "Read an execution's state: status, current and last stage, failure reason, stage \
             outputs, wave and iteration, terminal detail."
        }
        Operation::List => "Enumerate recent executions (id, status, workflow, started).",
        Operation::Approve => "Approve a parked human gate.",
        Operation::Reject => "Reject a parked human gate.",
        Operation::Cancel => {
            "Ask every live attempt's worker to stop; reports whether any was asked \
             (`stop_requested`). Terminal executions are idempotent no-ops. A stop is acknowledged when the worker reports \
             its terminal, and the execution's workspace cannot be parked until it is."
        }
        Operation::Promote => "Promote a candidate execution's workspace.",
        Operation::DischargeStop => {
            "Discharge an outstanding worker stop (a worker_stops evidence row carrying \
             `awaiting_worker_acknowledgement: true`) that no worker terminal will ever answer — \
             because the worker's host is gone, or the worker died before answering. Until it is discharged the stop refuses the execution's workspace \
             reclaim (`kata run park`). There is no probe mode: nothing can prove a process \
             exited, so `operator` and `assertion` are always required and the durable record \
             always says a human decided."
        }
        Operation::ForgeReconcile => {
            "Ask a pending forge export's remote and forge again now: each open intent's \
             observer reads at once, and the export goes on from its verdict. A read the remote \
             leaves unanswered counts toward the ten after which the effect is recorded \
             unclassified."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The operations this surface advertises, in contract order. Kept beside
    /// the tests that consume it so the positional `zip` below still aligns
    /// after the surface filter.
    const ADVERTISED: [Operation; 5] = [
        Operation::Author,
        Operation::Check,
        Operation::Run,
        Operation::Observe,
        Operation::List,
    ];

    #[test]
    fn tools_list_covers_every_advertised_operation_with_nonempty_input_schema() {
        let tools = tools_list();
        assert_eq!(tools.len(), ADVERTISED.len());
        for (tool, op) in tools.iter().zip(&ADVERTISED) {
            assert_eq!(tool["name"], op.as_str());
            assert!(
                tool["inputSchema"].is_object(),
                "{} inputSchema is an object",
                op.as_str()
            );
            assert!(
                tool["description"].as_str().is_some_and(|d| !d.is_empty()),
                "{} has a non-empty description",
                op.as_str()
            );
        }
    }

    /// Surface hygiene: Starlark (`.star`) is the sole workflow frontend, and
    /// TOML exists ONLY as the node config (`kata.toml`). No MCP tool an agent
    /// reads to pick a workflow argument may advertise a `.toml` workflow
    /// format. This grep-clean guard pins that so the wording cannot enter the
    /// surface (descriptions or the `workflow` request schema).
    ///
    /// It iterates [`descriptors`] — the FULL eleven-operation contract — and
    /// not `tools_list()`, which the surface filter narrows to five: iterating
    /// that would silently stop checking the six descriptions for approve /
    /// reject / cancel / promote / discharge_stop / forge_reconcile while staying
    /// green. Those descriptions are still live
    /// prose ([`operation_description`] has an arm for each) and re-enter the
    /// published surface the moment `SURFACE_CEILING` is raised or an operator
    /// mode is added — carrying whatever wording drifted into them in the
    /// interim, which is the exact regression this guard exists to catch. The
    /// hygiene claim is about the DESCRIPTIONS, so the guard's domain is the
    /// descriptions, not the subset one face happens to publish today.
    #[test]
    fn no_tool_description_advertises_the_deleted_toml_workflow_format() {
        let all = descriptors();
        assert_eq!(
            all.len(),
            Operation::ALL.len(),
            "the guard's domain is every operation's description, not the advertised subset"
        );
        for descriptor in all {
            let name = descriptor.name;

            // The short human description never names a workflow file format,
            // so it must never mention TOML at all.
            let description = operation_description(descriptor.op).to_ascii_lowercase();
            assert!(
                !description.contains("toml"),
                "tool `{name}` description mentions TOML; workflows are Starlark-only: {description}"
            );

            // The `workflow` argument is Starlark-name-or-`.star`-path only. Any
            // operation carrying it (run / check) must not leak `.toml` workflow
            // wording into the schema an agent reads. These schemas never
            // reference the `kata.toml` node config, so a bare "toml" substring
            // anywhere in the request schema is a stale-format regression.
            if descriptor.request_schema["properties"]["workflow"].is_object() {
                let schema = serde_json::to_string(&descriptor.request_schema)
                    .unwrap()
                    .to_ascii_lowercase();
                assert!(
                    !schema.contains("toml"),
                    "tool `{name}` request schema still advertises the deleted .toml \
                     workflow format: {schema}"
                );
            }
        }
    }

    /// `tools/list` must not advertise ELEVEN tools while the OPERATE ceiling
    /// refuses six of them at call time: an agent's only way to learn which
    /// five it could actually drive would be to call one and read the error.
    ///
    /// The expectation is a LITERAL name list, and that is the whole point.
    /// Deriving it from `surface_permits` would make the test tautological: it
    /// would stay green if someone raised `SURFACE_CEILING` to
    /// [`kata_types::identity::ApiScope::Admin`], which re-advertises all
    /// eleven — the exact regression. A literal list is the only assertion that
    /// survives a change to the predicate itself.
    #[test]
    fn tools_list_advertises_only_the_operate_callable_tools() {
        let tools = tools_list();
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().expect("a tool name"))
            .collect();
        assert_eq!(
            names,
            ["author", "check", "run", "observe", "list"],
            "tools/list advertises exactly the tools this surface can call"
        );
        for op in [
            Operation::Approve,
            Operation::Reject,
            Operation::Cancel,
            Operation::Promote,
            Operation::DischargeStop,
            Operation::ForgeReconcile,
        ] {
            assert!(
                !names.contains(&op.as_str()),
                "{op} exceeds the OPERATE ceiling and must not be advertised"
            );
        }
        assert!(
            names.len() < Operation::ALL.len(),
            "the filter is not vacuous"
        );
    }

    /// Name resolution stays UNFILTERED at all eleven on purpose: a client
    /// holding a stale `tools/list` must reach the explanatory OPERATE-only
    /// refusal, not `unknown tool: approve`.
    #[test]
    fn operation_for_tool_round_trips_every_name() {
        for op in Operation::ALL {
            assert_eq!(operation_for_tool(op.as_str()), Some(*op));
        }
        assert_eq!(operation_for_tool("not-a-tool"), None);
    }

    #[test]
    fn node_dependent_ops_return_structured_network_error() {
        use kata_op_contract::OpErrorCode;
        for op in [
            Operation::Run,
            Operation::Observe,
            Operation::List,
            Operation::Approve,
            Operation::Reject,
            Operation::Cancel,
            Operation::Promote,
            Operation::DischargeStop,
            Operation::ForgeReconcile,
        ] {
            let err = invoke(op, json!({"execution_id": "01H", "workflow": "x"})).unwrap_err();
            assert_eq!(err.code, OpErrorCode::Network, "{op} maps to Network");
            assert!(err.retryable, "{op} error is retryable");
        }
    }

    #[test]
    fn check_binds_locally_and_returns_a_payload() {
        // `kata-work-item` is a bundled stdlib workflow resolved via the
        // compile-time manifest fallback regardless of CWD, and — unlike
        // `kata-loop-lite`, which keeps `sandbox = "host"` until the deletion
        // and refuses under the shipped `oci` default — checks clean from a
        // node-less process.
        let value = invoke(
            Operation::Check,
            json!({"workflow": "kata-work-item", "deny_warnings": false}),
        )
        .expect("check binds locally");
        assert_eq!(value["name"], "kata-work-item");
        assert_eq!(value["passed"], true);
    }

    #[test]
    fn malformed_check_arguments_are_a_usage_error() {
        use kata_op_contract::OpErrorCode;
        // `all` must be a bool, not a string.
        let err = invoke(Operation::Check, json!({"all": "yes"})).unwrap_err();
        assert_eq!(err.code, OpErrorCode::Usage);
    }
}
