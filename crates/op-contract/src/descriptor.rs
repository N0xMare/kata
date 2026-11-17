//! Per-operation JSON-Schema descriptors.
//!
//! One [`OpDescriptor`] per class-A [`Operation`], carrying the derived
//! request + response JSON Schemas. This table feeds the MCP `tools/list`
//! (a tool per op, `inputSchema` = the request schema) and a machine-parseable
//! `--help`. Deriving the schema from the same `schemars` structs the faces
//! deserialize keeps the published schema and the runtime contract in lockstep.

use crate::envelope::OpResponse;
use crate::operation::Operation;
use crate::requests::{
    ApproveRequest, AuthorRequest, CancelRequest, CheckRequest, DischargeStopRequest,
    ForgeReconcileRequest, ListRequest, ObserveRequest, PromoteRequest, RejectRequest, RunRequest,
};
use crate::responses::{
    ApproveResponse, AuthorResponse, CancelResponse, CheckResponse, DischargeStopResponse,
    ForgeReconcileResponse, ListResponse, ObserveResponse, PromoteResponse, RejectResponse,
    RunResponse,
};

/// The published contract for one operation: its stable name plus the derived
/// JSON Schema of its request (input) and response (output).
#[derive(Debug, Clone)]
pub struct OpDescriptor {
    /// The operation's stable snake_case name (matches the MCP tool name).
    pub name: &'static str,
    /// The operation this descriptor describes.
    pub op: Operation,
    /// JSON Schema of the operation's request payload.
    pub request_schema: serde_json::Value,
    /// JSON Schema of the operation's response payload.
    pub response_schema: serde_json::Value,
}

macro_rules! descriptor {
    ($op:expr, $req:ty, $resp:ty) => {
        OpDescriptor {
            name: $op.as_str(),
            op: $op,
            request_schema: serde_json::to_value(schemars::schema_for!($req))
                .expect("request schema serializes to JSON"),
            response_schema: serde_json::to_value(schemars::schema_for!($resp))
                .expect("response schema serializes to JSON"),
        }
    };
}

/// THE operation table: every class-A [`Operation`] with its request and response
/// type, written once. [`descriptors`] and the [`OpResponse`] impls both expand
/// it, so the type an envelope tagged `op` may carry and the response schema
/// `op`'s descriptor publishes are one row and cannot disagree.
macro_rules! operation_table {
    ($expand:ident) => {
        $expand! {
            (Operation::Author, AuthorRequest, AuthorResponse),
            (Operation::Check, CheckRequest, CheckResponse),
            (Operation::Run, RunRequest, RunResponse),
            (Operation::Observe, ObserveRequest, ObserveResponse),
            (Operation::List, ListRequest, ListResponse),
            (Operation::Approve, ApproveRequest, ApproveResponse),
            (Operation::Reject, RejectRequest, RejectResponse),
            (Operation::Cancel, CancelRequest, CancelResponse),
            (Operation::Promote, PromoteRequest, PromoteResponse),
            (Operation::DischargeStop, DischargeStopRequest, DischargeStopResponse),
            (Operation::ForgeReconcile, ForgeReconcileRequest, ForgeReconcileResponse),
        }
    };
}

macro_rules! descriptor_vec {
    ($(($op:expr, $req:ty, $resp:ty)),* $(,)?) => {
        vec![$(descriptor!($op, $req, $resp)),*]
    };
}

macro_rules! response_impls {
    ($(($op:expr, $req:ty, $resp:ty)),* $(,)?) => {
        $(impl crate::envelope::sealed::Sealed for $resp {}
        impl OpResponse for $resp {
            const OP: Operation = $op;
        })*
    };
}

operation_table!(response_impls);

/// The full descriptor table, one entry per [`Operation::ALL`] variant.
#[must_use]
pub fn descriptors() -> Vec<OpDescriptor> {
    operation_table!(descriptor_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::OpEnvelope;

    /// Each response type's [`OpResponse::OP`] names the operation whose
    /// descriptor publishes THAT type's schema — the property a typed envelope
    /// relies on. Compared against `schema_for!` of the type itself, not
    /// against the table both sides expand.
    #[test]
    fn every_response_type_names_the_operation_that_publishes_its_schema() {
        fn published_by<R: OpResponse + schemars::JsonSchema>() -> bool {
            let schema = serde_json::to_value(schemars::schema_for!(R)).unwrap();
            descriptors()
                .into_iter()
                .any(|descriptor| descriptor.op == R::OP && descriptor.response_schema == schema)
        }
        assert!(published_by::<AuthorResponse>());
        assert!(published_by::<CheckResponse>());
        assert!(published_by::<RunResponse>());
        assert!(published_by::<ObserveResponse>());
        assert!(published_by::<ListResponse>());
        assert!(published_by::<ApproveResponse>());
        assert!(published_by::<RejectResponse>());
        assert!(published_by::<CancelResponse>());
        assert!(published_by::<PromoteResponse>());
        assert!(published_by::<DischargeStopResponse>());
        assert!(published_by::<ForgeReconcileResponse>());
    }

    #[test]
    fn descriptor_table_covers_every_operation_with_nonempty_schemas() {
        let descriptors = descriptors();
        assert_eq!(
            descriptors.len(),
            Operation::ALL.len(),
            "one descriptor per operation"
        );
        for (descriptor, op) in descriptors.iter().zip(Operation::ALL) {
            assert_eq!(descriptor.op, *op, "descriptor table in ALL order");
            assert_eq!(descriptor.name, op.as_str());
            assert!(
                descriptor.request_schema.is_object(),
                "{} request schema is a non-empty object",
                op.as_str()
            );
            assert!(
                descriptor.request_schema["properties"].is_object()
                    || descriptor.request_schema["type"].is_string(),
                "{} request schema has structure",
                op.as_str()
            );
            assert!(
                descriptor.response_schema.is_object(),
                "{} response schema is a non-empty object",
                op.as_str()
            );
        }
    }

    /// Every operation round-trips a representative Req and Resp through the
    /// shared `OpEnvelope`, proving the three faces share one payload shape.
    #[test]
    fn every_operation_round_trips_request_and_response() {
        use crate::requests as req;
        use crate::responses as resp;

        // Requests round-trip.
        macro_rules! rt_req {
            ($ty:ty, $val:expr) => {{
                let v: $ty = $val;
                let json = serde_json::to_string(&v).unwrap();
                let back: $ty = serde_json::from_str(&json).unwrap();
                assert_eq!(back, v);
            }};
        }
        rt_req!(
            req::AuthorRequest,
            req::AuthorRequest {
                config: ".kata/kata.toml".into(),
                force: false,
                print: true
            }
        );
        rt_req!(
            req::CheckRequest,
            req::CheckRequest {
                workflow: Some("kata-loop".into()),
                all: false,
                deny_warnings: true
            }
        );
        rt_req!(
            req::RunRequest,
            req::RunRequest {
                workflow: Some("kata-loop".into()),
                workflow_starlark: None,
                workflow_filename: None,
                params: serde_json::Map::new(),
                target: Some("pr:42".into()),
                wait: true,
                wait_timeout_secs: Some(30)
            }
        );
        // The inline-body variant round-trips too (a pure-MCP agent
        // authors + submits a brand-new workflow through the same contract).
        rt_req!(
            req::RunRequest,
            req::RunRequest {
                workflow: None,
                workflow_starlark: Some(
                    "only = stage(id = \"only\", prompt = \"hi\")\nworkflow(\"demo\", root = [only])\n"
                        .into()
                ),
                workflow_filename: Some("demo.star".into()),
                params: serde_json::Map::new(),
                target: None,
                wait: false,
                wait_timeout_secs: None
            }
        );
        rt_req!(
            req::ObserveRequest,
            req::ObserveRequest {
                execution_id: "01H".into()
            }
        );
        rt_req!(req::ListRequest, req::ListRequest { limit: Some(10) });
        rt_req!(
            req::ApproveRequest,
            req::ApproveRequest {
                execution_id: "01H".into()
            }
        );
        rt_req!(
            req::RejectRequest,
            req::RejectRequest {
                execution_id: "01H".into(),
                reason: Some("no".into())
            }
        );
        rt_req!(
            req::CancelRequest,
            req::CancelRequest {
                execution_id: "01H".into()
            }
        );
        rt_req!(
            req::PromoteRequest,
            req::PromoteRequest {
                execution_id: "01H".into()
            }
        );
        // ONE mode only. There is no probe form to round-trip, because
        // nothing in kata can prove a worker process exited — see
        // `DischargeStopRequest` for why `operator` is unconditionally required.
        rt_req!(
            req::DischargeStopRequest,
            req::DischargeStopRequest {
                execution_id: "01H".into(),
                attempt_id: "01J".into(),
                lease_epoch: 3,
                operator: "op".into(),
                assertion: "worker host terminated; PID 4711 is gone".into()
            }
        );
        rt_req!(
            req::ForgeReconcileRequest,
            req::ForgeReconcileRequest {
                execution_id: "01H".into()
            }
        );

        // Responses round-trip through the envelope, one per operation.
        let envelopes = [
            serde_json::to_value(OpEnvelope::ok(
                Operation::Author,
                resp::AuthorResponse {
                    config: ".kata/kata.toml".into(),
                    created: true,
                },
            ))
            .unwrap(),
            serde_json::to_value(OpEnvelope::ok(
                Operation::Check,
                resp::CheckResponse {
                    name: "kata-loop".into(),
                    passed: true,
                    status: "pass".into(),
                    error_count: 0,
                    warning_count: 0,
                    info_count: 0,
                    deferred_node_facts: Vec::new(),
                    capsule_networks: Vec::new(),
                },
            ))
            .unwrap(),
            serde_json::to_value(OpEnvelope::ok(
                Operation::Run,
                resp::RunResponse {
                    execution_id: "01H".into(),
                    status: "running".into(),
                    terminal: false,
                    wait_timed_out: false,
                },
            ))
            .unwrap(),
            serde_json::to_value(OpEnvelope::ok(
                Operation::Observe,
                resp::ObserveResponse {
                    execution_id: "01H".into(),
                    workflow_name: "kata-loop".into(),
                    status: "running".into(),
                    terminal: false,
                    current_stage: Some("plan".into()),
                    last_stage: Some("plan".into()),
                    failure_reason: None,
                    stage_outputs: std::collections::BTreeMap::new(),
                    wave: None,
                    iteration: Some(0),
                    terminal_detail: None,
                    capsule_networks: Vec::new(),
                },
            ))
            .unwrap(),
            serde_json::to_value(OpEnvelope::ok(
                Operation::List,
                resp::ListResponse {
                    executions: vec![resp::ExecutionSummary {
                        execution_id: "01H".into(),
                        workflow_name: "kata-loop".into(),
                        status: "running".into(),
                        submitted_at_ms: 0,
                    }],
                },
            ))
            .unwrap(),
            serde_json::to_value(OpEnvelope::ok(
                Operation::Approve,
                resp::ApproveResponse {
                    execution_id: "01H".into(),
                    approved: true,
                },
            ))
            .unwrap(),
            serde_json::to_value(OpEnvelope::ok(
                Operation::Reject,
                resp::RejectResponse {
                    execution_id: "01H".into(),
                    rejected: true,
                },
            ))
            .unwrap(),
            serde_json::to_value(OpEnvelope::ok(
                Operation::Cancel,
                resp::CancelResponse {
                    execution_id: "01H".into(),
                    stop_requested: true,
                },
            ))
            .unwrap(),
            serde_json::to_value(OpEnvelope::ok(
                Operation::Promote,
                resp::PromoteResponse {
                    execution_id: "01H".into(),
                    promoted: true,
                },
            ))
            .unwrap(),
            serde_json::to_value(OpEnvelope::ok(
                Operation::DischargeStop,
                resp::DischargeStopResponse {
                    execution_id: "01H".into(),
                    attempt_id: "01J".into(),
                    lease_epoch: 3,
                    discharged: true,
                    operator: "op".into(),
                    provenance: "operator_asserted".into(),
                    rests_on_a_proof: false,
                    assertion: "worker host terminated; PID 4711 is gone".into(),
                    outstanding_stops_remaining: 0,
                },
            ))
            .unwrap(),
            serde_json::to_value(OpEnvelope::ok(
                Operation::ForgeReconcile,
                resp::ForgeReconcileResponse {
                    execution_id: "01H".into(),
                    exports: vec![resp::ReconciledForgeExport {
                        attempt_id: "01J".into(),
                        stage_id: "export".into(),
                        state: "pending".into(),
                        intent: Some(resp::ReconciledForgeIntent {
                            effect_index: 0,
                            effect: "push".into(),
                            verdict: None,
                            unanswered_reads: 2,
                            last_read_error: Some("the remote did not answer".into()),
                            command_error: None,
                        }),
                    }],
                },
            ))
            .unwrap(),
        ];
        assert_eq!(envelopes.len(), Operation::ALL.len());
        for (value, op) in envelopes.iter().zip(Operation::ALL) {
            assert_eq!(value["op"], op.as_str());
            assert_eq!(value["ok"], true);
            assert_eq!(value["schema_version"], crate::envelope::SCHEMA_VERSION);
            assert!(value["data"].is_object(), "{} data present", op.as_str());
        }
    }
}
