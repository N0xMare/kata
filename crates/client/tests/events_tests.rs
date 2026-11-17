//! Integration coverage for the SDK's tiny SSE state machine.
//!
//! The parser in `crates/client/src/events.rs` is private to the SDK; these
//! tests reach it through the `kata_client::events::testing` shim
//! (`#[doc(hidden)] pub mod testing` re-export), which is the crate's
//! convention for hitting internals from out-of-crate tests.

use kata_client::events::testing::SseParser;
use kata_client::operator_projection;
use kata_client::types::{
    CHECK_ARTIFACT_EVIDENCE_SCHEMA_VERSION, CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION,
    CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION, ExecutionCheckArtifactEvidence,
    ExecutionCloseoutEvidence, ExecutionControllerApplicationEvidence,
    ExecutionControllerDecisionEvidence, ExecutionEvidence, ExecutionProgramIdentity,
    ExecutionRecord, ExecutionStatus, ExecutionValidationCriterionEvidence,
    ExecutionValidationCriterionStatus, ExecutionValidationEvidence, ExecutionWorkspacePromotion,
    ExecutionWorkspaceSnapshot, ProgressEvent, VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION,
};
use kata_client::{EventFrame, KataClientError, LedgerEvent};
use kata_types::execution::{
    CHECKED_DISPATCH_GUARD_EVIDENCE_SCHEMA_VERSION, CHECKED_DISPATCH_GUARD_ID,
    CHECKED_DISPATCH_POLICY_FIELDS, ExecutionCheckedDispatchGuardEvidence,
    ExecutionCheckedDispatchGuardStatus, ExecutionCheckedDispatchKind,
    ExecutionControllerApplicationSideEffectEvidence,
};
use kata_types::execution::{ExecutionHumanRequestEvidence, HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION};
use kata_types::execution::{
    ExecutionValidationCriterionWaiverEvidence,
    VALIDATION_CRITERION_WAIVER_EVIDENCE_SCHEMA_VERSION, WorkflowClassIdentity,
};
use kata_types::ledger::{AgentInvocationGraph, AssignmentStatus};
use kata_types::ledger::{AgentInvocationGraphNode, AgentInvocationKind, AgentInvocationStatus};
use kata_types::primitives::ContentHash;
use kata_types::workflow::ProgressVisibility;
use kata_types::workspace_awareness::ExecutionWorkspaceParking;
use smol_str::SmolStr;
use ulid::Ulid;

/// Construct a fresh parser, feed it the entire input as one chunk,
/// and drain every emitted outcome. Returns `(result, seq)` pairs.
fn parse_all(input: &str) -> Vec<(Result<LedgerEvent, KataClientError>, Option<u64>)> {
    let mut p = SseParser::new();
    p.feed(input.as_bytes());
    let mut out = Vec::new();
    while let Some(item) = p.next_emit() {
        out.push(item);
    }
    out
}

fn parse_frames(input: &str) -> Vec<(Result<EventFrame, KataClientError>, Option<u64>)> {
    let mut p = SseParser::new();
    p.feed(input.as_bytes());
    let mut out = Vec::new();
    while let Some(item) = p.next_frame() {
        out.push(item);
    }
    out
}

fn ulid(value: &str) -> Ulid {
    Ulid::from_string(value).expect("fixture ULID must parse")
}

fn record_with_operator_evidence() -> ExecutionRecord {
    let execution_id = ulid("01HV0VZTBP7TX5DQ1V0G7WB3SK");
    let assignment_id = ulid("01HV0VZTBP7TX5DQ1V0G7WB3SM");
    let invocation_id = ulid("01HV0VZTBP7TX5DQ1V0G7WB3SN");
    let program = ExecutionProgramIdentity {
        schema_version: 1,
        program_hash: ContentHash::zero(),
        workflow_class: WorkflowClassIdentity {
            schema_version: 1,
            id: ContentHash::zero(),
        },
    };
    ExecutionRecord {
        target: None,
        id: execution_id.to_string(),
        workflow_name: "operator-evidence".to_string(),
        execution_program: Some(program.clone()),
        status: ExecutionStatus::Running,
        submitted_at_ms: 1_700_000_000_000,
        started_at_ms: Some(1_700_000_000_100),
        finished_at_ms: None,
        worker_id: "worker-a".to_string(),
        outputs: None,
        error: None,
        running_cost_micro_usd: 0,
        child_cost_micro_usd: 0,
        metering: kata_types::metering::MeteringSummary::default(),
        warnings: Vec::new(),
        agent_invocation_graph: Some(AgentInvocationGraph {
            execution_id,
            nodes: vec![AgentInvocationGraphNode {
                id: invocation_id,
                parent_id: None,
                assignment_id,
                execution_id,
                stage_name: SmolStr::new("implement"),
                kind: AgentInvocationKind::Worker,
                role: SmolStr::new("package_writer"),
                agent_label: Some(SmolStr::new("codex")),
                effect_kind: None,
                topology_kind: Some(SmolStr::new("root_with_parallel_workers")),
                model_hint: Some(SmolStr::new("gpt-5.5")),
                timeout_ms: Some(60_000),
                progress_visibility: ProgressVisibility::Summary,
                owned_paths: vec![SmolStr::new("crates/client/src/client.rs")],
                sync_with_assignment: true,
                status: AgentInvocationStatus::Running,
                created_at_ms: 1_700_000_000_050,
                dispatched_at_ms: Some(1_700_000_000_100),
                started_at_ms: Some(1_700_000_000_150),
                finished_at_ms: None,
                child_ids: Vec::new(),
                latest_progress: Some(ProgressEvent {
                    execution_id,
                    assignment_id,
                    stage_name: SmolStr::new("implement"),
                    byte_offset: 42,
                    preview: "working".to_string(),
                    dropped: 0,
                    at_ms: 1_700_000_000_200,
                }),
                output: Some(serde_json::json!({"hidden_when_outputs_excluded": true})),
            }],
            roots: vec![invocation_id],
            orphaned: Vec::new(),
        }),
        evidence: ExecutionEvidence {
            execution_program: Some(program),
            checked_dispatch_guards: vec![ExecutionCheckedDispatchGuardEvidence {
                schema_version: CHECKED_DISPATCH_GUARD_EVIDENCE_SCHEMA_VERSION,
                stage_name: "implement".to_string(),
                guard: CHECKED_DISPATCH_GUARD_ID.to_string(),
                status: ExecutionCheckedDispatchGuardStatus::Passed,
                program_hash: ContentHash::zero(),
                workflow_class: WorkflowClassIdentity {
                    schema_version: 1,
                    id: ContentHash::zero(),
                },
                dispatch_policy_coverage: true,
                dispatch_kind: Some(ExecutionCheckedDispatchKind::ValidationRetry),
                derived_stage_name: Some("implement#validate-1".to_string()),
                approval_required: Some(false),
                model_hint: Some("gpt-5.5".to_string()),
                timeout_ms: Some(120_000),
                allowed_tools: vec!["read_file".to_string()],
                required_capabilities: vec!["network".to_string()],
                policy_fields: CHECKED_DISPATCH_POLICY_FIELDS
                    .iter()
                    .map(|field| (*field).to_string())
                    .collect(),
                diagnostic_codes: Vec::new(),
                error: None,
            }],
            validation_reports: vec![ExecutionValidationEvidence {
                stage_name: "validate".to_string(),
                status: Some("passed".to_string()),
                criteria: vec![
                    ExecutionValidationCriterionEvidence {
                        schema_version: VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION,
                        criterion_id: "vc-build".to_string(),
                        status: ExecutionValidationCriterionStatus::Passed,
                        required: true,
                        stage_name: Some("validate".to_string()),
                        evidence: vec!["client tests passed".to_string()],
                        missing: Vec::new(),
                        source: Some("validate".to_string()),
                        waiver: None,
                        candidate: None,
                    },
                    ExecutionValidationCriterionEvidence {
                        schema_version: VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION,
                        criterion_id: "vc-advisory".to_string(),
                        status: ExecutionValidationCriterionStatus::WaivedByPolicy,
                        required: false,
                        stage_name: Some("validate".to_string()),
                        evidence: vec!["operator waived advisory proof".to_string()],
                        missing: Vec::new(),
                        source: Some("policy".to_string()),
                        waiver: Some(ExecutionValidationCriterionWaiverEvidence {
                            schema_version: VALIDATION_CRITERION_WAIVER_EVIDENCE_SCHEMA_VERSION,
                            source: "operator".to_string(),
                            reason: "operator waived advisory proof".to_string(),
                            authority_id: None,
                            approved_by: Some("operator".to_string()),
                            approved_at_ms: Some(1),
                            evidence: vec!["operator waived advisory proof".to_string()],
                        }),
                        candidate: None,
                    },
                ],
                commands: vec!["just test-crate kata-client".to_string()],
                evidence: vec![
                    "client tests passed".to_string(),
                    "human_request_queue carries 1 nonblocking request".to_string(),
                ],
                test_count: Some(3),
                git_sha: Some("abc1234".to_string()),
                pgrep_clean: Some(true),
                check_artifacts: Vec::new(),
            }],
            closeout_reports: vec![ExecutionCloseoutEvidence {
                stage_name: "closeout".to_string(),
                outcome: Some("completed".to_string()),
                evidence: vec!["operator evidence serialized".to_string()],
                remaining: Vec::new(),
                next_action: Some("review".to_string()),
            }],
            controller_decisions: vec![ExecutionControllerDecisionEvidence {
                schema_version: CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION,
                stage_name: "controller".to_string(),
                decision_id: "decision-wave-1".to_string(),
                wave_id: Some("wave-1".to_string()),
                decision: "continue".to_string(),
                next_action: Some("start the next bounded wave".to_string()),
                reason: Some("validation passed but roadmap has remaining work".to_string()),
                evidence: vec!["validation report passed".to_string()],
                alternatives: vec!["stop".to_string(), "park".to_string()],
                human_required: false,
                scope: None,
                completion: None,
                memory_policy: None,
                runtime_policy: None,
            }],
            controller_applications: vec![ExecutionControllerApplicationEvidence {
                schema_version: CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION,
                application_id: "advance:decision-wave-1".to_string(),
                decision_id: "decision-wave-1".to_string(),
                decision: "continue".to_string(),
                action: "advance".to_string(),
                applied: true,
                applied_at_ms: 1_717_171_717,
                source: Some("factory_controller".to_string()),
                reason: Some("validation passed but roadmap has remaining work".to_string()),
                error: None,
                next_execution_id: Some("01HZZZZZZZZZZZZZZZZZZZZZZY".to_string()),
                parked_candidate: None,
                promotion: None,
                memory_policy: None,
                side_effect: Some(ExecutionControllerApplicationSideEffectEvidence {
                    kind: "park".to_string(),
                    parked_ref: Some("parked/01HZZZZZZZZZZZZZZZZZZZZZZX".to_string()),
                    next_execution_id: None,
                    workflow_label: None,
                    workflow_program_hash: None,
                    external_input_channel: None,
                    external_input_id: None,
                    effective_cost_limit_micro_usd: None,
                    cost_consumed_micro_usd: Some(0),
                    deadline_at_ms: None,
                    next_wave_stage_timeout_ms: None,
                    runtime_authority_source: None,
                }),
                recovery: None,
            }],
            human_requests: vec![ExecutionHumanRequestEvidence {
                schema_version: HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION,
                id: "HR-operator-evidence".to_string(),
                stage: Some("plan".to_string()),
                priority: "medium".to_string(),
                question: "Should the wave stay single-writer?".to_string(),
                default_assumption: "Keep it single-writer.".to_string(),
                context: Some("Owned paths overlap.".to_string()),
                blocking: false,
                status: "default_assumption_active".to_string(),
                projection: "HR-operator-evidence [plan]: Should the wave stay single-writer? Default: Keep it single-writer.".to_string(),
                answer_summary: None,
                answered_by_steering_id: None,
                answered_at_ms: None,
                auto_defaulted: false,
            }],
            ..ExecutionEvidence::default()
        },
        routing: Vec::new(),
        capsule_networks: Vec::new(),
    }
}

fn record_without_evidence() -> ExecutionRecord {
    let mut record = record_with_operator_evidence();
    record.execution_program = None;
    record.evidence = ExecutionEvidence::default();
    record.agent_invocation_graph = None;
    record
}

fn record_with_multi_worker_invocations() -> ExecutionRecord {
    let mut record = record_with_operator_evidence();
    let graph = record
        .agent_invocation_graph
        .as_mut()
        .expect("operator fixture has graph");
    let mut beta = graph.nodes[0].clone();
    beta.id = ulid("01HV0VZTBP7TX5DQ1V0G7WB3SP");
    beta.assignment_id = ulid("01HV0VZTBP7TX5DQ1V0G7WB3SQ");
    beta.stage_name = SmolStr::new("worker_beta");
    beta.role = SmolStr::new("worker_beta_probe");
    beta.status = AgentInvocationStatus::Completed;
    beta.finished_at_ms = Some(1_700_000_000_300);
    graph.nodes[0].stage_name = SmolStr::new("worker_alpha");
    graph.nodes[0].role = SmolStr::new("worker_alpha_probe");
    graph.nodes[0].status = AgentInvocationStatus::Completed;
    graph.nodes[0].finished_at_ms = Some(1_700_000_000_250);
    graph.roots = vec![graph.nodes[0].id, beta.id];
    graph.nodes.push(beta);
    record
}

/// Fold ledger events through the projection `collect_worker_attribution`
/// feeds from the live SSE stream.
fn attribution_from_events(events: &[LedgerEvent]) -> Vec<operator_projection::WorkerAttribution> {
    let mut projection = operator_projection::WorkerAttributionProjection::default();
    for event in events {
        projection.record_event(event);
    }
    projection.to_vec()
}

fn completed_worker_event(stage_name: &str, assignment_id: Ulid, worker_id: &str) -> LedgerEvent {
    LedgerEvent {
        execution_id: ulid("01HV0VZTBP7TX5DQ1V0G7WB3SK"),
        assignment_id,
        stage_name: SmolStr::new(stage_name),
        new_status: AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new(worker_id)),
        },
        output: None,
        terminal_charge: None,
    }
}

fn workspace_snapshot_for(record: &ExecutionRecord) -> ExecutionWorkspaceSnapshot {
    ExecutionWorkspaceSnapshot {
        schema_version: 1,
        execution_id: record.id.clone(),
        workflow_name: record.workflow_name.clone(),
        status: "completed".to_string(),
        workspace_provider_attached: true,
        workspace_provider_backend: Some("jj".to_string()),
        worktree: None,
        promotion: ExecutionWorkspacePromotion {
            available: true,
            safe_to_promote: true,
            status: "ready".to_string(),
            blockers: Vec::new(),
            reason: None,
            promoted_ref: None,
            promoted_commit_sha: None,
            identity: None,
        },
        parking: ExecutionWorkspaceParking {
            available: false,
            parked: false,
            auto_parked: false,
            status: "unavailable".to_string(),
            blockers: Vec::new(),
            reason: None,
            candidate: None,
        },
    }
}

#[test]
fn parses_one_ledger_event() {
    let body = "event: ledger\n\
        data: {\"execution_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SK\",\
        \"assignment_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SM\",\
        \"stage_name\":\"draft\",\
        \"new_status\":{\"kind\":\"dispatched\",\"worker_id\":\"w1\"},\
        \"output\":null}\n\n";
    let out = parse_all(body);
    assert_eq!(out.len(), 1);
    let (result, seq) = out.into_iter().next().unwrap();
    let ev = result.unwrap();
    assert_eq!(ev.stage_name.as_str(), "draft");
    assert!(seq.is_none(), "no id: field → seq must be None");
}

#[test]
fn parses_id_field() {
    let body = "id: 42\n\
        event: ledger\n\
        data: {\"execution_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SK\",\
        \"assignment_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SM\",\
        \"stage_name\":\"s\",\
        \"new_status\":{\"kind\":\"pending\"},\
        \"output\":null}\n\n";
    let out = parse_all(body);
    assert_eq!(out.len(), 1);
    let (result, seq) = out.into_iter().next().unwrap();
    assert!(result.is_ok());
    assert_eq!(seq, Some(42), "id: 42 must be surfaced as Some(42)");
}

#[test]
fn skips_comments_and_keepalive() {
    // LedgerEvent uses ulid::Ulid for the id fields, so the test
    // fixtures must carry real ULID-shaped strings — serde rejects
    // non-ULID placeholders like "a" / "b". Two distinct ULIDs ensure execution_id and
    // assignment_id remain visibly different in the JSON.
    let body = ": keep-alive\n\nevent: ledger\ndata: {\"execution_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SK\",\"assignment_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SM\",\"stage_name\":\"s\",\"new_status\":{\"kind\":\"pending\"},\"output\":null}\n\n";
    let out = parse_all(body);
    assert_eq!(out.len(), 1);
    assert!(out[0].0.is_ok());
}

#[test]
fn handles_chunked_input() {
    // Feed the same event in two chunks split mid-data-line.
    let mut p = SseParser::new();
    p.feed(
        b"event: ledger\ndata: {\"execution_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SK\",\"assignment_id\"",
    );
    assert!(p.next_emit().is_none());
    p.feed(b":\"01HV0VZTBP7TX5DQ1V0G7WB3SM\",\"stage_name\":\"s\",\"new_status\":{\"kind\":\"pending\"},\"output\":null}\n\n");
    let (r, _seq) = p.next_emit().unwrap();
    assert!(r.is_ok(), "expected Ok, got {r:?}");
}

#[test]
fn lagged_event_becomes_sse_error() {
    let body = "event: lagged\ndata: true\n\n";
    let out = parse_all(body);
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0].0, Err(KataClientError::Sse(_))));
}

#[test]
fn handles_crlf_line_endings() {
    let body = "event: ledger\r\ndata: {\"execution_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SK\",\"assignment_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SM\",\"stage_name\":\"s\",\"new_status\":{\"kind\":\"pending\"},\"output\":null}\r\n\r\n";
    let out = parse_all(body);
    assert_eq!(out.len(), 1, "expected 1 event from CRLF body, got {out:?}");
    assert!(out[0].0.is_ok());
}

#[test]
fn id_resets_per_event() {
    // id: field applies to the frame it appears in; subsequent frames
    // without an id: field get None.
    let body = concat!(
        "id: 7\nevent: ledger\ndata: {\"execution_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SK\",",
        "\"assignment_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SM\",\"stage_name\":\"s\",",
        "\"new_status\":{\"kind\":\"pending\"},\"output\":null}\n\n",
        "event: ledger\ndata: {\"execution_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SK\",",
        "\"assignment_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SM\",\"stage_name\":\"s\",",
        "\"new_status\":{\"kind\":\"completed\",\"output\":null},\"output\":null}\n\n",
    );
    let out = parse_all(body);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].1, Some(7), "first frame has id: 7");
    assert_eq!(out[1].1, None, "second frame has no id:");
}

#[test]
fn frame_stream_preserves_progress_events() {
    let body = "event: progress\n\
        data: {\"execution_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SK\",\
        \"assignment_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SM\",\
        \"stage_name\":\"implement\",\
        \"byte_offset\":42,\
        \"preview\":\"working\",\
        \"at_ms\":1234}\n\n";
    let out = parse_frames(body);
    assert_eq!(out.len(), 1);
    let (result, seq) = out.into_iter().next().unwrap();
    assert!(seq.is_none(), "progress frames are not durably sequenced");
    match result.unwrap() {
        EventFrame::Progress(event) => {
            assert_eq!(event.stage_name.as_str(), "implement");
            assert_eq!(event.byte_offset, 42);
            assert_eq!(event.preview, "working");
        }
        other => panic!("expected progress frame, got {other:?}"),
    }
}

#[test]
fn ledger_stream_ignores_progress_events() {
    let body = concat!(
        "event: progress\n",
        "data: {\"execution_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SK\",",
        "\"assignment_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SM\",",
        "\"stage_name\":\"implement\",\"byte_offset\":1,\"preview\":\"x\",\"at_ms\":1}\n\n",
        "event: ledger\n",
        "data: {\"execution_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SK\",",
        "\"assignment_id\":\"01HV0VZTBP7TX5DQ1V0G7WB3SM\",",
        "\"stage_name\":\"implement\",\"new_status\":{\"kind\":\"running\",\"worker_id\":\"w1\"},",
        "\"output\":null}\n\n",
    );
    let out = parse_all(body);
    assert_eq!(out.len(), 1);
    assert!(out[0].0.is_ok());
}

#[test]
fn replay_summary_serializes_operator_evidence_counts() {
    let summary = operator_projection::replay_summary_with_worker_attribution(
        record_with_operator_evidence(),
        false,
        Vec::new(),
    );
    let json = serde_json::to_value(summary).expect("summary serializes");

    assert_eq!(json["execution_program"]["schema_version"], 1);
    assert_eq!(json["validation_report_count"], 1);
    assert_eq!(json["closeout_report_count"], 1);
    assert_eq!(json["evidence_summary"]["checked_program_source"], "record");
    assert_eq!(json["evidence_summary"]["validation_report_count"], 1);
    assert_eq!(json["evidence_summary"]["closeout_report_count"], 1);
    assert_eq!(json["evidence_summary"]["checked_dispatch_guard_count"], 1);
    assert_eq!(
        json["evidence_summary"]["checked_dispatch_guard_stages"][0],
        "implement"
    );
    assert_eq!(
        json["evidence_summary"]["checked_dispatch_guard_targets"][0],
        "implement#validate-1"
    );
    assert_eq!(json["evidence_summary"]["operator_evidence_item_count"], 5);
    assert_eq!(json["evidence_summary"]["human_request_count"], 1);
    assert_eq!(json["evidence_summary"]["controller_decision_count"], 1);
    assert_eq!(json["evidence_summary"]["controller_application_count"], 1);
    assert_eq!(
        json["evidence_summary"]["controller_decisions"][0]["decision"],
        "continue"
    );
    assert_eq!(
        json["evidence_summary"]["controller_applications"][0]["action"],
        "advance"
    );
    assert_eq!(
        json["evidence_summary"]["human_requests"][0]["id"],
        "HR-operator-evidence"
    );
    assert_eq!(
        json["evidence_summary"]["human_requests"][0]["blocking"],
        false
    );
    assert_eq!(
        json["evidence_summary"]["human_request_projection"][0],
        "HR-operator-evidence [plan]: Should the wave stay single-writer? Default: Keep it single-writer."
    );
    assert_eq!(
        json["evidence_summary"]["human_request_evidence"][0],
        "human_request_queue carries 1 nonblocking request"
    );
    assert_eq!(json["operator_packet"]["status"], "running");
    assert_eq!(json["operator_packet"]["terminal"], false);
    assert_eq!(
        json["operator_packet"]["validation_reports"][0]["commands"][0],
        "just test-crate kata-client"
    );
    assert_eq!(
        json["operator_packet"]["validation_reports"][0]["criterion_count"],
        2
    );
    assert_eq!(
        json["operator_packet"]["validation_reports"][0]["criteria"][0]["criterion_id"],
        "vc-build"
    );
    assert_eq!(
        json["operator_packet"]["validation_reports"][0]["criteria"][0]["status"],
        "passed"
    );
    assert_eq!(
        json["operator_packet"]["validation_reports"][0]["criteria"][1]["required"],
        false
    );
    assert_eq!(
        json["operator_packet"]["validation_reports"][0]["criteria"][1]["status"],
        "waived_by_policy"
    );
    assert_eq!(
        json["operator_packet"]["closeout_reports"][0]["next_action"],
        "review"
    );
    assert_eq!(json["operator_packet"]["controller_decision_count"], 1);
    assert_eq!(json["operator_packet"]["controller_application_count"], 1);
    assert_eq!(
        json["operator_packet"]["controller_decisions"][0]["next_action"],
        "start the next bounded wave"
    );
    assert_eq!(
        json["operator_packet"]["controller_applications"][0]["next_execution_id"],
        "01HZZZZZZZZZZZZZZZZZZZZZZY"
    );
    assert_eq!(
        json["operator_packet"]["checked_dispatch_guards"][0]["guard"],
        CHECKED_DISPATCH_GUARD_ID
    );
    assert_eq!(
        json["operator_packet"]["checked_dispatch_guards"][0]["status"],
        "passed"
    );
    assert_eq!(
        json["operator_packet"]["checked_dispatch_guards"][0]["dispatch_kind"],
        "validation_retry"
    );
    assert_eq!(
        json["operator_packet"]["checked_dispatch_guards"][0]["derived_stage_name"],
        "implement#validate-1"
    );
    assert_eq!(
        json["operator_packet"]["human_requests"][0]["id"],
        "HR-operator-evidence"
    );
    assert_eq!(
        json["operator_packet"]["human_request_projection"][0],
        "HR-operator-evidence [plan]: Should the wave stay single-writer? Default: Keep it single-writer."
    );
    assert_eq!(json["active_invocation_count"], 1);
    assert_eq!(json["latest_progress_frame_count"], 1);
    assert_eq!(json["invocation_counts_by_status"]["running"], 1);
    assert_eq!(json["invocation_counts_by_kind"]["worker"], 1);
    assert!(
        json["agent_invocation_graph"]["nodes"][0]
            .get("output")
            .is_none(),
        "replay without --include-outputs must strip per-invocation output payloads"
    );
}

#[test]
fn replay_summary_serializes_multi_worker_attribution_projection() {
    let record = record_with_multi_worker_invocations();
    let graph = record
        .agent_invocation_graph
        .as_ref()
        .expect("multi-worker fixture has graph");
    let events = vec![
        completed_worker_event("worker_alpha", graph.nodes[0].assignment_id, "ls-worker-0"),
        completed_worker_event("worker_beta", graph.nodes[1].assignment_id, "ls-worker-1"),
    ];
    let worker_attribution = attribution_from_events(&events);
    let summary = operator_projection::replay_summary_with_worker_attribution(
        record,
        false,
        worker_attribution,
    );
    let json = serde_json::to_value(summary).expect("summary serializes");

    assert_eq!(json["worker_attribution"].as_array().unwrap().len(), 2);
    assert_eq!(json["worker_attribution"][0]["stage_name"], "worker_alpha");
    assert_eq!(json["worker_attribution"][0]["status"], "completed");
    assert_eq!(json["worker_attribution"][0]["worker_id"], "ls-worker-0");
    assert!(
        json["worker_attribution"][0]
            .get("placement_audit")
            .is_none()
            && json["operator_packet"]["worker_routes"][0]
                .get("placement_audit")
                .is_none(),
        "no producer writes a placement audit, so no operator view may claim one"
    );
    assert_eq!(json["worker_attribution"][1]["stage_name"], "worker_beta");
    assert_eq!(json["worker_attribution"][1]["worker_id"], "ls-worker-1");
}

#[test]
fn watch_snapshot_serializes_active_invocation_progress_evidence() {
    let record = record_with_operator_evidence();
    let snapshot =
        operator_projection::watch_snapshot_with_worker_attribution(&record, false, Vec::new());
    let json = serde_json::to_value(snapshot).expect("watch snapshot serializes");

    assert_eq!(json["execution_program"]["schema_version"], 1);
    assert_eq!(json["validation_report_count"], 1);
    assert_eq!(json["closeout_report_count"], 1);
    assert_eq!(json["evidence_summary"]["checked_program_source"], "record");
    assert_eq!(json["evidence_summary"]["operator_evidence_item_count"], 5);
    assert_eq!(json["evidence_summary"]["controller_decision_count"], 1);
    assert_eq!(json["evidence_summary"]["controller_application_count"], 1);
    assert_eq!(json["evidence_summary"]["checked_dispatch_guard_count"], 1);
    assert_eq!(json["evidence_summary"]["human_request_count"], 1);
    assert_eq!(
        json["evidence_summary"]["human_requests"][0]["status"],
        "default_assumption_active"
    );
    assert_eq!(
        json["evidence_summary"]["human_request_evidence"][0],
        "human_request_queue carries 1 nonblocking request"
    );
    assert_eq!(json["operator_packet"]["active_invocation_count"], 1);
    assert_eq!(
        json["operator_packet"]["active_invocations"][0]["stage_name"],
        "implement"
    );
    assert_eq!(
        json["operator_packet"]["validation_reports"][0]["test_count"],
        3
    );
    assert_eq!(
        json["operator_packet"]["human_requests"][0]["status"],
        "default_assumption_active"
    );
    assert_eq!(json["active_invocations"].as_array().unwrap().len(), 1);
    assert_eq!(json["active_invocations"][0]["stage_name"], "implement");
    assert_eq!(json["active_invocations"][0]["model_hint"], "gpt-5.5");
    assert_eq!(
        json["active_invocations"][0]["progress_visibility"],
        "summary"
    );
    assert_eq!(
        json["active_invocations"][0]["owned_paths"][0],
        "crates/client/src/client.rs"
    );
    assert_eq!(
        json["active_invocations"][0]["latest_progress"]["byte_offset"],
        42
    );
    assert_eq!(json["output_count"], 0);
    assert!(json["outputs"].is_null());
}

#[test]
fn run_summary_serializes_compact_operator_view() {
    let record = record_with_operator_evidence();
    let summary = operator_projection::run_summary_with_worker_attribution(&record, Vec::new());
    let json = serde_json::to_value(summary).expect("summary serializes");

    assert_eq!(json["summary_kind"], "operator_run_summary");
    assert_eq!(
        json["evidence_sources"],
        serde_json::json!(["execution_record"])
    );
    assert_eq!(json["status"], "running");
    assert_eq!(json["terminal"], false);
    assert_eq!(json["active_invocation_count"], 1);
    assert_eq!(json["worker_routes"][0]["stage_name"], "implement");
    assert_eq!(json["model_routes"][0]["model_hint"], "gpt-5.5");
    assert_eq!(json["validation_report_count"], 1);
    assert_eq!(json["closeout_report_count"], 1);
    assert_eq!(json["human_request_count"], 1);
    assert_eq!(json["checked_program_source"], "record");
    assert_eq!(json["checked_dispatch_guard_count"], 1);
    assert_eq!(
        json["checked_dispatch_guards"][0]["guard"],
        CHECKED_DISPATCH_GUARD_ID
    );
    assert_eq!(json["output_handle_count"], 0);
    assert!(json.get("evidence").is_none());
    assert!(json.get("agent_invocation_graph").is_none());
}

#[test]
fn explain_summary_serializes_decision_workspace_and_next_action() {
    let mut record = record_with_operator_evidence();
    record.status = ExecutionStatus::Completed;
    record.finished_at_ms = Some(1_700_000_000_500);
    let workspace = workspace_snapshot_for(&record);

    let summary = operator_projection::explain_summary(&record, workspace);
    let json = serde_json::to_value(summary).expect("explain summary serializes");

    assert_eq!(json["summary_kind"], "operator_explain");
    assert_eq!(json["execution_id"], record.id);
    assert_eq!(
        json["headline"],
        "controller chose `continue`; decision already applied by `advance`"
    );
    assert_eq!(json["run_summary"]["summary_kind"], "operator_run_summary");
    assert_eq!(json["run_summary"]["status"], "completed");
    assert_eq!(json["factory"]["summary_kind"], "factory_controller_status");
    assert_eq!(json["factory"]["latest_decision"]["decision"], "continue");
    assert_eq!(json["factory"]["latest_application"]["action"], "advance");
    assert!(json["factory"].get("next_wave_scheduling_plan").is_none());
    assert_eq!(json["factory"]["action"]["action"], "none");
    assert_eq!(json["factory"]["action"]["applicable"], false);
    assert_eq!(
        json["factory"]["action"]["reason"],
        "controller decision `decision-wave-1` was already applied by `advance`"
    );
    assert_eq!(json["evidence_counts"]["validation_reports"], 1);
    assert_eq!(json["evidence_counts"]["controller_decisions"], 1);
    assert_eq!(json["evidence_counts"]["controller_applications"], 1);
}

/// A running record whose only projection input is the record itself:
/// no controller decision, so `explain` produces the bare
/// `execution is running` headline the operator reported.
fn running_record_without_controller_decision() -> ExecutionRecord {
    let mut record = record_with_operator_evidence();
    record.status = ExecutionStatus::Running;
    record.finished_at_ms = None;
    record.evidence.controller_decisions.clear();
    record.evidence.controller_applications.clear();
    record
}

fn running_explain_packet() -> operator_projection::ExecutionExplainSummary {
    let record = running_record_without_controller_decision();
    let mut workspace = workspace_snapshot_for(&record);
    workspace.status = "running".to_string();
    operator_projection::explain_summary(&record, workspace)
}

fn pending_approval_fixture(
    stage: &str,
    assignment_id: &str,
    awaiting_since_ms: Option<u64>,
) -> kata_client::types::PendingApproval {
    kata_client::types::PendingApproval {
        execution_id: record_with_operator_evidence().id,
        assignment_id: assignment_id.to_string(),
        stage_name: stage.to_string(),
        reason: format!("stage {stage} requires operator sign-off before dispatch"),
        awaiting_since_ms,
        capsule: None,
        workspace_effect: None,
        expansion: None,
        target: None,
        params: Vec::new(),
    }
}

/// An unreadable approvals plane must never be projected as "no gates".
/// `GET /api/v1/approvals` answers 500 when the deciding planes cannot be
/// read; degrading that to an empty list would reintroduce, one level down,
/// the same silence that made `explain` report a parked run as healthy.
#[test]
fn explain_says_it_cannot_rule_out_a_parked_gate_when_the_approvals_plane_is_unreadable() {
    let mut packet = running_explain_packet();
    assert_eq!(packet.headline, "execution is running");

    operator_projection::fold_approval_gates_into_explain(
        &mut packet,
        &[],
        Some("the deciding planes could not be read"),
    );

    assert!(
        packet.why.iter().any(|why| {
            why.contains("approval-gate plane could not be read")
                && why.contains("cannot rule out a parked gate")
        }),
        "why={:?}",
        packet.why
    );
}

/// The reported defect: a parked approval gate is folded into `Running` by
/// `aggregate_status`, so the headline claimed a healthy run and
/// `recommended_actions` named nothing that clears the park.
#[test]
fn explain_names_the_parked_gate_and_leads_with_the_command_that_clears_it() {
    let mut packet = running_explain_packet();
    let execution_id = packet.execution_id.clone();
    assert_eq!(
        packet.recommended_actions.len(),
        1,
        "a running record with no controller decision recommends only `watch` before the fold"
    );
    assert_eq!(packet.recommended_actions[0].action, "watch");

    let gate = pending_approval_fixture("review", "01K-assignment-review", Some(1_700_000_000_123));
    operator_projection::fold_approval_gates_into_explain(&mut packet, &[gate], None);

    assert_eq!(
        packet.headline,
        "execution is running; parked on 1 approval gate: stage `review` \
         (assignment 01K-assignment-review) — stage review requires operator sign-off before dispatch"
    );
    assert!(
        packet.why[0].contains("01K-assignment-review") && packet.why[0].contains("awaiting since"),
        "why={:?}",
        packet.why
    );
    let approve = &packet.recommended_actions[0];
    assert_eq!(approve.action, "approve");
    assert_eq!(
        approve.command.as_deref(),
        Some(format!("kata run approve {execution_id} 01K-assignment-review").as_str())
    );
    assert!(
        approve.reason.contains("kata run reject"),
        "the refusal path must be named beside the approval: {}",
        approve.reason
    );
    assert_eq!(
        packet.recommended_actions[1].action, "watch",
        "`watch` is demoted, not deleted"
    );
}

/// `pending_approvals` sorts by `awaiting_since_ms` and `None` orders BEFORE
/// `Some`, so `gates[0]` may be an anchorless gate rather than the
/// longest-waiting one. The projection must say "the first", never "the oldest".
#[test]
fn explain_never_calls_the_first_approval_gate_the_oldest() {
    let mut packet = running_explain_packet();
    let execution_id = packet.execution_id.clone();
    let gates = vec![
        pending_approval_fixture("review", "01K-anchorless", None),
        pending_approval_fixture("ship", "01K-anchored", Some(1_700_000_000_000)),
    ];
    operator_projection::fold_approval_gates_into_explain(&mut packet, &gates, None);

    assert_eq!(
        packet.headline,
        "execution is running; parked on 2 approval gates; the first is stage `review` \
         (assignment 01K-anchorless)"
    );
    assert!(!packet.headline.contains("oldest"), "{}", packet.headline);
    assert!(
        packet.why[0].contains("holds the park and not the instant"),
        "an anchorless gate must not render as a zero-age park: {:?}",
        packet.why
    );
    let commands: Vec<Option<&str>> = packet
        .recommended_actions
        .iter()
        .map(|action| action.command.as_deref())
        .collect();
    assert_eq!(
        commands[0],
        Some(format!("kata run approve {execution_id} 01K-anchorless").as_str())
    );
    assert_eq!(
        commands[1],
        Some(format!("kata run approve {execution_id} 01K-anchored").as_str())
    );
}

/// Half B of the report: `why` already named the blocking human request and
/// `next_actions` named nothing that answers it.
#[test]
fn explain_recommends_the_command_that_answers_an_open_blocking_human_request() {
    let mut record = running_record_without_controller_decision();
    record.evidence.human_requests[0].id = "HR-blocking".to_string();
    record.evidence.human_requests[0].blocking = true;
    record.evidence.human_requests[0].status = "blocked".to_string();
    record.evidence.human_requests[0].answered_at_ms = None;
    let mut workspace = workspace_snapshot_for(&record);
    workspace.status = "running".to_string();

    let packet = operator_projection::explain_summary(&record, workspace);

    assert_eq!(
        packet.headline,
        "execution is running, stage `plan` is parked on 1 open human request: HR-blocking — \
         Should the wave stay single-writer?"
    );
    assert!(
        packet
            .why
            .iter()
            .any(|why| why.contains("1 blocking human request(s) are still open")),
        "why={:?}",
        packet.why
    );
    let answer = &packet.recommended_actions[0];
    assert_eq!(answer.action, "answer_human_request");
    assert_eq!(
        answer.command.as_deref(),
        Some(
            format!(
                "kata steer answer-human-request {} HR-blocking \"<answer>\"",
                record.id
            )
            .as_str()
        )
    );
    assert_eq!(
        packet.recommended_actions[1].action, "watch",
        "the blocker leads and `watch` follows"
    );
}

/// A run can carry BOTH blockers at once, and the two halves of the fix are
/// written by different code paths: `explain_headline` puts the open blocking
/// human request in the headline, and `fold_approval_gates_into_explain` then
/// rewrites that headline with the gate. If the fold REBUILDS the headline from
/// `packet.status` instead of appending to it, half B silently erases half A and
/// the operator is told about one of the two things holding the run.
#[test]
fn explain_keeps_the_human_request_blocker_when_an_approval_gate_is_also_parked() {
    let mut record = running_record_without_controller_decision();
    record.evidence.human_requests[0].id = "HR-blocking".to_string();
    record.evidence.human_requests[0].blocking = true;
    record.evidence.human_requests[0].status = "blocked".to_string();
    record.evidence.human_requests[0].answered_at_ms = None;
    let mut workspace = workspace_snapshot_for(&record);
    workspace.status = "running".to_string();
    let mut packet = operator_projection::explain_summary(&record, workspace);
    assert!(
        packet.headline.contains("HR-blocking"),
        "precondition: the pre-fold headline names the human-request blocker: {}",
        packet.headline
    );

    let gate = pending_approval_fixture("review", "01K-assignment-review", Some(1_700_000_000_123));
    operator_projection::fold_approval_gates_into_explain(&mut packet, &[gate], None);

    assert_eq!(
        packet.headline,
        "execution is running, stage `plan` is parked on 1 open human request: HR-blocking — \
         Should the wave stay single-writer?; parked on 1 approval gate: stage `review` \
         (assignment 01K-assignment-review) — stage review requires operator sign-off before dispatch",
        "the fold must APPEND to the headline it was given, never rebuild one from `status`"
    );
    assert_eq!(
        packet.recommended_actions[0].action, "approve",
        "the gate leads: {:?}",
        packet.recommended_actions
    );
    assert_eq!(
        packet.recommended_actions[1].action, "answer_human_request",
        "and the human request is still there behind it: {:?}",
        packet.recommended_actions
    );
}

/// A blocking human request parks the ONE stage it names —
/// `WorkflowRunner::hold_for_blocking_inputs` filters by `request.stage`, so a
/// sibling branch keeps dispatching past a parked one. So neither the headline
/// nor the action reason may claim the EXECUTION is held.
#[test]
fn explain_scopes_a_blocking_human_request_to_its_stage_not_the_whole_execution() {
    let mut record = running_record_without_controller_decision();
    record.evidence.human_requests[0].id = "HR-blocking".to_string();
    record.evidence.human_requests[0].blocking = true;
    record.evidence.human_requests[0].status = "blocked".to_string();
    record.evidence.human_requests[0].answered_at_ms = None;
    assert_eq!(
        record.evidence.human_requests[0].stage.as_deref(),
        Some("plan"),
        "fixture precondition: the request is stage-scoped"
    );
    let mut workspace = workspace_snapshot_for(&record);
    workspace.status = "running".to_string();

    let packet = operator_projection::explain_summary(&record, workspace);

    assert_eq!(
        packet.headline,
        "execution is running, stage `plan` is parked on 1 open human request: HR-blocking — \
         Should the wave stay single-writer?"
    );
    let answer = &packet.recommended_actions[0];
    assert_eq!(
        answer.reason,
        "blocking human request `HR-blocking` holds stage `plan` parked until it is answered — \
         the park is stage-scoped, so sibling stages keep dispatching: \
         Should the wave stay single-writer?"
    );
    for text in std::iter::once(&packet.headline).chain(std::iter::once(&answer.reason)) {
        assert!(
            !text.contains("nothing will dispatch"),
            "a stage-scoped park must never be projected as an execution-wide one: {text}"
        );
    }
}

/// An UNSCOPED blocking request names no stage, so it matches no submit site and
/// parks nothing. The projection must therefore make no dispatch claim about it
/// at all.
#[test]
fn explain_makes_no_dispatch_claim_for_an_unscoped_blocking_human_request() {
    let mut record = running_record_without_controller_decision();
    record.evidence.human_requests[0].id = "HR-unscoped".to_string();
    record.evidence.human_requests[0].stage = None;
    record.evidence.human_requests[0].blocking = true;
    record.evidence.human_requests[0].status = "blocked".to_string();
    record.evidence.human_requests[0].answered_at_ms = None;
    let mut workspace = workspace_snapshot_for(&record);
    workspace.status = "running".to_string();

    let packet = operator_projection::explain_summary(&record, workspace);

    assert_eq!(
        packet.headline,
        "execution is running, 1 open blocking human request: HR-unscoped — \
         Should the wave stay single-writer?"
    );
    assert_eq!(
        packet.recommended_actions[0].reason,
        "blocking human request `HR-unscoped` is open and unanswered: \
         Should the wave stay single-writer?"
    );
    assert!(
        !packet.headline.contains("parked")
            && !packet.recommended_actions[0].reason.contains("park"),
        "an unscoped request parks no stage, so nothing may say it does: {} / {}",
        packet.headline,
        packet.recommended_actions[0].reason
    );
}

/// `kata explain` and the `explain` sub-packet of `kata report` both stamp
/// `summary_kind: "operator_explain"`. A consumer keying on that discriminant is
/// entitled to the same answer from both. When only `explain` joined the
/// approvals plane, the two disagreed about whether the run was parked while
/// advertising the identical schema discriminant, and `report` — the surface
/// whose whole point is blockers-first — reported `blocker_count: 0` for a run
/// `kata approvals` lists as gated.
#[test]
fn report_and_explain_agree_about_a_parked_approval_gate() {
    let record = running_record_without_controller_decision();
    let mut workspace = workspace_snapshot_for(&record);
    workspace.status = "running".to_string();
    let factory = operator_projection::factory_controller_status_from_parts(&record, workspace);
    let gate = pending_approval_fixture("review", "01K-assignment-review", Some(1_700_000_000_123));

    let mut explain = running_explain_packet();
    operator_projection::fold_approval_gates_into_explain(
        &mut explain,
        std::slice::from_ref(&gate),
        None,
    );

    let mut report = operator_projection::execution_report_from_parts(&record, Vec::new(), factory);
    operator_projection::fold_approval_gates_into_report(
        &mut report,
        std::slice::from_ref(&gate),
        None,
    );

    assert_eq!(
        report.explain.summary_kind, explain.summary_kind,
        "the two packets advertise the same schema discriminant"
    );
    assert_eq!(
        report.explain.headline, explain.headline,
        "same discriminant, same answer"
    );
    assert_eq!(
        report.headline, explain.headline,
        "the report's own headline is the explain headline"
    );
    let gate_blockers: Vec<&str> = report
        .blockers
        .iter()
        .filter(|blocker| blocker.source == "approval_gate")
        .map(|blocker| blocker.code.as_str())
        .collect();
    assert_eq!(
        gate_blockers,
        vec!["01K-assignment-review"],
        "a blockers-first surface must list the gate that is blocking: {:?}",
        report.blockers
    );
    assert_eq!(
        report.outcome.blocker_count,
        report.blockers.len(),
        "blocker_count must count the folded gate"
    );
    assert!(
        report
            .recommended_actions
            .iter()
            .any(|action| action.action == "approve"),
        "the command that clears the park must reach the report surface: {:?}",
        report.recommended_actions
    );
}

/// The timeout self-heal resolves a blocking request by applying its
/// `default_assumption` and RE-DISPATCHING the parked stage, tagging the row
/// `auto_defaulted`. The client's open-blocker predicate did not look at that
/// mark, so it kept the request in `open_blocking_human_requests` — which now
/// drives an emitted command, meaning `kata explain` printed
/// `kata steer answer-human-request` against a request the runtime had already
/// answered and run past. Both surfaces read
/// `ExecutionHumanRequestEvidence::is_resolved` now, which is where
/// `auto_defaulted` lives.
#[test]
fn an_auto_defaulted_request_is_resolved_and_no_longer_recommends_answering_it() {
    let mut record = running_record_without_controller_decision();
    record.evidence.human_requests[0].id = "HR-selfhealed".to_string();
    record.evidence.human_requests[0].blocking = true;
    // Only `auto_defaulted` set — the row shape a writer that set only that mark
    // would produce; a predicate reading the other two marks misses it.
    record.evidence.human_requests[0].status = "blocked".to_string();
    record.evidence.human_requests[0].answered_at_ms = None;
    record.evidence.human_requests[0].auto_defaulted = true;
    let mut workspace = workspace_snapshot_for(&record);
    workspace.status = "running".to_string();

    let packet = operator_projection::explain_summary(&record, workspace);

    assert_eq!(
        packet.headline, "execution is running",
        "a resolved request holds nothing, so it belongs in no headline"
    );
    assert!(
        !packet
            .recommended_actions
            .iter()
            .any(|action| action.action == "answer_human_request"),
        "never recommend answering a request the runtime already resolved and \
         resumed past: {:?}",
        packet.recommended_actions
    );
    assert!(
        !packet
            .why
            .iter()
            .any(|why| why.contains("blocking human request(s) are still open")),
        "why={:?}",
        packet.why
    );

    let summary = operator_projection::run_summary_with_worker_attribution(&record, Vec::new());
    let json = serde_json::to_value(summary).expect("run summary serializes");
    assert_eq!(
        json["human_blocker_count"], 0,
        "`run-summary` counted `blocking` alone — the loosest of the four \
         definitions — and must agree with the rest"
    );
}

#[test]
fn run_summary_keeps_validation_proof_beyond_compact_context_limit() {
    let mut record = record_with_operator_evidence();
    let commands = (1..=5)
        .map(|index| format!("just validation-proof-{index}"))
        .collect::<Vec<_>>();
    let check_artifacts = commands
        .iter()
        .enumerate()
        .map(|(index, command)| ExecutionCheckArtifactEvidence {
            schema_version: CHECK_ARTIFACT_EVIDENCE_SCHEMA_VERSION,
            artifact_id: format!("factory-validation-command-{}", index + 1),
            stage_name: "validate".to_string(),
            status: Some("passed".to_string()),
            commands: vec![command.clone()],
            paths: Vec::new(),
            evidence: vec![format!("{command}: exit 0")],
            missing: Vec::new(),
            summary: Some(format!("{command}: passed")),
            source: Some("factory_validation_stage".to_string()),
        })
        .collect::<Vec<_>>();
    record.evidence.validation_reports[0].commands = commands.clone();
    record.evidence.validation_reports[0].check_artifacts = check_artifacts.clone();
    record.evidence.check_artifacts = check_artifacts;

    let summary = operator_projection::run_summary_with_worker_attribution(&record, Vec::new());
    let json = serde_json::to_value(summary).expect("summary serializes");

    assert_eq!(json["validation_reports"][0]["command_count"], 5);
    assert_eq!(
        json["validation_reports"][0]["commands"]
            .as_array()
            .expect("commands must be array")
            .len(),
        5
    );
    assert_eq!(json["check_artifact_count"], 5);
    assert_eq!(
        json["check_artifacts"]
            .as_array()
            .expect("check_artifacts must be array")
            .len(),
        5
    );
    assert_eq!(
        json["check_artifacts"][4]["commands"][0],
        "just validation-proof-5"
    );
}

#[test]
fn run_summary_serializes_legacy_empty_state() {
    let record = record_without_evidence();
    let summary = operator_projection::run_summary_with_worker_attribution(&record, Vec::new());
    let json = serde_json::to_value(summary).expect("summary serializes");

    assert_eq!(json["summary_kind"], "operator_run_summary");
    assert_eq!(json["status"], "running");
    assert_eq!(json["terminal"], false);
    assert_eq!(json["worker_attribution_count"], 0);
    assert_eq!(json["active_invocation_count"], 0);
    assert_eq!(json["validation_report_count"], 0);
    assert_eq!(json["closeout_report_count"], 0);
    assert_eq!(json["human_request_count"], 0);
    assert_eq!(json["checked_dispatch_guard_count"], 0);
    assert_eq!(json["output_handle_count"], 0);
    assert!(json["failed_reason"].is_null());
    assert!(json["parked_reason"].is_null());
    assert!(json["active_invocations"].as_array().unwrap().is_empty());
    assert!(json["worker_routes"].as_array().unwrap().is_empty());
    assert!(json["model_routes"].as_array().unwrap().is_empty());
}

#[test]
fn watch_snapshot_serializes_multi_worker_attribution_projection() {
    let record = record_with_multi_worker_invocations();
    let graph = record
        .agent_invocation_graph
        .as_ref()
        .expect("multi-worker fixture has graph");
    let events = vec![
        completed_worker_event("worker_beta", graph.nodes[1].assignment_id, "ls-worker-1"),
        completed_worker_event("worker_alpha", graph.nodes[0].assignment_id, "ls-worker-0"),
    ];
    let worker_attribution = attribution_from_events(&events);
    let snapshot = operator_projection::watch_snapshot_with_worker_attribution(
        &record,
        false,
        worker_attribution,
    );
    let json = serde_json::to_value(snapshot).expect("watch snapshot serializes");

    assert_eq!(json["worker_attribution"].as_array().unwrap().len(), 2);
    assert_eq!(json["worker_attribution"][0]["stage_name"], "worker_alpha");
    assert_eq!(json["worker_attribution"][0]["worker_id"], "ls-worker-0");
    assert_eq!(json["worker_attribution"][1]["stage_name"], "worker_beta");
    assert_eq!(json["worker_attribution"][1]["worker_id"], "ls-worker-1");
}

#[test]
fn replay_summary_uses_durable_checked_program_evidence() {
    let mut record = record_with_operator_evidence();
    record.execution_program = None;
    record.evidence.validation_reports.clear();
    record.evidence.closeout_reports.clear();
    record.evidence.controller_decisions.clear();
    record.evidence.controller_applications.clear();
    let summary =
        operator_projection::replay_summary_with_worker_attribution(record, false, Vec::new());
    let json = serde_json::to_value(summary).expect("summary serializes");

    assert_eq!(json["execution_program"]["schema_version"], 1);
    assert_eq!(
        json["evidence_summary"]["checked_program_source"],
        "evidence"
    );
    assert_eq!(
        json["evidence_summary"]["checked_program"]["schema_version"],
        1
    );
    assert_eq!(json["evidence_summary"]["validation_report_count"], 0);
    assert_eq!(json["evidence_summary"]["operator_evidence_item_count"], 0);
    assert_eq!(json["evidence_summary"]["controller_decision_count"], 0);
    assert_eq!(json["evidence_summary"]["human_request_count"], 1);
}

#[test]
fn replay_and_watch_omit_evidence_summary_for_legacy_records() {
    let record = record_without_evidence();
    let replay = operator_projection::replay_summary_with_worker_attribution(
        record.clone(),
        false,
        Vec::new(),
    );
    let replay_json = serde_json::to_value(replay).expect("replay summary serializes");
    assert!(replay_json["execution_program"].is_null());
    assert!(
        replay_json.get("evidence_summary").is_none(),
        "replay rows without operator evidence should keep the compact shape"
    );
    assert!(
        replay_json.get("worker_attribution").is_none(),
        "replay rows without worker evidence should keep the compact shape"
    );

    let snapshot =
        operator_projection::watch_snapshot_with_worker_attribution(&record, false, Vec::new());
    let snapshot_json = serde_json::to_value(snapshot).expect("watch snapshot serializes");
    assert!(snapshot_json["execution_program"].is_null());
    assert!(
        snapshot_json.get("evidence_summary").is_none(),
        "watch rows without operator evidence should keep the compact shape"
    );
    assert!(
        snapshot_json.get("worker_attribution").is_none(),
        "watch rows without worker evidence should keep the compact shape"
    );
}

#[test]
fn watch_line_serializes_progress_frames_without_ledger_fields() {
    let event = ProgressEvent {
        execution_id: ulid("01HV0VZTBP7TX5DQ1V0G7WB3SK"),
        assignment_id: ulid("01HV0VZTBP7TX5DQ1V0G7WB3SM"),
        stage_name: SmolStr::new("implement"),
        byte_offset: 99,
        preview: "delta".to_string(),
        dropped: 0,
        at_ms: 1_700_000_000_300,
    };
    let line = operator_projection::WatchLine::Progress {
        at_ms: 1_700_000_000_400,
        event,
    };
    let json = serde_json::to_value(line).expect("watch progress line serializes");

    assert_eq!(json["kind"], "progress");
    assert_eq!(json["event"]["stage_name"], "implement");
    assert_eq!(json["event"]["byte_offset"], 99);
    assert_eq!(json["event"]["preview"], "delta");
    assert!(
        json.get("execution").is_none(),
        "progress lines carry ProgressEvent evidence, not a refreshed execution snapshot"
    );
}
