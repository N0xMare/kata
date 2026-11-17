//! Tests for operator_projection. Extracted from the inline #[cfg(test)] module.
use std::collections::BTreeMap;

use super::*;
use crate::types::{
    ExecutionCloseoutEvidence, ExecutionControllerApplicationEvidence,
    ExecutionControllerApplicationRecoveryEvidence, ExecutionControllerDecisionEvidence,
    ExecutionMemorySelectorEvidence, ExecutionMemoryWritebackEvidence, ExecutionProgramIdentity,
    ExecutionRecord, ExecutionStatus, ExecutionValidationEvidence, ExecutionWorkspacePromotion,
    ExecutionWorkspaceSnapshot, ExecutionWorkspaceWorktree, ParkedExecution,
};
use kata_types::execution::WorkflowClassIdentity;
use kata_types::ledger::{
    AgentInvocationGraph, AgentInvocationGraphNode, AgentInvocationKind, AgentInvocationStatus,
};
use kata_types::primitives::ContentHash;
use kata_types::workflow::ProgressVisibility;
use kata_types::workspace_awareness::ExecutionWorkspaceParking;
use smol_str::SmolStr;
use ulid::Ulid;

fn test_ulid(value: &str) -> Ulid {
    Ulid::from_string(value).expect("fixture ULID must parse")
}

fn controller_decision() -> ExecutionControllerDecisionEvidence {
    ExecutionControllerDecisionEvidence {
        schema_version: 1,
        stage_name: "controller".to_string(),
        decision_id: "decision-repair".to_string(),
        wave_id: Some("wave-1".to_string()),
        decision: "repair".to_string(),
        next_action: Some("advance".to_string()),
        reason: Some("repair validation".to_string()),
        evidence: Vec::new(),
        alternatives: Vec::new(),
        human_required: false,
        scope: None,
        completion: None,
        memory_policy: None,
        runtime_policy: None,
    }
}

fn recovered_controller_application(mode: &str) -> ExecutionControllerApplicationEvidence {
    let reason = match mode {
        "finalize_observed" => "operator finalized observed side effect",
        "resume_claimed_side_effect" => "operator requested retry of claimed side effect",
        _ => "claimed next execution is visible in the executor ledger",
    };
    ExecutionControllerApplicationEvidence {
        schema_version: 1,
        application_id: "advance:decision-repair".to_string(),
        decision_id: "decision-repair".to_string(),
        decision: "repair".to_string(),
        action: "advance".to_string(),
        applied: true,
        applied_at_ms: 4,
        source: Some("factory_controller_reconcile".to_string()),
        reason: Some("claimed next execution became visible".to_string()),
        error: None,
        next_execution_id: Some("01KPREVIEWNEXT00000000000".to_string()),
        parked_candidate: None,
        promotion: None,
        memory_policy: None,
        side_effect: None,
        recovery: Some(ExecutionControllerApplicationRecoveryEvidence {
            mode: mode.to_string(),
            source: Some(format!("factory_controller_{mode}")),
            reason: reason.to_string(),
            evidence: vec![
                "application_id=advance:decision-repair".to_string(),
                "next_execution_id=01KPREVIEWNEXT00000000000".to_string(),
            ],
        }),
    }
}

fn workspace() -> ExecutionWorkspaceSnapshot {
    ExecutionWorkspaceSnapshot {
        schema_version: 1,
        execution_id: "01KPREVIEW0000000000000000".to_string(),
        workflow_name: "factory-prev".to_string(),
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

fn status_with_decision(decision: ExecutionControllerDecisionEvidence) -> FactoryControllerStatus {
    FactoryControllerStatus {
        summary_kind: "factory_controller_status",
        execution_id: "01KPREVIEW0000000000000000".to_string(),
        workflow_name: "factory-prev".to_string(),
        status: ExecutionStatus::Completed,
        terminal: true,
        controller_decision_count: 1,
        controller_application_count: 0,
        latest_decision: Some(decision.clone()),
        latest_application: None,
        decisions: vec![decision.clone()],
        applications: Vec::new(),
        action: FactoryControllerAction {
            action: "none",
            applicable: false,
            decision_id: Some(decision.decision_id.clone()),
            decision: Some(decision.decision.clone()),
            reason: None,
        },
        workspace: workspace(),
    }
}

fn completed_record_for_report() -> ExecutionRecord {
    let graph_execution_id = test_ulid("01HV0VZTBP7TX5DQ1V0G7WB3SK");
    let assignment_id = test_ulid("01HV0VZTBP7TX5DQ1V0G7WB3SM");
    let invocation_id = test_ulid("01HV0VZTBP7TX5DQ1V0G7WB3SN");
    ExecutionRecord {
        target: None,
        id: "01KPREVIEW0000000000000000".to_string(),
        workflow_name: "factory-prev".to_string(),
        execution_program: Some(ExecutionProgramIdentity {
            schema_version: 1,
            program_hash: ContentHash::zero(),
            workflow_class: WorkflowClassIdentity {
                schema_version: 1,
                id: ContentHash::zero(),
            },
        }),
        status: ExecutionStatus::Completed,
        submitted_at_ms: 1,
        started_at_ms: Some(2),
        finished_at_ms: Some(3),
        worker_id: "worker-1".to_string(),
        outputs: Some(BTreeMap::from([(
            "closeout".to_string(),
            serde_json::json!({"summary": "done"}),
        )])),
        error: None,
        running_cost_micro_usd: 0,
        child_cost_micro_usd: 0,
        metering: kata_types::metering::MeteringSummary::default(),
        warnings: Vec::new(),
        agent_invocation_graph: Some(AgentInvocationGraph {
            execution_id: graph_execution_id,
            nodes: vec![AgentInvocationGraphNode {
                id: invocation_id,
                parent_id: None,
                assignment_id,
                execution_id: graph_execution_id,
                stage_name: SmolStr::new("implement"),
                kind: AgentInvocationKind::Worker,
                role: SmolStr::new("package_writer"),
                agent_label: Some(SmolStr::new("codex")),
                effect_kind: None,
                topology_kind: Some(SmolStr::new("root_with_parallel_workers")),
                model_hint: Some(SmolStr::new("gpt-5.5")),
                timeout_ms: Some(60_000),
                progress_visibility: ProgressVisibility::Summary,
                owned_paths: vec![SmolStr::new("README.md")],
                sync_with_assignment: true,
                status: AgentInvocationStatus::Completed,
                created_at_ms: 1,
                dispatched_at_ms: Some(1),
                started_at_ms: Some(2),
                finished_at_ms: Some(3),
                child_ids: Vec::new(),
                latest_progress: None,
                output: None,
            }],
            roots: vec![invocation_id],
            orphaned: Vec::new(),
        }),
        evidence: crate::types::ExecutionEvidence {
            validation_reports: vec![ExecutionValidationEvidence {
                stage_name: "validate".to_string(),
                status: Some("passed".to_string()),
                criteria: Vec::new(),
                commands: vec!["cargo test -p kata-client operator_projection".to_string()],
                evidence: vec!["all checks passed".to_string()],
                test_count: Some(1),
                git_sha: Some("abc123".to_string()),
                pgrep_clean: Some(true),
                check_artifacts: Vec::new(),
            }],
            closeout_reports: vec![ExecutionCloseoutEvidence {
                stage_name: "closeout".to_string(),
                outcome: Some("complete".to_string()),
                evidence: vec!["report packet emitted".to_string()],
                remaining: Vec::new(),
                next_action: Some("none".to_string()),
            }],
            memory_selectors: vec![ExecutionMemorySelectorEvidence {
                schema_version: 1,
                selector_id: "factory_active_context".to_string(),
                stage: Some("implement".to_string()),
                expose_as: "factory_context".to_string(),
                kinds: vec!["objective".to_string()],
                statuses: vec!["active".to_string()],
                max_objects: 4,
                required: true,
                query: Some("Kata report".to_string()),
                purpose: Some("closeout context".to_string()),
                revision_head: 7,
                object_count: 1,
                truncated: false,
                store_available: true,
                missing_required: false,
                objects: Vec::new(),
                projection: "factory_active_context: 1 object".to_string(),
                materialized_at_ms: 2,
            }],
            memory_writebacks: vec![ExecutionMemoryWritebackEvidence {
                schema_version: 1,
                writeback_id: "factory_controller_decisions".to_string(),
                stage_name: "controller".to_string(),
                object_id: Some("mem-1".to_string()),
                kind: Some("decision".to_string()),
                action: "applied".to_string(),
                reason: Some("controller decision retained".to_string()),
                source: Some("controller".to_string()),
            }],
            controller_decisions: vec![controller_decision()],
            ..crate::types::ExecutionEvidence::default()
        },
        routing: Vec::new(),
        capsule_networks: Vec::new(),
    }
}

#[test]
fn factory_candidate_packet_surfaces_live_candidate_actions() {
    let decision = controller_decision();
    let mut status = status_with_decision(decision);
    status.action = FactoryControllerAction {
        action: "park",
        applicable: true,
        decision_id: Some("decision-repair".to_string()),
        decision: Some("repair".to_string()),
        reason: None,
    };
    status.workspace.worktree = Some(ExecutionWorkspaceWorktree {
        path: "/tmp/kata-candidate".to_string(),
        exists: true,
        dirty: Some(true),
        changed_path_count: 1,
        changed_paths: vec!["README.md".to_string()],
        status_error: None,
        identity: None,
    });
    status.workspace.parking.available = true;
    status.workspace.parking.status = "ready_dirty_snapshot".to_string();

    let packet = factory_candidate_packet(&status);

    assert_eq!(packet.summary_kind, "factory_candidate");
    assert_eq!(packet.candidate_state, "live_worktree");
    assert_eq!(packet.source, "workspace_worktree");
    assert_eq!(packet.changed_paths, vec!["README.md"]);
    assert_eq!(
        packet
            .recommended_actions
            .iter()
            .map(|action| action.action.as_str())
            .collect::<Vec<_>>(),
        vec!["inspect_workspace", "inspect_live_diff", "park"]
    );
    let diff_action = packet
        .recommended_actions
        .iter()
        .find(|action| action.action == "inspect_live_diff")
        .expect("diff action");
    assert_eq!(
        diff_action.argv,
        vec![
            "git",
            "-C",
            "/tmp/kata-candidate",
            "diff",
            "--",
            "README.md"
        ]
    );
}

#[test]
fn factory_candidate_packet_surfaces_parked_candidate_evidence() {
    let decision = controller_decision();
    let mut status = status_with_decision(decision);
    status.workspace.parking.parked = true;
    status.workspace.parking.status = "parked".to_string();
    status.workspace.parking.candidate = Some(ParkedExecution {
        status: "parked".to_string(),
        parked_ref: "parked/kata-candidate".to_string(),
        commit_sha: "abc123".to_string(),
        identity: None,
    });

    let packet = factory_candidate_packet(&status);

    assert_eq!(packet.candidate_state, "parked");
    assert_eq!(packet.source, "parked_candidate_evidence");
    assert_eq!(
        packet
            .parked_candidate
            .as_ref()
            .map(|candidate| candidate.parked_ref.as_str()),
        Some("parked/kata-candidate")
    );
    assert_eq!(packet.changed_path_count, 0);
    assert!(
        packet
            .recommended_actions
            .iter()
            .any(|action| action.action == "replay_evidence")
    );
}

#[test]
fn execution_report_packet_composes_closeout_views() {
    let record = completed_record_for_report();
    let mut status = status_with_decision(controller_decision());
    let recovered_application = recovered_controller_application("reconcile_observed");
    status.controller_application_count = 1;
    status.latest_application = Some(recovered_application.clone());
    status.applications = vec![recovered_application];
    status.workspace.worktree = Some(ExecutionWorkspaceWorktree {
        path: "/tmp/kata-candidate".to_string(),
        exists: true,
        dirty: Some(true),
        changed_path_count: 1,
        changed_paths: vec!["README.md".to_string()],
        status_error: None,
        identity: None,
    });
    let packet = execution_report_from_parts(
        &record,
        vec![WorkerAttribution {
            stage_name: "implement".to_string(),
            assignment_id: "01HV0VZTBP7TX5DQ1V0G7WB3SM".to_string(),
            status: "completed".to_string(),
            worker_id: "worker-1".to_string(),
        }],
        status,
    );
    let json = serde_json::to_value(&packet).expect("report serializes");

    assert_eq!(packet.summary_kind, "operator_report");
    assert_eq!(packet.schema_version, 1);
    assert_eq!(packet.execution_id, "01KPREVIEW0000000000000000");
    assert_eq!(packet.checked_program_source, Some("record"));
    assert_eq!(packet.outcome.validation_report_count, 1);
    assert_eq!(packet.outcome.closeout_report_count, 1);
    assert_eq!(packet.stages.total, 1);
    assert_eq!(packet.stages.completed, 1);
    assert_eq!(packet.stages.output_stages, vec!["closeout"]);
    assert_eq!(
        packet.stages.stages[0].worker_id.as_deref(),
        Some("worker-1")
    );
    assert_eq!(packet.validation.report_count, 1);
    assert_eq!(packet.validation.passed, 1);
    assert_eq!(packet.closeout.report_count, 1);
    assert_eq!(packet.closeout.complete, 1);
    assert_eq!(packet.closeout.incomplete, 0);
    assert_eq!(packet.closeout.remaining_count, 0);
    assert_eq!(packet.closeout.next_actions, vec!["none"]);
    assert_eq!(packet.closeout.reports[0].stage_name, "closeout");
    assert_eq!(packet.closeout.reports[0].outcome, "complete");
    assert_eq!(packet.memory.selector_count, 1);
    assert_eq!(packet.memory.writeback_applied_count, 1);
    assert_eq!(
        packet.controller.latest_decision_id.as_deref(),
        Some("decision-repair")
    );
    assert_eq!(
        packet.controller.latest_application_id.as_deref(),
        Some("advance:decision-repair")
    );
    assert_eq!(
        packet.controller.latest_application_status.as_deref(),
        Some("applied")
    );
    assert_eq!(
        packet.controller.latest_application_action.as_deref(),
        Some("advance")
    );
    assert_eq!(
        packet
            .controller
            .latest_application_recovery_mode
            .as_deref(),
        Some("reconcile_observed")
    );
    assert_eq!(
        packet
            .controller
            .latest_application_recovery_source
            .as_deref(),
        Some("factory_controller_reconcile_observed")
    );
    assert_eq!(
        packet.controller.latest_application_recovery_evidence_count,
        Some(2)
    );
    assert_eq!(packet.candidate.summary_kind, "factory_candidate");
    assert_eq!(packet.candidate.candidate_state, "live_worktree");
    assert_eq!(packet.explain.summary_kind, "operator_explain");
    assert_eq!(
        json["explain"]["run_summary"]["summary_kind"],
        "operator_run_summary"
    );
    assert_eq!(
        json["explain"]["factory"]["summary_kind"],
        "factory_controller_status"
    );
    assert_eq!(json["stages"]["stages"][0]["stage_name"], "implement");
    assert_eq!(
        json["memory"]["selectors"][0]["selector_id"],
        "factory_active_context"
    );
    assert_eq!(
        json["controller"]["latest_application_recovery_mode"],
        "reconcile_observed"
    );
    assert!(
        packet
            .recommended_actions
            .iter()
            .any(|action| action.action == "inspect_live_diff")
    );
}

#[test]
fn execution_report_controller_summary_surfaces_recovery_modes() {
    let record = completed_record_for_report();

    for mode in [
        "reconcile_observed",
        "finalize_observed",
        "resume_claimed_side_effect",
    ] {
        let mut status = status_with_decision(controller_decision());
        let application = recovered_controller_application(mode);
        status.controller_application_count = 1;
        status.latest_application = Some(application.clone());
        status.applications = vec![application];

        let packet = execution_report_from_parts(&record, Vec::new(), status);
        let json = serde_json::to_value(&packet).expect("report serializes");
        let expected_source = format!("factory_controller_{mode}");

        assert_eq!(
            packet.controller.latest_application_id.as_deref(),
            Some("advance:decision-repair")
        );
        assert_eq!(
            packet.controller.latest_application_status.as_deref(),
            Some("applied")
        );
        assert_eq!(
            packet.controller.latest_application_action.as_deref(),
            Some("advance")
        );
        assert_eq!(
            packet
                .controller
                .latest_application_recovery_mode
                .as_deref(),
            Some(mode)
        );
        assert_eq!(
            packet
                .controller
                .latest_application_recovery_source
                .as_deref(),
            Some(expected_source.as_str())
        );
        assert!(
            packet
                .controller
                .latest_application_recovery_reason
                .as_deref()
                .is_some_and(|reason| !reason.is_empty())
        );
        assert_eq!(
            packet.controller.latest_application_recovery_evidence_count,
            Some(2)
        );
        assert_eq!(json["controller"]["latest_application_recovery_mode"], mode);
        assert_eq!(
            json["controller"]["latest_application_recovery_evidence_count"],
            2
        );
    }
}

#[test]
fn execution_report_surfaces_blockers_without_hiding_actions() {
    let mut record = completed_record_for_report();
    record.execution_program = None;
    record.status = ExecutionStatus::Failed;
    record.error = Some("validator crashed".to_string());
    record.evidence.validation_reports[0].status = Some("failed".to_string());
    let mut workspace = workspace();
    workspace.promotion.blockers = vec!["validation_criterion:vc-report:failed".to_string()];
    let status = factory_controller_status_from_parts(&record, workspace);

    let packet = execution_report_from_parts(&record, Vec::new(), status);

    assert!(
        packet
            .blockers
            .iter()
            .any(|blocker| blocker.code == "checked_program_missing")
    );
    assert!(
        packet
            .blockers
            .iter()
            .any(|blocker| blocker.code == "execution_failed")
    );
    assert!(
        packet
            .blockers
            .iter()
            .all(|blocker| blocker.source != "validation")
    );
    assert!(packet.blockers.iter().any(|blocker| {
        blocker.source == "workspace_promotion"
            && blocker
                .message
                .contains("validation_criterion:vc-report:failed")
    }));
    assert!(!packet.recommended_actions.is_empty());
}

/// Worker attribution waits only for attempts a WORKER can attribute. A
/// main-resolved node (an `Invoke`, a join, a reused stage) is never placed, so no
/// ledger event will ever carry a worker for it; expecting it made
/// `collect_worker_attribution` wait out its whole drain on every such execution.
///
/// **Watched red:** with every graph node expected, the set held the main node's
/// assignment id too.
#[test]
fn worker_attribution_expects_only_dispatched_nodes() {
    let mut record = completed_record_for_report();
    let graph = record
        .agent_invocation_graph
        .as_mut()
        .expect("the fixture carries a graph");
    let dispatched = graph.nodes[0].assignment_id;
    let mut main_resolved = graph.nodes[0].clone();
    main_resolved.id = test_ulid("01HV0VZTBP7TX5DQ1V0G7WB3SP");
    main_resolved.assignment_id = test_ulid("01HV0VZTBP7TX5DQ1V0G7WB3SQ");
    main_resolved.stage_name = SmolStr::new("sub");
    main_resolved.dispatched_at_ms = None;
    main_resolved.started_at_ms = None;
    graph.nodes.push(main_resolved);

    assert_eq!(
        super::worker_attribution::expected_worker_assignment_ids(&record),
        std::collections::BTreeSet::from([dispatched.to_string()]),
    );
}
