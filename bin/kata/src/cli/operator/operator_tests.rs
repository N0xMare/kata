//! Tests for the operator module. Extracted from the inline #[cfg(test)] module.
use super::*;
use kata_client::ExecutionRecord;
use kata_client::operator_projection::{
    execution_report_from_parts, explain_summary, factory_controller_action,
    factory_controller_status_from_parts,
};
use kata_client::types::{
    ExecutionControllerApplicationEvidence, ExecutionControllerDecisionEvidence, ExecutionEvidence,
    ExecutionStatus, ExecutionWorkspacePromotion, ExecutionWorkspaceSnapshot,
    ExecutionWorkspaceWorktree, ParkedExecution,
};
use kata_types::execution::{
    EXECUTION_WORKSPACE_IDENTITY_SCHEMA_VERSION, ExecutionControllerApplicationRecoveryEvidence,
    ExecutionControllerApplicationSideEffectEvidence, ExecutionWorkspaceIdentity,
    WorkflowClassIdentity,
};
use kata_types::primitives::ContentHash;
use kata_types::workspace_awareness::ExecutionWorkspaceParking;

fn workspace_with_blockers(blockers: Vec<String>) -> ExecutionWorkspaceSnapshot {
    ExecutionWorkspaceSnapshot {
        schema_version: 1,
        execution_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
        workflow_name: "factory-test".to_string(),
        status: "completed".to_string(),
        workspace_provider_attached: false,
        workspace_provider_backend: None,
        worktree: None,
        promotion: ExecutionWorkspacePromotion {
            available: true,
            safe_to_promote: blockers.is_empty(),
            status: if blockers.is_empty() {
                "clean"
            } else {
                "validation_criteria_missing"
            }
            .to_string(),
            blockers,
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

fn controller_decision(decision: &str) -> ExecutionControllerDecisionEvidence {
    ExecutionControllerDecisionEvidence {
        schema_version: 1,
        stage_name: "controller".to_string(),
        decision_id: format!("decision-{decision}"),
        wave_id: None,
        decision: decision.to_string(),
        next_action: None,
        reason: None,
        evidence: Vec::new(),
        alternatives: Vec::new(),
        human_required: false,
        scope: None,
        completion: None,
        memory_policy: None,
        runtime_policy: None,
    }
}

fn completed_record_with_decision(decision: &str) -> ExecutionRecord {
    ExecutionRecord {
        target: None,
        id: "01HZZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
        workflow_name: "factory-test".to_string(),
        execution_program: None,
        status: ExecutionStatus::Completed,
        submitted_at_ms: 1,
        started_at_ms: Some(2),
        finished_at_ms: Some(3),
        worker_id: "worker-1".to_string(),
        outputs: None,
        error: None,
        running_cost_micro_usd: 0,
        child_cost_micro_usd: 0,
        metering: kata_types::metering::MeteringSummary::default(),
        warnings: Vec::new(),
        agent_invocation_graph: None,
        evidence: ExecutionEvidence {
            controller_decisions: vec![controller_decision(decision)],
            ..ExecutionEvidence::default()
        },
        routing: Vec::new(),
        capsule_networks: Vec::new(),
    }
}

fn completed_record_with_applied_decision(decision: &str, action: &str) -> ExecutionRecord {
    let mut record = completed_record_with_decision(decision);
    record
        .evidence
        .controller_applications
        .push(ExecutionControllerApplicationEvidence {
            schema_version: kata_client::types::CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION,
            application_id: format!("{action}:decision-{decision}"),
            decision_id: format!("decision-{decision}"),
            decision: decision.to_string(),
            action: action.to_string(),
            applied: true,
            applied_at_ms: 4,
            source: Some("factory_controller".to_string()),
            reason: None,
            error: None,
            next_execution_id: Some("01HZZZZZZZZZZZZZZZZZZZZZZY".to_string()),
            parked_candidate: None,
            promotion: None,
            memory_policy: None,
            side_effect: None,
            recovery: None,
        });
    record
}

fn completed_record_with_claimed_decision(decision: &str, action: &str) -> ExecutionRecord {
    let mut record = completed_record_with_applied_decision(decision, action);
    let application = record
        .evidence
        .controller_applications
        .last_mut()
        .expect("seeded controller application");
    application.applied = false;
    application.next_execution_id = None;
    application.reason = Some("claim written before interrupted side effect".to_string());
    application.side_effect = match action {
        "park" => Some(ExecutionControllerApplicationSideEffectEvidence {
            kind: "park".to_string(),
            parked_ref: Some("parked/01HZZZZZZZZZZZZZZZZZZZZZZZ".to_string()),
            next_execution_id: None,
            workflow_label: None,
            workflow_program_hash: None,
            external_input_channel: None,
            external_input_id: None,
            effective_cost_limit_micro_usd: None,
            cost_consumed_micro_usd: None,
            deadline_at_ms: None,
            next_wave_stage_timeout_ms: None,
            runtime_authority_source: None,
        }),
        _ => None,
    };
    record
}

#[test]
fn memory_inbox_summary_counts_terminal_statuses() {
    let summary = MemoryInboxImportSummary::from_results(
        ".kata/memory/inbox".to_string(),
        Some(".kata/memory/archive".to_string()),
        false,
        4,
        vec![
            MemoryInboxImportResult {
                file: "applied.json".to_string(),
                status: "applied".to_string(),
                response: None,
                error: None,
                archived_to: Some("archive/applied.json".to_string()),
                deleted: false,
            },
            MemoryInboxImportResult {
                file: "conflict.json".to_string(),
                status: "conflicted".to_string(),
                response: None,
                error: None,
                archived_to: Some("archive/conflict.json".to_string()),
                deleted: false,
            },
            MemoryInboxImportResult {
                file: "bad.json".to_string(),
                status: "failed".to_string(),
                response: None,
                error: Some("invalid json".to_string()),
                archived_to: None,
                deleted: false,
            },
            MemoryInboxImportResult {
                file: "README.md".to_string(),
                status: "skipped".to_string(),
                response: None,
                error: Some("not a JSON proposal file".to_string()),
                archived_to: None,
                deleted: false,
            },
        ],
    );

    assert_eq!(summary.total_entries, 4);
    assert_eq!(summary.total_files, 3);
    assert_eq!(summary.imported, 2);
    assert_eq!(summary.applied, 1);
    assert_eq!(summary.conflicted, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.skipped, 1);
}

#[test]
fn memory_inbox_entries_separates_json_files_from_skips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inbox = dir.path();
    std::fs::write(inbox.join("proposal.json"), "{}").expect("write proposal");
    std::fs::write(inbox.join("notes.txt"), "not json").expect("write notes");
    std::fs::create_dir(inbox.join("nested")).expect("mkdir nested");

    let entries = memory_inbox_entries(inbox).expect("scan inbox");

    assert_eq!(entries.total_entries, 3);
    assert_eq!(entries.files, vec![inbox.join("proposal.json")]);
    assert_eq!(entries.skipped.len(), 2);
    assert!(
        entries
            .skipped
            .iter()
            .any(|skipped| skipped.path == inbox.join("notes.txt")
                && skipped.reason == "not a JSON proposal file")
    );
    assert!(
        entries
            .skipped
            .iter()
            .any(|skipped| skipped.path == inbox.join("nested")
                && skipped.reason == "not a regular file")
    );
}

#[test]
fn archive_memory_inbox_file_uses_unique_destination() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inbox = dir.path().join("inbox");
    let archive = dir.path().join("archive");
    std::fs::create_dir_all(&inbox).expect("create inbox");
    std::fs::create_dir_all(&archive).expect("create archive");
    let existing = archive.join("proposal.json");
    std::fs::write(&existing, "old").expect("write existing archive file");
    let proposal = inbox.join("proposal.json");
    std::fs::write(&proposal, "new").expect("write proposal");

    let archived = archive_memory_inbox_file(&proposal, &archive).expect("archive file");

    assert_eq!(archived, archive.join("proposal.json.1"));
    assert!(!proposal.exists());
    assert_eq!(std::fs::read_to_string(existing).unwrap(), "old");
    assert_eq!(std::fs::read_to_string(archived).unwrap(), "new");
}

#[test]
fn controller_apply_workflow_source_snapshots_refs_and_starlark() {
    let library = controller_apply_workflow_source("std.software_factory.smoke")
        .expect("library ref resolves");
    assert_eq!(
        library.workflow_ref.as_deref(),
        Some("std.software_factory.smoke")
    );
    assert!(library.workflow_starlark.is_none());
    assert!(library.workflow_filename.is_none());

    let dir = tempfile::tempdir().expect("tempdir");
    let star = dir.path().join("factory.star");
    std::fs::write(
        &star,
        "only = stage(id = \"only\", prompt = \"hi\")\nworkflow(\"factory-star\", root = [only])\n",
    )
    .expect("write Starlark workflow");
    let star_source = controller_apply_workflow_source(star.to_str().expect("utf8 path"))
        .expect("Starlark path snapshots");
    assert!(star_source.workflow_ref.is_none());
    assert!(
        star_source
            .workflow_starlark
            .as_deref()
            .unwrap()
            .contains("factory-star")
    );
    assert_eq!(
        star_source.workflow_filename.as_deref(),
        Some(star.to_str().expect("utf8 path"))
    );
}

#[test]
fn factory_status_marks_refine_decisions_non_applicable() {
    // In the in-execution-loop model a refine decision (continue / repair /
    // split / reduce_scope) is consumed by the loop, not by an operator
    // command. There is no manual advance, so the operator-status action is
    // informational and never applicable.
    for decision_kind in ["repair", "continue", "split", "reduce_scope"] {
        let workspace = workspace_with_blockers(Vec::new());
        let decision = controller_decision(decision_kind);

        let action = factory_controller_action(Some(&decision), None, &workspace);

        assert_eq!(action.action, "none", "{decision_kind}");
        assert!(!action.applicable, "{decision_kind}");
        assert_eq!(action.decision.as_deref(), Some(decision_kind));
        assert!(
            action
                .reason
                .as_deref()
                .expect("reason")
                .contains("in-execution loop"),
            "{decision_kind}: {:?}",
            action.reason
        );
    }
}

#[test]
fn factory_status_treats_stop_decision_as_terminal_noop() {
    let workspace = workspace_with_blockers(Vec::new());
    let decision = controller_decision("stop");

    let action = factory_controller_action(Some(&decision), None, &workspace);

    assert_eq!(action.action, "none");
    assert!(!action.applicable);
    assert_eq!(action.decision_id.as_deref(), Some("decision-stop"));
    assert_eq!(action.decision.as_deref(), Some("stop"));
    assert_eq!(
        action.reason.as_deref(),
        Some("controller decision `stop` completed the factory run")
    );
}

#[test]
fn factory_status_from_parts_reuses_action_policy() {
    let record = completed_record_with_decision("promote");
    let mut workspace = workspace_with_blockers(Vec::new());
    workspace.workspace_provider_attached = true;

    let status = factory_controller_status_from_parts(&record, workspace);

    assert_eq!(status.summary_kind, "factory_controller_status");
    assert_eq!(status.execution_id, record.id);
    assert_eq!(status.controller_decision_count, 1);
    assert_eq!(status.action.action, "promote");
    assert!(status.action.applicable);
    assert_eq!(
        status.action.decision_id.as_deref(),
        Some("decision-promote")
    );
}

#[test]
fn factory_status_blocks_already_applied_controller_decision() {
    let record = completed_record_with_applied_decision("repair", "advance");
    let workspace = workspace_with_blockers(Vec::new());

    let status = factory_controller_status_from_parts(&record, workspace);

    assert_eq!(status.controller_application_count, 1);
    assert_eq!(
        status
            .latest_application
            .as_ref()
            .map(|app| app.action.as_str()),
        Some("advance")
    );
    assert_eq!(status.action.action, "none");
    assert!(!status.action.applicable);
    assert_eq!(
        status.action.reason.as_deref(),
        Some("controller decision `decision-repair` was already applied by `advance`")
    );
}

#[test]
fn factory_status_surfaces_incomplete_controller_application_claim() {
    let record = completed_record_with_claimed_decision("park", "park");
    let workspace = workspace_with_blockers(Vec::new());

    let status = factory_controller_status_from_parts(&record, workspace);
    let json = serde_json::to_value(&status).expect("factory status serializes");

    assert_eq!(status.controller_application_count, 1);
    assert_eq!(
        status.latest_application.as_ref().map(|app| app.applied),
        Some(false)
    );
    assert_eq!(status.action.action, "finalize");
    assert!(!status.action.applicable);
    let reason = status.action.reason.as_deref().expect("finalize reason");
    assert!(reason.contains("incomplete `park` application claim"));
    assert!(reason.contains("--confirm-side-effect"));
    assert!(reason.contains("--reason <reason>"));
    assert!(reason.contains("--evidence <proof>"));
    assert!(reason.contains("--resume-claimed-side-effect"));
    assert_eq!(json["latest_application"]["applied"], false);
    assert_eq!(json["action"]["action"], "finalize");

    let packet = explain_summary(&record, workspace_with_blockers(Vec::new()));
    let explain = serde_json::to_value(packet).expect("explain packet serializes");
    assert_eq!(
        explain["headline"],
        "controller chose `park`; `park` application claim needs finalization"
    );
    assert_eq!(
        explain["factory"]["latest_application"]["applied"],
        serde_json::Value::Bool(false)
    );
    assert!(
        explain["why"]
            .as_array()
            .expect("why array")
            .iter()
            .any(|entry| entry.as_str().is_some_and(
                |text| text.contains("kata factory finalize --decision-id decision-park")
            ))
    );
    assert_eq!(explain["recommended_actions"][0]["action"], "retry_apply");
    assert_eq!(
        explain["recommended_actions"][0]["command"],
        "kata factory apply 01HZZZZZZZZZZZZZZZZZZZZZZZ --decision-id decision-park --action park"
    );
    assert_eq!(explain["recommended_actions"][1]["action"], "finalize");
    assert_eq!(
        explain["recommended_actions"][1]["command"],
        "kata factory finalize 01HZZZZZZZZZZZZZZZZZZZZZZZ --decision-id decision-park --action park --confirm-side-effect --reason <reason> --evidence <proof>"
    );
    assert_eq!(
        explain["recommended_actions"][2]["action"],
        "resume_claimed_side_effect"
    );
    assert_eq!(
        explain["recommended_actions"][2]["command"],
        "kata factory apply 01HZZZZZZZZZZZZZZZZZZZZZZZ --decision-id decision-park --action park --resume-claimed-side-effect"
    );
}

#[test]
fn explain_packet_recommends_safe_factory_apply() {
    let record = completed_record_with_decision("promote");
    let mut workspace = workspace_with_blockers(Vec::new());
    workspace.workspace_provider_attached = true;

    let packet = explain_summary(&record, workspace);
    let json = serde_json::to_value(packet).expect("explain packet serializes");

    assert_eq!(json["summary_kind"], "operator_explain");
    assert_eq!(
        json["headline"],
        "controller chose `promote`; the candidate is safe to promote"
    );
    assert_eq!(json["recommended_actions"][0]["action"], "promote");
    assert_eq!(
        json["recommended_actions"][0]["command"],
        "kata factory apply 01HZZZZZZZZZZZZZZZZZZZZZZZ --decision-id decision-promote"
    );
    assert_eq!(json["evidence_counts"]["controller_decisions"], 1);
    assert_eq!(json["factory"]["action"]["action"], "promote");
    assert_eq!(json["run_summary"]["summary_kind"], "operator_run_summary");
}

#[test]
fn operator_status_without_runs_points_to_factory_preflight() {
    let actions = operator_status_recommended_actions(None, None);

    assert_eq!(actions[0].action, "run_factory_preflight");
    assert_eq!(
        actions[0].command.as_deref(),
        Some(
            "kata factory run std.software_factory.kata_self_improve_preflight --wait --timeout-secs 900"
        )
    );
}

#[test]
fn operator_status_reuses_factory_action_policy() {
    let record = completed_record_with_decision("promote");
    let mut workspace = workspace_with_blockers(Vec::new());
    workspace.workspace_provider_attached = true;
    let status = factory_controller_status_from_parts(&record, workspace);

    let actions = operator_status_recommended_actions(None, Some(&status));

    assert_eq!(actions[0].action, "promote");
    assert_eq!(
        actions[0].command.as_deref(),
        Some("kata factory apply 01HZZZZZZZZZZZZZZZZZZZZZZZ --decision-id decision-promote")
    );
}

#[test]
fn operator_status_does_not_recommend_advance_for_refine_decision() {
    // The in-execution loop iterates waves internally; a refine decision
    // never produces an operator `kata factory advance` recommendation.
    let record = completed_record_with_decision("continue");
    let mut workspace = workspace_with_blockers(Vec::new());
    workspace.workspace_provider_attached = true;
    workspace.promotion.safe_to_promote = true;
    workspace.promotion.status = "ready_dirty_snapshot".to_string();
    let status = factory_controller_status_from_parts(&record, workspace);

    let actions = operator_status_recommended_actions(None, Some(&status));

    assert!(
        !actions
            .iter()
            .any(|action| action.action == "advance" || action.action == "promote_then_advance"),
        "refine decisions must not recommend advance: {actions:?}"
    );
    assert!(
        actions.iter().all(|action| action
            .command
            .as_deref()
            .is_none_or(|command| !command.contains("kata factory advance"))),
        "no advance command may be recommended: {actions:?}"
    );
    // The status falls through to the informational explain action.
    assert!(actions.iter().any(|action| action.action == "explain"));
}

#[test]
fn operator_status_recommends_claim_recovery_actions() {
    let record = completed_record_with_claimed_decision("park", "park");
    let workspace = workspace_with_blockers(Vec::new());
    let status = factory_controller_status_from_parts(&record, workspace);

    let actions = operator_status_recommended_actions(None, Some(&status));

    assert_eq!(actions[0].action, "retry_apply");
    assert_eq!(
        actions[0].command.as_deref(),
        Some(
            "kata factory apply 01HZZZZZZZZZZZZZZZZZZZZZZZ --decision-id decision-park --action park"
        )
    );
    assert_eq!(actions[1].action, "finalize");
    assert_eq!(
        actions[1].command.as_deref(),
        Some(
            "kata factory finalize 01HZZZZZZZZZZZZZZZZZZZZZZZ --decision-id decision-park --action park --confirm-side-effect --reason <reason> --evidence <proof>"
        )
    );
    assert_eq!(actions[2].action, "resume_claimed_side_effect");
    assert_eq!(
        actions[2].command.as_deref(),
        Some(
            "kata factory apply 01HZZZZZZZZZZZZZZZZZZZZZZZ --decision-id decision-park --action park --resume-claimed-side-effect"
        )
    );
}

#[test]
fn report_text_surfaces_controller_application_recovery_state() {
    let mut record = completed_record_with_applied_decision("repair", "advance");
    let application = record
        .evidence
        .controller_applications
        .first_mut()
        .expect("applied controller application");
    application.recovery = Some(ExecutionControllerApplicationRecoveryEvidence {
        mode: "resume_claimed_side_effect".to_string(),
        source: Some("factory_controller_resume".to_string()),
        reason: "operator requested retry of claimed next-wave side effect".to_string(),
        evidence: vec![
            "application_id=advance:decision-repair".to_string(),
            "next_execution_id=01HZZZZZZZZZZZZZZZZZZZZZZY".to_string(),
        ],
    });
    let workspace = workspace_with_blockers(Vec::new());
    let status = factory_controller_status_from_parts(&record, workspace);
    let report = execution_report_from_parts(&record, Vec::new(), status);

    let text = render_report_text(&report).expect("report text renders");

    assert!(text.contains("latest_application=advance"), "{text}");
    assert!(text.contains("latest_application_status=applied"), "{text}");
    assert!(
        text.contains("recovery=resume_claimed_side_effect"),
        "{text}"
    );
    assert!(text.contains("recovery_evidence=2"), "{text}");
    assert!(text.contains("closeout: reports=0"), "{text}");
    // The JSON pointer names the global `--format json`: report takes no
    // per-command `--json` (`enveloped_commands_refuse_a_per_command_json_flag`).
    assert!(
        text.contains(&format!(
            "\njson: kata --format json report {}\n",
            record.id
        )),
        "{text}"
    );
    assert!(
        text.find("blockers:").is_some_and(|blockers| text
            .find("\nchecked_program:")
            .is_some_and(|checked| blockers < checked)),
        "report text must be blocker-first, got: {text}"
    );
    assert!(
        text.find("next_actions:").is_some_and(|actions| text
            .find("\nchecked_program:")
            .is_some_and(|checked| actions < checked)),
        "report text must put safe next actions before detail sections, got: {text}"
    );
}

fn sample_workspace_identity(
    backend: &str,
    target_ref: &str,
    target_commit: &str,
) -> ExecutionWorkspaceIdentity {
    ExecutionWorkspaceIdentity {
        schema_version: EXECUTION_WORKSPACE_IDENTITY_SCHEMA_VERSION,
        execution_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
        invocation_id: None,
        stage_name: None,
        backend: backend.to_string(),
        workspace_ref: Some("exec-01HZZZZZZZZZZZZZZZZZZZZZZZ".to_string()),
        workspace_commit_sha: Some("abc123".to_string()),
        base_ref: Some("main".to_string()),
        base_commit_sha: Some("base123".to_string()),
        target_ref: Some(target_ref.to_string()),
        target_commit_sha: Some(target_commit.to_string()),
        author: Some("Ada Lovelace <ada@example.invalid>".to_string()),
    }
}

#[test]
fn report_text_surfaces_parked_candidate_workspace_identity() {
    let record = completed_record_with_decision("park");
    let mut workspace = workspace_with_blockers(Vec::new());
    workspace.workspace_provider_attached = true;
    workspace.workspace_provider_backend = Some("jj".to_string());
    workspace.parking.available = true;
    workspace.parking.parked = true;
    workspace.parking.status = "parked".to_string();
    workspace.parking.candidate = Some(ParkedExecution {
        status: "parked".to_string(),
        parked_ref: "parked/01HZZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
        commit_sha: "abc123".to_string(),
        identity: Some(sample_workspace_identity(
            "jj",
            "parked/01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "abc123",
        )),
    });
    let status = factory_controller_status_from_parts(&record, workspace);
    let report = execution_report_from_parts(&record, Vec::new(), status);

    let text = render_report_text(&report).expect("report text renders");

    assert!(text.contains("candidate: parked"), "{text}");
    assert!(
        text.contains("workspace_identity: origin=parked_candidate backend=jj"),
        "{text}"
    );
    assert!(
        text.contains("target_ref=parked/01HZZZZZZZZZZZZZZZZZZZZZZZ"),
        "{text}"
    );
    assert!(text.contains("target_commit=abc123"), "{text}");
    // WHO committed it. Three commit SHAs without an author would let an
    // operator see which commit was attested and not who wrote it.
    assert!(
        text.contains("author=Ada Lovelace <ada@example.invalid>"),
        "{text}"
    );
}

#[test]
fn report_text_surfaces_live_worktree_workspace_identity() {
    let record = completed_record_with_decision("continue");
    let mut workspace = workspace_with_blockers(Vec::new());
    workspace.workspace_provider_attached = true;
    workspace.workspace_provider_backend = Some("jj".to_string());
    workspace.worktree = Some(ExecutionWorkspaceWorktree {
        path: "/tmp/exec-ws".to_string(),
        exists: true,
        dirty: Some(true),
        changed_path_count: 2,
        changed_paths: vec!["src/lib.rs".to_string(), "README.md".to_string()],
        status_error: None,
        identity: Some(sample_workspace_identity(
            "jj",
            "exec-01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "abc123",
        )),
    });
    let status = factory_controller_status_from_parts(&record, workspace);
    let report = execution_report_from_parts(&record, Vec::new(), status);

    let text = render_report_text(&report).expect("report text renders");

    assert!(text.contains("candidate: live_worktree"), "{text}");
    assert!(
        text.contains("workspace_identity: origin=live_worktree backend=jj"),
        "{text}"
    );
    assert!(
        text.contains("workspace_ref=exec-01HZZZZZZZZZZZZZZZZZZZZZZZ"),
        "{text}"
    );
}

#[test]
fn report_text_surfaces_controller_recovery_source_and_reason() {
    let mut record = completed_record_with_applied_decision("repair", "advance");
    let application = record
        .evidence
        .controller_applications
        .first_mut()
        .expect("applied controller application");
    application.recovery = Some(ExecutionControllerApplicationRecoveryEvidence {
        mode: "finalize_observed".to_string(),
        source: Some("operator_admin_finalize".to_string()),
        reason: "operator confirmed\npromotion in base repo".to_string(),
        evidence: vec!["base repo contains promoted candidate commit".to_string()],
    });
    let workspace = workspace_with_blockers(Vec::new());
    let status = factory_controller_status_from_parts(&record, workspace);
    let report = execution_report_from_parts(&record, Vec::new(), status);

    let text = render_report_text(&report).expect("report text renders");

    assert!(text.contains("recovery=finalize_observed"), "{text}");
    assert!(
        text.contains("recovery_source=operator_admin_finalize"),
        "{text}"
    );
    assert!(
        text.contains("recovery_reason=operator confirmed promotion in base repo"),
        "free-form recovery reason must be collapsed onto one line: {text}"
    );
    assert!(text.contains("recovery_evidence=1"), "{text}");
}

#[test]
fn report_text_renders_workspace_identity_none_without_attestation() {
    let record = completed_record_with_decision("stop");
    let workspace = workspace_with_blockers(Vec::new());
    let status = factory_controller_status_from_parts(&record, workspace);
    let report = execution_report_from_parts(&record, Vec::new(), status);

    let text = render_report_text(&report).expect("report text renders");

    assert!(text.contains("workspace_identity: none"), "{text}");
    assert!(text.contains("recovery=none"), "{text}");
    assert!(text.contains("recovery_source=none"), "{text}");
    assert!(text.contains("recovery_reason=none"), "{text}");
}

#[test]
fn explain_text_is_blocker_first_and_action_oriented() {
    let record = completed_record_with_claimed_decision("park", "park");
    let packet = explain_summary(&record, workspace_with_blockers(Vec::new()));
    let text = render_explain_text(&packet).expect("explain text renders");

    assert!(
        text.contains(&format!("Kata explain: {}", record.id)),
        "{text}"
    );
    assert!(text.contains("headline:"), "{text}");
    assert!(text.contains("next_actions:"), "{text}");
    assert!(
        text.contains("- [retry_apply] kata factory apply"),
        "explain text must render recommended actions with command: {text}"
    );
    assert!(text.contains("factory: action="), "{text}");
    assert!(text.contains("evidence: warnings="), "{text}");
    // The JSON pointer names the global `--format json`: explain takes no
    // per-command `--json` (`enveloped_commands_refuse_a_per_command_json_flag`).
    assert!(
        text.contains(&format!(
            "\njson: kata --format json explain {}\n",
            record.id
        )),
        "{text}"
    );
    // Blocker-first: headline / why / next_actions precede detail sections.
    assert!(
        text.find("next_actions:")
            .is_some_and(|na| text.find("\nfactory:").is_some_and(|f| na < f)),
        "explain text must put next actions before factory/evidence detail: {text}"
    );
}

#[test]
fn report_bundle_dir_writes_strict_evidence_artifacts() {
    let mut record = completed_record_with_decision("stop");
    record.execution_program = Some(kata_client::types::ExecutionProgramIdentity {
        schema_version: 1,
        program_hash: ContentHash::zero(),
        workflow_class: WorkflowClassIdentity {
            schema_version: 1,
            id: ContentHash::zero(),
        },
    });
    let mut workspace = workspace_with_blockers(Vec::new());
    workspace.workspace_provider_attached = true;
    workspace.workspace_provider_backend = Some("jj".to_string());
    let status = factory_controller_status_from_parts(&record, workspace);
    let report = execution_report_from_parts(&record, Vec::new(), status);
    let dir = tempfile::tempdir().expect("tempdir");

    let summary = write_report_bundle_dir(&report, dir.path()).expect("bundle writes");

    assert_eq!(summary.status, "passed");
    for artifact in REPORT_BUNDLE_ARTIFACTS {
        assert!(
            dir.path().join(artifact).is_file(),
            "missing report bundle artifact {artifact}"
        );
    }
    let evidence_summary_path = dir.path().join("evidence-summary.json");
    assert!(evidence_summary_path.is_file());
    let evidence_summary: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&evidence_summary_path).expect("read evidence summary"),
    )
    .expect("evidence summary json");
    assert_eq!(evidence_summary["summary_kind"], "operator_report_bundle");
    assert_eq!(evidence_summary["status"], "passed");
    assert_eq!(
        evidence_summary["artifacts"]
            .as_array()
            .expect("artifacts array")
            .len(),
        REPORT_BUNDLE_ARTIFACTS.len()
    );
    assert!(
        evidence_summary["artifacts"]
            .as_array()
            .expect("artifacts array")
            .iter()
            .any(|artifact| artifact.as_str() == Some("evidence-summary.json")),
        "bundle manifest must declare evidence-summary.json"
    );
    let report_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("report.json")).expect("read report"),
    )
    .expect("report json");
    assert_eq!(report_json["summary_kind"], "operator_report");
    assert_eq!(report_json["execution_id"], record.id);

    let err = write_report_bundle_dir(&report, dir.path()).expect_err("non-empty dir rejected");
    assert!(
        err.to_string().contains("must be empty"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn operator_status_does_not_resume_custom_park_claim() {
    let mut record = completed_record_with_claimed_decision("park", "park");
    let application = record
        .evidence
        .controller_applications
        .first_mut()
        .expect("claim");
    application
        .side_effect
        .as_mut()
        .expect("park side effect")
        .parked_ref = Some("parked/custom-claim".to_string());
    let workspace = workspace_with_blockers(Vec::new());
    let status = factory_controller_status_from_parts(&record, workspace);

    let actions = operator_status_recommended_actions(None, Some(&status));

    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0].action, "retry_apply");
    assert_eq!(actions[1].action, "finalize");
}

#[test]
fn operator_status_keeps_promote_claim_recovery_finalize_only() {
    let record = completed_record_with_claimed_decision("promote", "promote");
    let workspace = workspace_with_blockers(Vec::new());
    let status = factory_controller_status_from_parts(&record, workspace);

    let actions = operator_status_recommended_actions(None, Some(&status));

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].action, "finalize");
    assert_eq!(
        actions[0].command.as_deref(),
        Some(
            "kata factory finalize 01HZZZZZZZZZZZZZZZZZZZZZZZ --decision-id decision-promote --action promote --confirm-side-effect --reason <reason> --evidence <proof>"
        )
    );
}

#[test]
fn operator_status_keeps_composite_claim_recovery_finalize_only() {
    let record = completed_record_with_claimed_decision("continue", "promote_then_advance");
    let workspace = workspace_with_blockers(Vec::new());
    let status = factory_controller_status_from_parts(&record, workspace);

    let actions = operator_status_recommended_actions(None, Some(&status));

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].action, "finalize");
    assert_eq!(
        actions[0].command.as_deref(),
        Some(
            "kata factory finalize 01HZZZZZZZZZZZZZZZZZZZZZZZ --decision-id decision-continue --action promote_then_advance --confirm-side-effect --reason <reason> --evidence <proof>"
        )
    );
}

#[test]
fn factory_run_initial_options_require_context() {
    let err = factory_initial_context_inputs(
        None,
        None,
        Some("operator_steering".to_string()),
        None,
        None,
        None,
        None,
    )
    .expect_err("channel without context must fail");

    assert!(
        err.to_string()
            .contains("initial input options require --context")
    );
}

fn terminal_record(status: ExecutionStatus, error: Option<&str>) -> ExecutionRecord {
    ExecutionRecord {
        target: None,
        id: "01HZZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
        workflow_name: "factory-test".to_string(),
        execution_program: None,
        status,
        submitted_at_ms: 1,
        started_at_ms: Some(2),
        finished_at_ms: Some(3),
        worker_id: "worker-1".to_string(),
        outputs: None,
        error: error.map(str::to_string),
        running_cost_micro_usd: 0,
        child_cost_micro_usd: 0,
        metering: kata_types::metering::MeteringSummary::default(),
        warnings: Vec::new(),
        agent_invocation_graph: None,
        evidence: ExecutionEvidence::default(),
        routing: Vec::new(),
        capsule_networks: Vec::new(),
    }
}

// `kata run --wait` / `kata run wait` / `kata watch`
// must exit non-zero when the execution terminates Failed so CI/agent callers
// can trust the process exit status. `exit_for_terminal_status` is the shared
// mapping those three surfaces return through.
#[test]
fn terminal_failed_maps_to_nonzero_engine_exit_code() {
    let record = terminal_record(ExecutionStatus::Failed, Some("stage boom exploded"));
    let err = exit_for_terminal_status(&record)
        .expect_err("Failed terminal status must produce a non-zero exit error");
    // Engine-class OpError → exit 5 via the top-level exit-code contract.
    let code = crate::cli::exit_code_for_error(&err);
    assert_ne!(code, 0, "Failed execution must not exit 0");
    assert_eq!(code, 5, "Failed execution maps to the engine exit code");
    assert!(
        err.to_string().contains("stage boom exploded"),
        "surfaced error should carry the execution failure reason: {err}"
    );
}

#[test]
fn terminal_failed_without_reason_still_nonzero() {
    let record = terminal_record(ExecutionStatus::Failed, None);
    let err = exit_for_terminal_status(&record)
        .expect_err("Failed terminal status must produce a non-zero exit error");
    assert_eq!(crate::cli::exit_code_for_error(&err), 5);
}

#[test]
fn terminal_completed_maps_to_success() {
    let record = terminal_record(ExecutionStatus::Completed, None);
    assert!(
        exit_for_terminal_status(&record).is_ok(),
        "Completed execution must exit 0"
    );
}

// A `Cancelled` terminal is non-zero too — the run did not do what was asked,
// so a CI caller must not read exit 0 — but it says `cancelled`, not `failed`,
// because an operator's stop is not an engine failure.
#[test]
fn terminal_cancelled_maps_to_nonzero_engine_exit_code() {
    let record = terminal_record(
        ExecutionStatus::Cancelled,
        Some("stage s2 cancelled: operator stop"),
    );
    let err = exit_for_terminal_status(&record)
        .expect_err("a Cancelled terminal status must produce a non-zero exit error");
    let code = crate::cli::exit_code_for_error(&err);
    assert_ne!(code, 0, "a cancelled execution must not exit 0");
    assert_eq!(
        code, 5,
        "a cancelled execution takes the same engine-class exit as a failed one"
    );
    assert!(
        err.to_string().contains("was cancelled"),
        "the message says the run was cancelled, not failed: {err}"
    );
}

#[test]
fn terminal_cancelled_without_reason_still_nonzero() {
    let record = terminal_record(ExecutionStatus::Cancelled, None);
    let err = exit_for_terminal_status(&record)
        .expect_err("a Cancelled terminal status must produce a non-zero exit error");
    assert_eq!(crate::cli::exit_code_for_error(&err), 5);
    assert!(
        err.to_string().contains("was cancelled"),
        "the message says the run was cancelled, not failed: {err}"
    );
}

// ---------------------------------------------------------------------------
// Time-travel READ surface (`kata timeline` / `kata diff`) + the terse
// `kata run list` table shape. The renderers are pure over the wire records,
// so these assert their reconstruction + text goldens directly.
// ---------------------------------------------------------------------------

/// Deterministic 26-char Crockford ULID string from a small seed — decimal
/// digits are valid Crockford base32, so this always deserializes as a Ulid.
fn ulid_str(seed: u64) -> String {
    format!("01H{seed:023}")
}

fn record_from_json(value: serde_json::Value) -> ExecutionRecord {
    serde_json::from_value(value).expect("record json deserializes into ExecutionRecord")
}

fn timeline_sample_record() -> ExecutionRecord {
    record_from_json(serde_json::json!({
        "id": ulid_str(1),
        "workflow_name": "std.hello",
        "status": "completed",
        "submitted_at_ms": 1000,
        "started_at_ms": 2000,
        "finished_at_ms": 20000,
        "worker_id": "worker-1",
        "outputs": null,
        "error": null,
        "agent_invocation_graph": {
            "execution_id": ulid_str(1),
            "nodes": [
                {
                    "id": ulid_str(11), "assignment_id": ulid_str(21),
                    "execution_id": ulid_str(1), "stage_name": "greet",
                    "kind": "stage", "role": "worker", "status": "completed",
                    "created_at_ms": 2500, "dispatched_at_ms": 3000,
                    "started_at_ms": 4000, "finished_at_ms": 10000
                },
                {
                    "id": ulid_str(12), "assignment_id": ulid_str(22),
                    "execution_id": ulid_str(1), "stage_name": "farewell",
                    "kind": "stage", "role": "worker", "status": "completed",
                    "created_at_ms": 10500, "dispatched_at_ms": 11000,
                    "started_at_ms": 12000, "finished_at_ms": 20000
                }
            ],
            "roots": [], "orphaned": []
        }
    }))
}

#[test]
fn timeline_reconstructs_chronological_events_from_record() {
    let record = timeline_sample_record();
    let packet = build_timeline(&record).expect("timeline builds");

    let kinds: Vec<&str> = packet.events.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![
            "submitted",
            "running",
            "dispatch",
            "start",
            "finish",
            "dispatch",
            "start",
            "finish",
            "terminal",
        ],
        "events are in chronological order"
    );

    // First event has no predecessor; running is +1s after submit.
    assert_eq!(packet.events[0].delta_ms, 0);
    assert_eq!(packet.events[1].delta_ms, 1000);

    let finish_greet = &packet.events[4];
    assert_eq!(finish_greet.stage.as_deref(), Some("greet"));
    assert!(
        finish_greet
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("status=completed") && d.contains("dur=6.000s")),
        "finish line carries per-stage status + duration: {:?}",
        finish_greet.detail
    );

    let terminal = packet.events.last().expect("terminal event present");
    assert_eq!(terminal.kind, "terminal");
    assert!(
        terminal
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("total=19.000s")),
        "terminal line carries total wall duration: {:?}",
        terminal.detail
    );
    assert_eq!(packet.total_duration_ms, Some(19_000));
}

#[test]
fn timeline_text_golden() {
    let record = timeline_sample_record();
    let packet = build_timeline(&record).expect("timeline builds");
    let text = render_timeline_text(&packet);
    // kata-spacing: intentional
    let expected = "\
Kata timeline: 01H00000000000000000000001  workflow=std.hello  status=completed
+0ms        1970-01-01 00:00:01.000Z  submitted
+1.000s     1970-01-01 00:00:02.000Z  running
+1.000s     1970-01-01 00:00:03.000Z  dispatch   stage=greet  role=worker kind=stage
+1.000s     1970-01-01 00:00:04.000Z  start      stage=greet
+6.000s     1970-01-01 00:00:10.000Z  finish     stage=greet  status=completed dur=6.000s
+1.000s     1970-01-01 00:00:11.000Z  dispatch   stage=farewell  role=worker kind=stage
+1.000s     1970-01-01 00:00:12.000Z  start      stage=farewell
+8.000s     1970-01-01 00:00:20.000Z  finish     stage=farewell  status=completed dur=8.000s
+0ms        1970-01-01 00:00:20.000Z  terminal   status=completed total=19.000s
";
    assert_eq!(text, expected);
}

#[test]
fn timeline_narrows_when_no_invocation_metadata() {
    let record = terminal_record(ExecutionStatus::Completed, None);
    let packet = build_timeline(&record).expect("timeline builds");
    let kinds: Vec<&str> = packet.events.iter().map(|e| e.kind).collect();
    // Only submit/running/terminal survive with no invocation graph.
    assert_eq!(kinds, vec!["submitted", "running", "terminal"]);
    assert!(
        packet
            .narrowings
            .iter()
            .any(|n| n.contains("no per-stage invocation metadata")),
        "absent graph is a logged narrowing, not silent"
    );
}

fn diff_sample_record() -> ExecutionRecord {
    record_from_json(serde_json::json!({
        "id": ulid_str(1),
        "workflow_name": "std.build",
        "status": "completed",
        "submitted_at_ms": 1000,
        "started_at_ms": 2000,
        "finished_at_ms": 12000,
        "worker_id": "worker-1",
        "outputs": {
            "plan": { "content": "the plan", "parsed": { "steps": 3 } },
            "greet": { "content": "hi there" },
            "build": { "content": "built ok", "parsed": { "status": "ok" } }
        },
        "error": null,
        "agent_invocation_graph": {
            "execution_id": ulid_str(1),
            "nodes": [
                {
                    "id": ulid_str(11), "assignment_id": ulid_str(21),
                    "execution_id": ulid_str(1), "stage_name": "plan",
                    "kind": "stage", "role": "worker", "status": "completed",
                    "created_at_ms": 2100, "started_at_ms": 2200, "finished_at_ms": 5000
                },
                {
                    "id": ulid_str(12), "assignment_id": ulid_str(22),
                    "execution_id": ulid_str(1), "stage_name": "greet",
                    "kind": "stage", "role": "worker", "status": "completed",
                    "created_at_ms": 5100, "started_at_ms": 5200, "finished_at_ms": 6000
                },
                {
                    "id": ulid_str(13), "assignment_id": ulid_str(23),
                    "execution_id": ulid_str(1), "stage_name": "build",
                    "kind": "stage", "role": "worker", "status": "completed",
                    "created_at_ms": 6500, "started_at_ms": 7000, "finished_at_ms": 12000
                }
            ],
            "roots": [], "orphaned": []
        },
        "evidence": {
            "external_inputs": [
                {
                    "schema_version": 1, "id": "ext-1", "channel": "ops",
                    "target_stage": "build", "text": "ship it",
                    "projection": "ops: ship it", "appended_at_ms": 6800
                }
            ],
            "output_closures": [
                {
                    "schema_version": 1, "stage_name": "build",
                    "observed_outputs": ["README.md", "src/lib.rs"], "undeclared": []
                }
            ]
        }
    }))
}

/// A stage output shaped like the main's `capsule_result` envelope
/// (`kata_core::operational::capsule_result_output`), with the runner's
/// `parsed` beside it: the process exit code sits at the envelope root.
fn diff_sample_output() -> serde_json::Value {
    serde_json::json!({
        "kind": "capsule_result",
        "content": "built ok",
        "parsed": { "status": "ok" },
        "exit_code": 0,
        "token_usage": { "cost_micro_usd": 50000 },
        "stage": "build"
    })
}

#[test]
fn diff_projects_input_output_and_workspace_effect() {
    let record = diff_sample_record();
    let packet = build_diff(&record, "build", Ok(diff_sample_output()));

    // INPUT: only stages that finished before build started (plan @5000,
    // greet @6000 < build start @7000), ordered by finish time.
    let upstream_stages: Vec<&str> = packet
        .input
        .upstream
        .iter()
        .map(|u| u.stage.as_str())
        .collect();
    assert_eq!(upstream_stages, vec!["plan", "greet"]);
    assert_eq!(
        packet.input.upstream[0].parsed,
        Some(serde_json::json!({"steps": 3}))
    );
    assert_eq!(packet.input.external_inputs.len(), 1);

    // OUTPUT envelope: content/parsed/exit_code/cost all surfaced.
    assert!(packet.output.available);
    assert_eq!(packet.output.exit_code, Some(0));
    assert_eq!(packet.output.cost_micro_usd, Some(50000));
    assert_eq!(
        packet.output.parsed,
        Some(serde_json::json!({"status": "ok"}))
    );

    // WORKSPACE EFFECT: files-touched from the output-closure evidence.
    let effect = packet
        .workspace_effect
        .as_ref()
        .expect("build carried an output-closure effect");
    assert_eq!(effect.files_touched, vec!["README.md", "src/lib.rs"]);
    assert!(effect.conforming);

    // The tree-id and per-template-edge limits are logged narrowings.
    assert!(
        packet
            .narrowings
            .iter()
            .any(|n| n.contains("workspace-effect tree root")),
        "tree-id narrowing present"
    );
    assert!(
        packet
            .narrowings
            .iter()
            .any(|n| n.contains("per-template dependency edges")),
        "edge-attribution narrowing present"
    );
}

#[test]
fn diff_text_golden() {
    let record = diff_sample_record();
    let packet = build_diff(&record, "build", Ok(diff_sample_output()));
    let text = render_diff_text(&packet);
    let expected = "\
Kata diff: 01H00000000000000000000001  stage=build
INPUT (consumed):
  <- plan
     parsed: {\"steps\":3}
  <- greet
     content: hi there
  <- external[ext-1] channel=ops: ship it
OUTPUT (produced):
  exit_code: 0
  parsed: {\"status\":\"ok\"}
  content: built ok
  cost: $0.050000
WORKSPACE EFFECT: 2 file(s) touched, conforming=true
  ~ README.md
  ~ src/lib.rs
narrowings:
- consumed inputs are the parsed outputs of upstream stages per the evidence chain; precise per-template dependency edges are not on the operator read plane.
- the workspace-effect tree root is an effect-plane internal not surfaced on the operator read record; the files-touched set below is the output-closure observation.
";
    assert_eq!(text, expected);
}

/// The exit code a diff reports is one the engine owns: the
/// `capsule_result` envelope's root `exit_code`
/// (`kata_core::operational::capsule_result_output`, the only position a
/// production stage output carries it). An `exit_code` inside `parsed` is the
/// author's own field and is never reported as the process exit code.
#[test]
fn diff_reads_the_exit_code_the_engine_measured_and_ignores_parsed() {
    let record = diff_sample_record();
    let capsule_root = serde_json::json!({
        "kind": "capsule_result",
        "content": "{\"exit_code\":4}",
        "parsed": { "exit_code": 4 },
        "exit_code": 3,
    });
    let packet = build_diff(&record, "build", Ok(capsule_root));
    assert_eq!(packet.output.exit_code, Some(3));

    let parsed_only = serde_json::json!({
        "content": "{\"exit_code\":4}",
        "parsed": { "exit_code": 4 },
    });
    let packet = build_diff(&record, "build", Ok(parsed_only));
    assert_eq!(packet.output.exit_code, None);
}

#[test]
fn diff_narrows_when_output_half_unavailable() {
    let record = diff_sample_record();
    let packet = build_diff(
        &record,
        "build",
        Err("stage \"build\" has not yet completed".to_string()),
    );
    assert!(!packet.output.available);
    assert!(
        packet
            .narrowings
            .iter()
            .any(|n| n.contains("output half unavailable")),
        "unavailable output is a logged narrowing"
    );
    // INPUT half still renders from the record.
    assert_eq!(packet.input.upstream.len(), 2);
}

fn run_list_record(
    seed: u64,
    name: &str,
    submitted: u64,
    finished: Option<u64>,
    cost: u64,
) -> ExecutionRecord {
    record_from_json(serde_json::json!({
        "id": ulid_str(seed),
        "workflow_name": name,
        "status": if finished.is_some() { "completed" } else { "running" },
        "submitted_at_ms": submitted,
        "started_at_ms": submitted + 5,
        "finished_at_ms": finished,
        "worker_id": "worker-1",
        "outputs": null,
        "error": null,
        "running_cost_micro_usd": cost
    }))
}

#[test]
fn run_list_table_is_terse_and_newest_first() {
    let records = vec![
        run_list_record(1, "alpha", 1000, Some(3000), 10844),
        run_list_record(2, "beta", 5000, None, 0),
    ];
    let table = render_run_list_table(&records).expect("table renders");
    let lines: Vec<&str> = table.lines().collect();

    // Header + one row per execution.
    assert_eq!(lines.len(), 3, "header + 2 rows");
    assert!(lines[0].starts_with("ID"));
    assert!(lines[0].contains("NAME"));
    assert!(lines[0].contains("STATUS"));
    assert!(lines[0].contains("SUBMITTED"));
    assert!(lines[0].contains("DURATION"));
    assert!(lines[0].contains("COST"));

    // Newest submission first: beta (5000) precedes alpha (1000).
    assert!(lines[1].contains("beta"), "newest first: {}", lines[1]);
    assert!(lines[2].contains("alpha"));

    // Terse: the verbose record fields never appear in the table.
    assert!(!table.contains("agent_invocation_graph"));
    assert!(!table.contains("submitted_at_ms"));
    assert!(!table.contains("worker_id"));

    // Running row has no computable duration.
    assert!(lines[1].contains('-'), "running row shows '-' duration");
    // Completed alpha: cost rendered, duration computed (3000-1005).
    assert!(lines[2].contains("$0.010844"));
    assert!(lines[2].contains("1.995s"));
}

#[test]
fn run_list_full_json_keeps_verbose_records() {
    // The `--json`/`--format json` path emits the full wire record, every
    // field included.
    let record = run_list_record(1, "alpha", 1000, Some(3000), 10844);
    let json = serde_json::to_string(&record).expect("record serializes");
    assert!(json.contains("submitted_at_ms"));
    assert!(json.contains("worker_id"));
    // While the terse table deliberately drops them.
    let table = render_run_list_table(std::slice::from_ref(&record)).expect("table renders");
    assert!(!table.contains("submitted_at_ms"));
}

#[test]
fn run_list_table_empty_is_explicit() {
    let table = render_run_list_table(&[]).expect("table renders");
    assert_eq!(table, "no executions\n");
}

#[test]
fn run_list_output_selection_maps_flags_to_full_records() {
    use crate::cli::output::OutputFormat;
    // Bare command → terse table (NOT full records).
    assert!(!run_list_emits_full_records(false, OutputFormat::Human));
    // `--json` → full NDJSON records regardless of --format.
    assert!(run_list_emits_full_records(true, OutputFormat::Human));
    assert!(run_list_emits_full_records(true, OutputFormat::Json));
    // Global `--format json` (no per-command flag) → full NDJSON records too,
    // the deliberate raw-NDJSON divergence from the schema'd-envelope sites.
    assert!(run_list_emits_full_records(false, OutputFormat::Json));
}

/// The `--format` help and `run_list_emits_full_records` are two statements
/// about ONE behaviour, and they had drifted: the help promised "a schema'd,
/// versioned `OpEnvelope` for every operation that supports structured output"
/// while this selector deliberately keeps `run list` on raw NDJSON so existing
/// stream consumers survive (`crates/test-utils/tests/smokes.rs`'s `json_lines`
/// parses exactly this stream, and `just api-executions` prints it).
///
/// Tying them here means the two can only move together: route `run list`
/// through `output::emit_record` and this fails, naming the help sentence that must change
/// with it.
#[test]
fn format_help_agrees_with_the_run_list_ndjson_divergence() {
    use clap::CommandFactory as _;

    use crate::cli::output::OutputFormat;

    let command = crate::cli::Cli::command();
    let format = command
        .get_arguments()
        .find(|arg| arg.get_id() == "format")
        .expect("the CLI has a global --format argument");
    let help = format
        .get_long_help()
        .or_else(|| format.get_help())
        .expect("--format documents itself")
        .to_string();

    assert!(
        run_list_emits_full_records(false, OutputFormat::Json),
        "`--format json` on `run list` selects the raw NDJSON records"
    );
    assert!(
        help.contains("run list"),
        "`run list` is the one NDJSON `--format json` site, so the flag's \
         own help has to say so; it reads:\n{help}"
    );
    assert!(
        help.contains("newline-delimited JSON") || help.contains("NDJSON"),
        "the help must name the SHAPE `run list` emits under `--format json`, not merely \
         list the command; it reads:\n{help}"
    );
    assert!(
        !help.contains("for every operation that supports structured output"),
        "the help must not claim an envelope for every structured-output operation — \
         `run list`, `run show`, `run current`, `workers` and `status` emit bare records. \
         It reads:\n{help}"
    );
}

/// A still-running execution with no aggregate `outputs` map and an
/// invocation graph carrying the target stage's start time.
fn diff_running_record() -> ExecutionRecord {
    record_from_json(serde_json::json!({
        "id": ulid_str(1),
        "workflow_name": "std.build",
        "status": "running",
        "submitted_at_ms": 1000,
        "started_at_ms": 2000,
        "finished_at_ms": null,
        "worker_id": "worker-1",
        "outputs": null,
        "error": null,
        "agent_invocation_graph": {
            "execution_id": ulid_str(1),
            "nodes": [
                {
                    "id": ulid_str(13), "assignment_id": ulid_str(23),
                    "execution_id": ulid_str(1), "stage_name": "build",
                    "kind": "stage", "role": "worker", "status": "running",
                    "created_at_ms": 6500, "started_at_ms": 7000
                }
            ],
            "roots": [], "orphaned": []
        }
    }))
}

#[test]
fn diff_narrows_when_execution_is_still_running() {
    // Mid-run, the aggregate stage-outputs map is absent (populated only on
    // success), so the INPUT half is empty. That must be an honest narrowing —
    // "not yet available", not "the stage consumed nothing".
    let record = diff_running_record();
    let packet = build_diff(
        &record,
        "build",
        Err("stage \"build\" has not yet completed".to_string()),
    );
    assert!(
        packet.input.upstream.is_empty(),
        "no aggregate outputs mid-run → empty INPUT"
    );
    assert!(
        packet
            .narrowings
            .iter()
            .any(|n| n.contains("not yet terminal") && n.contains("not yet available")),
        "running execution gets a non-terminal INPUT narrowing: {:?}",
        packet.narrowings
    );
    // And it is distinct from the Failed-only narrowing.
    assert!(
        !packet
            .narrowings
            .iter()
            .any(|n| n.contains("execution failed")),
        "running execution must not claim it failed: {:?}",
        packet.narrowings
    );
}

// ---------------------------------------------------------------------------
// `kata watch` — the bounds that stop it waiting forever
//
// REGRESSION: a `watch_execution` with no deadline of any kind, whose SSE-error
// arm printed and looped, could sit inside
// `smoke_product_cli_init_main_submit_watch_wait_output_shutdown` until
// nextest's 300s runner kill — a bound that cannot name what it killed.
// Each test below fails if a bound is removed AND if its message stops naming
// the layer, because an unattributable bound is undiagnosable.
// ---------------------------------------------------------------------------

/// A stand-in main that answers `GET /executions/{id}` with a RUNNING record
/// and holds `GET /events` open forever without ever emitting a terminal
/// frame. This is a healthy-looking server with a workflow that never
/// finishes — precisely the shape no transport bound can catch.
async fn spawn_never_terminal_main() -> (String, tokio::task::JoinHandle<()>) {
    use axum::response::IntoResponse as _;
    use axum::routing::get;

    let record = serde_json::json!({
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "workflow_name": "never-terminal",
        "status": "running",
        "submitted_at_ms": 1,
        "worker_id": "worker-1",
        "running_cost_micro_usd": 0,
    });
    let app = axum::Router::new()
        .route(
            "/api/v1/executions/{id}",
            get(move || {
                let record = record.clone();
                async move { axum::Json(record) }
            }),
        )
        .route(
            "/api/v1/events",
            get(|| async {
                // An open stream that yields nothing. `futures::stream::pending`
                // keeps the response body alive without frames, which is what a
                // real quiet subscription looks like between keep-alives.
                axum::response::sse::Sse::new(futures::stream::pending::<
                    Result<axum::response::sse::Event, std::convert::Infallible>,
                >())
                .into_response()
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind never-terminal main");
    let addr = listener.local_addr().expect("never-terminal main addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread")]
async fn watch_timeout_secs_stops_following_and_names_what_it_was_waiting_on() {
    let (base_url, server) = spawn_never_terminal_main().await;
    let client = KataClient::new(&base_url).expect("client");

    let started = std::time::Instant::now();
    let err = watch::watch_execution(
        &client,
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        false,
        Some(std::time::Duration::from_millis(400)),
    )
    .await
    .expect_err("a never-terminal execution must not satisfy a bounded watch");
    let elapsed = started.elapsed();

    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("kata watch:"),
        "the message must name the LAYER that gave up: {rendered}"
    );
    assert!(
        rendered.contains("01HZZZZZZZZZZZZZZZZZZZZZZZ"),
        "the message must name the OPERATION — which execution it was following: {rendered}"
    );
    assert!(
        rendered.contains("--timeout-secs"),
        "the message must name the bound the operator can move: {rendered}"
    );
    assert!(
        rendered.contains("Running"),
        "the message must report the last status it saw, or the operator learns only that \
         something stopped: {rendered}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "the bound must fire at its deadline, not at the runner's; took {elapsed:?}"
    );
    server.abort();
}

#[test]
fn watch_timeout_secs_zero_means_follow_until_terminal_not_expire_immediately() {
    // The dangerous misreading of `default_value_t = 0`. If this ever becomes
    // `Some(Duration::ZERO)`, every interactive `kata watch` dies on its first
    // poll, so the mapping is pinned rather than left to the reader.
    assert_eq!(
        watch::watch_deadline(0),
        None,
        "0 is the interactive follow-until-terminal default, not a zero deadline"
    );
    assert_eq!(
        watch::watch_deadline(45),
        Some(std::time::Duration::from_secs(45))
    );
}

/// The uncommitted-edits read never writes the checkout's index. A fresh clone's index
/// is racy (its entries no older than the index file), and a `git status` that may take
/// the index lock refreshes such an index and writes it back: `kata run` would take
/// `index.lock` beside the operator's own git, and in kata's own checkout rewrite the
/// index `bin/kata/build.rs` watches (the E3 host column's next cargo rebuilt `kata`).
/// The positive control is that plain `git status`: it rewrites this fixture's index,
/// so the index is racy.
#[test]
fn the_uncommitted_edits_read_leaves_a_racy_index_untouched() {
    let (_tmp, repo) = kata_test_utils::git::init_git_repo();
    let index = repo.join(".git/index");
    let tracked = kata_test_utils::git::hermetic_git_in(&repo)
        .args(["ls-files", "-z"])
        .output()
        .unwrap();
    let newest = String::from_utf8(tracked.stdout)
        .unwrap()
        .split('\0')
        .filter(|name| !name.is_empty())
        .map(|name| {
            std::fs::metadata(repo.join(name))
                .and_then(|meta| meta.modified())
                .unwrap()
        })
        .max()
        .expect("the fixture tracks a file");
    // The index's mtime set back to the newest tracked file's whole second, as a
    // checkout that writes the files and then the index within one second leaves it.
    let second = newest
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let make_racy = || {
        std::fs::File::options()
            .write(true)
            .open(&index)
            .and_then(|file| {
                file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(second))
            })
            .unwrap();
    };
    let index_state = || {
        let modified = std::fs::metadata(&index)
            .and_then(|meta| meta.modified())
            .unwrap();
        (modified, std::fs::read(&index).unwrap())
    };

    make_racy();
    let before = index_state();
    assert_eq!(dirty_checkout(&repo), None, "a clean checkout");
    assert!(
        index_state() == before,
        "the uncommitted-edits read rewrote the racy index (its mtime moved from {:?} to {:?})",
        before.0,
        index_state().0
    );

    make_racy();
    let before = index_state();
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(
        index_state().0 != before.0,
        "the positive control: a plain git status left the index alone, so it was not racy"
    );
}

/// The checkout's own `core.fsmonitor` command, which would write a marker
/// file, does not run when kata reads whether the checkout has uncommitted
/// edits, and the answer is still git's: a modified tracked file names the
/// checkout.
#[test]
fn the_uncommitted_edits_read_runs_no_fsmonitor_command() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_tmp, repo) = kata_test_utils::git::init_git_repo();
    // The fixture's own git reads run BEFORE the fsmonitor is armed, so the only
    // `git` that can meet it is kata's.
    let tracked = kata_test_utils::git::hermetic_git_in(&repo)
        .args(["ls-files"])
        .output()
        .unwrap();
    let tracked = String::from_utf8(tracked.stdout).unwrap();
    let first = tracked.lines().next().expect("the fixture tracks a file");
    std::fs::write(repo.join(first), "edited\n").unwrap();
    let outside = tempfile::tempdir().unwrap();
    let marker = outside.path().join("fsmonitor-ran");
    let fsmonitor = outside.path().join("fsmonitor");
    std::fs::write(
        &fsmonitor,
        format!("#!/bin/sh\necho ran >> '{}'\nexit 1\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&fsmonitor, std::fs::Permissions::from_mode(0o755)).unwrap();
    kata_test_utils::git::run_git(
        &repo,
        &["config", "core.fsmonitor", fsmonitor.to_str().unwrap()],
    );
    assert!(!marker.exists(), "arming the fsmonitor ran it");

    assert_eq!(
        dirty_checkout(&repo).map(|p| std::fs::canonicalize(p).unwrap()),
        Some(std::fs::canonicalize(&repo).unwrap())
    );
    assert!(
        !marker.exists(),
        "the checkout's fsmonitor command ran inside kata's `git status`"
    );
}

/// The uncommitted-edits notice reads git's own answer: a clean checkout and a
/// directory in no checkout owe none; an untracked file is not a tracked
/// change and owes none; a modified TRACKED file does, naming the checkout's
/// top level (from a subdirectory too) — and the notice names the committed
/// target the run forks.
#[test]
fn a_dirty_checkout_owes_the_uncommitted_edits_notice_and_a_clean_one_does_not() {
    let outside = tempfile::tempdir().unwrap();
    assert_eq!(dirty_checkout(outside.path()), None, "in no checkout");

    let (_tmp, repo) = kata_test_utils::git::init_git_repo();
    assert_eq!(dirty_checkout(&repo), None, "a clean checkout");
    std::fs::write(repo.join("untracked.txt"), "new\n").unwrap();
    assert_eq!(
        dirty_checkout(&repo),
        None,
        "an untracked file is not a tracked edit"
    );

    let tracked = kata_test_utils::git::hermetic_git_in(&repo)
        .args(["ls-files"])
        .output()
        .unwrap();
    let tracked = String::from_utf8(tracked.stdout).unwrap();
    let first = tracked.lines().next().expect("the fixture tracks a file");
    std::fs::write(repo.join(first), "edited\n").unwrap();
    let subdir = repo.join("nested");
    std::fs::create_dir(&subdir).unwrap();
    let toplevel = std::fs::canonicalize(&repo).unwrap();
    assert_eq!(
        dirty_checkout(&repo).map(|p| std::fs::canonicalize(p).unwrap()),
        Some(toplevel.clone())
    );
    assert_eq!(
        dirty_checkout(&subdir).map(|p| std::fs::canonicalize(p).unwrap()),
        Some(toplevel.clone()),
        "found from a subdirectory too"
    );

    let target = kata_types::test_support::fixture_trunk_target();
    let notice = uncommitted_edits_notice(&toplevel, &target);
    assert!(
        notice.contains("uncommitted edits in")
            && notice.contains("are not part of this run")
            && notice.contains(&target.summary()),
        "{notice}"
    );
}
