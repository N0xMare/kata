//! Tests for `crates/types/src/execution.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::execution::{
    CHECK_ARTIFACT_EVIDENCE_SCHEMA_VERSION, CHECKED_DISPATCH_GUARD_EVIDENCE_SCHEMA_VERSION,
    CHECKED_DISPATCH_GUARD_ID, CHECKED_DISPATCH_POLICY_FIELDS,
    CHECKED_RUNTIME_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
    CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION, CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION,
    EXECUTION_WORKSPACE_IDENTITY_SCHEMA_VERSION, ExecutionCheckArtifactEvidence,
    ExecutionCheckedDispatchGuardEvidence, ExecutionCheckedDispatchGuardStatus,
    ExecutionCheckedDispatchKind, ExecutionCheckedRuntimeAuthorityEvidence,
    ExecutionControllerApplicationEvidence, ExecutionControllerApplicationRecoveryEvidence,
    ExecutionControllerCompletionEvidence, ExecutionControllerDecisionEvidence,
    ExecutionControllerDecisionScopeEvidence, ExecutionControllerMemoryPolicyApplicationEvidence,
    ExecutionControllerMemoryPolicyEvidence, ExecutionControllerMemoryProposalEvidence,
    ExecutionEvidence, ExecutionMemoryWritebackEvidence, ExecutionProgramIdentity, ExecutionRecord,
    ExecutionStatus, ExecutionValidationCriterionEvidence, ExecutionValidationCriterionStatus,
    ExecutionValidationCriterionWaiverEvidence, ExecutionValidationEvidence,
    ExecutionWorkspaceIdentity, MEMORY_WRITEBACK_EVIDENCE_SCHEMA_VERSION, MemoryProposalEvidence,
    VALIDATION_CRITERION_CANDIDATE_EVIDENCE_SCHEMA_VERSION,
    VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION,
    VALIDATION_CRITERION_WAIVER_EVIDENCE_SCHEMA_VERSION, WorkflowClassIdentity,
};
use kata_types::primitives::ContentHash;

#[test]
fn execution_status_serializes_snake_case() {
    assert_eq!(
        serde_json::to_string(&ExecutionStatus::Pending).unwrap(),
        "\"pending\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionStatus::Running).unwrap(),
        "\"running\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionStatus::Completed).unwrap(),
        "\"completed\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionStatus::Failed).unwrap(),
        "\"failed\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionStatus::Cancelled).unwrap(),
        "\"cancelled\""
    );
}

#[test]
fn execution_status_is_terminal() {
    assert!(!ExecutionStatus::Pending.is_terminal());
    assert!(!ExecutionStatus::Running.is_terminal());
    assert!(ExecutionStatus::Completed.is_terminal());
    assert!(ExecutionStatus::Failed.is_terminal());
    assert!(ExecutionStatus::Cancelled.is_terminal());
}

#[test]
fn execution_workspace_identity_round_trips_and_omits_absent_optional_fields() {
    let identity = ExecutionWorkspaceIdentity {
        schema_version: EXECUTION_WORKSPACE_IDENTITY_SCHEMA_VERSION,
        execution_id: "01KWORKSPACEIDENTITY000000001".to_string(),
        invocation_id: None,
        stage_name: Some("implement".to_string()),
        backend: "jj".to_string(),
        workspace_ref: Some("exec-01KWORKSPACEIDENTITY000000001".to_string()),
        workspace_commit_sha: Some("abc123".to_string()),
        base_ref: Some("main".to_string()),
        base_commit_sha: Some("base123".to_string()),
        target_ref: None,
        target_commit_sha: None,
        author: None,
    };

    let value = serde_json::to_value(&identity).expect("serialize identity");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["backend"], "jj");
    assert_eq!(value["stage_name"], "implement");
    assert!(value.get("invocation_id").is_none());
    assert!(value.get("target_ref").is_none());
    assert!(value.get("target_commit_sha").is_none());
    assert!(value.get("author").is_none());

    // The AUTHOR RECEIPT is a stamped value, not a projection — it rides the
    // builder rather than the constructor, and it serializes when present.
    let stamped = identity
        .clone()
        .with_author(Some("Ada Lovelace <ada@example.invalid>".to_string()));
    let stamped_value = serde_json::to_value(&stamped).expect("serialize stamped identity");
    assert_eq!(
        stamped_value["author"],
        "Ada Lovelace <ada@example.invalid>"
    );
    assert_eq!(
        serde_json::from_value::<ExecutionWorkspaceIdentity>(stamped_value)
            .expect("deserialize stamped identity"),
        stamped
    );

    let decoded: ExecutionWorkspaceIdentity =
        serde_json::from_value(value).expect("deserialize identity");
    assert_eq!(decoded, identity);
}

#[test]
fn controller_scheduler_and_recovery_evidence_stays_serde_compatible() {
    let minimal: ExecutionControllerDecisionEvidence = serde_json::from_value(serde_json::json!({
        "schema_version": CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION,
        "stage_name": "controller",
        "decision_id": "decision-minimal",
        "decision": "repair",
        "human_required": false
    }))
    .unwrap();
    assert!(minimal.scope.is_none());
    assert!(minimal.completion.is_none());
    assert!(minimal.memory_policy.is_none());

    let decision = ExecutionControllerDecisionEvidence {
        schema_version: CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION,
        stage_name: "controller".to_string(),
        decision_id: "decision-typed".to_string(),
        wave_id: Some("wave-1".to_string()),
        decision: "repair".to_string(),
        next_action: Some("run bounded repair".to_string()),
        reason: Some("validation blocker remains".to_string()),
        evidence: vec!["validate failed vc-gate".to_string()],
        alternatives: vec!["park".to_string()],
        human_required: false,
        scope: Some(ExecutionControllerDecisionScopeEvidence {
            summary: Some("repair vc-gate".to_string()),
            focus_areas: vec!["validation".to_string()],
            owned_paths: vec!["crates/api".to_string()],
            validation_blockers: vec!["validation_criterion:vc-gate".to_string()],
            rationale: Some("keep next wave bounded".to_string()),
        }),
        completion: Some(ExecutionControllerCompletionEvidence {
            status: "partial".to_string(),
            validation_passed: false,
            remaining: vec!["repair vc-gate".to_string()],
            blockers: vec!["validation_criterion:vc-gate".to_string()],
            rationale: Some("one criterion remains".to_string()),
        }),
        memory_policy: Some(ExecutionControllerMemoryPolicyEvidence {
            selectors: vec!["factory_active_context".to_string()],
            writebacks: vec!["factory_next_actions".to_string()],
            context_queries: vec!["recent validation failures".to_string()],
            proposals: vec![ExecutionControllerMemoryProposalEvidence {
                object_id: "finding-blocker-context".to_string(),
                kind: "finding".to_string(),
                title: Some("Carry blocker context".to_string()),
                summary: Some("validation gate vc-gate remains".to_string()),
                tags: vec!["controller".to_string()],
            }],
            rationale: Some("carry blocker context".to_string()),
        }),
        runtime_policy: None,
    };
    let application = ExecutionControllerApplicationEvidence {
        schema_version: CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION,
        application_id: "advance:decision-typed".to_string(),
        decision_id: "decision-typed".to_string(),
        decision: "repair".to_string(),
        action: "advance".to_string(),
        applied: true,
        applied_at_ms: 1,
        source: Some("operator_admin_finalize".to_string()),
        reason: Some("verified claimed next execution".to_string()),
        error: None,
        next_execution_id: Some("01HZZZZZZZZZZZZZZZZZZZZZZY".to_string()),
        parked_candidate: None,
        promotion: None,
        memory_policy: Some(ExecutionControllerMemoryPolicyApplicationEvidence {
            status: "applied".to_string(),
            selectors: vec!["factory_active_context".to_string()],
            writebacks: vec!["factory_next_actions".to_string()],
            context_queries: vec!["recent validation failures".to_string()],
            proposals: vec![MemoryProposalEvidence {
                object_id: "finding-blocker-context".to_string(),
                kind: "finding".to_string(),
                action: "declared".to_string(),
            }],
            rationale: Some("carry blocker context".to_string()),
        }),
        side_effect: None,
        recovery: Some(ExecutionControllerApplicationRecoveryEvidence {
            mode: "finalize_observed".to_string(),
            source: Some("operator_admin_finalize".to_string()),
            reason: "verified claimed next execution".to_string(),
            evidence: vec!["next execution exists".to_string()],
        }),
    };
    let encoded = serde_json::to_value(ExecutionEvidence {
        controller_decisions: vec![decision.clone()],
        controller_applications: vec![application.clone()],
        ..ExecutionEvidence::default()
    })
    .unwrap();
    let decoded: ExecutionEvidence = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.controller_decisions, vec![decision]);
    assert_eq!(decoded.controller_applications, vec![application]);
}

#[test]
fn execution_record_decodes_pending_shape() {
    // The Pending shape the server emits before any stage lands.
    let raw = serde_json::json!({
        "id": "01HV0VZTBP7TX5DQ1V0G7WB3SK",
        "workflow_name": "demo",
        "status": "pending",
        "submitted_at_ms": 1_700_000_000_000u64,
        "started_at_ms": null,
        "finished_at_ms": null,
        "worker_id": "pending",
        "outputs": null,
        "error": null,
    });
    let rec: ExecutionRecord = serde_json::from_value(raw).unwrap();
    assert_eq!(rec.status, ExecutionStatus::Pending);
    assert_eq!(rec.worker_id, "pending");
    assert!(rec.outputs.is_none());
}

#[test]
fn execution_record_decodes_completed_shape() {
    let raw = serde_json::json!({
        "id": "01HV0VZTBP7TX5DQ1V0G7WB3SK",
        "workflow_name": "demo",
        "status": "completed",
        "submitted_at_ms": 1_700_000_000_000u64,
        "started_at_ms": 1_700_000_000_100u64,
        "finished_at_ms": 1_700_000_000_500u64,
        "worker_id": "ls-worker-1",
        "outputs": { "only": { "stage": "ok" } },
        "error": null,
    });
    let rec: ExecutionRecord = serde_json::from_value(raw).unwrap();
    assert!(rec.is_terminal());
    assert_eq!(
        rec.outputs.as_ref().unwrap().get("only").unwrap(),
        &serde_json::json!({ "stage": "ok" })
    );
    assert!(rec.agent_invocation_graph.is_none());
    assert!(rec.evidence.is_empty());
    assert!(rec.execution_program.is_none());
}

#[test]
fn execution_record_roundtrips_json() {
    let rec = ExecutionRecord {
        target: None,
        id: "01HV0VZTBP7TX5DQ1V0G7WB3SK".to_string(),
        workflow_name: "demo".to_string(),
        execution_program: None,
        status: ExecutionStatus::Running,
        submitted_at_ms: 1_700_000_000_000,
        started_at_ms: Some(1_700_000_000_100),
        finished_at_ms: None,
        worker_id: "ls-worker-1".to_string(),
        outputs: None,
        error: None,
        running_cost_micro_usd: 0,
        child_cost_micro_usd: 0,
        metering: kata_types::metering::MeteringSummary::default(),
        warnings: Vec::new(),
        agent_invocation_graph: None,
        evidence: ExecutionEvidence::default(),
        routing: Vec::new(),
        capsule_networks: Vec::new(),
    };
    let s = serde_json::to_string(&rec).unwrap();
    let back: ExecutionRecord = serde_json::from_str(&s).unwrap();
    assert_eq!(back.id, rec.id);
    assert_eq!(back.status, ExecutionStatus::Running);
    assert_eq!(back.started_at_ms, Some(1_700_000_000_100));
}

#[test]
fn execution_evidence_includes_execution_program_identity() {
    let evidence = ExecutionEvidence {
        execution_program: Some(ExecutionProgramIdentity {
            schema_version: 1,
            program_hash: ContentHash::zero(),
            workflow_class: WorkflowClassIdentity {
                schema_version: 1,
                id: ContentHash::zero(),
            },
        }),
        ..ExecutionEvidence::default()
    };

    assert!(!evidence.is_empty());
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["execution_program"]["schema_version"], 1);
    assert!(json["execution_program"]["program_hash"].is_string());
    assert!(json["execution_program"]["workflow_class"]["id"].is_string());
    let back: ExecutionEvidence = serde_json::from_value(json).unwrap();
    assert_eq!(back, evidence);
}

/// A program identity or runtime authority without its `workflow_class` is
/// REFUSED at decode, naming the field: every writer stamps the class, so a row
/// without it is not one this build wrote, and decoding it would invent a zero
/// class identity rather than read one.
///
/// REFUSES exactly: an `ExecutionProgramIdentity` or an
/// `ExecutionCheckedRuntimeAuthorityEvidence` object with no `workflow_class` key.
#[test]
fn an_identity_without_its_workflow_class_is_refused_at_decode() {
    let class = WorkflowClassIdentity {
        schema_version: 1,
        id: ContentHash::zero(),
    };
    let mut identity = serde_json::to_value(ExecutionProgramIdentity {
        schema_version: 1,
        program_hash: ContentHash::zero(),
        workflow_class: class.clone(),
    })
    .unwrap();
    let mut authority = serde_json::to_value(ExecutionCheckedRuntimeAuthorityEvidence {
        schema_version: CHECKED_RUNTIME_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
        program_hash: ContentHash::zero(),
        workflow_class: class,
        runtime_authority_source: "execution_program:sha256:trusted".to_string(),
        trusted_cost_limit_micro_usd: None,
        trusted_deadline_at_ms: None,
    })
    .unwrap();
    // Both encode the key, so the decode below sees only its removal.
    assert!(
        identity
            .as_object_mut()
            .unwrap()
            .remove("workflow_class")
            .is_some()
    );
    assert!(
        authority
            .as_object_mut()
            .unwrap()
            .remove("workflow_class")
            .is_some()
    );

    let error = serde_json::from_value::<ExecutionProgramIdentity>(identity)
        .expect_err("a program identity without its workflow class must not decode")
        .to_string();
    assert!(
        error.contains("workflow_class"),
        "the refusal names the field: {error}"
    );
    let error = serde_json::from_value::<ExecutionCheckedRuntimeAuthorityEvidence>(authority)
        .expect_err("a runtime authority without its workflow class must not decode")
        .to_string();
    assert!(
        error.contains("workflow_class"),
        "the refusal names the field: {error}"
    );
}

#[test]
fn execution_evidence_includes_checked_runtime_authority() {
    let evidence = ExecutionEvidence {
        checked_runtime_authority: Some(ExecutionCheckedRuntimeAuthorityEvidence {
            schema_version: CHECKED_RUNTIME_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
            program_hash: ContentHash::zero(),
            workflow_class: WorkflowClassIdentity {
                schema_version: 1,
                id: ContentHash::zero(),
            },
            runtime_authority_source: "execution_program:sha256:trusted".to_string(),
            trusted_cost_limit_micro_usd: Some(2_000_000),
            trusted_deadline_at_ms: Some(1_700_000_001_000),
        }),
        ..ExecutionEvidence::default()
    };

    assert!(!evidence.is_empty());
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(
        json["checked_runtime_authority"]["schema_version"],
        CHECKED_RUNTIME_AUTHORITY_EVIDENCE_SCHEMA_VERSION
    );
    assert_eq!(
        json["checked_runtime_authority"]["runtime_authority_source"],
        "execution_program:sha256:trusted"
    );
    assert_eq!(
        json["checked_runtime_authority"]["trusted_cost_limit_micro_usd"],
        2_000_000
    );
    let back: ExecutionEvidence = serde_json::from_value(json).unwrap();
    assert_eq!(back, evidence);
}

#[test]
fn validation_evidence_roundtrips_criterion_statuses() {
    let report = ExecutionValidationEvidence {
        stage_name: "validate".to_string(),
        status: Some("passed".to_string()),
        criteria: vec![ExecutionValidationCriterionEvidence {
            schema_version: VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION,
            criterion_id: "vc-build".to_string(),
            status: ExecutionValidationCriterionStatus::Passed,
            required: true,
            stage_name: Some("validate".to_string()),
            evidence: vec!["cargo check passed".to_string()],
            missing: Vec::new(),
            source: Some("validate".to_string()),
            waiver: None,
            candidate: None,
        }],
        commands: vec!["cargo check --workspace --all-features".to_string()],
        evidence: vec!["cargo check passed".to_string()],
        test_count: None,
        git_sha: None,
        pgrep_clean: None,
        check_artifacts: Vec::new(),
    };

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["criteria"][0]["criterion_id"], "vc-build");
    assert_eq!(json["criteria"][0]["status"], "passed");
    let back: ExecutionValidationEvidence = serde_json::from_value(json).unwrap();
    assert_eq!(back, report);
}

#[test]
fn validation_evidence_parses_raw_parsed_and_content_outputs() {
    let raw = serde_json::json!({
        "status": "passed",
        "criteria": [{
            "id": "vc-build",
            "status": "passed",
            "evidence": ["cargo check passed"],
            "source": "shell",
        }],
        "commands": ["cargo check"],
        "evidence": ["ok"],
        "test_count": 12,
        "git_sha": "abc123",
        "pgrep_clean": true,
        "check_artifacts": [{
            "artifact_id": "cargo-check",
            "status": "passed",
            "commands": ["cargo check"],
            "paths": ["target/check.txt"],
            "evidence": ["ok"],
            "summary": "cargo check passed"
        }],
    });

    let report = ExecutionValidationEvidence::from_stage_output("validate", &raw)
        .expect("raw validation output parses");
    assert_eq!(report.stage_name, "validate");
    assert_eq!(report.status.as_deref(), Some("passed"));
    assert_eq!(report.criteria.len(), 1);
    assert_eq!(report.criteria[0].criterion_id, "vc-build");
    assert_eq!(
        report.criteria[0].status,
        ExecutionValidationCriterionStatus::Passed
    );
    assert_eq!(report.criteria[0].waiver, None);
    assert_eq!(report.commands, vec!["cargo check".to_string()]);
    assert_eq!(report.test_count, Some(12));
    assert_eq!(report.git_sha.as_deref(), Some("abc123"));
    assert_eq!(report.pgrep_clean, Some(true));
    assert_eq!(report.check_artifacts.len(), 1);
    assert_eq!(report.check_artifacts[0].artifact_id, "cargo-check");

    let parsed_envelope = serde_json::json!({ "content": "ignored", "parsed": raw });
    let parsed_report =
        ExecutionValidationEvidence::from_stage_output("validate", &parsed_envelope)
            .expect("parsed envelope parses");
    assert_eq!(parsed_report, report);

    let content_envelope = serde_json::json!({
        "content": serde_json::to_string(&parsed_envelope["parsed"]).unwrap(),
    });
    let content_report =
        ExecutionValidationEvidence::from_stage_output("validate", &content_envelope)
            .expect("JSON content envelope parses");
    assert_eq!(content_report, report);
}

#[test]
fn validation_evidence_parses_typed_criterion_waiver_provenance() {
    let raw = serde_json::json!({
        "status": "passed",
        "criteria": [{
            "id": "vc-risk",
            "status": "waived_by_policy",
            "waiver": {
                "source": "operator",
                "reason": "accepted by release owner for docs-only candidate",
                "approved_by": "release-owner",
                "approved_at_ms": 1234,
                "evidence": ["approval ticket KATA-1"]
            }
        }]
    });

    let report = ExecutionValidationEvidence::from_stage_output("validate", &raw)
        .expect("typed waiver validation output parses");

    assert_eq!(
        report.criteria[0].status,
        ExecutionValidationCriterionStatus::WaivedByPolicy
    );
    assert_eq!(
        report.criteria[0].waiver,
        Some(ExecutionValidationCriterionWaiverEvidence {
            schema_version: VALIDATION_CRITERION_WAIVER_EVIDENCE_SCHEMA_VERSION,
            source: "operator".to_string(),
            reason: "accepted by release owner for docs-only candidate".to_string(),
            authority_id: None,
            approved_by: Some("release-owner".to_string()),
            approved_at_ms: Some(1234),
            evidence: vec!["approval ticket KATA-1".to_string()],
        })
    );
}

#[test]
fn validation_evidence_parses_candidate_binding() {
    let fingerprint = ContentHash::new([0x42; 32]);
    let content_hash = ContentHash::new([0x24; 32]);
    let raw = serde_json::json!({
        "status": "passed",
        "criteria": [{
            "id": "vc-build",
            "status": "passed",
            "candidate": {
                "execution_id": "01J00000000000000000000000",
                "fingerprint": fingerprint,
                "content_hash": content_hash,
                "workspace_backend": "jj",
                "head_commit": "abc123",
                "dirty": true,
                "changed_paths": ["src/lib.rs"]
            },
            "evidence": ["cargo check passed"]
        }]
    });

    let report = ExecutionValidationEvidence::from_stage_output("validate", &raw)
        .expect("candidate binding validation output parses");
    let candidate = report.criteria[0]
        .candidate
        .as_ref()
        .expect("criterion has candidate binding");
    assert_eq!(
        candidate.schema_version,
        VALIDATION_CRITERION_CANDIDATE_EVIDENCE_SCHEMA_VERSION
    );
    assert_eq!(candidate.execution_id, "01J00000000000000000000000");
    assert_eq!(candidate.fingerprint, fingerprint);
    assert_eq!(candidate.content_hash, content_hash);
    assert_eq!(candidate.workspace_backend.as_deref(), Some("jj"));
    assert_eq!(candidate.head_commit.as_deref(), Some("abc123"));
    assert_eq!(candidate.dirty, Some(true));
    assert_eq!(candidate.changed_paths, vec!["src/lib.rs".to_string()]);
}

#[test]
fn execution_evidence_includes_check_artifacts_and_memory_writebacks() {
    let evidence = ExecutionEvidence {
        check_artifacts: vec![ExecutionCheckArtifactEvidence {
            schema_version: CHECK_ARTIFACT_EVIDENCE_SCHEMA_VERSION,
            artifact_id: "artifact-1".to_string(),
            stage_name: "validate".to_string(),
            status: Some("passed".to_string()),
            commands: vec!["cargo check".to_string()],
            paths: vec!["target/check.txt".to_string()],
            evidence: vec!["ok".to_string()],
            missing: Vec::new(),
            summary: Some("cargo check passed".to_string()),
            source: Some("validate".to_string()),
        }],
        memory_writebacks: vec![ExecutionMemoryWritebackEvidence {
            schema_version: MEMORY_WRITEBACK_EVIDENCE_SCHEMA_VERSION,
            writeback_id: "wb-1".to_string(),
            stage_name: "validate".to_string(),
            object_id: Some("artifact:1".to_string()),
            kind: Some("artifact".to_string()),
            action: "applied".to_string(),
            reason: None,
            source: Some("checked_memory_writeback".to_string()),
        }],
        controller_decisions: vec![ExecutionControllerDecisionEvidence {
            schema_version: CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION,
            stage_name: "controller".to_string(),
            decision_id: "decision-1".to_string(),
            wave_id: Some("wave-1".to_string()),
            decision: "park".to_string(),
            next_action: Some("park the candidate workspace".to_string()),
            reason: Some("validation passed and candidate is dirty".to_string()),
            evidence: vec!["validate passed".to_string()],
            alternatives: vec!["stop".to_string()],
            human_required: false,
            scope: None,
            completion: None,
            memory_policy: None,
            runtime_policy: None,
        }],
        controller_applications: vec![ExecutionControllerApplicationEvidence {
            schema_version: CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION,
            application_id: "park:decision-1".to_string(),
            decision_id: "decision-1".to_string(),
            decision: "park".to_string(),
            action: "park".to_string(),
            applied: true,
            applied_at_ms: 1_717_171_717,
            source: Some("factory_controller".to_string()),
            reason: Some("candidate should be preserved".to_string()),
            error: None,
            next_execution_id: None,
            parked_candidate: None,
            promotion: None,
            memory_policy: None,
            side_effect: None,
            recovery: None,
        }],
        ..ExecutionEvidence::default()
    };

    assert!(!evidence.is_empty());
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(json["check_artifacts"][0]["artifact_id"], "artifact-1");
    assert_eq!(json["memory_writebacks"][0]["action"], "applied");
    assert_eq!(json["controller_decisions"][0]["decision"], "park");
    assert_eq!(json["controller_applications"][0]["action"], "park");
    let back: ExecutionEvidence = serde_json::from_value(json).unwrap();
    assert_eq!(back, evidence);
}

#[test]
fn execution_evidence_includes_checked_dispatch_guards() {
    let evidence = ExecutionEvidence {
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
        ..ExecutionEvidence::default()
    };

    assert!(!evidence.is_empty());
    let json = serde_json::to_value(&evidence).unwrap();
    assert_eq!(
        json["checked_dispatch_guards"][0]["guard"],
        serde_json::json!(CHECKED_DISPATCH_GUARD_ID)
    );
    assert_eq!(
        json["checked_dispatch_guards"][0]["status"],
        serde_json::json!("passed")
    );
    assert_eq!(
        json["checked_dispatch_guards"][0]["policy_fields"],
        serde_json::json!(CHECKED_DISPATCH_POLICY_FIELDS)
    );
    assert_eq!(
        json["checked_dispatch_guards"][0]["dispatch_kind"],
        serde_json::json!("validation_retry")
    );
    assert_eq!(
        json["checked_dispatch_guards"][0]["required_capabilities"],
        serde_json::json!(["network"])
    );
    assert_eq!(
        json["checked_dispatch_guards"][0]["derived_stage_name"],
        serde_json::json!("implement#validate-1")
    );
    let back: ExecutionEvidence = serde_json::from_value(json).unwrap();
    assert_eq!(back, evidence);
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "execution_tests/agent_tests.rs"]
mod agent_tests;
#[path = "execution_tests/error_tests.rs"]
mod error_tests;
#[path = "execution_tests/event_tests.rs"]
mod event_tests;
#[path = "execution_tests/health_tests.rs"]
mod health_tests;
#[path = "execution_tests/idempotency_tests.rs"]
mod idempotency_tests;
#[path = "execution_tests/primitives_tests.rs"]
mod primitives_tests;
#[path = "execution_tests/worker_tests.rs"]
mod worker_tests;
