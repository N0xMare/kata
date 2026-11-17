use kata_types::memory::{
    MEMORY_SCHEMA_VERSION, MemoryConflict, MemoryObjectDraft, MemoryObjectKind, MemoryObjectStatus,
    MemoryProposal, MemoryProvenance, MemoryScope, MemorySnapshot, MemorySourceKind,
};

#[test]
fn memory_proposal_roundtrips_file_bridge_shape() {
    let proposal = MemoryProposal {
        proposal_id: Some("proposal-1".to_string()),
        expected_revision: None,
        object: MemoryObjectDraft {
            id: Some("task-1".to_string()),
            kind: MemoryObjectKind::Task,
            scope: MemoryScope::Global,
            status: MemoryObjectStatus::Active,
            title: Some("Tighten validation criteria".to_string()),
            body: serde_json::json!({
                "summary": "Make validation criteria block completion claims.",
                "acceptance": ["promotion blocked without required evidence"]
            }),
            tags: vec!["factory".to_string()],
            links: Vec::new(),
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::ExternalFile,
                source_id: Some("codex".to_string()),
                execution_id: None,
                agent_id: None,
                path: Some(".kata/memory/inbox/task-1.json".to_string()),
            },
        },
        source_file: Some(".kata/memory/inbox/task-1.json".to_string()),
    };

    let json = serde_json::to_value(&proposal).expect("proposal serializes");
    assert_eq!(json["object"]["kind"], "task");
    assert_eq!(json["object"]["status"], "active");
    assert_eq!(json["object"]["provenance"]["source_kind"], "external_file");
    let decoded: MemoryProposal = serde_json::from_value(json).expect("proposal decodes");
    assert_eq!(decoded, proposal);
}

#[test]
fn memory_snapshot_and_conflict_shapes_are_stable() {
    let proposal = MemoryProposal {
        proposal_id: None,
        expected_revision: Some(1),
        object: MemoryObjectDraft {
            id: Some("decision-1".to_string()),
            kind: MemoryObjectKind::Decision,
            scope: MemoryScope::Global,
            status: MemoryObjectStatus::Active,
            title: Some("Use native store".to_string()),
            body: serde_json::json!({"choice": "api_authoritative"}),
            tags: Vec::new(),
            links: Vec::new(),
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::Operator,
                source_id: None,
                execution_id: None,
                agent_id: None,
                path: None,
            },
        },
        source_file: None,
    };
    let conflict = MemoryConflict {
        schema_version: MEMORY_SCHEMA_VERSION,
        conflict_id: "conflict-1".to_string(),
        object_id: "decision-1".to_string(),
        expected_revision: Some(1),
        actual_revision: Some(2),
        reason: "revision_mismatch".to_string(),
        proposal,
        recorded_at_ms: 1,
    };
    let snapshot = MemorySnapshot {
        schema_version: MEMORY_SCHEMA_VERSION,
        generated_at_ms: 2,
        revision_head: 0,
        object_count: 0,
        objects: Vec::new(),
    };

    let conflict_json = serde_json::to_value(&conflict).expect("conflict serializes");
    assert_eq!(conflict_json["reason"], "revision_mismatch");
    let snapshot_json = serde_json::to_value(&snapshot).expect("snapshot serializes");
    assert_eq!(snapshot_json["schema_version"], MEMORY_SCHEMA_VERSION);
    assert_eq!(snapshot_json["object_count"], 0);
}

#[test]
fn memory_labels_parse_back_to_enums() {
    for kind in [
        MemoryObjectKind::Objective,
        MemoryObjectKind::Task,
        MemoryObjectKind::Scenario,
        MemoryObjectKind::ValidationCriterion,
        MemoryObjectKind::Decision,
        MemoryObjectKind::Finding,
        MemoryObjectKind::Claim,
        MemoryObjectKind::Artifact,
        MemoryObjectKind::Candidate,
        MemoryObjectKind::Risk,
        MemoryObjectKind::MemoryLink,
        MemoryObjectKind::Summary,
    ] {
        assert_eq!(MemoryObjectKind::parse(kind.label()), Some(kind));
    }

    for status in [
        MemoryObjectStatus::Proposed,
        MemoryObjectStatus::Active,
        MemoryObjectStatus::Superseded,
        MemoryObjectStatus::Resolved,
        MemoryObjectStatus::Rejected,
        MemoryObjectStatus::Parked,
    ] {
        assert_eq!(MemoryObjectStatus::parse(status.label()), Some(status));
    }
}

/// A STORED object always carries its scope, so a blob without one is refused at
/// decode rather than read as `Global`; the same blob with its scope decodes.
#[test]
fn a_stored_memory_object_without_a_scope_is_refused() {
    let mut stored = serde_json::json!({
        "schema_version": MEMORY_SCHEMA_VERSION,
        "id": "task-1",
        "kind": "task",
        "status": "active",
        "body": {},
        "provenance": {"source_kind": "operator"},
        "revision": 1,
        "created_at_ms": 1,
        "updated_at_ms": 1,
    });
    let error = serde_json::from_value::<kata_types::memory::MemoryObject>(stored.clone())
        .expect_err("a stored object without a scope must not decode")
        .to_string();
    assert!(error.contains("missing field `scope`"), "{error}");

    stored["scope"] = serde_json::to_value(MemoryScope::Global).expect("scope encodes");
    let decoded = serde_json::from_value::<kata_types::memory::MemoryObject>(stored)
        .expect("the same object with its scope decodes");
    assert_eq!(decoded.scope, MemoryScope::Global);
}
