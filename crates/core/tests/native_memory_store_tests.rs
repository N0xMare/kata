use kata_core::store::{MemoryObjectQuery, SqliteNativeMemoryStore};
use kata_types::memory::{
    MemoryObjectDraft, MemoryObjectKind, MemoryObjectStatus, MemoryProposal, MemoryProvenance,
    MemoryScope, MemorySourceKind,
};

#[test]
fn native_memory_authority_uses_full_synchronous_durability() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteNativeMemoryStore::open(dir.path().join("memory.db")).unwrap();
    assert_eq!(
        store.debug_synchronous_level().unwrap(),
        2,
        "authoritative memory commits must survive a later terminal lifecycle commit"
    );
}

fn proposal(
    id: Option<&str>,
    expected_revision: Option<u64>,
    title: &str,
    status: MemoryObjectStatus,
) -> MemoryProposal {
    proposal_with_kind(id, expected_revision, title, MemoryObjectKind::Task, status)
}

fn proposal_with_kind(
    id: Option<&str>,
    expected_revision: Option<u64>,
    title: &str,
    kind: MemoryObjectKind,
    status: MemoryObjectStatus,
) -> MemoryProposal {
    MemoryProposal {
        proposal_id: None,
        expected_revision,
        object: MemoryObjectDraft {
            id: id.map(ToOwned::to_owned),
            kind,
            scope: MemoryScope::Global,
            status,
            title: Some(title.to_string()),
            body: serde_json::json!({ "summary": title }),
            tags: vec!["factory".to_string()],
            links: Vec::new(),
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::Workflow,
                source_id: Some("test".to_string()),
                execution_id: None,
                agent_id: None,
                path: None,
            },
        },
        source_file: None,
    }
}

#[test]
fn native_memory_store_applies_create_and_update_proposals() {
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();

    let created = store
        .apply_proposal(proposal(
            Some("task-1"),
            None,
            "Draft product objective",
            MemoryObjectStatus::Proposed,
        ))
        .unwrap();
    let object = created.object.unwrap();
    assert_eq!(created.status, "applied");
    assert_eq!(object.id, "task-1");
    assert_eq!(object.revision, 1);

    let updated = store
        .apply_proposal(proposal(
            Some("task-1"),
            Some(1),
            "Draft product objective with evidence",
            MemoryObjectStatus::Active,
        ))
        .unwrap();
    let object = updated.object.unwrap();
    assert_eq!(updated.status, "applied");
    assert_eq!(object.revision, 2);
    assert_eq!(object.status, MemoryObjectStatus::Active);
    assert_eq!(
        object.title.as_deref(),
        Some("Draft product objective with evidence")
    );
}

#[test]
fn native_memory_store_records_conflict_without_overwriting_current_object() {
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    store
        .apply_proposal(proposal(
            Some("task-1"),
            None,
            "First",
            MemoryObjectStatus::Proposed,
        ))
        .unwrap();
    store
        .apply_proposal(proposal(
            Some("task-1"),
            Some(1),
            "Second",
            MemoryObjectStatus::Active,
        ))
        .unwrap();

    let stale = store
        .apply_proposal(proposal(
            Some("task-1"),
            Some(1),
            "Stale third write",
            MemoryObjectStatus::Rejected,
        ))
        .unwrap();

    assert_eq!(stale.status, "conflict");
    let conflict = stale.conflict.unwrap();
    assert_eq!(conflict.object_id, "task-1");
    assert_eq!(conflict.expected_revision, Some(1));
    assert_eq!(conflict.actual_revision, Some(2));
    assert!(stale.object.is_none());

    let current = store.get("task-1").unwrap().unwrap();
    assert_eq!(current.revision, 2);
    assert_eq!(current.status, MemoryObjectStatus::Active);
    assert_eq!(current.title.as_deref(), Some("Second"));
}

#[test]
fn native_memory_store_snapshots_and_persists_across_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("memory.db");
    {
        let store = SqliteNativeMemoryStore::open(&path).unwrap();
        store
            .apply_proposal(proposal(
                Some("task-1"),
                None,
                "Persist me",
                MemoryObjectStatus::Active,
            ))
            .unwrap();
        let snapshot = store
            .snapshot(
                Some(MemoryObjectKind::Task),
                Some(MemoryObjectStatus::Active),
            )
            .unwrap();
        assert_eq!(snapshot.object_count, 1);
        assert_eq!(snapshot.objects[0].id, "task-1");
        assert_eq!(snapshot.revision_head, 1);
    }

    let reopened = SqliteNativeMemoryStore::open(&path).unwrap();
    let object = reopened.get("task-1").unwrap().unwrap();
    assert_eq!(object.title.as_deref(), Some("Persist me"));
    assert_eq!(object.revision, 1);
}

#[test]
fn native_memory_store_queries_objects_by_kind_status_and_limit() {
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    for (id, title, kind, status) in [
        (
            "task-active",
            "Active task",
            MemoryObjectKind::Task,
            MemoryObjectStatus::Active,
        ),
        (
            "task-proposed",
            "Proposed task",
            MemoryObjectKind::Task,
            MemoryObjectStatus::Proposed,
        ),
        (
            "finding-active",
            "Active finding",
            MemoryObjectKind::Finding,
            MemoryObjectStatus::Active,
        ),
        (
            "risk-active",
            "Active risk",
            MemoryObjectKind::Risk,
            MemoryObjectStatus::Active,
        ),
        (
            "controller-decision",
            "Controller decision",
            MemoryObjectKind::Decision,
            MemoryObjectStatus::Active,
        ),
    ] {
        store
            .apply_proposal(proposal_with_kind(Some(id), None, title, kind, status))
            .unwrap();
    }

    let active_tasks_or_findings = store
        .query_objects(MemoryObjectQuery {
            kinds: vec![MemoryObjectKind::Task, MemoryObjectKind::Finding],
            statuses: vec![MemoryObjectStatus::Active],
            query: None,
            limit: None,
            scope_window: None,
        })
        .unwrap();
    let ids = active_tasks_or_findings
        .iter()
        .map(|object| object.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["finding-active", "task-active"]);

    let limited = store
        .query_objects(MemoryObjectQuery {
            kinds: Vec::new(),
            statuses: vec![MemoryObjectStatus::Active],
            query: None,
            limit: Some(2),
            scope_window: None,
        })
        .unwrap();
    assert_eq!(limited.len(), 2);
    assert!(
        limited
            .iter()
            .all(|object| object.status == MemoryObjectStatus::Active)
    );

    let controller_decisions = store
        .query_objects(MemoryObjectQuery {
            kinds: vec![MemoryObjectKind::Decision],
            statuses: vec![MemoryObjectStatus::Active],
            query: Some("recent controller decisions".to_string()),
            limit: Some(1),
            scope_window: None,
        })
        .unwrap();
    let ids = controller_decisions
        .iter()
        .map(|object| object.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["controller-decision"]);

    let missing = store
        .query_objects(MemoryObjectQuery {
            kinds: Vec::new(),
            statuses: vec![MemoryObjectStatus::Active],
            query: Some("nonexistent controller token".to_string()),
            limit: Some(1),
            scope_window: None,
        })
        .unwrap();
    assert!(missing.is_empty());

    let no_effective_terms = store
        .query_objects(MemoryObjectQuery {
            kinds: Vec::new(),
            statuses: vec![MemoryObjectStatus::Active],
            query: Some("recent".to_string()),
            limit: Some(1),
            scope_window: None,
        })
        .unwrap();
    assert!(no_effective_terms.is_empty());
}

// ---------------------------------------------------------------------------
// typed memory scope model
// ---------------------------------------------------------------------------

fn scoped_proposal(id: &str, scope: MemoryScope) -> MemoryProposal {
    MemoryProposal {
        proposal_id: None,
        expected_revision: None,
        object: MemoryObjectDraft {
            id: Some(id.to_string()),
            kind: MemoryObjectKind::Finding,
            scope,
            status: MemoryObjectStatus::Active,
            title: Some(id.to_string()),
            body: serde_json::json!({ "summary": id }),
            tags: Vec::new(),
            links: Vec::new(),
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::Workflow,
                source_id: Some("scope-test".to_string()),
                execution_id: None,
                agent_id: None,
                path: None,
            },
        },
        source_file: None,
    }
}

fn sorted_ids(objects: &[kata_types::memory::MemoryObject]) -> Vec<String> {
    let mut ids = objects
        .iter()
        .map(|object| object.id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

#[test]
fn ancestors_inclusive_is_correct() {
    assert_eq!(
        MemoryScope::Global.ancestors_inclusive(),
        vec![MemoryScope::Global]
    );
    assert_eq!(
        MemoryScope::Project {
            project: "p".to_string()
        }
        .ancestors_inclusive(),
        vec![
            MemoryScope::Project {
                project: "p".to_string()
            },
            MemoryScope::Global,
        ]
    );
    assert_eq!(
        MemoryScope::Workflow {
            project: "p".to_string(),
            workflow: "w".to_string(),
        }
        .ancestors_inclusive(),
        vec![
            MemoryScope::Workflow {
                project: "p".to_string(),
                workflow: "w".to_string(),
            },
            MemoryScope::Project {
                project: "p".to_string()
            },
            MemoryScope::Global,
        ]
    );

    // A workflow's window must NEVER contain a sibling workflow in the same
    // project — this is the cross-workflow isolation guarantee.
    let window = MemoryScope::Workflow {
        project: "p1".to_string(),
        workflow: "w1".to_string(),
    }
    .ancestors_inclusive();
    assert!(!window.contains(&MemoryScope::Workflow {
        project: "p1".to_string(),
        workflow: "w2".to_string(),
    }));
}

#[test]
fn scope_round_trips_through_canonical_key() {
    let scopes = vec![
        MemoryScope::Global,
        MemoryScope::Project {
            project: "p".to_string(),
        },
        MemoryScope::Workflow {
            project: "p".to_string(),
            workflow: "w".to_string(),
        },
        // Tricky names containing the delimiters a naive join would confuse.
        MemoryScope::Project {
            project: "a/b:c".to_string(),
        },
        MemoryScope::Workflow {
            project: "a/b".to_string(),
            workflow: "c".to_string(),
        },
        MemoryScope::Workflow {
            project: "a".to_string(),
            workflow: "b/c".to_string(),
        },
        MemoryScope::Workflow {
            project: "proj:with:colons".to_string(),
            workflow: "wf/with/slashes".to_string(),
        },
        // Injectivity: a `\x1f` (unit separator) inside a component must NOT
        // forge another scope's key. These two would collide under a plain
        // `\x1f`-separated form.
        MemoryScope::Workflow {
            project: "a".to_string(),
            workflow: "b\u{1f}c".to_string(),
        },
        MemoryScope::Workflow {
            project: "a\u{1f}b".to_string(),
            workflow: "c".to_string(),
        },
        // A project literally named "global" must not alias the Global tier.
        MemoryScope::Project {
            project: "global".to_string(),
        },
        // Empty components round-trip (length prefix encodes 0).
        MemoryScope::Workflow {
            project: String::new(),
            workflow: String::new(),
        },
    ];
    for scope in &scopes {
        assert_eq!(
            MemoryScope::parse_canonical_key(&scope.canonical_key()).as_ref(),
            Some(scope),
            "round-trip failed for {scope:?}"
        );
    }

    // The length prefix must keep `Workflow{"a/b","c"}` distinct from
    // `Workflow{"a","b/c"}` AND `Workflow{"a","b\x1fc"}` from
    // `Workflow{"a\x1fb","c"}` — a naive join on ANY separator collides one pair.
    let a = MemoryScope::Workflow {
        project: "a/b".to_string(),
        workflow: "c".to_string(),
    };
    let b = MemoryScope::Workflow {
        project: "a".to_string(),
        workflow: "b/c".to_string(),
    };
    assert_ne!(a.canonical_key(), b.canonical_key());

    // No two distinct scopes in the set may share a canonical key.
    let mut keys = std::collections::HashSet::new();
    for scope in &scopes {
        assert!(
            keys.insert(scope.canonical_key()),
            "canonical key collision for {scope:?}"
        );
    }
}

#[test]
fn scope_window_isolates_projects() {
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    store
        .apply_proposal(scoped_proposal(
            "p1w1",
            MemoryScope::Workflow {
                project: "p1".to_string(),
                workflow: "w1".to_string(),
            },
        ))
        .unwrap();
    store
        .apply_proposal(scoped_proposal(
            "p2w2",
            MemoryScope::Workflow {
                project: "p2".to_string(),
                workflow: "w2".to_string(),
            },
        ))
        .unwrap();
    store
        .apply_proposal(scoped_proposal(
            "p2proj",
            MemoryScope::Project {
                project: "p2".to_string(),
            },
        ))
        .unwrap();
    store
        .apply_proposal(scoped_proposal("glob", MemoryScope::Global))
        .unwrap();

    let window = MemoryScope::Workflow {
        project: "p1".to_string(),
        workflow: "w1".to_string(),
    }
    .ancestors_inclusive();
    let visible = store
        .query_objects(MemoryObjectQuery {
            scope_window: Some(window),
            ..Default::default()
        })
        .unwrap();

    // Only the reader's own workflow object and the Global object are visible.
    // p2's workflow and p2's project are another project's scope — never visible.
    assert_eq!(sorted_ids(&visible), vec!["glob", "p1w1"]);
}

#[test]
fn scope_is_immutable_across_a_plain_update() {
    // A routine update must NOT relocate an
    // existing object to a wider-visibility scope. Create at Workflow{p1,w1},
    // then submit an update that *declares* Global — the stored scope must stay
    // Workflow{p1,w1} so the object cannot escalate its visibility.
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    let own = MemoryScope::Workflow {
        project: "p1".to_string(),
        workflow: "w1".to_string(),
    };
    store
        .apply_proposal(scoped_proposal("obj", own.clone()))
        .unwrap();

    let mut escalate = scoped_proposal("obj", MemoryScope::Global);
    escalate.expected_revision = Some(1);
    escalate.object.title = Some("relocated".to_string()); // force a real update
    let response = store.apply_proposal(escalate).unwrap();
    assert_eq!(response.status, "applied", "the update itself must apply");

    let stored = store.get("obj").unwrap().unwrap();
    assert_eq!(
        stored.scope, own,
        "scope must be pinned to the created scope, not the draft's Global"
    );
    assert_eq!(
        stored.title.as_deref(),
        Some("relocated"),
        "fields still update"
    );

    // It must remain invisible to a sibling project and visible to its own.
    let sibling_window = MemoryScope::Workflow {
        project: "p2".to_string(),
        workflow: "w2".to_string(),
    }
    .ancestors_inclusive();
    let from_sibling = store
        .query_objects(MemoryObjectQuery {
            scope_window: Some(sibling_window),
            ..Default::default()
        })
        .unwrap();
    assert!(
        from_sibling.is_empty(),
        "escalation attempt must not have leaked the object to another project"
    );
}

#[test]
fn scope_window_none_is_flat() {
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    let inserted = [
        (
            "p1w1",
            MemoryScope::Workflow {
                project: "p1".into(),
                workflow: "w1".into(),
            },
        ),
        (
            "p2w2",
            MemoryScope::Workflow {
                project: "p2".into(),
                workflow: "w2".into(),
            },
        ),
        (
            "p2proj",
            MemoryScope::Project {
                project: "p2".into(),
            },
        ),
        ("glob", MemoryScope::Global),
    ];
    for (id, scope) in inserted.iter().cloned() {
        store.apply_proposal(scoped_proposal(id, scope)).unwrap();
    }

    let all = store
        .query_objects(MemoryObjectQuery {
            scope_window: None,
            ..Default::default()
        })
        .unwrap();
    // No scope predicate => flat behavior: every scope is visible.
    assert_eq!(sorted_ids(&all), vec!["glob", "p1w1", "p2proj", "p2w2"]);
}

#[test]
fn a_draft_naming_no_scope_is_global() {
    // A draft that names no scope is Global: `MemoryObjectDraft::scope` defaults to
    // it, and the store's `scope` column (DEFAULT 'global') mirrors the same key.
    let draft_json = serde_json::json!({
        "kind": "finding",
        "status": "active",
        "title": "unscoped",
        "provenance": { "source_kind": "workflow" }
    });
    let draft: MemoryObjectDraft = serde_json::from_value(draft_json).unwrap();
    assert_eq!(draft.scope, MemoryScope::Global);

    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    let applied = store
        .apply_proposal(MemoryProposal {
            proposal_id: None,
            expected_revision: None,
            object: draft,
            source_file: None,
        })
        .unwrap();
    let object = applied.object.unwrap();
    assert_eq!(object.scope, MemoryScope::Global);

    // The mirrored column key is exactly "global": a window of only [Global]
    // returns it, while a window that omits Global (e.g. [Project{"p"}]) does not.
    let global_only = store
        .query_objects(MemoryObjectQuery {
            scope_window: Some(vec![MemoryScope::Global]),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(sorted_ids(&global_only), vec![object.id.clone()]);

    let project_only = store
        .query_objects(MemoryObjectQuery {
            scope_window: Some(vec![MemoryScope::Project {
                project: "p".to_string(),
            }]),
            ..Default::default()
        })
        .unwrap();
    assert!(project_only.is_empty());

    // A Workflow base scope's window includes Global, so it still sees the row.
    let workflow_window = MemoryScope::Workflow {
        project: "p".to_string(),
        workflow: "w".to_string(),
    }
    .ancestors_inclusive();
    let via_workflow = store
        .query_objects(MemoryObjectQuery {
            scope_window: Some(workflow_window),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(sorted_ids(&via_workflow), vec![object.id]);
}
