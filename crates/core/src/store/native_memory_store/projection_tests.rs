use super::*;

use kata_types::memory::{
    MemoryObjectDraft, MemoryObjectKind, MemoryObjectStatus, MemoryProposal, MemoryProvenance,
    MemoryScope, MemorySourceKind,
};

use super::projection::select_objects_with_query;

fn draft_proposal(
    id: &str,
    kind: MemoryObjectKind,
    status: MemoryObjectStatus,
    scope: MemoryScope,
    title: &str,
    body: serde_json::Value,
) -> MemoryProposal {
    MemoryProposal {
        proposal_id: None,
        expected_revision: None,
        object: MemoryObjectDraft {
            id: Some(id.to_string()),
            kind,
            scope,
            status,
            title: Some(title.to_string()),
            body,
            tags: Vec::new(),
            links: Vec::new(),
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::Workflow,
                source_id: Some("proj-test".to_string()),
                execution_id: None,
                agent_id: None,
                path: None,
            },
        },
        source_file: None,
    }
}

fn spread(store: &SqliteNativeMemoryStore) {
    let rows = [
        (
            "a",
            MemoryObjectKind::Finding,
            MemoryObjectStatus::Active,
            MemoryScope::Global,
            "alpha summary",
        ),
        (
            "b",
            MemoryObjectKind::Task,
            MemoryObjectStatus::Active,
            MemoryScope::Project {
                project: "p1".into(),
            },
            "beta task",
        ),
        (
            "c",
            MemoryObjectKind::Finding,
            MemoryObjectStatus::Proposed,
            MemoryScope::Workflow {
                project: "p1".into(),
                workflow: "w1".into(),
            },
            "gamma finding",
        ),
        (
            "d",
            MemoryObjectKind::Risk,
            MemoryObjectStatus::Active,
            MemoryScope::Workflow {
                project: "p2".into(),
                workflow: "w2".into(),
            },
            "delta risk",
        ),
        (
            "e",
            MemoryObjectKind::Task,
            MemoryObjectStatus::Resolved,
            MemoryScope::Global,
            "epsilon done",
        ),
    ];
    for (id, kind, status, scope, title) in rows {
        store
            .apply_proposal(draft_proposal(
                id,
                kind,
                status,
                scope,
                title,
                serde_json::json!({ "summary": title }),
            ))
            .unwrap();
    }
}

/// The in-RAM projection query (the prod read path) must return byte-for-byte
/// the same objects, in the same order, as the SQL reference reader — across
/// kind/status/scope/text/limit filters. This pins the "linear scan
/// mirrors the SQL" contract.
#[test]
fn projection_query_matches_sql_reference() {
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    spread(&store);
    let queries = vec![
        MemoryObjectQuery::default(),
        MemoryObjectQuery {
            kinds: vec![MemoryObjectKind::Finding],
            ..Default::default()
        },
        MemoryObjectQuery {
            statuses: vec![MemoryObjectStatus::Active],
            ..Default::default()
        },
        MemoryObjectQuery {
            kinds: vec![MemoryObjectKind::Task, MemoryObjectKind::Finding],
            statuses: vec![MemoryObjectStatus::Active],
            ..Default::default()
        },
        MemoryObjectQuery {
            limit: Some(2),
            ..Default::default()
        },
        MemoryObjectQuery {
            query: Some("finding".to_string()),
            ..Default::default()
        },
        MemoryObjectQuery {
            query: Some("finding".to_string()),
            limit: Some(1),
            ..Default::default()
        },
        MemoryObjectQuery {
            scope_window: Some(
                MemoryScope::Workflow {
                    project: "p1".into(),
                    workflow: "w1".into(),
                }
                .ancestors_inclusive(),
            ),
            ..Default::default()
        },
    ];
    for query in queries {
        let via_projection = store.query_objects(query.clone()).unwrap();
        let via_sql = {
            let conn = store.conn.lock();
            select_objects_with_query(&conn, &query).unwrap()
        };
        let proj_ids: Vec<&str> = via_projection.iter().map(|o| o.id.as_str()).collect();
        let sql_ids: Vec<&str> = via_sql.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(
            proj_ids, sql_ids,
            "projection vs SQL diverged for query {query:?}"
        );
    }
}

/// the SECURITY property. A read scoped to workflow
/// A's visibility window does NOT see a sibling workflow B's object, and the
/// test proves the scope window is LOAD-BEARING: without it
/// (`scope_window: None`), B leaks into A's read.
#[test]
fn scope_window_isolates_cross_workflow_reads() {
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    let scope_a = MemoryScope::Workflow {
        project: "p".into(),
        workflow: "w1".into(),
    };
    let scope_b = MemoryScope::Workflow {
        project: "p".into(),
        workflow: "w2".into(),
    };
    store
        .apply_proposal(draft_proposal(
            "obj-a",
            MemoryObjectKind::Finding,
            MemoryObjectStatus::Active,
            scope_a.clone(),
            "a secret",
            serde_json::json!({ "s": "a" }),
        ))
        .unwrap();
    store
        .apply_proposal(draft_proposal(
            "obj-b",
            MemoryObjectKind::Finding,
            MemoryObjectStatus::Active,
            scope_b,
            "b secret",
            serde_json::json!({ "s": "b" }),
        ))
        .unwrap();

    // Scoped to A: only A's object is visible; B is isolated.
    let scoped = store
        .query_objects(MemoryObjectQuery {
            scope_window: Some(scope_a.ancestors_inclusive()),
            ..Default::default()
        })
        .unwrap();
    let scoped_ids: Vec<&str> = scoped.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(
        scoped_ids,
        vec!["obj-a"],
        "a workflow-A-scoped read must see ONLY A's object, not sibling B's"
    );

    // Load-bearing proof: WITHOUT the window (flat), B leaks in.
    let unscoped = store
        .query_objects(MemoryObjectQuery {
            scope_window: None,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        unscoped.len(),
        2,
        "without the scope window every scope is visible — the leak the \
         threading closes"
    );
}

/// Write entitlement: a non-`Global` writer cannot write a `Global`-scope
/// object (nor reach outside its own subtree); an entitled write succeeds and
/// a rejected write persists NOTHING.
#[test]
fn global_write_from_non_global_writer_is_rejected() {
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    let project_writer = MemoryScope::Project {
        project: "p".into(),
    };

    // A Project{p} writer targeting Global → REJECTED, nothing persisted.
    let rejected = store.apply_proposal_entitled(
        draft_proposal(
            "escalate",
            MemoryObjectKind::Finding,
            MemoryObjectStatus::Active,
            MemoryScope::Global,
            "escalation attempt",
            serde_json::json!({}),
        ),
        &project_writer,
    );
    assert!(
        rejected.is_err(),
        "a non-global writer must NOT write Global scope"
    );
    assert!(
        store.get("escalate").unwrap().is_none(),
        "a rejected entitlement write persists nothing"
    );

    // A Project{p} writer reaching into a SIBLING project → REJECTED.
    let cross = store.apply_proposal_entitled(
        draft_proposal(
            "sibling",
            MemoryObjectKind::Finding,
            MemoryObjectStatus::Active,
            MemoryScope::Project {
                project: "q".into(),
            },
            "cross-tenant",
            serde_json::json!({}),
        ),
        &project_writer,
    );
    assert!(
        cross.is_err(),
        "a writer cannot reach a sibling project's scope"
    );

    // A Project{p} writer targeting its OWN scope → allowed.
    let own = store
        .apply_proposal_entitled(
            draft_proposal(
                "own",
                MemoryObjectKind::Finding,
                MemoryObjectStatus::Active,
                project_writer.clone(),
                "own scope write",
                serde_json::json!({}),
            ),
            &project_writer,
        )
        .unwrap();
    assert_eq!(own.status, "applied", "own-scope write is entitled");

    // A Project{p} writer targeting a DESCENDANT workflow → allowed.
    let descendant = store
        .apply_proposal_entitled(
            draft_proposal(
                "child",
                MemoryObjectKind::Finding,
                MemoryObjectStatus::Active,
                MemoryScope::Workflow {
                    project: "p".into(),
                    workflow: "w".into(),
                },
                "descendant write",
                serde_json::json!({}),
            ),
            &project_writer,
        )
        .unwrap();
    assert_eq!(
        descendant.status, "applied",
        "descendant-scope write is entitled"
    );

    // A Global writer targeting Global → allowed (the root is entitled to all).
    let global = store
        .apply_proposal_entitled(
            draft_proposal(
                "root",
                MemoryObjectKind::Finding,
                MemoryObjectStatus::Active,
                MemoryScope::Global,
                "global write",
                serde_json::json!({}),
            ),
            &MemoryScope::Global,
        )
        .unwrap();
    assert_eq!(global.status, "applied", "a global writer may write Global");
}

/// The durable recovery path: wiping the `memory_objects` mirror leaves
/// the append-only `memory_events` log intact, and rebuild reconstructs the
/// full current state (latest revision per id) into both mirror + projection.
#[test]
fn rebuild_objects_from_events_recovers_corrupted_mirror() {
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    spread(&store);
    // Update one object so it has a revision > 1 — rebuild must take the
    // LATEST revision, not the original.
    let mut bump = draft_proposal(
        "a",
        MemoryObjectKind::Finding,
        MemoryObjectStatus::Superseded,
        MemoryScope::Global,
        "alpha v2",
        serde_json::json!({ "summary": "alpha v2" }),
    );
    bump.expected_revision = Some(1);
    store.apply_proposal(bump).unwrap();

    // Corrupt the mirror: delete every row from memory_objects directly.
    {
        let conn = store.conn.lock();
        conn.execute("DELETE FROM memory_objects", []).unwrap();
    }
    // The projection still serves reads (it is independent of the mirror)...
    assert_eq!(
        store
            .query_objects(MemoryObjectQuery::default())
            .unwrap()
            .len(),
        5
    );

    let recovered = store.rebuild_objects_from_events().unwrap();
    assert_eq!(
        recovered, 5,
        "all five objects reconstructed from the event log"
    );

    // The mirror is repopulated and reopening (cold start from the mirror)
    // yields the LATEST revision of the bumped object.
    let a = store.get("a").unwrap().unwrap();
    assert_eq!(a.revision, 2, "rebuild kept the latest revision");
    assert_eq!(a.title.as_deref(), Some("alpha v2"));
    assert_eq!(a.status, MemoryObjectStatus::Superseded);
}
