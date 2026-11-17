//! deterministic memory-plane compaction + namespace-scoped bounds.
//!
//! These tests are the synthetic long-run proof: hundreds of writes across
//! namespaces stay under the per-namespace bound, summaries are present, reads
//! still resolve (recent verbatim / older via summary), namespace isolation
//! holds, and the bounds survive a reopen.

use super::*;

use kata_types::memory::{
    MemoryObject, MemoryObjectDraft, MemoryObjectKind, MemoryObjectStatus, MemoryProposal,
    MemoryProvenance, MemoryScope, MemorySourceKind,
};

fn draft(id: &str, scope: MemoryScope, title: &str) -> MemoryProposal {
    MemoryProposal {
        proposal_id: None,
        expected_revision: None,
        object: MemoryObjectDraft {
            id: Some(id.to_string()),
            kind: MemoryObjectKind::Finding,
            status: MemoryObjectStatus::Active,
            scope,
            title: Some(title.to_string()),
            body: serde_json::json!({ "note": title }),
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

fn wf(project: &str, workflow: &str) -> MemoryScope {
    MemoryScope::Workflow {
        project: project.into(),
        workflow: workflow.into(),
    }
}

/// Count the live (non-summary) objects currently in a scope.
fn live_count(store: &SqliteNativeMemoryStore, scope: &MemoryScope) -> usize {
    store
        .query_objects(MemoryObjectQuery::default())
        .unwrap()
        .into_iter()
        .filter(|o| o.kind != MemoryObjectKind::Summary && &o.scope == scope)
        .count()
}

fn summary_of(store: &SqliteNativeMemoryStore, scope: &MemoryScope) -> Option<MemoryObject> {
    store.get(&summary_object_id(scope)).unwrap()
}

/// Hundreds of writes into ONE namespace fold down to the bound + a summary, the
/// most recent entries stay verbatim, and every folded entry is still resolvable
/// through the summary digest.
#[test]
fn compaction_bounds_a_single_namespace_and_preserves_reads() {
    // bound 10, auto-cadence off (explicit compact) so the assertion is exact.
    let store = SqliteNativeMemoryStore::open_in_memory()
        .unwrap()
        .with_compaction(10, 0);
    let scope = MemoryScope::Global;

    // 250 live writes into one namespace — a long-run stand-in.
    for i in 0..250 {
        store
            .apply_proposal(draft(
                &format!("obj-{i:04}"),
                scope.clone(),
                &format!("row {i}"),
            ))
            .unwrap();
    }
    assert_eq!(live_count(&store, &scope), 250, "all writes land first");

    let outcome = store.compact().unwrap();
    assert_eq!(outcome.namespaces_compacted, 1);
    assert_eq!(outcome.objects_folded, 240, "250 - bound(10) fold");
    assert_eq!(outcome.summaries_written, 1);

    // Bound holds: exactly `max_live` live objects remain, plus one summary.
    assert_eq!(
        live_count(&store, &scope),
        10,
        "namespace folded to the bound"
    );

    // The most-recent 10 (highest ids) survive verbatim; the oldest are gone.
    for i in 240..250 {
        assert!(
            store.get(&format!("obj-{i:04}")).unwrap().is_some(),
            "recent entry obj-{i:04} stays verbatim"
        );
    }
    for i in 0..240 {
        assert!(
            store.get(&format!("obj-{i:04}")).unwrap().is_none(),
            "folded entry obj-{i:04} evicted from the live set"
        );
    }

    // Older entries resolve through the summary digest (exact folded_count; the
    // entry window keeps up to summary_entry_cap = 256 >= 240 stubs, so every
    // folded id is present here).
    let summary = summary_of(&store, &scope).expect("summary object present");
    assert_eq!(summary.kind, MemoryObjectKind::Summary);
    assert_eq!(summary.body["kata_compaction"], serde_json::json!(true));
    assert_eq!(summary.body["folded_count"], serde_json::json!(240));
    assert_eq!(
        summary.body["by_status"]["active"],
        serde_json::json!(240),
        "histogram is exact over every folded object"
    );
    let entries = summary.body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 240, "all folded stubs fit under the cap");
    let ids: std::collections::HashSet<&str> =
        entries.iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert!(
        ids.contains("obj-0000"),
        "oldest folded id resolvable via summary"
    );
    assert!(
        ids.contains("obj-0239"),
        "newest folded id resolvable via summary"
    );
}

/// Compaction is per-namespace: an over-bound namespace folds while a
/// sibling under-bound namespace is untouched, and the SECURITY isolation
/// (a workflow B reader cannot see workflow A's objects or summary without an
/// explicit cross-namespace opt-in) holds after compaction.
#[test]
fn compaction_is_per_namespace_and_isolation_holds() {
    let store = SqliteNativeMemoryStore::open_in_memory()
        .unwrap()
        .with_compaction(5, 0);
    let a = wf("proj", "wf-a");
    let b = wf("proj", "wf-b");

    for i in 0..20 {
        store
            .apply_proposal(draft(&format!("a-{i:03}"), a.clone(), &format!("a {i}")))
            .unwrap();
    }
    for i in 0..3 {
        store
            .apply_proposal(draft(&format!("b-{i:03}"), b.clone(), &format!("b {i}")))
            .unwrap();
    }

    let outcome = store.compact().unwrap();
    assert_eq!(
        outcome.namespaces_compacted, 1,
        "only the over-bound namespace folds"
    );
    assert_eq!(outcome.objects_folded, 15, "20 - bound(5) fold in A only");

    assert_eq!(live_count(&store, &a), 5, "A folded to the bound");
    assert_eq!(live_count(&store, &b), 3, "B (under bound) untouched");
    assert!(summary_of(&store, &a).is_some(), "A has a summary");
    assert!(
        summary_of(&store, &b).is_none(),
        "B, never folded, has no summary"
    );

    // Isolation regression: a reader scoped to workflow B sees ONLY B's window
    // (B + its ancestors: Project{proj}, Global) — never A's objects or summary.
    let b_window = b.ancestors_inclusive();
    let visible_to_b = store
        .query_objects(MemoryObjectQuery {
            scope_window: Some(b_window),
            ..MemoryObjectQuery::default()
        })
        .unwrap();
    assert!(
        visible_to_b.iter().all(|o| o.scope != a),
        "workflow B cannot read workflow A's namespace without opt-in"
    );
    assert!(
        visible_to_b.iter().any(|o| o.scope == b),
        "workflow B still reads its own namespace"
    );
    // A's summary lives in scope A, so it is invisible to B too.
    assert!(
        visible_to_b
            .iter()
            .all(|o| o.kind != MemoryObjectKind::Summary),
        "A's compaction summary is not visible to B"
    );

    // Cross-namespace opt-in: an unscoped read (no window) is the explicit
    // wider read and DOES see A's objects + summary.
    let flat = store.query_objects(MemoryObjectQuery::default()).unwrap();
    assert!(
        flat.iter().any(|o| o.scope == a),
        "an explicit unscoped read opts into A's namespace"
    );
}

/// The per-namespace bound and the summary survive a store reopen (durable
/// mirror + event log), and an event-log rebuild does not resurrect folded
/// objects.
#[test]
fn compaction_bounds_survive_reopen_and_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.db");
    let scope = MemoryScope::Global;

    {
        let store = SqliteNativeMemoryStore::open(&path)
            .unwrap()
            .with_compaction(8, 0);
        for i in 0..40 {
            store
                .apply_proposal(draft(
                    &format!("obj-{i:04}"),
                    scope.clone(),
                    &format!("r {i}"),
                ))
                .unwrap();
        }
        let outcome = store.compact().unwrap();
        assert_eq!(outcome.objects_folded, 32, "40 - bound(8)");
        assert_eq!(live_count(&store, &scope), 8);
    }

    // Reopen: the bound holds from the durable mirror alone (no in-RAM state).
    let reopened = SqliteNativeMemoryStore::open(&path).unwrap();
    assert_eq!(
        live_count(&reopened, &scope),
        8,
        "bound holds across reopen"
    );
    let summary = summary_of(&reopened, &scope).expect("summary persisted");
    assert_eq!(summary.body["folded_count"], serde_json::json!(32));
    assert!(
        reopened.get("obj-0000").unwrap().is_none(),
        "a folded object stays evicted after reopen"
    );

    // Rebuild from the event log recovers the survivors + the summary, and never
    // resurrects the folded objects (their events were deleted at fold time).
    let rebuilt = reopened.rebuild_objects_from_events().unwrap();
    assert_eq!(rebuilt, 9, "8 survivors + 1 summary");
    assert!(reopened.get("obj-0000").unwrap().is_none());
    assert!(summary_of(&reopened, &scope).is_some());
}

/// The write-threshold cadence folds automatically — no explicit `compact`
/// call — once the configured number of writes elapses.
#[test]
fn write_threshold_cadence_auto_compacts() {
    // bound 5, auto-compact every 10 writes.
    let store = SqliteNativeMemoryStore::open_in_memory()
        .unwrap()
        .with_compaction(5, 10);
    let scope = MemoryScope::Global;

    // 12 writes: the 10th trips the cadence (10 live > bound 5 → fold 5), then
    // writes 11 and 12 grow the live set back to 7. No manual compact() here.
    for i in 0..12 {
        store
            .apply_proposal(draft(
                &format!("obj-{i:04}"),
                scope.clone(),
                &format!("w {i}"),
            ))
            .unwrap();
    }

    assert!(
        summary_of(&store, &scope).is_some(),
        "the write-threshold cadence produced a summary with no explicit compact() call"
    );
    assert_eq!(
        live_count(&store, &scope),
        7,
        "auto-fold at write 10 (10->5), then two more writes -> 7 live"
    );
    let summary = summary_of(&store, &scope).unwrap();
    assert_eq!(summary.body["folded_count"], serde_json::json!(5));
}

/// A disabled bound (operator sets the knob to 0) is a hard no-op: nothing folds
/// and no summary is created, even far past where a bound would have tripped.
#[test]
fn disabled_compaction_is_a_noop() {
    let store = SqliteNativeMemoryStore::open_in_memory()
        .unwrap()
        .with_compaction(0, 0);
    let scope = MemoryScope::Global;
    for i in 0..40 {
        store
            .apply_proposal(draft(
                &format!("obj-{i:04}"),
                scope.clone(),
                &format!("n {i}"),
            ))
            .unwrap();
    }
    let outcome = store.compact().unwrap();
    assert_eq!(outcome, MemoryCompactionOutcome::default(), "no-op outcome");
    assert_eq!(live_count(&store, &scope), 40, "nothing folded");
    assert!(summary_of(&store, &scope).is_none(), "no summary created");
}

/// Successive folds accumulate EXACT counts while the summary's own entry window
/// stays bounded by `summary_entry_cap` — the summary object cannot itself grow
/// without limit.
#[test]
fn successive_folds_accumulate_exact_counts_under_a_bounded_summary() {
    let store = SqliteNativeMemoryStore::open_in_memory().unwrap();
    let scope = MemoryScope::Global;
    let policy = MemoryCompactionPolicy {
        max_live_objects_per_namespace: Some(2),
        summary_entry_cap: 3,
    };

    for i in 0..6 {
        store
            .apply_proposal(draft(
                &format!("p1-{i:02}"),
                scope.clone(),
                &format!("a {i}"),
            ))
            .unwrap();
    }
    let first = store.compact_with(&policy).unwrap();
    assert_eq!(first.objects_folded, 4, "6 - bound(2)");
    let s1 = summary_of(&store, &scope).unwrap();
    assert_eq!(s1.body["folded_count"], serde_json::json!(4));
    assert_eq!(
        s1.body["entries"].as_array().unwrap().len(),
        3,
        "entry window is capped"
    );

    // Second pass over a fresh batch: counts accumulate, window stays capped.
    for i in 0..5 {
        store
            .apply_proposal(draft(
                &format!("p2-{i:02}"),
                scope.clone(),
                &format!("b {i}"),
            ))
            .unwrap();
    }
    let second = store.compact_with(&policy).unwrap();
    // Live before pass 2 = 2 survivors + 5 new = 7 → fold 5.
    assert_eq!(second.objects_folded, 5);
    let s2 = summary_of(&store, &scope).unwrap();
    assert_eq!(
        s2.body["folded_count"],
        serde_json::json!(9),
        "cumulative exact count across both passes"
    );
    assert_eq!(
        s2.body["entries"].as_array().unwrap().len(),
        3,
        "summary entry window remains bounded across folds"
    );
    assert_eq!(
        s2.revision, 2,
        "the same summary object was updated in place"
    );
}
