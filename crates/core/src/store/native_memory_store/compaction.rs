//! Deterministic memory-plane compaction.
//!
//! The native memory store is event-sourced, and without compaction its *live*
//! object set grows without bound: a long factory run accumulates `Active`
//! findings/claims/decisions per workflow with no ceiling. This module is the
//! compaction processor that bounds that live working set; the namespace axis is
//! [`MemoryScope`]. Nothing reclaims terminal objects or the history events of
//! surviving objects: those grow with the run.
//!
//! **What it does.** Per namespace (memory scope), when the live (non-terminal)
//! object count exceeds [`MemoryCompactionPolicy::max_live_objects_per_namespace`],
//! the OLDEST overflow objects are folded into a single per-namespace `Summary`
//! object (kind [`MemoryObjectKind::Summary`]) and then evicted. Recent live
//! entries stay verbatim; older ones are still readable through the summary's
//! digest. This bounds per-namespace live object count across an arbitrarily
//! long run, and the folded objects' events are deleted with them.
//!
//! **Deterministic only.** The summary body is [`fold_summary_body`] — a free,
//! deterministic digest (counts by kind/status + a bounded window of entry
//! stubs). NO live-model summarization runs here.
//!
//! **Read-side note — summaries surface in kind-unfiltered reads.** A summary is
//! written with `updated_at_ms = now` and status `Active`, and the read
//! projection orders `updated_at_ms DESC`. So a kind-unfiltered selector (empty
//! `kinds`) returns the freshly-written summary as the NEWEST row, and it can
//! displace a genuinely recent object within a `limit`. This is intentional —
//! it is how "older entries resolve via the summary" reaches an unfiltered
//! reader — but the injected body is a compaction-digest shape, not a normal
//! object. A reader that wants only verbatim objects should filter by `kinds`
//! (excluding [`MemoryObjectKind::Summary`]); a reader that wants the digest
//! asks for `MemoryObjectKind::Summary` explicitly. Kind-filtered selectors
//! (e.g. the `workflows/smoke` memory-context rig) are unaffected.
//!
//! **Mid-run note — compaction evicts ACTIVE objects.** It evicts the oldest
//! *live* (`Active`) objects the moment a namespace overflows and the cadence
//! fires.
//! Memory is a non-authoritative retrieval plane (evidence folds to latest), so
//! this is sound, but a stage's memory-selector result can differ between its
//! first dispatch and a resync re-materialization (folded objects replaced by
//! the summary). Retrieval across a resync is therefore best-effort by design.
//!
//! [`MemoryObjectKind::Summary`]: kata_types::memory::MemoryObjectKind::Summary
//! [`MemoryScope`]: kata_types::memory::MemoryScope

use std::collections::BTreeMap;

use kata_types::memory::{MemoryObject, MemoryScope};
use serde_json::{Value, json};

/// Reserved tag stamped on every compaction summary object. Lets a reader
/// recognize a summary independent of its kind, and lets the compactor exclude
/// summaries from the fold set defensively.
pub const COMPACTION_SUMMARY_TAG: &str = "kata:compaction-summary";

/// Per-namespace bounds for the deterministic memory compaction processor.
///
/// Every field defaults to a generous retention in [`Default`]; boot tightens it
/// from `[runtime]` config, and a caller (or a future scheduled pass) may pass a
/// stricter policy to [`compact_with`](super::store::SqliteNativeMemoryStore::compact_with).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryCompactionPolicy {
    /// Max live (non-terminal, non-summary) objects retained VERBATIM per
    /// namespace. When a namespace exceeds this, the oldest overflow objects fold
    /// into that namespace's summary and are evicted. `None` disables folding
    /// (unbounded growth). The effective per-namespace object ceiling after a
    /// pass is `max_live_objects_per_namespace + 1` (the summary itself).
    pub max_live_objects_per_namespace: Option<usize>,
    /// Max folded-entry stubs retained inside a namespace summary body. Older
    /// stubs collapse into the aggregate `by_kind`/`by_status` counters (which
    /// are always exact), bounding the summary object's own byte size so it does
    /// not itself grow without limit across successive folds.
    pub summary_entry_cap: usize,
}

impl Default for MemoryCompactionPolicy {
    fn default() -> Self {
        Self {
            // Generous default: a namespace keeps up to 512 live objects verbatim
            // before older ones fold. Bounds growth without perturbing typical
            // short runs (which never approach it).
            max_live_objects_per_namespace: Some(512),
            summary_entry_cap: 256,
        }
    }
}

impl MemoryCompactionPolicy {
    /// A policy that never folds — compaction is a no-op. Used when the operator
    /// sets the bound to 0 (narrowing-logged at boot).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            max_live_objects_per_namespace: None,
            summary_entry_cap: 256,
        }
    }
}

/// What a [`compact`](super::store::SqliteNativeMemoryStore::compact) pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryCompactionOutcome {
    /// Namespaces (scopes) that had at least one object folded this pass.
    pub namespaces_compacted: usize,
    /// Live objects folded into a summary and evicted.
    pub objects_folded: usize,
    /// Summary objects created or updated (one per compacted namespace).
    pub summaries_written: usize,
}

/// Build the new summary body for `scope`, folding `folded` (the objects being
/// compacted away this pass) into `prior` (the existing summary body for this
/// namespace, if one already exists).
///
/// A structured JSON digest: exact `folded_count`, exact `by_kind`/`by_status`
/// histograms, and a bounded window (`entry_cap`) of the most-recently-folded
/// entry stubs. Merges cleanly with a prior summary body so successive folds
/// accumulate exact counts while the body stays byte-bounded.
pub(super) fn fold_summary_body(
    scope: &MemoryScope,
    prior: Option<&Value>,
    folded: &[MemoryObject],
    entry_cap: usize,
) -> Value {
    // Seed the running aggregates from any prior summary body so counts are
    // cumulative across every fold this namespace has ever undergone.
    let mut folded_count = prior
        .and_then(|p| p.get("folded_count"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut by_kind = histogram_from_prior(prior, "by_kind");
    let mut by_status = histogram_from_prior(prior, "by_status");

    // Newest-folded-first entry stubs. New entries lead; prior stubs follow;
    // the whole list truncates to `entry_cap` so older stubs age out (their
    // contribution survives exactly in the histograms).
    let mut entries: Vec<Value> = Vec::new();
    // Fold newest-first so the retained window keeps the most recent context.
    let mut newest_first = folded.to_vec();
    newest_first.sort_by(|a, b| {
        b.updated_at_ms
            .cmp(&a.updated_at_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    for object in &newest_first {
        *by_kind.entry(object.kind.label().to_string()).or_insert(0) += 1;
        *by_status
            .entry(object.status.label().to_string())
            .or_insert(0) += 1;
        entries.push(entry_stub(object));
    }
    folded_count += folded.len() as u64;

    if let Some(prior_entries) = prior
        .and_then(|p| p.get("entries"))
        .and_then(Value::as_array)
    {
        entries.extend(prior_entries.iter().cloned());
    }
    entries.truncate(entry_cap);

    json!({
        "kata_compaction": true,
        "scope": scope.canonical_key(),
        "folded_count": folded_count,
        "by_kind": histogram_to_value(&by_kind),
        "by_status": histogram_to_value(&by_status),
        "entries": entries,
    })
}

/// A compact, self-describing record of one folded object retained in the
/// summary so a reader can still resolve the older entry.
fn entry_stub(object: &MemoryObject) -> Value {
    json!({
        "id": object.id,
        "kind": object.kind.label(),
        "status": object.status.label(),
        "title": object.title,
        "updated_at_ms": object.updated_at_ms,
    })
}

fn histogram_from_prior(prior: Option<&Value>, key: &str) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    if let Some(obj) = prior.and_then(|p| p.get(key)).and_then(Value::as_object) {
        for (k, v) in obj {
            if let Some(n) = v.as_u64() {
                map.insert(k.clone(), n);
            }
        }
    }
    map
}

fn histogram_to_value(map: &BTreeMap<String, u64>) -> Value {
    let mut obj = serde_json::Map::new();
    for (k, v) in map {
        obj.insert(k.clone(), json!(v));
    }
    Value::Object(obj)
}

/// The deterministic summary object id for a namespace. Stable across passes so
/// successive folds update the SAME summary object (via revision CAS) rather than
/// spawning a new one each time. Uses the scope's collision-free canonical key.
#[must_use]
pub fn summary_object_id(scope: &MemoryScope) -> String {
    format!("kata-summary::{}", scope.canonical_key())
}
