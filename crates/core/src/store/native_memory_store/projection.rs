//! Standalone projection / serialization helpers for the native memory store.
//!
//! These are the free functions that back the store's read projection and its
//! durable (de)serialization: the in-RAM query scan, the SQLite mirror row I/O,
//! the event-log fold, the deterministic search-term normalization, and the
//! JSON + integer conversion helpers. They carry no store state — the concrete
//! [`super::store::SqliteNativeMemoryStore`] drives them — so they live apart
//! from the store impl (concern split; behavior-preserving).

use std::collections::HashSet;
use std::fmt::Write as _;
use std::sync::Arc;

use dashmap::DashMap;
use kata_types::memory::{
    MEMORY_SCHEMA_VERSION, MemoryConflict, MemoryObject, MemoryObjectKind, MemoryObjectStatus,
    MemoryProposal,
};
use kata_types::{KataError, KataResult};
use rusqlite::{Connection, OptionalExtension, params};
use ulid::Ulid;

use super::store::MemoryObjectQuery;

/// Insert one object row into the `memory_objects` mirror. Shared by the apply
/// path and the event-replay rebuild so the column set (incl. `scope`) has one
/// source of truth.
pub(super) fn insert_object_row(
    tx: &rusqlite::Transaction<'_>,
    object: &MemoryObject,
) -> KataResult<()> {
    let object_json = serialize_json(object, "memory object")?;
    tx.execute(
        "INSERT INTO memory_objects
            (object_id, kind, status, revision, object_json, created_at_ms, updated_at_ms, scope)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            object.id.as_str(),
            object.kind.label(),
            object.status.label(),
            u64_to_i64(object.revision, "object revision")?,
            object_json.as_slice(),
            u64_to_i64(object.created_at_ms, "object created_at_ms")?,
            u64_to_i64(object.updated_at_ms, "object updated_at_ms")?,
            object.scope.canonical_key(),
        ],
    )
    .map_err(|e| KataError::Storage(format!("native_memory_store insert object: {e}")))?;
    Ok(())
}

/// Load every object from the SQLite mirror into a fresh read projection. Run
/// at `open` (cold start) — the mirror is the durable materialization the
/// projection is seeded from.
pub(super) fn seed_projection(conn: &Connection) -> KataResult<DashMap<String, Arc<MemoryObject>>> {
    let projection = DashMap::new();
    let mut stmt = conn
        .prepare("SELECT object_json FROM memory_objects")
        .map_err(|e| KataError::Storage(format!("native_memory_store seed prepare: {e}")))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|e| KataError::Storage(format!("native_memory_store seed query: {e}")))?;
    for row in rows {
        let bytes =
            row.map_err(|e| KataError::Storage(format!("native_memory_store seed row: {e}")))?;
        let object: MemoryObject = deserialize_json(&bytes, "memory object")?;
        projection.insert(object.id.clone(), Arc::new(object));
    }
    Ok(projection)
}

/// Fold the append-only `memory_events` log into each object's current state.
/// Every `created`/`updated` event carries the FULL object at its revision, so
/// the latest event (by `sequence`) per `object_id` is the current value. This
/// is the reconstruct primitive behind [`super::store::SqliteNativeMemoryStore::rebuild_objects_from_events`].
#[cfg(any(test, feature = "test-support"))]
pub(super) fn fold_events_to_objects(
    conn: &Connection,
) -> KataResult<std::collections::BTreeMap<String, MemoryObject>> {
    let mut stmt = conn
        .prepare(
            "SELECT event_json FROM memory_events
             WHERE event_kind IN ('created', 'updated')
             ORDER BY sequence ASC",
        )
        .map_err(|e| KataError::Storage(format!("native_memory_store fold prepare: {e}")))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|e| KataError::Storage(format!("native_memory_store fold query: {e}")))?;
    let mut current = std::collections::BTreeMap::new();
    for row in rows {
        let bytes =
            row.map_err(|e| KataError::Storage(format!("native_memory_store fold row: {e}")))?;
        let object: MemoryObject = deserialize_json(&bytes, "memory event object")?;
        // Sequence-ascending: a later event for the same id overwrites — last
        // write wins, which is the object's current revision.
        current.insert(object.id.clone(), object);
    }
    Ok(current)
}

/// In-RAM query over the read projection: the linear scan that mirrors the
/// SQL reader's semantics exactly — kind/status/scope-window membership, the
/// shared `memory_object_matches_query` text matcher, `updated_at_ms DESC,
/// object_id ASC` ordering, and the same limit interaction. Equivalence to the
/// SQL path is pinned by `projection_query_matches_sql_reference`.
pub(super) fn query_projection(
    objects: &DashMap<String, Arc<MemoryObject>>,
    query: &MemoryObjectQuery,
) -> Vec<MemoryObject> {
    let has_text_query = query
        .query
        .as_deref()
        .is_some_and(|text| !text.trim().is_empty());
    let query_terms = query
        .query
        .as_deref()
        .map(normalized_memory_search_terms)
        .unwrap_or_default();
    // A non-empty text query that normalizes to zero terms matches nothing —
    // mirrors the SQL reader's early return.
    if has_text_query && query_terms.is_empty() {
        return Vec::new();
    }
    let kinds: HashSet<MemoryObjectKind> = query.kinds.iter().copied().collect();
    let statuses: HashSet<MemoryObjectStatus> = query.statuses.iter().copied().collect();
    let scope_keys: Option<HashSet<String>> = query.scope_window.as_ref().map(|window| {
        window
            .iter()
            .map(kata_types::memory::MemoryScope::canonical_key)
            .collect()
    });

    let mut matched: Vec<MemoryObject> = objects
        .iter()
        .filter(|entry| {
            let object = entry.as_ref();
            if !kinds.is_empty() && !kinds.contains(&object.kind) {
                return false;
            }
            if !statuses.is_empty() && !statuses.contains(&object.status) {
                return false;
            }
            if let Some(scope_keys) = scope_keys.as_ref()
                && !scope_keys.contains(&object.scope.canonical_key())
            {
                return false;
            }
            if !query_terms.is_empty() && !memory_object_matches_query(object, &query_terms) {
                return false;
            }
            true
        })
        .map(|entry| entry.as_ref().clone())
        .collect();

    // ORDER BY updated_at_ms DESC, object_id ASC.
    matched.sort_by(|a, b| {
        b.updated_at_ms
            .cmp(&a.updated_at_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    if let Some(limit) = query.limit {
        matched.truncate(limit as usize);
    }
    matched
}

/// Read one object's current durable state from the SQLite mirror. Used by the
/// apply path's revision-CAS, which MUST read the committed durable state inside
/// its write transaction (the projection updates only after commit, so it can be
/// momentarily behind an in-flight write).
pub(super) fn select_object(conn: &Connection, id: &str) -> KataResult<Option<MemoryObject>> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT object_json FROM memory_objects WHERE object_id = ?1",
            params![id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| KataError::Storage(format!("native_memory_store select object: {e}")))?;
    bytes
        .map(|bytes| deserialize_json(&bytes, "memory object"))
        .transpose()
}

#[cfg(test)]
pub(super) fn select_objects_with_query(
    conn: &Connection,
    query: &MemoryObjectQuery,
) -> KataResult<Vec<MemoryObject>> {
    let has_text_query = query
        .query
        .as_deref()
        .is_some_and(|query| !query.trim().is_empty());
    let query_terms = query
        .query
        .as_deref()
        .map(normalized_memory_search_terms)
        .unwrap_or_default();
    if has_text_query && query_terms.is_empty() {
        return Ok(Vec::new());
    }
    let mut sql = "SELECT object_json FROM memory_objects".to_string();
    let mut clauses = Vec::new();
    let mut values = Vec::new();
    if !query.kinds.is_empty() {
        let placeholders = std::iter::repeat_n("?", query.kinds.len())
            .collect::<Vec<_>>()
            .join(", ");
        clauses.push(format!("kind IN ({placeholders})"));
        values.extend(query.kinds.iter().map(|kind| kind.label().to_string()));
    }
    if !query.statuses.is_empty() {
        let placeholders = std::iter::repeat_n("?", query.statuses.len())
            .collect::<Vec<_>>()
            .join(", ");
        clauses.push(format!("status IN ({placeholders})"));
        values.extend(
            query
                .statuses
                .iter()
                .map(|status| status.label().to_string()),
        );
    }
    // Scope visibility window. `None` = no predicate = flat behavior (every scope
    // visible). `Some(window)` restricts rows to scopes in
    // the reader's `ancestors_inclusive()` set via `scope IN (...)`, binding each
    // scope's collision-free `canonical_key()`. An empty window admits no rows.
    if let Some(window) = query.scope_window.as_ref() {
        if window.is_empty() {
            clauses.push("1 = 0".to_string());
        } else {
            let placeholders = std::iter::repeat_n("?", window.len())
                .collect::<Vec<_>>()
                .join(", ");
            clauses.push(format!("scope IN ({placeholders})"));
            values.extend(
                window
                    .iter()
                    .map(kata_types::memory::MemoryScope::canonical_key),
            );
        }
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY updated_at_ms DESC, object_id ASC");
    if query_terms.is_empty()
        && let Some(limit) = query.limit
    {
        write!(&mut sql, " LIMIT {limit}").expect("writing to String cannot fail");
    }

    let mut stmt = conn.prepare(&sql).map_err(|e| {
        KataError::Storage(format!("native_memory_store prepare select objects: {e}"))
    })?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(values.iter()), |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .map_err(|e| KataError::Storage(format!("native_memory_store query objects: {e}")))?;
    let mut objects = Vec::new();
    for row in rows {
        let bytes =
            row.map_err(|e| KataError::Storage(format!("native_memory_store object row: {e}")))?;
        let object = deserialize_json(&bytes, "memory object row")?;
        if !query_terms.is_empty() && !memory_object_matches_query(&object, &query_terms) {
            continue;
        }
        objects.push(object);
        if !query_terms.is_empty()
            && let Some(limit) = query.limit
            && objects.len() >= limit as usize
        {
            break;
        }
    }
    Ok(objects)
}

pub(super) fn memory_object_matches_query(object: &MemoryObject, query_terms: &[String]) -> bool {
    let mut haystack = String::new();
    write!(
        &mut haystack,
        "{} {} {}",
        object.id,
        object.kind.label(),
        object.status.label()
    )
    .expect("writing to String cannot fail");
    if let Some(title) = object.title.as_deref() {
        write!(&mut haystack, " {title}").expect("writing to String cannot fail");
    }
    for tag in &object.tags {
        write!(&mut haystack, " {tag}").expect("writing to String cannot fail");
    }
    write!(&mut haystack, " {}", object.body).expect("writing to String cannot fail");
    if let Some(source_id) = object.provenance.source_id.as_deref() {
        write!(&mut haystack, " {source_id}").expect("writing to String cannot fail");
    }
    if let Some(execution_id) = object.provenance.execution_id.as_deref() {
        write!(&mut haystack, " {execution_id}").expect("writing to String cannot fail");
    }
    if let Some(agent_id) = object.provenance.agent_id.as_deref() {
        write!(&mut haystack, " {agent_id}").expect("writing to String cannot fail");
    }
    if let Some(path) = object.provenance.path.as_deref() {
        write!(&mut haystack, " {path}").expect("writing to String cannot fail");
    }

    let indexed_terms = normalized_memory_search_terms(&haystack)
        .into_iter()
        .collect::<HashSet<_>>();
    query_terms
        .iter()
        .all(|term| indexed_terms.contains(term.as_str()))
}

pub(super) fn normalized_memory_search_terms(value: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut seen = HashSet::new();
    for raw in value.split(|ch: char| !ch.is_alphanumeric()) {
        let Some(term) = normalized_memory_search_term(raw) else {
            continue;
        };
        if seen.insert(term.clone()) {
            terms.push(term);
        }
    }
    terms
}

fn normalized_memory_search_term(raw: &str) -> Option<String> {
    let mut value = raw.trim().to_lowercase();
    if value.is_empty() || is_memory_search_stopword(&value) {
        return None;
    }
    if value.len() > 3 {
        if let Some(prefix) = value.strip_suffix("ies") {
            value = format!("{prefix}y");
        } else if let Some(prefix) = value.strip_suffix('s') {
            value = prefix.to_string();
        }
    }
    if value.is_empty() || is_memory_search_stopword(&value) {
        None
    } else {
        Some(value)
    }
}

fn is_memory_search_stopword(value: &str) -> bool {
    matches!(
        value,
        "a" | "an"
            | "and"
            | "are"
            | "as"
            | "at"
            | "by"
            | "for"
            | "from"
            | "in"
            | "into"
            | "latest"
            | "of"
            | "on"
            | "or"
            | "recent"
            | "the"
            | "to"
            | "with"
    )
}

pub(super) fn revision_head(conn: &Connection) -> KataResult<u64> {
    conn.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM memory_events",
        [],
        |row| row.get::<_, i64>(0),
    )
    .map_err(|e| KataError::Storage(format!("native_memory_store select revision head: {e}")))
    .and_then(|value| i64_to_u64(value, "memory event sequence"))
}

pub(super) fn conflict_for_revision_mismatch(
    object_id: String,
    expected_revision: Option<u64>,
    actual_revision: Option<u64>,
    proposal: MemoryProposal,
    now_ms: u64,
) -> MemoryConflict {
    MemoryConflict {
        schema_version: MEMORY_SCHEMA_VERSION,
        conflict_id: Ulid::new().to_string(),
        object_id,
        expected_revision,
        actual_revision,
        reason: "revision_mismatch".to_string(),
        proposal,
        recorded_at_ms: now_ms,
    }
}

pub(super) fn persist_conflict(
    tx: &rusqlite::Transaction<'_>,
    proposal_id: &str,
    conflict: &MemoryConflict,
    proposal_json: &[u8],
    now_ms: u64,
) -> KataResult<()> {
    persist_proposal(
        tx,
        proposal_id,
        conflict.object_id.as_str(),
        conflict.expected_revision,
        "conflict",
        proposal_json,
        now_ms,
    )?;
    let conflict_json = serialize_json(conflict, "memory conflict")?;
    tx.execute(
        "INSERT INTO memory_conflicts
            (conflict_id, proposal_id, object_id, expected_revision, actual_revision,
             conflict_json, created_at_ms, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open')",
        params![
            conflict.conflict_id.as_str(),
            proposal_id,
            conflict.object_id.as_str(),
            conflict
                .expected_revision
                .map(|revision| u64_to_i64(revision, "expected revision"))
                .transpose()?,
            conflict
                .actual_revision
                .map(|revision| u64_to_i64(revision, "actual revision"))
                .transpose()?,
            conflict_json.as_slice(),
            u64_to_i64(now_ms, "conflict created_at_ms")?,
        ],
    )
    .map_err(|e| KataError::Storage(format!("native_memory_store insert conflict: {e}")))?;
    persist_event(
        tx,
        conflict.object_id.as_str(),
        conflict.actual_revision,
        proposal_id,
        "conflict",
        conflict,
        now_ms,
    )
}

pub(super) fn persist_proposal(
    tx: &rusqlite::Transaction<'_>,
    proposal_id: &str,
    object_id: &str,
    expected_revision: Option<u64>,
    status: &str,
    proposal_json: &[u8],
    now_ms: u64,
) -> KataResult<()> {
    tx.execute(
        "INSERT INTO memory_proposals
            (proposal_id, target_object_id, expected_revision, status, proposal_json,
             submitted_at_ms, decided_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            proposal_id,
            object_id,
            expected_revision
                .map(|revision| u64_to_i64(revision, "expected revision"))
                .transpose()?,
            status,
            proposal_json,
            u64_to_i64(now_ms, "proposal submitted_at_ms")?,
            u64_to_i64(now_ms, "proposal decided_at_ms")?,
        ],
    )
    .map_err(|e| KataError::Storage(format!("native_memory_store insert proposal: {e}")))?;
    Ok(())
}

pub(super) fn persist_event<T: serde::Serialize>(
    tx: &rusqlite::Transaction<'_>,
    object_id: &str,
    revision: Option<u64>,
    proposal_id: &str,
    event_kind: &str,
    event: &T,
    now_ms: u64,
) -> KataResult<()> {
    let event_json = serialize_json(event, "memory event")?;
    tx.execute(
        "INSERT INTO memory_events
            (object_id, revision, proposal_id, event_kind, event_json, recorded_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            object_id,
            revision
                .map(|revision| u64_to_i64(revision, "event revision"))
                .transpose()?,
            proposal_id,
            event_kind,
            event_json,
            u64_to_i64(now_ms, "event recorded_at_ms")?,
        ],
    )
    .map_err(|e| KataError::Storage(format!("native_memory_store insert event: {e}")))?;
    Ok(())
}

pub(super) fn serialize_json<T: serde::Serialize>(value: &T, label: &str) -> KataResult<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|e| KataError::Serialization(format!("serialize {label}: {e}")))
}

pub(super) fn deserialize_json<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    label: &str,
) -> KataResult<T> {
    serde_json::from_slice(bytes)
        .map_err(|e| KataError::Serialization(format!("deserialize {label}: {e}")))
}

pub(super) fn u64_to_i64(value: u64, label: &str) -> KataResult<i64> {
    i64::try_from(value)
        .map_err(|_| KataError::Validation(format!("{label} exceeds SQLite i64 range: {value}")))
}

fn i64_to_u64(value: i64, label: &str) -> KataResult<u64> {
    u64::try_from(value)
        .map_err(|_| KataError::Storage(format!("{label} was negative in SQLite: {value}")))
}
