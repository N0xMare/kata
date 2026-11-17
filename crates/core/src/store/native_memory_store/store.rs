//! The concrete SQLite-backed native memory store and its public types.
//!
//! This module owns the store struct, the query value type, and the impl block
//! carrying the
//! persist/load/query methods. The standalone projection + serialization
//! helpers it drives live in [`super::projection`] (concern split;
//! behavior-preserving).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;
use kata_types::memory::{
    MEMORY_SCHEMA_VERSION, MemoryObject, MemoryObjectKind, MemoryObjectStatus, MemoryProposal,
    MemoryProposalResponse, MemoryProvenance, MemoryScope, MemorySnapshot, MemorySourceKind,
};
use kata_types::time::now_ms;
use kata_types::{KataError, KataResult};
use parking_lot::Mutex;
use rusqlite::{Connection, params};
use ulid::Ulid;

#[cfg(any(test, feature = "test-support"))]
use crate::store::sqlite_backed::open_sqlite_in_memory;
use crate::store::sqlite_backed::{
    apply_wal_pragmas, open_existing_for_schema_validation, open_sqlite,
    refuse_orphan_sidecars_for_missing_main, sqlite_affinity,
};

use super::compaction::{
    COMPACTION_SUMMARY_TAG, MemoryCompactionOutcome, MemoryCompactionPolicy, fold_summary_body,
    summary_object_id,
};
#[cfg(any(test, feature = "test-support"))]
use super::projection::fold_events_to_objects;
use super::projection::{
    conflict_for_revision_mismatch, deserialize_json, insert_object_row, persist_conflict,
    persist_event, persist_proposal, query_projection, revision_head, seed_projection,
    select_object, serialize_json, u64_to_i64,
};

/// SQLite-backed native memory store with an in-RAM read projection.
///
/// The durability shape mirrors [`crate::ledger::InFlightLedger`]: the
/// append-only `memory_events` log is the durable source of truth (it carries
/// the full object at every revision, so [`SqliteNativeMemoryStore::rebuild_objects_from_events`]
/// can reconstruct everything), the `memory_objects` SQLite table is the
/// materialized cold-start mirror, and the in-RAM `objects` projection is the
/// authoritative READ hot-path — every successful write commits to SQLite first,
/// then becomes visible in the projection (persist-before-visible). The
/// projection is seeded from the mirror at `open`. v1 keeps the whole resident
/// set (writebacks are count-capped); scope-windowed residency + the named
/// scale paths (`papaya`, BTree index) are deferred behind this unchanged
/// interface.
/// Default write-threshold cadence for the compaction processor when the store
/// is opened without an explicit `[runtime]` override (e.g. tests). Boot passes
/// the operator's configured value via [`SqliteNativeMemoryStore::with_compaction`].
const DEFAULT_COMPACTION_WRITE_INTERVAL: usize = 256;

/// This store's label in every error message the shared sqlite helpers raise —
/// the open path, the pragma path, and the forward-version refusal.
const NATIVE_MEMORY_LABEL: &str = "native_memory_store";

pub struct SqliteNativeMemoryStore {
    pub(super) conn: Mutex<Connection>,
    /// Authoritative read projection: `object_id → current object`. Seeded from
    /// the SQLite mirror at open, updated after every committed write.
    objects: DashMap<String, Arc<MemoryObject>>,
    /// Per-namespace compaction bounds. Consulted by [`Self::compact`]
    /// and the write-threshold auto-trigger. Defaults to the generous
    /// [`MemoryCompactionPolicy::default`]; boot tightens it from `[runtime]`.
    compaction_policy: MemoryCompactionPolicy,
    /// Write-threshold cadence: run a compaction pass automatically after
    /// this many successful writes. `0` disables the automatic cadence.
    compaction_write_interval: usize,
    /// Successful writes since the last compaction pass (write-threshold cadence).
    writes_since_compaction: AtomicUsize,
    path: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryObjectQuery {
    /// Empty means all kinds.
    pub kinds: Vec<MemoryObjectKind>,
    /// Empty means all statuses.
    pub statuses: Vec<MemoryObjectStatus>,
    /// Optional deterministic text filter over id/title/tags/body/provenance.
    pub query: Option<String>,
    pub limit: Option<u32>,
    /// When `Some`, restrict results to objects whose scope is in this visibility
    /// window (the reader's `base_scope.ancestors_inclusive()`). `None` = no scope
    /// filter = flat behavior (every scope visible). Default `None`.
    pub scope_window: Option<Vec<kata_types::memory::MemoryScope>>,
}

impl std::fmt::Debug for SqliteNativeMemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteNativeMemoryStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SqliteNativeMemoryStore {
    /// Open (or create) `memory.db` at `path`.
    ///
    /// # Failure
    ///
    /// A database stamped ABOVE [`Self::SCHEMA_VERSION`] is refused with
    /// [`KataError::SchemaMigrationRequired`] by plain file I/O, before SQLite
    /// is opened at all — so an older binary cannot write into a newer
    /// release's knowledge plane.
    pub fn open(path: impl AsRef<Path>) -> KataResult<Self> {
        let path = path.as_ref().to_path_buf();
        refuse_orphan_sidecars_for_missing_main(&path, NATIVE_MEMORY_LABEL)?;
        // BEFORE `open_sqlite`, which applies `journal_mode=WAL` — a persistent
        // header write. A gate after it would have already mutated the newer
        // release's file it exists to refuse.
        let exists = path.exists();
        if exists {
            Self::refuse_noncurrent_file_schema(&path)?;
        }
        // Native memory objects/proposals/conflicts are an independent
        // knowledge authority, and terminal workflow writebacks must survive
        // any later FULL-synchronous execution-lifecycle commit.
        let conn = if exists {
            open_existing_for_schema_validation(&path, NATIVE_MEMORY_LABEL)?
        } else {
            open_sqlite(&path, NATIVE_MEMORY_LABEL)?
        };
        if exists {
            Self::refuse_noncurrent_schema_on_conn(&conn)?;
            Self::validate_current_schema(&conn)?;
            apply_wal_pragmas(&conn, NATIVE_MEMORY_LABEL)?;
        } else {
            Self::create_current_schema(&conn)?;
        }
        let objects = seed_projection(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            objects,
            compaction_policy: MemoryCompactionPolicy::default(),
            compaction_write_interval: DEFAULT_COMPACTION_WRITE_INTERVAL,
            writes_since_compaction: AtomicUsize::new(0),
            path: Some(path),
        })
    }

    /// Require an existing native-memory database at exactly the current disk
    /// schema without opening SQLite or creating sidecars.
    pub fn refuse_noncurrent_file_schema(path: impl AsRef<Path>) -> KataResult<()> {
        let observed = crate::store::sqlite_backed::stamped_user_version_from_files(
            path.as_ref(),
            NATIVE_MEMORY_LABEL,
        )?;
        if observed != Self::SCHEMA_VERSION {
            return Err(KataError::SchemaMigrationRequired(format!(
                "memory.db schema version {observed} is not the clean runtime version {}; use a new empty data directory and preserve this directory offline",
                Self::SCHEMA_VERSION
            )));
        }
        Ok(())
    }

    pub(super) fn refuse_noncurrent_schema_on_conn(conn: &Connection) -> KataResult<()> {
        let observed: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| KataError::Storage(format!("memory.db read user_version: {e}")))?;
        if observed != Self::SCHEMA_VERSION {
            return Err(KataError::SchemaMigrationRequired(format!(
                "memory.db schema version {observed} is not the clean runtime version {}",
                Self::SCHEMA_VERSION
            )));
        }
        Ok(())
    }

    fn validate_current_schema(conn: &Connection) -> KataResult<()> {
        for (table, expected) in [
            (
                "memory_objects",
                &[
                    ("object_id", "TEXT", 1_i64, 1_i64),
                    ("kind", "TEXT", 1, 0),
                    ("status", "TEXT", 1, 0),
                    ("revision", "INTEGER", 1, 0),
                    ("object_json", "BLOB", 1, 0),
                    ("created_at_ms", "INTEGER", 1, 0),
                    ("updated_at_ms", "INTEGER", 1, 0),
                    ("scope", "TEXT", 1, 0),
                ][..],
            ),
            (
                "memory_proposals",
                &[
                    ("proposal_id", "TEXT", 1_i64, 1_i64),
                    ("target_object_id", "TEXT", 1, 0),
                    ("expected_revision", "INTEGER", 0, 0),
                    ("status", "TEXT", 1, 0),
                    ("proposal_json", "BLOB", 1, 0),
                    ("submitted_at_ms", "INTEGER", 1, 0),
                    ("decided_at_ms", "INTEGER", 1, 0),
                ][..],
            ),
            (
                "memory_events",
                &[
                    ("sequence", "INTEGER", 0_i64, 1_i64),
                    ("object_id", "TEXT", 1, 0),
                    ("revision", "INTEGER", 0, 0),
                    ("proposal_id", "TEXT", 1, 0),
                    ("event_kind", "TEXT", 1, 0),
                    ("event_json", "BLOB", 1, 0),
                    ("recorded_at_ms", "INTEGER", 1, 0),
                ][..],
            ),
            (
                "memory_conflicts",
                &[
                    ("conflict_id", "TEXT", 1_i64, 1_i64),
                    ("proposal_id", "TEXT", 1, 0),
                    ("object_id", "TEXT", 1, 0),
                    ("expected_revision", "INTEGER", 0, 0),
                    ("actual_revision", "INTEGER", 0, 0),
                    ("conflict_json", "BLOB", 1, 0),
                    ("created_at_ms", "INTEGER", 1, 0),
                    ("status", "TEXT", 1, 0),
                ][..],
            ),
        ] {
            let mut statement = conn
                .prepare(&format!("PRAGMA table_info({table})"))
                .map_err(|e| KataError::Storage(format!("memory.db inspect {table}: {e}")))?;
            let observed = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(1)?,
                        sqlite_affinity(&row.get::<_, String>(2)?),
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .map_err(|e| KataError::Storage(format!("memory.db inspect {table} columns: {e}")))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| KataError::Storage(format!("memory.db read {table} columns: {e}")))?;
            let expected = expected
                .iter()
                .map(|(name, affinity, not_null, primary_key)| {
                    (name.to_string(), *affinity, *not_null, *primary_key)
                })
                .collect::<Vec<_>>();
            if observed != expected {
                return Err(KataError::SchemaMigrationRequired(format!(
                    "memory.db table {table} has column contract {observed:?}; expected {expected:?}"
                )));
            }
        }
        for index in [
            "idx_memory_objects_updated_at",
            "idx_memory_objects_kind_status",
            "idx_memory_objects_scope",
            "idx_memory_objects_kind_status_scope_updated",
            "idx_memory_events_recorded_at",
            "idx_memory_events_object_kind_seq",
        ] {
            let present: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1)",
                    [index],
                    |row| row.get(0),
                )
                .map_err(|e| KataError::Storage(format!("memory.db inspect index {index}: {e}")))?;
            if !present {
                return Err(KataError::SchemaMigrationRequired(format!(
                    "memory.db is missing required current index {index}"
                )));
            }
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn open_in_memory() -> KataResult<Self> {
        let conn = open_sqlite_in_memory(NATIVE_MEMORY_LABEL)?;
        Self::create_current_schema(&conn)?;
        let objects = seed_projection(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            objects,
            compaction_policy: MemoryCompactionPolicy::default(),
            compaction_write_interval: DEFAULT_COMPACTION_WRITE_INTERVAL,
            writes_since_compaction: AtomicUsize::new(0),
            path: None,
        })
    }

    /// Test/diagnostic seam for the connection's live SQLite durability level
    /// (`2` = FULL). `synchronous` is per connection and cannot be verified by
    /// opening the database through a second handle.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn debug_synchronous_level(&self) -> KataResult<i64> {
        let conn = self.conn.lock();
        crate::store::sqlite_backed::read_synchronous(&conn)
    }

    /// Configure the deterministic compaction processor.
    ///
    /// `max_live_per_namespace` is the per-namespace live-object bound (`0`
    /// DISABLES folding — unbounded growth); `write_interval` is the
    /// write-threshold cadence (`0` disables the automatic pass). Boot wires the
    /// operator's `[runtime]` knobs through here.
    #[must_use]
    pub fn with_compaction(mut self, max_live_per_namespace: usize, write_interval: usize) -> Self {
        self.compaction_policy = if max_live_per_namespace == 0 {
            MemoryCompactionPolicy::disabled()
        } else {
            MemoryCompactionPolicy {
                max_live_objects_per_namespace: Some(max_live_per_namespace),
                ..MemoryCompactionPolicy::default()
            }
        };
        self.compaction_write_interval = write_interval;
        self
    }

    fn create_current_schema(conn: &Connection) -> KataResult<()> {
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE memory_objects (
                object_id     TEXT    NOT NULL PRIMARY KEY,
                kind          TEXT    NOT NULL,
                status        TEXT    NOT NULL,
                revision      INTEGER NOT NULL,
                object_json   BLOB    NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                scope         TEXT    NOT NULL DEFAULT 'global'
            );
            CREATE TABLE memory_proposals (
                proposal_id       TEXT    NOT NULL PRIMARY KEY,
                target_object_id  TEXT    NOT NULL,
                expected_revision INTEGER,
                status            TEXT    NOT NULL,
                proposal_json     BLOB    NOT NULL,
                submitted_at_ms   INTEGER NOT NULL,
                decided_at_ms     INTEGER NOT NULL
            );
            CREATE TABLE memory_events (
                sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id      TEXT    NOT NULL,
                revision       INTEGER,
                proposal_id    TEXT    NOT NULL,
                event_kind     TEXT    NOT NULL,
                event_json     BLOB    NOT NULL,
                recorded_at_ms INTEGER NOT NULL
            );
            CREATE TABLE memory_conflicts (
                conflict_id       TEXT    NOT NULL PRIMARY KEY,
                proposal_id       TEXT    NOT NULL,
                object_id         TEXT    NOT NULL,
                expected_revision INTEGER,
                actual_revision   INTEGER,
                conflict_json     BLOB    NOT NULL,
                created_at_ms     INTEGER NOT NULL,
                status            TEXT    NOT NULL
            );
            CREATE INDEX idx_memory_objects_updated_at ON memory_objects(updated_at_ms);
            CREATE INDEX idx_memory_objects_kind_status ON memory_objects(kind, status);
            CREATE INDEX idx_memory_objects_scope ON memory_objects(scope);
            CREATE INDEX idx_memory_objects_kind_status_scope_updated
                ON memory_objects(kind, status, scope, updated_at_ms);
            CREATE INDEX idx_memory_events_recorded_at ON memory_events(recorded_at_ms);
            CREATE INDEX idx_memory_events_object_kind_seq
                ON memory_events(object_id, event_kind, sequence);
            PRAGMA user_version = 3;
            COMMIT;",
        )
        .map_err(|e| {
            KataError::Storage(format!(
                "native_memory_store create current schema failed: {e}"
            ))
        })
    }

    /// The `PRAGMA user_version` CEILING for `memory.db`: the highest on-disk
    /// stamp this binary understands, and the value a fresh open converges to.
    ///
    /// # Invariant
    ///
    /// Version 3 is the current shape, created directly by
    /// [`Self::create_current_schema`]; a database at any other stamp is refused
    /// with [`KataError::SchemaMigrationRequired`].
    ///
    /// # Not to be confused with
    ///
    /// [`kata_types::memory::MEMORY_SCHEMA_VERSION`] (= 1) is the wire/snapshot
    /// ENVELOPE version stamped on [`MemorySnapshot::schema_version`]. It
    /// appears NOWHERE in the `user_version` path and is a different number from
    /// this one.
    pub(super) const SCHEMA_VERSION: i64 = 3;

    /// The applied schema `PRAGMA user_version`. Exposed for operability and
    /// schema tests; a store this binary opens always reports
    /// `SCHEMA_VERSION`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn schema_user_version(&self) -> KataResult<u32> {
        let conn = self.conn.lock();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| {
                KataError::Storage(format!("native_memory_store read user_version: {e}"))
            })?;
        u32::try_from(version)
            .map_err(|_| KataError::Storage(format!("user_version out of range: {version}")))
    }

    pub fn snapshot(
        &self,
        kind: Option<MemoryObjectKind>,
        status: Option<MemoryObjectStatus>,
    ) -> KataResult<MemorySnapshot> {
        self.snapshot_query(MemoryObjectQuery {
            kinds: kind.into_iter().collect(),
            statuses: status.into_iter().collect(),
            query: None,
            limit: None,
            scope_window: None,
        })
    }

    pub fn apply_proposal(&self, proposal: MemoryProposal) -> KataResult<MemoryProposalResponse> {
        // Single-operator default: unrestricted writer (may write any scope,
        // including `Global`). Agent-originated writes go through
        // [`Self::apply_proposal_entitled`] with the execution's real scope.
        self.apply_proposal_with_entitlement(proposal, None)
    }

    /// Apply a proposal on behalf of a writer entitled only at `writer_scope`
    /// The effective target scope must be `writer_scope`
    /// itself or a DESCENDANT of it; a write that would land at a wider-visibility
    /// scope (canonically: a non-`Global` writer targeting `Global`, or any writer
    /// reaching outside its own subtree) is REJECTED with a validation error and
    /// nothing is persisted. Equivalent to: `writer_scope` must be an
    /// ancestor-or-self of the target scope.
    pub fn apply_proposal_entitled(
        &self,
        proposal: MemoryProposal,
        writer_scope: &kata_types::memory::MemoryScope,
    ) -> KataResult<MemoryProposalResponse> {
        self.apply_proposal_with_entitlement(proposal, Some(writer_scope))
    }

    fn apply_proposal_with_entitlement(
        &self,
        mut proposal: MemoryProposal,
        entitlement: Option<&kata_types::memory::MemoryScope>,
    ) -> KataResult<MemoryProposalResponse> {
        let proposal_id = proposal
            .proposal_id
            .as_ref()
            .map(|id| id.trim())
            .filter(|id| !id.is_empty())
            .map_or_else(|| Ulid::new().to_string(), ToOwned::to_owned);
        proposal.proposal_id = Some(proposal_id.clone());
        let object_id = proposal
            .object
            .id
            .as_ref()
            .map(|id| id.trim())
            .filter(|id| !id.is_empty())
            .map_or_else(|| Ulid::new().to_string(), ToOwned::to_owned);
        proposal.object.id = Some(object_id.clone());
        let now_ms = now_ms();
        let proposal_json = serialize_json(&proposal, "memory proposal")?;

        let mut conn = self.conn.lock();
        let tx = conn
            .transaction()
            .map_err(|e| KataError::Storage(format!("native_memory_store begin tx: {e}")))?;
        let existing = select_object(&tx, &object_id)?;

        if let Some(existing) = existing.as_ref() {
            if proposal.expected_revision != Some(existing.revision) {
                let conflict = conflict_for_revision_mismatch(
                    object_id,
                    proposal.expected_revision,
                    Some(existing.revision),
                    proposal,
                    now_ms,
                );
                persist_conflict(&tx, &proposal_id, &conflict, &proposal_json, now_ms)?;
                tx.commit().map_err(|e| {
                    KataError::Storage(format!("native_memory_store tx commit: {e}"))
                })?;
                return Ok(MemoryProposalResponse {
                    status: "conflict".to_string(),
                    object: None,
                    conflict: Some(conflict),
                });
            }
        } else if let Some(expected) = proposal.expected_revision
            && expected != 0
        {
            let conflict =
                conflict_for_revision_mismatch(object_id, Some(expected), None, proposal, now_ms);
            persist_conflict(&tx, &proposal_id, &conflict, &proposal_json, now_ms)?;
            tx.commit()
                .map_err(|e| KataError::Storage(format!("native_memory_store tx commit: {e}")))?;
            return Ok(MemoryProposalResponse {
                status: "conflict".to_string(),
                object: None,
                conflict: Some(conflict),
            });
        }

        let created_at_ms = existing
            .as_ref()
            .map_or(now_ms, |object| object.created_at_ms);
        let revision = existing.as_ref().map_or(1, |object| object.revision + 1);
        // Scope is fixed at creation: a plain proposal carries the draft's scope
        // for a NEW object, but for an existing one it is pinned to the stored
        // scope — a routine update can never silently relocate an object to a
        // wider-visibility scope (a write-up escalation). Intentional re-scoping
        // is a separately-gated operation. The `object_json` blob is the
        // authoritative scope on read; the `scope` column below mirrors it for
        // WHERE filtering.
        let scope = existing.as_ref().map_or_else(
            || proposal.object.scope.clone(),
            |object| object.scope.clone(),
        );
        // Entitlement gate: a scope-restricted writer may
        // only land a write at its own scope or a descendant. `writer_scope` must
        // be an ancestor-or-self of the effective target scope; canonically this
        // rejects a non-`Global` writer trying to write `Global`. The tx is still
        // open and untouched, so returning here rolls back — nothing persists.
        if let Some(writer_scope) = entitlement
            && !scope.ancestors_inclusive().contains(writer_scope)
        {
            return Err(KataError::Validation(format!(
                "memory write to scope {:?} rejected: writer entitled only at {:?} \
                 (a writer may only write its own scope or a descendant)",
                scope.canonical_key(),
                writer_scope.canonical_key(),
            )));
        }
        let object = MemoryObject {
            schema_version: MEMORY_SCHEMA_VERSION,
            id: object_id,
            kind: proposal.object.kind,
            status: proposal.object.status,
            scope,
            title: proposal.object.title.clone(),
            body: proposal.object.body.clone(),
            tags: proposal.object.tags.clone(),
            links: proposal.object.links.clone(),
            provenance: proposal.object.provenance.clone(),
            revision,
            created_at_ms,
            updated_at_ms: now_ms,
        };
        let object_json = serialize_json(&object, "memory object")?;
        if existing.is_some() {
            let updated = tx
                .execute(
                    "UPDATE memory_objects
                     SET kind = ?2,
                         status = ?3,
                         revision = ?4,
                         object_json = ?5,
                         updated_at_ms = ?6,
                         scope = ?8
                     WHERE object_id = ?1 AND revision = ?7",
                    params![
                        object.id.as_str(),
                        object.kind.label(),
                        object.status.label(),
                        u64_to_i64(object.revision, "object revision")?,
                        object_json.as_slice(),
                        u64_to_i64(object.updated_at_ms, "object updated_at_ms")?,
                        u64_to_i64(revision - 1, "previous object revision")?,
                        object.scope.canonical_key(),
                    ],
                )
                .map_err(|e| {
                    KataError::Storage(format!("native_memory_store update object: {e}"))
                })?;
            if updated != 1 {
                return Err(KataError::Storage(format!(
                    "native_memory_store CAS update affected {updated} rows"
                )));
            }
        } else {
            insert_object_row(&tx, &object)?;
        }
        persist_proposal(
            &tx,
            &proposal_id,
            object.id.as_str(),
            proposal.expected_revision,
            "applied",
            &proposal_json,
            now_ms,
        )?;
        persist_event(
            &tx,
            object.id.as_str(),
            Some(object.revision),
            &proposal_id,
            if revision == 1 { "created" } else { "updated" },
            &object,
            now_ms,
        )?;
        tx.commit()
            .map_err(|e| KataError::Storage(format!("native_memory_store tx commit: {e}")))?;
        // Release the connection mutex before the (self-locking) auto-compaction
        // check below — `compact` re-locks `conn` and the guard is non-reentrant.
        drop(conn);
        // Persist-before-visible: the durable mirror + event log committed above;
        // only now does the write become visible in the read projection.
        self.objects
            .insert(object.id.clone(), Arc::new(object.clone()));
        // Write-threshold cadence — fold a namespace past its bound.
        // Best-effort: never couples write success to compaction success.
        self.maybe_auto_compact();
        Ok(MemoryProposalResponse {
            status: "applied".to_string(),
            object: Some(object),
            conflict: None,
        })
    }

    /// Run a compaction pass if the write-threshold cadence has elapsed.
    ///
    /// Called after every successful write. Increments the write counter; when it
    /// reaches [`Self::compaction_write_interval`] the counter resets and
    /// [`Self::compact`] runs. A `0` interval or a folding-disabled policy makes
    /// this a no-op, so compaction stays fully off when the operator disables it.
    ///
    /// Best-effort: the write that triggered this pass has already committed and
    /// is visible (persist-before-visible). A compaction failure here is therefore
    /// logged and swallowed — it MUST NOT surface as a write failure and make the
    /// caller retry a persisted write (a spurious extra revision / phantom
    /// conflict). The over-bound namespace is simply retried on the next cadence
    /// tick. Infallible by contract.
    fn maybe_auto_compact(&self) {
        if self.compaction_write_interval == 0
            || self
                .compaction_policy
                .max_live_objects_per_namespace
                .is_none()
        {
            return;
        }
        let n = self.writes_since_compaction.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.compaction_write_interval {
            // Reset first so a concurrent writer starts a fresh window even if the
            // pass below does no folding.
            self.writes_since_compaction.store(0, Ordering::Relaxed);
            if let Err(err) = self.compact() {
                tracing::warn!(
                    error = %err,
                    "native memory: auto-compaction pass failed (write already \
                     durable + visible); retrying on the next cadence tick"
                );
            }
        }
    }

    /// Run a deterministic compaction pass with the store's configured policy.
    /// See [`Self::compact_with`].
    pub fn compact(&self) -> KataResult<MemoryCompactionOutcome> {
        let policy = self.compaction_policy;
        self.compact_with(&policy)
    }

    /// Deterministic per-namespace compaction pass.
    ///
    /// For each namespace (memory scope) whose live (non-terminal, non-summary)
    /// object count exceeds `policy.max_live_objects_per_namespace`, the OLDEST
    /// overflow objects are folded into that namespace's `Summary` object (created
    /// or updated via revision CAS) and then evicted along with their events. The
    /// summary body is the deterministic digest [`fold_summary_body`] builds — NO
    /// live-model spend. Runs in
    /// ONE transaction; the read projection is updated persist-before-visible
    /// after commit. `None` bound = disabled = no-op. Returns what was folded.
    pub fn compact_with(
        &self,
        policy: &MemoryCompactionPolicy,
    ) -> KataResult<MemoryCompactionOutcome> {
        let Some(max_live) = policy.max_live_objects_per_namespace else {
            return Ok(MemoryCompactionOutcome::default());
        };
        let now = now_ms();
        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(|e| {
            KataError::Storage(format!("native_memory_store compact begin tx: {e}"))
        })?;

        // Load every live (non-terminal), non-summary object, oldest-first. The
        // fold set for an over-bound namespace is its oldest overflow slice.
        let live: Vec<MemoryObject> = {
            let mut stmt = tx
                .prepare(
                    "SELECT object_json FROM memory_objects
                     WHERE status IN ('proposed', 'active', 'parked')
                       AND kind != 'summary'
                     ORDER BY updated_at_ms ASC, object_id ASC",
                )
                .map_err(|e| {
                    KataError::Storage(format!("native_memory_store compact prepare: {e}"))
                })?;
            let rows = stmt
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|e| {
                    KataError::Storage(format!("native_memory_store compact query: {e}"))
                })?;
            let mut out = Vec::new();
            for row in rows {
                let bytes = row.map_err(|e| {
                    KataError::Storage(format!("native_memory_store compact row: {e}"))
                })?;
                out.push(deserialize_json::<MemoryObject>(&bytes, "memory object")?);
            }
            out
        };

        // Group by namespace, preserving the oldest-first order within each.
        let mut by_scope: std::collections::BTreeMap<String, Vec<MemoryObject>> =
            std::collections::BTreeMap::new();
        for object in live {
            by_scope
                .entry(object.scope.canonical_key())
                .or_default()
                .push(object);
        }

        let mut outcome = MemoryCompactionOutcome::default();
        let mut evicted_ids: Vec<String> = Vec::new();
        let mut written_summaries: Vec<MemoryObject> = Vec::new();

        for (scope_key, objects) in by_scope {
            if objects.len() <= max_live {
                continue;
            }
            let overflow = objects.len() - max_live;
            let folded = &objects[..overflow];
            let scope = MemoryScope::parse_canonical_key(&scope_key).ok_or_else(|| {
                KataError::Storage(format!(
                    "native_memory_store compact: unparseable scope key {scope_key:?}"
                ))
            })?;

            let summary_id = summary_object_id(&scope);
            let prior = select_object(&tx, &summary_id)?;
            let prior_body = prior.as_ref().map(|object| &object.body);
            let body = fold_summary_body(&scope, prior_body, folded, policy.summary_entry_cap);
            let (revision, created_at_ms) = prior.as_ref().map_or((1, now), |object| {
                (object.revision + 1, object.created_at_ms)
            });
            let summary = MemoryObject {
                schema_version: MEMORY_SCHEMA_VERSION,
                id: summary_id.clone(),
                kind: MemoryObjectKind::Summary,
                status: MemoryObjectStatus::Active,
                scope: scope.clone(),
                title: Some(format!("Compaction summary — {scope_key}")),
                body,
                tags: vec![COMPACTION_SUMMARY_TAG.to_string()],
                links: Vec::new(),
                provenance: MemoryProvenance {
                    source_kind: MemorySourceKind::System,
                    source_id: None,
                    execution_id: None,
                    agent_id: None,
                    path: None,
                },
                revision,
                created_at_ms,
                updated_at_ms: now,
            };
            let proposal_id = format!("kata-compaction-{}", Ulid::new());
            if prior.is_some() {
                let object_json = serialize_json(&summary, "compaction summary")?;
                let updated = tx
                    .execute(
                        "UPDATE memory_objects
                         SET kind = ?2,
                             status = ?3,
                             revision = ?4,
                             object_json = ?5,
                             updated_at_ms = ?6,
                             scope = ?8
                         WHERE object_id = ?1 AND revision = ?7",
                        params![
                            summary.id.as_str(),
                            summary.kind.label(),
                            summary.status.label(),
                            u64_to_i64(summary.revision, "summary revision")?,
                            object_json.as_slice(),
                            u64_to_i64(summary.updated_at_ms, "summary updated_at_ms")?,
                            u64_to_i64(revision - 1, "previous summary revision")?,
                            summary.scope.canonical_key(),
                        ],
                    )
                    .map_err(|e| {
                        KataError::Storage(format!(
                            "native_memory_store compact update summary: {e}"
                        ))
                    })?;
                if updated != 1 {
                    return Err(KataError::Storage(format!(
                        "native_memory_store compact summary CAS affected {updated} rows"
                    )));
                }
            } else {
                insert_object_row(&tx, &summary)?;
            }
            persist_event(
                &tx,
                summary.id.as_str(),
                Some(summary.revision),
                &proposal_id,
                if revision == 1 { "created" } else { "updated" },
                &summary,
                now,
            )?;

            // Evict the folded objects and their events. Their content survives in
            // the summary; a later `rebuild_objects_from_events` cannot resurrect
            // them (all their events are gone).
            for object in folded {
                tx.execute(
                    "DELETE FROM memory_objects WHERE object_id = ?1",
                    params![object.id],
                )
                .map_err(|e| {
                    KataError::Storage(format!("native_memory_store compact evict object: {e}"))
                })?;
                tx.execute(
                    "DELETE FROM memory_events WHERE object_id = ?1",
                    params![object.id],
                )
                .map_err(|e| {
                    KataError::Storage(format!("native_memory_store compact evict events: {e}"))
                })?;
                evicted_ids.push(object.id.clone());
            }

            outcome.namespaces_compacted += 1;
            outcome.objects_folded += overflow;
            outcome.summaries_written += 1;
            written_summaries.push(summary);
        }

        tx.commit()
            .map_err(|e| KataError::Storage(format!("native_memory_store compact commit: {e}")))?;
        drop(conn);

        // Persist-before-visible: the mirror committed above; only now do the
        // evictions + summary upserts become visible in the read projection.
        for id in &evicted_ids {
            self.objects.remove(id);
        }
        for summary in written_summaries {
            self.objects.insert(summary.id.clone(), Arc::new(summary));
        }

        Ok(outcome)
    }

    /// Reconstruct the `memory_objects` mirror AND the read projection from the
    /// append-only `memory_events` log — the durable recovery path.
    ///
    /// Each `applied` event records the FULL object at its revision, so the
    /// current state of every object is its highest-sequence `created`/`updated`
    /// event. This folds the log (sequence-ordered, last write wins per id),
    /// rewrites the mirror table inside one transaction, and reseeds the
    /// projection. Use it to heal a corrupted/missing `memory_objects` snapshot
    /// without losing history. Returns the number of objects reconstructed.
    #[cfg(any(test, feature = "test-support"))]
    pub fn rebuild_objects_from_events(&self) -> KataResult<usize> {
        let conn = self.conn.lock();
        let reconstructed = fold_events_to_objects(&conn)?;
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| KataError::Storage(format!("native_memory_store rebuild tx: {e}")))?;
        tx.execute("DELETE FROM memory_objects", [])
            .map_err(|e| KataError::Storage(format!("native_memory_store rebuild clear: {e}")))?;
        for object in reconstructed.values() {
            insert_object_row(&tx, object)?;
        }
        tx.commit()
            .map_err(|e| KataError::Storage(format!("native_memory_store rebuild commit: {e}")))?;
        // Reseed the projection from the freshly rebuilt mirror.
        self.objects.clear();
        for (id, object) in reconstructed {
            self.objects.insert(id, Arc::new(object));
        }
        Ok(self.objects.len())
    }

    pub fn get(&self, id: &str) -> KataResult<Option<MemoryObject>> {
        // Point read from the authoritative projection — no SQLite round-trip.
        Ok(self.objects.get(id).map(|entry| entry.as_ref().clone()))
    }

    pub fn snapshot_query(&self, query: MemoryObjectQuery) -> KataResult<MemorySnapshot> {
        let objects = query_projection(&self.objects, &query);
        let revision_head = {
            let conn = self.conn.lock();
            revision_head(&conn)?
        };
        Ok(MemorySnapshot {
            schema_version: MEMORY_SCHEMA_VERSION,
            generated_at_ms: now_ms(),
            revision_head,
            object_count: objects.len(),
            objects,
        })
    }

    pub fn query_objects(&self, query: MemoryObjectQuery) -> KataResult<Vec<MemoryObject>> {
        Ok(query_projection(&self.objects, &query))
    }

    pub fn revision_head(&self) -> KataResult<u64> {
        let conn = self.conn.lock();
        revision_head(&conn)
    }
}
