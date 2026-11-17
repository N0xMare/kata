//! Minimal SQLite-backed workflow state.
//!
//! Scope today: the co-located CAS (`cas.db` + `cas/` blob tree) this store
//! owns, and the capsule-reuse HINT table (`capsule_reuse_v1`) — a rebuildable
//! index naming which accepted occurrence last produced a capsule reuse key.
//! The hint is never authority: the operational plane re-verifies every hit
//! under its writer lock (`OperationalDb::reuse_accepted_capsule_result`), so a
//! lost or stale row costs one container run and nothing else.
//!
//! SQLite is synchronous; `rusqlite::Connection` is not `Send` without
//! Mutex, so every method that touches the connection does so behind a
//! `parking_lot::Mutex`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kata_types::config::ModelReuseMaxAge;
use kata_types::execution_contract::{CapsuleReuseKey, OccurrenceId};
use kata_types::execution_platform::ExecutorTerm;
use kata_types::primitives::ContentHash;
use kata_types::{KataError, KataResult};
use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::store::cas::CasStore;
use crate::store::sqlite_backed::refuse_orphan_sidecars_for_missing_main;

/// Handle to the workflow SQLite database — `<data_dir>/stage_cache.db`,
/// opened by `BootRig::open_stage_cache`. Capsule reuse is occurrence-driven
/// through `operational.db`, so the only SQL this file carries is the hint
/// table below.
pub struct SqliteWorkflowStore {
    conn: Mutex<Connection>,
    path: PathBuf,
    cas: Arc<CasStore>,
    model_reuse_max_age: ModelReuseMaxAge,
    executor_term: Option<ExecutorTerm>,
}

impl std::fmt::Debug for SqliteWorkflowStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteWorkflowStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SqliteWorkflowStore {
    /// Open (or create) the SQLite database at `path`. Enables WAL mode for
    /// concurrent-reader safety and sets a few conservative pragmas.
    pub fn open(path: impl AsRef<Path>) -> KataResult<Self> {
        let path = path.as_ref().to_path_buf();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let cas_path = parent.join("cas.db");
        let cas_tree = parent.join("cas");
        refuse_orphan_sidecars_for_missing_main(&path, "stage_cache.db")?;
        refuse_orphan_sidecars_for_missing_main(&cas_path, "cas.db")?;
        let authority_present = [cas_path.exists(), cas_tree.is_dir()];
        let has_all_authority = authority_present.into_iter().all(std::convert::identity);
        let has_any_authority = authority_present.into_iter().any(std::convert::identity);
        if (path.exists() && !has_all_authority)
            || (!path.exists() && has_any_authority && !has_all_authority)
        {
            return Err(KataError::SchemaMigrationRequired(
                "stage-cache store set is missing required authority (cas.db, cas/)".to_string(),
            ));
        }
        let existing_cas = if has_all_authority {
            CasStore::refuse_noncurrent_file_schema(&cas_path)?;
            Some(CasStore::open(&cas_path, &cas_tree)?)
        } else {
            None
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KataError::Storage(format!(
                    "sqlite create_dir_all({}) failed: {e}",
                    parent.display()
                ))
            })?;
        }
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| KataError::Storage(format!("sqlite open({}) failed: {e}", path.display())))?;

        // WAL mode is the only safe default for concurrent readers. We keep
        // synchronous=NORMAL to match rusqlite's WAL best practice.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| {
                KataError::Storage(format!("sqlite PRAGMA journal_mode=WAL failed: {e}"))
            })?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| KataError::Storage(format!("sqlite PRAGMA synchronous failed: {e}")))?;

        // `capsule_reuse_v1` is the whole of this file:
        // a HINT naming which accepted occurrence last produced a capsule reuse
        // key, never authority. The operational plane re-verifies every hit
        // under its writer lock
        // (`OperationalDb::reuse_accepted_capsule_result`), so a lost, stale or
        // deleted row is only a miss. It holds no object id and retains nothing.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS capsule_reuse_v1 (
                reuse_key            BLOB    NOT NULL PRIMARY KEY,
                source_occurrence_id BLOB    NOT NULL,
                recorded_at_ms       INTEGER NOT NULL,
                CHECK (length(reuse_key) = 32),
                CHECK (length(source_occurrence_id) = 32)
            );",
        )
        .map_err(|e| KataError::Storage(format!("sqlite create table failed: {e}")))?;

        // Co-locate the content-addressed value store: `cas.db` + `cas/`
        // blob tree derive from this db's parent dir, so boot needs no new
        // wiring.
        let cas = match existing_cas {
            Some(cas) => cas,
            None => CasStore::open(parent.join("cas.db"), parent.join("cas"))?,
        };

        Ok(Self {
            conn: Mutex::new(conn),
            path,
            cas: Arc::new(cas),
            model_reuse_max_age: ModelReuseMaxAge::Default,
            executor_term: None,
        })
    }

    /// Install the node's memoised-spend bound
    /// (`[runtime] model_reuse_max_age_secs`). Boot installs it once; a store opened
    /// without it carries the 7-day default.
    ///
    /// The store only CARRIES the bound, so every runner handed this store applies the
    /// node's value: the age it bounds is the SOURCE occurrence's acceptance, which
    /// lives in `operational.db`, and `WorkflowRunner::consult_capsule_reuse` reads it
    /// there for a `model_reuse` stage before adopting.
    #[must_use]
    pub fn with_model_reuse_max_age(mut self, bound: ModelReuseMaxAge) -> Self {
        self.model_reuse_max_age = bound;
        self
    }

    /// The node's memoised-spend bound — see [`Self::with_model_reuse_max_age`].
    #[must_use]
    pub fn model_reuse_max_age(&self) -> ModelReuseMaxAge {
        self.model_reuse_max_age
    }

    /// Install the node's EXECUTOR TERM (`kata_worker::executor_term`) — the
    /// term every capsule reuse key consulted through this store folds. Boot installs
    /// it once.
    ///
    /// A store opened without one (a backup, a lock probe, a test that never asks)
    /// serves and records NO capsule reuse hint: an executor kata cannot name is the
    /// undeterminable fact the cache refuses over, and a substitute term
    /// would key two different fences alike.
    #[must_use]
    pub fn with_executor_term(mut self, term: ExecutorTerm) -> Self {
        self.executor_term = Some(term);
        self
    }

    /// The node's executor term — see [`Self::with_executor_term`].
    #[must_use]
    pub fn executor_term(&self) -> Option<&ExecutorTerm> {
        self.executor_term.as_ref()
    }

    /// Share the node's existing CAS with the authoritative output writer.
    #[must_use]
    pub fn shared_cas(&self) -> Arc<CasStore> {
        Arc::clone(&self.cas)
    }

    /// Force a full WAL checkpoint so the main database file is
    /// crash-consistent and self-contained — after this returns, all
    /// committed frames have been folded back into `stage_cache.db` and the
    /// `-wal` sidecar is truncated to zero length.
    ///
    /// Callers run this before a backup is taken so the copied `.db` is a
    /// complete point-in-time snapshot even if the process is then killed.
    /// (`backup_data_dir` does not depend on it: `VACUUM INTO` is consistent
    /// against a concurrent writer regardless.) Uses `TRUNCATE` (not `PASSIVE`) so the
    /// checkpoint is total rather than best-effort; the store owns the
    /// only connection, so it never blocks on a competing reader.
    ///
    /// # Errors
    ///
    /// Returns `KataError::Storage` if the checkpoint pragma fails.
    pub fn checkpoint(&self) -> KataResult<()> {
        // Flush the CAS (objects) plane BEFORE the workflow (references) plane.
        // The durability invariant is "object durable before its reference", so
        // a crash between the two fsyncs must leave objects AHEAD of references
        // (an orphan is GC-able; a reference ahead of its object is a dangling
        // ref). Checkpointing references first would invert that order.
        self.cas.checkpoint()?;
        {
            let conn = self.conn.lock();
            // `PRAGMA wal_checkpoint(TRUNCATE)` returns one row —
            // `(busy, log_frames, checkpointed_frames)`. We read the first
            // column to force statement execution; a non-WAL database yields
            // `(0, -1, -1)`, which is still a successful no-op flush.
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|e| {
                KataError::Storage(format!("sqlite wal_checkpoint(TRUNCATE) failed: {e}"))
            })?;
        }
        Ok(())
    }

    /// The occurrence the CAPSULE REUSE HINT names for `key` — the accepted occurrence
    /// that last produced a capsule with this reuse key on this node — or `None`.
    ///
    /// A HINT, not authority: the caller hands it to
    /// `OperationalDb::reuse_accepted_capsule_result`, which re-verifies the source
    /// under the operational writer lock and answers a miss for anything it cannot
    /// adopt. So an absent, stale or deleted row costs one container run and nothing
    /// else.
    ///
    /// # Errors
    ///
    /// A SQLite read failure, or a stored occurrence id that is not 32 bytes (the table
    /// CHECK forbids it).
    pub fn capsule_reuse_hint(&self, key: &CapsuleReuseKey) -> KataResult<Option<OccurrenceId>> {
        let stored: Option<Vec<u8>> = self
            .conn
            .lock()
            .query_row(
                "SELECT source_occurrence_id FROM capsule_reuse_v1 WHERE reuse_key = ?1",
                params![key.0.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| KataError::Storage(format!("sqlite select capsule_reuse_v1: {e}")))?;
        stored
            .map(|bytes| {
                <[u8; 32]>::try_from(bytes.as_slice())
                    .map(|id| OccurrenceId(ContentHash::new(id)))
                    .map_err(|_| {
                        KataError::Storage(format!(
                            "capsule_reuse_v1 holds a {}-byte source occurrence id",
                            bytes.len()
                        ))
                    })
            })
            .transpose()
    }

    /// RECORD (or re-point) the hint for `key` at `source` — an occurrence whose capsule
    /// with this reuse key was just ACCEPTED. The latest acceptance wins: a later source
    /// is at least as likely to still be retained as an earlier one.
    ///
    /// `recorded_at_ms` is WHEN THE HINT FIRST NAMED ITS CURRENT SOURCE: re-recording
    /// the source it already names leaves the row untouched, and only a re-point at a
    /// different source stamps it again. Nothing bounds reuse by this column — the
    /// memoised-spend bound reads the source occurrence's own acceptance — but a stamp
    /// that moved on every re-record would tell any reader the hint is younger than
    /// its source — a sliding window, which the bound forbids.
    ///
    /// # Errors
    ///
    /// A SQLite write failure.
    pub fn record_capsule_reuse_hint(
        &self,
        key: &CapsuleReuseKey,
        source: OccurrenceId,
    ) -> KataResult<()> {
        self.conn
            .lock()
            .execute(
                "INSERT INTO capsule_reuse_v1 (reuse_key, source_occurrence_id, recorded_at_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(reuse_key) DO UPDATE
                    SET source_occurrence_id = excluded.source_occurrence_id,
                        recorded_at_ms = excluded.recorded_at_ms
                  WHERE source_occurrence_id IS NOT excluded.source_occurrence_id",
                params![
                    key.0.as_bytes(),
                    source.0.as_bytes(),
                    crate::operational::now_ms()
                ],
            )
            .map_err(|e| KataError::Storage(format!("sqlite upsert capsule_reuse_v1: {e}")))?;
        Ok(())
    }

    /// FORGET the hint for `key` if — and only if — it still names `source`: the one the
    /// caller found stale. A hint another submit re-pointed in between names a different
    /// source and is kept.
    ///
    /// # Errors
    ///
    /// A SQLite write failure.
    pub fn forget_capsule_reuse_hint(
        &self,
        key: &CapsuleReuseKey,
        source: OccurrenceId,
    ) -> KataResult<()> {
        self.conn
            .lock()
            .execute(
                "DELETE FROM capsule_reuse_v1 WHERE reuse_key = ?1 AND source_occurrence_id = ?2",
                params![key.0.as_bytes(), source.0.as_bytes()],
            )
            .map_err(|e| KataError::Storage(format!("sqlite delete capsule_reuse_v1: {e}")))?;
        Ok(())
    }

    /// The co-located content-addressed store this workflow store reads and
    /// writes.
    ///
    /// A production accessor, not a test seam: the operational plane's
    /// authoritative CAS roots point INTO this store, so the dangling-root
    /// verifier (`operational::cas_liveness`) needs a handle to it, and boot must
    /// be able to obtain one without opening `cas.db` a second time.
    #[must_use]
    pub fn cas(&self) -> &CasStore {
        &self.cas
    }
}
