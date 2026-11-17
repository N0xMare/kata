//! The execution's `/work` heads, branch-aware — ADR-0001's "map by content, never by path"
//! applied to the INPUT side.
//!
//! # What this plane adds
//!
//! The walk producer [`crate::work_tree::walk_work_tree`] runs ONCE per
//! non-isolated execution, at admission, inside
//! [`crate::work_tree::publish_scratch_tree_head`]. This table records the
//! stronger fact an `oci` execution is built on: **`/work` is a durable head,
//! not a scratch directory.** The execution head (`branch = ''`) is recorded
//! once at admission — the committed base tree for a worktree-isolated
//! execution, the seeded scratch-workspace walk for a non-isolated one — and a
//! `parallel()`
//! branch gets its OWN head, forked off its parent's, the first time a stage
//! inside it is dispatched. The capsule submit path reads the head row at the
//! stage's coordinate instead of walking a scratch directory per attempt, so
//! what a stage sees at `/work` is the content the execution's head chain has
//! already admitted — and an uncommitted edit in a scratch directory is
//! structurally not an input.
//!
//! # One row per coordinate, write-once, converge-or-refuse
//!
//! `(execution_id, branch)` is the PRIMARY KEY: an execution has at most one
//! `/work` head per coordinate, by construction.
//! [`OperationalDb::record_work_tree_head`] (the admission verb, `branch = ''`)
//! is IDEMPOTENT-OR-REFUSING rather than blind-insert:
//!
//! * **identical re-record converges.** Re-admission after a crash — the
//!   `after_base_tree_published_before_head_recorded` window left the artifact
//!   durable and this row absent, or a recovery re-presentation that reaches
//!   the writer again — re-states the same `(base_commit,
//!   work_tree_artifact_id)` pair and gets the stored row back. Retried
//!   admission is a property of the protocol, not an error.
//! * **a divergent re-record is refused** (`WORK_TREE_HEAD_DIVERGENT`). A row
//!   naming a different artifact, or a different base commit, would be a
//!   second body of input under one execution — exactly the ambiguity
//!   `occurrences.work_tree_artifact_id`'s divergent-redeclaration refusal
//!   already owns at attempt granularity, here at the execution's whole
//!   `/work`. No arm of this verb ever overwrites.
//!
//! [`OperationalDb::ensure_work_tree_head`] is the FORK verb: a branch
//! coordinate's row is created on demand — off the recorded fork base of an
//! already-forked sibling (every branch of one barrier forks at ONE point, so
//! the join's deltas share one base), else off the parent head's current
//! artifact. Either way `fork_base_artifact_id` freezes the fork point: the
//! join computes `between(fork_base, head)` per branch no matter how far the
//! parent advanced meanwhile.
//!
//! # What the row carries, and deliberately does not
//!
//! `work_tree_artifact_id` names the declared `kind='tree'` artifact — the
//! manifest — and the join to `artifacts` supplies the `object_id`,
//! `size_bytes` and `privacy` a capsule's `/work` mapping is built from. The
//! row does NOT copy those: a second encoding of the artifact's identity on a
//! second table could disagree with the row the artifact registry already
//! authoritatively answers.
//!
//! `base_commit`/`candidate_commit_id` are the backend's own spellings of the
//! commits a jj workspace sits over — PROVENANCE, never an input the mapping
//! is computed from, and `''` where no jj workspace exists (the scratch-seeded
//! head, every branch head: a branch has no checkout, its applies are
//! CAS-only). `candidate_commit_id` is additionally the apply's
//! `work_apply_candidate_diverged` fence where a workspace does exist.
//! `committed_commit_id` is the commit the latest `commit` workspace effect
//! finalized (`''` until one resolves) — what `promote` and `forge_export`
//! deliver while the candidate is the empty `@` that commit left on top of it.
//!
//! `execution_id` REFERENCES `programs` ON DELETE CASCADE: the head is a fact
//! ABOUT the execution and dies with it — an execution-scoped prune takes the
//! workspace, the occurrences and these rows in one statement.
//! `work_tree_artifact_id` and `fork_base_artifact_id` REFERENCE `artifacts`
//! ON DELETE NO ACTION: a head still naming an artifact that row got deleted
//! under would be the two-facts-one-crash shape this schema exists to refuse;
//! nothing in this plane deletes artifact rows today, so the action is the
//! statement.

use kata_types::error::{KataError, KataResult};
use kata_types::work_tree_head::WorkTreeHeadCoordinate;
use rusqlite::{OptionalExtension, Transaction, params};
use ulid::Ulid;

use super::{OperationalDb, now_ms, ulid_from_bytes};

/// The refusal token for re-recording an execution's `/work` head with a
/// different artifact or a different base commit.
pub const WORK_TREE_HEAD_DIVERGENT: &str = "work_tree_head_divergent";

/// The refusal token for a capsule submit or fan-in that names a head
/// coordinate the execution never recorded — admission owes the execution
/// head and there is no scratch walk to substitute.
pub const WORK_TREE_HEAD_UNRECORDED: &str = "work_tree_head_unrecorded";

/// One `execution_work_tree_heads` row, decoded — the recorded `/work` head of
/// one coordinate of one execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionWorkTreeHead {
    /// The execution the head is recorded for.
    pub execution_id: Ulid,
    /// The coordinate's spelling — `''` for the execution's own head, the JSON
    /// fork stack for a `parallel()` branch head.
    pub branch: String,
    /// The base commit the workspace was created over, in the backend's own
    /// spelling (jj's commit hex) — `''` where no jj workspace exists (a
    /// scratch-seeded or branch head). The divergent check compares it, an
    /// operator reads it, and the `{{ workspace.changed_files }}` prompt read
    /// diffs the recorded head FROM it; the capsule's `/work` is computed from
    /// the ARTIFACT, never from this string.
    pub base_commit: String,
    /// The declared `kind='tree'` artifact the head's `/work` maps.
    pub work_tree_artifact_id: [u8; 32],
    /// The workspace's candidate commit at this head — what the apply's
    /// candidate fence (`work_apply_candidate_diverged`) re-reads before it
    /// rewrites `@`. `''` for a head with no jj checkout behind it — a
    /// scratch-seeded head and every branch head, whose applies are CAS-only.
    pub candidate_commit_id: String,
    /// The commit the execution's latest `commit` workspace effect finalized —
    /// `''` until one resolves. The commit's resolve moves it together with
    /// `candidate_commit_id` (which becomes the empty `@` on top of it), so
    /// `promote` and `forge_export` deliver THIS commit while the candidate is
    /// still its empty child, instead of the empty, undescribed `@`.
    pub committed_commit_id: String,
    /// How many applies this head row has accepted — the ordinal the recovery
    /// sweep and a second-branch apply reason over (`work_delta_base_stale`).
    pub head_seq: i64,
    /// The barrier stage a branch head answers to — `''` on the execution
    /// head.
    pub join_stage: String,
    /// The coordinate this row was forked from — `''` on the execution head
    /// and on a branch of a root-level barrier (whose parent IS the root).
    pub forked_from: String,
    /// The parent head's artifact at the fork — frozen so the join's fan-in
    /// computes every branch delta against ONE base. `NULL` on the execution
    /// head.
    pub fork_base_artifact_id: Option<[u8; 32]>,
    /// When the row committed.
    pub recorded_at_ms: i64,
}

/// The `/work` head one accepted apply ADVANCES the row to: the result manifest
/// the delta produces, the candidate commit the jj transaction left on `@`
/// (the row's own where no jj ran), and the next `head_seq`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkTreeHeadAdvance {
    /// The head's new `/work` artifact — the manifest `delta.apply(base)` built,
    /// already declared in `artifacts`.
    pub work_tree_artifact_id: [u8; 32],
    /// The candidate commit the apply's jj transaction committed — the row's
    /// own `candidate_commit_id` unchanged when no jj effect ran (a
    /// scratch-seeded or branch head).
    pub candidate_commit_id: String,
    /// The head the caller read when it decided — the advance compares it under
    /// the write lock and refuses a row that moved since (`seq` or artifact).
    pub expected_head_seq: i64,
    /// The artifact the caller's base check ran against.
    pub expected_artifact_id: [u8; 32],
}

/// What one resolved `commit` workspace effect moves on the execution head:
/// the candidate it was claimed against (the compare-and-swap's premise), the
/// empty `@` the commit left (the new candidate), and the finalized commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadCommitAdvance<'a> {
    /// The recorded candidate the commit fenced on — the row must still name it.
    pub expected_candidate: &'a str,
    /// The empty working-copy commit `jj commit` left on top of the finalized one.
    pub new_candidate: &'a str,
    /// The commit the effect finalized — what `promote` and `forge_export`
    /// deliver while the candidate is its empty child.
    pub committed_commit: &'a str,
}

/// The one column list every head read uses, so a column added to the table
/// cannot reach one reader and miss another.
const HEAD_COLUMNS: &str = "SELECT execution_id, branch, base_commit, work_tree_artifact_id, \
                            candidate_commit_id, committed_commit_id, head_seq, join_stage, \
                            forked_from, fork_base_artifact_id, recorded_at_ms \
                            FROM execution_work_tree_heads";

impl OperationalDb {
    /// The execution's recorded `/work` head at `coordinate` — `''` reads the
    /// execution's own head — or `None` when no row exists at that coordinate.
    /// For the execution head that means admission never recorded one — the
    /// crash window before the row was written; for a branch it means no stage
    /// of the branch has been dispatched yet.
    ///
    /// # The capsule path's caller
    ///
    /// `kata_workflow`'s capsule submit reads this at the stage's own
    /// coordinate and refuses to assemble a `/work` for an execution it names
    /// nothing for; it does not fall back to walking.
    pub fn work_tree_head_at(
        &self,
        execution_id: Ulid,
        branch: &str,
    ) -> KataResult<Option<ExecutionWorkTreeHead>> {
        self.with_read(|conn| {
            conn.query_row(
                &format!("{HEAD_COLUMNS} WHERE execution_id = ?1 AND branch = ?2"),
                params![execution_id.to_bytes().as_slice(), branch],
                decode_head,
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read work-tree head: {error}")))?
            .transpose()
        })
    }

    /// The execution's OWN recorded `/work` head — the `branch = ''` row.
    ///
    /// # Errors
    ///
    /// A plane read fault.
    pub fn execution_work_tree_head(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Option<ExecutionWorkTreeHead>> {
        self.work_tree_head_at(execution_id, "")
    }

    /// RECORD the execution's `/work` head — idempotent on an identical
    /// restatement, refusing a divergent one.
    ///
    /// # Refused set
    ///
    /// [`WORK_TREE_HEAD_DIVERGENT`]: the stored row's `base_commit` or
    /// `work_tree_artifact_id` differs from the one this call records. The
    /// comparison and the insert are one writer transaction, so the
    /// converge-or-refuse is exact under the single writer rather than a
    /// read-then-write a racing second admission could split. A FOREIGN KEY
    /// violation — an execution with no `programs` row, or an artifact id no
    /// `artifacts` row carries — surfaces as `Storage`, and both are the
    /// caller's construction error, not a head-plane refusal:
    /// `publish_base_tree_head` records the head only over an artifact it just
    /// declared for this execution.
    ///
    /// `recorded_at_ms` is NOT compared: it is this plane's clock reading of
    /// when the row committed, not part of the head's identity — the same
    /// exclusion `declare_artifact` documents for `created_at_ms`.
    pub fn record_work_tree_head(
        &self,
        execution_id: Ulid,
        base_commit: &str,
        work_tree_artifact_id: [u8; 32],
        candidate_commit_id: &str,
    ) -> KataResult<ExecutionWorkTreeHead> {
        self.in_writer_txn(|tx| {
            if let Some(stored) = read_head_in_tx_pub(tx, execution_id, "")? {
                if stored.base_commit == base_commit
                    && stored.work_tree_artifact_id == work_tree_artifact_id
                    && stored.candidate_commit_id == candidate_commit_id
                {
                    return Ok(stored);
                }
                return Err(KataError::Validation(format!(
                    "{WORK_TREE_HEAD_DIVERGENT}: execution {execution_id} already records /work \
                     head {} over base commit {}, and this admission derived {} over {}. The head \
                     is the base tree published for ONE admission; a second one disagreeing is a \
                     second input under one execution — refused rather than adopted",
                    hex::encode(stored.work_tree_artifact_id),
                    stored.base_commit,
                    hex::encode(work_tree_artifact_id),
                    base_commit,
                )));
            }
            let head = ExecutionWorkTreeHead {
                execution_id,
                branch: String::new(),
                base_commit: base_commit.to_owned(),
                work_tree_artifact_id,
                candidate_commit_id: candidate_commit_id.to_owned(),
                committed_commit_id: String::new(),
                head_seq: 0,
                join_stage: String::new(),
                forked_from: String::new(),
                fork_base_artifact_id: None,
                recorded_at_ms: now_ms(),
            };
            insert_head_in_tx(tx, &head)?;
            Ok(head)
        })
    }

    /// The `/work` head at `coordinate`, forking it off its parent if no row
    /// exists yet — the branch-head verb a capsule submit (and, recursively, a
    /// nested join's own precondition) reaches.
    ///
    /// A branch row is created exactly once, inside this one writer
    /// transaction, so two first-submits of the same branch converge rather
    /// than race. Its `fork_base_artifact_id` — the artifact every delta this
    /// branch later produces is computed against at its barrier's fan-in —
    /// comes from the FIRST sibling row already recorded under the same
    /// `(forked_from, join_stage)` pair: one barrier forks at ONE point, and a
    /// later sibling cannot pin its own. With no sibling, the fork base is the
    /// parent head's artifact read under the same lock.
    ///
    /// # Errors
    ///
    /// [`WORK_TREE_HEAD_UNRECORDED`] when the root coordinate is absent (an
    /// `oci` execution's admission owes it; nothing seeds it here) — read as
    /// the recursion's base case, so an unseeded execution is refused rather
    /// than forked; `Storage` on plane faults and on the parent chain being
    /// absent partway down, which is the same corruption one level up.
    pub fn ensure_work_tree_head(
        &self,
        execution_id: Ulid,
        coordinate: &WorkTreeHeadCoordinate,
    ) -> KataResult<ExecutionWorkTreeHead> {
        self.in_writer_txn(|tx| ensure_head_in_tx(tx, execution_id, coordinate))
    }
}

/// [`OperationalDb::ensure_work_tree_head`] inside a caller's transaction —
/// the join's fan-in precondition forks the rows it reads under the same lock
/// it merges on.
pub(crate) fn ensure_head_in_tx(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    coordinate: &WorkTreeHeadCoordinate,
) -> KataResult<ExecutionWorkTreeHead> {
    let spelling = coordinate.spelling();
    if let Some(head) = read_head_in_tx_pub(tx, execution_id, &spelling)? {
        return Ok(head);
    }
    if coordinate.is_root() {
        return Err(KataError::Validation(format!(
            "{WORK_TREE_HEAD_UNRECORDED}: execution {execution_id} records no /work head — \
             admission owes the execution head (the committed base tree for an isolated run, the \
             seeded scratch walk for a non-isolated one), and there is no scratch walk to \
             substitute here"
        )));
    }
    let fork = coordinate.innermost().expect("non-root");
    let parent = coordinate.parent().expect("non-root");
    let parent_head = ensure_head_in_tx(tx, execution_id, &parent)?;
    // ONE fork point per barrier: a sibling already forked under this
    // (parent coordinate, barrier) pair pinned the base every branch's delta
    // is computed against — take it over the parent's CURRENT artifact, which
    // may have advanced since.
    let sibling_base: Option<Vec<u8>> = tx
        .query_row(
            "SELECT fork_base_artifact_id FROM execution_work_tree_heads
              WHERE execution_id = ?1 AND forked_from = ?2 AND join_stage = ?3
                AND fork_base_artifact_id IS NOT NULL
              ORDER BY recorded_at_ms, branch LIMIT 1",
            params![
                execution_id.to_bytes().as_slice(),
                parent.spelling(),
                fork.join.as_str(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read fork siblings: {error}")))?;
    let fork_base: [u8; 32] = match sibling_base {
        Some(bytes) => bytes.as_slice().try_into().map_err(|_| {
            KataError::Storage(format!(
                "operational.db fork_base_artifact_id column must be 32 bytes, got {}",
                bytes.len()
            ))
        })?,
        None => parent_head.work_tree_artifact_id,
    };
    let head = ExecutionWorkTreeHead {
        execution_id,
        branch: spelling,
        base_commit: String::new(),
        work_tree_artifact_id: fork_base,
        candidate_commit_id: String::new(),
        committed_commit_id: String::new(),
        head_seq: 0,
        join_stage: fork.join.clone(),
        forked_from: parent.spelling(),
        fork_base_artifact_id: Some(fork_base),
        recorded_at_ms: now_ms(),
    };
    insert_head_in_tx(tx, &head)?;
    Ok(head)
}

pub(crate) fn read_head_in_tx_pub(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    branch: &str,
) -> KataResult<Option<ExecutionWorkTreeHead>> {
    tx.query_row(
        &format!("{HEAD_COLUMNS} WHERE execution_id = ?1 AND branch = ?2"),
        params![execution_id.to_bytes().as_slice(), branch],
        decode_head,
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read work-tree head: {error}")))?
    .transpose()
}

fn insert_head_in_tx(tx: &Transaction<'_>, head: &ExecutionWorkTreeHead) -> KataResult<()> {
    tx.execute(
        "INSERT INTO execution_work_tree_heads \
         (execution_id, branch, base_commit, work_tree_artifact_id, candidate_commit_id, \
          committed_commit_id, head_seq, join_stage, forked_from, fork_base_artifact_id, \
          recorded_at_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            head.execution_id.to_bytes().as_slice(),
            head.branch.as_str(),
            head.base_commit.as_str(),
            head.work_tree_artifact_id.as_slice(),
            head.candidate_commit_id.as_str(),
            head.committed_commit_id.as_str(),
            head.head_seq,
            head.join_stage.as_str(),
            head.forked_from.as_str(),
            head.fork_base_artifact_id.map(|id| id.to_vec()),
            head.recorded_at_ms,
        ],
    )
    .map_err(|error| {
        KataError::Storage(format!(
            "insert work-tree head for {} at {:?}: {error}",
            head.execution_id, head.branch,
        ))
    })?;
    Ok(())
}

impl OperationalDb {
    /// ADVANCE the execution's `/work` head at `branch` to the tree one
    /// accepted apply produced — inside the caller's writer transaction, so
    /// the head and the WorkApply resolution are one commit.
    ///
    /// The compare-and-swap carries BOTH halves the apply keyed on: the row
    /// must still read `expected_head_seq`/`expected_artifact_id`, else a
    /// second apply for a later accepted occurrence won the advance and this
    /// one is the stale-base shape — `work_delta_base_stale` by another name,
    /// refused rather than overwritten.
    ///
    /// # Errors
    ///
    /// `Validation` (`work_delta_base_stale`) when the row moved; `Storage`
    /// for a missing row or a write fault.
    pub(crate) fn advance_work_tree_head_in_tx(
        tx: &Transaction<'_>,
        execution_id: Ulid,
        branch: &str,
        advance: &WorkTreeHeadAdvance,
    ) -> KataResult<()> {
        let changed = tx
            .execute(
                "UPDATE execution_work_tree_heads \
                 SET work_tree_artifact_id = ?3, candidate_commit_id = ?4, head_seq = head_seq + 1 \
                 WHERE execution_id = ?1 AND branch = ?2 \
                   AND head_seq = ?5 AND work_tree_artifact_id = ?6",
                params![
                    execution_id.to_bytes().as_slice(),
                    branch,
                    advance.work_tree_artifact_id.as_slice(),
                    advance.candidate_commit_id.as_str(),
                    advance.expected_head_seq,
                    advance.expected_artifact_id.as_slice(),
                ],
            )
            .map_err(|error| {
                KataError::Storage(format!(
                    "advance work-tree head for {execution_id}: {error}"
                ))
            })?;
        if changed != 1 {
            return Err(KataError::Validation(format!(
                "work_delta_base_stale: the recorded /work head for execution {execution_id} at \
                 {branch:?} is no longer seq {} over artifact {} — a later apply won, and this \
                 delta's base is spent",
                advance.expected_head_seq,
                hex::encode(advance.expected_artifact_id),
            )));
        }
        Ok(())
    }

    /// The `commit` workspace-effect's head advance: the tree
    /// is UNCHANGED — `jj commit` left an empty `@` on top of the finalized
    /// candidate, so `head_seq` and the artifact stay; `candidate_commit_id`
    /// moves to that `@` and `committed_commit_id` to the finalized commit,
    /// together, compare-and-swapped against the candidate the effect was
    /// claimed against. `false` means the row moved — the caller fails the
    /// attempt rather than resolve over a head it did not see.
    pub(crate) fn advance_head_past_commit_in_tx(
        tx: &Transaction<'_>,
        execution_id: Ulid,
        advance: &HeadCommitAdvance<'_>,
    ) -> KataResult<bool> {
        let changed = tx
            .execute(
                "UPDATE execution_work_tree_heads \
                 SET candidate_commit_id = ?3, committed_commit_id = ?4 \
                 WHERE execution_id = ?1 AND branch = '' AND candidate_commit_id = ?2",
                params![
                    execution_id.to_bytes().as_slice(),
                    advance.expected_candidate,
                    advance.new_candidate,
                    advance.committed_commit,
                ],
            )
            .map_err(|error| {
                KataError::Storage(format!(
                    "update work-tree head candidate for {execution_id}: {error}"
                ))
            })?;
        Ok(changed == 1)
    }
}

fn decode_head(row: &rusqlite::Row<'_>) -> rusqlite::Result<KataResult<ExecutionWorkTreeHead>> {
    let execution: Vec<u8> = row.get(0)?;
    let branch: String = row.get(1)?;
    let base_commit: String = row.get(2)?;
    let artifact: Vec<u8> = row.get(3)?;
    let candidate_commit_id: String = row.get(4)?;
    let committed_commit_id: String = row.get(5)?;
    let head_seq: i64 = row.get(6)?;
    let join_stage: String = row.get(7)?;
    let forked_from: String = row.get(8)?;
    let fork_base: Option<Vec<u8>> = row.get(9)?;
    let recorded_at_ms: i64 = row.get(10)?;
    Ok((|| {
        let artifact_id: [u8; 32] = artifact.as_slice().try_into().map_err(|_| {
            KataError::Storage(format!(
                "operational.db work_tree_artifact_id column must be 32 bytes, got {}",
                artifact.len()
            ))
        })?;
        let fork_base_artifact_id = fork_base
            .map(|bytes| {
                <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                    KataError::Storage(format!(
                        "operational.db fork_base_artifact_id column must be 32 bytes, got {}",
                        bytes.len()
                    ))
                })
            })
            .transpose()?;
        Ok(ExecutionWorkTreeHead {
            execution_id: ulid_from_bytes(&execution)?,
            branch,
            base_commit,
            work_tree_artifact_id: artifact_id,
            candidate_commit_id,
            committed_commit_id,
            head_seq,
            join_stage,
            forked_from,
            fork_base_artifact_id,
            recorded_at_ms,
        })
    })())
}
