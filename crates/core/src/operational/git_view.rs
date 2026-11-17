//! The execution's git-history VIEW — the
//! durable record of the artifact an agent capsule's `/work` repository is
//! materialized from.
//!
//! # What this plane adds
//!
//! [`crate::git_view::publish_execution_git_view`] runs ONCE per `oci`
//! execution whose program contains an agent stage, at admission: the
//! provider's `committed_base_git_history` packs every object reachable from
//! the committed base commit, the members and manifest are declared as a
//! `kind='tree'` artifact owned by the execution, and this table records the
//! row LAST, after the artifact is durable — the
//! `after_git_view_published_before_recorded` window. The capsule submit path
//! reads the row to build the `CapsuleGitView` an agent capsule's bundle
//! carries: `history_artifact_id` joins to `artifacts` for the `ArtifactRef`,
//! and `base_commit`/`branch_name`/`branch_commit`/`identity_*` are the metadata the worker's
//! scratch repository is configured with — recorded rather than re-resolved
//! so a recovered admission and a late dispatch see the identity admission
//! saw.
//!
//! One row per execution, write-once, converge-or-refuse — the same
//! discipline [`super::work_tree_head`] states for the `/work` head:
//! re-admission after the crash window re-states the identical row (the
//! producer walks the same base commit, CAS dedup gives the same artifact id)
//! and converges; a divergent re-record is `GIT_VIEW_DIVERGENT`, a second
//! body of history under one execution refused rather than adopted.
//!
//! `execution_id` REFERENCES `programs` ON DELETE CASCADE: the view is a fact
//! about the execution and dies with it. `history_artifact_id` REFERENCES
//! `artifacts` ON DELETE NO ACTION — a view still naming an artifact that row
//! got deleted under would be the two-facts-one-crash shape this schema
//! exists to refuse; nothing in this plane deletes artifact rows today, so
//! the action is the statement.

use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::GitViewRef;
use rusqlite::{OptionalExtension, Transaction, params};
use ulid::Ulid;

use super::{OperationalDb, now_ms, ulid_from_bytes};

/// The refusal token for re-recording an execution's git view with a
/// different artifact, base commit, branch ref or identity.
pub const GIT_VIEW_DIVERGENT: &str = "git_view_divergent";

/// One `execution_git_views` row, decoded — the recorded git-history view of
/// one execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionGitView {
    /// The execution the view is recorded for.
    pub execution_id: Ulid,
    /// The base commit the view is rooted at — the git object-id hex the
    /// workspace's committed base names, spelled as the scratch repository's
    /// `refs/heads/kata/<execution>` value.
    pub base_commit: String,
    /// The capsule's second scratch ref, off the execution's frozen target:
    /// trunk's name at the base, a pull request's base branch at its compare
    /// base, or none.
    pub branch: Option<GitViewRef>,
    /// `user.name` the scratch repository's config carries.
    pub identity_name: String,
    /// `user.email` the scratch repository's config carries.
    pub identity_email: String,
    /// The declared `kind='tree'` artifact — the manifest over
    /// `objects/pack/pack-*.{pack,idx}`, `index` and a possible `shallow`.
    pub history_artifact_id: [u8; 32],
    /// When the row committed.
    pub recorded_at_ms: i64,
}

/// The one column list every view read uses, so a column added to the table
/// cannot reach one reader and miss another.
const VIEW_COLUMNS: &str = "SELECT execution_id, base_commit, branch_name, branch_commit, \
                            identity_name, identity_email, history_artifact_id, recorded_at_ms \
                            FROM execution_git_views";

fn decode_view(row: &rusqlite::Row<'_>) -> rusqlite::Result<KataResult<ExecutionGitView>> {
    let execution_id: Vec<u8> = row.get(0)?;
    let base_commit: String = row.get(1)?;
    let branch_name: Option<String> = row.get(2)?;
    let branch_commit: Option<String> = row.get(3)?;
    let identity_name: String = row.get(4)?;
    let identity_email: String = row.get(5)?;
    let history_artifact_id: Vec<u8> = row.get(6)?;
    let recorded_at_ms: i64 = row.get(7)?;
    Ok((|| {
        let branch = match (branch_name, branch_commit) {
            (None, None) => None,
            (Some(name), Some(commit)) => Some(GitViewRef {
                name: name.into(),
                commit: commit.into(),
            }),
            _ => {
                return Err(KataError::Storage(
                    "operational.db execution_git_views carries half a branch ref".to_owned(),
                ));
            }
        };
        Ok(ExecutionGitView {
            execution_id: ulid_from_bytes(&execution_id)?,
            base_commit,
            branch,
            identity_name,
            identity_email,
            history_artifact_id: history_artifact_id.as_slice().try_into().map_err(|_| {
                KataError::Storage(format!(
                    "operational.db history_artifact_id column must be 32 bytes, got {}",
                    history_artifact_id.len()
                ))
            })?,
            recorded_at_ms,
        })
    })())
}

impl OperationalDb {
    /// The execution's recorded git-history view, or `None` when no row
    /// exists — the crash window before it was written, or an execution whose
    /// program carries no agent stage and so has no view to record.
    ///
    /// # The capsule path's caller
    ///
    /// `kata_workflow`'s capsule submit reads this when the stage it
    /// dispatches is an agent stage: the row supplies the `CapsuleGitView`
    /// the assembled capsule carries, and its absence for an agent stage is
    /// the admission record contradicting the stage set.
    ///
    /// # Errors
    ///
    /// A plane read fault, or a stored row that fails to decode.
    pub fn execution_git_view(&self, execution_id: Ulid) -> KataResult<Option<ExecutionGitView>> {
        self.with_read(|conn| {
            conn.query_row(
                &format!("{VIEW_COLUMNS} WHERE execution_id = ?1"),
                params![execution_id.to_bytes().as_slice()],
                decode_view,
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read git view: {error}")))?
            .transpose()
        })
    }

    /// RECORD the execution's git view — idempotent on an identical
    /// restatement, refusing a divergent one.
    ///
    /// # Refused set
    ///
    /// [`GIT_VIEW_DIVERGENT`]: the stored row's `base_commit`, branch ref,
    /// identity or `history_artifact_id` differs from the one this call
    /// records. The comparison and the insert are one writer transaction, so
    /// the converge-or-refuse is exact under the single writer. A FOREIGN KEY
    /// violation — an execution with no `programs` row, or an artifact id no
    /// `artifacts` row carries — surfaces as `Storage`, the caller's
    /// construction error: `publish_execution_git_view` records the view only
    /// over an artifact it just declared for this execution.
    ///
    /// `recorded_at_ms` is NOT compared: it is this plane's clock reading of
    /// when the row committed, not part of the view's identity — the same
    /// exclusion `declare_artifact` documents for `created_at_ms`.
    pub fn record_execution_git_view(
        &self,
        execution_id: Ulid,
        base_commit: &str,
        branch: Option<&GitViewRef>,
        identity_name: &str,
        identity_email: &str,
        history_artifact_id: [u8; 32],
    ) -> KataResult<ExecutionGitView> {
        self.in_writer_txn(|tx| {
            if let Some(stored) = read_view_in_tx(tx, execution_id)? {
                if stored.base_commit == base_commit
                    && stored.branch.as_ref() == branch
                    && stored.identity_name == identity_name
                    && stored.identity_email == identity_email
                    && stored.history_artifact_id == history_artifact_id
                {
                    return Ok(stored);
                }
                return Err(KataError::Validation(format!(
                    "{GIT_VIEW_DIVERGENT}: execution {execution_id} already records a git view \
                     over base commit {} on branch {:?} (history {}), and this admission derived \
                     base {} on {:?} (history {}). The view is the history published for ONE \
                     admission; a second one disagreeing is a second input under one execution \
                     — refused rather than adopted",
                    stored.base_commit,
                    stored.branch,
                    hex::encode(stored.history_artifact_id),
                    base_commit,
                    branch,
                    hex::encode(history_artifact_id),
                )));
            }
            let view = ExecutionGitView {
                execution_id,
                base_commit: base_commit.to_owned(),
                branch: branch.cloned(),
                identity_name: identity_name.to_owned(),
                identity_email: identity_email.to_owned(),
                history_artifact_id,
                recorded_at_ms: now_ms(),
            };
            insert_view_in_tx(tx, &view)?;
            Ok(view)
        })
    }
}

fn read_view_in_tx(
    tx: &Transaction<'_>,
    execution_id: Ulid,
) -> KataResult<Option<ExecutionGitView>> {
    tx.query_row(
        &format!("{VIEW_COLUMNS} WHERE execution_id = ?1"),
        params![execution_id.to_bytes().as_slice()],
        decode_view,
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read git view: {error}")))?
    .transpose()
}

fn insert_view_in_tx(tx: &Transaction<'_>, view: &ExecutionGitView) -> KataResult<()> {
    tx.execute(
        "INSERT INTO execution_git_views \
         (execution_id, base_commit, branch_name, branch_commit, identity_name, \
          identity_email, history_artifact_id, recorded_at_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            view.execution_id.to_bytes().as_slice(),
            view.base_commit.as_str(),
            view.branch.as_ref().map(|branch| branch.name.as_str()),
            view.branch.as_ref().map(|branch| branch.commit.as_str()),
            view.identity_name.as_str(),
            view.identity_email.as_str(),
            view.history_artifact_id.as_slice(),
            view.recorded_at_ms,
        ],
    )
    .map_err(|error| {
        KataError::Storage(format!(
            "insert git view for {}: {error}",
            view.execution_id,
        ))
    })?;
    Ok(())
}
