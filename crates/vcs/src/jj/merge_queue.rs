//! Serialized landing queue (MergeQueue) for jj candidate promotion.
//!
//! A fast-forward-ONLY promote would HARD-FAIL a second candidate whose base
//! had advanced (trunk moved since it forked), so concurrent LANDINGS would be
//! unsafe even though concurrent WORKSPACES are fine.
//!
//! This module makes concurrent landings safe with a serialized landing ladder
//! (one landing at a time per repo):
//!
//! 1. **fast-forward** onto trunk when trunk is still an ancestor of the
//!    candidate (a pointer-only move);
//! 2. **rebase** the candidate onto the advanced trunk head when the base moved
//!    — jj's rebase ALWAYS succeeds structurally (conflicts live IN the tree),
//!    so this step is crash-safe;
//! 3. if the rebased tree is **conflict-free**, land it (retry the ff);
//! 4. if the rebased tree carries **conflicts**, PARK the candidate under the
//!    existing `parked/<name>` mechanism with a typed reason naming what
//!    conflicted — NEVER silently overwrite trunk, NEVER hard-fail the whole
//!    execution.
//!
//! ## Serialization + crash-safety
//!
//! Landings are serialized by a per-repo lock (an in-process registry mutex for
//! deterministic same-process ordering, plus a cross-process `flock` released on
//! `Drop` or process death). The read-decide-write of the trunk bookmark is
//! atomic w.r.t. other landings, so a stale rebase can never regress trunk. Each
//! landing step is an individually-atomic jj transaction (`tx.commit()` is
//! all-or-nothing), so a crash mid-landing leaves trunk in jj either un-moved
//! (the candidate is intact — a re-run lands it) or moved to a single resolved
//! commit (landed). A re-run of the queue after a kill converges
//! deterministically.
//!
//! **The GIT half of a landing is not covered by that transaction, and it is
//! written FIRST.** [`JjBackend::export_bookmark_to_git`] rides the same
//! transaction, but jj-lib's `export_refs` moves `refs/heads/…` on disk inside
//! the call and only its bookkeeping rides `tx.commit` — so a crash between the
//! two leaves git AHEAD of jj (never behind). See that function's doc for the
//! measured consequences: a re-drive to the same commit converges, and a later
//! export of a different commit refuses fail-closed rather than clobbering.
//!
//! ## Revalidation fence (fail-closed floor)
//!
//! After a rebase the tree that WOULD land is not the tree the stage's validation
//! ran on, so validation is OWED before it can be trusted. Landing the
//! conflict-free rebased tree immediately would advance trunk to a tree
//! validation never approved. So the fence is FAIL-CLOSED: a rebased candidate is
//! NEVER landed. Its (conflict-free) rebased
//! tree is PARKED under the execution's needs-revalidation ref with trunk left
//! UNTOUCHED (see [`LandingOutcome::ParkedForRevalidation`]); an operator/runner
//! revalidates the parked tree and re-lands it. Auto-revalidate-then-land
//! (re-running validation against the rebased tree from the landing path, which
//! needs the runner's validation machinery not reachable from this crate) is not
//! built.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use jj_lib::backend::CommitId;
use jj_lib::lock::FileLock;
use jj_lib::merge::Merge;
use jj_lib::merged_tree::MergedTree;
use jj_lib::object_id::ObjectId as _;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::RefNameBuf;
use jj_lib::repo::Repo as _;
use jj_lib::rewrite::merge_commit_trees;
use kata_types::target::{TARGET_TRUNK_RENAMED, TargetRefusal};
use kata_types::{KataError, KataResult};

use crate::trunk::EXECUTION_REF_PREFIX;
use kata_effects_contract::{
    ExecutionWorkspaceBackend, ExecutionWorkspaceKey, ParkedWorkspace, PromotedWorkspace,
    execution_workspace_identity,
};

use super::JjBackend;

/// How a candidate reached trunk. A landing is ALWAYS a fast-forward (or the
/// idempotent already-landed no-op): a candidate whose base advanced is NOT
/// landed — its rebased tree is owed revalidation, so it is parked
/// ([`LandingOutcome::ParkedForRevalidation`]) rather than landed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LandingKind {
    /// Trunk already contained the candidate (base == candidate, or the
    /// candidate is an ancestor of trunk). Idempotent no-op — trunk untouched.
    AlreadyLanded,
    /// Trunk was an ancestor of the candidate: a pointer-only fast-forward.
    FastForward,
}

/// The rebased-candidate state the revalidation fence exposes to the
/// runner/operator. Carried by [`LandingOutcome::ParkedForRevalidation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebasedCandidate {
    /// Candidate commit the stage's validation actually ran on (pre-rebase).
    pub original_commit_sha: String,
    /// Trunk head the candidate was rebased onto.
    pub base_commit_sha: String,
    /// The (conflict-free) rebased commit — PARKED for revalidation, NOT on
    /// trunk. This is the exact tree owed revalidation before it can be trusted.
    pub rebased_commit_sha: String,
}

/// Typed reason a candidate was parked instead of landed: its rebase onto the
/// advanced trunk carried conflicts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictPark {
    /// The parked candidate commit (its work preserved intact under `parked/…`).
    pub candidate_commit_sha: String,
    /// Trunk head the rebase targeted (untouched — never overwritten).
    pub base_commit_sha: String,
    /// Repo-relative paths whose 3-way merge onto trunk conflicted.
    pub conflicted_paths: Vec<String>,
}

/// Outcome of a serialized landing attempt.
#[derive(Clone, Debug)]
pub enum LandingOutcome {
    /// The candidate landed on trunk as a fast-forward (or was already an
    /// ancestor of trunk). The landed tree IS the tree validation approved, so
    /// it is trusted with no revalidation owed.
    Landed {
        promoted: PromotedWorkspace,
        kind: LandingKind,
    },
    /// The rebase carried conflicts; the candidate was parked, trunk untouched.
    Parked {
        parked: ParkedWorkspace,
        conflict: ConflictPark,
    },
    /// Fail-closed floor: the candidate's base advanced since validation
    /// approved it, so its (conflict-free) rebased tree is NOT the tree
    /// validation ran on. Rather than silently landing that unvalidated tree,
    /// the rebased commit is PARKED under the execution's needs-revalidation ref
    /// and trunk is left UNTOUCHED — a rebased candidate is never trusted until
    /// its rebased tree is revalidated. `rebased` carries the (original, base,
    /// rebased) shas an operator/runner revalidates before re-landing.
    ParkedForRevalidation {
        parked: ParkedWorkspace,
        rebased: RebasedCandidate,
    },
}

impl LandingOutcome {
    /// Whether the candidate reached trunk (was landed-and-trusted). A parked
    /// candidate — conflict OR revalidation-owed — is NOT landed.
    #[must_use]
    pub fn is_landed(&self) -> bool {
        matches!(self, Self::Landed { .. })
    }
}

/// Per-repo in-process landing mutex registry. Guarantees deterministic
/// same-process serialization independent of any `flock` same-process quirks;
/// the cross-process `flock` layered on top covers multi-process landings.
fn landing_mutex(repo_path: &Path) -> Arc<Mutex<()>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = registry.lock().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(
        map.entry(repo_path.to_path_buf())
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    )
}

/// Per-repo count of completed landing attempts, driving the post-land
/// op-log GC cadence (`vcs.op_log_gc_every_n_lands`). Process-local: a long-lived
/// node accumulates ticks between boots and compacts every N; a restart resets
/// the counter, and the boot sweep runs a compaction anyway, so no tick is lost
/// to the reset.
fn landing_counter(repo_path: &Path) -> Arc<AtomicU64> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Arc<AtomicU64>>>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = registry.lock().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(
        map.entry(repo_path.to_path_buf())
            .or_insert_with(|| Arc::new(AtomicU64::new(0))),
    )
}

impl JjBackend {
    /// Path of the per-repo landing lock file (cross-process `flock` anchor).
    fn landing_lock_path(&self) -> PathBuf {
        self.repo_path.join(".jj").join("kata-landing.lock")
    }

    /// Serialized landing of an already-committed candidate onto trunk (the
    /// `main` bookmark). This is the crash-safe queue primitive: it operates
    /// purely on the given candidate commit sha and the trunk bookmark, taking
    /// the per-repo landing lock for the whole read-decide-write ladder. It does
    /// NOT touch the execution workspace (that lifecycle belongs to the caller —
    /// [`ExecutionWorkspaceProvider::promote_workspace`] wraps this with the
    /// workspace teardown).
    ///
    /// [`ExecutionWorkspaceProvider::promote_workspace`]: kata_effects_contract::ExecutionWorkspaceProvider::promote_workspace
    pub fn land_committed_candidate(
        &self,
        key: &ExecutionWorkspaceKey,
        candidate_commit_sha: &str,
        label: Option<&str>,
    ) -> KataResult<LandingOutcome> {
        self.land_committed_candidate_tagged(key, candidate_commit_sha, label, None, None)
    }

    /// `land_committed_candidate` with `kata.effect` = `effect_tag` on the
    /// ladder's publishing transactions — the `oci` `workspace_effect`
    /// promote's variant; the untagged promote delegates with `None`.
    ///
    /// `landing_branch` is the execution's FROZEN landable branch, when it has
    /// one: the trunk the ladder resolves under the lock must carry that name,
    /// or the land refuses `target_trunk_renamed` before it moves anything.
    ///
    /// The lock serializes landings, not every writer: a `jj` command on the
    /// repository, or kata's own import of a `git` move (a run's target
    /// resolution or workspace creation), can move the trunk bookmark between
    /// the ladder's read and its fast-forward's re-read. The land then refuses
    /// `target_trunk_raced` and moves nothing.
    pub fn land_committed_candidate_tagged(
        &self,
        key: &ExecutionWorkspaceKey,
        candidate_commit_sha: &str,
        label: Option<&str>,
        effect_tag: Option<&str>,
        landing_branch: Option<&str>,
    ) -> KataResult<LandingOutcome> {
        // SERIALIZE: one landing at a time per repo. The in-process mutex gives
        // deterministic same-process ordering; the flock covers cross-process.
        // Both release on scope exit / process death, so a crash cannot wedge the
        // queue.
        let outcome = {
            let inproc = landing_mutex(&self.repo_path);
            let _inproc_guard = inproc.lock().unwrap_or_else(PoisonError::into_inner);
            let lock_path = self.landing_lock_path();
            let _file_guard = FileLock::lock(lock_path.clone()).map_err(|err| {
                KataError::Internal(format!(
                    "failed to acquire jj landing lock {}: {err}",
                    lock_path.display()
                ))
            })?;

            // The landing base is RESOLVED inside the ladder, under the lock,
            // from the same `crate::trunk::resolve_trunk` the fork base goes
            // through. One resolver is what keeps "the fork base and the
            // landing base are the same ref" true by construction rather than
            // by two literals happening to match.
            super::record_vcs_op("land", || {
                self.run_landing_ladder(
                    key,
                    candidate_commit_sha,
                    label,
                    effect_tag,
                    landing_branch,
                )
            })?
        };

        // Land cadence — bound the op-log on a long-lived node that lands
        // continuously and may never reboot to hit the boot sweep. Runs OUTSIDE
        // the landing lock (op-log GC takes only the op-heads lock), best-effort
        // and non-fatal: the landing outcome above is authoritative and is
        // returned unchanged whether or not compaction runs or errors. This does
        // not alter merge-queue landing semantics.
        self.maybe_compact_op_log_after_land();

        Ok(outcome)
    }

    /// Tick the per-repo landing counter and, on every `every_n_lands`-th land,
    /// run one bounded op-log compaction pass. Best-effort: a GC error is
    /// swallowed so it can never fail a landing (the landing already committed).
    fn maybe_compact_op_log_after_land(&self) {
        let policy = self.op_log_gc_policy();
        if !policy.enabled || policy.every_n_lands == 0 {
            return;
        }
        let counter = landing_counter(&self.repo_path);
        let ticks = counter.fetch_add(1, Ordering::Relaxed) + 1;
        if !ticks.is_multiple_of(policy.every_n_lands) {
            return;
        }
        // A pass that abandoned ops bumps the success metric; a no-op pass
        // (already bounded) and a best-effort failure (the landing is already
        // committed and authoritative, so a GC error is swallowed) are both
        // silent — surfaced only via the absent metric increment.
        if let Ok(stats) = self.compact_op_log(&policy)
            && stats.ran
        {
            metrics::counter!(
                "kata_vcs_op_log_gc_total",
                "trigger" => "land_cadence",
            )
            .increment(1);
        }
    }

    /// The read-decide-write landing ladder. MUST be called under the landing
    /// lock so the trunk read and the trunk write cannot interleave with another
    /// landing.
    fn run_landing_ladder(
        &self,
        key: &ExecutionWorkspaceKey,
        candidate_commit_sha: &str,
        label: Option<&str>,
        effect_tag: Option<&str>,
        landing_branch: Option<&str>,
    ) -> KataResult<LandingOutcome> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        // Opened before the rebase writes its trees: the park-for-revalidation
        // transaction below names them.
        let barrier = super::durability::RepositoryBarrier::for_git_store(repo.store())?;

        // Resolved HERE, inside the lock, from the repo view the ladder is
        // about to read - not passed in from a constant, and not resolved at
        // `open()`: a constant would make `promote` on a repository whose trunk
        // is `master` fail naming a bookmark the operator never had.
        let base_bookmark = self
            .resolve_trunk_in(repo.as_ref())?
            .require("promote")?
            .to_owned();
        // The execution froze trunk's NAME at admission; landing on a trunk
        // resolved to another name would move a branch the run never targeted.
        if let Some(frozen) = landing_branch
            && frozen != base_bookmark
        {
            return Err(TargetRefusal::new(
                TARGET_TRUNK_RENAMED,
                format!(
                    "execution {} froze trunk `{frozen}` as its landable branch, and this \
                     repository's trunk now resolves to `{base_bookmark}`; nothing lands. Re-run \
                     against the trunk as it is now",
                    key.execution_id
                ),
            )
            .into());
        }
        let base_bookmark = base_bookmark.as_str();

        let bookmark_name = RefNameBuf::from(base_bookmark.to_owned());
        let base_commit_id = repo
            .view()
            .get_local_bookmark(bookmark_name.as_ref())
            .as_normal()
            .cloned()
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "landing base bookmark {base_bookmark} is absent or conflicted"
                ))
            })?;
        let candidate_commit_id =
            CommitId::try_from_hex(candidate_commit_sha).ok_or_else(|| {
                KataError::Internal(format!(
                    "landing candidate commit id is not valid hex: {candidate_commit_sha}"
                ))
            })?;
        let candidate_commit = repo
            .store()
            .get_commit(&candidate_commit_id)
            .map_err(|err| {
                KataError::Internal(format!("failed to load jj landing candidate commit: {err}"))
            })?;

        let index = repo.index();

        // (a) Already landed: base IS the candidate, or the candidate is already
        // an ancestor of trunk (a prior land already integrated it). No-op.
        let candidate_is_ancestor_of_base = base_commit_id == candidate_commit_id
            || index
                .is_ancestor(&candidate_commit_id, &base_commit_id)
                .map_err(|err| {
                    KataError::Internal(format!("failed to check jj landing ancestry: {err}"))
                })?;
        if candidate_is_ancestor_of_base {
            return Ok(LandingOutcome::Landed {
                promoted: Self::landed_promoted(key, base_bookmark, candidate_commit_sha),
                kind: LandingKind::AlreadyLanded,
            });
        }

        // (b) Fast-forward: trunk is an ancestor of the candidate (trunk did not
        // move since the fork) — a pointer-only bookmark move.
        let fast_forward = index
            .is_ancestor(&base_commit_id, &candidate_commit_id)
            .map_err(|err| {
                KataError::Internal(format!("failed to check jj landing ancestry: {err}"))
            })?;
        if fast_forward {
            #[cfg(any(test, feature = "test-support"))]
            crate::test_support::run_landing_interleave(&self.repo_path);
            // Reuse the existing, tested fast-forward bookmark move (a
            // pointer-only land), as a compare-and-swap on the trunk read
            // above. Under the landing lock no other landing moves trunk, so
            // the trunk it re-reads is the trunk we just decided on unless a
            // writer outside kata moved it in between — to any commit, or
            // away — which it refuses `target_trunk_raced`, moving nothing.
            self.promote_local_bookmark_ff_only_tagged(
                base_bookmark,
                &base_commit_id,
                candidate_commit_sha,
                key.execution_id,
                effect_tag,
            )?;
            return Ok(LandingOutcome::Landed {
                promoted: Self::landed_promoted(key, base_bookmark, candidate_commit_sha),
                kind: LandingKind::FastForward,
            });
        }

        // (c) Base advanced: REBASE the candidate onto the new trunk head.
        let base_commit = repo.store().get_commit(&base_commit_id).map_err(|err| {
            KataError::Internal(format!("failed to load jj landing base commit: {err}"))
        })?;
        let Some(rebased_tree) =
            Self::rebased_tree(repo.as_ref(), &candidate_commit, &base_commit)?
        else {
            return Err(KataError::Validation(format!(
                "cannot land candidate {candidate_commit_sha}: no common ancestor with trunk \
                 {base_bookmark} (unrelated histories)"
            )));
        };

        if rebased_tree.has_conflict() {
            // (d) Conflicts: PARK the candidate, leave trunk untouched.
            let conflicted_paths = rebased_tree
                .conflicts()
                .map(|(path, _)| path.into_internal_string())
                .collect::<Vec<_>>();
            let ref_name = Self::parked_bookmark_name(key.execution_id, label);
            self.set_local_bookmark_tagged(&ref_name, candidate_commit_sha, effect_tag)?;
            let parked = ParkedWorkspace {
                identity: Some(execution_workspace_identity(
                    key,
                    ExecutionWorkspaceBackend::Jj,
                    Some(format!("{EXECUTION_REF_PREFIX}{}", key.execution_id)),
                    Some(candidate_commit_sha.to_string()),
                    Some(base_bookmark.to_string()),
                    Some(base_commit_id.hex()),
                    Some(ref_name.clone()),
                    Some(candidate_commit_sha.to_string()),
                )),
                ref_name,
                commit_sha: candidate_commit_sha.to_string(),
            };
            metrics::counter!(
                "kata_merge_queue_landings_total",
                "outcome" => "parked_conflict",
            )
            .increment(1);
            return Ok(LandingOutcome::Parked {
                parked,
                conflict: ConflictPark {
                    candidate_commit_sha: candidate_commit_sha.to_string(),
                    base_commit_sha: base_commit_id.hex(),
                    conflicted_paths,
                },
            });
        }

        // Fail-closed floor: the base advanced, so the (conflict-free)
        // rebased tree is NOT the tree validation approved — it is OWED
        // revalidation before it can be trusted. Write the rebased commit
        // (parented on trunk) but DO NOT move the trunk bookmark: PARK the rebased
        // commit under the execution's needs-revalidation ref so it is
        // operator-visible and can never be silently landed-as-validated. Trunk
        // stays exactly where it was — one atomic transaction that touches ONLY
        // the parked ref, never trunk.
        let parked_ref_name = Self::parked_bookmark_name(key.execution_id, label);
        let mut tx = repo.start_transaction();
        let rebased_commit = Self::block_on(
            tx.repo_mut()
                .new_commit(vec![base_commit_id.clone()], rebased_tree)
                .set_description(Self::revalidation_rebase_description(
                    key.execution_id,
                    base_bookmark,
                ))
                .write(),
        )
        .map_err(|err| KataError::Internal(format!("failed to write jj rebased commit: {err}")))?;
        let rebased_sha = rebased_commit.id().hex();
        tx.repo_mut().set_local_bookmark_target(
            &RefNameBuf::from(parked_ref_name.clone()),
            RefTarget::normal(rebased_commit.id().clone()),
        );
        // Publish the needs-revalidation ref to the colocated `.git` in the SAME
        // transaction: the whole point of parking is that an operator can find,
        // inspect and revalidate the rebased tree, and a ref only jj can resolve
        // is not findable with any tool they use.
        Self::export_bookmark_to_git(tx.repo_mut(), &parked_ref_name, "merge-queue park")?;
        super::workspace_effect::tag_effect(&mut tx, effect_tag);
        super::durability::commit_transaction(
            &barrier,
            tx,
            format!(
                "kata merge-queue park-for-revalidation {} (base advanced; rebased tree owed \
                 revalidation before trust)",
                key.execution_id
            ),
            "failed to commit jj park-for-revalidation",
        )?;

        metrics::counter!(
            "kata_merge_queue_landings_total",
            "outcome" => "parked_revalidation_owed",
        )
        .increment(1);

        Ok(LandingOutcome::ParkedForRevalidation {
            parked: ParkedWorkspace {
                identity: Some(execution_workspace_identity(
                    key,
                    ExecutionWorkspaceBackend::Jj,
                    Some(format!("{EXECUTION_REF_PREFIX}{}", key.execution_id)),
                    Some(rebased_sha.clone()),
                    Some(base_bookmark.to_string()),
                    Some(base_commit_id.hex()),
                    Some(parked_ref_name.clone()),
                    Some(rebased_sha.clone()),
                )),
                ref_name: parked_ref_name,
                commit_sha: rebased_sha.clone(),
            },
            rebased: RebasedCandidate {
                original_commit_sha: candidate_commit_sha.to_string(),
                base_commit_sha: base_commit_id.hex(),
                rebased_commit_sha: rebased_sha,
            },
        })
    }

    /// `candidate`'s tree rebased onto `base`: the 3-way merge of (base, fork,
    /// candidate) at the TRUE fork point (their common ancestors), so the
    /// candidate's full contribution is reproduced on top of `base` regardless
    /// of the candidate's chain shape. jj resolves trivial merges; genuine
    /// conflicts stay IN the tree. `None` when the two share no ancestor. The
    /// landing ladder rebases with it, and the promote classify recomputes it to
    /// prove a parked commit is the ladder's own rebase.
    pub(super) fn rebased_tree(
        repo: &dyn jj_lib::repo::Repo,
        candidate: &jj_lib::commit::Commit,
        base: &jj_lib::commit::Commit,
    ) -> KataResult<Option<MergedTree>> {
        let fork_ids = repo
            .index()
            .common_ancestors(
                std::slice::from_ref(candidate.id()),
                std::slice::from_ref(base.id()),
            )
            .map_err(|err| {
                KataError::Internal(format!("failed to find jj landing fork point: {err}"))
            })?;
        if fork_ids.is_empty() {
            return Ok(None);
        }
        let fork_commits = fork_ids
            .iter()
            .map(|id| repo.store().get_commit(id))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                KataError::Internal(format!("failed to load jj landing fork commit: {err}"))
            })?;
        let fork_tree = Self::block_on(merge_commit_trees(repo, &fork_commits)).map_err(|err| {
            KataError::Internal(format!("failed to merge jj landing fork trees: {err}"))
        })?;
        // 3-way merge terms [base (add), fork (remove), candidate (add)] →
        // base + (candidate - fork).
        let rebased = Self::block_on(MergedTree::merge(Merge::from_vec(vec![
            (base.tree(), "trunk (rebase destination)".to_string()),
            (fork_tree, "fork (parents of rebased candidate)".to_string()),
            (candidate.tree(), "candidate (rebased revision)".to_string()),
        ])))
        .map_err(|err| KataError::Internal(format!("failed to rebase jj landing tree: {err}")))?;
        Ok(Some(rebased))
    }

    /// The description the ladder gives the rebased commit it parks for
    /// revalidation — part of the evidence the promote classify reads back.
    pub(super) fn revalidation_rebase_description(
        execution_id: ulid::Ulid,
        base_bookmark: &str,
    ) -> String {
        format!("kata merge-queue rebase (needs revalidation) {execution_id} onto {base_bookmark}")
    }

    /// Build the [`PromotedWorkspace`] for a landed candidate. The trusted base
    /// bookmark now points at `landed_sha`, so identity base/target both address
    /// it — mirroring [`kata_effects_contract::ExecutionWorkspaceProvider::lookup_promoted_workspace`]
    /// so an interrupted landing reconciles observe-first.
    ///
    /// `base_bookmark` is the RESOLVED trunk the ladder just landed on, threaded
    /// from [`Self::run_landing_ladder`]. It stamped a constant until the trunk
    /// binding landed, so the recorded `ref_name` of every promote on a
    /// non-`main` repository named a ref that had not moved.
    fn landed_promoted(
        key: &ExecutionWorkspaceKey,
        base_bookmark: &str,
        landed_sha: &str,
    ) -> PromotedWorkspace {
        let base_bookmark = base_bookmark.to_string();
        PromotedWorkspace {
            identity: Some(execution_workspace_identity(
                key,
                ExecutionWorkspaceBackend::Jj,
                Some(format!("{EXECUTION_REF_PREFIX}{}", key.execution_id)),
                Some(landed_sha.to_string()),
                Some(base_bookmark.clone()),
                Some(landed_sha.to_string()),
                Some(base_bookmark.clone()),
                Some(landed_sha.to_string()),
            )),
            ref_name: base_bookmark,
            commit_sha: landed_sha.to_string(),
        }
    }
}
