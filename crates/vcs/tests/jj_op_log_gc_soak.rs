//! Jj operation-log GC soak + safety regressions.
//!
//! HEAD-move imports and land/promote traffic each publish a jj
//! operation-log entry, so a long-lived adopted repo grows the op-log (and the
//! store objects behind abandoned operations) without bound. These tests pin the
//! two claims op-log GC owes:
//!
//! * **Bound (soak):** repeated create-workspace → commit → land cycles grow the
//!   op-log unboundedly WITHOUT GC (the RED counterfactual, asserted in-test),
//!   and stay bounded WITH kata-triggered compaction (GREEN).
//! * **Safety:** a parked candidate + a live workspace both SURVIVE an aggressive
//!   GC and remain usable — the parked commit still resolves and a landing still
//!   works after compaction.
//!
//! On-disk-jj-repo I/O class (real repos + workspaces + FileLock traffic), so
//! both tests join the `heavy-io` nextest group (`.config/nextest.toml`).

use std::fs;
use std::path::Path;
use std::time::Duration;

use jj_lib::backend::CommitId;
use jj_lib::config::StackedConfig;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::RefNameBuf;
use jj_lib::repo::{ReadonlyRepo, Repo as _, StoreFactories};
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_effects_contract::ExecutionWorkspaceKey;
use kata_types::AgentId;
use kata_vcs::{JjBackend, LandingOutcome, OpLogGcPolicy, VcsBackend};
use ulid::Ulid;

/// Open an adopted jj repo at `tmp` that STATES its identity as well as its
/// trunk.
///
/// The identity half is the same shape as the trunk half above and exists for
/// the same reason. `JjBackend::open` colocates a `.git` with NO local config,
/// so a bare fixture's answer to "who commits here" was whatever the operator's
/// GLOBAL git config happened to say — and on a host with none,
/// `create_workspace` REFUSES, because kata inherits the host's identity and
/// never invents one (`kata_vcs::identity`). Without the declaration these
/// tests go red under `GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null`,
/// which is what a fresh CI host looks like and what `just gate` must not
/// depend on.
///
/// `write_hermetic_config` is the declaration, not a workaround: it writes the
/// SAME `user.name` / `user.email` every other hermetic fixture in this
/// workspace declares, into the repo-LOCAL layer a process kata spawns reads.
fn open_declared(tmp: &tempfile::TempDir) -> JjBackend {
    let backend = JjBackend::open(tmp.path()).unwrap();
    kata_test_utils::git::write_hermetic_config(tmp.path());
    backend
}

/// Aggressive test horizon: keep only the newest few operations, with a
/// zero-second safety floor so every surplus operation is immediately
/// abandonable. `every_n_lands = 0` — the tests drive compaction explicitly so
/// the bound is asserted deterministically, not on a hidden cadence.
fn aggressive_policy() -> OpLogGcPolicy {
    OpLogGcPolicy {
        enabled: true,
        max_operations: 8,
        keep_newer: Duration::ZERO,
        every_n_lands: 0,
    }
}

fn load_repo(repo_path: &Path) -> std::sync::Arc<ReadonlyRepo> {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        repo_path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap()
}

fn set_local_bookmark(repo_path: &Path, ref_name: &str, commit_id: &str) {
    let repo = load_repo(repo_path);
    let commit_id = CommitId::try_from_hex(commit_id).unwrap();
    repo.store().get_commit(&commit_id).unwrap();
    let mut tx = repo.start_transaction();
    let bookmark_name = RefNameBuf::from(ref_name.to_owned());
    tx.repo_mut()
        .set_local_bookmark_target(&bookmark_name, RefTarget::normal(commit_id));
    futures::executor::block_on(tx.commit(format!("test set bookmark {ref_name}"))).unwrap();
}

fn local_bookmark_commit(repo_path: &Path, ref_name: &str) -> Option<String> {
    let repo = load_repo(repo_path);
    let ids = repo
        .view()
        .get_local_bookmark(ref_name.as_ref())
        .added_ids()
        .map(jj_lib::object_id::ObjectId::hex)
        .collect::<Vec<_>>();
    if ids.len() == 1 {
        ids.into_iter().next()
    } else {
        None
    }
}

/// The kata growth vector, once: create a fresh execution workspace (fork
/// churn), write + commit a file (HEAD move), and land the candidate onto trunk
/// (land traffic). Each cycle publishes several op-log entries. Returns the
/// landed/parked commit sha.
fn land_cycle(backend: &JjBackend, i: usize) -> String {
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(backend, &key).unwrap();
    let agent = AgentId(key.execution_id);
    let file = format!("cycle-{i}.txt");
    fs::write(handle.path.join(&file), format!("cycle-{i}\n")).unwrap();
    let commit = VcsBackend::commit(backend, &agent, &format!("cycle {i}")).unwrap();
    // Best-effort land — the first cycle fast-forwards, later cycles whose base
    // advanced park for revalidation. Either way the op-log grew.
    let _ = backend.land_committed_candidate(&key, &commit, None);
    commit
}

/// Grow the op-log by `n` cheap HEAD-move-class operations under a SINGLE repo
/// load: re-point a `probe` bookmark `n` times, each `tx.commit()` publishing one
/// op-log entry (no working-copy checkout). Amortizing the repo load across the
/// whole burst keeps the soak fast under load (a per-op `Workspace::load` is the
/// dominant fsync cost otherwise); the real fork/HEAD-move/land vector is
/// exercised by the `land_cycle` calls at the head of the soak and throughout the
/// safety test.
fn grow_ops(repo_path: &Path, base_sha: &str, n: usize) {
    let mut repo = load_repo(repo_path);
    let commit_id = CommitId::try_from_hex(base_sha).unwrap();
    let bookmark_name = RefNameBuf::from("probe".to_owned());
    for k in 0..n {
        let mut tx = repo.start_transaction();
        tx.repo_mut()
            .set_local_bookmark_target(&bookmark_name, RefTarget::normal(commit_id.clone()));
        repo = futures::executor::block_on(tx.commit(format!("probe move {k}"))).unwrap();
    }
}

/// Count the loose op-store object files physically on disk (`operations/` +
/// `views/` under `.jj/repo/op_store`). Unlike [`JjBackend::op_log_len`] — which
/// counts only operations *reachable from head*, and so is bounded by reparenting
/// ALONE — this counts EVERY operation/view file still present on disk, so it
/// only drops when `op_store.gc` actually deletes the abandoned objects. This is
/// the disk half of the op-log bound ("op-log op count AND .jj on-disk size
/// stay bounded"): a regression that reparented the log but stopped collecting
/// store objects would leave this ratcheting upward while `op_log_len` still
/// looked bounded.
fn op_store_object_count(repo_path: &Path) -> u64 {
    let op_store = repo_path.join(".jj/repo/op_store");
    let mut count = 0u64;
    for sub in ["operations", "views"] {
        if let Ok(entries) = fs::read_dir(op_store.join(sub)) {
            count += entries
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                .count() as u64;
        }
    }
    count
}

/// Recursively sum the byte size of every regular file under `.jj` — the whole
/// on-disk footprint (op-store objects, store objects, index). Symlinks are
/// skipped (jj working-copy metadata). Complements [`op_store_object_count`] with
/// a total-bytes view of the same bound.
fn jj_dir_size_bytes(repo_path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![repo_path.join(".jj")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(entry.path()),
                Ok(ft) if ft.is_file() => {
                    if let Ok(meta) = entry.metadata() {
                        total += meta.len();
                    }
                }
                _ => {}
            }
        }
    }
    total
}

/// SOAK — the op-log grows unbounded WITHOUT GC (RED) and stays bounded
/// WITH kata-triggered compaction (GREEN). A few real fork/HEAD-move/land cycles
/// exercise the true growth vectors; the bulk grows via cheap HEAD-move ops so
/// the count climbs high enough to prove the bound without a workspace per op.
#[test]
fn op_log_gc_soak_keeps_operation_log_bounded() {
    let tmp = tempfile::TempDir::new().unwrap();
    // STATES its trunk. `grow_ops` re-points a `probe` bookmark to churn the
    // op-log, which is a second non-kata branch, and a repository with two of
    // those has no host-declared trunk — `kata_vcs::trunk::resolve_trunk`
    // refuses rather than guessing. `vcs.trunk` is the operator's answer to
    // exactly that, so the fixture gives it rather than relying on an accident
    // of how many bookmarks the churn happens to leave behind.
    let backend = open_declared(&tmp).with_configured_trunk(Some("main".to_owned()));
    let policy = aggressive_policy();
    let repo_path = tmp.path();

    // Anchor trunk so the land ladder has its base bookmark.
    let seed_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let seed_handle = kata_vcs::test_support::create_trunk_workspace(&backend, &seed_key).unwrap();
    let seed_status =
        VcsBackend::workspace_status(&backend, &AgentId(seed_key.execution_id)).unwrap();
    let base_sha = seed_status
        .head
        .base_commit_id
        .clone()
        .unwrap_or(seed_status.head.commit_id);
    set_local_bookmark(repo_path, "main", &base_sha);
    drop(seed_handle);

    // Exercise the REAL growth vectors (fork churn + HEAD move + land) a few
    // times up front, so the soak is not a bookmark-only artifact.
    for i in 0..4 {
        land_cycle(&backend, i);
    }

    // ---- RED: no GC → the op-log climbs without bound (1 op per HEAD move). ----
    let baseline = backend.op_log_len().unwrap();
    const RED_OPS: usize = 30;
    grow_ops(repo_path, &base_sha, RED_OPS);
    let no_gc_len = backend.op_log_len().unwrap();
    assert!(
        no_gc_len >= baseline + RED_OPS as u64,
        "expected unbounded op-log growth without GC: baseline={baseline}, \
         after {RED_OPS} ops={no_gc_len}"
    );
    // The surplus is well past the retention ceiling — the RED state is real.
    assert!(
        no_gc_len > policy.max_operations + 8,
        "RED op-log should exceed the GC ceiling: len={no_gc_len}, ceiling≈{}",
        policy.max_operations + 8
    );
    // DISK RED: the surplus is on disk too — the loose op-store object files
    // ratchet 1:1 with the ungc'd ops, well past the retention ceiling.
    let red_disk_objects = op_store_object_count(repo_path);
    assert!(
        red_disk_objects > policy.max_operations + 8,
        "RED on-disk op-store objects should exceed the GC ceiling: \
         objects={red_disk_objects}, ceiling≈{}",
        policy.max_operations + 8
    );

    // Prove the counterfactual is real: one compaction pass abandons the surplus.
    let first_gc = backend.compact_op_log(&policy).unwrap();
    assert!(
        first_gc.ran && first_gc.ops_abandoned > 0,
        "GC should abandon the surplus it just observed: {first_gc:?}"
    );
    let after_first_gc = backend.op_log_len().unwrap();
    assert!(
        after_first_gc < no_gc_len,
        "GC must shrink the op-log: {no_gc_len} -> {after_first_gc}"
    );
    // DISK GREEN (counterfactual half): store gc physically DELETED the abandoned
    // operation/view files — the on-disk object count dropped, not just the
    // logical reachable count. A reparent-only regression (no store gc) would
    // leave `after_first_gc_disk == red_disk_objects`.
    let after_first_gc_disk = op_store_object_count(repo_path);
    assert!(
        after_first_gc_disk < red_disk_objects,
        "store gc must physically collect abandoned op-store objects on disk: \
         {red_disk_objects} -> {after_first_gc_disk}"
    );

    // ---- GREEN: grow a burst, compact, repeat → the op-log stays bounded
    // ACROSS a multi-round soak. Batched (compaction is a fsync-heavy reindex, so
    // the soak drives a bounded number of them) while still proving the invariant
    // that matters: after every compaction the log returns near the retention
    // count and NEVER ratchets upward with the round number.
    const BATCH: usize = 12;
    const ROUNDS: usize = 6;
    // Steady-state ceiling: retention count + a batch's surplus + the root op and
    // a little slack for the ops the up-front land cycles' bookmarks leave live.
    let ceiling = policy.max_operations + BATCH as u64 + 6;
    let mut post_gc_lens = Vec::with_capacity(ROUNDS);
    let mut post_gc_disk_objects = Vec::with_capacity(ROUNDS);
    let mut post_gc_disk_bytes = Vec::with_capacity(ROUNDS);
    for round in 0..ROUNDS {
        grow_ops(repo_path, &base_sha, BATCH);
        let pre = backend.op_log_len().unwrap();
        let stats = backend.compact_op_log(&policy).unwrap();
        let post = backend.op_log_len().unwrap();
        assert!(
            stats.ran && stats.ops_abandoned > 0,
            "round {round}: a burst of {BATCH} ops must give GC something to abandon: {stats:?}"
        );
        assert!(
            post < pre && post <= ceiling,
            "round {round}: GC must return the op-log near the retention count: \
             pre={pre}, post={post}, ceiling={ceiling}"
        );
        post_gc_lens.push(post);
        // Disk half: after each round's gc the ON-DISK op-store object count must
        // also return near the retention ceiling (store gc collected the round's
        // abandoned operation/view files), not accumulate with the round number.
        let post_disk = op_store_object_count(repo_path);
        assert!(
            post_disk <= ceiling,
            "round {round}: on-disk op-store objects must return near the retention \
             count after gc: post_disk={post_disk}, ceiling={ceiling}"
        );
        post_gc_disk_objects.push(post_disk);
        post_gc_disk_bytes.push(jj_dir_size_bytes(repo_path));
    }
    // The bound does NOT ratchet with rounds: the last post-GC length is no larger
    // than the first (steady state, not slow growth).
    let first = post_gc_lens[0];
    let last = post_gc_lens[ROUNDS - 1];
    assert!(
        last <= first,
        "op-log ratcheted upward across the soak (unbounded): post-GC lengths={post_gc_lens:?}"
    );
    // The DISK bound likewise does not ratchet: on-disk op-store object count is no
    // larger at the end than after the first round, and the whole-`.jj` byte
    // footprint has not grown proportionally to the rounds (a generous 50% slack
    // absorbs index/fs jitter while still catching linear-in-rounds accumulation —
    // 6 ungc'd rounds would multiply, not nudge, the footprint).
    let first_disk = post_gc_disk_objects[0];
    let last_disk = post_gc_disk_objects[ROUNDS - 1];
    assert!(
        last_disk <= first_disk,
        "on-disk op-store objects ratcheted upward across the soak (store gc not bounding disk): \
         per-round counts={post_gc_disk_objects:?}"
    );
    let first_bytes = post_gc_disk_bytes[0];
    let last_bytes = post_gc_disk_bytes[ROUNDS - 1];
    assert!(
        last_bytes <= first_bytes + first_bytes / 2,
        "`.jj` on-disk byte footprint ratcheted upward across the soak: \
         per-round bytes={post_gc_disk_bytes:?}"
    );
}

/// Read the raw op-head count WITHOUT resolving divergence (`get_op_heads`, not
/// `load_at_head`, which would merge the heads and write a resolution op). Lets a
/// test observe that compaction left a divergent log untouched.
fn op_head_count(repo_path: &Path) -> usize {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        repo_path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let loader = workspace.repo_loader();
    futures::executor::block_on(loader.op_heads_store().get_op_heads())
        .unwrap()
        .len()
}

/// TOCTOU REGRESSION — a concurrent committer that publishes in the
/// compaction window manifests as a second op-head. If compaction reparented the
/// head it decided on anyway, it would strand that committer's
/// branch: op-heads would go divergent (`{their head, our reparented head}` whose
/// only common ancestor is root → add-vs-add bookmark conflicts that stall the
/// merge queue), and gc with only our head could physically collect objects the
/// other branch still references. Compaction re-reads the heads UNDER the same lock
/// jj's publish takes and bails on any divergence. This pins the invariant the
/// race depends on: compaction observes a multi-headed log and refuses to run,
/// leaving BOTH heads intact for jj's normal resolution to merge.
#[test]
fn op_log_gc_bails_under_op_head_divergence_leaving_both_heads_intact() {
    let tmp = tempfile::TempDir::new().unwrap();
    // STATES its trunk. `grow_ops` re-points a `probe` bookmark to churn the
    // op-log, which is a second non-kata branch, and a repository with two of
    // those has no host-declared trunk — `kata_vcs::trunk::resolve_trunk`
    // refuses rather than guessing. `vcs.trunk` is the operator's answer to
    // exactly that, so the fixture gives it rather than relying on an accident
    // of how many bookmarks the churn happens to leave behind.
    let backend = open_declared(&tmp).with_configured_trunk(Some("main".to_owned()));
    let repo_path = tmp.path();

    // Seed a commit both divergent branches can point a bookmark at.
    let seed_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let seed_handle = kata_vcs::test_support::create_trunk_workspace(&backend, &seed_key).unwrap();
    let seed_status =
        VcsBackend::workspace_status(&backend, &AgentId(seed_key.execution_id)).unwrap();
    let base_sha = seed_status
        .head
        .base_commit_id
        .clone()
        .unwrap_or(seed_status.head.commit_id);
    drop(seed_handle);

    // Forge the divergence the TOCTOU race would produce: two transactions both
    // rooted at the SAME base operation, each committed. The second
    // `update_op_heads([base], op2)` finds `base` already replaced by `op1`, so it
    // simply ADDS `op2` — leaving two heads.
    let commit_id = CommitId::try_from_hex(&base_sha).unwrap();
    let base = load_repo(repo_path);
    let mut tx1 = base.start_transaction();
    tx1.repo_mut().set_local_bookmark_target(
        &RefNameBuf::from("branch-x".to_owned()),
        RefTarget::normal(commit_id.clone()),
    );
    futures::executor::block_on(tx1.commit("branch x")).unwrap();
    let mut tx2 = base.start_transaction();
    tx2.repo_mut().set_local_bookmark_target(
        &RefNameBuf::from("branch-y".to_owned()),
        RefTarget::normal(commit_id.clone()),
    );
    futures::executor::block_on(tx2.commit("branch y")).unwrap();

    assert_eq!(
        op_head_count(repo_path),
        2,
        "test setup must produce a genuinely divergent (2-head) op-log"
    );

    // Compaction must observe the divergence and BAIL — never reparent under
    // ambiguity.
    let stats = backend.compact_op_log(&aggressive_policy()).unwrap();
    assert!(
        !stats.ran,
        "compaction must refuse to run on a divergent op-log (would strand a \
         concurrent committer's head): {stats:?}"
    );
    // Both heads survive untouched — compaction did not reparent, merge, or gc.
    assert_eq!(
        op_head_count(repo_path),
        2,
        "compaction must leave the divergent heads intact for jj's own resolution"
    );

    // jj's normal resolution then merges the two heads; BOTH bookmarks survive —
    // no branch was lost.
    assert_eq!(
        local_bookmark_commit(repo_path, "branch-x").as_deref(),
        Some(base_sha.as_str()),
        "branch-x must survive divergence resolution after a bailed compaction"
    );
    assert_eq!(
        local_bookmark_commit(repo_path, "branch-y").as_deref(),
        Some(base_sha.as_str()),
        "branch-y must survive divergence resolution after a bailed compaction"
    );
}

/// SAFETY — a parked candidate and a live workspace both survive an
/// aggressive GC and remain usable: the parked commit still resolves, the live
/// workspace still commits, and a subsequent landing still works.
#[test]
fn op_log_gc_preserves_parked_candidate_and_live_workspace() {
    let tmp = tempfile::TempDir::new().unwrap();
    // STATES its trunk. `grow_ops` re-points a `probe` bookmark to churn the
    // op-log, which is a second non-kata branch, and a repository with two of
    // those has no host-declared trunk — `kata_vcs::trunk::resolve_trunk`
    // refuses rather than guessing. `vcs.trunk` is the operator's answer to
    // exactly that, so the fixture gives it rather than relying on an accident
    // of how many bookmarks the churn happens to leave behind.
    let backend = open_declared(&tmp).with_configured_trunk(Some("main".to_owned()));
    let policy = aggressive_policy();

    // Anchor trunk at the shared base.
    let base_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let base_handle = kata_vcs::test_support::create_trunk_workspace(&backend, &base_key).unwrap();
    let base_status =
        VcsBackend::workspace_status(&backend, &AgentId(base_key.execution_id)).unwrap();
    let base_sha = base_status
        .head
        .base_commit_id
        .clone()
        .unwrap_or(base_status.head.commit_id);
    set_local_bookmark(tmp.path(), "main", &base_sha);
    drop(base_handle);

    // (1) Land a first candidate to advance trunk (fast-forward). BOTH candidates
    // are forked from the shared base BEFORE either lands — the genuine
    // concurrent shape. `create_workspace` forks trunk, so a loser forked after
    // the winner landed would not have a stale base.
    let winner_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let winner_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &winner_key).unwrap();
    let parked_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let parked_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &parked_key).unwrap();

    fs::write(winner_handle.path.join("winner.txt"), "winner\n").unwrap();
    let winner_commit =
        VcsBackend::commit(&backend, &AgentId(winner_key.execution_id), "winner").unwrap();
    let winner_outcome = backend
        .land_committed_candidate(&winner_key, &winner_commit, None)
        .unwrap();
    assert!(winner_outcome.is_landed(), "first candidate should land");

    // (2) The second candidate was forked from the OLD base above and now has an
    // advanced trunk → it PARKS (revalidation-owed or conflict), producing a
    // parked/* bookmark.
    fs::write(parked_handle.path.join("winner.txt"), "loser\n").unwrap();
    let parked_commit =
        VcsBackend::commit(&backend, &AgentId(parked_key.execution_id), "loser").unwrap();
    let parked_outcome = backend
        .land_committed_candidate(&parked_key, &parked_commit, Some("candidate-b"))
        .unwrap();
    let parked_ref = match &parked_outcome {
        LandingOutcome::Parked { parked, .. }
        | LandingOutcome::ParkedForRevalidation { parked, .. } => parked.ref_name.clone(),
        LandingOutcome::Landed { .. } => panic!("second candidate should have parked, not landed"),
    };
    let parked_sha_before = local_bookmark_commit(tmp.path(), &parked_ref)
        .expect("parked bookmark must resolve before GC");

    // (3) A THIRD workspace stays LIVE (created, never torn down) across the GC.
    let live_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let live_handle = kata_vcs::test_support::create_trunk_workspace(&backend, &live_key).unwrap();

    // (4) Churn the op-log well past the retention count, then GC aggressively.
    grow_ops(tmp.path(), &base_sha, 20);
    let stats = backend.compact_op_log(&policy).unwrap();
    assert!(
        stats.ran,
        "GC should have run against the churned log: {stats:?}"
    );

    // ---- SAFETY ASSERTIONS ----

    // (a) The parked candidate's commit is STILL reachable after GC (its bookmark
    // sits in the live view, so store gc never collected it).
    let parked_sha_after = local_bookmark_commit(tmp.path(), &parked_ref)
        .expect("parked bookmark must STILL resolve after GC");
    assert_eq!(
        parked_sha_before, parked_sha_after,
        "GC must not disturb the parked candidate commit"
    );
    // The commit object itself still loads (store gc did not collect it).
    let repo = load_repo(tmp.path());
    let parked_id = CommitId::try_from_hex(&parked_sha_after).unwrap();
    repo.store()
        .get_commit(&parked_id)
        .expect("parked commit object must survive store GC");

    // (b) The live workspace is STILL usable after GC: write + commit succeeds.
    fs::write(live_handle.path.join("live.txt"), "live-after-gc\n").unwrap();
    let live_commit =
        VcsBackend::commit(&backend, &AgentId(live_key.execution_id), "live after gc")
            .expect("live workspace must still commit after GC");

    // (c) A landing still works after GC — the merge queue is fully operational.
    let post_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let post_handle = kata_vcs::test_support::create_trunk_workspace(&backend, &post_key).unwrap();
    fs::write(post_handle.path.join("post.txt"), "post-gc\n").unwrap();
    let post_commit =
        VcsBackend::commit(&backend, &AgentId(post_key.execution_id), "post gc").unwrap();
    let post_outcome = backend
        .land_committed_candidate(&post_key, &post_commit, None)
        .expect("landing must still work after GC");
    // Landed or parked, but never an error — the queue survived compaction.
    assert!(
        matches!(
            post_outcome,
            LandingOutcome::Landed { .. }
                | LandingOutcome::Parked { .. }
                | LandingOutcome::ParkedForRevalidation { .. }
        ),
        "post-GC landing produced no terminal outcome"
    );
    // Keep the live commit id referenced so the workspace commit is observed.
    assert!(!live_commit.is_empty());
}
