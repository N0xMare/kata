//! MergeQueue N-candidate soak / property proof.
//!
//! The two-candidate cells prove the serialized landing ladder; this is the
//! adversarial parallel-agent claim under load: N candidates forked from ONE base
//! and fired at the queue CONCURRENTLY each resolve to exactly one terminal
//! outcome — WITHOUT a wedge, WITHOUT trunk corruption, and WITHOUT lost work.
//!
//! Under the fail-closed revalidation fence a candidate whose base advanced is NEVER
//! auto-landed: only the fast-forward winner lands; every candidate that would
//! require a rebase is PARKED — for revalidation when its rebase is conflict-free
//! (the rebased tree is owed revalidation before trust), or on a genuine
//! conflict.
//!
//! ## Why this is not flaky
//!
//! Concurrency makes the *order* of landings nondeterministic (whichever thread
//! grabs the per-repo landing lock first is the winner). Every assertion here is
//! deliberately chosen to be **interleaving-INDEPENDENT**, so it holds for ALL
//! schedules:
//!
//! * `landed + parked == N` — every candidate resolves to exactly one terminal
//!   outcome (nothing lost, nothing double-counted);
//! * EXACTLY ONE candidate lands, and it lands as a fast-forward — the first to
//!   grab the lock (its base was still trunk). Every other candidate's base has
//!   advanced, so it is fail-closed PARKED (revalidation-owed or conflict), never
//!   silently rebased-and-landed;
//! * trunk carries EXACTLY the winner's file with its content; every other
//!   candidate's contribution stays parked and absent from trunk;
//! * the final trunk tree is conflict-free and the trunk head is a descendant of
//!   the shared base (the winner fast-forwarded onto it).
//!
//! The only timing-sensitive claim — "the landing lock never wedges" — is proved
//! structurally: each landing runs on a blocking task and the test body awaits
//! their join under `#[kata_timeout]`; a wedged lock would stall the join and the
//! timeout would fire with an attributable panic rather than hang. Under normal
//! operation the serialized ladder drains in well under the budget.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use futures::future::join_all;
use jj_lib::backend::{CommitId, TreeValue};
use jj_lib::config::StackedConfig;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::RefNameBuf;
use jj_lib::repo::{ReadonlyRepo, Repo as _, StoreFactories};
use jj_lib::repo_path::RepoPathBuf;
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_effects_contract::{ExecutionWorkspaceHandle, ExecutionWorkspaceKey};
use kata_types::AgentId;
use kata_vcs::{JjBackend, LandingKind, LandingOutcome, VcsBackend};
use tokio::io::AsyncReadExt as _;
use ulid::Ulid;

/// Open an adopted jj repo at `path` that STATES its commit identity.
///
/// `JjBackend::open` colocates a `.git` with NO local config, so a bare fixture
/// inherited whatever the operator's GLOBAL git config said — and on a host with
/// none, `create_workspace` REFUSES, because kata inherits the host's identity
/// and never invents one (`kata_vcs::identity`). `just gate` must be
/// host-independent, so the fixture DECLARES the binding rather than depending
/// on the host, exactly as `kata_test_utils::host_repo::HostBindings` does for
/// trunk. `write_hermetic_config` writes the same `user.name` / `user.email`
/// every other hermetic fixture in this workspace declares, into the repo-LOCAL
/// layer a process kata spawns reads.
fn open_declared(path: &std::path::Path) -> JjBackend {
    let backend = JjBackend::open(path).expect("open adopted jj repo");
    kata_test_utils::git::write_hermetic_config(path);
    backend
}

/// One prepared, already-committed candidate forked from the shared base.
#[derive(Clone)]
struct Candidate {
    key: ExecutionWorkspaceKey,
    commit: String,
    /// Repo-relative file the candidate mutated.
    file: String,
    /// Unique content the candidate wrote (so same-file candidates genuinely
    /// conflict: an add/add of DIFFERENT bytes once one has landed).
    contents: String,
}

/// Everything a soak run needs, produced off the async workers. Owns the
/// `TempDir` and the workspace handles so the repo (and every candidate's
/// working copy) stays live for the whole run.
struct Prepared {
    tmp: tempfile::TempDir,
    backend: JjBackend,
    base_sha: String,
    candidates: Vec<Candidate>,
    _handles: Vec<ExecutionWorkspaceHandle>,
}

/// Facts read back off trunk after all landings have drained.
struct TrunkFacts {
    trunk_has_conflict: bool,
    base_is_ancestor_of_trunk: bool,
    /// Content on trunk for each candidate file (`None` if absent).
    files: BTreeMap<String, Option<String>>,
}

fn load_repo(repo_path: &Path) -> Arc<ReadonlyRepo> {
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

fn local_bookmark_commit(repo_path: &Path, ref_name: &str) -> String {
    let repo = load_repo(repo_path);
    let target = repo.view().get_local_bookmark(ref_name.as_ref());
    let mut ids = target
        .added_ids()
        .map(jj_lib::object_id::ObjectId::hex)
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 1, "bookmark {ref_name} should have one target");
    ids.pop().unwrap()
}

fn commit_tree_has_conflict(repo_path: &Path, commit_hex: &str) -> bool {
    let repo = load_repo(repo_path);
    let commit_id = CommitId::try_from_hex(commit_hex).unwrap();
    let commit = repo.store().get_commit(&commit_id).unwrap();
    commit.tree().has_conflict()
}

fn is_ancestor(repo_path: &Path, ancestor_hex: &str, descendant_hex: &str) -> bool {
    let repo = load_repo(repo_path);
    let ancestor = CommitId::try_from_hex(ancestor_hex).unwrap();
    let descendant = CommitId::try_from_hex(descendant_hex).unwrap();
    repo.index().is_ancestor(&ancestor, &descendant).unwrap()
}

/// Read a committed file's contents from trunk, or `None` if the path is absent.
fn read_committed_file_opt(repo_path: &Path, commit_hex: &str, file_path: &str) -> Option<String> {
    let repo = load_repo(repo_path);
    let commit_id = CommitId::try_from_hex(commit_hex).unwrap();
    let commit = repo.store().get_commit(&commit_id).unwrap();
    let path = RepoPathBuf::from_internal_string(file_path).unwrap();
    let value = commit
        .tree()
        .path_value(path.as_ref())
        .unwrap()
        .into_resolved()
        .unwrap();
    let Some(TreeValue::File { id, .. }) = value else {
        return None;
    };
    // Off the async workers (spawn_blocking / setup thread), so a scoped runtime
    // is safe; jj's async file read is polled to completion here.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut contents = String::new();
    let mut reader = runtime
        .block_on(commit.store().read_file(path.as_ref(), &id))
        .unwrap();
    runtime
        .block_on(async { reader.read_to_string(&mut contents).await })
        .unwrap();
    Some(contents)
}

/// Build N candidates forked from one shared base: create every workspace first
/// (so all fork from the same empty root), anchor `main` at that base, then write
/// + commit each candidate's mutation.
fn prepare(n: usize, num_shared: usize) -> Prepared {
    assert!(n >= 1, "soak needs at least one candidate");
    assert!(num_shared <= n, "num_shared must be <= n");

    let tmp = tempfile::TempDir::new().unwrap();
    let backend = open_declared(tmp.path());

    let mut keys = Vec::with_capacity(n);
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let key = ExecutionWorkspaceKey::execution(Ulid::new());
        let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
        keys.push(key);
        handles.push(handle);
    }

    // Anchor trunk at the shared base (every fresh workspace forks from the empty
    // root, so the first workspace's base is the base of them all). This makes the
    // first landing a fast-forward and every later landing a rebase onto trunk.
    let first_agent = AgentId(keys[0].execution_id);
    let init = VcsBackend::workspace_status(&backend, &first_agent).unwrap();
    let base_sha = init
        .head
        .base_commit_id
        .clone()
        .unwrap_or_else(|| init.head.commit_id.clone());
    set_local_bookmark(tmp.path(), "main", &base_sha);

    let mut candidates = Vec::with_capacity(n);
    for (i, key) in keys.iter().enumerate() {
        let agent = AgentId(key.execution_id);
        let shared = i < num_shared;
        let (file, contents) = if shared {
            // Same path, DIFFERENT bytes per candidate → a genuine add/add
            // conflict once the first of the group has landed.
            ("shared.txt".to_string(), format!("shared-from-{i}\n"))
        } else {
            (format!("disjoint-{i}.txt"), format!("disjoint-{i}\n"))
        };
        fs::write(handles[i].path.join(&file), &contents).unwrap();
        let commit = VcsBackend::commit(&backend, &agent, &format!("candidate {i}")).unwrap();
        candidates.push(Candidate {
            key: key.clone(),
            commit,
            file,
            contents,
        });
    }

    Prepared {
        tmp,
        backend,
        base_sha,
        candidates,
        _handles: handles,
    }
}

fn collect_trunk_facts(repo_path: &Path, base_sha: &str, candidates: &[Candidate]) -> TrunkFacts {
    let trunk_head = local_bookmark_commit(repo_path, "main");
    let mut files = BTreeMap::new();
    for cand in candidates {
        files
            .entry(cand.file.clone())
            .or_insert_with(|| read_committed_file_opt(repo_path, &trunk_head, &cand.file));
    }
    TrunkFacts {
        trunk_has_conflict: commit_tree_has_conflict(repo_path, &trunk_head),
        base_is_ancestor_of_trunk: is_ancestor(repo_path, base_sha, &trunk_head),
        files,
    }
}

/// Core soak: prepare N candidates (`num_shared` of them contending on one file),
/// fire every landing CONCURRENTLY, and assert the interleaving-independent
/// invariants. `prepare` and the trunk read-back run on blocking threads; the
/// concurrent landings each run on a blocking task whose join is awaited under
/// the caller's `#[kata_timeout]`, so a wedged landing lock surfaces as a bounded
/// timeout, never a hang.
async fn run_soak(n: usize, num_shared: usize) {
    let prepared = tokio::task::spawn_blocking(move || prepare(n, num_shared))
        .await
        .expect("soak setup task panicked");

    let backend = prepared.backend.clone();
    let candidates = prepared.candidates.clone();
    let base_sha = prepared.base_sha.clone();
    let repo_path = prepared.tmp.path().to_path_buf();

    // Fire every landing at once — real contention on the per-repo landing lock.
    let mut tasks = Vec::with_capacity(n);
    for cand in &candidates {
        let backend = backend.clone();
        let key = cand.key.clone();
        let commit = cand.commit.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            backend.land_committed_candidate(&key, &commit, None)
        }));
    }
    let joined = join_all(tasks).await;

    let mut landed = 0usize;
    let mut parked = 0usize;
    let mut winner_idx: Option<usize> = None;
    for (idx, res) in joined.into_iter().enumerate() {
        let outcome = res
            .expect("landing task panicked (possible wedge)")
            .unwrap_or_else(|err| panic!("candidate {idx} landing errored: {err:?}"));
        match outcome {
            LandingOutcome::Landed { kind, .. } => {
                landed += 1;
                // The sole winner grabbed the lock while trunk was still its base,
                // so it lands as a FAST-FORWARD — never a rebase.
                assert_eq!(
                    kind,
                    LandingKind::FastForward,
                    "the sole winner must land via fast-forward, never a rebase",
                );
                winner_idx = Some(idx);
            }
            LandingOutcome::Parked { conflict, .. } => {
                parked += 1;
                assert_eq!(
                    conflict.conflicted_paths,
                    vec!["shared.txt".to_string()],
                    "a conflict-parked candidate must name the genuinely-conflicting shared.txt",
                );
            }
            LandingOutcome::ParkedForRevalidation {
                rebased,
                parked: parked_ws,
            } => {
                parked += 1;
                // The rebased tree is a NEW commit owed revalidation,
                // durably preserved under its needs-revalidation ref — NOT trunk.
                assert_eq!(parked_ws.commit_sha, rebased.rebased_commit_sha);
                assert_ne!(rebased.rebased_commit_sha, rebased.original_commit_sha);
            }
        }
    }

    // Fail-closed floor invariant, interleaving-INDEPENDENT: exactly ONE candidate
    // lands (the ff winner); every OTHER candidate required a rebase and is
    // fail-closed PARKED (conflict OR revalidation-owed) — a rebased tree is
    // NEVER auto-landed-as-validated. Nothing is lost or double-counted.
    assert_eq!(
        landed, 1,
        "exactly one candidate lands (the ff winner); every rebased candidate parks",
    );
    assert_eq!(
        landed + parked,
        n,
        "landed ({landed}) + parked ({parked}) must equal N ({n}) — nothing lost",
    );
    let winner_idx = winner_idx.expect("exactly one winner landed");

    let verify_candidates = candidates.clone();
    let verify_base = base_sha.clone();
    let facts = tokio::task::spawn_blocking(move || {
        collect_trunk_facts(&repo_path, &verify_base, &verify_candidates)
    })
    .await
    .expect("trunk verification task panicked");

    assert!(
        !facts.trunk_has_conflict,
        "the final trunk tree must be conflict-free",
    );
    assert!(
        facts.base_is_ancestor_of_trunk,
        "the trunk head must be a descendant of the shared base (valid ancestor chain)",
    );

    // Trunk carries EXACTLY the winner's file with its content; every other
    // candidate's contribution stayed PARKED (owed revalidation or conflict) and
    // never reached trunk.
    let winner = &candidates[winner_idx];
    for cand in &candidates {
        let got = facts.files.get(&cand.file).cloned().flatten();
        if cand.file == winner.file {
            assert_eq!(
                got.as_deref(),
                Some(winner.contents.as_str()),
                "the winner's file {} must be on trunk with its (validated) content",
                winner.file,
            );
        } else {
            assert!(
                got.is_none(),
                "non-winner file {} must be ABSENT from trunk (its candidate parked)",
                cand.file,
            );
        }
    }

    // Hold the repo + workspaces live through verification, then tear down.
    drop(prepared);
}

/// N=8 disjoint candidates fired concurrently: EXACTLY ONE fast-forwards and
/// lands; the other seven require a rebase and are fail-closed PARKED for
/// revalidation (never silently rebased-and-landed). No wedge, no lost work.
#[kata_test_utils::kata_timeout(secs = 160)]
#[tokio::test(flavor = "multi_thread")]
async fn jj_merge_queue_soak_8_disjoint_candidates_one_lands_rest_park() {
    run_soak(8, 0).await;
}

/// Heavier tier: N=16 disjoint candidates. One lands; the other fifteen park for
/// revalidation. Drains under the timeout with no lost work.
#[kata_test_utils::kata_timeout(secs = 160)]
#[tokio::test(flavor = "multi_thread")]
async fn jj_merge_queue_soak_16_disjoint_candidates_one_lands_rest_park() {
    run_soak(16, 0).await;
}

/// Conflict tier: 8 candidates, 3 of them contending on the same file. Exactly
/// one lands (ff winner); the other seven PARK — those whose rebase conflicts on
/// `shared.txt` with a typed conflict reason, the rest for revalidation.
/// landed + parked == 8 and trunk is never corrupted.
#[kata_test_utils::kata_timeout(secs = 160)]
#[tokio::test(flavor = "multi_thread")]
async fn jj_merge_queue_conflict_tier_one_lands_rest_park() {
    run_soak(8, 3).await;
}

/// Property flavor: a small deterministic matrix over N and the disjoint/conflict
/// mix. The interleaving-independent fail-closed invariant (`landed ∪ parked == all`;
/// exactly one ff winner; every rebased candidate fail-closed parked; trunk
/// conflict-free and a descendant of the base carrying only the winner's file)
/// holds across every combination.
#[kata_test_utils::kata_timeout(secs = 160)]
#[tokio::test(flavor = "multi_thread")]
async fn jj_merge_queue_invariant_matrix_holds_across_mixes() {
    for &(n, num_shared) in &[(2usize, 0usize), (4, 2), (5, 5), (8, 3), (12, 4)] {
        run_soak(n, num_shared).await;
    }
}
