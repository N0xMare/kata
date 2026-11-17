//! `ExecutionWorkspaceProvider::reap_terminal_workspaces` on the DEFAULT backend:
//! the jj provider (`VcsConfig::default()`) is the reaper
//! `boot::reap_terminal_workspaces_once` — startup plus hourly — calls on every
//! real run.
//!
//! ## What actually leaked, measured against the repository
//!
//! All four paths were driven end to end and the REPOSITORY observed (agents
//! dirs, jj bookmarks, `git for-each-ref`, `view().wc_commit_ids()`):
//!
//! | path | `agents/<exec>` | jj wc registration |
//! |---|---|---|
//! | terminal `promote` | removed | removed |
//! | terminal `park` | removed | removed |
//! | non-terminal `commit` | **LEAKS** | **LEAKS** |
//! | no `workspace_effect` at all | **LEAKS** | **LEAKS** |
//!
//! So the leak is exactly the runs that reach a terminal state through NEITHER
//! terminal effect — and those accumulate once per run, forever.
//!
//! ## The half that matters more than the reclamation
//!
//! Under-reclaiming is a disk-space bug; over-reclaiming destroys an operator's
//! work. Three of these tests exist to pin what the reaper must NOT do: a PARKED
//! candidate's ref is deliberately preserved work, an IN-FLIGHT execution's
//! workspace is what recovery replays into, and an `exec-<id>` ref outlives its
//! workspace ON PURPOSE (it is the only thing keeping a `commit` effect's
//! published commit reachable once the non-terminal workspace is gone).

use std::path::Path;
use std::time::Duration;

use jj_lib::config::StackedConfig;
use jj_lib::repo::{ReadonlyRepo, StoreFactories};
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_effects_contract::{
    ExecutionLiveness, ExecutionWorkspaceKey, ExecutionWorkspaceProvider,
    TerminalWorkspaceReapPolicy,
};
use kata_types::time::now_ms;
use kata_vcs::{JjBackend, VcsBackend};
use ulid::Ulid;

// ----- observers: the REPOSITORY, never kata's own records ------------------

fn load_repo(repo: &Path) -> std::sync::Arc<ReadonlyRepo> {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        repo,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap()
}

/// Every local bookmark in the jj view. The reaper must never shrink this.
fn jj_bookmarks(repo: &Path) -> Vec<String> {
    let mut v: Vec<String> = load_repo(repo)
        .view()
        .local_bookmarks()
        .map(|(name, _)| name.as_str().to_owned())
        .collect();
    v.sort();
    v
}

/// Every ref in the colocated `.git` — what an operator and any git tool read.
fn git_refs(repo: &Path) -> Vec<String> {
    let out = kata_test_utils::git::hermetic_git_in(repo)
        .args(["for-each-ref", "--format=%(refname)"])
        .output()
        .unwrap();
    let mut v: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    v.sort();
    v
}

/// Immediate children of `<repo>/agents/`.
fn agents_entries(repo: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(repo.join("agents")) else {
        return Vec::new();
    };
    let mut v: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    v.sort();
    v
}

/// The jj working copies the SHARED REPO still believes exist. A directory
/// removed without forgetting this leaves the repo carrying a phantom working
/// copy, so reclamation has to be judged on both.
fn jj_workspace_registrations(repo: &Path) -> Vec<String> {
    let mut v: Vec<String> = load_repo(repo)
        .view()
        .wc_commit_ids()
        .keys()
        .map(|name| name.as_str().to_owned())
        .collect();
    v.sort();
    v
}

const TERMINAL_NOW: TerminalWorkspaceReapPolicy = TerminalWorkspaceReapPolicy {
    terminal_ttl: Duration::ZERO,
    unknown_ttl: Duration::ZERO,
    terminal_grace: Duration::ZERO,
};

fn repo_fixture(tmp: &tempfile::TempDir) -> (std::path::PathBuf, JjBackend) {
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    let backend = JjBackend::open(&repo).unwrap();
    (repo, backend)
}

/// A run whose graph ends in a NON-terminal `commit` effect: the leak shape.
/// Returns its key and the `exec-<id>` ref the commit published.
fn leaked_run_with_commit_effect(
    backend: &JjBackend,
    file: &str,
) -> (ExecutionWorkspaceKey, String) {
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(backend, &key).unwrap();
    std::fs::write(handle.path.join(file), "agent work\n").unwrap();
    VcsBackend::commit(
        backend,
        &kata_types::AgentId(key.execution_id),
        "agent work",
    )
    .unwrap();
    let candidate = ExecutionWorkspaceProvider::workspace_effect_candidate_commit(backend, &key)
        .unwrap()
        .expect("a live workspace's @ reads");
    let committed = ExecutionWorkspaceProvider::commit_workspace_effect(
        backend,
        &key,
        &candidate,
        "leaked-commit",
    )
    .unwrap();
    (key, committed.ref_name)
}

// ----- 1. the leak, and the ref that must outlive its workspace -------------

#[test]
fn a_leaked_non_terminal_workspace_is_reclaimed_and_its_exec_ref_survives() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo, backend) = repo_fixture(&tmp);

    let (key, exec_ref) = leaked_run_with_commit_effect(&backend, "work.txt");
    let dir = key.execution_id.to_string();
    let workspace_name = format!("agent-{}", key.execution_id);

    // THE LEAK, stated against the repository before anything reclaims it.
    assert!(
        agents_entries(&repo).contains(&dir),
        "a run ending in a non-terminal `commit` leaves its workspace dir standing"
    );
    assert!(
        jj_workspace_registrations(&repo).contains(&workspace_name),
        "...and the shared repo still carries its working-copy registration"
    );

    let reaped =
        ExecutionWorkspaceProvider::reap_terminal_workspaces(&backend, TERMINAL_NOW, &|_| {
            ExecutionLiveness::Terminal {
                terminal_since_ms: Some(0),
            }
        })
        .unwrap();

    assert_eq!(
        reaped, 1,
        "the jj provider's reaper must reclaim the leaked workspace. `0` here is the shipped \
         defect: the trait's `Ok(0)` default stood on the DEFAULT backend, so boot's startup + \
         hourly sweep reclaimed nothing, permanently"
    );
    assert!(
        !agents_entries(&repo).contains(&dir),
        "the leaked workspace dir must be gone"
    );
    assert!(
        !jj_workspace_registrations(&repo).contains(&workspace_name),
        "and the shared repo must not keep a phantom working copy for it"
    );

    // The REF and the WORKSPACE have different lifetimes. `exec-<id>` is the
    // only thing keeping the commit this run published reachable now that the
    // workspace is gone — reaping it alongside the dir would be the data-loss
    // defect this reaper exists to avoid.
    assert!(
        jj_bookmarks(&repo).contains(&exec_ref),
        "the `exec-<id>` bookmark must SURVIVE the reap: it is the sole reachability anchor for \
         the commit the run published, which is exactly why the `commit` effect creates it"
    );
    assert!(
        git_refs(&repo).contains(&format!("refs/heads/{exec_ref}")),
        "and it must survive in the colocated `.git`, which is where an operator reads it"
    );
}

// ----- 2. in flight: never, at any age -------------------------------------

#[test]
fn an_in_flight_execution_workspace_is_never_reaped() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo, backend) = repo_fixture(&tmp);

    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    std::fs::write(
        handle.path.join("in-flight.txt"),
        "uncommitted agent work\n",
    )
    .unwrap();
    let dir = key.execution_id.to_string();

    // The most aggressive policy expressible: no TTL, no grace. Only the
    // durable liveness verdict stands between this workspace and deletion.
    let reaped =
        ExecutionWorkspaceProvider::reap_terminal_workspaces(&backend, TERMINAL_NOW, &|_| {
            ExecutionLiveness::Live
        })
        .unwrap();

    assert_eq!(reaped, 0, "a LIVE execution is never reaped, at any age");
    assert!(
        agents_entries(&repo).contains(&dir),
        "an in-flight execution's workspace is exactly what recovery replays into; reaping it \
         breaks resume"
    );
    assert_eq!(
        std::fs::read_to_string(handle.path.join("in-flight.txt")).unwrap(),
        "uncommitted agent work\n",
        "and the agent's UNCOMMITTED disk state must still be there — it exists nowhere else"
    );
    assert!(
        jj_workspace_registrations(&repo).contains(&format!("agent-{}", key.execution_id)),
        "the working-copy registration must stand too, or the workspace is unusable on resume"
    );
}

// ----- 3. a parked candidate is preserved work -----------------------------

#[test]
fn the_reaper_deletes_no_ref_and_a_parked_candidate_is_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo, backend) = repo_fixture(&tmp);

    // A parked candidate: `park_workspace` already removed its workspace, so
    // what stands is the deliberately-preserved `parked/<id>` ref.
    let parked_key = ExecutionWorkspaceKey::execution(Ulid::new());
    let parked_handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &parked_key).unwrap();
    std::fs::write(parked_handle.path.join("rescued.txt"), "the agent's work\n").unwrap();
    let parked =
        ExecutionWorkspaceProvider::park_workspace(&backend, &parked_key, Some("needs-review"))
            .unwrap();

    // ...and the crash window in which a park's ref exists while a workspace
    // for that same execution is still on disk. The DIR is reclaimable there
    // (the work is safe in the ref); the REF never is.
    kata_vcs::test_support::create_trunk_workspace(&backend, &parked_key).unwrap();
    // Plus an ordinary leak, so the sweep has something to do and a green here
    // cannot come from a reaper that simply did nothing.
    let (leaked_key, exec_ref) = leaked_run_with_commit_effect(&backend, "leak.txt");

    let bookmarks_before = jj_bookmarks(&repo);
    let git_refs_before = git_refs(&repo);
    assert!(bookmarks_before.contains(&parked.ref_name));

    let reaped =
        ExecutionWorkspaceProvider::reap_terminal_workspaces(&backend, TERMINAL_NOW, &|_| {
            ExecutionLiveness::Terminal {
                terminal_since_ms: Some(0),
            }
        })
        .unwrap();
    assert_eq!(reaped, 2, "both standing workspace dirs are reclaimable");

    assert_eq!(
        jj_bookmarks(&repo),
        bookmarks_before,
        "the reaper must delete NO ref. Parking exists precisely so a failed revalidation does \
         not lose the agent's changes; reaping `{}` would destroy them, and retiring it is the \
         operator's call, not a sweep's",
        parked.ref_name
    );
    assert_eq!(
        git_refs(&repo),
        git_refs_before,
        "and no ref may vanish from the colocated `.git` either"
    );

    // The parked commit is still resolvable, which is the property the ref is
    // for — not merely that a name is present.
    let observed = ExecutionWorkspaceProvider::lookup_parked_workspace(
        &backend,
        &parked_key,
        &parked.ref_name,
    )
    .unwrap()
    .expect("the parked candidate must still resolve after a reap");
    assert_eq!(observed.commit_sha, parked.commit_sha);

    // Both dirs really did go.
    let entries = agents_entries(&repo);
    assert!(!entries.contains(&parked_key.execution_id.to_string()));
    assert!(!entries.contains(&leaked_key.execution_id.to_string()));
    assert!(jj_bookmarks(&repo).contains(&exec_ref));
}

// ----- 4/5. what the sweep must refuse to walk -----------------------------

#[test]
fn the_reaper_refuses_anything_it_cannot_prove_kata_created() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo, backend) = repo_fixture(&tmp);
    let agents = repo.join("agents");

    // A leak, so the sweep genuinely runs.
    let (leaked_key, _) = leaked_run_with_commit_effect(&backend, "leak.txt");

    // A ULID-named directory with no `.jj`: kata cannot prove it created this,
    // and the teardown ends in `remove_dir_all`. Refuse.
    let impostor = agents.join(Ulid::new().to_string());
    std::fs::create_dir_all(&impostor).unwrap();
    std::fs::write(impostor.join("operator-notes.md"), "not kata's\n").unwrap();

    // And something not even ULID-shaped.
    let operator_dir = agents.join("notes");
    std::fs::create_dir_all(&operator_dir).unwrap();
    std::fs::write(operator_dir.join("README"), "operator's\n").unwrap();

    let reaped =
        ExecutionWorkspaceProvider::reap_terminal_workspaces(&backend, TERMINAL_NOW, &|_| {
            ExecutionLiveness::Terminal {
                terminal_since_ms: Some(0),
            }
        })
        .unwrap();

    assert_eq!(
        reaped, 1,
        "exactly the one leaked execution workspace — nothing else under `<agents>` is this \
         sweep's to claim"
    );
    assert!(!agents_entries(&repo).contains(&leaked_key.execution_id.to_string()));
    assert!(
        impostor.join("operator-notes.md").exists(),
        "a ULID-named dir with no `.jj` is not provably kata's; refusing costs an empty dir left \
         by a crash mid-create, reaping could delete an operator's files"
    );
    assert!(operator_dir.join("README").exists());
}

// ----- 6/7. the two age gates are distinct, and grace is real --------------

#[test]
fn unknown_liveness_waits_the_longer_ttl_and_terminal_waits_out_its_grace() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo, backend) = repo_fixture(&tmp);
    let (key, _) = leaked_run_with_commit_effect(&backend, "leak.txt");
    let dir = key.execution_id.to_string();

    // UNKNOWN is not terminal PROOF, so the longer `unknown_ttl` applies — even
    // where `terminal_ttl` would already permit the reap.
    let split = TerminalWorkspaceReapPolicy {
        terminal_ttl: Duration::ZERO,
        unknown_ttl: Duration::from_secs(3600),
        terminal_grace: Duration::ZERO,
    };
    assert_eq!(
        ExecutionWorkspaceProvider::reap_terminal_workspaces(&backend, split, &|_| {
            ExecutionLiveness::Unknown
        })
        .unwrap(),
        0,
        "an execution the durable store cannot vouch for waits the longer TTL"
    );
    assert!(agents_entries(&repo).contains(&dir));

    // A terminal transition that only just happened is inside the grace: the
    // normal promote/park teardown owns that window and the sweep must not race
    // it.
    let graced = TerminalWorkspaceReapPolicy {
        terminal_ttl: Duration::ZERO,
        unknown_ttl: Duration::ZERO,
        terminal_grace: Duration::from_secs(3600),
    };
    assert_eq!(
        ExecutionWorkspaceProvider::reap_terminal_workspaces(&backend, graced, &|_| {
            ExecutionLiveness::Terminal {
                terminal_since_ms: Some(now_ms()),
            }
        })
        .unwrap(),
        0,
        "a just-terminal run is inside the grace window"
    );
    assert!(agents_entries(&repo).contains(&dir));

    // Same execution, same directory: only the verdict changed.
    assert_eq!(
        ExecutionWorkspaceProvider::reap_terminal_workspaces(&backend, graced, &|_| {
            ExecutionLiveness::Terminal {
                terminal_since_ms: Some(0),
            }
        })
        .unwrap(),
        1,
        "past the grace it is reclaimable"
    );
    assert!(!agents_entries(&repo).contains(&dir));
}

// ----- the sweep must survive a repository that has never run anything ------

#[test]
fn a_repository_with_no_agents_root_reaps_nothing_without_failing() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo, backend) = repo_fixture(&tmp);
    assert!(!repo.join("agents").exists());
    assert_eq!(
        ExecutionWorkspaceProvider::reap_terminal_workspaces(&backend, TERMINAL_NOW, &|_| {
            ExecutionLiveness::Terminal {
                terminal_since_ms: Some(0),
            }
        })
        .unwrap(),
        0,
        "a node that has never created an execution workspace has no `<agents>` root; nothing to \
         reap is not a failure, and an `Err` here would log a scary warning at every boot"
    );
}
