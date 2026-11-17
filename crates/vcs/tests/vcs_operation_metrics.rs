//! Integration test: `kata-vcs` emits `kata_vcs_operation_duration_seconds`
//! histograms, labeled by `operation`, for every expensive jj code path.
//!
//! The `commit`, `snapshot`, `workspace_create`, `land`, `promote` and
//! `import` labels go through the shared `jj::record_vcs_op`
//! helper. This is the
//! RED->GREEN regression test that each emit site fires with the intended
//! `operation` label and non-vacuous samples.
//!
//! WHAT "NON-VACUOUS" MEANS. A collector predicate
//! `samples.iter().any(|s| s.into_inner() >= 0.0)` is vacuous: the only producer is [`kata_vcs`]'s
//! `record_vcs_op`, which records `started.elapsed().as_secs_f64()` — never negative, never NaN —
//! so that predicate is true of every value production can emit and the check collapses to "this
//! label registered at least one sample" — a constant `.record(0.0)` would leave it GREEN while the
//! histogram measured nothing. The predicate below is strictly positive and finite, which is the
//! weakest bound that the constant-recording mutant fails.
//!
//! `import` (the adopted-git HEAD/refs import) is the one label not driven here:
//! it fires only on a colocated/adopted git repo and shares the *identical*
//! `record_vcs_op("import", …)` wrapper as every label asserted below, so the
//! seven driven labels prove the helper's label plumbing; the `import` site is
//! additionally exercised by the adoption path and the live `/metrics` scrape.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use jj_lib::backend::CommitId;
use jj_lib::config::StackedConfig;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::RefNameBuf;
use jj_lib::repo::{Repo as _, StoreFactories};
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_types::AgentId;
use kata_vcs::{JjBackend, VcsBackend};
use ulid::Ulid;

fn agent() -> AgentId {
    AgentId(Ulid::new())
}

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

/// Point the `main` local bookmark at `commit_id` so the merge queue has a trunk
/// to fast-forward onto (mirrors the private helper in `jj_backend.rs`).
fn set_local_bookmark(repo_path: &Path, ref_name: &str, commit_id: &str) {
    let settings = UserSettings::from_config(StackedConfig::with_defaults()).unwrap();
    let workspace = Workspace::load(
        &settings,
        repo_path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .unwrap();
    let repo = futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap();
    let commit_id = CommitId::try_from_hex(commit_id).unwrap();
    repo.store().get_commit(&commit_id).unwrap();

    let mut tx = repo.start_transaction();
    let bookmark_name = RefNameBuf::from(ref_name.to_owned());
    tx.repo_mut()
        .set_local_bookmark_target(&bookmark_name, RefTarget::normal(commit_id));
    futures::executor::block_on(tx.commit(format!("test set bookmark {ref_name}"))).unwrap();
}

#[test]
fn jj_expensive_ops_emit_vcs_operation_duration_histogram() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    metrics::with_local_recorder(&recorder, || {
        // --- flow 1: raw VcsBackend surface — workspace_create / snapshot /
        //     commit ---
        let tmp = tempfile::TempDir::new().unwrap();
        let backend = open_declared(tmp.path());
        let aid = agent();
        // "workspace_create"
        let handle = VcsBackend::create_workspace(&backend, &aid).unwrap();

        fs::write(handle.workspace_path.join("tracked.txt"), "one\n").unwrap();

        // "snapshot" (workspace_status snapshots the working copy into `@`).
        VcsBackend::workspace_status(&backend, &aid).unwrap();

        // "commit"
        VcsBackend::commit(&backend, &aid, "baseline").unwrap();

        // --- flow 2: execution-workspace promote — drives "land" + "promote"
        //     (and another "workspace_create" / "snapshot" / "commit") ---
        let tmp2 = tempfile::TempDir::new().unwrap();
        let backend2 = open_declared(tmp2.path());
        let key = ExecutionWorkspaceKey::execution(Ulid::new());
        let ex_handle = kata_vcs::test_support::create_trunk_workspace(&backend2, &key).unwrap();
        let ex_agent = AgentId(key.execution_id);
        let initial = VcsBackend::workspace_status(&backend2, &ex_agent).unwrap();
        set_local_bookmark(
            tmp2.path(),
            "main",
            initial
                .head
                .base_commit_id
                .as_deref()
                .unwrap_or(initial.head.commit_id.as_str()),
        );
        fs::write(ex_handle.path.join("candidate.txt"), "candidate\n").unwrap();
        VcsBackend::commit(&backend2, &ex_agent, "promote candidate").unwrap();
        // "promote" (which lands the candidate through the merge queue → "land").
        ExecutionWorkspaceProvider::promote_workspace(
            &backend2,
            &key,
            &kata_types::execution::CandidateTreePin::Unpinned,
            None,
        )
        .unwrap();
    });

    // Collect every operation label that fired with a sample that MEASURED
    // something: strictly positive (a constant/zero recording fails) and finite
    // (a poisoned duration fails). Every asserted label wraps real jj work —
    // workspace create, snapshot, commit, land, promote — so
    // an elapsed time of exactly 0.0 at `Instant`'s nanosecond resolution would
    // itself be the defect.
    let mut fired: BTreeMap<String, bool> = BTreeMap::new();
    for (key, _unit, _desc, value) in snapshotter.snapshot().into_vec() {
        if key.key().name() != "kata_vcs_operation_duration_seconds" {
            continue;
        }
        let Some(operation) = key
            .key()
            .labels()
            .find(|l| l.key() == "operation")
            .map(|l| l.value().to_string())
        else {
            continue;
        };
        if let DebugValue::Histogram(samples) = value {
            let measured = samples
                .iter()
                .any(|s| s.into_inner() > 0.0 && s.into_inner().is_finite());
            let entry = fired.entry(operation).or_insert(false);
            *entry |= measured;
        }
    }

    for op in ["workspace_create", "snapshot", "commit", "land", "promote"] {
        assert_eq!(
            fired.get(op),
            Some(&true),
            "expected kata_vcs_operation_duration_seconds{{operation=\"{op}\"}} with a \
             strictly-positive, finite sample — a label that fires with a constant or \
             zero-valued recording measures nothing; fired = {fired:?}"
        );
    }
}
