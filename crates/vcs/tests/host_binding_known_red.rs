//! Proofs of what kata MUST do about two host bindings.
//!
//! Both are LIVE: no `#[ignore]`, run by `just gate` with every other test, so
//! `bin/kata-eval/tests/gate_exclusion.rs` needs no capability-conditional row
//! for this binary.
//!
//! * **TRUNK.** The trunk proofs run across `master` / `develop` /
//!   `release/next`; `kata_vcs::trunk::resolve_trunk` is what makes them green.
//! * **IDENTITY.** `jj_authored_commit_carries_the_repositorys_operator_identity`
//!   reads the author back from git; `kata_vcs::identity` is what makes it green
//!   (the defect's shape is `JJ_EMPTY_STRING <JJ_EMPTY_STRING>`).
//!
//! # Why these need an axis
//!
//! `kata_test_utils::git::HERMETIC_OVERRIDES` pins `init.defaultBranch = main`
//! and `user.name` / `user.email`. Every fixture repository in this workspace
//! therefore has a trunk named `main` and an identity nothing reads back unless
//! asked, so a suite of thousands of tests is structurally unable to fail on
//! either binding. `kata_test_utils::host_repo::HostBindings` is the axis that
//! varies them.

use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_test_utils::host_repo::{HostBindings, TRUNK_NAMES};
use kata_vcs::{JjBackend, VcsBackend as _};
use ulid::Ulid;

/// POSITIVE CONTROL: on a trunk-`main` repository the execution workspace really
/// is forked from trunk and the repository's files are materialized.
///
/// Without this, every proof in this file could be satisfied by a fixture that
/// simply does not work, and a real defect would be indistinguishable from a
/// broken harness.
#[test]
fn control_execution_workspace_materializes_trunk_when_the_repo_trunk_is_main() {
    let repo = HostBindings::new().init_git_repo();
    let backend = JjBackend::open(repo.path()).expect("adopt the fixture repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &key).expect("create workspace");

    assert!(
        handle.path.join("README.md").is_file(),
        "on a trunk-`main` repo the committed baseline MUST be materialized; if this \
         fails the fixture is broken and every proof in this file is meaningless"
    );

    let identity = ExecutionWorkspaceProvider::workspace_status(&backend, &key)
        .expect("workspace status")
        .expect("workspace exists")
        .identity
        .expect("jj status identity");
    assert_eq!(identity.base_ref.as_deref(), Some("main"));
    assert_eq!(
        identity.base_commit_sha.as_deref(),
        Some(repo.trunk_sha().as_str()),
        "the candidate must be based on the real trunk head"
    );
}

/// An execution workspace must be forked from the repository's OWN trunk.
///
/// THE DEFECT THIS REFUSES: a base bookmark hard-coded to `"main"` that, on a
/// repository whose trunk is anything else, silently leaves the agent's
/// workspace checked out at jj's EMPTY ROOT COMMIT — the agent runs against a
/// tree with none of the repository's files in it, and nothing reports a
/// problem.
///
/// `vcs.trunk` is rank 1 of `kata_vcs::trunk::resolve_trunk`, the
/// remote's own `HEAD` is rank 2, the one branch kata did not create is rank 3,
/// and anything else REFUSES. `JjBackend::base_workspace_on_trunk_named` goes
/// through it, and an absent trunk is two typed outcomes, never a silent `Ok(())`.
#[test]
fn jj_execution_workspace_is_forked_from_the_repositorys_own_trunk() {
    let mut failures = Vec::new();

    for trunk in TRUNK_NAMES {
        let repo = HostBindings::new().with_trunk(trunk).init_git_repo();
        let backend = JjBackend::open(repo.path()).expect("adopt the fixture repo");
        let key = ExecutionWorkspaceKey::execution(Ulid::new());
        let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key)
            .expect("create workspace");

        let materialized = handle.path.join("README.md").is_file();
        let identity = ExecutionWorkspaceProvider::workspace_status(&backend, &key)
            .expect("workspace status")
            .expect("workspace exists")
            .identity
            .expect("jj status identity");

        if !materialized {
            failures.push(format!(
                "trunk={trunk}: the repository's committed README.md is ABSENT from the \
                 execution workspace at {} — the candidate was forked from the empty root, \
                 so the agent sees none of the repository",
                handle.path.display()
            ));
        }
        if identity.base_ref.as_deref() != Some(*trunk) {
            failures.push(format!(
                "trunk={trunk}: workspace identity reports base_ref={:?}, which is not this \
                 repository's trunk (and for a non-`main` repo names a bookmark that does \
                 not exist)",
                identity.base_ref
            ));
        }
        if identity.base_commit_sha.as_deref() == Some(&"0".repeat(40)) {
            failures.push(format!(
                "trunk={trunk}: base_commit_sha is the all-zero id, i.e. the empty root \
                 commit; the real trunk head is {}",
                repo.trunk_sha()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} host-trunk failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// A `promote` must land on the repository's OWN trunk.
///
/// THE DEFECT THIS PROVES FIXED: `JjBackend::run_landing_ladder` resolved the
/// landing base by the same hard-coded `"main"`. On a repository whose trunk is
/// `master` the promote could not find a base at all, so a workflow that
/// validated and promoted cleanly reported a typed failure naming a bookmark
/// the operator never had.
///
/// The fork base and the landing base now come from ONE resolver called at ONE
/// place each — `base_workspace_on_trunk_named` and `run_landing_ladder` — so
/// they cannot be two literals that happen to agree.
#[test]
fn jj_promote_lands_on_the_repositorys_own_trunk() {
    let repo = HostBindings::new().with_trunk("master").init_git_repo();
    let trunk_before = repo.trunk_sha();

    let backend = JjBackend::open(repo.path()).expect("adopt the fixture repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &key).expect("create workspace");
    std::fs::write(handle.path.join("agent-output.txt"), "work\n").expect("agent writes");

    let promoted = ExecutionWorkspaceProvider::promote_workspace(
        &backend,
        &key,
        &kata_types::execution::CandidateTreePin::Unpinned,
        None,
    )
    .expect("promote must land on this repository's trunk");

    assert_eq!(
        promoted.ref_name,
        repo.trunk(),
        "the promotion must name the repository's own trunk"
    );
    assert_ne!(
        repo.trunk_sha(),
        trunk_before,
        "the repository's trunk must have advanced to the promoted candidate"
    );
    assert_eq!(repo.trunk_sha(), promoted.commit_sha);
}

/// A kata-authored commit must carry the repository's operator identity.
///
/// THE DEFECT THIS REFUSES: `UserSettings::from_config(StackedConfig::with_defaults())`
/// is exactly one config layer, jj's built-in `config/misc.toml`, which carries
/// `user.email = ""` and `user.name = ""`. No file, no environment, no repo
/// config. Every commit kata authored on it would be identity-less, and reaches git as jj-lib's
/// `EMPTY_STRING_PLACEHOLDER` (`JJ_EMPTY_STRING`) because git refuses an empty
/// ident field. `git log`, `git blame` and every forge attribute the work to
/// nobody.
///
/// The fixture declares the identity repo-locally, which is the layer a process
/// kata spawns can read.
///
/// `JjBackend::user_settings_at` folds ONE layer at jj's highest
/// precedence (`ConfigSource::CommandArg`) carrying the identity
/// `kata_vcs::identity::resolve_commit_identity` obtained by ASKING GIT about
/// this repository — `git -c user.useConfigOnly=true var GIT_AUTHOR_IDENT`,
/// which resolves the env layer, the system/global/local config layers and
/// `includeIf`, none of which a file read gets right. This test's own fixture is
/// the repo-LOCAL layer, and it is the one an `includeIf` would also land in.
#[test]
fn jj_authored_commit_carries_the_repositorys_operator_identity() {
    let repo = HostBindings::new()
        .with_identity("Ada Lovelace", "ada@example.invalid")
        .init_git_repo();
    let expected = repo
        .identity()
        .git_author_line()
        .expect("the fixture declared an identity");

    // NON-VACUOUS: the repository really does declare it, and its own history
    // carries it — so a failure below is about KATA, not about the fixture.
    assert_eq!(repo.commit_author("HEAD"), expected);

    let backend = JjBackend::open(repo.path()).expect("adopt the fixture repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    kata_vcs::test_support::create_trunk_workspace(&backend, &key).expect("create workspace");
    let candidate = ExecutionWorkspaceProvider::workspace_effect_candidate_commit(&backend, &key)
        .expect("the candidate reads")
        .expect("a live workspace's @ reads");

    // The `commit` effect is where kata authors a commit of its own.
    let committed = ExecutionWorkspaceProvider::commit_workspace_effect(
        &backend,
        &key,
        &candidate,
        "identity-cell-commit",
    )
    .expect("commit effect");

    assert_eq!(
        repo.commit_author(&committed.commit_sha),
        expected,
        "a kata-authored commit must carry the repository's operator identity"
    );
    assert_eq!(
        repo.commit_committer(&committed.commit_sha),
        expected,
        "...and so must its committer field"
    );
}
