//! `kata doctor`'s `trunk_resolution` row: kata must say, before anything is
//! spent, which branch it would treat as this repository's trunk.
//!
//! # The defect these tests pin
//!
//! kata hard-coded trunk as the literal `"main"`. On a repository whose trunk
//! was `master`, `create_workspace` returned `Ok` with the agent's workspace
//! checked out at jj's EMPTY ROOT — none of the repository visible — and the run
//! failed at its LAST stage, after the model spend. doctor, whose entire job is
//! first-run readiness, reported PASS the whole time.
//!
//! # Whose environment this measures
//!
//! The DAEMON's. Every arm below points `vcs.jj_repo` at a repository and reads
//! `vcs.trunk` from the config a node would boot with. Nothing here consults the
//! process CWD, and nothing consults git `HEAD` — which (measured, git 2.43.0)
//! names an unborn branch in an empty repository and the operator's feature
//! branch whenever one is checked out.
//!
//! # Hermeticity
//!
//! Fixtures come from `kata_test_utils::host_repo::HostBindings`, the axis that
//! varies ONE host binding on purpose while every `HERMETIC_OVERRIDES` pin stays
//! exactly where it is.

use std::path::{Path, PathBuf};

use kata::cli::testing::{DoctorStatus, doctor_report_with_logins_dir, no_kata_logins};
use kata::cli::{Cli, Command, OutputFormat};
use kata_test_utils::host_repo::{HostBindings, HostRepo};

/// A `kata init` project whose `jj_repo = ".."` resolves to `repo`.
fn project_in(repo: &Path) -> PathBuf {
    let config = repo.join(".kata").join("kata.toml");
    kata::cli::run(Cli {
        api_url: "http://127.0.0.1:8400".to_string(),
        format: OutputFormat::Human,
        command: Command::Init {
            config: config.clone(),
            force: false,
            print: false,
        },
    })
    .expect("kata init");
    config
}

fn trunk_row(config: &Path) -> (DoctorStatus, String, Vec<String>) {
    let report = doctor_report_with_logins_dir(config, &[], no_kata_logins(config));
    let check = report
        .checks
        .iter()
        .find(|check| check.name == "trunk_resolution")
        .unwrap_or_else(|| {
            panic!(
                "kata doctor published no `trunk_resolution` row; rows were {:?}",
                report
                    .checks
                    .iter()
                    .map(|check| check.name)
                    .collect::<Vec<_>>()
            )
        });
    (
        check.status,
        check.message.clone(),
        check.diagnostic.clone(),
    )
}

/// Append `key = value` to the `[vcs]` table of a `kata init` config.
fn set_vcs_key(config: &Path, line: &str) {
    let text = std::fs::read_to_string(config).expect("read config");
    let patched = text.replacen("[vcs]\n", &format!("[vcs]\n{line}\n"), 1);
    assert_ne!(
        patched, text,
        "`kata init` no longer writes a `[vcs]` table"
    );
    std::fs::write(config, patched).expect("write config");
}

/// GREEN: a repository with one branch resolves, whatever that branch is named.
///
/// Without the row, doctor publishes nothing at all, so a `master` repository
/// kata could not work on scores a clean report.
#[test]
fn a_single_branch_repository_resolves_whatever_the_branch_is_called() {
    for trunk in ["main", "master", "develop", "release/next"] {
        let repo: HostRepo = HostBindings::new().with_trunk(trunk).init_git_repo();
        let config = project_in(repo.path());
        let (status, message, diagnostic) = trunk_row(&config);
        assert_eq!(
            status,
            DoctorStatus::Pass,
            "trunk={trunk}: {message} / {diagnostic:?}"
        );
        assert!(
            message.contains(&format!("`{trunk}`")),
            "trunk={trunk}: the row must NAME the trunk it resolved: {message}"
        );
        assert!(
            diagnostic
                .iter()
                .any(|line| line.contains("sole_local_branch")),
            "trunk={trunk}: the row must say WHICH rank answered: {diagnostic:?}"
        );
    }
}

/// FAIL: several operator branches and no remote default is not an answer.
///
/// This is the row's whole reason to exist — kata refuses such a repository at
/// `create_workspace`, and before this row an operator learned that by watching
/// a run die.
#[test]
fn an_ambiguous_repository_fails_and_names_both_remedies() {
    let repo = HostBindings::new().with_trunk("master").init_git_repo();
    repo.run_git(&["branch", "develop"]);
    let config = project_in(repo.path());

    let (status, message, _) = trunk_row(&config);
    assert_eq!(status, DoctorStatus::Fail, "{message}");
    assert!(
        message.contains("cannot tell which branch is trunk"),
        "{message}"
    );
    assert!(message.contains("vcs.trunk"), "{message}");
    assert!(message.contains("git remote set-head origin"), "{message}");
    assert!(
        message.contains("master") && message.contains("develop"),
        "the refusal must name the candidates it could not choose between: {message}"
    );
}

/// ...and `vcs.trunk` resolves it. Rank 1 is the operator's declaration: the
/// user decides, and kata stops asking.
#[test]
fn vcs_trunk_resolves_an_otherwise_ambiguous_repository() {
    let repo = HostBindings::new().with_trunk("master").init_git_repo();
    repo.run_git(&["branch", "develop"]);
    let config = project_in(repo.path());
    set_vcs_key(&config, r#"trunk = "develop""#);

    let (status, message, diagnostic) = trunk_row(&config);
    assert_eq!(status, DoctorStatus::Pass, "{message}");
    assert!(message.contains("`develop`"), "{message}");
    assert!(
        diagnostic.iter().any(|line| line.contains("configured")),
        "{diagnostic:?}"
    );
}

/// A configured trunk that does not exist is a FAIL, not a silent fallback.
///
/// The shipped behaviour for "the named trunk is absent" was `Ok(())` and an
/// empty workspace. Refusing here is the same decision one layer earlier.
#[test]
fn a_configured_trunk_that_does_not_exist_fails() {
    let repo = HostBindings::new().with_trunk("master").init_git_repo();
    let config = project_in(repo.path());
    set_vcs_key(&config, r#"trunk = "nonesuch""#);

    let (status, message, _) = trunk_row(&config);
    assert_eq!(status, DoctorStatus::Fail, "{message}");
    assert!(message.contains("nonesuch"), "{message}");
    assert!(
        message.contains("does not have"),
        "the row must say the branch is absent, not merely that something failed: {message}"
    );
}

/// kata's OWN refs must not make a repository ambiguous — the rank-3 trap.
///
/// A resolver counting all local branches would pass on a fresh repository and
/// FAIL this one, which is what an operator's repository looks like after a
/// single `park`.
#[test]
fn katas_own_refs_do_not_make_doctor_report_ambiguity() {
    let repo = HostBindings::new().with_trunk("master").init_git_repo();
    for kata_ref in [
        "exec-01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "parked/01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "kata/01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ] {
        repo.run_git(&["branch", kata_ref, "master"]);
    }
    // NON-VACUOUS: the repository really does hold four branches.
    assert_eq!(repo.branch_refs().len(), 4);

    let config = project_in(repo.path());
    let (status, message, _) = trunk_row(&config);
    assert_eq!(status, DoctorStatus::Pass, "{message}");
    assert!(message.contains("`master`"), "{message}");
}

/// A repository with no branch at all WARNS: a run can start (there is nothing
/// to fork) but nothing can land. Two different states, two different verdicts —
/// the same split `base_workspace_on_trunk_named` now makes.
#[test]
fn a_repository_with_no_branches_warns_rather_than_failing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path().to_path_buf();
    let out = kata_test_utils::git::hermetic_git_in(&repo)
        .args(["init", "-q", "-b", "master"])
        .output()
        .expect("git init");
    assert!(out.status.success());

    let config = project_in(&repo);
    let (status, message, _) = trunk_row(&config);
    assert_eq!(status, DoctorStatus::Warn, "{message}");
    assert!(message.contains("no trunk yet"), "{message}");
    assert!(
        message.contains("promote"),
        "the warning must say what it costs — nothing can LAND: {message}"
    );
}
