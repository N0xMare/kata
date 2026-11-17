//! `kata init` must leave a first run that `kata doctor` calls green.
//!
//! # The defect this pins
//!
//! MEASURED against the real binary in a scratch git repository, without the
//! init-time ignore declarations:
//!
//! ```text
//! $ kata init
//! initialized kata project
//!   config: ./.kata/kata.toml
//!   data: ./.kata/data
//!   …
//! next:
//!   kata config check --config ./.kata/kata.toml
//!   kata doctor --config ./.kata/kata.toml
//!   …
//! $ kata doctor --config ./.kata/kata.toml
//! kata doctor: fail (failures=1 warnings=0)
//! [fail] target_repo_ignore  the target repository … does NOT ignore `.jj/` and
//!        `agents/` and `.kata/data/` …
//! Error: kata doctor found 1 failed check(s); fix them before running factory workflows
//! ```
//!
//! One of the three paths that row names — `.kata/data/` — exists only because
//! `kata init` chose where to put it, and it is a directory `kata init` itself
//! creates. init routed the operator straight
//! at a doctor that fails over init's own output, and said nothing about the
//! step in between. The very first thing a new operator does ends red.
//!
//! # Why the suite did not see it
//!
//! `doctor_init_tests::init_creates_valid_project_config_and_refuses_clobber`
//! already asserted `report.passed` after `kata init` — over a bare
//! `tempfile::tempdir()`. That directory is not inside a git repository, so
//! `git check-ignore` exits 128, the row WARNS "cannot verify", and a warning
//! does not sink the report. The green was real and measured the wrong shape:
//! no operator runs `kata init` outside their project's repository, which is
//! the only shape where the row can answer at all. These tests run it in the
//! shape operators have.
//!
//! # What is asserted, and what is deliberately not
//!
//! ASSERTED: after `kata init` inside a git repository, doctor's whole report
//! is green, the `target_repo_ignore` row PASSES, and the rule that decided
//! every declared root is a `.gitignore` line — so the row is green because
//! init made the property TRUE, not because the row could not look.
//!
//! NOT asserted: that `.gitignore` is the only acceptable home for those rules.
//! `rules_in_git_info_exclude_are_honored` (in
//! `doctor_target_repo_ignore_tests`) owns that axis; an operator who moves
//! kata's rules into `.git/info/exclude` stays correct, and init's write is a
//! default, not a requirement.

use std::path::{Path, PathBuf};

use kata::cli::testing::{DoctorStatus, doctor_report_with_logins_dir, no_kata_logins};
use kata::cli::{Cli, Command, OutputFormat};
use kata_test_utils::git::init_git_repo_at;

fn run_init(config: &Path, force: bool) {
    kata::cli::run(Cli {
        api_url: "http://127.0.0.1:8400".to_string(),
        format: OutputFormat::Human,
        command: Command::Init {
            config: config.to_path_buf(),
            force,
            print: false,
        },
    })
    .expect("kata init");
}

/// A `kata init` project whose `jj_repo = ".."` resolves to a real git
/// repository — the shape `kata init` produces when run inside the operator's
/// own checkout.
fn project_inside_a_git_repo() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path().to_path_buf();
    init_git_repo_at(&repo);
    let config = repo.join(".kata").join("kata.toml");
    run_init(&config, false);
    (dir, config, repo)
}

/// Every repo-relative path doctor scores for this config, read from the one
/// source of truth rather than retyped.
fn declared_paths(config: &Path) -> Vec<String> {
    let snapshot = kata_core::ConfigManager::load(config)
        .expect("the generated config loads")
        .snapshot();
    kata_workflow::repo_artifacts::repo_local_artifact_paths(
        &snapshot.vcs,
        snapshot.node.data_dir.as_path(),
    )
}

/// THE ASSERTION. A first run is honest: `kata init`, then the `kata doctor`
/// that init's own `next:` list routes to, and doctor is green.
#[test]
fn a_first_run_inside_a_git_repo_leaves_doctor_green() {
    let (_dir, config, _repo) = project_inside_a_git_repo();

    let report = doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config));
    let failing: Vec<&str> = report
        .checks
        .iter()
        .filter(|check| check.status == DoctorStatus::Fail)
        .map(|check| check.name)
        .collect();
    assert!(
        failing.is_empty(),
        "`kata init` routes the operator at `kata doctor`; doctor must not then fail over \
         state init created. Failing rows: {failing:?}\n{report:#?}"
    );
    assert_eq!(report.failure_count, 0);
    assert!(report.passed, "{report:#?}");
}

/// The row is green because the property HOLDS, not because git declined to
/// answer: every declared root must be decided by a rule init wrote.
#[test]
fn init_writes_the_ignore_rules_the_row_asks_for() {
    let (_dir, config, repo) = project_inside_a_git_repo();

    let gitignore = repo.join(".gitignore");
    assert!(
        gitignore.is_file(),
        "`kata init` must declare the paths it makes kata write into this repository"
    );
    let written = std::fs::read_to_string(&gitignore).expect("read .gitignore");

    // Derived, never retyped: the patterns are the ones doctor's remedy names,
    // for the roots the one source of truth declares.
    for root in declared_paths(&config) {
        assert!(
            written
                .lines()
                .any(|line| line.trim() == format!("/{root}/")),
            "`kata init` must ignore the declared root {root}; .gitignore was:\n{written}"
        );
    }

    let row = report_row(&config);
    assert_eq!(row.0, DoctorStatus::Pass, "message={}", row.1);
    assert!(
        row.2.iter().all(|line| line.contains(".gitignore:")),
        "every root must be decided by the file init wrote, or the row is green for a \
         reason init did not cause: {:#?}",
        row.2
    );
}

/// Re-running `kata init --force` must not accumulate duplicate rules. init
/// asks git what is ALREADY ignored and writes only what is missing, so the
/// second run writes nothing.
#[test]
fn re_running_init_does_not_duplicate_the_ignore_rules() {
    let (_dir, config, repo) = project_inside_a_git_repo();
    let gitignore = repo.join(".gitignore");
    let first = std::fs::read_to_string(&gitignore).expect("read .gitignore");

    run_init(&config, true);

    let second = std::fs::read_to_string(&gitignore).expect("read .gitignore");
    assert_eq!(
        first, second,
        "a second `kata init` must leave the operator's .gitignore byte-identical"
    );
}

/// An operator's existing `.gitignore` is theirs. init appends; it never
/// rewrites, reorders, or drops a line.
#[test]
fn init_appends_to_an_existing_gitignore_without_touching_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path().to_path_buf();
    init_git_repo_at(&repo);
    let gitignore = repo.join(".gitignore");
    let existing = "# the operator's own rules\n/target/\n*.log\n";
    std::fs::write(&gitignore, existing).expect("seed .gitignore");

    let config = repo.join(".kata").join("kata.toml");
    run_init(&config, false);

    let written = std::fs::read_to_string(&gitignore).expect("read .gitignore");
    assert!(
        written.starts_with(existing),
        "the operator's rules must survive verbatim and in order; got:\n{written}"
    );
    let report = doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config));
    assert_eq!(report.failure_count, 0, "{report:#?}");
}

/// A rule the operator already has, in the file kata does not own, must not be
/// re-added: init asks git, so `.git/info/exclude` counts.
#[test]
fn init_does_not_re_add_a_root_the_operator_already_ignores_elsewhere() {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path().to_path_buf();
    init_git_repo_at(&repo);
    let exclude = repo.join(".git").join("info").join("exclude");
    std::fs::create_dir_all(exclude.parent().expect("info dir")).expect("mkdir info");
    std::fs::write(&exclude, "/.jj/\n").expect("write exclude");

    let config = repo.join(".kata").join("kata.toml");
    run_init(&config, false);

    let written = std::fs::read_to_string(repo.join(".gitignore")).expect("read .gitignore");
    assert!(
        !written.lines().any(|line| line.trim() == "/.jj/"),
        "`.jj/` is already ignored via .git/info/exclude; init must not restate it:\n{written}"
    );
    let report = doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config));
    assert_eq!(report.failure_count, 0, "{report:#?}");
}

/// Degenerate, and it must stay quiet: a project directory that is not inside a
/// git repository has nothing to ignore and no repository to ask. `kata init`
/// must still succeed and must not create a `.gitignore` in a non-repository.
#[test]
fn init_outside_a_git_repo_writes_no_gitignore() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("project").join(".kata").join("kata.toml");
    run_init(&config, false);

    assert!(
        !dir.path().join("project").join(".gitignore").exists(),
        "there is no repository here to declare anything to"
    );
    // doctor warns "cannot verify" rather than failing.
    let (status, message, _) = report_row(&config);
    assert_eq!(status, DoctorStatus::Warn, "message={message}");
}

fn report_row(config: &Path) -> (DoctorStatus, String, Vec<String>) {
    let report = doctor_report_with_logins_dir(config, &[], no_kata_logins(config));
    let check = report
        .checks
        .iter()
        .find(|check| check.name == "target_repo_ignore")
        .unwrap_or_else(|| panic!("no `target_repo_ignore` row: {report:#?}"));
    (
        check.status,
        check.message.clone(),
        check.diagnostic.clone(),
    )
}
