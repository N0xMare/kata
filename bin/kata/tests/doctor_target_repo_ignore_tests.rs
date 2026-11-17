//! `kata doctor`'s `target_repo_ignore` row: kata must not pollute the
//! repository it is pointed at.
//!
//! # The defect these tests pin
//!
//! kata writes `.jj/` and `agents/<exec>/` INSIDE
//! `vcs.jj_repo` — which `kata init` sets to the operator's own project root.
//! kata's `.gitignore` names them with a
//! comment describing exactly this case, so kata REQUIRED the property; nothing
//! verified it. The first live `gold-loop` run promoted 46 files / 333
//! insertions of those internals into a fixture repository's trunk while every
//! stage reported green.
//!
//! # Hermeticity
//!
//! Every fixture repo is built by [`kata_test_utils::git::init_git_repo_at`],
//! which writes `HERMETIC_OVERRIDES` repo-locally. `core.excludesFile` is in
//! that set because of THIS suite: measured (git 2.43.0), a global
//! excludes file naming `.jj/` makes `git check-ignore` report those paths
//! ignored in a repo with no `.gitignore` at all, so the RED arm below would
//! have passed on such a host for a reason unrelated to the fixture.

use std::path::{Path, PathBuf};

use kata::cli::testing::{DoctorStatus, doctor_report_with_logins_dir, no_kata_logins};
use kata::cli::{Cli, Command, OutputFormat};
use kata_test_utils::git::init_git_repo_at;

/// A `kata init` project whose `jj_repo = ".."` resolves to a real git
/// repository — the shape `kata init` produces when run inside the operator's
/// own checkout, which is the shape the gold-loop run used.
fn project_inside_a_git_repo() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path().to_path_buf();
    init_git_repo_at(&repo);
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
    (dir, config, repo)
}

/// Undo the `.gitignore` `kata init` writes, leaving a repository that ignores
/// NOTHING kata writes into it.
///
/// `kata init` declares kata's artifact roots itself
/// (`cli::init::declare_kata_artifacts_in_gitignore`), because otherwise the
/// first run it produces would route the operator at a `kata doctor` that fails
/// over state init had just created. That is the right default and it is proved by
/// `init_first_run_is_green_tests`.
///
/// It also means `project_inside_a_git_repo()` alone cannot produce the
/// unignored fixture THIS suite is about. The arms below are not about init;
/// they are about whether the ROW has teeth, whether its printed remedy works,
/// and where a rule may live — properties that must hold for any repository, an
/// operator's pre-existing one included. So the fixture states its premise
/// explicitly instead of inheriting it.
fn forget_the_ignore_rules_init_wrote(repo: &Path) {
    let gitignore = repo.join(".gitignore");
    if gitignore.exists() {
        std::fs::remove_file(&gitignore).expect("remove the .gitignore kata init wrote");
    }
    assert!(
        !gitignore.exists(),
        "the fixture must start with no .gitignore"
    );
}

/// Every repo-relative path `kata doctor` scores for this config, read from the
/// one source of truth. A test that retypes the list stops testing the row and
/// starts testing its own copy of it.
fn declared_paths(config: &Path) -> Vec<String> {
    let snapshot = kata_core::ConfigManager::load(config)
        .expect("the generated config loads")
        .snapshot();
    kata_workflow::repo_artifacts::repo_local_artifact_paths(
        &snapshot.vcs,
        snapshot.node.data_dir.as_path(),
    )
}

fn ignore_row(config: &Path) -> (DoctorStatus, String, Vec<String>) {
    let report = doctor_report_with_logins_dir(config, &[], no_kata_logins(config));
    let check = report
        .checks
        .iter()
        .find(|check| check.name == "target_repo_ignore")
        .unwrap_or_else(|| {
            panic!(
                "kata doctor published no `target_repo_ignore` row; rows were {:?}",
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

/// Parse the ignore patterns out of the remedy the FAILING row prints, so the
/// green arm applies what an operator would actually type rather than a second
/// hand-kept list beside it.
fn patterns_the_remedy_names(message: &str) -> Vec<String> {
    let (_, rest) = message
        .split_once("Add `")
        .expect("the remedy starts with ``Add `<pattern>`''");
    let (list, _) = rest
        .split_once("` to ")
        .expect("the remedy's pattern list is terminated by `` ` to ''");
    list.split("` and `")
        .map(|pattern| pattern.trim().to_string())
        .filter(|pattern| !pattern.is_empty())
        .collect()
}

/// RED before this row existed: a repository that does not ignore what kata
/// writes into it is exactly the fixture the first live gold-loop run used, and
/// `kata doctor` reported it green.
///
/// The row must FAIL, not warn: the failure mode is kata's internals committed
/// into a repository kata does not own, which doctor cannot undo afterwards.
#[test]
fn a_target_repo_that_ignores_nothing_fails_doctor() {
    let (_dir, config, repo) = project_inside_a_git_repo();
    forget_the_ignore_rules_init_wrote(&repo);

    let (status, message, diagnostic) = ignore_row(&config);
    assert_eq!(
        status,
        DoctorStatus::Fail,
        "message={message}\ndiagnostic={diagnostic:#?}"
    );
    for root in [".jj", "agents"] {
        assert!(
            diagnostic
                .iter()
                .any(|line| line.starts_with(&format!("{root}/")) && line.contains("NOT ignored")),
            "the row must NAME the offending root {root}; diagnostic={diagnostic:#?}"
        );
    }
    assert!(
        message.contains(&repo.display().to_string()),
        "the row must name the repository it is talking about: {message}"
    );

    // A failing row must sink the whole report, or it is an advisory wearing a
    // `[fail]` label.
    let report = doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config));
    assert!(!report.passed, "report should be red: {report:#?}");
}

/// GREEN after: doing exactly what the failing row SAYS clears it.
///
/// This does not compare two strings — it applies the remedy parsed out of the
/// failure message and re-asks the real check, so a remedy that drifts from the
/// check fails here however it is worded.
#[test]
fn following_the_remedy_the_row_prints_clears_the_row() {
    let (_dir, config, repo) = project_inside_a_git_repo();
    forget_the_ignore_rules_init_wrote(&repo);
    let (status, message, _) = ignore_row(&config);
    assert_eq!(status, DoctorStatus::Fail, "precondition");

    let patterns = patterns_the_remedy_names(&message);
    assert!(
        patterns.len() >= 2,
        "the remedy must name every offending root; parsed {patterns:?} from {message}"
    );
    std::fs::write(
        repo.join(".gitignore"),
        format!("{}\n", patterns.join("\n")),
    )
    .expect("write .gitignore");

    let (status, message, diagnostic) = ignore_row(&config);
    assert_eq!(
        status,
        DoctorStatus::Pass,
        "the remedy kata printed must clear the row it came from\nmessage={message}\n\
         diagnostic={diagnostic:#?}"
    );
    for line in &diagnostic {
        assert!(
            line.contains(".gitignore:"),
            "a passing row must still name WHICH rule decided each root: {line}"
        );
    }
}

/// The measured trap, pinned.
///
/// `git check-ignore .jj` answers NOT IGNORED against the pattern `.jj/`
/// whenever `.jj` does not exist on disk (git 2.43.0) — a directory-only pattern
/// cannot match a path git has no reason to believe is a directory. Every repo
/// doctor runs against BEFORE first boot is in that state, which is doctor's
/// entire audience, so a check that named the bare directory would have failed
/// correctly-configured repositories: a refused set WIDER than the claim.
///
/// This fixture uses kata's OWN directory-only spellings and creates NONE of the
/// directories. COUNTERFACTUAL: drop `/{IGNORE_PROBE_LEAF}/{IGNORE_PROBE_LEAF}`
/// from the probe path in `push_target_repo_ignore_check` and this goes red.
///
/// The patterns are DERIVED from the declared set, not typed: this test wrote
/// `.jj/` and `/agents/` verbatim and went red the day the declared set grew,
/// for a reason that has nothing to do with what it measures. What it owns is
/// the trailing-slash trap, and that is a property of every root.
#[test]
fn directory_only_patterns_pass_before_the_directories_exist() {
    let (_dir, config, repo) = project_inside_a_git_repo();
    let declared = declared_paths(&config);
    // Every pattern is directory-only (trailing `/`), which is the trap.
    let gitignore = declared
        .iter()
        .map(|path| format!("/{path}/"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(repo.join(".gitignore"), format!("{gitignore}\n")).expect("write .gitignore");
    // The trap only bites a path git has no reason to believe is a directory, so
    // the precondition is that the PROVIDER roots are absent — none of them is
    // created before first boot. `node.data_dir` is exempt and must be: `kata
    // init` creates it, which is precisely why it cannot carry this proof.
    for root in kata_workflow::repo_artifacts::repo_local_artifact_roots() {
        assert!(
            !repo.join(root).exists(),
            "fixture must not have booted: {root} exists"
        );
    }

    let (status, message, diagnostic) = ignore_row(&config);
    assert_eq!(
        status,
        DoctorStatus::Pass,
        "message={message}\ndiagnostic={diagnostic:#?}"
    );
}

/// Asking git rather than string-matching `.gitignore` is the whole point: an
/// operator who keeps kata's rules out of the shared, committed `.gitignore` and
/// in their own `.git/info/exclude` is correctly configured, and a text scan
/// would call them broken.
#[test]
fn rules_in_git_info_exclude_are_honored() {
    let (_dir, config, repo) = project_inside_a_git_repo();
    // `.git/info/exclude` must be the ONLY rule source, or this measures which
    // file git prefers rather than whether it honours the exclude at all.
    forget_the_ignore_rules_init_wrote(&repo);
    let exclude = repo.join(".git").join("info").join("exclude");
    std::fs::create_dir_all(exclude.parent().expect("info dir")).expect("mkdir info");
    // Derived from the declared set, for the reason
    // `directory_only_patterns_pass_before_the_directories_exist` states: what
    // this test owns is WHERE the rule lives, not which roots there are.
    let rules = declared_paths(&config)
        .iter()
        .map(|path| format!("/{path}/"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&exclude, format!("{rules}\n")).expect("write exclude");

    let (status, message, diagnostic) = ignore_row(&config);
    assert_eq!(
        status,
        DoctorStatus::Pass,
        "message={message}\ndiagnostic={diagnostic:#?}"
    );
    assert!(
        diagnostic.iter().all(|line| line.contains("info/exclude:")),
        "the row must name the file that actually decided: {diagnostic:#?}"
    );
}

/// Degenerate: `vcs.jj_repo` does not exist yet. There is no repository to ask,
/// so the row WARNS. An unobserved property must not be published as a verified
/// one in either direction — not as a pass, and not as a failure the operator
/// cannot act on.
#[test]
fn a_missing_target_repo_warns_rather_than_guessing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("project").join(".kata").join("kata.toml");
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
    // `jj_repo = ".."` resolves to `<tmp>/project`, which `kata init` created.
    // Point it somewhere that does not exist at all.
    let toml = std::fs::read_to_string(&config).expect("read config");
    let absent = dir.path().join("no-such-repo");
    let toml = toml.replace(
        "jj_repo = \"..\"",
        &format!("jj_repo = \"{}\"", absent.display()),
    );
    std::fs::write(&config, toml).expect("write config");

    let (status, message, _) = ignore_row(&config);
    assert_eq!(status, DoctorStatus::Warn, "message={message}");
    assert!(
        message.contains("cannot verify"),
        "a warn must say it did not observe the property: {message}"
    );
}

/// Degenerate: `vcs.jj_repo` exists but is not inside a git repository — the
/// hermetic-scratch shape. `git check-ignore` exits 128 there, which is git
/// declining to answer, and a decline is not a pass.
#[test]
fn a_target_dir_that_is_not_a_git_repo_warns() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("project").join(".kata").join("kata.toml");
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

    // `<tmp>/project` exists (kata init made it) and is not a git repo, and the
    // tempdir root above it is not one either.
    let (status, message, _) = ignore_row(&config);
    assert_eq!(status, DoctorStatus::Warn, "message={message}");
    assert!(
        message.contains("cannot verify") && message.contains("128"),
        "the warn must name why git could not answer: {message}"
    );
}

/// REGRESSION — the hole a row scoring only the provider's roots has while it
/// is green.
///
/// `repo_local_artifact_roots(backend)` is the set of roots the PROVIDER
/// writes. `kata init` renders `data_dir = "data"` beside the config,
/// so a `<repo>/.kata/kata.toml` project keeps the node's whole durable state at
/// `<repo>/.kata/data` — `operational.db`, `cas.db` + `cas/`, `memory.db`,
/// `stage_cache.db`, `main.lock`, `recovery-generations/**`.
///
/// MEASURED on a fixture in exactly the state this test builds — the operator
/// applied a remedy naming only the provider roots, and only that — a row
/// scoring only those answers `pass`, and after one `kata serve`
/// `jj status` at the repo root lists the entire `.kata/data` tree as `A`dded
/// to the working copy.
///
/// So the fixture is a provider-roots-only remedy applied in full: a repository
/// that is correct about every provider root and wrong about the data dir.
///
/// COUNTERFACTUAL: point `push_target_repo_ignore_check` back at
/// `repo_local_artifact_roots` and this goes red — the row passes.
#[test]
fn a_repo_that_ignores_only_the_provider_roots_still_fails_for_the_data_dir() {
    let (_dir, config, repo) = project_inside_a_git_repo();
    std::fs::write(repo.join(".gitignore"), "/.jj/\n/agents/\n").expect("write .gitignore");

    let (status, message, diagnostic) = ignore_row(&config);
    assert_eq!(
        status,
        DoctorStatus::Fail,
        "kata's durable state lives at <repo>/.kata/data under the config `kata init` \
         generates; a repository that does not ignore it commits operational.db\nmessage={message}\n\
         diagnostic={diagnostic:#?}"
    );
    assert!(
        diagnostic
            .iter()
            .any(|line| line.starts_with(".kata/data/") && line.contains("NOT ignored")),
        "the row must NAME the data directory; diagnostic={diagnostic:#?}"
    );
    // And the provider roots it DOES cover must not be re-reported as offenders,
    // or the remedy would tell the operator to add what they already added.
    for covered in [".jj/", "agents/"] {
        assert!(
            diagnostic
                .iter()
                .any(|line| line.starts_with(covered) && !line.contains("NOT ignored")),
            "{covered} is ignored by this fixture and must be reported as such; \
             diagnostic={diagnostic:#?}"
        );
    }

    // GREEN: applying the remedy this row prints clears it, same contract as
    // `following_the_remedy_the_row_prints_clears_the_row`.
    let mut patterns = patterns_the_remedy_names(&message);
    patterns.extend(["/.jj/".to_string(), "/agents/".to_string()]);
    std::fs::write(
        repo.join(".gitignore"),
        format!("{}\n", patterns.join("\n")),
    )
    .expect("write .gitignore");
    let (status, message, diagnostic) = ignore_row(&config);
    assert_eq!(
        status,
        DoctorStatus::Pass,
        "message={message}\ndiagnostic={diagnostic:#?}"
    );
}

/// The row's declared set and `kata init`'s generated config must agree about
/// where the data directory is — a composition, because each half is fine alone.
///
/// If `kata init` ever moves `data_dir` outside the project (the shipped
/// `config/kata.example.toml` puts it at `~/.kata/data`), the data-dir arm stops
/// contributing and the two tests above stop meaning what they say. This states
/// the premise so that change fails HERE, naming it, rather than silently
/// hollowing them out.
#[test]
fn kata_init_puts_the_data_dir_inside_the_repository_it_points_at() {
    let (_dir, config, repo) = project_inside_a_git_repo();
    let snapshot = kata_core::ConfigManager::load(&config)
        .expect("the generated config loads")
        .snapshot();
    assert!(
        snapshot.node.data_dir.starts_with(&repo),
        "`kata init` renders data_dir beside the config, so it lands inside \
         vcs.jj_repo ({}); got {}",
        repo.display(),
        snapshot.node.data_dir.display()
    );
    assert!(
        declared_paths(&config)
            .iter()
            .any(|path| path == ".kata/data"),
        "and the declared set must therefore contain it"
    );
}
