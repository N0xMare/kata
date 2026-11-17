//! `kata doctor`'s `commit_identity` row: kata must say, before anything is
//! spent, WHO it would commit as in this repository.
//!
//! # The defect these tests pin
//!
//! A `JjBackend::user_settings` that loads exactly one config layer, jj-lib's
//! built-in `config/misc.toml`, sets `user.name` and `user.email` to the empty
//! string, so kata would author commits with jj's EMPTY identity and PUSH them
//! to the operator's forge. On the git side such a commit carries
//! **`JJ_EMPTY_STRING <JJ_EMPTY_STRING>`**. A fabricated identity (say
//! `kata <kata@example.invalid>`) would be worse: no empty-identity refusal could
//! ever fire on it.
//!
//! doctor's entire job is first-run readiness, so it must not report PASS
//! while either holds.
//!
//! # Whose environment this measures
//!
//! The DAEMON's, following the `trunk_resolution` row's precedent for the same
//! reason. Every arm here points `vcs.jj_repo` at a repository and asks about
//! THAT path, never about the process CWD. The distinction is measurable rather
//! than stylistic: git's `includeIf "gitdir:…"` gives ONE `~/.gitconfig`
//! different identities per repository, so "who am I" asked in the wrong
//! directory is a different question with a different answer.
//!
//! # Hermeticity
//!
//! Fixtures come from `kata_test_utils::host_repo::HostBindings`, the axis that
//! varies ONE host binding on purpose while every `HERMETIC_OVERRIDES` pin stays
//! where it is. The REFUSAL arm is reached by DECLARING an identity kata itself
//! refuses rather than by removing one — `HostBindings::without_identity` clears
//! only the repo-LOCAL layer and says so in its own doc, so on a box with a
//! global identity it would prove nothing.
//!
//! # What is NOT covered here, and why
//!
//! The row's `warn` arm — "`vcs.jj_repo` is not an existing directory" — is
//! UNREACHABLE through `kata doctor`, and that is a fact about doctor rather
//! than about this row: `config_validation` refuses such a config first, so the
//! whole `if let Some(cfg)` block that publishes both this row AND
//! `trunk_resolution` never runs. MEASURED — a config naming a nonexistent
//! `jj_repo` published NEITHER row, and the rows it did publish are listed in
//! this test file's history. The arm stays because `push_commit_identity_check`
//! is callable with any config and an unobserved property must not be published
//! as a verified one in either direction; it is simply not reachable from this
//! surface today.

use std::path::{Path, PathBuf};

use kata::cli::testing::{DoctorStatus, doctor_report_with_logins_dir, no_kata_logins};
use kata::cli::{Cli, Command, OutputFormat};
use kata_test_utils::host_repo::HostBindings;
use kata_types::commit_identity::{SANDBOX_AGENT_EMAIL, SANDBOX_AGENT_NAME};

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

fn identity_row(config: &Path) -> (DoctorStatus, String, Vec<String>) {
    let report = doctor_report_with_logins_dir(config, &[], no_kata_logins(config));
    let check = report
        .checks
        .iter()
        .find(|check| check.name == "commit_identity")
        .unwrap_or_else(|| {
            panic!(
                "kata doctor published no `commit_identity` row; rows were {:?}",
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

#[test]
fn doctor_names_the_identity_kata_would_commit_as() {
    let repo = HostBindings::new()
        .with_identity("Ada Lovelace", "ada@example.invalid")
        .init_git_repo();
    let config = project_in(repo.path());

    let (status, message, diagnostic) = identity_row(&config);
    assert_eq!(status, DoctorStatus::Pass, "{message}");
    assert!(
        message.contains("Ada Lovelace <ada@example.invalid>"),
        "the row must NAME the identity, not merely assert one exists: {message}"
    );
    assert!(
        diagnostic
            .iter()
            .any(|line| line.contains("GIT_AUTHOR_IDENT")),
        "the diagnostic must say HOW kata resolved it, so an operator can \
         reproduce the answer: {diagnostic:?}"
    );
}

#[test]
fn doctor_fails_when_kata_would_have_no_identity_to_commit_as() {
    // Declared rather than absent — see the module doc.
    let repo = HostBindings::new()
        .with_identity(SANDBOX_AGENT_NAME, SANDBOX_AGENT_EMAIL)
        .init_git_repo();
    let config = project_in(repo.path());

    let (status, message, _) = identity_row(&config);
    assert_eq!(status, DoctorStatus::Fail, "{message}");
    assert!(message.contains("no identity to commit as"), "{message}");
    assert!(
        message.contains("refuse at workspace creation"),
        "the row must say what the failure COSTS — every worktree_isolated run \
         refuses — rather than reporting a bare mismatch: {message}"
    );
    assert!(
        message.contains("git config user.email"),
        "a doctor failure without a remedy is a dead end: {message}"
    );
}

/// The row is scoped to the DAEMON's repository, not the invoking shell's.
///
/// Two projects pointing at two repositories that declare DIFFERENT identities
/// must produce two different rows from the same process. That is the property
/// git's `includeIf "gitdir:..."` makes real — one `~/.gitconfig`, two answers,
/// measured — and the reason the row asks about `vcs.jj_repo` rather than about
/// wherever `kata doctor` was typed.
#[test]
fn the_row_answers_for_the_configured_repository_not_the_process_cwd() {
    let ada = HostBindings::new()
        .with_identity("Ada Lovelace", "ada@example.invalid")
        .init_git_repo();
    let grace = HostBindings::new()
        .with_identity("Grace Hopper", "grace@example.invalid")
        .init_git_repo();

    let (_, ada_message, _) = identity_row(&project_in(ada.path()));
    let (_, grace_message, _) = identity_row(&project_in(grace.path()));

    assert!(ada_message.contains("ada@example.invalid"), "{ada_message}");
    assert!(
        grace_message.contains("grace@example.invalid"),
        "{grace_message}"
    );
    assert_ne!(
        ada_message, grace_message,
        "one process asking about two repositories must get two answers, or the \
         row is reporting a fact about the shell rather than about the daemon"
    );
}
