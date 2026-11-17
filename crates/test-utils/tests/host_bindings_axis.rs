//! Proof that the host-binding axis varies exactly what it claims to, and
//! nothing else.
//!
//! `crates/test-utils/tests/git_hermeticity.rs` proves the pins hold against a
//! hostile operator environment. This file proves the complementary property:
//! that a fixture can now MOVE one pinned host fact on purpose, that the move is
//! visible where it must be, and that every other pin is untouched by it — which
//! is the only thing that makes the axis safe to use.
//!
//! Every test here is a differential: two repositories that differ in one stated
//! binding, compared field by field. A single-repo assertion could not tell
//! "the trunk moved" from "the fixture is broken".

use std::collections::BTreeMap;

use kata_test_utils::git::HERMETIC_OVERRIDES;
use kata_test_utils::host_repo::{
    HostBindings, HostIdentity, HostRepo, TRUNK_NAMES, default_identity, default_trunk,
};

/// Every hermetic key's repo-LOCAL value, as a process kata spawns would read it.
fn local_overrides(repo: &HostRepo) -> BTreeMap<&'static str, Option<String>> {
    HERMETIC_OVERRIDES
        .iter()
        .map(|(key, _)| (*key, repo.local_config(key)))
        .collect()
}

/// The keys the axis is ALLOWED to move. Everything else must be identical
/// across every arm of every table below.
const AXIS_KEYS: &[&str] = &["user.name", "user.email"];

fn overrides_outside_the_axis(repo: &HostRepo) -> BTreeMap<&'static str, Option<String>> {
    local_overrides(repo)
        .into_iter()
        .filter(|(key, _)| !AXIS_KEYS.contains(key))
        .collect()
}

/// A fixture that varies NOTHING must be indistinguishable from today's pinned
/// fixture — same trunk, same identity, same repo-local override set.
///
/// This is the opt-out guarantee. If it ever fails, every existing test in the
/// workspace has silently changed meaning.
#[test]
fn host_bindings_default_reproduces_the_pinned_fixture_exactly() {
    let repo = HostBindings::new().init_git_repo();

    assert_eq!(
        repo.trunk(),
        "main",
        "the default trunk must stay `main`, the value HERMETIC_OVERRIDES pins"
    );
    assert_eq!(
        repo.symbolic_head(),
        "refs/heads/main",
        "a fixture that names no trunk must land on the pinned one"
    );
    assert_eq!(default_trunk(), "main");
    assert_eq!(
        default_identity(),
        HostIdentity::named("kata test", "test@example.invalid")
    );

    // Every hermetic override is present repo-locally at its pinned value.
    for (key, value) in HERMETIC_OVERRIDES {
        assert_eq!(
            repo.local_config(key).as_deref(),
            Some(*value),
            "a default HostRepo must carry the pinned `{key}` in its LOCAL config"
        );
    }

    // And the seed commit carries the pinned identity.
    assert_eq!(
        repo.commit_author("HEAD"),
        "kata test <test@example.invalid>",
        "the default fixture's seed commit must carry the pinned identity"
    );

    // NO DRIFT from `git::init_git_repo`, the other default-repo builder. The two
    // builders are separate code; this compares what they PRODUCE, so an edit to
    // either one that changes the fixture's shape fails here rather than silently
    // giving two kinds of "default repo".
    let (_seeded_tmp, seeded) = kata_test_utils::git::init_git_repo();
    let seeded_git = |args: &[&str]| -> String {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(&seeded)
            .args(args)
            .output()
            .expect("git invocation");
        assert!(out.status.success(), "git {args:?} failed");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    assert_eq!(seeded_git(&["symbolic-ref", "HEAD"]), repo.symbolic_head());
    assert_eq!(
        seeded_git(&["log", "-1", "--format=%an <%ae> %s %G?"]),
        repo.git_stdout(&["log", "-1", "--format=%an <%ae> %s %G?"]),
        "the axis's default fixture must be indistinguishable from `init_git_repo`'s"
    );
    assert_eq!(
        seeded_git(&["for-each-ref", "--format=%(refname)", "refs/heads/"]),
        repo.branch_refs().join("\n")
    );
}

/// The TRUNK axis moves the trunk, in the two places that matter — `HEAD` and the
/// ref set — and moves nothing else.
///
/// NON-VACUOUS by construction: the arms are compared against each other, so a
/// builder that silently ignored `with_trunk` would collapse every arm onto
/// `main` and fail the first inequality.
#[test]
fn host_bindings_trunk_axis_moves_the_trunk_and_only_the_trunk() {
    let baseline = HostBindings::new().init_git_repo();
    let baseline_outside = overrides_outside_the_axis(&baseline);
    let baseline_identity = baseline.commit_author("HEAD");

    for trunk in TRUNK_NAMES {
        let repo = HostBindings::new().with_trunk(trunk).init_git_repo();

        // What the axis CLAIMS to move.
        assert_eq!(repo.trunk(), *trunk);
        assert_eq!(
            repo.symbolic_head(),
            format!("refs/heads/{trunk}"),
            "the repository's HEAD must be symbolic to the trunk this fixture declared"
        );
        assert_eq!(
            repo.branch_refs(),
            vec![format!("refs/heads/{trunk}")],
            "the declared trunk must be the ONLY branch a freshly seeded repo carries"
        );
        // The seed commit is reachable through the declared trunk, not through
        // some other name that happens to exist.
        assert_eq!(
            repo.trunk_sha(),
            repo.git_stdout(&["rev-parse", "HEAD"]),
            "the trunk ref must point at the seed commit"
        );

        // What it must NOT move.
        assert_eq!(
            overrides_outside_the_axis(&repo),
            baseline_outside,
            "varying the trunk must leave every non-identity hermetic override at its \
             pinned value; trunk={trunk}"
        );
        assert_eq!(
            repo.commit_author("HEAD"),
            baseline_identity,
            "varying the trunk must not move the identity; trunk={trunk}"
        );
        assert_eq!(
            repo.local_config("init.defaultBranch").as_deref(),
            Some("main"),
            "the axis ADDS an explicit `-b`; it must not unpin init.defaultBranch"
        );
    }
}

/// The IDENTITY axis moves the identity in the repo's own config and on the
/// commits the fixture writes, and moves nothing else.
#[test]
fn host_bindings_identity_axis_moves_the_identity_and_only_the_identity() {
    let baseline = HostBindings::new().init_git_repo();
    let baseline_outside = overrides_outside_the_axis(&baseline);

    let repo = HostBindings::new()
        .with_identity("Ada Lovelace", "ada@example.invalid")
        .init_git_repo();

    assert_eq!(
        repo.identity(),
        &HostIdentity::named("Ada Lovelace", "ada@example.invalid")
    );

    // The repo-LOCAL layer — the only one a process we do not spawn can read.
    assert_eq!(
        repo.local_config("user.name").as_deref(),
        Some("Ada Lovelace")
    );
    assert_eq!(
        repo.local_config("user.email").as_deref(),
        Some("ada@example.invalid")
    );

    // ...and the history the fixture itself wrote.
    assert_eq!(
        repo.commit_author("HEAD"),
        "Ada Lovelace <ada@example.invalid>"
    );
    assert_eq!(
        repo.commit_committer("HEAD"),
        "Ada Lovelace <ada@example.invalid>"
    );

    // NON-VACUOUS: the baseline really does say something else.
    assert_ne!(
        repo.commit_author("HEAD"),
        baseline.commit_author("HEAD"),
        "if these matched, the identity axis would be indistinguishable from the default"
    );

    // Nothing else moved.
    assert_eq!(
        overrides_outside_the_axis(&repo),
        baseline_outside,
        "varying the identity must leave every other hermetic override pinned"
    );
    assert_eq!(
        repo.symbolic_head(),
        "refs/heads/main",
        "varying the identity must not move the trunk"
    );
}

/// `without_identity` leaves the repository declaring no identity to a process
/// kata spawns, while every other pin — including the ones that make the fixture
/// commit at all — stays in force.
#[test]
fn host_bindings_absent_identity_leaves_no_repo_local_identity() {
    let repo = HostBindings::new().without_identity().init_git_repo();

    assert_eq!(repo.identity(), &HostIdentity::Absent);
    assert_eq!(
        repo.local_config("user.name"),
        None,
        "an Absent identity must not leave a repo-local user.name behind"
    );
    assert_eq!(repo.local_config("user.email"), None);

    // The other pins are untouched, so the fixture is still hermetic in every
    // respect except the one it declared.
    assert_eq!(
        repo.local_config("commit.gpgsign").as_deref(),
        Some("false")
    );
    assert_eq!(
        repo.local_config("core.hooksPath").as_deref(),
        HERMETIC_OVERRIDES
            .iter()
            .find(|(key, _)| *key == "core.hooksPath")
            .map(|(_, value)| *value)
    );

    // And the seed commit still exists — the command-line prefix carried it —
    // which is what makes `Absent` usable rather than merely a broken fixture.
    assert_eq!(
        repo.git_stdout(&["log", "-1", "--format=%s"]),
        "seed",
        "an Absent-identity fixture must still be able to seed itself"
    );
}

/// The axis is impossible to use by ACCIDENT: a fixture that names no trunk gets
/// a deterministic one even on a host whose configured default branch is
/// something else entirely.
///
/// MEASURED, not argued. The hostile `init.defaultBranch` is applied to the
/// fixture's own child processes via `GIT_CONFIG_GLOBAL`, so nothing here touches
/// the real user's configuration. The NON-VACUITY arm shows the hazard is real:
/// the same environment, with a plain `git init`, adopts the operator's name.
#[test]
fn host_bindings_omitted_trunk_is_deterministic_under_a_hostile_default_branch() {
    let hostile = tempfile::tempdir().expect("hostile config tempdir");
    let global_config = hostile.path().join("gitconfig");
    std::fs::write(&global_config, "[init]\n\tdefaultBranch = operator-trunk\n")
        .expect("write hostile global config");

    // NON-VACUOUS: a plain `git init` under this environment really does adopt
    // `operator-trunk`.
    let plain = tempfile::tempdir().expect("plain repo tempdir");
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(plain.path())
        .args(["init", "-q"])
        .env("GIT_CONFIG_GLOBAL", &global_config)
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("git init");
    assert!(out.status.success(), "plain init must succeed");
    let head = std::process::Command::new("git")
        .arg("-C")
        .arg(plain.path())
        .args(["symbolic-ref", "HEAD"])
        .env("GIT_CONFIG_GLOBAL", &global_config)
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("git symbolic-ref");
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        "refs/heads/operator-trunk",
        "the hazard must be real: a plain git init is expected to adopt the operator's \
         default branch"
    );

    // The axis, naming no trunk, under the same environment.
    let repo = HostBindings::new()
        .with_ambient_env("GIT_CONFIG_GLOBAL", global_config.as_os_str())
        .with_ambient_env("GIT_CONFIG_SYSTEM", "/dev/null")
        .init_git_repo();
    assert_eq!(
        repo.symbolic_head(),
        "refs/heads/main",
        "a fixture that forgets to name a trunk must still get the pinned one"
    );

    // ...and naming one still wins over both the pin and the hostile default.
    let named = HostBindings::new()
        .with_trunk("develop")
        .with_ambient_env("GIT_CONFIG_GLOBAL", global_config.as_os_str())
        .with_ambient_env("GIT_CONFIG_SYSTEM", "/dev/null")
        .init_git_repo();
    assert_eq!(named.symbolic_head(), "refs/heads/develop");
}

/// The axis's defaults are DERIVED from the pins, so the two can never drift.
///
/// A transcribed default would pass on the day it was written and rot silently:
/// the whole point of the opt-out guarantee is that it holds after somebody
/// edits `HERMETIC_OVERRIDES`.
#[test]
fn host_bindings_defaults_are_derived_from_the_pins_not_transcribed() {
    let pinned_branch = HERMETIC_OVERRIDES
        .iter()
        .find(|(key, _)| *key == "init.defaultBranch")
        .map(|(_, value)| *value)
        .expect("HERMETIC_OVERRIDES must pin init.defaultBranch");
    assert_eq!(default_trunk(), pinned_branch);

    let pinned_name = HERMETIC_OVERRIDES
        .iter()
        .find(|(key, _)| *key == "user.name")
        .map(|(_, value)| *value)
        .expect("HERMETIC_OVERRIDES must pin user.name");
    let pinned_email = HERMETIC_OVERRIDES
        .iter()
        .find(|(key, _)| *key == "user.email")
        .map(|(_, value)| *value)
        .expect("HERMETIC_OVERRIDES must pin user.email");
    assert_eq!(
        default_identity(),
        HostIdentity::named(pinned_name, pinned_email)
    );
}
