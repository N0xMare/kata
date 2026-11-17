//! Regression proof for the fixture-git hermeticity defect.
//!
//! A host with a global `commit.gpgsign = true` makes a fixture's seed commit
//! inherit it: when gpg-agent falls over, a healthy test fails with
//! `gpg: signing failed: Cannot allocate memory`; when gpg-agent is healthy the
//! same defect is silent, and the suite simply signs every throwaway commit with
//! the operator's key.
//!
//! These tests reconstruct a hostile environment inside a tempdir — a global
//! git config that turns signing ON, a `gpg` that always fails, a `pre-commit`
//! hook that always fails, an operator default branch name — and assert the
//! shared helpers are unmoved by all of it. The hostility is applied to the
//! child process only (`GIT_CONFIG_GLOBAL` / `PATH` via [`Command::env`]), so
//! nothing here can touch the real user's configuration.
//!
//! Each test is NON-VACUOUS by construction: it first shows a plain `git`
//! FAILS in the same environment, then shows the hermetic command succeeds.

use std::path::Path;
use std::process::Command;

use kata_test_utils::git::{
    HERMETIC_OVERRIDES, hermetic_git_in, init_git_repo, init_git_repo_at, write_hermetic_config,
};

/// The hostile ambient environment: a global git config and a PATH whose `gpg`
/// and hooks are booby-trapped. Returns the tempdir owning it (keep it alive)
/// plus the values to hand to [`Command::env`].
struct HostileEnv {
    _tmp: tempfile::TempDir,
    global_config: std::path::PathBuf,
    path: std::ffi::OsString,
}

impl HostileEnv {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("hostile env tempdir");
        let root = tmp.path();

        // A `gpg` that reproduces the gate's failure verbatim, first on PATH.
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir bin");
        let gpg = bin.join("gpg");
        std::fs::write(
            &gpg,
            "#!/bin/sh\necho 'gpg: signing failed: Cannot allocate memory' >&2\nexit 2\n",
        )
        .expect("write gpg shim");
        make_executable(&gpg);

        // A `pre-commit` hook that refuses every commit, reachable only via a
        // global `core.hooksPath`.
        let hooks = root.join("hooks");
        std::fs::create_dir_all(&hooks).expect("mkdir hooks");
        let pre_commit = hooks.join("pre-commit");
        std::fs::write(
            &pre_commit,
            "#!/bin/sh\necho 'operator pre-commit hook refuses' >&2\nexit 1\n",
        )
        .expect("write hook");
        make_executable(&pre_commit);

        // An operator-wide excludes file naming the directories kata writes into
        // a target repository. Harmless to a commit; fatal to any test that
        // asserts a fixture repo does NOT ignore them.
        let excludes = root.join("global_excludes");
        std::fs::write(&excludes, ".jj/\n/agents/\n.kata/\n").expect("write global excludes");

        // The operator's global config: signing on, hooks hijacked, a default
        // branch name no fixture expects, an ambient excludes file, an
        // identity we must not adopt, and auto-maintenance that mutates the
        // repository underneath any process that merely committed into it.
        let global_config = root.join("gitconfig");
        std::fs::write(
            &global_config,
            format!(
                "[user]\n\tname = Operator\n\temail = operator@example.com\n\
                 \tsigningkey = DEADBEEFDEADBEEF\n\
                 [commit]\n\tgpgsign = true\n\
                 [tag]\n\tgpgsign = true\n\
                 [gpg]\n\tprogram = gpg\n\tformat = openpgp\n\
                 [core]\n\thooksPath = {}\n\texcludesFile = {}\n\
                 [init]\n\tdefaultBranch = operator-trunk\n\
                 [gc]\n\tauto = 1\n\tautoDetach = false\n\
                 [maintenance]\n\tauto = true\n\tautoDetach = false\n",
                hooks.display(),
                excludes.display()
            ),
        )
        .expect("write hostile global config");

        let mut path = std::ffi::OsString::from(bin.as_os_str());
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_default());

        Self {
            _tmp: tmp,
            global_config,
            path,
        }
    }

    /// Apply the hostile environment to `cmd`. `GIT_CONFIG_SYSTEM` is pinned at
    /// `/dev/null` so the host's own `/etc/gitconfig` cannot make the test pass
    /// or fail for a reason this file did not set up.
    fn apply(&self, cmd: &mut Command) {
        cmd.env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("PATH", &self.path)
            .env_remove("GIT_CONFIG_NOSYSTEM");
    }
}

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod +x shim");
    }
}

/// Run a plain (non-hermetic) `git -C <repo>` under the hostile environment.
fn hostile_plain_git(env: &HostileEnv, repo: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).args(args);
    env.apply(&mut cmd);
    cmd.output().expect("git invocation")
}

/// Run a hermetic `git -C <repo>` under the hostile environment.
fn hostile_hermetic_git(env: &HostileEnv, repo: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = hermetic_git_in(repo);
    cmd.args(args);
    env.apply(&mut cmd);
    cmd.output().expect("git invocation")
}

/// THE REGRESSION. Under the exact environment that reddened the gate — global
/// `commit.gpgsign = true` and a `gpg` that fails — a plain `git commit` dies
/// with the gate's verbatim error, and the hermetic one commits.
#[test]
fn hermetic_git_survives_a_signing_config_that_kills_plain_git() {
    let env = HostileEnv::new();
    let tmp = tempfile::tempdir().expect("repo tempdir");
    let repo = tmp.path();

    // Bootstrap the repo hermetically so the ONLY variable under test below is
    // the commit itself.
    assert!(
        hostile_hermetic_git(&env, repo, &["init", "-q", "-b", "main"])
            .status
            .success(),
        "hermetic init must succeed under a hostile environment"
    );
    std::fs::write(repo.join("a.txt"), "one\n").expect("seed file");
    assert!(
        hostile_hermetic_git(&env, repo, &["add", "a.txt"])
            .status
            .success()
    );

    // NON-VACUOUS: plain git inherits the ambient signing config and dies the
    // way the gate died.
    //
    // The baseline neutralizes ONLY `core.hooksPath`, because the hostile
    // environment carries that hazard too and `pre-commit` runs BEFORE signing
    // — leaving it in place makes the baseline fail for the wrong reason, which
    // is exactly what the stderr assertion below caught the first time. Signing
    // is left ambient, so it is the single variable under test.
    let plain = hostile_plain_git(
        &env,
        repo,
        &[
            "-c",
            "core.hooksPath=/nonexistent/kata-test-utils-no-hooks",
            "commit",
            "-q",
            "-m",
            "seed",
        ],
    );
    let plain_stderr = String::from_utf8_lossy(&plain.stderr);
    assert!(
        !plain.status.success(),
        "the hazard must be real: a plain git commit is expected to FAIL under a global \
         commit.gpgsign=true with a broken gpg, but it succeeded"
    );
    assert!(
        plain_stderr.contains("gpg failed to sign the data"),
        "the hazard must be the SIGNING one, not some other failure; stderr={plain_stderr}"
    );

    // The fix: the same commit, hermetically, succeeds — and gpg is never
    // consulted, which the shim proves by being fatal whenever it IS.
    let hermetic = hostile_hermetic_git(&env, repo, &["commit", "-q", "-m", "seed"]);
    assert!(
        hermetic.status.success(),
        "hermetic commit must not invoke gpg: stderr={}",
        String::from_utf8_lossy(&hermetic.stderr)
    );

    // And the commit really is unsigned, so nothing merely deferred the spend.
    let sig = hostile_hermetic_git(&env, repo, &["log", "-1", "--format=%G?"]);
    assert_eq!(
        String::from_utf8_lossy(&sig.stdout).trim(),
        "N",
        "the seed commit must carry NO signature"
    );
}

/// A global `core.hooksPath` runs the operator's hooks inside an unrelated
/// fixture repo. `--no-verify` would only cover the commit hooks; pinning
/// `core.hooksPath` at a path that cannot exist covers all of them.
#[test]
fn hermetic_git_cannot_run_an_operator_hook_in_a_fixture_repo() {
    let env = HostileEnv::new();
    let tmp = tempfile::tempdir().expect("repo tempdir");
    let repo = tmp.path();

    assert!(
        hostile_hermetic_git(&env, repo, &["init", "-q", "-b", "main"])
            .status
            .success()
    );
    std::fs::write(repo.join("a.txt"), "one\n").expect("seed file");
    assert!(
        hostile_hermetic_git(&env, repo, &["add", "a.txt"])
            .status
            .success()
    );

    // NON-VACUOUS: with signing forced off but hooks still ambient, the
    // operator's pre-commit hook fires and refuses.
    let mut plain = Command::new("git");
    plain
        .arg("-C")
        .arg(repo)
        .args(["-c", "commit.gpgsign=false"])
        .args(["commit", "-q", "-m", "seed"]);
    env.apply(&mut plain);
    let plain = plain.output().expect("git invocation");
    let plain_stderr = String::from_utf8_lossy(&plain.stderr);
    assert!(
        !plain.status.success() && plain_stderr.contains("operator pre-commit hook refuses"),
        "the hooks hazard must be real; status={:?} stderr={plain_stderr}",
        plain.status.code()
    );

    assert!(
        hostile_hermetic_git(&env, repo, &["commit", "-q", "-m", "seed"])
            .status
            .success(),
        "no operator hook may run against a fixture repo"
    );
}

/// A bare `git init` adopts `init.defaultBranch`, so a fixture that does not
/// pass `-b` gets an operator-dependent trunk name.
#[test]
fn hermetic_git_bare_init_does_not_adopt_the_operators_default_branch() {
    let env = HostileEnv::new();

    let plain_tmp = tempfile::tempdir().expect("tempdir");
    assert!(
        hostile_plain_git(&env, plain_tmp.path(), &["init", "-q"])
            .status
            .success()
    );
    let plain_head = hostile_hermetic_git(&env, plain_tmp.path(), &["symbolic-ref", "HEAD"]);
    // NON-VACUOUS: plain init really does take the operator's branch name.
    assert_eq!(
        String::from_utf8_lossy(&plain_head.stdout).trim(),
        "refs/heads/operator-trunk",
        "the default-branch hazard must be real"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    assert!(
        hostile_hermetic_git(&env, tmp.path(), &["init", "-q"])
            .status
            .success()
    );
    let head = hostile_hermetic_git(&env, tmp.path(), &["symbolic-ref", "HEAD"]);
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        "refs/heads/main",
        "a bare `git init` must land on a fixture-chosen trunk, not the operator's"
    );
}

/// An operator's global `core.excludesFile` must not decide what a fixture
/// repository ignores.
///
/// MEASURED (git 2.43.0). `kata doctor`'s `target_repo_ignore` row
/// asks `git check-ignore` whether a target repository ignores `.jj/` and
/// `agents/`, and its RED arm is a fixture that ignores NOTHING. On a host whose
/// global excludes file happens to name those paths, git answers "ignored" for
/// a repo with no `.gitignore` at all — so that RED arm would go green for a
/// reason having nothing to do with the fixture, and the check under test would
/// never be exercised.
///
/// The repo-LOCAL layer is the one that matters here: kata's production code
/// spawns `git` itself, without this crate's `-c` prefix, and reads only the
/// config it finds on disk.
#[test]
fn hermetic_git_repo_does_not_inherit_the_operators_global_excludes() {
    let env = HostileEnv::new();
    let probe = ".jj/probe/probe";

    // NON-VACUOUS: the hazard is real. A repo built WITHOUT the repo-local layer
    // inherits the ambient excludes file, and plain git calls the path ignored.
    let bare = tempfile::tempdir().expect("bare repo tempdir");
    assert!(
        hostile_plain_git(&env, bare.path(), &["init", "-q", "-b", "main"])
            .status
            .success()
    );
    let leaked = hostile_plain_git(&env, bare.path(), &["check-ignore", "--", probe]);
    assert_eq!(
        leaked.status.code(),
        Some(0),
        "the hazard must be real: a repo with no .gitignore is expected to report {probe} \
         IGNORED under an ambient core.excludesFile, stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&leaked.stdout),
        String::from_utf8_lossy(&leaked.stderr)
    );

    // The seeded fixture carries the override in its own config, so the same
    // plain-git call — the shape kata's production code makes — sees only what
    // the fixture itself wrote.
    let tmp = tempfile::tempdir().expect("repo tempdir");
    init_git_repo_at(tmp.path());
    let sealed = hostile_plain_git(&env, tmp.path(), &["check-ignore", "--", probe]);
    assert_eq!(
        sealed.status.code(),
        Some(1),
        "a seeded fixture must ignore exactly what IT declares; got stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&sealed.stdout),
        String::from_utf8_lossy(&sealed.stderr)
    );
}

/// The command-line layer only binds children THIS crate spawns. Kata's
/// production code shells `git` against these fixtures too, so the settings
/// must also be readable out of the repo's own config — that is the only layer
/// a process we do not spawn can see.
#[test]
fn hermetic_git_seeded_repo_carries_the_overrides_in_its_own_config() {
    let (_tmp, repo) = init_git_repo();
    for (key, value) in HERMETIC_OVERRIDES {
        let out = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["config", "--local", "--get", key])
            .output()
            .expect("git config --get");
        assert!(
            out.status.success(),
            "a seeded fixture must carry `{key}` in its LOCAL config, so a git child kata \
             spawns against it — which never sees our `-c` prefix — is hermetic too"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            *value,
            "local `{key}` must match the shared override set"
        );
    }
}

/// `init_git_repo_at` is the caller-chosen-path shape several fixtures need;
/// it must be hermetic on exactly the same terms as `init_git_repo`.
#[test]
fn hermetic_git_init_repo_at_seeds_a_repo_at_a_caller_chosen_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("nested").join("repo");
    std::fs::create_dir_all(&repo).expect("mkdir repo");
    init_git_repo_at(&repo);

    let head = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["log", "-1", "--format=%s %G?"])
        .output()
        .expect("git log");
    assert!(head.status.success(), "the seed commit must be reachable");
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        "seed N",
        "the seed commit must exist and be UNSIGNED"
    );
    let branch = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .expect("git symbolic-ref");
    assert_eq!(String::from_utf8_lossy(&branch.stdout).trim(), "main");
}

/// A caller that wants a different value for one of these keys can still get
/// it: git takes the LAST `-c` for a key, and caller args land after the
/// prefix. Without this the shared helper would be unusable by the fixtures
/// that deliberately commit as a second identity.
#[test]
fn hermetic_git_caller_supplied_override_still_wins_over_the_prefix() {
    let (_tmp, repo) = init_git_repo();
    write_hermetic_config(&repo);

    let out = hermetic_git_in(&repo)
        .args([
            "-c",
            "user.name=Reviewer",
            "-c",
            "user.email=reviewer@example.invalid",
            "commit",
            "--allow-empty",
            "-q",
            "-m",
            "reviewer fixup",
        ])
        .output()
        .expect("git commit");
    assert!(
        out.status.success(),
        "commit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let author = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["log", "-1", "--format=%an <%ae>"])
        .output()
        .expect("git log");
    assert_eq!(
        String::from_utf8_lossy(&author.stdout).trim(),
        "Reviewer <reviewer@example.invalid>",
        "a caller's own `-c` must override the shared prefix"
    );
}

/// `git commit` may silently launch repository mutation the caller never asked
/// for: git 2.54 runs `git maintenance run --auto` after a commit, DETACHED by
/// default (`maintenance.autoDetach` → `gc.autoDetach` → true), whose
/// `loose-objects` / `incremental-repack` tasks rewrite `objects/pack` under a
/// reader that opened the odb a moment earlier.
///
/// MEASURED (git 2.54.0): a detached maintenance repack can leave a
/// half-written `.tmp` pack at the moment jj's adoption opens the odb, failing
/// `failed to import git HEAD into jj: Failed to read Git HEAD target commit
/// <id>`; `git fsck` refuses the same file. And on the configuration side:
/// `GIT_TRACE2_EVENT` shows a `git commit` spawning `git maintenance run --auto`
/// unconditionally when `maintenance.auto` is not pinned off.
///
/// The cell asserts the two layers of the fix against the hostile global:
/// the pins land on the child (`gc.auto` / `maintenance.auto` read back off),
/// and a hermetic commit spawns NO maintenance child where a plain one does
/// (read off `GIT_TRACE2_EVENT`, the trace git itself emits).
#[test]
fn hermetic_git_never_launches_unrequested_repo_maintenance() {
    let env = HostileEnv::new();
    let tmp = tempfile::tempdir().expect("repo tempdir");
    let repo = tmp.path();

    assert!(
        hostile_hermetic_git(&env, repo, &["init", "-q", "-b", "main"])
            .status
            .success()
    );
    std::fs::write(repo.join("a.txt"), "one\n").expect("seed file");
    assert!(
        hostile_hermetic_git(&env, repo, &["add", "a.txt"])
            .status
            .success()
    );

    // NON-VACUOUS, layer one: the hostile knobs reach a plain git.
    let plain_gc = hostile_plain_git(&env, repo, &["config", "--get", "gc.auto"]);
    assert_eq!(
        String::from_utf8_lossy(&plain_gc.stdout).trim(),
        "1",
        "the hostile gc.auto must reach a plain git"
    );
    let plain_maint = hostile_plain_git(&env, repo, &["config", "--get", "maintenance.auto"]);
    assert_eq!(
        String::from_utf8_lossy(&plain_maint.stdout).trim(),
        "true",
        "the hostile maintenance.auto must reach a plain git"
    );

    // NON-VACUOUS, layer two: a plain commit under the hostile config really
    // does spawn the auto-maintenance child — read off git's own event trace.
    let trace_tmp = tempfile::tempdir().expect("trace tempdir");
    let plain_trace = trace_tmp.path().join("plain-trace.jsonl");
    let mut plain = Command::new("git");
    plain
        .arg("-C")
        .arg(repo)
        .args(["-c", "commit.gpgsign=false"])
        .args(["-c", "core.hooksPath=/nonexistent/kata-test-utils-no-hooks"])
        .args(["commit", "-q", "-m", "seed"]);
    env.apply(&mut plain);
    plain.env("GIT_TRACE2_EVENT", &plain_trace);
    assert!(
        plain.output().expect("plain commit").status.success(),
        "the baseline commit itself must succeed"
    );
    let trace = std::fs::read_to_string(&plain_trace).expect("plain trace");
    assert!(
        trace.contains(r#""argv":["git","maintenance","run","--auto"#),
        "the hazard must be real: a plain commit must spawn `maintenance run \
         --auto`; trace={trace}"
    );

    // The fix, layer one: the pins land on the hermetic child.
    let her_gc = hostile_hermetic_git(&env, repo, &["config", "--get", "gc.auto"]);
    assert_eq!(
        String::from_utf8_lossy(&her_gc.stdout).trim(),
        "0",
        "the shared overrides must pin gc.auto off"
    );
    let her_maint = hostile_hermetic_git(&env, repo, &["config", "--get", "maintenance.auto"]);
    assert_eq!(
        String::from_utf8_lossy(&her_maint.stdout).trim(),
        "false",
        "the shared overrides must pin maintenance.auto off"
    );

    // The fix, layer two: no maintenance child under the hermetic spawn.
    let tmp2 = tempfile::tempdir().expect("repo tempdir");
    let repo2 = tmp2.path();
    assert!(
        hostile_hermetic_git(&env, repo2, &["init", "-q", "-b", "main"])
            .status
            .success()
    );
    std::fs::write(repo2.join("b.txt"), "two\n").expect("seed file");
    assert!(
        hostile_hermetic_git(&env, repo2, &["add", "b.txt"])
            .status
            .success()
    );
    let her_trace = trace_tmp.path().join("hermetic-trace.jsonl");
    let mut commit = hermetic_git_in(repo2);
    commit.args(["commit", "-q", "-m", "seed"]);
    env.apply(&mut commit);
    commit.env("GIT_TRACE2_EVENT", &her_trace);
    assert!(
        commit.output().expect("hermetic commit").status.success(),
        "hermetic commit under hostile auto-maintenance"
    );
    let trace = std::fs::read_to_string(&her_trace).expect("hermetic trace");
    assert!(
        !trace.contains(r#""argv":["git","maintenance","run","--auto"#),
        "a kata-spawned commit must never launch auto-maintenance; trace={trace}"
    );
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "git_hermeticity/gold_fixture_hermetic_derivation.rs"]
mod gold_fixture_hermetic_derivation;
