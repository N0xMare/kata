//! Shared git-repo helpers for tests that need a real on-disk repository
//! (worktree isolation, workspace providers, crash recovery, executor
//! integration): the one `run_git` / `init_git_repo` the
//! `kata-workflow` and `kata-api` test suites share.
//!
//! # Hermeticity against the operator's git configuration
//!
//! A test fixture repository must not inherit the config of whoever runs the
//! suite. A host with a global `commit.gpgsign = true` makes every throwaway
//! seed commit shell out to `gpg`, so a failing gpg-agent fails healthy tests;
//! and where gpg-agent IS healthy nothing fails — the suite merely signs
//! several hundred throwaway commits with the operator's key.
//!
//! Two layers close it, and each covers a case the other cannot:
//!
//! 1. **[`hermetic_git`] / [`hermetic_git_in`] put the settings on the command
//!    line** as `git -c <key>=<value>`. Command-line `-c` is the highest
//!    precedence git has, so no repo-local, global, or system value can defeat
//!    it — and it applies to the FIRST invocation, before any `git config` has
//!    had a chance to run. Config written into the repo cannot protect the
//!    `git init` that creates the repo, nor a `git clone`, nor a command run
//!    against a bare remote that has no config of ours at all.
//! 2. **[`write_hermetic_config`] additionally writes the settings repo-local.**
//!    `-c` only binds the invocations *this crate* spawns. Production VCS commands
//!    carry the same behavioral overrides through `VcsCommand`, but
//!    intentionally inherit identity and trunk. Seeding the fixture supplies
//!    those test-only facts to every process that touches it.
//!
//! [`HERMETIC_OVERRIDES`] adds fixture identity/trunk to the production
//! [`GIT_EXECUTION_OVERRIDES`] definition. Everything in it
//! was chosen against an observed or demonstrated leak, not defensively:
//!
//! - `commit.gpgsign` / `tag.gpgsign` — the observed gate failure.
//! - `user.name` / `user.email` — a fixture that omits them is red on any host
//!   with no global identity. Supplying them per-invocation makes each call
//!   self-sufficient rather than dependent on a `git config` that ran earlier.
//! - `core.hooksPath` — measured: a global `core.hooksPath` whose `pre-commit`
//!   exits non-zero fails the seed commit of an unrelated fixture repo. Aiming
//!   it at `/dev/null` disables every hooks-DIRECTORY hook (git is silent about
//!   a missing hooks directory), which `--no-verify` does not do.
//! - `hook.<event>.enabled` / `core.fsmonitor` — measured (git 2.56): a
//!   `hook.<name>.command` in the global or repository config runs under
//!   `core.hooksPath=/dev/null`, and a configured `core.fsmonitor` command runs
//!   inside `git status` and `git check-ignore`. The production set switches off
//!   each githooks(5) event and the fsmonitor; its module doc states the
//!   refused set.
//! - `init.defaultBranch` — measured: a bare `git init` adopts the operator's
//!   configured default branch name, so a fixture that does not pass `-b` has
//!   an operator-dependent trunk.
//! - `core.autocrlf` — a global `true` rewrites line endings on checkout, which
//!   breaks byte-identical content assertions against a checked-out worktree.
//! - `gc.auto` / `maintenance.auto` — MEASURED (git 2.54.0): a
//!   `git commit` spawns `git maintenance run --auto`, DETACHED by default,
//!   and its loose-objects repack rewrote `objects/pack` mid-flight — a
//!   `.tmp` pack both `jj` adoption and `git fsck` refused. A kata spawn must
//!   never detach repo mutation a concurrent reader can trip over.
//! - `core.excludesFile` — MEASURED (git 2.43.0): with a global
//!   excludes file containing `.jj/` and `/agents/`, `git check-ignore` reports
//!   those paths IGNORED in a fixture repo that has no `.gitignore` at all. A
//!   test whose RED arm is "this repo does NOT ignore kata's artifact roots"
//!   (`kata doctor`'s `target_repo_ignore` row) then passes for a reason that
//!   has nothing to do with the fixture. Aiming it at a path that cannot exist
//!   makes the fixture's ignore rules exactly the ones the fixture wrote.
//!
//! Two more were checked and deliberately left out: `commit.template` is
//! ignored when `-m` is passed (measured), and every commit here passes `-m`;
//! and `gpg.format` / `gpg.program` only matter to a signing run, which
//! `commit.gpgsign=false` has already prevented.
//!
//! Callers that need a different value for one of these — a fixture that
//! deliberately commits under a second identity, say — just pass their own `-c`
//! in the argument list. Git takes the LAST `-c` for a key, and the caller's
//! args land after this prefix.
//!
//! # The pins are also a BLIND SPOT, and [`crate::host_repo`] is the axis out
//!
//! Two of these overrides pin a fact kata must RESOLVE about a real host, and
//! pinning them is what makes the suite structurally unable to fail on it.
//! `init.defaultBranch = main` means every fixture repository in this workspace
//! has a trunk named `main` — so a hard-coded `"main"` in kata would agree with
//! the pin and no fixture test could disagree with it. `user.name` /
//! `user.email` are pinned, so a commit authored under jj's EMPTY identity would
//! pass every fixture unless something asserted the author — **BOTH halves are
//! closed**:
//! `crates/vcs/tests/identity_binding.rs` and
//! `crates/vcs/tests/host_binding_known_red.rs` read the author BACK
//! from the repository and compare it to the identity the fixture declared.
//!
//! [`crate::host_repo::HostBindings`] is where a fixture VARIES one of those two
//! deliberately. It never unpins anything: its defaults are DERIVED from
//! [`HERMETIC_OVERRIDES`] (so a fixture that opts out is byte-identical to
//! today), it adds an explicit `git init -b <trunk>` on top of the still-pinned
//! `init.defaultBranch`, and it writes a declared identity into the repository's
//! own config — the layer a process kata spawns can actually read.

use kata_types::git_policy::GIT_EXECUTION_OVERRIDES;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The git settings a test fixture must state rather than inherit, as
/// `(key, value)` pairs. See the module docs for why each one is here.
///
/// Applied on the command line by [`hermetic_git`] and written repo-local by
/// [`write_hermetic_config`], so the two layers can never drift apart.
pub const HERMETIC_OVERRIDES: &[(&str, &str)] = &fixture_overrides();

const FIXTURE_IDENTITY_OVERRIDES: &[(&str, &str)] = &[
    ("user.name", "kata test"),
    ("user.email", "test@example.invalid"),
    ("init.defaultBranch", "main"),
];

const fn fixture_overrides()
-> [(&'static str, &'static str); GIT_EXECUTION_OVERRIDES.len() + FIXTURE_IDENTITY_OVERRIDES.len()]
{
    let mut result = [("", ""); GIT_EXECUTION_OVERRIDES.len() + FIXTURE_IDENTITY_OVERRIDES.len()];
    let mut index = 0;
    while index < FIXTURE_IDENTITY_OVERRIDES.len() {
        result[index] = FIXTURE_IDENTITY_OVERRIDES[index];
        index += 1;
    }
    index = 0;
    while index < GIT_EXECUTION_OVERRIDES.len() {
        result[index + FIXTURE_IDENTITY_OVERRIDES.len()] = GIT_EXECUTION_OVERRIDES[index];
        index += 1;
    }
    result
}

/// A `git` [`Command`] carrying [`HERMETIC_OVERRIDES`] as `-c key=value`, with
/// no subcommand yet.
///
/// The caller adds its own directory selection (`-C <dir>` or
/// [`Command::current_dir`]) and the subcommand. Because git requires `-c`
/// before the subcommand, add nothing to the returned command until after the
/// options you want overridden.
#[must_use]
pub fn hermetic_git() -> Command {
    let mut cmd = Command::new("git");
    for (key, value) in HERMETIC_OVERRIDES {
        cmd.arg("-c").arg(format!("{key}={value}"));
    }
    cmd
}

/// [`hermetic_git`] aimed at `repo` via `git -C <repo>`.
#[must_use]
pub fn hermetic_git_in(repo: &Path) -> Command {
    let mut cmd = hermetic_git();
    cmd.arg("-C").arg(repo);
    cmd
}

/// Write [`HERMETIC_OVERRIDES`] into `repo`'s LOCAL config.
///
/// This is the layer that reaches processes we do not spawn: kata's own
/// production code shells `git` against these fixtures, and a linked worktree
/// shares this config file. Requires `repo` to already be a git repository.
///
/// Panics if any `git config` invocation fails — this is a test helper, so a
/// fixture that cannot be made hermetic is a hard failure.
pub fn write_hermetic_config(repo: &Path) {
    for (key, value) in HERMETIC_OVERRIDES {
        run_git(repo, &["config", key, value]);
    }
}

/// Run `git -C <repo> <args...>` hermetically and assert it succeeded.
///
/// Panics with the captured stderr if the invocation fails — this is a
/// test helper, so a non-zero git exit is a hard test failure.
pub fn run_git(repo: &Path, args: &[&str]) {
    let out = hermetic_git_in(repo)
        .args(args)
        .output()
        .expect("git invocation");
    assert!(
        out.status.success(),
        "git {args:?} failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Add the git remote `name` to `repo`, configured the way a forge's is, and
/// answered offline by the bare repository `bare`: its URL is
/// `https://<repository>.git` (`repository` is `HOST/OWNER/REPO`), and a
/// `url.<bare>.insteadOf` sends every git push and read of it to `bare`. A
/// `forge_export` reads the forge repository off the remote's configured URL,
/// before that rewrite, while the cells read the pushes back off `bare`.
pub fn add_forge_remote(repo: &Path, name: &str, bare: &Path, repository: &str) {
    let url = format!("https://{repository}.git");
    run_git(repo, &["remote", "add", name, &url]);
    run_git(
        repo,
        &["config", &format!("url.{}.insteadOf", bare.display()), &url],
    );
}

/// Initialize a fresh git repository at `repo` (which must already exist),
/// seeded with a single `README.md` commit on `main` so `HEAD` is reachable.
///
/// The caller-chosen-path counterpart to [`init_git_repo`], for fixtures that
/// need the repo at a specific location inside a directory tree they already
/// own. Both layers of hermeticity are applied: the invocations here carry
/// [`HERMETIC_OVERRIDES`] on the command line, and the finished repo also
/// carries them locally for any process kata spawns against it later.
pub fn init_git_repo_at(repo: &Path) {
    run_git(repo, &["init", "-q", "-b", "main"]);
    write_hermetic_config(repo);
    std::fs::write(repo.join("README.md"), "seed\n").expect("seed file");
    run_git(repo, &["add", "README.md"]);
    run_git(repo, &["commit", "-q", "-m", "seed"]);
}

/// Initialize a fresh git repository in a new temp directory, seeded with a
/// single `README.md` commit on `main` so `HEAD` is reachable.
///
/// Returns the owning [`tempfile::TempDir`] (keep it alive for the repo's
/// lifetime) and the repository path. The repo is hermetic against the
/// operator's git configuration — see the module docs.
#[must_use]
pub fn init_git_repo() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().to_path_buf();
    init_git_repo_at(&repo);
    (tmp, repo)
}
