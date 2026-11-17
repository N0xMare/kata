//! Host bindings — the axis along which a fixture may deliberately VARY one fact
//! about the host, while every other hermetic pin stays exactly where it is.
//!
//! # Why this module exists
//!
//! [`crate::git`] pins the operator's git configuration out of every fixture, and
//! its module doc explains each pin against an observed leak. Those pins are
//! correct and this module does not weaken any of them.
//!
//! But hermeticity has a cost that is invisible from inside it. `init.defaultBranch`
//! is pinned to `main`, so **every fixture repository in this workspace has a trunk
//! named `main`**, and a kata that hard-coded trunk as `main` would agree with
//! it. Two constants agreeing is not a test. No
//! suite that only ever builds trunk-`main` repositories can fail on a repository
//! whose trunk is `master`, because it never builds one. The same shape held for
//! identity: `user.name` / `user.email` are pinned, so unless something ASSERTS
//! that a kata-authored commit carries them, kata authoring commits with jj's
//! EMPTY identity is a fact thousands of green tests cannot see. **Both bindings
//! are resolved** — trunk by `kata_vcs::trunk`, identity by
//! `kata_vcs::identity` — and this axis is what their proofs are built on.
//!
//! **The hermeticity that makes the suite trustworthy is precisely what blinds it to
//! every host binding.** This module gives the suite an axis along which a binding
//! can be varied on purpose, at a call site that names the value, without giving up
//! hermeticity anywhere else.
//!
//! # Two bindings, two mechanisms, because they are resolved from different places
//!
//! **Trunk is a construction parameter**, because trunk is a property of the
//! repository's own refs. [`HostBindings::with_trunk`] threads the name into
//! `git init -b <trunk>`, and the value is recorded on the returned [`HostRepo`] so
//! assertions read [`HostRepo::trunk`] instead of a literal. `init.defaultBranch`
//! stays pinned in [`crate::git::HERMETIC_OVERRIDES`]: the axis ADDS an explicit
//! `-b`, it never removes a pin, so a fixture that forgets to name a trunk still
//! gets a deterministic one and a bare `git init` anywhere still cannot inherit the
//! operator's.
//!
//! **Identity is a config-layer parameter**, because the question under test is
//! whether kata *resolves* the operator's identity — and a `-c user.name=…` on the
//! command line would bind only the git children THIS crate spawns, which is the
//! opposite of what must be varied. So a declared identity is written into the
//! repository's own config, where a process we do not spawn can read it, and the
//! fixture records what it declared.
//!
//! # What this module deliberately does NOT do
//!
//! It writes no **jj** config layer. jj 0.39 stores per-repo config outside the
//! repository under a generated config id (`jj_lib::secure_config::SecureConfig::new_repo`),
//! so a hermetic fixture cannot own it. The axis therefore states the FACT
//! ("this repository's operator identity is X") and leaves the MECHANISM ("which
//! config layer kata should read to discover it") to kata.
//!
//! **kata asks GIT, which makes the repo-LOCAL layer this module writes
//! exactly the right one.** `kata_vcs::identity` asks
//! `git -c user.useConfigOnly=true var GIT_AUTHOR_IDENT` at the repository root,
//! and the repo-local config is a layer that answer includes — it is also where
//! an `includeIf "gitdir:..."` resolves to. Measured: jj does NOT read git's
//! `user.name`/`user.email`, so a jj config layer would have proved nothing
//! about the shipped resolver.
//!
//! [`HostIdentity::Absent`] removes the repo-LOCAL identity only. It cannot remove
//! the operator's global identity from a process kata spawns — that would need
//! `GIT_CONFIG_GLOBAL` in a child environment this fixture does not own. Read a
//! result under `Absent` as "the repository declares no identity", never as "this
//! host has none".

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::git::{HERMETIC_OVERRIDES, hermetic_git_in, write_hermetic_config};

/// The value [`HERMETIC_OVERRIDES`] pins for `key`.
///
/// Derived, never transcribed: the axis's defaults ARE the pins, so a fixture that
/// does not opt in is byte-identical to today and the two cannot drift apart.
fn pinned(key: &str) -> &'static str {
    match HERMETIC_OVERRIDES.iter().find(|(name, _)| *name == key) {
        Some((_, value)) => value,
        None => panic!(
            "kata_test_utils::git::HERMETIC_OVERRIDES no longer pins `{key}`, so the host \
             binding axis has lost the default it derives from. Either restore the pin or \
             state the default here explicitly and say why it is no longer the pin."
        ),
    }
}

/// The trunk name a fixture gets when it does not name one: the same value
/// [`HERMETIC_OVERRIDES`] pins for `init.defaultBranch`.
#[must_use]
pub fn default_trunk() -> &'static str {
    pinned("init.defaultBranch")
}

/// The identity a fixture gets when it does not declare one: the same pair
/// [`HERMETIC_OVERRIDES`] pins for `user.name` / `user.email`.
#[must_use]
pub fn default_identity() -> HostIdentity {
    HostIdentity::named(pinned("user.name"), pinned("user.email"))
}

/// Trunk names worth sweeping in a table-driven case.
///
/// Four shapes, not four synonyms: git's two historical defaults, a gitflow trunk,
/// and one carrying a `/` — which is a legal git branch name AND a legal jj bookmark
/// name (kata mints `parked/<exec>` itself), so a resolver that string-splits on `/`
/// is caught here rather than in an operator's repository.
pub const TRUNK_NAMES: &[&str] = &["main", "master", "develop", "release/next"];

/// The identity a repository declares for whoever commits in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostIdentity {
    /// The repository declares this name/email pair in its own config.
    Declared { name: String, email: String },
    /// The repository declares no identity at all. See the module docs for what
    /// this does and does not prove.
    Absent,
}

impl HostIdentity {
    /// A declared name/email pair.
    #[must_use]
    pub fn named(name: &str, email: &str) -> Self {
        Self::Declared {
            name: name.to_owned(),
            email: email.to_owned(),
        }
    }

    /// `git log --format=%an <%ae>` rendering of the declared identity, for the
    /// assertion side of a test. `None` when [`Self::Absent`].
    #[must_use]
    pub fn git_author_line(&self) -> Option<String> {
        match self {
            Self::Declared { name, email } => Some(format!("{name} <{email}>")),
            Self::Absent => None,
        }
    }

    /// The `-c key=value` pairs that make an invocation of OURS commit under this
    /// identity. Empty for [`Self::Absent`], which leaves the
    /// [`HERMETIC_OVERRIDES`] prefix in force so a fixture with no declared
    /// identity can still write its own seed commit.
    fn command_line_overrides(&self) -> Vec<(&'static str, &str)> {
        match self {
            Self::Declared { name, email } => {
                vec![("user.name", name.as_str()), ("user.email", email.as_str())]
            }
            Self::Absent => Vec::new(),
        }
    }
}

/// The facts about the host that a fixture states rather than inherits.
///
/// Construct with [`HostBindings::new`], vary what the test is about, and
/// materialize with [`HostBindings::init_git_repo`] /
/// [`HostBindings::init_git_repo_at`].
///
/// ```no_run
/// # use kata_test_utils::host_repo::HostBindings;
/// let repo = HostBindings::new().with_trunk("master").init_git_repo();
/// assert_eq!(repo.trunk(), "master");
/// ```
#[derive(Clone, Debug)]
pub struct HostBindings {
    trunk: String,
    identity: HostIdentity,
    ambient_env: Vec<(OsString, OsString)>,
}

impl Default for HostBindings {
    fn default() -> Self {
        Self {
            trunk: default_trunk().to_owned(),
            identity: default_identity(),
            ambient_env: Vec::new(),
        }
    }
}

impl HostBindings {
    /// Today's pinned answers: trunk [`default_trunk`], identity
    /// [`default_identity`]. A fixture that varies nothing is byte-identical to one
    /// built by [`crate::git::init_git_repo`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// This repository's trunk is `name`.
    #[must_use]
    pub fn with_trunk(mut self, name: &str) -> Self {
        name.clone_into(&mut self.trunk);
        self
    }

    /// This repository's operator identity is `name <email>`.
    #[must_use]
    pub fn with_identity(mut self, name: &str, email: &str) -> Self {
        self.identity = HostIdentity::named(name, email);
        self
    }

    /// This repository declares no operator identity. See the module docs.
    #[must_use]
    pub fn without_identity(mut self) -> Self {
        self.identity = HostIdentity::Absent;
        self
    }

    /// Run the repository-CREATING git invocations under an extra environment
    /// variable.
    ///
    /// This exists for one job: proving the axis is impossible to use by accident.
    /// A test can point `GIT_CONFIG_GLOBAL` at an operator config whose
    /// `init.defaultBranch` is something else entirely and observe that a fixture
    /// which named no trunk still lands on [`default_trunk`]. Without it, that
    /// property could only be argued, not measured.
    #[must_use]
    pub fn with_ambient_env(mut self, key: &str, value: impl Into<OsString>) -> Self {
        self.ambient_env.push((OsString::from(key), value.into()));
        self
    }

    /// The trunk this fixture will build.
    #[must_use]
    pub fn trunk(&self) -> &str {
        &self.trunk
    }

    /// The identity this fixture will declare.
    #[must_use]
    pub fn identity(&self) -> &HostIdentity {
        &self.identity
    }

    /// Materialize the repository in a fresh temp directory.
    #[must_use]
    pub fn init_git_repo(self) -> HostRepo {
        let tmp = tempfile::tempdir().expect("host repo tempdir");
        let path = tmp.path().to_path_buf();
        let mut repo = self.seed(path);
        repo.tmp = Some(tmp);
        repo
    }

    /// Materialize the repository at a caller-owned path, which must already exist.
    #[must_use]
    pub fn init_git_repo_at(self, path: &Path) -> HostRepo {
        self.seed(path.to_path_buf())
    }

    fn seed(self, path: PathBuf) -> HostRepo {
        let repo = HostRepo {
            tmp: None,
            path,
            bindings: self,
        };

        // The axis: an EXPLICIT `-b`. `init.defaultBranch` stays pinned underneath
        // it, so this overrides a deterministic value rather than an inherited one.
        repo.run_git(&["init", "-q", "-b", repo.trunk()]);

        // Both hermetic layers, unchanged — command line above, repo-local here.
        write_hermetic_config(&repo.path);

        // ...then the ONE binding this fixture varies, written where a process we
        // do not spawn can read it.
        match &repo.bindings.identity {
            HostIdentity::Declared { name, email } => {
                repo.run_git(&["config", "user.name", name]);
                repo.run_git(&["config", "user.email", email]);
            }
            HostIdentity::Absent => {
                // `--unset` on an absent key exits 5; that is a success for us.
                repo.git()
                    .args(["config", "--unset", "user.name"])
                    .output()
                    .expect("git config");
                repo.git()
                    .args(["config", "--unset", "user.email"])
                    .output()
                    .expect("git config");
            }
        }

        std::fs::write(repo.path.join("README.md"), "seed\n").expect("seed file");
        repo.run_git(&["add", "README.md"]);
        repo.run_git(&["commit", "-q", "-m", "seed"]);
        repo
    }
}

/// A git repository whose host bindings are STATED, not inherited.
///
/// Hold it for the repository's lifetime — when built by
/// [`HostBindings::init_git_repo`] it owns the temp directory.
#[derive(Debug)]
pub struct HostRepo {
    tmp: Option<tempfile::TempDir>,
    path: PathBuf,
    bindings: HostBindings,
}

impl HostRepo {
    /// The repository root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The trunk this repository was built with.
    #[must_use]
    pub fn trunk(&self) -> &str {
        self.bindings.trunk()
    }

    /// The `refs/heads/<trunk>` name, for assertions against a git ref.
    #[must_use]
    pub fn trunk_ref(&self) -> String {
        format!("refs/heads/{}", self.bindings.trunk())
    }

    /// The identity this repository declares.
    #[must_use]
    pub fn identity(&self) -> &HostIdentity {
        self.bindings.identity()
    }

    /// A hermetic `git -C <repo>` carrying this repository's declared identity and
    /// ambient environment. Caller args land after the prefix, so a caller's own
    /// `-c` still wins (git takes the LAST `-c` for a key).
    #[must_use]
    pub fn git(&self) -> Command {
        let mut cmd = hermetic_git_in(&self.path);
        for (key, value) in self.bindings.identity.command_line_overrides() {
            cmd.arg("-c").arg(format!("{key}={value}"));
        }
        for (key, value) in &self.bindings.ambient_env {
            cmd.env(key, value);
        }
        cmd
    }

    /// Run [`Self::git`] with `args` and assert it succeeded.
    pub fn run_git(&self, args: &[&str]) {
        let out = self.git().args(args).output().expect("git invocation");
        assert!(
            out.status.success(),
            "git {args:?} failed in {}: stderr={}",
            self.path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Trimmed stdout of [`Self::git`] with `args`, asserting success.
    #[must_use]
    pub fn git_stdout(&self, args: &[&str]) -> String {
        let out = self.git().args(args).output().expect("git invocation");
        assert!(
            out.status.success(),
            "git {args:?} failed in {}: stderr={}",
            self.path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// What `HEAD` resolves to symbolically, e.g. `refs/heads/master`.
    #[must_use]
    pub fn symbolic_head(&self) -> String {
        self.git_stdout(&["symbolic-ref", "HEAD"])
    }

    /// The commit `refs/heads/<trunk>` points at.
    #[must_use]
    pub fn trunk_sha(&self) -> String {
        self.git_stdout(&["rev-parse", &self.trunk_ref()])
    }

    /// `<name> <email>` of `rev`'s AUTHOR, exactly as the commit object records it.
    ///
    /// This is the read surface an operator has: an empty jj identity reaches git
    /// as jj-lib's `EMPTY_STRING_PLACEHOLDER` (`JJ_EMPTY_STRING`), because git
    /// refuses an empty ident field.
    #[must_use]
    pub fn commit_author(&self, rev: &str) -> String {
        self.git_stdout(&["show", "-s", "--format=%an <%ae>", rev])
    }

    /// `<name> <email>` of `rev`'s COMMITTER.
    #[must_use]
    pub fn commit_committer(&self, rev: &str) -> String {
        self.git_stdout(&["show", "-s", "--format=%cn <%ce>", rev])
    }

    /// A repo-LOCAL config value, or `None` when the key is unset there.
    ///
    /// Deliberately spawns a PLAIN `git` with no `-c` prefix: the question is what
    /// the repository itself declares to a process we did not spawn.
    #[must_use]
    pub fn local_config(&self, key: &str) -> Option<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .args(["config", "--local", "--get", key])
            .output()
            .expect("git config --get");
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    /// Every `refs/heads/*` in the repository, sorted.
    #[must_use]
    pub fn branch_refs(&self) -> Vec<String> {
        let mut refs: Vec<String> = self
            .git_stdout(&["for-each-ref", "--format=%(refname)", "refs/heads/"])
            .lines()
            .map(str::to_owned)
            .collect();
        refs.sort();
        refs
    }
}
