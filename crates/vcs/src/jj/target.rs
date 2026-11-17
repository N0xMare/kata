//! Target resolution and the target PINS for the jj provider.
//!
//! A target is resolved before its execution is accepted, and what it resolved
//! is pinned at once under [`TARGET_PIN_PREFIX`]: `<id>/head` at the frozen head
//! and `<id>/compare` at the compare base. From then until the execution's
//! workspace exists, the pin is the only thing keeping a commit a moved trunk
//! no longer reaches from being collected. jj never imports the namespace (its
//! git import reads `refs/heads`, `refs/remotes` and `refs/tags` only), and the
//! trunk resolver ranks only local branches and `refs/remotes/*/HEAD`.
//!
//! Pins are git refs written through gix into the git store behind the jj
//! backend (the colocated `.git`, or a native repository's internal store); an
//! `unborn` target pins nothing. A backend with no git store (jj's simple
//! backend) holds no pin: a target with a commit to pin is refused
//! [`TARGET_REQUIRES_GIT_BACKEND`] there, and release and the sweep find
//! nothing to do. A pin is released by the execution's terminal
//! cleanup obligation, at once when a submission is refused after its
//! resolution, and a pin no execution owns any more — a refusal or a crash
//! between resolution and acceptance — is collected by the boot sweep.
//!
//! Resolution answers only once its pins are durable (the provider's
//! `durably` barrier), so an acceptance never outlives them across a power
//! loss; release and the sweep answer once their deletions are, each in one
//! ref transaction, because a deletion of a packed pin rewrites the
//! repository-wide `packed-refs` that holds every packed ref. A pin a power loss TORE before its barrier — a loose file that does
//! not parse, which a ref store refuses to instantiate — is deleted by release
//! and by the sweep like an intact one (gix's `PreviousValue::Any` reads no
//! old value), and the sweep rewrites an owned execution's torn pin at its
//! recorded target (`TargetPinClaim`).

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
use jj_lib::object_id::ObjectId as _;
use jj_lib::ref_name::RefNameBuf;
use jj_lib::repo::Repo as _;
use kata_types::git_policy::GIT_EXECUTION_OVERRIDES;
use kata_types::target::{
    CompareBase, ExecutionTarget, MAX_PR_BODY_BYTES, MAX_PR_TITLE_BYTES, PullRequestFacts,
    TARGET_FORGE_UNAVAILABLE, TARGET_PR_FETCH_FAILED, TARGET_PR_HEAD_RACED,
    TARGET_PR_NO_MERGE_BASE, TARGET_PR_REF_INVALID, TARGET_PR_REMOTE_UNRESOLVED,
    TARGET_PR_URL_INVALID, TARGET_REQUIRES_GIT_BACKEND, TargetHead, TargetRefusal, TargetSpec,
    is_pull_request_url, is_short_branch_name,
};
use kata_types::{KataError, KataResult};
use ulid::Ulid;

use super::JjBackend;
use super::census::common_git_dir;
use crate::process::VcsCommand;
use crate::trunk::TrunkResolution;
use kata_effects_contract::{Forge, ForgePullRequest};
use kata_effects_contract::{
    PULL_REQUEST_RESOLUTION_BOUND, TARGET_PIN_PREFIX, TargetPinClaim, TargetPinSweep,
};

/// The pin `<prefix><id>/<leaf>`.
fn pin_name(execution_id: Ulid, leaf: &str) -> String {
    format!("{TARGET_PIN_PREFIX}{execution_id}/{leaf}")
}

/// `raw` cut to at most `max` bytes at a character boundary, and whether the
/// cut dropped anything. A cut text is at least `max - 3` bytes long: a UTF-8
/// character is at most four bytes, so the boundary is at most three bytes
/// below `max`.
fn cut_at_char_boundary(mut raw: String, max: usize) -> (String, bool) {
    if raw.len() <= max {
        return (raw, false);
    }
    let mut cut = max;
    while !raw.is_char_boundary(cut) {
        cut -= 1;
    }
    raw.truncate(cut);
    (raw, true)
}

/// `git <overrides> --git-dir=<git_dir> <args>` under `bound`, with no
/// terminal to prompt on.
fn git_in(git_dir: &Path, bound: Duration) -> VcsCommand {
    let mut command = VcsCommand::new("git", GIT_EXECUTION_OVERRIDES, bound);
    command
        .arg(format!("--git-dir={}", git_dir.display()))
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

/// The forge's answer about pull request `number`, validated before any of it
/// is used. Refuses exactly: an answer about another number
/// ([`TARGET_FORGE_UNAVAILABLE`]); a head commit id that is not 40 lowercase
/// hex, or a base or head branch name that starts with `-`, is not a plain
/// short branch name, or that `git check-ref-format --branch` refuses
/// ([`TARGET_PR_REF_INVALID`]); a url that is not a forge URL of that pull
/// request ([`TARGET_PR_URL_INVALID`]).
fn validate_pull_request(
    git_dir: &Path,
    number: u64,
    pr: &ForgePullRequest,
    bound: Duration,
) -> KataResult<()> {
    if pr.number != number {
        return Err(TargetRefusal::new(
            TARGET_FORGE_UNAVAILABLE,
            format!(
                "asked for pull request #{number}, the forge answered #{}",
                pr.number
            ),
        )
        .into());
    }
    let is_commit_id = pr.head_ref_oid.len() == 40
        && pr
            .head_ref_oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !is_commit_id {
        return Err(TargetRefusal::new(
            TARGET_PR_REF_INVALID,
            format!(
                "pull request #{number}'s head commit `{}` is not a 40-hex commit id",
                pr.head_ref_oid.escape_debug()
            ),
        )
        .into());
    }
    for (role, name) in [("base", &pr.base_ref_name), ("head", &pr.head_ref_name)] {
        // `-` first: a name that is an option never reaches git's argv.
        let plain = !name.starts_with('-')
            && is_short_branch_name(name)
            && git_accepts_branch_name(git_dir, name, bound)?;
        if !plain {
            return Err(TargetRefusal::new(
                TARGET_PR_REF_INVALID,
                format!(
                    "pull request #{number}'s {role} branch `{}` is not a plain git branch name",
                    name.escape_debug()
                ),
            )
            .into());
        }
    }
    if !is_pull_request_url(&pr.url, number) {
        return Err(TargetRefusal::new(
            TARGET_PR_URL_INVALID,
            format!(
                "pull request #{number}'s url `{}` is not a bounded https forge URL of it",
                pr.url.escape_debug()
            ),
        )
        .into());
    }
    Ok(())
}

/// Whether `git check-ref-format --branch <name>` accepts `name` as exactly
/// itself. The caller has refused a leading `-` and `@{`, so the argument is
/// never an option and never a reflog expansion. A check that starts with the
/// resolution's bound spent, or outlives it, is [`TARGET_FORGE_UNAVAILABLE`]:
/// the forge's reads spent the bound the check shares.
fn git_accepts_branch_name(git_dir: &Path, name: &str, bound: Duration) -> KataResult<bool> {
    let elapsed = || -> KataError {
        TargetRefusal::new(
            TARGET_FORGE_UNAVAILABLE,
            format!(
                "the resolution's time bound elapsed before the branch name `{}` was checked",
                name.escape_debug()
            ),
        )
        .into()
    };
    if bound.is_zero() {
        return Err(elapsed());
    }
    let output = git_in(git_dir, bound)
        .args(["check-ref-format", "--branch", name])
        .output()
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::TimedOut => elapsed(),
            _ => KataError::Internal(format!(
                "`git check-ref-format --branch` did not run: {err}"
            )),
        })?;
    Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).trim_end() == name)
}

/// A repository URL's `(host, path)`, case-folded, with the path's leading
/// and trailing `/` and one trailing `.git` dropped — the identity an https,
/// ssh or scp-like spelling of one forge repository share.
pub(super) fn repository_identity(url: &gix::Url) -> Option<(String, String)> {
    let host = url.host()?.to_ascii_lowercase();
    let path = std::str::from_utf8(&url.path).ok()?.trim_matches('/');
    let path = path
        .strip_suffix(".git")
        .unwrap_or(path)
        .trim_end_matches('/');
    (!path.is_empty()).then(|| (host, path.to_ascii_lowercase()))
}

/// The ONE git remote whose configured fetch URL — read before any
/// `url.*.insteadOf` rewrite — names the repository at `repository_url`, by
/// [`repository_identity`]. None or several refuse
/// [`TARGET_PR_REMOTE_UNRESOLVED`]; so does a remote name starting with `-`,
/// which never reaches git's argv. Each refusal names the recourse that fixes
/// it.
fn forge_remote(store: &gix::Repository, repository_url: &str) -> KataResult<String> {
    let unresolved = |detail: String| -> KataError {
        TargetRefusal::new(TARGET_PR_REMOTE_UNRESOLVED, detail).into()
    };
    let wanted = gix::url::parse(repository_url.as_bytes().into())
        .ok()
        .as_ref()
        .and_then(repository_identity)
        .ok_or_else(|| {
            unresolved(format!(
                "the forge serves `{}`, which is not a repository URL; name the forge \
                 repository with `gh repo set-default`",
                repository_url.escape_debug()
            ))
        })?;
    let mut matched = Vec::new();
    for name in store.remote_names() {
        let Some(Ok(remote)) = store.try_find_remote_without_url_rewrite(name.as_ref()) else {
            continue;
        };
        if remote
            .url(gix::remote::Direction::Fetch)
            .and_then(repository_identity)
            .is_some_and(|identity| identity == wanted)
        {
            matched.push(name.to_string());
        }
    }
    match matched.as_slice() {
        [name] if name.starts_with('-') => Err(unresolved(format!(
            "the git remote `{}` fetches from `{repository_url}`, and a remote name starting \
             with `-` would be read as an option; rename it with `git remote rename`",
            name.escape_debug()
        ))),
        [name] => Ok(name.clone()),
        [] => Err(unresolved(format!(
            "no git remote of this repository fetches from `{repository_url}`, the repository \
             the forge serves; add one git remote for it, or name the forge repository with \
             `gh repo set-default`"
        ))),
        names => Err(unresolved(format!(
            "the git remotes {names:?} all fetch from `{repository_url}`, so kata cannot tell \
             which one to fetch the pull request from; remove all but one of them"
        ))),
    }
}

/// `git fetch` pull request `number`'s head and its base branch straight into
/// `execution_id`'s pins — each refspec its own argument, `base` checked
/// already — and nothing else: no tags, no submodules, no `FETCH_HEAD`, no
/// automatic maintenance, and `--refmap=` so no configured refspec updates a
/// remote-tracking ref on the way.
fn fetch_pull_request(
    git_dir: &Path,
    remote: &str,
    number: u64,
    base: &str,
    execution_id: Ulid,
    bound: Duration,
) -> KataResult<()> {
    let failed = |detail: String| -> KataError {
        TargetRefusal::new(
            TARGET_PR_FETCH_FAILED,
            format!("fetching pull request #{number} from `{remote}`: {detail}"),
        )
        .into()
    };
    if bound.is_zero() {
        return Err(failed(
            "the resolution's time bound elapsed before the fetch ran".to_owned(),
        ));
    }
    let output = git_in(git_dir, bound)
        .args([
            "fetch",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--no-auto-maintenance",
            "--refmap=",
            "--",
            remote,
        ])
        .arg(format!(
            "+refs/pull/{number}/head:{}",
            pin_name(execution_id, "head")
        ))
        .arg(format!(
            "+refs/heads/{base}:{}",
            pin_name(execution_id, "compare")
        ))
        .output()
        .map_err(|err| failed(format!("did not finish: {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(failed(
            cut_at_char_boundary(stderr.trim().to_owned(), MAX_QUOTED_STDERR_BYTES).0,
        ));
    }
    Ok(())
}

/// The most bytes of a failed fetch's stderr a refusal quotes.
const MAX_QUOTED_STDERR_BYTES: usize = 1024;

impl JjBackend {
    /// The git store behind the jj backend (the colocated `.git`, or a native
    /// repository's internal store), opened through gix — or `None` when the
    /// backend has no git store at all (jj's simple backend), which therefore
    /// holds no pin.
    pub(super) fn target_git_store(&self) -> KataResult<Option<gix::Repository>> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let Ok(git_backend) = jj_lib::git::get_git_backend(repo.store()) else {
            return Ok(None);
        };
        let git_dir = common_git_dir(git_backend.git_repo_path());
        gix::open(&git_dir).map(Some).map_err(|err| {
            KataError::Internal(format!(
                "failed to open the git store {} for target pins: {err}",
                git_dir.display()
            ))
        })
    }

    /// [`Self::target_git_store`] for a target that has something to pin:
    /// a backend with no git store refuses [`TARGET_REQUIRES_GIT_BACKEND`].
    fn pinning_git_store(&self, spec: &TargetSpec) -> KataResult<gix::Repository> {
        self.target_git_store()?.ok_or_else(|| {
            KataError::Validation(format!(
                "{TARGET_REQUIRES_GIT_BACKEND}: target `{spec}` freezes a commit, and this \
                 repository's jj store has no git object store to pin it in (jj's simple \
                 backend); run kata over a git-backed jj repository"
            ))
        })
    }

    /// Resolve `spec`, then pin it. See
    /// [`crate::ExecutionWorkspaceProvider::resolve_target`].
    pub(super) fn resolve_and_pin_target(
        &self,
        execution_id: Ulid,
        spec: &TargetSpec,
        forge: Option<&dyn Forge>,
    ) -> KataResult<ExecutionTarget> {
        match spec {
            TargetSpec::Trunk => {
                let target = self.resolve_trunk_target()?;
                self.write_target_pins(execution_id, &target)?;
                Ok(target)
            }
            TargetSpec::PullRequest { number } => {
                let forge = forge.ok_or_else(|| {
                    TargetRefusal::new(
                        TARGET_FORGE_UNAVAILABLE,
                        format!("this node has no forge to read pull request #{number} from"),
                    )
                })?;
                self.resolve_pull_request_target(
                    execution_id,
                    *number,
                    forge,
                    PULL_REQUEST_RESOLUTION_BOUND,
                )
            }
        }
    }

    /// Resolve `pr:<number>` within `bound` — one deadline over every step —
    /// and pin it. The fetch writes the pins itself, so a refusal after it
    /// deletes them before answering.
    ///
    /// In order, each step's refusal preceding every later step's I/O:
    /// 1. a store with no git backend refuses [`TARGET_REQUIRES_GIT_BACKEND`]
    ///    before the forge is asked anything;
    /// 2. the forge's answer ([`Forge::resolve_pull_request`]) is validated
    ///    before any of it is used: its number is the one asked for, the head
    ///    commit id is 40 lowercase hex and both branch names are ones git
    ///    accepts ([`TARGET_PR_REF_INVALID`]), and the url is a forge URL of
    ///    that pull request ([`TARGET_PR_URL_INVALID`]). The head NAME is the
    ///    author's: `git check-ref-format --branch` checks it as one argument
    ///    after a leading `-` and `@{` are refused, and it is never composed
    ///    into a refspec or the fetch's argv;
    /// 3. the remote is the ONE git remote whose configured fetch URL names
    ///    the repository the forge serves ([`TARGET_PR_REMOTE_UNRESOLVED`]);
    /// 4. `git fetch` writes `+refs/pull/<N>/head` and `+refs/heads/<base>`
    ///    straight into the `head` and `compare` pins and nowhere else (no
    ///    tags, no remote-tracking refs, no `FETCH_HEAD`)
    ///    ([`TARGET_PR_FETCH_FAILED`]);
    /// 5. the fetched head must be the commit the forge named
    ///    ([`TARGET_PR_HEAD_RACED`]), and head and base must share history
    ///    ([`TARGET_PR_NO_MERGE_BASE`]), the merge base computed locally.
    ///
    /// The frozen title and body are cut to [`MAX_PR_TITLE_BYTES`] and
    /// [`MAX_PR_BODY_BYTES`] at a character boundary: they are advisory text,
    /// and the full text stays at the frozen url.
    pub(crate) fn resolve_pull_request_target(
        &self,
        execution_id: Ulid,
        number: u64,
        forge: &dyn Forge,
        bound: Duration,
    ) -> KataResult<ExecutionTarget> {
        let deadline = Instant::now() + bound;
        let remaining = || deadline.saturating_duration_since(Instant::now());
        let spec = TargetSpec::PullRequest { number };
        let store = self.pinning_git_store(&spec)?;
        let git_dir = store.git_dir().to_path_buf();

        let pr = forge.resolve_pull_request(number, remaining())?;
        validate_pull_request(&git_dir, number, &pr, remaining())?;
        let remote = forge_remote(&store, &forge.repository_url(remaining())?)?;

        let pinned = fetch_pull_request(
            &git_dir,
            &remote,
            number,
            &pr.base_ref_name,
            execution_id,
            remaining(),
        )
        .and_then(|()| self.read_fetched_pull_request(execution_id, &pr));
        let (head, compare, merge_base) = match pinned {
            Ok(fetched) => fetched,
            Err(refusal) => {
                // A failed fetch can still have written a pin; nothing will
                // admit this execution, so none is left for the sweep.
                Self::delete_pins_in(&store, &[execution_id])?;
                return Err(refusal);
            }
        };
        let (title, title_truncated) = cut_at_char_boundary(pr.title, MAX_PR_TITLE_BYTES);
        let (body, body_truncated) = cut_at_char_boundary(pr.body, MAX_PR_BODY_BYTES);
        Ok(ExecutionTarget {
            spec,
            head: TargetHead::Commit(head),
            branch: None,
            compare: Some(CompareBase {
                name: Some(pr.base_ref_name.clone()),
                commit: compare,
                merge_base,
            }),
            pull_request: Some(PullRequestFacts {
                number,
                url: pr.url,
                head_ref: pr.head_ref_name,
                base_ref: pr.base_ref_name,
                cross_repository: pr.is_cross_repository,
                title,
                title_truncated,
                body,
                body_truncated,
            }),
        })
    }

    /// The fetched pins, checked: the head is the commit the forge named, and
    /// head and base share a merge base. Answers `(head, compare, merge_base)`.
    fn read_fetched_pull_request(
        &self,
        execution_id: Ulid,
        pr: &ForgePullRequest,
    ) -> KataResult<(String, String, String)> {
        // A fresh handle: the fetch wrote the refs behind the first one.
        let store = self.pinning_git_store(&TargetSpec::PullRequest { number: pr.number })?;
        let pin = |leaf: &str| -> KataResult<gix::ObjectId> {
            let name = pin_name(execution_id, leaf);
            let mut reference = store.find_reference(name.as_str()).map_err(|err| {
                KataError::Internal(format!("the fetched pin {name} is not readable: {err}"))
            })?;
            reference.peel_to_id().map(gix::Id::detach).map_err(|err| {
                KataError::Internal(format!("the fetched pin {name} names no object: {err}"))
            })
        };
        let head = pin("head")?;
        let compare = pin("compare")?;
        if head.to_hex().to_string() != pr.head_ref_oid {
            return Err(TargetRefusal::new(
                TARGET_PR_HEAD_RACED,
                format!(
                    "pull request #{} moved: the forge named head {}, and the fetch found {head}; \
                     submit again",
                    pr.number, pr.head_ref_oid
                ),
            )
            .into());
        }
        let merge_base = match store.merge_base(head, compare) {
            Ok(base) => base.detach(),
            Err(gix::repository::merge_base::Error::NotFound { .. }) => {
                return Err(TargetRefusal::new(
                    TARGET_PR_NO_MERGE_BASE,
                    format!(
                        "pull request #{}'s head {head} and its base `{}` at {compare} share no \
                         history, so there is no range to review",
                        pr.number, pr.base_ref_name
                    ),
                )
                .into());
            }
            Err(err) => {
                return Err(KataError::Internal(format!(
                    "the merge base of {head} and {compare}: {err}"
                )));
            }
        };
        Ok((
            head.to_hex().to_string(),
            compare.to_hex().to_string(),
            merge_base.to_hex().to_string(),
        ))
    }

    /// Trunk, as the fork has always resolved it — the configured name, the
    /// remote's `HEAD`, or the sole local branch — re-imported from git first
    /// so the head is trunk NOW, not trunk at node boot. The compare base is
    /// the head's first parent ("review the last commit"); a root commit has
    /// none. jj reports a root commit's parent as its virtual all-zero root,
    /// which is no git object, so that parent is "none" — pinned, it would be a
    /// broken ref every later `git gc` refuses to run over. For the same reason
    /// a trunk bookmark AT the virtual root freezes an `unborn` head.
    fn resolve_trunk_target(&self) -> KataResult<ExecutionTarget> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let unborn = ExecutionTarget {
            spec: TargetSpec::Trunk,
            head: TargetHead::Unborn,
            branch: None,
            compare: None,
            pull_request: None,
        };
        let TrunkResolution::Resolved { name, .. } = self.resolve_trunk_in(repo.as_ref())? else {
            return Ok(unborn);
        };
        let repo = Self::refresh_trunk_from_git(repo, &name)?;
        let Some(head_id) = repo
            .view()
            .get_local_bookmark(&RefNameBuf::from(name.clone()))
            .as_normal()
            .cloned()
        else {
            return Err(KataError::Validation(format!(
                "the resolved trunk bookmark `{name}` is absent or conflicted in this \
                 repository, so there is no single commit to freeze as the run's target. \
                 Resolve the conflict, or name the trunk explicitly with `vcs.trunk`"
            )));
        };
        // A bookmark at jj's virtual root (a native repository whose trunk was
        // set before anything was committed) names no git commit: the run's base
        // is the empty root, exactly as for a repository with no trunk yet, and
        // there is nothing to pin.
        if head_id == *repo.store().root_commit_id() {
            return Ok(unborn);
        }
        let head = repo.store().get_commit(&head_id).map_err(|err| {
            KataError::Internal(format!("failed to load the trunk head commit: {err}"))
        })?;
        let compare = head
            .parent_ids()
            .first()
            .filter(|parent| *parent != repo.store().root_commit_id())
            .map(|parent| {
                let parent = parent.hex();
                CompareBase {
                    name: None,
                    commit: parent.clone(),
                    merge_base: parent,
                }
            });
        Ok(ExecutionTarget {
            spec: TargetSpec::Trunk,
            head: TargetHead::Commit(head_id.hex()),
            branch: Some(name),
            compare,
            pull_request: None,
        })
    }

    /// Point `<id>/head` at the frozen head and `<id>/compare` at the compare
    /// base. Unconditional writes, so a re-resolution of one id converges.
    fn write_target_pins(&self, execution_id: Ulid, target: &ExecutionTarget) -> KataResult<()> {
        let pins: Vec<(&str, &str)> = [
            ("head", target.head.commit()),
            (
                "compare",
                target
                    .compare
                    .as_ref()
                    .map(|compare| compare.commit.as_str()),
            ),
        ]
        .into_iter()
        .filter_map(|(leaf, commit)| commit.map(|commit| (leaf, commit)))
        .collect();
        if pins.is_empty() {
            return Ok(());
        }
        let store = self.pinning_git_store(&target.spec)?;
        let edits = pins
            .into_iter()
            .map(|(leaf, commit)| {
                let id = gix::ObjectId::from_hex(commit.as_bytes()).map_err(|err| {
                    KataError::Internal(format!(
                        "target pin {leaf}: `{commit}` is not an id: {err}"
                    ))
                })?;
                let name = pin_name(execution_id, leaf).try_into().map_err(|err| {
                    KataError::Internal(format!("target pin name for {execution_id}: {err}"))
                })?;
                Ok(RefEdit {
                    change: Change::Update {
                        // git keeps no reflog for refs outside heads, remotes and
                        // notes, so none is created; the host's own committer
                        // signs one only where its config asks for every ref to
                        // be logged.
                        log: LogChange {
                            mode: RefLog::AndReference,
                            force_create_reflog: false,
                            message: "kata: pin execution target".into(),
                        },
                        expected: PreviousValue::Any,
                        new: gix::refs::Target::Object(id),
                    },
                    name,
                    deref: false,
                })
            })
            .collect::<KataResult<Vec<_>>>()?;
        store.edit_references(edits).map_err(|err| {
            KataError::Internal(format!(
                "failed to pin the target of execution {execution_id}: {err}"
            ))
        })?;
        Ok(())
    }

    /// Delete `execution_id`'s pins, intact or torn; absent pins are not an
    /// error.
    pub(super) fn delete_target_pins(&self, execution_id: Ulid) -> KataResult<()> {
        let Some(store) = self.target_git_store()? else {
            return Ok(());
        };
        Self::delete_pins_in(&store, &[execution_id])
    }

    /// Delete both leaves of every execution in `executions`, in ONE ref
    /// transaction — so the repository-wide `packed-refs` is rewritten at most
    /// once, whatever the count. gix's delete with `PreviousValue::Any` reads no
    /// old value, so a TORN pin (a loose file that does not parse, which a ref
    /// store refuses to instantiate) is deleted like an intact one, and an absent
    /// one changes nothing.
    fn delete_pins_in(store: &gix::Repository, executions: &[Ulid]) -> KataResult<()> {
        let mut edits = Vec::new();
        for execution_id in executions {
            for leaf in ["head", "compare"] {
                edits.push(RefEdit {
                    change: Change::Delete {
                        expected: PreviousValue::Any,
                        log: RefLog::AndReference,
                    },
                    name: pin_name(*execution_id, leaf).try_into().map_err(|err| {
                        KataError::Internal(format!("target pin name for {execution_id}: {err}"))
                    })?,
                    deref: false,
                });
            }
        }
        if edits.is_empty() {
            return Ok(());
        }
        store.edit_references(edits).map_err(|err| {
            KataError::Internal(format!("failed to delete the target pins: {err}"))
        })?;
        Ok(())
    }

    /// Every pin under the prefix, by `(execution, leaf)`, with what it names:
    /// `Some(object)` for a ref the store reads, `None` for a TORN loose file
    /// (one that does not parse). A name under the prefix that is not
    /// `<ULID>/<head|compare>` is not kata's and is left out.
    fn listed_pins(
        store: &gix::Repository,
    ) -> KataResult<std::collections::BTreeMap<(Ulid, &'static str), Option<gix::ObjectId>>> {
        let mut pins = std::collections::BTreeMap::new();
        let mut note = |full: &str, names: Option<gix::ObjectId>| {
            let Some(rest) = full.strip_prefix(TARGET_PIN_PREFIX) else {
                return;
            };
            let Some((id, leaf)) = rest.split_once('/') else {
                return;
            };
            let leaf = match leaf {
                "head" => "head",
                "compare" => "compare",
                _ => return,
            };
            if let Ok(id) = Ulid::from_string(id) {
                pins.entry((id, leaf)).or_insert(names);
            }
        };
        // The ref store's view: every pin it can instantiate, loose or packed.
        let platform = store
            .references()
            .map_err(|err| KataError::Internal(format!("failed to list target pins: {err}")))?;
        let refs = platform
            .prefixed(TARGET_PIN_PREFIX.as_bytes())
            .map_err(|err| KataError::Internal(format!("failed to list target pins: {err}")))?;
        for reference in refs.flatten() {
            let full = reference.name().as_bstr().to_string();
            note(&full, reference.target().try_id().map(ToOwned::to_owned));
        }
        // The loose files themselves: a torn one the store would not
        // instantiate (it errs above and is skipped there) is listed here.
        for full in super::durability::loose_refs_under(store.common_dir(), "refs/kata/targets")? {
            note(&full, None);
        }
        Ok(pins)
    }

    /// The boot sweep. See [`crate::ExecutionWorkspaceProvider::sweep_target_pins`].
    pub(super) fn sweep_claimed_target_pins(
        &self,
        claim: &dyn Fn(Ulid) -> TargetPinClaim,
    ) -> KataResult<TargetPinSweep> {
        let mut sweep = TargetPinSweep::default();
        let Some(store) = self.target_git_store()? else {
            return Ok(sweep);
        };
        let pins = Self::listed_pins(&store)?;
        let executions: BTreeSet<Ulid> = pins.keys().map(|(id, _)| *id).collect();
        let mut unowned = Vec::new();
        for execution_id in executions {
            let target = match claim(execution_id) {
                TargetPinClaim::Unowned => {
                    unowned.push(execution_id);
                    continue;
                }
                TargetPinClaim::Owned(None) => continue,
                TargetPinClaim::Owned(Some(target)) => *target,
            };
            for (leaf, recorded) in [
                ("head", target.head.commit()),
                (
                    "compare",
                    target
                        .compare
                        .as_ref()
                        .map(|compare| compare.commit.as_str()),
                ),
            ] {
                let Some(names) = pins.get(&(execution_id, leaf)) else {
                    continue;
                };
                let intact = match names {
                    Some(object) => super::durability::object_intact(&store, *object)?,
                    None => false,
                };
                if intact {
                    continue;
                }
                let name = pin_name(execution_id, leaf);
                let rederived = recorded
                    .map(|commit| {
                        gix::ObjectId::from_hex(commit.as_bytes()).map_err(|err| {
                            KataError::Internal(format!(
                                "the recorded target of execution {execution_id} names `{commit}`, \
                                 not an object id: {err}"
                            ))
                        })
                    })
                    .transpose()?;
                match rederived {
                    Some(object) if super::durability::object_intact(&store, object)? => {
                        super::durability::rewrite_ref(
                            &store,
                            &name,
                            Some(object),
                            "kata: re-derive a torn execution target pin",
                        )?;
                        sweep.rederived.push(name);
                    }
                    _ => {
                        super::durability::rewrite_ref(
                            &store,
                            &name,
                            None,
                            "kata: delete a torn target pin",
                        )?;
                        sweep.head_absent.push(name);
                    }
                }
            }
        }
        Self::delete_pins_in(&store, &unowned)?;
        sweep.deleted = unowned.len();
        Ok(sweep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ref check that starts with the resolution's bound spent is refused
    /// `target_forge_unavailable` by name — the forge spent the bound — and
    /// never an internal error.
    #[test]
    fn a_ref_check_past_the_bound_is_refused_by_name() {
        let error = git_accepts_branch_name(&std::env::temp_dir(), "main", Duration::ZERO)
            .expect_err("a spent bound runs no check");
        assert!(
            matches!(&error, KataError::Validation(message)
                if message.starts_with(TARGET_FORGE_UNAVAILABLE)
                    && message.contains("time bound elapsed")),
            "a spent bound is a named refusal: {error:?}"
        );
    }
}
