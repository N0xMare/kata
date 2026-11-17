//! The jj half of the `forge_export` terminal effect: point a
//! kata-owned git branch at the commit the execution's claim delivers and push
//! it, all through the COLOCATED ROOT `.git`.
//!
//! ## Why the colocated root (and not a secondary workspace)
//!
//! jj-lib 0.39 colocation is ROOT-only: the secondary execution
//! workspaces under `agents/<exec>` have no independent git surface. What
//! `forge_export` pushes — the commit a `commit` effect finalized, or the one a
//! `promote` landed — is reachable from the root store, so every git-facing
//! step here runs against the root repo — which is exactly correct.
//!
//! ## Branch export mechanism (jj is never ahead of git)
//!
//! [`JjBackend::write_forge_branch_tagged`] sets a jj LOCAL BOOKMARK and then runs
//! jj's own `git::export_refs` in the SAME transaction. jj bookmarks are the
//! source of truth in a colocated repo; `export_refs` writes them into the
//! colocated `.git` AND records the exported ref in jj's `git_refs` view, so
//! jj's next status/import sees the branch as ALREADY EXPORTED — never as an
//! external git change to re-import. A raw `git branch -f` would instead leave
//! jj's `git_refs` view stale, so the next `jj git import` would treat the
//! branch as a new external ref (a desync); going bookmark → `export_refs`
//! keeps the ORDER right by construction.
//!
//! The lockstep is ONE-WAY. `export_refs` writes the git ref on disk inside the call and only
//! records the export on `tx.commit`, so a crash in between leaves git ahead of jj. What that
//! guarantees is the direction that matters here — a bookmark jj believes it exported IS in `.git`,
//! so the push below can never push a branch git does not have. See
//! [`JjBackend::export_bookmark_to_git`] for the measured behaviour of the other direction.
//!
//! ## Push semantics (`--force-with-lease=<ref>:<head>`)
//!
//! The branch name embeds the execution ulid (`kata/<exec>`), so kata OWNS it
//! exclusively. A re-driven or advanced export must be able to UPDATE it (a
//! rebase-land changes the commit id → a plain push would be rejected non-ff),
//! so a force is required. The force is leased on the head the export READ off
//! the remote before it recorded the push's intent ([`JjBackend::remote_branch_head`]),
//! never on a local remote-tracking ref: it lands only over exactly that head,
//! and REFUSES a branch that moved since the read — e.g. a reviewer pushing a
//! fixup onto the open PR's branch. That is the fail-closed, non-destructive
//! behavior a SINK wants: a moved remote fails the push with a typed error
//! rather than silently discarding a human's work.
//!
//! ## Narrowings
//!
//! * **`export_refs` exports ALL local bookmarks** into the colocated `.git`
//!   (that is jj's own export granularity), but the push writes one ref,
//!   `refs/heads/kata/<exec>` on the export's remote, at the commit the export
//!   recorded, and sends only objects that commit reaches. No write from
//!   outside kata in this closed set changes that — the local refs (a name
//!   shadowing the commit's id, replace refs), a graft file, and the
//!   configuration's `push.followTags` and `push.recurseSubmodules`:
//!   - the refspec's source is `<commit>^{commit}`, a full hex id of the
//!     repository's own object format (read by gix), which git resolves as
//!     that object under every one of its name rules — `<commit>`,
//!     `refs/<commit>`, `refs/tags/<commit>`, `refs/heads/<commit>`,
//!     `refs/remotes/<commit>`, `refs/remotes/<commit>/HEAD` — never as a ref,
//!     so neither the local `kata/<exec>` nor a ref spelled as the commit is
//!     read;
//!   - the push runs with replace objects off (`GIT_NO_REPLACE_OBJECTS=1`, no
//!     inherited `GIT_REPLACE_REF_BASE`), so no `refs/replace/<commit>`
//!     substitutes another object or another commit's content;
//!   - the push reads no graft file (`GIT_GRAFT_FILE=/dev/null`, over
//!     `.git/info/grafts` and an inherited `GIT_GRAFT_FILE`), so no graft
//!     gives the commit or an ancestor a parent whose objects would be packed;
//!   - `--no-follow-tags` and `--recurse-submodules=no` override
//!     `push.followTags` and `push.recurseSubmodules`, so no tag and no
//!     submodule's branch goes with it, and `only` cannot skip the branch.
//!
//!   The `kata/` prefix is
//!   [`crate::trunk::FORGE_BRANCH_PREFIX`], which is also what the trunk
//!   resolver excludes when counting operator branches.

use std::time::Duration;

use crate::process::{VcsCommand, forge_command_error, forge_exit_error};
use kata_effects_contract::FORGE_COMMAND_TIMEOUT;
use kata_types::git_policy::GIT_EXECUTION_OVERRIDES;

use jj_lib::backend::CommitId;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::RefNameBuf;
use jj_lib::repo::Repo as _;
use kata_types::{KataError, KataResult};

use super::JjBackend;

/// The operator's fix for a forge `git` that is not on `PATH`.
const GIT_NOT_FOUND: &str = "`git` not found on PATH; a colocated push shells the git CLI";

/// `url` as a refusal may show it: its host and path only. A configured URL
/// may carry a user name and password (`https://user:token@host/...`), and a
/// refusal is written into the attempt's durable failure reason, so neither
/// is ever rendered — nor the scheme or port, which name no credential but
/// which no refusal needs.
fn url_host_and_path(url: &gix::Url) -> String {
    let path = String::from_utf8_lossy(&url.path);
    match url.host() {
        Some(host) => format!("{host}/{}", path.trim_start_matches('/')),
        None => path.into_owned(),
    }
}

impl JjBackend {
    /// The tree of a commit in the repository — `forge_export`'s claim binds
    /// this when it names the LANDED candidate (post-`promote` the execution
    /// workspace is gone, so the live-workspace tree reads have no answer).
    /// Read through the root repo view; a commit the store does not hold is
    /// a rig inconsistency, surfaced `Internal`.
    pub(super) fn commit_tree_id(&self, commit_sha: &str) -> KataResult<String> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let commit_id = jj_lib::backend::CommitId::try_from_hex(commit_sha).ok_or_else(|| {
            KataError::Internal(format!("the commit id {commit_sha} is not valid hex"))
        })?;
        let commit = repo.store().get_commit(&commit_id).map_err(|err| {
            KataError::Internal(format!(
                "the commit {commit_sha} is not in the repository's store: {err}"
            ))
        })?;
        Ok(Self::merged_tree_id_hex(commit.tree_ids()))
    }

    /// Point the git branch `branch` at `commit_sha` in the COLOCATED ROOT
    /// `.git` via a jj local bookmark + `git::export_refs` (see the module doc
    /// for why this cannot desync jj's view), with `kata.effect` = `effect_tag`
    /// on the export transaction when a tag is given.
    ///
    /// `branch` is the plain branch name (`kata/<exec>`), not a `refs/heads/…`
    /// path. Fails if `commit_sha` is not a real commit in the store, or if
    /// jj's export reports the bookmark as failed (e.g. a non-colocated repo
    /// with no git backend).
    pub fn write_forge_branch_tagged(
        &self,
        branch: &str,
        commit_sha: &str,
        effect_tag: Option<&str>,
    ) -> KataResult<()> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;

        let commit_id = CommitId::try_from_hex(commit_sha).ok_or_else(|| {
            KataError::Internal(format!(
                "forge_export: candidate commit id is not valid hex: {commit_sha}"
            ))
        })?;
        repo.store().get_commit(&commit_id).map_err(|err| {
            KataError::Internal(format!(
                "forge_export: candidate commit {commit_sha} is not in the store: {err}"
            ))
        })?;

        let barrier = super::durability::RepositoryBarrier::for_git_store(repo.store())?;
        let mut tx = repo.start_transaction();
        let bookmark_name = RefNameBuf::from(branch.to_owned());
        tx.repo_mut()
            .set_local_bookmark_target(&bookmark_name, RefTarget::normal(commit_id));
        // Sync jj bookmarks → colocated git refs so `git push` sees the branch,
        // and record the export in jj's git_refs view (no desync). Shared with
        // every other ref-moving effect, so no effect leaves a git ref stale.
        Self::export_bookmark_to_git(tx.repo_mut(), branch, "forge_export")?;
        super::workspace_effect::tag_effect(&mut tx, effect_tag);
        super::durability::commit_transaction(
            &barrier,
            tx,
            format!("kata forge-export bookmark {branch}"),
            "forge_export: failed to commit jj export",
        )?;
        Ok(())
    }

    /// The git remote a `forge_export` into `branch` (the execution's frozen
    /// landable branch) pushes to — inherited, never guessed: git's PUSH
    /// remote for `branch`, the one `git push` on it would use
    /// (`branch.<branch>.pushRemote`, else `remote.pushDefault`, else
    /// `branch.<branch>.remote`, in gix's `Direction::Push` order) when it
    /// names a configured remote, else the repository's only remote.
    ///
    /// # Errors
    ///
    /// [`super::FORGE_REMOTE_UNRESOLVED`] for exactly its documented refused
    /// set, each naming the recourse.
    pub(super) fn forge_export_remote(&self, branch: &str) -> KataResult<String> {
        let unresolved = |detail: String| -> KataError {
            KataError::Validation(format!("{}: {detail}", super::FORGE_REMOTE_UNRESOLVED))
        };
        let store = self.target_git_store()?.ok_or_else(|| {
            unresolved(
                "this repository's jj store has no git backend, so it has no git remote to \
                 push to"
                    .to_owned(),
            )
        })?;
        let names: Vec<String> = store
            .remote_names()
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        // The keys `Direction::Push` reads, first to last; the refusals name
        // them all, since gix answers the value and not the key it came from.
        let push_keys = format!(
            "`branch.{branch}.pushRemote`, else `remote.pushDefault`, else \
             `branch.{branch}.remote`"
        );
        let inherited = match store.branch_remote_name(branch, gix::remote::Direction::Push) {
            Some(gix::remote::Name::Symbol(name)) => {
                let name = name.into_owned();
                if !names.contains(&name) {
                    return Err(unresolved(format!(
                        "the push remote git names for `{branch}` ({push_keys}) is `{}`, \
                         which is no configured git remote; set the first of those keys \
                         that is set to the remote `{branch}` is pushed to",
                        name.escape_debug()
                    )));
                }
                name
            }
            Some(gix::remote::Name::Url(url)) => {
                let url = gix::url::parse(url.as_ref()).map_or_else(
                    |_| "that does not parse".to_owned(),
                    |url| format!("`{}`", url_host_and_path(&url)),
                );
                return Err(unresolved(format!(
                    "the push remote git names for `{branch}` ({push_keys}) is a URL, \
                     {url}, not a configured git remote; add a remote for it and name \
                     that remote instead"
                )));
            }
            None => match names.as_slice() {
                [name] => name.clone(),
                [] => {
                    return Err(unresolved(
                        "this repository has no git remote to push the export to; add one \
                         with `git remote add`"
                            .to_owned(),
                    ));
                }
                several => {
                    return Err(unresolved(format!(
                        "no push remote is named for `{branch}` ({push_keys}) and this \
                         repository has the git remotes {several:?}, so kata cannot tell \
                         which one `{branch}` is pushed to; set one, e.g. `git branch \
                         --set-upstream-to <remote>/{branch} {branch}`"
                    )));
                }
            },
        };
        if inherited.starts_with('-') {
            return Err(unresolved(format!(
                "the git remote `{}` starts with `-` and would be read as an option; rename \
                 it with `git remote rename`",
                inherited.escape_debug()
            )));
        }
        Ok(inherited)
    }

    /// The forge repository the git remote `remote` names, `HOST/OWNER/REPO`
    /// case-folded: its configured push URL (`pushurl`, else `url`) before
    /// any `url.*.insteadOf` rewrite, by the identity the `pr:<N>` target's
    /// remote match uses (`target::repository_identity`).
    ///
    /// # Errors
    ///
    /// [`super::FORGE_REPOSITORY_UNRESOLVED`] for exactly its documented
    /// refused set, each naming the recourse.
    pub(super) fn forge_export_repository(&self, remote: &str) -> KataResult<String> {
        let unresolved = |detail: String| -> KataError {
            KataError::Validation(format!("{}: {detail}", super::FORGE_REPOSITORY_UNRESOLVED))
        };
        let store = self.target_git_store()?.ok_or_else(|| {
            unresolved(
                "this repository's jj store has no git backend, so no git remote names the \
                 forge repository to open the pull request in"
                    .to_owned(),
            )
        })?;
        let shown = remote.escape_debug();
        if !store
            .remote_names()
            .iter()
            .any(|name| name.as_ref() == remote.as_bytes())
        {
            return Err(unresolved(format!(
                "the push remote `{shown}` is no configured git remote; nothing names the forge \
                 repository to open the pull request in"
            )));
        }
        let url = match store.try_find_remote_without_url_rewrite(remote) {
            Some(Ok(found)) => found.url(gix::remote::Direction::Push).cloned(),
            Some(Err(err)) => {
                return Err(unresolved(format!(
                    "the git remote `{shown}` does not read as a remote: {err}"
                )));
            }
            None => None,
        };
        let url = url.ok_or_else(|| {
            unresolved(format!(
                "the git remote `{shown}` has no URL; set one with `git remote set-url`"
            ))
        })?;
        let named = super::target::repository_identity(&url)
            .filter(|(_, path)| {
                matches!(path.split('/').collect::<Vec<_>>().as_slice(),
                    [owner, repo] if !owner.is_empty() && !repo.is_empty())
            })
            .ok_or_else(|| {
                unresolved(format!(
                    "the git remote `{shown}` pushes to `{url}`, which names no forge \
                     repository `HOST/OWNER/REPO` (read before any `url.*.insteadOf` \
                     rewrite); set its URL to the forge repository's, e.g. \
                     `https://github.com/<owner>/<repo>.git`",
                    url = url_host_and_path(&url)
                ))
            })?;
        Ok(format!("{}/{}", named.0, named.1))
    }

    /// Push `commit` to `branch` (`kata/<exec>`) on `remote` from the
    /// colocated root, leased on what the caller READ (see the module doc):
    /// `expected_remote = Some(sha)` forces only over exactly that remote head,
    /// `None` only over ABSENCE. Anything else on the remote refuses the push
    /// instead of being overwritten.
    ///
    /// The refspec's source is `commit^{commit}`, resolved by object id and
    /// never as a ref name — not the local `refs/heads/<branch>`, nor a local
    /// ref spelled as `commit` itself — with replace objects off and the
    /// configuration's `push.followTags` and `push.recurseSubmodules`
    /// overridden (the module doc's narrowing states each): the push writes
    /// exactly the commit its caller recorded to `branch`, and nothing else,
    /// whatever a write from outside kata left in the local refs or in those
    /// two keys since kata wrote the branch. Its outcome is git's exit status
    /// alone; stderr (an ambiguous-refname warning included) only words an
    /// error.
    ///
    /// Shelling `git` at the colocated root is the established compat surface:
    /// kata never embeds git plumbing for the push, and the operator's
    /// credentials for `remote` — the one the export's claim inherited
    /// (`forge_export_remote`) — drive it.
    ///
    /// # Errors
    ///
    /// `Internal`, with nothing run, when the repository's object format
    /// cannot be read or `commit` is not a full hex object id of that format.
    pub fn push_forge_branch_expecting(
        &self,
        remote: &str,
        branch: &str,
        commit: &str,
        expected_remote: Option<&str>,
    ) -> KataResult<()> {
        let lease = format!(
            "--force-with-lease=refs/heads/{branch}:{}",
            expected_remote.unwrap_or("")
        );
        self.push_forge_branch_lease_at("git".as_ref(), remote, branch, commit, &lease)
    }

    /// The push under `lease_arg` with the `git` program as an argument, so a
    /// test can read the environment the push runs under.
    fn push_forge_branch_lease_at(
        &self,
        program: &std::ffi::OsStr,
        remote: &str,
        branch: &str,
        commit: &str,
        lease_arg: &str,
    ) -> KataResult<()> {
        // The repository's own object format (`extensions.objectFormat`, read
        // by gix; one gix cannot read — SHA-256 today — refuses here) fixes
        // the one length a full hex id has. A string of the other format's
        // length is no object id to git, which would resolve it as a ref
        // name. A full hex id never starts with `-`, so it is never read as
        // an option, and is never empty, which would make the refspec a
        // delete.
        let hex_len = gix::open(&self.repo_path)
            .map_err(|err| {
                KataError::Internal(format!(
                    "forge_export: the push could not read the object format of the git \
                     repository at {}: {err}",
                    self.repo_path.display()
                ))
            })?
            .object_hash()
            .len_in_hex();
        if !(commit.len() == hex_len && commit.bytes().all(|b| b.is_ascii_hexdigit())) {
            return Err(KataError::Internal(format!(
                "forge_export: the commit to push is not a full {hex_len}-digit hex object \
                 id: {commit:?}"
            )));
        }
        // `git push` matches a bare refspec source against the local refs
        // before it reads it as an object id, so a bare `<commit>` would send
        // what a local `refs/heads/<commit>`, `refs/tags/<commit>`,
        // `refs/remotes/<commit>` or `refs/remotes/<commit>/HEAD` holds.
        // `^{commit}` cannot appear in a ref name: the source is resolved as
        // an object name, where a full hex id of the repository's length is
        // that object under every one of git's name rules (`<commit>`,
        // `refs/<commit>` and the four above; git only warns, on stderr, that
        // a ref spelled as it exists), peeled to a commit — an id the
        // repository lacks, or one that names no commit, fails the push with
        // nothing sent.
        //
        // A `refs/replace/<commit>` would still substitute another object for
        // the commit — an annotated tag peels to whatever commit it tags — so
        // the push runs with replacement off (`GIT_NO_REPLACE_OBJECTS`, which
        // git honours whatever replace ref base or `core.useReplaceRefs` it
        // finds, and which its `pack-objects` child inherits), and without an
        // inherited `GIT_REPLACE_REF_BASE`. A graft would give a commit
        // parents it does not have, and `pack-objects` walks them, so the push
        // reads no graft file: `GIT_GRAFT_FILE=/dev/null` stands in for
        // `.git/info/grafts` and for an inherited `GIT_GRAFT_FILE` alike.
        //
        // `--no-follow-tags` and `--recurse-submodules=no` override the
        // configuration's `push.followTags` and `push.recurseSubmodules`: no
        // tag and no submodule's branch is pushed with the one ref, and
        // `only` cannot skip it under an exit 0.
        let refspec = format!("{commit}^{{commit}}:refs/heads/{branch}");
        let output = forge_git(program, &self.repo_path, FORGE_COMMAND_TIMEOUT)
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env_remove("GIT_REPLACE_REF_BASE")
            .env("GIT_GRAFT_FILE", "/dev/null")
            .arg("push")
            .arg("--no-follow-tags")
            .arg("--recurse-submodules=no")
            .arg(lease_arg)
            .arg(remote)
            .arg(&refspec)
            .output();

        let output =
            output.map_err(|err| forge_command_error("`git push`", GIT_NOT_FOUND, &err))?;
        if !output.status.success() {
            // Push failed — a diverged remote (lease) or auth/remote error. SINK:
            // trunk/candidate are untouched; the caller fails this stage typed.
            return Err(forge_exit_error(
                &format!("`git push` of `{branch}` to `{remote}`"),
                &output,
            ));
        }
        Ok(())
    }

    /// The remote's head sha for `refs/heads/<branch>` — `Some(sha)` when the
    /// remote advertises the ref, `None` when it advertises nothing, an Err
    /// when the remote cannot answer (a remote that cannot be read is NOT a
    /// `None` — a failed read taken for absence would lease a push on absence,
    /// or read a push NOT PERFORMED, over a state nobody saw).
    ///
    /// `git ls-remote` at the colocated root inherits the host's credentials
    /// and remote config exactly like `push_forge_branch_expecting`; `timeout` bounds the
    /// read so a dead remote resolves the attempt instead of hanging it.
    pub fn remote_branch_head(
        &self,
        remote: &str,
        branch: &str,
        timeout: Duration,
    ) -> KataResult<Option<String>> {
        self.remote_branch_head_at("git".as_ref(), remote, branch, timeout)
    }

    /// `remote_branch_head` with the `git` program as an argument so the
    /// spawn-error classification is exercisable in a test (a test cannot
    /// empty the process's PATH).
    fn remote_branch_head_at(
        &self,
        program: &std::ffi::OsStr,
        remote: &str,
        branch: &str,
        timeout: Duration,
    ) -> KataResult<Option<String>> {
        let output = forge_git(program, &self.repo_path, timeout)
            .arg("ls-remote")
            .arg("--heads")
            .arg(remote)
            .arg(format!("refs/heads/{branch}"))
            .output();
        let output =
            output.map_err(|err| forge_command_error("`git ls-remote`", GIT_NOT_FOUND, &err))?;
        if !output.status.success() {
            return Err(forge_exit_error(
                &format!("`git ls-remote` of `{branch}` on `{remote}`"),
                &output,
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let want = format!("refs/heads/{branch}");
        let mut heads = stdout
            .lines()
            .filter(|line| line.split_whitespace().nth(1) == Some(want.as_str()));
        // `ls-remote --heads` filters server-side; a clean empty answer is the
        // absent-ref state, not a failure.
        let Some(line) = heads.next() else {
            return Ok(None);
        };
        if heads.next().is_some() {
            return Err(KataError::Internal(format!(
                "forge_export: `git ls-remote` advertised `refs/heads/{branch}` more than once"
            )));
        }
        // Filtered lines have `<sha>\t<ref>` — the sha is the first field.
        let sha = line.split_whitespace().next().ok_or_else(|| {
            KataError::Internal(
                "forge_export: `git ls-remote` answered a row with no object name".to_string(),
            )
        })?;
        Ok(Some(sha.to_string()))
    }

    /// Refuse `forge_export` of a commit whose `MergedTree` carries a
    /// conflict — git cannot express one, so the push would export one side's
    /// reading of a contested file. Checked on the RESOLVED sha before the
    /// branch is written; nothing in the export path moves a ref until this
    /// passes.
    pub(crate) fn refuse_conflicted_export(&self, commit_sha: &str) -> KataResult<()> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let commit_id = CommitId::try_from_hex(commit_sha).ok_or_else(|| {
            KataError::Internal(format!(
                "forge_export: candidate commit id is not valid hex: {commit_sha}"
            ))
        })?;
        let commit = repo.store().get_commit(&commit_id).map_err(|err| {
            KataError::Internal(format!(
                "forge_export: candidate commit {commit_sha} is not in the store: {err}"
            ))
        })?;
        if commit.has_conflict() {
            return Err(KataError::Validation(format!(
                "{}: the candidate commit {commit_sha} carries a CONFLICTED tree — a conflicted \
                 commit has no faithful git form and must never reach the forge; resolve the \
                 conflict (re-validate + re-land) before exporting",
                super::FORGE_EXPORT_CONFLICTED_COMMIT
            )));
        }
        Ok(())
    }

    /// The colocated repo root (test/introspection accessor).
    #[must_use]
    pub fn repo_root(&self) -> &std::path::Path {
        &self.repo_path
    }
}

/// `<program> <overrides>` under `bound` that cannot wait on a prompt: the
/// push and every read of the remote's head reach the operator's remote with
/// the operator's credentials, and a remote that would ask for anything fails
/// at once with git's or ssh's own error instead of holding the export until
/// `FORGE_COMMAND_TIMEOUT`.
///
/// - git's own username/password prompt is off (`GIT_TERMINAL_PROMPT=0`, as
///   the PR fetch in `jj::target` runs).
/// - ssh's passphrase and host-key prompts are not git's: the ssh command git
///   would have run ([`batch_ssh_command`]) runs with `-oBatchMode=yes`
///   appended, as `recovery_remote` composes it. The host's command is
///   extended, never replaced, so it must be an OpenSSH-compatible client; an
///   ssh remote's key must be usable without a prompt (an agent-held key) and
///   its host key already known.
fn forge_git(program: &std::ffi::OsStr, repo: &std::path::Path, bound: Duration) -> VcsCommand {
    let mut command = VcsCommand::new(program, GIT_EXECUTION_OVERRIDES, bound);
    let ssh = batch_ssh_command(
        std::env::var_os("GIT_SSH_COMMAND"),
        repository_ssh_command(program, repo, bound.min(SSH_CONFIG_READ_BOUND)),
        std::env::var_os("GIT_SSH"),
    );
    command
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSH_COMMAND", ssh)
        .arg("-C")
        .arg(repo);
    command
}

/// A local `git config` read; far below any forge bound.
const SSH_CONFIG_READ_BOUND: Duration = Duration::from_secs(10);

/// The repository's `core.sshCommand` (the last value, as git reads it), or
/// `None` when it is unset. A read that does not answer is also `None`: the
/// command it serves reads the same configuration and fails on it with git's
/// own error.
fn repository_ssh_command(
    program: &std::ffi::OsStr,
    repo: &std::path::Path,
    bound: Duration,
) -> Option<std::ffi::OsString> {
    let output = VcsCommand::new(program, GIT_EXECUTION_OVERRIDES, bound)
        .arg("-C")
        .arg(repo)
        .args(["config", "--get", "core.sshCommand"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut value = output.stdout;
    if value.last() == Some(&b'\n') {
        value.pop();
    }
    use std::os::unix::ffi::OsStringExt as _;
    Some(std::ffi::OsString::from_vec(value))
}

/// The ssh command git would run, in git's own order (`connect.c`
/// `get_ssh_command`: `GIT_SSH_COMMAND`, then `core.sshCommand`; then the
/// `GIT_SSH` program, then `ssh`), with `-oBatchMode=yes` appended. A
/// `GIT_SSH` program is one word, so it is single-quoted for the shell git
/// runs `GIT_SSH_COMMAND` through.
fn batch_ssh_command(
    env_command: Option<std::ffi::OsString>,
    config_command: Option<std::ffi::OsString>,
    env_program: Option<std::ffi::OsString>,
) -> std::ffi::OsString {
    let mut ssh = match (env_command.or(config_command), env_program) {
        (Some(command), _) => command,
        (None, Some(program)) => {
            use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
            let mut quoted = vec![b'\''];
            for &byte in program.as_bytes() {
                if byte == b'\'' {
                    quoted.extend_from_slice(b"'\\''");
                } else {
                    quoted.push(byte);
                }
            }
            quoted.push(b'\'');
            std::ffi::OsString::from_vec(quoted)
        }
        (None, None) => "ssh".into(),
    };
    ssh.push(" -oBatchMode=yes");
    ssh
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `git ls-remote` spawn-failure classification: a program that does not
    /// exist is `Config` ("git not found on PATH" — the operator fix), and a
    /// program that exists but cannot exec is `Internal` — NOT a false
    /// not-found claim. The `NotFound` arm's `==` is the whole contract: flipped,
    /// an absent git reports Internal and every other spawn fault reports the
    /// actionable-but-wrong Config.
    #[test]
    fn ls_remote_spawn_failures_are_classified_by_kind() {
        let dir = tempfile::tempdir().unwrap();
        let backend = JjBackend {
            repo_path: dir.path().to_path_buf(),
            op_log_gc: crate::jj::op_log_gc::OpLogGcPolicy::default(),
            configured_trunk: None,
        };
        let missing = dir.path().join("no-such-git");
        let err = backend
            .remote_branch_head_at(missing.as_ref(), "origin", "b", Duration::from_secs(2))
            .expect_err("a program that is not there errors");
        assert!(
            matches!(err, KataError::Config(_)),
            "a missing `git` is the Config answer, not {err:?}"
        );
        assert!(err.to_string().contains("not found"), "{err}");

        // Exists, but not executable — PermissionDenied at spawn, the NOT-NotFound
        // arm: Internal, never the false "not found" claim.
        let noexec = dir.path().join("git-noexec");
        std::fs::write(&noexec, "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&noexec, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = backend
            .remote_branch_head_at(noexec.as_ref(), "origin", "b", Duration::from_secs(2))
            .expect_err("a program that cannot exec errors");
        assert!(
            matches!(err, KataError::Internal(_)),
            "a spawn fault that is not NotFound is Internal, not a false \
             'git not found' Config — got {err:?}"
        );
    }

    /// **The forge push and its head read can never wait on a prompt.**
    /// A stand-in `git` records the `GIT_TERMINAL_PROMPT` and
    /// `GIT_SSH_COMMAND` it was spawned with into files beside itself — read
    /// back off the filesystem, not out of the command builder — for the push
    /// (both lease spellings share it) and for `ls-remote`, and answers
    /// `config --get core.sshCommand` with the repository's ssh command.
    ///
    /// **Would red if:** either spawn inherited the caller's prompt setting
    /// (an unset variable records `unset`), or ran ssh without `BatchMode`
    /// (a passphrase or host-key prompt would hold the export until
    /// `FORGE_COMMAND_TIMEOUT`), or replaced the host's own ssh command
    /// instead of extending it.
    #[test]
    fn the_forge_push_and_ls_remote_never_prompt_on_a_terminal() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let backend = JjBackend {
            repo_path: dir.path().to_path_buf(),
            op_log_gc: crate::jj::op_log_gc::OpLogGcPolicy::default(),
            configured_trunk: None,
        };
        kata_test_utils::git::init_git_repo_at(dir.path());
        let git = dir.path().join("git-records-prompt");
        std::fs::write(
            &git,
            "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in push|ls-remote|config) verb=$a; break;; \
             esac; done\nif [ \"$verb\" = config ]; then printf '%s\\n' 'ssh -i /k'; exit 0; fi\n\
             printf '%s' \"${GIT_TERMINAL_PROMPT-unset}\" > \"$0.$verb\"\n\
             printf '%s' \"${GIT_SSH_COMMAND-unset}\" > \"$0.$verb.ssh\"\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
        let recorded = |file: &str| {
            std::fs::read_to_string(dir.path().join(format!("git-records-prompt.{file}")))
                .unwrap_or_else(|error| panic!("the stand-in recorded no `{file}`: {error}"))
        };
        // git's own precedence puts the environment's command over the
        // repository's; the runner's environment is not this test's to set.
        let ssh = std::env::var("GIT_SSH_COMMAND").map_or_else(
            |_| "ssh -i /k -oBatchMode=yes".to_string(),
            |host| format!("{host} -oBatchMode=yes"),
        );

        backend
            .push_forge_branch_lease_at(
                git.as_ref(),
                "origin",
                "kata/x",
                "0123456789abcdef0123456789abcdef01234567",
                "--force-with-lease",
            )
            .expect("the stand-in push exits 0");
        assert_eq!(
            recorded("push"),
            "0",
            "the push runs with GIT_TERMINAL_PROMPT=0"
        );
        assert_eq!(
            recorded("push.ssh"),
            ssh,
            "the push runs the host's ssh command under BatchMode"
        );

        backend
            .remote_branch_head_at(git.as_ref(), "origin", "kata/x", Duration::from_secs(5))
            .expect("the stand-in ls-remote exits 0 with no output");
        assert_eq!(
            recorded("ls-remote"),
            "0",
            "ls-remote runs with GIT_TERMINAL_PROMPT=0"
        );
        assert_eq!(
            recorded("ls-remote.ssh"),
            ssh,
            "ls-remote runs the host's ssh command under BatchMode"
        );
    }

    /// **The push's source is a full hex object id of the repository's own
    /// format, or nothing runs.** In a SHA-1 repository a commit that is not
    /// a 40-digit hex id — an option spelling, a ref name, an abbreviated id,
    /// a non-hex digit, SHA-256's 64-digit length, the empty string (`:<dst>`
    /// is a delete) — is refused `Internal` before `git` is spawned: a
    /// stand-in that records every run records no `push`, and records the one
    /// `push` a 40-digit id makes. In a SHA-256 repository, which gix 0.80 cannot
    /// open, every source — a 64-digit id too — is refused with nothing run.
    ///
    /// **Would red if:** any of them reached `git push`, where `-…` reads as
    /// an option, a ref name or an id of the other format's length sends
    /// whatever the ref of that name holds, an abbreviation names whatever
    /// object it resolves to, and an empty source deletes the remote branch
    /// — the 64-digit one with the length checked against both formats.
    #[test]
    fn a_push_source_that_is_not_an_object_id_runs_nothing() {
        use std::os::unix::fs::PermissionsExt as _;
        let runs = |format: &str, sources: &[&str]| -> (Vec<String>, usize) {
            let dir = tempfile::tempdir().unwrap();
            kata_test_utils::git::run_git(
                dir.path(),
                &["init", "-q", &format!("--object-format={format}")],
            );
            let backend = JjBackend {
                repo_path: dir.path().to_path_buf(),
                op_log_gc: crate::jj::op_log_gc::OpLogGcPolicy::default(),
                configured_trunk: None,
            };
            let git = dir.path().join("git-records-runs");
            std::fs::write(&git, "#!/bin/sh\necho \"$*\" >> \"$0.log\"\nexit 0\n").unwrap();
            std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
            let refused = sources
                .iter()
                .filter_map(|source| {
                    match backend.push_forge_branch_lease_at(
                        git.as_ref(),
                        "origin",
                        "kata/x",
                        source,
                        "--force-with-lease",
                    ) {
                        Err(KataError::Internal(_)) => Some((*source).to_owned()),
                        _ => None,
                    }
                })
                .collect();
            let ran = std::fs::read_to_string(dir.path().join("git-records-runs.log"))
                .unwrap_or_default()
                .lines()
                .filter(|argv| argv.split(' ').any(|arg| arg == "push"))
                .count();
            (refused, ran)
        };
        let sha1 = "0123456789abcdef0123456789abcdef01234567";
        let sha256 = "0123456789abcdef".repeat(4);
        let invalid = [
            "--delete",
            "refs/heads/kata/x",
            "kata/x",
            "",
            "0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456g",
            sha256.as_str(),
        ];
        assert_eq!(
            runs("sha1", &invalid),
            (invalid.iter().map(|s| (*s).to_owned()).collect(), 0),
            "SHA-1: each is refused and git never runs"
        );
        assert_eq!(
            runs("sha1", &[sha1]),
            (Vec::new(), 1),
            "SHA-1: a 40-digit id runs the push"
        );
        assert_eq!(
            runs("sha256", &[sha1, sha256.as_str()]),
            (vec![sha1.to_owned(), sha256.clone()], 0),
            "SHA-256: the repository's format cannot be read, so nothing runs"
        );
    }

    /// git's own resolution order (`connect.c` `get_ssh_command`, then
    /// `GIT_SSH`, then `ssh`), each extended with `-oBatchMode=yes`; a
    /// `GIT_SSH` program is one word and is quoted as one.
    ///
    /// **Would red if:** the order changed, or a `GIT_SSH` path with a space
    /// or a quote were split by the shell git runs the command through.
    #[test]
    fn the_forge_ssh_command_extends_what_git_would_have_run() {
        let run = |env: Option<&str>, config: Option<&str>, program: Option<&str>| {
            batch_ssh_command(
                env.map(Into::into),
                config.map(Into::into),
                program.map(Into::into),
            )
        };
        assert_eq!(run(None, None, None), "ssh -oBatchMode=yes");
        assert_eq!(
            run(Some("ssh -p 2"), Some("ssh -i /k"), Some("/g")),
            "ssh -p 2 -oBatchMode=yes"
        );
        assert_eq!(
            run(None, Some("ssh -i /k"), Some("/g")),
            "ssh -i /k -oBatchMode=yes"
        );
        assert_eq!(
            run(None, None, Some("/o p/it's")),
            "'/o p/it'\\''s' -oBatchMode=yes"
        );
    }
}
