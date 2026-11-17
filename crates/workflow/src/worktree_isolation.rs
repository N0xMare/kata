//! The execution workspace's validation-candidate binding and the trunk
//! observation `kata doctor` shares with the provider.
//!
//! Two pieces live here: the candidate binding minted from a provider's
//! RECORDED status, and [`observe_trunk_at`]. The jj execution workspace
//! (`kata_vcs::JjBackend`) is the one execution-workspace provider; nothing here
//! creates, promotes, parks or removes a workspace, and nothing here scans a
//! worktree's files.

use std::path::Path;

use kata_vcs::process::{LOCAL_COMMAND_TIMEOUT, VcsCommand};
use kata_vcs::trunk::TrunkObservation;

use kata_types::error::KataResult;
use kata_types::execution::{
    ExecutionValidationCandidateEvidence, VALIDATION_CRITERION_CANDIDATE_EVIDENCE_SCHEMA_VERSION,
};
use kata_types::git_policy::GIT_EXECUTION_OVERRIDES;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

mod hashing;

use hashing::{
    CandidatePathHash, validation_candidate_content_hash, validation_candidate_fingerprint,
};

/// The validation-candidate binding: minted from the
/// workspace's RECORDED status (the provider's repo-view read), never a disk scan
/// of the worktree. The fingerprint folds `head_commit = None`,
/// `changed_paths = []` and a single tree-address `path_hashes` entry, so a
/// criterion's fingerprint stays comparable to itself across commits that leave
/// the tree unchanged.
pub fn validation_candidate_binding_for_recorded(
    execution_id: Ulid,
    workspace_backend: Option<&str>,
    recorded: &kata_effects_contract::RecordedWorkspaceStatus,
) -> KataResult<ExecutionValidationCandidateEvidence> {
    // The recorded candidate's content basis is its tree address — a jj
    // `MergedTree` id is not guaranteed to parse as a `ContentHash`, so fold
    // its hex bytes directly: a stable, deterministic content identity.
    let path_hashes = vec![CandidatePathHash {
        path: String::new(),
        kind: "tree",
        digest: Some(ContentHash::new(
            *blake3::hash(recorded.tree_id.as_bytes()).as_bytes(),
        )),
    }];
    let content_hash = validation_candidate_content_hash(None, &path_hashes);
    let changed_paths: Vec<String> = Vec::new();
    let fingerprint = validation_candidate_fingerprint(
        execution_id,
        workspace_backend,
        None,
        &content_hash,
        &changed_paths,
    );
    Ok(ExecutionValidationCandidateEvidence {
        schema_version: VALIDATION_CRITERION_CANDIDATE_EVIDENCE_SCHEMA_VERSION,
        execution_id: execution_id.to_string(),
        fingerprint,
        content_hash,
        workspace_backend: workspace_backend.map(ToOwned::to_owned),
        head_commit: Some(recorded.head.clone()),
        dirty: Some(false),
        changed_paths,
        // The promote pin's currency — the recorded `@`'s MergedTree id.
        tree_id: Some(recorded.tree_id.clone()),
    })
}

/// Observe `repo_root`'s branches and its remotes' own default, for
/// [`kata_vcs::trunk::resolve_trunk`].
///
/// Public so `kata doctor`'s `trunk_resolution` row asks the SAME question
/// through the SAME surface the provider will ask at run time, rather than
/// re-deriving a second opinion that could disagree with the daemon's.
///
/// It reads git refs, not jj bookmarks, deliberately. Doctor's audience is
/// first-run readiness, where `.jj/` does not exist yet and constructing a
/// `JjBackend` would CREATE it — doctor must not mutate the repository it
/// is inspecting. In a colocated repository the two views agree anyway:
/// adoption imports `refs/heads/*` into jj bookmarks and every kata
/// bookmark write exports back. The narrowing is a jj bookmark that was
/// never exported, which only a failed export produces.
#[must_use]
pub fn observe_trunk_at(repo_root: &Path, configured: Option<String>) -> TrunkObservation {
    let local_branches = git_lines(
        repo_root,
        &["for-each-ref", "--format=%(refname:short)", "refs/heads/"],
    );
    // `refs/remotes/<remote>/HEAD` -> `refs/remotes/<remote>/<branch>`.
    // EVERY remote must agree: two remotes naming different defaults is not
    // an answer, and picking one would be kata deciding for the operator.
    let mut answers: Vec<String> = Vec::new();
    for line in git_lines(
        repo_root,
        &[
            "for-each-ref",
            "--format=%(refname)|%(symref)",
            "refs/remotes/*/HEAD",
        ],
    ) {
        let Some((name, symref)) = line.split_once('|') else {
            continue;
        };
        let Some(remote) = name
            .strip_prefix("refs/remotes/")
            .and_then(|rest| rest.strip_suffix("/HEAD"))
        else {
            continue;
        };
        if let Some(branch) = symref.strip_prefix(&format!("refs/remotes/{remote}/"))
            && !branch.is_empty()
        {
            answers.push(branch.to_owned());
        }
    }
    answers.sort_unstable();
    answers.dedup();

    TrunkObservation {
        configured: configured.filter(|name| !name.trim().is_empty()),
        local_branches,
        remote_head: match answers.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        },
    }
}

/// Trimmed non-empty stdout lines of `git -C <repo> <args>`, or empty when
/// git declines to answer. A missing answer is not an error here — it feeds
/// a resolver whose whole job is to refuse when it has no answer.
fn git_lines(repo_root: &Path, args: &[&str]) -> Vec<String> {
    let Ok(out) = VcsCommand::new("git", GIT_EXECUTION_OVERRIDES, LOCAL_COMMAND_TIMEOUT)
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
#[path = "worktree_isolation_tests.rs"]
mod tests;
