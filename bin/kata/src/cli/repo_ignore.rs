//! Which of the paths kata writes into the operator's repository that
//! repository already ignores — asked of git, once, and shared by the two
//! commands that need the answer.
//!
//! # Two callers, one answer
//!
//! * `kata doctor`'s `target_repo_ignore` row REPORTS the property.
//! * `kata init` MAKES it true, by writing the rules for the roots that are
//!   missing (see `cli::init::declare_kata_artifacts_in_gitignore`).
//!
//! They must agree exactly, or `kata init` writes rules that do not clear the
//! row it routes the operator at. A second hand-written `git check-ignore`
//! invocation beside the first would be a twin that drifts.
//!
//! WHAT LIVES HERE and what does not: this module answers "is root R ignored in
//! repo P, and by which rule". It does NOT know which roots there are — that is
//! `kata_workflow::repo_artifacts::repo_local_artifact_paths`, the one
//! enumerable list, keyed on the configured provider — and it does not decide
//! what a caller does with a `None`.

use std::path::Path;

/// The leaf appended to each artifact root when asking git whether that root is
/// ignored. Never created, never written — `git check-ignore` is pure pattern
/// matching over a path string.
///
/// TWO segments, because that is the shape kata actually writes:
/// `agents/<exec>/…`, `.jj/repo/…`. Asking about
/// a shallower shape would answer a question nobody has. Asking about the bare
/// directory answers the WRONG question: measured on git 2.43.0,
/// `git check-ignore .jj` reports NOT IGNORED against the pattern `.jj/`
/// whenever `.jj` does not exist on disk, and every repository doctor runs
/// against before first boot is in exactly that state.
pub(crate) const IGNORE_PROBE_LEAF: &str = "kata-doctor-ignore-probe";

/// The `.gitignore` pattern that ignores an artifact root, anchored to the
/// repository root and directory-only.
///
/// Spelled ONCE: `kata doctor`'s remedy prints it, and `kata init` writes it.
/// Anchored (`/…`) because these roots are kata's at the repository root and
/// nowhere else; directory-only (`…/`) because they are directories and a
/// bare-name pattern would also swallow a file an operator happens to name
/// `agents`.
pub(crate) fn ignore_pattern(root: &str) -> String {
    format!("/{root}/")
}

/// git's answer for ONE artifact root.
pub(crate) struct IgnoreAnswer {
    /// The repository-root-relative root that was asked about.
    pub(crate) root: String,
    /// `Some((source, linenum, pattern))` naming the rule that matched, or
    /// `None` when no rule did.
    pub(crate) matched: Option<(String, String, String)>,
}

impl IgnoreAnswer {
    pub(crate) fn is_ignored(&self) -> bool {
        self.matched.is_some()
    }
}

/// Ask git which of `roots` are ignored in `repo`, in the order given.
///
/// `Err` is git DECLINING to answer — a missing directory, a path that is not a
/// repository, git not on `PATH`, a malformed reply. A decline is never a pass
/// and never a failure: both callers must surface it as unverified rather than
/// guess in either direction.
pub(crate) fn probe_ignored(repo: &Path, roots: &[String]) -> Result<Vec<IgnoreAnswer>, String> {
    if !repo.is_dir() {
        return Err(
            "`vcs.jj_repo` is not an existing directory, so there is no repository to ask"
                .to_string(),
        );
    }

    let probes: Vec<String> = roots
        .iter()
        .map(|root| format!("{root}/{IGNORE_PROBE_LEAF}/{IGNORE_PROBE_LEAF}"))
        .collect();
    let output = run_check_ignore(repo, &probes)?;

    // check-ignore exits 0 for "at least one path matched" and 1 for "none
    // matched". Both are ANSWERS. Anything else (128 = not a git repository) is
    // git declining to answer, and a decline is not a pass.
    if !matches!(output.status.code(), Some(0 | 1)) {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "`git check-ignore` in that directory exited {} ({stderr})",
            output
                .status
                .code()
                .map_or_else(|| "on a signal".to_string(), |code| code.to_string()),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Records are groups of four NUL-terminated fields; the trailing NUL leaves
    // one empty tail element that the chunking discards.
    let fields: Vec<&str> = stdout.split('\0').collect();
    let records: Vec<&[&str; 4]> = fields.as_chunks::<4>().0.iter().collect();
    if records.len() != probes.len() {
        return Err(format!(
            "`git check-ignore` answered for {} of the {} paths it was asked about",
            records.len(),
            probes.len()
        ));
    }

    Ok(roots
        .iter()
        .zip(records)
        .map(|(root, record)| {
            let (source, linenum, pattern) = (record[0], record[1], record[2]);
            IgnoreAnswer {
                root: root.clone(),
                matched: if source.is_empty() {
                    None
                } else {
                    Some((source.to_string(), linenum.to_string(), pattern.to_string()))
                },
            }
        })
        .collect())
}

/// Ask git whether each probe path is ignored in `repo`, returning git's raw
/// output or the reason it could not answer.
///
/// `--stdin -z` rather than argv paths: NUL-delimited input and output are
/// unambiguous for any path, and `-z` is rejected outright without `--stdin`
/// (`fatal: -z only makes sense with --stdin`). `-v --non-matching` makes git
/// emit a record for EVERY probe — four NUL-separated fields each (`source`,
/// `linenum`, `pattern`, `pathname`), with the first three empty when nothing
/// matched — so one invocation answers for every root AND names the rule that
/// decided each one.
fn run_check_ignore(repo: &Path, probes: &[String]) -> Result<std::process::Output, String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    // The operator's configuration is inherited on purpose: the question is
    // what THIS repository, as its owner configured it, ignores. Its
    // `core.fsmonitor` command is not part of that answer and is a hook
    // `check-ignore` would run (measured, git 2.56), so it is switched off.
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.fsmonitor=false"])
        .arg("check-ignore")
        .arg("-v")
        .arg("--non-matching")
        .arg("--stdin")
        .arg("-z")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("`git` could not be started ({err})"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "`git check-ignore` stdin was not piped".to_string())?;
    // EPIPE here is git ANSWERING, not git failing: on a path that is not a
    // repository git prints `fatal: not a git repository` and exits before it
    // reads a byte, so our write loses a race it was never in. Reporting the
    // pipe error would replace git's reason with our plumbing — and it is
    // LOAD-DEPENDENT, so it reads as a flake rather than as the wrong message.
    // Measured: green on a quiet gate, red on a loaded one, with
    // `a_target_dir_that_is_not_a_git_repo_warns` asserting on a `Broken pipe`
    // string. Swallow the broken pipe and let `wait_with_output` report what
    // git actually said; every other write error is still ours to name.
    if let Err(err) = stdin.write_all(probes.join("\0").as_bytes())
        && err.kind() != std::io::ErrorKind::BrokenPipe
    {
        return Err(format!(
            "writing probe paths to `git check-ignore` failed ({err})"
        ));
    }
    // `wait_with_output` only closes the stdin IT owns; this handle was taken
    // out of the child, so git would block on EOF forever without this drop.
    drop(stdin);
    child
        .wait_with_output()
        .map_err(|err| format!("`git check-ignore` did not complete ({err})"))
}

#[cfg(test)]
mod tests {
    use super::probe_ignored;

    /// The repository's own `core.fsmonitor` command, which would write a
    /// marker file, does not run when kata asks git what the repository
    /// ignores, and the answer still names the repository's own rule.
    #[test]
    fn the_ignore_probe_runs_no_fsmonitor_command() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        kata_test_utils::git::init_git_repo_at(&repo);
        std::fs::write(repo.join(".gitignore"), "/agents/\n").unwrap();
        let marker = dir.path().join("fsmonitor-ran");
        let fsmonitor = dir.path().join("fsmonitor");
        std::fs::write(
            &fsmonitor,
            format!("#!/bin/sh\necho ran >> '{}'\nexit 1\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&fsmonitor, std::fs::Permissions::from_mode(0o755)).unwrap();
        kata_test_utils::git::run_git(
            &repo,
            &["config", "core.fsmonitor", fsmonitor.to_str().unwrap()],
        );

        let answers = probe_ignored(&repo, &["agents".to_owned(), ".jj".to_owned()]).unwrap();
        assert!(answers[0].is_ignored() && !answers[1].is_ignored());
        assert!(
            !marker.exists(),
            "the repository's fsmonitor command ran inside kata's `git check-ignore`"
        );
    }
}
