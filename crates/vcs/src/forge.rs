//! The `gh` CLI forge: [`GhCliForge`], the thin implementation of
//! [`kata_effects_contract::Forge`] that shells the `gh` binary the operator
//! already authenticates (`gh auth login`). The trait, the values it carries
//! and the rules every forge keeps — a SINK for the export, an untrusted SOURCE
//! for a `pr:<N>` target — are documented in `kata-effects-contract`.
//!
//! ## No network in tests
//!
//! [`GhCliForge`] resolves `gh` through `PATH`, so a test can put a recording
//! shim named `gh` on `PATH` and machine-check the exact argv contract without
//! ever reaching GitHub.

use std::path::PathBuf;
use std::time::Duration;

use crate::process::{VcsCommand, forge_command_error, forge_exit_error, quoted_stderr};

use kata_effects_contract::{
    FORGE_COMMAND_TIMEOUT, Forge, ForgePullRequest, MarkedPullRequest, PullRequestReceipt,
    PullRequestSpec,
};
use kata_types::target::{TARGET_FORGE_UNAVAILABLE, TARGET_PR_NOT_FOUND, TargetRefusal};
use kata_types::{KataError, KataResult};

/// The most bytes any `gh` command may print on stdout, its answer. A pull
/// request's body is the large field: the forge bounds one far below this,
/// and the marker observer's listing of many past it is the
/// [`MarkedPullRequest::BeyondBound`] answer. Stderr is no answer: it is read
/// to the end and only its first [`KEPT_GH_STDERR_BYTES`] kept.
const MAX_FORGE_ANSWER_BYTES: usize = 1024 * 1024;

/// The most bytes of a `gh` command's stderr kept: enough for the
/// not-found and authentication texts a refusal is classified by.
const KEPT_GH_STDERR_BYTES: usize = 64 * 1024;

/// The operator's fix for a `gh` that is not on `PATH`.
const GH_NOT_FOUND: &str = "`gh` CLI not found on PATH; install GitHub CLI and run `gh auth \
     login` on the main (kata shells `gh` to open the PR)";

/// `gh`'s exit status when no credential is configured (`gh auth login`).
const GH_EXIT_AUTH_REQUIRED: i32 = 4;

/// The GitHub API's answer, which `gh` prints on stderr, for a pull-request
/// number the repository does not have.
const GH_PULL_REQUEST_NOT_FOUND: &str = "Could not resolve to a PullRequest";

/// The most pull requests on one head name either listing —
/// [`GhCliForge::find_open_pr`] and [`GhCliForge::find_marked_pull_request`] —
/// asks for (`--limit`). kata owns the head, so a listing this long is not one
/// it made, and a listing that reaches it proves no absence.
const PULL_REQUEST_LIST_BOUND: usize = 100;

/// The `--json` fields [`ForgePullRequest`] is read from — one spelling for
/// the argv and the struct's serde names.
const PULL_REQUEST_FIELDS: &str =
    "number,url,headRefOid,headRefName,baseRefName,isCrossRepository,title,body";

/// Thin `gh` CLI forge: shells `gh pr create` from the colocated repo root.
///
/// The repo root is the git surface the branch was pushed from (the colocated
/// `.git`). The export's three verbs — the open-PR lookup, the create and the
/// marker observer — each pass `--repo <HOST/OWNER/REPO>`, the repository the
/// export's push remote names, and its confirmation before the push names it
/// as `gh repo view`'s argument, so none runs in `gh`'s own default repository
/// (`remote.<name>.gh-resolved`, else its ranking of the remotes, which puts
/// `upstream` ahead of `origin`, measured on gh 2.103.3 with `gh browse -n`;
/// or `GH_REPO`). The `pr:<N>` target's two reads pass none: they read `gh`'s
/// default, and the target resolution matches it to a configured remote
/// itself. `gh` uses the operator's `gh auth login` credentials, which are not
/// the credentials git pushes with; kata never embeds a token.
#[derive(Clone, Debug)]
pub struct GhCliForge {
    repo_root: PathBuf,
    /// The `gh` program to exec — `gh` (PATH-resolved) in production, or an
    /// explicit path (a recording shim) in tests / a non-standard install.
    program: PathBuf,
}

impl GhCliForge {
    /// Construct a `gh` forge shelling `gh` (resolved via `PATH`) from
    /// `repo_root` (the colocated repo root the candidate branch was pushed
    /// from).
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self::with_program("gh", repo_root)
    }

    /// Construct a `gh` forge that execs an explicit `program` instead of the
    /// PATH-resolved `gh`. Lets an operator point at a non-standard `gh`
    /// install, and lets a test point at a recording shim so the argv contract
    /// is machine-checked without touching the process-global `PATH`.
    #[must_use]
    pub fn with_program(program: impl Into<PathBuf>, repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
            program: program.into(),
        }
    }

    /// The exact `gh pr create` argv (sans the `gh` program name) for `req`.
    /// Extracted so the argv contract is one source of truth the shim test and
    /// the live path share.
    fn pr_create_args(req: &PullRequestSpec) -> Vec<String> {
        vec![
            "pr".to_string(),
            "create".to_string(),
            "--repo".to_string(),
            req.repository.clone(),
            "--title".to_string(),
            req.title.clone(),
            "--body".to_string(),
            req.body.clone(),
            "--base".to_string(),
            req.base.clone(),
            "--head".to_string(),
            req.head.clone(),
        ]
    }

    /// The `gh pr list` argv for the open-PR lookup on `head` in
    /// `repository`, which the
    /// export asks before the pull request's intent, up to the listing's
    /// bound. It asks for each pull request's base and whether its head lives
    /// in another repository, which [`Forge::find_open_pr`] matches itself:
    /// `--head` filters by the branch NAME only (gh 2.103.3: "`<owner>:<branch>`
    /// syntax not supported"), so a fork's branch of the same name lists too.
    fn pr_list_args(repository: &str, head: &str) -> Vec<String> {
        vec![
            "pr".to_string(),
            "list".to_string(),
            "--repo".to_string(),
            repository.to_string(),
            "--head".to_string(),
            head.to_string(),
            "--state".to_string(),
            "open".to_string(),
            "--json".to_string(),
            "number,url,baseRefName,isCrossRepository".to_string(),
            "--limit".to_string(),
            PULL_REQUEST_LIST_BOUND.to_string(),
        ]
    }

    /// The `gh pr list` argv for the marker observer: every pull request of
    /// `repository` on `head`, in any state, with its body, up to the read's bound.
    fn pr_list_any_state_args(repository: &str, head: &str) -> Vec<String> {
        vec![
            "pr".to_string(),
            "list".to_string(),
            "--repo".to_string(),
            repository.to_string(),
            "--head".to_string(),
            head.to_string(),
            "--state".to_string(),
            "all".to_string(),
            "--json".to_string(),
            "number,url,body,isCrossRepository".to_string(),
            "--limit".to_string(),
            PULL_REQUEST_LIST_BOUND.to_string(),
        ]
    }

    /// Run `args` under this forge's program/cwd/timeout, its output capped.
    fn run_gh(&self, args: &[String]) -> Result<std::process::Output, std::io::Error> {
        self.run_gh_under(args, FORGE_COMMAND_TIMEOUT)
    }

    /// `run_gh` with the deadline as an argument so the timeout arm is
    /// exercisable in a test without waiting out the shipped 300s budget.
    /// Its stdout is capped at [`MAX_FORGE_ANSWER_BYTES`]; past it the command
    /// is killed, an `OutcomeUnknown` whose `io` kind is `FileTooLarge`
    /// ([`Self::answer_too_large`]).
    fn run_gh_under(
        &self,
        args: &[String],
        timeout: std::time::Duration,
    ) -> Result<std::process::Output, std::io::Error> {
        VcsCommand::new(&self.program, &[], timeout)
            .args(args)
            .current_dir(&self.repo_root)
            .output_capping_stdout(MAX_FORGE_ANSWER_BYTES, KEPT_GH_STDERR_BYTES)
    }

    /// Run `args`, answering its output or the typed error its failure to
    /// reach an exit status is.
    fn run_gh_typed(&self, args: &[String], what: &str) -> KataResult<std::process::Output> {
        self.run_gh(args)
            .map_err(|err| forge_command_error(&format!("`{what}`"), GH_NOT_FOUND, &err))
    }

    /// `true` when `err` is the cap on a forge command's stdout.
    fn answer_too_large(err: &std::io::Error) -> bool {
        err.kind() == std::io::ErrorKind::FileTooLarge
    }

    /// Run a READ verb under `bound`, its stdout capped at
    /// [`MAX_FORGE_ANSWER_BYTES`], and answer its stdout — or the refusal its
    /// failure is. `not_found` is the refusal a failed exit naming
    /// [`GH_PULL_REQUEST_NOT_FOUND`] on stderr becomes, when the verb has one.
    fn read_gh(
        &self,
        args: &[String],
        what: &str,
        bound: Duration,
        not_found: Option<&str>,
    ) -> Result<String, TargetRefusal> {
        let unavailable = |detail: String| {
            TargetRefusal::new(TARGET_FORGE_UNAVAILABLE, format!("`{what}`: {detail}"))
        };
        if bound.is_zero() {
            return Err(unavailable(
                "the resolution's time bound elapsed before it ran".to_owned(),
            ));
        }
        let output = VcsCommand::new(&self.program, &[], bound)
            .args(args)
            .current_dir(&self.repo_root)
            .output_capping_stdout(MAX_FORGE_ANSWER_BYTES, KEPT_GH_STDERR_BYTES)
            .map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => unavailable(format!(
                    "`{}` was not found; install GitHub CLI and run `gh auth login` on the main",
                    self.program.display()
                )),
                std::io::ErrorKind::TimedOut => unavailable(format!(
                    "the forge did not answer within {} s",
                    bound.as_secs_f64()
                )),
                _ => unavailable(format!("failed: {err}")),
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let quoted = quoted_stderr(&output.stderr);
            if output.status.code() == Some(GH_EXIT_AUTH_REQUIRED) {
                return Err(unavailable(format!(
                    "`gh` is not authenticated; run `gh auth login` on the main ({quoted})"
                )));
            }
            if let Some(not_found) = not_found
                && stderr.contains(GH_PULL_REQUEST_NOT_FOUND)
            {
                return Err(TargetRefusal::new(
                    TARGET_PR_NOT_FOUND,
                    format!("{not_found} ({quoted})"),
                ));
            }
            let code = output
                .status
                .code()
                .map_or_else(|| "signal".to_owned(), |c| c.to_string());
            return Err(unavailable(format!("failed (exit {code}): {quoted}")));
        }
        String::from_utf8(output.stdout)
            .map_err(|err| unavailable(format!("answered bytes that are not UTF-8: {err}")))
    }

    /// The `gh repo view` argv that confirms `gh` addresses `repository`
    /// (`HOST/OWNER/REPO`, which `gh` takes as `[HOST/]OWNER/REPO`).
    fn repo_confirm_args(repository: &str) -> Vec<String> {
        vec![
            "repo".to_owned(),
            "view".to_owned(),
            repository.to_owned(),
            "--json".to_owned(),
            "nameWithOwner".to_owned(),
        ]
    }

    /// The `gh pr view` argv that reads pull request `number`.
    fn pr_view_args(number: u64) -> Vec<String> {
        vec![
            "pr".to_owned(),
            "view".to_owned(),
            number.to_string(),
            "--json".to_owned(),
            PULL_REQUEST_FIELDS.to_owned(),
        ]
    }

    /// The `gh repo view` argv that reads the served repository's URL.
    fn repo_view_args() -> Vec<String> {
        vec![
            "repo".to_owned(),
            "view".to_owned(),
            "--json".to_owned(),
            "url".to_owned(),
        ]
    }

    /// Parse the PR URL out of `gh pr create` stdout. `gh` prints the PR URL as
    /// the final line; we take the last non-empty line that looks like an
    /// `http(s)` URL. Returns `None` when no URL line is present.
    fn parse_pr_url(stdout: &str) -> Option<String> {
        stdout
            .lines()
            .map(str::trim)
            .rfind(|line| line.starts_with("http://") || line.starts_with("https://"))
            .map(ToString::to_string)
    }
}

impl Forge for GhCliForge {
    fn create_pull_request(&self, req: &PullRequestSpec) -> KataResult<PullRequestReceipt> {
        let output = self.run_gh_typed(&Self::pr_create_args(req), "gh pr create")?;
        if !output.status.success() {
            // A forge/remote failure — Network is the closest typed bucket, and
            // it never implies the candidate is un-validated (SINK).
            return Err(forge_exit_error("`gh pr create`", &output));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let url = Self::parse_pr_url(&stdout).ok_or_else(|| {
            KataError::Internal(format!(
                "forge_export: `gh pr create` succeeded but no PR URL was found in its output: {}",
                stdout.trim()
            ))
        })?;
        Ok(PullRequestReceipt::from_url(url))
    }

    fn confirm_repository(&self, repository: &str) -> KataResult<()> {
        let output = self.run_gh_typed(&Self::repo_confirm_args(repository), "gh repo view")?;
        if !output.status.success() {
            return Err(forge_exit_error(
                &format!("`gh repo view {repository}`"),
                &output,
            ));
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Repository {
            name_with_owner: String,
        }
        let answered: Repository = serde_json::from_slice(&output.stdout).map_err(|err| {
            KataError::Internal(format!(
                "forge_export: `gh repo view {repository}` output did not parse as its --json \
                 contract: {err}"
            ))
        })?;
        let named = repository.split_once('/').map_or("", |(_, path)| path);
        if !answered.name_with_owner.eq_ignore_ascii_case(named) {
            return Err(KataError::Validation(format!(
                "forge_export: `gh repo view {repository}` answered the repository `{}`, not \
                 `{named}`",
                answered.name_with_owner.escape_debug()
            )));
        }
        Ok(())
    }

    fn find_open_pr(
        &self,
        repository: &str,
        head: &str,
        base: &str,
    ) -> KataResult<Option<PullRequestReceipt>> {
        let output = self.run_gh_typed(&Self::pr_list_args(repository, head), "gh pr list")?;
        if !output.status.success() {
            return Err(forge_exit_error("`gh pr list`", &output));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ListedPr {
            url: String,
            base_ref_name: String,
            is_cross_repository: bool,
        }
        let listed: Vec<ListedPr> = serde_json::from_str(&stdout).map_err(|err| {
            KataError::Internal(format!(
                "forge_export: `gh pr list` output did not parse as its --json contract: {err}"
            ))
        })?;
        // The forge keeps at most one open pull request per head REPOSITORY,
        // branch and base, so the one from this repository's `head` into
        // `base` is this export's. One whose head is a fork's branch of the
        // same name, or into another base, is not.
        if let Some(pr) = listed
            .iter()
            .find(|pr| !pr.is_cross_repository && pr.base_ref_name == base)
        {
            return Ok(Some(PullRequestReceipt::from_url(&pr.url)));
        }
        if listed.len() >= PULL_REQUEST_LIST_BOUND {
            return Err(KataError::Validation(format!(
                "forge_export: `gh pr list` listed {} open pull requests on `{head}`, its bound, \
                 so an open one of this repository's past it cannot be ruled out",
                listed.len()
            )));
        }
        Ok(None)
    }

    fn find_marked_pull_request(
        &self,
        repository: &str,
        head: &str,
        marker: &str,
    ) -> KataResult<MarkedPullRequest> {
        let what = "gh pr list --state all";
        let output = match self.run_gh(&Self::pr_list_any_state_args(repository, head)) {
            Ok(output) => output,
            Err(err) if Self::answer_too_large(&err) => {
                return Ok(MarkedPullRequest::BeyondBound(format!(
                    "`{what}` on `{head}` printed more than the {MAX_FORGE_ANSWER_BYTES} bytes a \
                     forge command may, so a pull request carrying `{marker}` in it cannot be \
                     ruled out"
                )));
            }
            Err(err) => {
                return Err(forge_command_error(
                    &format!("`{what}`"),
                    GH_NOT_FOUND,
                    &err,
                ));
            }
        };
        if !output.status.success() {
            return Err(forge_exit_error(&format!("`{what}`"), &output));
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ListedPr {
            url: String,
            body: String,
            is_cross_repository: bool,
        }
        let listed: Vec<ListedPr> = serde_json::from_slice(&output.stdout).map_err(|err| {
            KataError::Internal(format!(
                "forge_export: `gh pr list --state all` output did not parse as its --json \
                 contract: {err}"
            ))
        })?;
        // A fork's pull request from a branch of the same name lists too, and
        // anyone can copy a marker into its body: only one whose head is in
        // this repository is the intent's.
        if let Some(pr) = listed
            .iter()
            .find(|pr| !pr.is_cross_repository && pr.body.contains(marker))
        {
            return Ok(MarkedPullRequest::Found(PullRequestReceipt::from_url(
                &pr.url,
            )));
        }
        if listed.len() >= PULL_REQUEST_LIST_BOUND {
            return Ok(MarkedPullRequest::BeyondBound(format!(
                "`{what}` listed {} pull requests on `{head}`, its bound, so a pull request \
                 carrying `{marker}` past it cannot be ruled out",
                listed.len()
            )));
        }
        Ok(MarkedPullRequest::Absent)
    }

    fn resolve_pull_request(
        &self,
        number: u64,
        bound: Duration,
    ) -> Result<ForgePullRequest, TargetRefusal> {
        let stdout = self.read_gh(
            &Self::pr_view_args(number),
            "gh pr view",
            bound,
            Some(&format!("the forge has no pull request #{number}")),
        )?;
        serde_json::from_str(&stdout).map_err(|err| {
            TargetRefusal::new(
                TARGET_FORGE_UNAVAILABLE,
                format!("`gh pr view` did not answer in its --json contract: {err}"),
            )
        })
    }

    fn repository_url(&self, bound: Duration) -> Result<String, TargetRefusal> {
        #[derive(serde::Deserialize)]
        struct Repository {
            url: String,
        }
        let stdout = self.read_gh(&Self::repo_view_args(), "gh repo view", bound, None)?;
        serde_json::from_str::<Repository>(&stdout)
            .map(|repository| repository.url)
            .map_err(|err| {
                TargetRefusal::new(
                    TARGET_FORGE_UNAVAILABLE,
                    format!("`gh repo view` did not answer in its --json contract: {err}"),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// A `gh` that outlives the command deadline is a TIMEOUT, not an internal
    /// fault — the classification is what the caller's retry/ambiguous-outcome
    /// policy reads. `KataError::Timeout` is the ambiguous spelling; the
    /// `Internal` the mutant falls through to would settle a verdict that the
    /// expired push never earned.
    #[test]
    fn a_forge_command_that_times_out_is_a_typed_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("gh-sleeps");
        std::fs::write(&shim, "#!/bin/sh\nexec sleep 30\n").unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let forge = GhCliForge::with_program(&shim, dir.path());
        let error = forge_command_error(
            "`gh pr list`",
            GH_NOT_FOUND,
            &forge
                .run_gh_under(&["pr".into(), "list".into()], Duration::from_millis(300))
                .expect_err("a child that outlives the deadline errors"),
        );
        assert!(
            matches!(error, kata_types::error::KataError::Timeout(_)),
            "a timed-out `gh` is Timeout, not {error:?}"
        );
    }

    /// A shim `gh` that appends its argv to `gh.log`, prints `stdout` and
    /// `stderr`, and exits `status`.
    fn gh_shim(dir: &std::path::Path, stdout: &str, stderr: &str, status: i32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(dir.join("stdout"), stdout).unwrap();
        std::fs::write(dir.join("stderr"), stderr).unwrap();
        let shim = dir.join("gh");
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\nprintf '%s|' \"$@\" >> {dir}/gh.log\nprintf '\\n' >> {dir}/gh.log\n\
                 cat {dir}/stdout\ncat {dir}/stderr >&2\nexit {status}\n",
                dir = dir.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        shim
    }

    fn gh_log(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("gh.log")).unwrap_or_default()
    }

    const PR_JSON: &str = r#"{"number":7,"url":"https://forge.example/o/r/pull/7","headRefOid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","headRefName":"feature","baseRefName":"main","isCrossRepository":true,"title":"T","body":"B"}"#;

    /// **The repository confirmation refuses every answer but the named
    /// repository.** Its argv is the pinned `gh repo view <HOST/OWNER/REPO>
    /// --json nameWithOwner` (the shim's log); the named `OWNER/REPO`, in any
    /// case, confirms it; another repository (one renamed since the URL was
    /// written), and a failed `gh` (a host it cannot reach), are each an error.
    ///
    /// **Would red if:** the confirmation took any answer for the repository
    /// (L3 re-fix, R3-02's alias case): a push would land in a repository no
    /// later `gh` call of the export addresses.
    #[test]
    fn the_repository_confirmation_refuses_every_answer_but_the_named_repository() {
        let confirm = |stdout: &str, stderr: &str, status: i32| {
            let dir = tempfile::tempdir().unwrap();
            let forge =
                GhCliForge::with_program(gh_shim(dir.path(), stdout, stderr, status), dir.path());
            let confirmed = forge.confirm_repository("forge.example/o/r");
            assert_eq!(
                gh_log(dir.path()),
                "repo|view|forge.example/o/r|--json|nameWithOwner|\n"
            );
            confirmed
        };
        confirm(r#"{"nameWithOwner":"O/R"}"#, "", 0).expect("the named repository");
        assert!(
            matches!(
                confirm(r#"{"nameWithOwner":"o/renamed"}"#, "", 0),
                Err(KataError::Validation(text)) if text.contains("o/renamed")
            ),
            "another repository is refused"
        );
        confirm("", "error connecting to forge.example", 1)
            .expect_err("a forge that does not answer confirms nothing");
    }

    /// The pull-request read's argv is the pinned `gh pr view <N> --json
    /// <fields>` (read back from the shim's log), and its answer decodes field
    /// for field.
    #[test]
    fn a_pull_request_read_runs_the_pinned_argv_and_decodes_its_answer() {
        let dir = tempfile::tempdir().unwrap();
        let forge = GhCliForge::with_program(gh_shim(dir.path(), PR_JSON, "", 0), dir.path());
        let pr = forge
            .resolve_pull_request(7, Duration::from_secs(30))
            .expect("the shim answers");
        assert_eq!(
            gh_log(dir.path()),
            "pr|view|7|--json|number,url,headRefOid,headRefName,baseRefName,isCrossRepository,title,body|\n"
        );
        assert_eq!(
            pr,
            ForgePullRequest {
                number: 7,
                url: "https://forge.example/o/r/pull/7".to_owned(),
                head_ref_oid: "a".repeat(40),
                head_ref_name: "feature".to_owned(),
                base_ref_name: "main".to_owned(),
                is_cross_repository: true,
                title: "T".to_owned(),
                body: "B".to_owned(),
            }
        );
    }

    /// The repository read's argv is `gh repo view --json url`.
    #[test]
    fn a_repository_read_runs_the_pinned_argv() {
        let dir = tempfile::tempdir().unwrap();
        let forge = GhCliForge::with_program(
            gh_shim(dir.path(), r#"{"url":"https://forge.example/o/r"}"#, "", 0),
            dir.path(),
        );
        assert_eq!(
            forge.repository_url(Duration::from_secs(30)).unwrap(),
            "https://forge.example/o/r"
        );
        assert_eq!(gh_log(dir.path()), "repo|view|--json|url|\n");
    }

    /// Only the forge's own "no such pull request" answer is
    /// `target_pr_not_found`; an unauthenticated `gh` (exit 4), any other
    /// failed exit, a missing program, an answer outside the `--json` contract
    /// and a read past its bound are all `target_forge_unavailable`.
    #[test]
    fn a_failed_read_is_not_found_only_when_the_forge_says_so() {
        let refused = |stdout: &str, stderr: &str, status: i32| {
            let dir = tempfile::tempdir().unwrap();
            let forge =
                GhCliForge::with_program(gh_shim(dir.path(), stdout, stderr, status), dir.path());
            forge
                .resolve_pull_request(7, Duration::from_secs(30))
                .expect_err("the read is refused")
                .code()
        };
        assert_eq!(
            refused(
                "",
                "GraphQL: Could not resolve to a PullRequest with the number of 7. (repository.pullRequest)",
                1
            ),
            TARGET_PR_NOT_FOUND
        );
        assert_eq!(
            refused(
                "",
                "To get started with GitHub CLI, please run:  gh auth login",
                4
            ),
            TARGET_FORGE_UNAVAILABLE
        );
        assert_eq!(
            refused("", "error connecting to api.github.com", 1),
            TARGET_FORGE_UNAVAILABLE
        );
        assert_eq!(refused("not json", "", 0), TARGET_FORGE_UNAVAILABLE);
        assert_eq!(
            refused(r#"{"number":7}"#, "", 0),
            TARGET_FORGE_UNAVAILABLE,
            "an answer missing a field is outside the contract"
        );

        let dir = tempfile::tempdir().unwrap();
        let missing = GhCliForge::with_program(dir.path().join("no-gh"), dir.path());
        assert_eq!(
            missing
                .resolve_pull_request(7, Duration::from_secs(30))
                .unwrap_err()
                .code(),
            TARGET_FORGE_UNAVAILABLE
        );
    }

    /// A forge that does not answer within the read's bound is refused
    /// `target_forge_unavailable` once the bound elapses — not after the
    /// shim's 30 s — and a bound already spent refuses without running.
    #[test]
    fn a_read_past_its_bound_is_refused_unavailable_at_the_bound() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("gh-sleeps");
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\necho ran >> {}/gh.log\nexec sleep 30\n",
                dir.path().display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let forge = GhCliForge::with_program(&shim, dir.path());
        let started = std::time::Instant::now();
        let refusal = forge
            .resolve_pull_request(7, Duration::from_millis(300))
            .expect_err("a read past its bound is refused");
        assert_eq!(refusal.code(), TARGET_FORGE_UNAVAILABLE);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "refused at the bound, not after the shim: {:?}",
            started.elapsed()
        );
        std::fs::remove_file(dir.path().join("gh.log")).unwrap();
        assert_eq!(
            forge.repository_url(Duration::ZERO).unwrap_err().code(),
            TARGET_FORGE_UNAVAILABLE
        );
        assert!(
            !dir.path().join("gh.log").exists(),
            "a spent bound runs nothing"
        );
    }

    /// **The marker observer lists every state and adopts only the marked
    /// pull request.** The argv is the pinned `gh pr list --head <h> --state
    /// all --json number,url,body --limit 100` (the shim's log); a CLOSED pull
    /// request carrying the marker is the answer over an open one without it,
    /// and a listing with no marked pull request answers `None`.
    ///
    /// **Would red if:** the read asked only for open pull requests (a closed
    /// one the export opened would be opened again), or matched any pull
    /// request on the head rather than the one carrying the marker.
    #[test]
    fn the_marker_observer_adopts_a_marked_pull_request_in_any_state() {
        let listed = r#"[{"number":3,"url":"https://forge.example/o/r/pull/3","body":"someone else's","isCrossRepository":false},{"number":2,"url":"https://forge.example/o/r/pull/2","body":"Exported\n\n<!-- kata-forge-intent: 01ABC -->","isCrossRepository":false}]"#;
        let dir = tempfile::tempdir().unwrap();
        let forge = GhCliForge::with_program(gh_shim(dir.path(), listed, "", 0), dir.path());
        let found = forge
            .find_marked_pull_request("forge.example/o/r", "kata/x", "kata-forge-intent: 01ABC")
            .expect("the shim answers");
        assert_eq!(
            gh_log(dir.path()),
            "pr|list|--repo|forge.example/o/r|--head|kata/x|--state|all|--json|number,url,body,isCrossRepository|--limit|100|\n"
        );
        assert_eq!(
            found,
            MarkedPullRequest::Found(PullRequestReceipt::from_url(
                "https://forge.example/o/r/pull/2"
            ))
        );
        assert_eq!(
            forge
                .find_marked_pull_request("forge.example/o/r", "kata/x", "kata-forge-intent: 01XYZ")
                .unwrap(),
            MarkedPullRequest::Absent,
            "no pull request carries that marker"
        );
    }

    /// **The marker observer claims no absence it did not read.** A failed
    /// exit and an answer outside the `--json` contract are each an error (the
    /// forge did not answer); a listing that reaches the read's bound, and an
    /// answer past the bytes a forge command may print, are each
    /// `BeyondBound` (an answer that rules nothing out) — never `Absent`.
    ///
    /// **Would red if:** a failed or truncated listing answered `Absent` — the
    /// export would read its pull request as never opened and open another —
    /// or an oversized one were read whole (the cap on every `gh` command).
    #[test]
    fn the_marker_observer_never_claims_an_unread_absence() {
        let read = |stdout: &str, status: i32| {
            let dir = tempfile::tempdir().unwrap();
            GhCliForge::with_program(gh_shim(dir.path(), stdout, "boom", status), dir.path())
                .find_marked_pull_request("forge.example/o/r", "kata/x", "kata-forge-intent: 01ABC")
        };
        assert!(matches!(read("", 1), Err(KataError::Network(_))));
        assert!(matches!(read("not json", 0), Err(KataError::Internal(_))));
        let listing = |count: usize, body: &str| {
            format!(
                "[{}]",
                (0..count)
                    .map(|n| format!(
                        r#"{{"number":{n},"url":"https://f/pull/{n}","body":"{body}","isCrossRepository":false}}"#
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        assert!(
            matches!(read(&listing(PULL_REQUEST_LIST_BOUND, ""), 0),
                Ok(MarkedPullRequest::BeyondBound(text)) if text.contains("its bound")),
            "a listing at the bound proves no absence"
        );
        let large_body = "x".repeat(64 * 1024);
        assert!(
            matches!(read(&listing(20, &large_body), 0),
                Ok(MarkedPullRequest::BeyondBound(text)) if text.contains("bytes a forge command may")),
            "an answer past the cap proves no absence"
        );
    }

    /// **A failing `gh` did not answer, however much stderr it prints, and
    /// its refusal quotes a bounded part of it.** A marker listing that exits
    /// 1 after 2 MiB on stderr (and nothing on stdout) is a `Network` error —
    /// the forge did not answer, so the observer counts it unanswered — never
    /// `BeyondBound`, and the error quotes at most `process::MAX_QUOTED_STDERR_BYTES`
    /// of that stderr.
    ///
    /// **Would red if:** stderr counted toward the answer's cap (the failed
    /// listing would settle its intent UNCLASSIFIED at once), or the refusal
    /// quoted the whole stderr into the durable error columns.
    #[test]
    fn a_failing_gh_is_unanswered_however_much_stderr_it_prints() {
        let dir = tempfile::tempdir().unwrap();
        let stderr = "e".repeat(2 * 1024 * 1024);
        let forge = GhCliForge::with_program(gh_shim(dir.path(), "", &stderr, 1), dir.path());
        let answer = forge.find_marked_pull_request(
            "forge.example/o/r",
            "kata/x",
            "kata-forge-intent: 01ABC",
        );
        let Err(KataError::Network(message)) = answer else {
            panic!("a failed listing is unanswered: {answer:?}");
        };
        assert!(
            message.len() < crate::process::MAX_QUOTED_STDERR_BYTES + 256,
            "the refusal quotes a bounded stderr: {} bytes",
            message.len()
        );
    }

    /// **The open-PR lookup adopts only a pull request into the export's
    /// base.** The argv asks for `baseRefName` (the shim's log); of two open
    /// pull requests on the head, the one into `main` is the answer for base
    /// `main`, and for base `trunk`, which none targets, the answer is `None`.
    ///
    /// **Would red if:** the lookup adopted any open pull request on the head
    /// (vcs-effects-evidence-7): the export would report a pull request into
    /// another base as its own.
    #[test]
    fn the_open_pull_request_lookup_adopts_only_one_into_the_base() {
        let listed = r#"[{"number":4,"url":"https://forge.example/o/r/pull/4","baseRefName":"release","isCrossRepository":false},{"number":5,"url":"https://forge.example/o/r/pull/5","baseRefName":"main","isCrossRepository":false}]"#;
        let dir = tempfile::tempdir().unwrap();
        let forge = GhCliForge::with_program(gh_shim(dir.path(), listed, "", 0), dir.path());
        assert_eq!(
            forge
                .find_open_pr("forge.example/o/r", "kata/x", "main")
                .unwrap(),
            Some(PullRequestReceipt::from_url(
                "https://forge.example/o/r/pull/5"
            ))
        );
        assert_eq!(
            forge
                .find_open_pr("forge.example/o/r", "kata/x", "trunk")
                .unwrap(),
            None
        );
        assert_eq!(
            gh_log(dir.path()),
            "pr|list|--repo|forge.example/o/r|--head|kata/x|--state|open|--json|number,url,baseRefName,isCrossRepository|--limit|100|\n"
                .repeat(2)
        );
    }

    /// **No pull request whose head lives in another repository is the
    /// export's.** `gh pr list --head` filters by the head branch NAME only, so
    /// a fork's pull request from a branch named like the export's head lists
    /// beside the export's own. The open-PR lookup asks `isCrossRepository`
    /// (the shim's log) and answers `None` for an open cross-repository pull
    /// request into the base; the marker observer reads a cross-repository
    /// pull request carrying the marker as no answer of its own (`Absent`).
    ///
    /// **Would red if:** either read adopted a pull request on the head name
    /// without asking whether its head is in the repository it lists (R3-01:
    /// the export recorded a fork's pull request as carrying its commit).
    #[test]
    fn a_fork_pull_request_on_the_head_name_is_never_the_exports() {
        let open = r#"[{"number":15003,"url":"https://forge.example/o/r/pull/15003","baseRefName":"main","isCrossRepository":true}]"#;
        let dir = tempfile::tempdir().unwrap();
        let forge = GhCliForge::with_program(gh_shim(dir.path(), open, "", 0), dir.path());
        assert_eq!(
            forge
                .find_open_pr("forge.example/o/r", "kata/x", "main")
                .unwrap(),
            None
        );
        assert!(
            gh_log(dir.path()).contains("isCrossRepository"),
            "the lookup asks where each head lives: {}",
            gh_log(dir.path())
        );
        let marked = r#"[{"number":15004,"url":"https://forge.example/o/r/pull/15004","body":"copied\n\n<!-- kata-forge-intent: 01ABC -->","isCrossRepository":true}]"#;
        let dir = tempfile::tempdir().unwrap();
        let forge = GhCliForge::with_program(gh_shim(dir.path(), marked, "", 0), dir.path());
        assert_eq!(
            forge
                .find_marked_pull_request("forge.example/o/r", "kata/x", "kata-forge-intent: 01ABC")
                .unwrap(),
            MarkedPullRequest::Absent,
            "a fork's pull request carrying the marker is not the intent's"
        );
        assert!(gh_log(dir.path()).contains("isCrossRepository"));
    }

    /// **The open-PR lookup proves no absence past its listing's bound.** A
    /// listing of `PULL_REQUEST_LIST_BOUND` open pull requests on the head, none
    /// the export's, is an error (the export then records no intent and opens
    /// nothing), never `None`; the argv carries the bound as `--limit`.
    ///
    /// **Would red if:** the lookup took gh's default listing (30) or a
    /// listing at its bound as complete — the export's own open pull request
    /// past it would read as absent and the create would follow.
    #[test]
    fn the_open_pull_request_lookup_claims_no_absence_past_its_bound() {
        let listing = format!(
            "[{}]",
            (0..PULL_REQUEST_LIST_BOUND)
                .map(|n| format!(
                    r#"{{"number":{n},"url":"https://f/pull/{n}","baseRefName":"main","isCrossRepository":true}}"#
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        let dir = tempfile::tempdir().unwrap();
        let forge = GhCliForge::with_program(gh_shim(dir.path(), &listing, "", 0), dir.path());
        assert!(
            matches!(forge.find_open_pr("forge.example/o/r", "kata/x", "main"), Err(KataError::Validation(text)) if text.contains("its bound")),
            "a listing at the bound proves no absence"
        );
        assert!(
            gh_log(dir.path()).contains(&format!("|--limit|{PULL_REQUEST_LIST_BOUND}|")),
            "{}",
            gh_log(dir.path())
        );
    }

    #[test]
    fn parse_pr_url_takes_last_http_line() {
        let stdout = "Warning: 1 uncommitted change\n\nhttps://github.com/o/r/pull/9\n";
        assert_eq!(
            GhCliForge::parse_pr_url(stdout).as_deref(),
            Some("https://github.com/o/r/pull/9")
        );
    }

    #[test]
    fn parse_pr_url_none_when_no_url() {
        assert_eq!(GhCliForge::parse_pr_url("no url here\n"), None);
    }

    #[test]
    fn pr_create_args_are_the_pinned_contract() {
        let spec = PullRequestSpec {
            repository: "github.com/o/r".into(),
            title: "T".into(),
            body: "B".into(),
            base: "main".into(),
            head: "kata/exec-1".into(),
        };
        assert_eq!(
            GhCliForge::pr_create_args(&spec),
            vec![
                "pr",
                "create",
                "--repo",
                "github.com/o/r",
                "--title",
                "T",
                "--body",
                "B",
                "--base",
                "main",
                "--head",
                "kata/exec-1"
            ]
        );
    }
}
