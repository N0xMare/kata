//! The execution TARGET: what a caller asks an isolated run to work on
//! ([`TargetSpec`]), and what admission resolved that request to and froze
//! ([`ExecutionTarget`]).
//!
//! # Invariant
//!
//! An isolated execution's `/work` fork base, its git view's branch ref and its
//! review range are read off ONE frozen value, resolved before acceptance and
//! bound by the admission digest. Nothing downstream re-resolves trunk to learn
//! what the run forked: a trunk that moves between acceptance and workspace
//! creation — or across a crash in that window — cannot change the run's base.
//!
//! # Spec grammar
//!
//! [`TargetSpec::parse`] is the one parser every face uses:
//!
//! | spelling | spec |
//! |---|---|
//! | `trunk` | [`TargetSpec::Trunk`] — the default when a caller names none |
//! | `pr:<N>`, `N > 0` | [`TargetSpec::PullRequest`] — the forge's pull request `N`, its head and base fetched into the pins |
//! | `branch:…`, `commit:…` | refused [`TARGET_KIND_UNSUPPORTED`] |
//! | anything else | refused [`TARGET_SPEC_INVALID`] |
//!
//! # Refused set of the structural check
//!
//! [`ExecutionTarget::check_structure`] refuses exactly:
//!
//! * [`TARGET_HEAD_INVALID`] — a head that is neither a commit id (40
//!   lowercase hex digits, not all zero) nor `unborn`, or `unborn` on a target
//!   that is not `trunk`;
//! * [`TARGET_COMPARE_INVALID`] — a compare base whose commit or merge base is
//!   not a commit id, a compare on an `unborn` head, or a trunk compare that
//!   carries a branch name;
//! * [`TARGET_FIELDS_INCONSISTENT`] — kind/field disagreement: a `trunk` target
//!   whose landable branch is absent on a commit head or present on an `unborn`
//!   one, or that carries pull-request facts; a `pr` target with a
//!   landable branch, without pull-request facts, without a compare, or whose
//!   facts name another number; a landable branch, a pull request's base or
//!   head ref, or a compare base's name that is not a plain short branch name;
//!   a pull request's `title_truncated` / `body_truncated` set on a text more
//!   than three bytes shorter than its bound (a cut at a character boundary
//!   stops at most three bytes below it, so no cut leaves such a text; an
//!   unflagged text of any length within its bound is not refused);
//! * [`TARGET_PR_URL_INVALID`] — a pull request's `url` that is not a bounded
//!   https forge URL naming that pull request (see [`is_pull_request_url`]);
//! * [`TARGET_PR_TEXT_OVER_BOUND`] — a pull-request title or body over its
//!   byte bound.

use serde::{Deserialize, Serialize};

/// A spelling outside the grammar.
pub const TARGET_SPEC_INVALID: &str = "target_spec_invalid";
/// A kind of the grammar this build does not resolve.
pub const TARGET_KIND_UNSUPPORTED: &str = "target_kind_unsupported";
/// A target named for a program that forks no isolated workspace.
pub const TARGET_REQUIRES_ISOLATED_WORKSPACE: &str = "target_requires_isolated_workspace";
/// A non-trunk target on a program that can invoke an isolated child.
pub const TARGET_CHILDREN_UNSUPPORTED: &str = "target_children_unsupported";
/// A landing program (`promote` / `forge_export`) under a target with no
/// landable branch.
pub const TARGET_NOT_LANDABLE: &str = "target_not_landable";
/// The trunk resolved at landing is not the trunk the target froze.
pub const TARGET_TRUNK_RENAMED: &str = "target_trunk_renamed";
/// The trunk moved between the landing ladder's read and its fast-forward,
/// under the landing lock: a writer outside kata moved it, and nothing landed.
pub const TARGET_TRUNK_RACED: &str = "target_trunk_raced";
/// A frozen head that is not a commit id (or an `unborn` head off trunk).
pub const TARGET_HEAD_INVALID: &str = "target_head_invalid";
/// A frozen compare base that is not a pair of commit ids.
pub const TARGET_COMPARE_INVALID: &str = "target_compare_invalid";
/// Kind/field disagreement inside a frozen target.
pub const TARGET_FIELDS_INCONSISTENT: &str = "target_fields_inconsistent";
/// Pull-request text over its byte bound.
pub const TARGET_PR_TEXT_OVER_BOUND: &str = "target_pr_text_over_bound";
/// A pull-request target on a node whose forge cannot answer: no forge, no
/// `gh`, an unauthenticated `gh`, a failed or timed-out read, an answer
/// outside the read's `--json` contract or about another pull request, or a
/// resolution bound the forge's reads spent before the ref checks finished.
pub const TARGET_FORGE_UNAVAILABLE: &str = "target_forge_unavailable";
/// A pull-request target the forge reports it has no pull request for.
pub const TARGET_PR_NOT_FOUND: &str = "target_pr_not_found";
/// A pull request whose head commit id is not 40 lowercase hex, or whose base
/// or head branch name is not one git accepts as a plain branch name.
pub const TARGET_PR_REF_INVALID: &str = "target_pr_ref_invalid";
/// No git remote, or more than one, is the repository the forge serves.
pub const TARGET_PR_REMOTE_UNRESOLVED: &str = "target_pr_remote_unresolved";
/// The fetch of a pull request's head and base into the pins failed.
pub const TARGET_PR_FETCH_FAILED: &str = "target_pr_fetch_failed";
/// The pull request's head moved between the forge's answer and the fetch.
pub const TARGET_PR_HEAD_RACED: &str = "target_pr_head_raced";
/// The fetched pull-request head and base share no history.
pub const TARGET_PR_NO_MERGE_BASE: &str = "target_pr_no_merge_base";
/// A target with a commit to pin, in a repository whose jj store has no git
/// object store to pin it in (jj's simple backend).
pub const TARGET_REQUIRES_GIT_BACKEND: &str = "target_requires_git_backend";
/// A pull request's frozen `url` that is not a bounded https forge URL naming
/// that pull request.
pub const TARGET_PR_URL_INVALID: &str = "target_pr_url_invalid";
/// A target present where the program forks no isolated workspace, or absent
/// where it does.
pub const TARGET_PRESENCE_INVALID: &str = "target_presence_invalid";

/// The member of a serialized execution invocation envelope that carries its
/// frozen [`ExecutionTarget`]. Named once here because the operational plane
/// splices a schedule fire's target into the pinned envelope by this name,
/// without the typed envelope; the envelope type's own serialization is pinned
/// to it by a test.
pub const INVOCATION_TARGET_MEMBER: &str = "target";

/// The byte bound on a frozen pull-request title.
pub const MAX_PR_TITLE_BYTES: usize = 512;
/// The byte bound on a frozen pull-request body.
pub const MAX_PR_BODY_BYTES: usize = 8 * 1024;
/// The byte bound on a frozen pull-request URL.
pub const MAX_PR_URL_BYTES: usize = 2048;

/// A refusal of a target, carrying its stable code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetRefusal {
    code: &'static str,
    message: String,
}

impl TargetRefusal {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The stable refusal code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The refusal coded `code` that `error` carries when it is exactly such a
    /// refusal lowered into a [`crate::KataError`] (`From<TargetRefusal>`): a
    /// `Validation` whose message is the refusal's display, `<code>: <message>`.
    /// The inverse of that lowering, kept beside it so a raise site that builds
    /// a [`TargetRefusal`] and the door that recognises it share one spelling.
    /// Any other error — another class, another code, the code anywhere but at
    /// the start, the code without its `": "` — is `None`.
    #[must_use]
    pub fn lowered_in(error: &crate::KataError, code: &'static str) -> Option<Self> {
        let crate::KataError::Validation(text) = error else {
            return None;
        };
        let message = text.strip_prefix(code)?.strip_prefix(": ")?;
        Some(Self::new(code, message))
    }
}

impl std::fmt::Display for TargetRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for TargetRefusal {}

impl From<TargetRefusal> for crate::KataError {
    fn from(refusal: TargetRefusal) -> Self {
        Self::Validation(refusal.to_string())
    }
}

/// What the caller asked an isolated run to work on. Provenance: the resolved
/// facts live in [`ExecutionTarget`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetSpec {
    /// The repository's trunk, resolved the way every fork and land resolves it.
    Trunk,
    /// A forge pull request, by number: its head is the fork base, its base
    /// branch the review baseline, and it has no landable branch.
    PullRequest { number: u64 },
}

impl TargetSpec {
    /// Parse a face's spelling. See the module doc for the grammar.
    ///
    /// # Errors
    ///
    /// [`TARGET_KIND_UNSUPPORTED`] for `branch:` / `commit:`,
    /// [`TARGET_SPEC_INVALID`] for every other spelling outside the grammar.
    pub fn parse(raw: &str) -> Result<Self, TargetRefusal> {
        if raw == "trunk" {
            return Ok(Self::Trunk);
        }
        if let Some(number) = raw.strip_prefix("pr:") {
            let parsed = (!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
                .then(|| number.parse::<u64>().ok())
                .flatten()
                .filter(|n| *n > 0);
            return parsed
                .map(|number| Self::PullRequest { number })
                .ok_or_else(|| {
                    TargetRefusal::new(
                        TARGET_SPEC_INVALID,
                        format!(
                            "`{raw}` is not a pull-request target: `pr:` takes a pull-request \
                             number greater than zero, such as `pr:42`"
                        ),
                    )
                });
        }
        if raw.starts_with("branch:") || raw.starts_with("commit:") {
            return Err(TargetRefusal::new(
                TARGET_KIND_UNSUPPORTED,
                format!(
                    "`{raw}` names a target kind this build does not resolve; it resolves \
                     `trunk` and `pr:<N>`"
                ),
            ));
        }
        Err(TargetRefusal::new(
            TARGET_SPEC_INVALID,
            format!("`{raw}` is not a target; this build resolves `trunk` and `pr:<N>`"),
        ))
    }

    /// The kind label: `trunk` or `pr`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Trunk => "trunk",
            Self::PullRequest { .. } => "pr",
        }
    }
}

impl std::fmt::Display for TargetSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trunk => f.write_str("trunk"),
            Self::PullRequest { number } => write!(f, "pr:{number}"),
        }
    }
}

/// The `/work` fork base a target froze.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetHead {
    /// A commit, as 40 lowercase hex digits.
    Commit(String),
    /// A repository with no trunk yet: the empty root is the base. Legal only
    /// for [`TargetSpec::Trunk`].
    Unborn,
}

impl TargetHead {
    /// The commit id, or `None` for an unborn head.
    #[must_use]
    pub fn commit(&self) -> Option<&str> {
        match self {
            Self::Commit(commit) => Some(commit),
            Self::Unborn => None,
        }
    }
}

/// The review baseline a target froze.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompareBase {
    /// The baseline's branch name, when it has one (a PR's base branch). `None`
    /// for a trunk target, whose baseline is the head's first parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The baseline commit.
    pub commit: String,
    /// The merge base of the head and the baseline.
    pub merge_base: String,
}

/// The forge's facts about a pull-request target, frozen at resolution.
/// `title` and `body` are text the PR author controls, cut at resolution to
/// [`MAX_PR_TITLE_BYTES`] / [`MAX_PR_BODY_BYTES`] at a character boundary;
/// `title_truncated` / `body_truncated` record whether the cut dropped
/// anything. They are stored, not derived: an uncut text within three bytes of
/// its bound looks exactly like a cut one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestFacts {
    pub number: u64,
    pub url: String,
    pub head_ref: String,
    pub base_ref: String,
    pub cross_repository: bool,
    pub title: String,
    pub title_truncated: bool,
    pub body: String,
    pub body_truncated: bool,
}

/// What admission resolved a [`TargetSpec`] to and froze inside the invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTarget {
    /// What the caller asked for.
    pub spec: TargetSpec,
    /// The `/work` fork base.
    pub head: TargetHead,
    /// The LANDABLE branch: trunk's name for a trunk target with a head, `None`
    /// for an unborn trunk and for a PR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// The review baseline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compare: Option<CompareBase>,
    /// The forge's facts, for a PR target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<PullRequestFacts>,
}

/// 40 lowercase hex digits, not all zero — the one commit-id spelling a target
/// carries. The all-zero id is jj's virtual root, which no git store holds: a
/// target naming it would pin a broken ref.
#[must_use]
fn is_commit_id(raw: &str) -> bool {
    raw.len() == 40
        && raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && raw.bytes().any(|b| b != b'0')
}

/// A plain git short branch name: non-empty, not starting with `-`, no
/// whitespace or control character, no `..`, none of `~^:?*[\`, no `refs/`
/// prefix, no leading or trailing `/`, no `.lock` suffix. The structural check's
/// spelling test, and the first half of pull-request resolution's check on a
/// forge's branch name; the second half is git's own `check-ref-format`.
///
/// The `.lock` suffix is not a file extension: git refuses a ref name ending
/// in exactly `.lock`, case-sensitively, because it names the ref's lock file.
#[must_use]
#[allow(clippy::case_sensitive_file_extension_comparisons)] // git's own rule is case-sensitive.
pub fn is_short_branch_name(raw: &str) -> bool {
    !raw.is_empty()
        && !raw.starts_with('-')
        && !raw.starts_with('/')
        && !raw.ends_with('/')
        && !raw.starts_with("refs/")
        && !raw.ends_with(".lock")
        && !raw.contains("..")
        && !raw.contains("//")
        && !raw.contains("@{")
        && !raw
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "~^:?*[\\".contains(c))
}

/// A bounded https forge URL naming pull request `number`, and nothing wider:
/// at most [`MAX_PR_URL_BYTES`] bytes, spelled exactly
/// `https://<host>[:<port>](/<segment>){2,}/pull/<number>` — a host of ASCII
/// letters, digits, `.` and `-` not starting with `.` or `-`, a decimal port,
/// path segments of ASCII letters, digits, `.`, `_` and `-` (a forge's owner
/// and repository, behind an optional path prefix), and `number` in decimal
/// without a leading zero. No userinfo, query, fragment, percent-encoding,
/// whitespace or non-ASCII byte can appear in it.
#[must_use]
pub fn is_pull_request_url(url: &str, number: u64) -> bool {
    fn host_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
    }
    fn segment(raw: &str) -> bool {
        !raw.is_empty()
            && raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    }
    if url.len() > MAX_PR_URL_BYTES {
        return false;
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty()
        || host.starts_with(['.', '-'])
        || !host.bytes().all(host_byte)
        || port.is_some_and(|port| port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let Some(repository) = path.strip_suffix(&format!("/pull/{number}")) else {
        return false;
    };
    let segments: Vec<&str> = repository.split('/').collect();
    segments.len() >= 2 && segments.into_iter().all(segment)
}

/// The fewest bytes a cut of a longer text to `bound` bytes at a character
/// boundary leaves: the boundary falls at most one character's continuation
/// bytes below `bound`.
const fn shortest_cut(bound: usize) -> usize {
    bound - (char::MAX_LEN_UTF8 - 1)
}

impl ExecutionTarget {
    /// The structural check. See the module doc for its refused set.
    ///
    /// # Errors
    ///
    /// The first violation found, under its code.
    pub fn check_structure(&self) -> Result<(), TargetRefusal> {
        match &self.head {
            TargetHead::Commit(commit) if !is_commit_id(commit) => {
                return Err(TargetRefusal::new(
                    TARGET_HEAD_INVALID,
                    format!("the frozen head `{commit}` is not a 40-hex commit id"),
                ));
            }
            TargetHead::Unborn if self.spec != TargetSpec::Trunk => {
                return Err(TargetRefusal::new(
                    TARGET_HEAD_INVALID,
                    format!(
                        "an unborn head is legal only for a trunk target, not `{}`",
                        self.spec
                    ),
                ));
            }
            TargetHead::Commit(_) | TargetHead::Unborn => {}
        }
        if let Some(compare) = &self.compare {
            if !is_commit_id(&compare.commit) || !is_commit_id(&compare.merge_base) {
                return Err(TargetRefusal::new(
                    TARGET_COMPARE_INVALID,
                    format!(
                        "the frozen compare base `{}` / merge base `{}` are not both 40-hex \
                         commit ids",
                        compare.commit, compare.merge_base
                    ),
                ));
            }
            if self.head == TargetHead::Unborn {
                return Err(TargetRefusal::new(
                    TARGET_COMPARE_INVALID,
                    "an unborn head has nothing to compare against",
                ));
            }
        }
        if let Some(branch) = &self.branch
            && !is_short_branch_name(branch)
        {
            return Err(TargetRefusal::new(
                TARGET_FIELDS_INCONSISTENT,
                format!("the frozen branch `{branch}` is not a plain short branch name"),
            ));
        }
        match &self.spec {
            TargetSpec::Trunk => {
                // A trunk with a head has a name; an unborn trunk (a repository
                // with no branch yet) has neither, and kata does not invent one.
                let named = self.head != TargetHead::Unborn;
                if self.branch.is_some() != named || self.pull_request.is_some() {
                    return Err(TargetRefusal::new(
                        TARGET_FIELDS_INCONSISTENT,
                        "a trunk target carries trunk's branch name exactly when it has a head, \
                         and no pull-request facts",
                    ));
                }
                if self.compare.as_ref().is_some_and(|c| c.name.is_some()) {
                    return Err(TargetRefusal::new(
                        TARGET_COMPARE_INVALID,
                        "a trunk target's baseline is the head's first parent, which has no \
                         branch name",
                    ));
                }
            }
            TargetSpec::PullRequest { number } => {
                let Some(facts) = &self.pull_request else {
                    return Err(TargetRefusal::new(
                        TARGET_FIELDS_INCONSISTENT,
                        format!("pull-request target `pr:{number}` carries no pull-request facts"),
                    ));
                };
                if self.branch.is_some() || self.compare.is_none() || facts.number != *number {
                    return Err(TargetRefusal::new(
                        TARGET_FIELDS_INCONSISTENT,
                        format!(
                            "pull-request target `pr:{number}` must carry no landable branch, a \
                             compare base, and facts for that same number (facts name {})",
                            facts.number
                        ),
                    ));
                }
                // The git view writes `base_ref` as the capsule's branch ref, so
                // its spelling is refused here, at admission, not first at the
                // worker.
                let compare_name = self.compare.as_ref().and_then(|c| c.name.as_deref());
                if let Some(name) = [
                    Some(facts.base_ref.as_str()),
                    Some(facts.head_ref.as_str()),
                    compare_name,
                ]
                .into_iter()
                .flatten()
                .find(|name| !is_short_branch_name(name))
                {
                    return Err(TargetRefusal::new(
                        TARGET_FIELDS_INCONSISTENT,
                        format!(
                            "pull-request target `pr:{number}` names `{name}`, which is not a \
                             plain short branch name"
                        ),
                    ));
                }
                if !is_pull_request_url(&facts.url, *number) {
                    return Err(TargetRefusal::new(
                        TARGET_PR_URL_INVALID,
                        format!(
                            "pull-request target `pr:{number}` names the url `{}`, which is not \
                             a bounded https forge URL of that pull request",
                            facts.url.escape_debug()
                        ),
                    ));
                }
                if facts.title.len() > MAX_PR_TITLE_BYTES || facts.body.len() > MAX_PR_BODY_BYTES {
                    return Err(TargetRefusal::new(
                        TARGET_PR_TEXT_OVER_BOUND,
                        format!(
                            "pull-request text over its bound: title {} bytes (max \
                             {MAX_PR_TITLE_BYTES}), body {} bytes (max {MAX_PR_BODY_BYTES})",
                            facts.title.len(),
                            facts.body.len()
                        ),
                    ));
                }
                for (field, text, truncated, bound) in [
                    (
                        "title",
                        &facts.title,
                        facts.title_truncated,
                        MAX_PR_TITLE_BYTES,
                    ),
                    ("body", &facts.body, facts.body_truncated, MAX_PR_BODY_BYTES),
                ] {
                    if truncated && text.len() < shortest_cut(bound) {
                        return Err(TargetRefusal::new(
                            TARGET_FIELDS_INCONSISTENT,
                            format!(
                                "pull-request target `pr:{number}` says its {field} was cut, \
                                 but it is {} bytes: a cut to {bound} bytes leaves at least {}",
                                text.len(),
                                shortest_cut(bound)
                            ),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// One operator line: `target=trunk head=<sha> compare=<sha>`, or
    /// `compare=main@<sha>` when the baseline has a name.
    #[must_use]
    pub fn summary(&self) -> String {
        let head = self.head.commit().unwrap_or("unborn");
        let compare = self.compare.as_ref().map_or_else(
            || "none".to_owned(),
            |compare| match &compare.name {
                Some(name) => format!("{name}@{}", compare.commit),
                None => compare.commit.clone(),
            },
        );
        format!("target={} head={head} compare={compare}", self.spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn trunk() -> ExecutionTarget {
        ExecutionTarget {
            spec: TargetSpec::Trunk,
            head: TargetHead::Commit(A.to_owned()),
            branch: Some("main".to_owned()),
            compare: Some(CompareBase {
                name: None,
                commit: B.to_owned(),
                merge_base: B.to_owned(),
            }),
            pull_request: None,
        }
    }

    fn pr() -> ExecutionTarget {
        ExecutionTarget {
            spec: TargetSpec::PullRequest { number: 7 },
            head: TargetHead::Commit(A.to_owned()),
            branch: None,
            compare: Some(CompareBase {
                name: Some("main".to_owned()),
                commit: B.to_owned(),
                merge_base: B.to_owned(),
            }),
            pull_request: Some(PullRequestFacts {
                number: 7,
                url: "https://forge.example/o/r/pull/7".to_owned(),
                head_ref: "feature".to_owned(),
                base_ref: "main".to_owned(),
                cross_repository: false,
                title: "t".to_owned(),
                title_truncated: false,
                body: "b".to_owned(),
                body_truncated: false,
            }),
        }
    }

    fn refused(target: &ExecutionTarget) -> &'static str {
        target
            .check_structure()
            .expect_err("the target is refused")
            .code()
    }

    #[test]
    fn the_grammar_parses_trunk_and_pull_requests_and_round_trips_its_spelling() {
        assert_eq!(TargetSpec::parse("trunk"), Ok(TargetSpec::Trunk));
        assert_eq!(
            TargetSpec::parse("pr:42"),
            Ok(TargetSpec::PullRequest { number: 42 })
        );
        for spelling in ["trunk", "pr:42", "pr:1"] {
            assert_eq!(TargetSpec::parse(spelling).unwrap().to_string(), spelling);
        }
    }

    #[test]
    fn a_spelling_outside_the_grammar_is_refused_by_name() {
        for raw in [
            "",
            "Trunk",
            " trunk",
            "pr:",
            "pr:0",
            "pr:-1",
            "pr:+1",
            "pr:1x",
            "pr: 1",
            "tag:v1",
            "pr:99999999999999999999999",
        ] {
            assert_eq!(
                TargetSpec::parse(raw).unwrap_err().code(),
                TARGET_SPEC_INVALID,
                "{raw:?}"
            );
        }
        for raw in ["branch:main", "commit:3f9a2c1", "branch:", "commit:"] {
            assert_eq!(
                TargetSpec::parse(raw).unwrap_err().code(),
                TARGET_KIND_UNSUPPORTED,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn well_formed_targets_pass_the_structural_check() {
        trunk().check_structure().unwrap();
        pr().check_structure().unwrap();
        let mut unborn = trunk();
        unborn.head = TargetHead::Unborn;
        unborn.branch = None;
        unborn.compare = None;
        unborn.check_structure().unwrap();
        let mut root = trunk();
        root.compare = None;
        root.check_structure().unwrap();
    }

    #[test]
    fn a_head_that_is_not_a_commit_id_is_refused() {
        for head in [
            "",
            "not-a-commit-id",
            &A[..39],
            &A.to_uppercase(),
            &format!("{A}0"),
            &"0".repeat(40),
        ] {
            let mut target = trunk();
            target.head = TargetHead::Commit(head.to_owned());
            assert_eq!(refused(&target), TARGET_HEAD_INVALID, "{head:?}");
        }
        let mut target = pr();
        target.head = TargetHead::Unborn;
        assert_eq!(refused(&target), TARGET_HEAD_INVALID);
    }

    #[test]
    fn a_compare_base_that_is_not_a_commit_pair_is_refused() {
        let mut target = trunk();
        target.compare.as_mut().unwrap().merge_base = "x".to_owned();
        assert_eq!(refused(&target), TARGET_COMPARE_INVALID);
        let mut target = trunk();
        target.compare.as_mut().unwrap().commit = "0".repeat(40);
        assert_eq!(
            refused(&target),
            TARGET_COMPARE_INVALID,
            "jj's virtual root is no commit"
        );
        let mut target = trunk();
        target.compare.as_mut().unwrap().name = Some("main".to_owned());
        assert_eq!(refused(&target), TARGET_COMPARE_INVALID);
        let mut target = trunk();
        target.head = TargetHead::Unborn;
        assert_eq!(refused(&target), TARGET_COMPARE_INVALID);
    }

    #[test]
    fn kind_and_fields_that_disagree_are_refused() {
        let mut target = trunk();
        target.branch = None;
        assert_eq!(refused(&target), TARGET_FIELDS_INCONSISTENT);
        let mut target = trunk();
        target.head = TargetHead::Unborn;
        target.compare = None;
        assert_eq!(
            refused(&target),
            TARGET_FIELDS_INCONSISTENT,
            "an unborn trunk names no branch"
        );
        let mut target = trunk();
        target.pull_request = pr().pull_request;
        assert_eq!(refused(&target), TARGET_FIELDS_INCONSISTENT);
        let mut target = trunk();
        target.branch = Some("refs/heads/main".to_owned());
        assert_eq!(refused(&target), TARGET_FIELDS_INCONSISTENT);
        let mut target = pr();
        target.branch = Some("main".to_owned());
        assert_eq!(refused(&target), TARGET_FIELDS_INCONSISTENT);
        let mut target = pr();
        target.pull_request = None;
        assert_eq!(refused(&target), TARGET_FIELDS_INCONSISTENT);
        let mut target = pr();
        target.compare = None;
        assert_eq!(refused(&target), TARGET_FIELDS_INCONSISTENT);
        let mut target = pr();
        target.pull_request.as_mut().unwrap().number = 8;
        assert_eq!(refused(&target), TARGET_FIELDS_INCONSISTENT);
    }

    #[test]
    fn a_pull_request_ref_that_is_not_a_short_branch_name_is_refused() {
        for name in ["../x", "refs/heads/main", "-main", "a b", ""] {
            let mut target = pr();
            target.pull_request.as_mut().unwrap().base_ref = name.to_owned();
            assert_eq!(
                refused(&target),
                TARGET_FIELDS_INCONSISTENT,
                "base {name:?}"
            );
            let mut target = pr();
            target.pull_request.as_mut().unwrap().head_ref = name.to_owned();
            assert_eq!(
                refused(&target),
                TARGET_FIELDS_INCONSISTENT,
                "head {name:?}"
            );
            let mut target = pr();
            target.compare.as_mut().unwrap().name = Some(name.to_owned());
            assert_eq!(
                refused(&target),
                TARGET_FIELDS_INCONSISTENT,
                "compare {name:?}"
            );
        }
    }

    #[test]
    fn a_pull_request_url_outside_the_forge_grammar_is_refused() {
        let at_bound = format!(
            "https://forge.example/{}/r/pull/7",
            "o".repeat(MAX_PR_URL_BYTES - "https://forge.example//r/pull/7".len())
        );
        assert_eq!(at_bound.len(), MAX_PR_URL_BYTES);
        for url in [
            "https://forge.example/o/r/pull/7",
            "https://github.com/N0xMare/kata-e2-fixture/pull/7",
            "https://ghe.example:8443/prefix/o/r.git_x/pull/7",
            at_bound.as_str(),
        ] {
            let mut target = pr();
            target.pull_request.as_mut().unwrap().url = url.to_owned();
            target
                .check_structure()
                .unwrap_or_else(|refusal| panic!("{url:?} is a forge URL: {refusal}"));
        }
        let over_bound = format!("{at_bound}x").replace("/pull/7x", "x/pull/7");
        assert_eq!(over_bound.len(), MAX_PR_URL_BYTES + 1);
        for url in [
            "",
            "http://forge.example/o/r/pull/7",
            "https://forge.example/o/r/pull/8",
            "https://forge.example/o/r/pull/07",
            "https://forge.example/o/r/pull/7/",
            "https://forge.example/r/pull/7",
            "https://forge.example//r/pull/7",
            "https://forge.example/o/r/pulls/7",
            "https://forge.example/o/r/pull/7?x=1",
            "https://forge.example/o/r/pull/7#c",
            "https://u@forge.example/o/r/pull/7",
            "https://forge.example:/o/r/pull/7",
            "https://forge.example:x/o/r/pull/7",
            "https://-forge.example/o/r/pull/7",
            "https:///o/r/pull/7",
            "https://forge.example/o%2F/r/pull/7",
            "https://forge.example/o r/r/pull/7",
            "https://forge.example/o\nr/r/pull/7",
            "https://forgé.example/o/r/pull/7",
            "file:///o/r/pull/7",
            over_bound.as_str(),
        ] {
            let mut target = pr();
            target.pull_request.as_mut().unwrap().url = url.to_owned();
            assert_eq!(refused(&target), TARGET_PR_URL_INVALID, "{url:?}");
        }
    }

    #[test]
    fn pull_request_text_over_its_bound_is_refused_and_at_its_bound_is_not() {
        let mut target = pr();
        target.pull_request.as_mut().unwrap().title = "t".repeat(MAX_PR_TITLE_BYTES);
        target.pull_request.as_mut().unwrap().body = "b".repeat(MAX_PR_BODY_BYTES);
        target.check_structure().unwrap();
        target.pull_request.as_mut().unwrap().title.push('t');
        assert_eq!(refused(&target), TARGET_PR_TEXT_OVER_BOUND);
        let mut target = pr();
        target.pull_request.as_mut().unwrap().body = "b".repeat(MAX_PR_BODY_BYTES + 1);
        assert_eq!(refused(&target), TARGET_PR_TEXT_OVER_BOUND);
    }

    /// A flag that says the text was cut is refused when the text is shorter
    /// than any cut produces: a cut stops at most three bytes below the bound
    /// (a UTF-8 character is at most four bytes). Admitted: a flagged text at
    /// every length a cut can leave, and an unflagged one at any length within
    /// the bound.
    #[test]
    fn a_truncated_flag_on_text_shorter_than_any_cut_is_refused() {
        for (bound, edit) in [
            (
                MAX_PR_TITLE_BYTES,
                (|facts: &mut PullRequestFacts, len: usize, cut: bool| {
                    facts.title = "t".repeat(len);
                    facts.title_truncated = cut;
                }) as fn(&mut PullRequestFacts, usize, bool),
            ),
            (
                MAX_PR_BODY_BYTES,
                |facts: &mut PullRequestFacts, len, cut| {
                    facts.body = "b".repeat(len);
                    facts.body_truncated = cut;
                },
            ),
        ] {
            let with = |len: usize, cut: bool| {
                let mut target = pr();
                edit(target.pull_request.as_mut().unwrap(), len, cut);
                target
            };
            for len in bound - 3..=bound {
                with(len, true).check_structure().unwrap_or_else(|refusal| {
                    panic!("a cut can leave {len} of {bound} bytes: {refusal}")
                });
            }
            for len in [0, 1, bound - 4] {
                assert_eq!(
                    refused(&with(len, true)),
                    TARGET_FIELDS_INCONSISTENT,
                    "no cut leaves {len} of {bound} bytes"
                );
                with(len, false)
                    .check_structure()
                    .unwrap_or_else(|refusal| panic!("uncut text of {len} bytes: {refusal}"));
            }
        }
    }

    /// The flags have no default: pull-request facts without them (what
    /// invocation schema 2 froze) do not decode.
    #[test]
    fn pull_request_facts_without_their_truncation_flags_do_not_decode() {
        let facts = serde_json::to_value(pr().pull_request.unwrap()).unwrap();
        for flag in ["title_truncated", "body_truncated"] {
            let mut older = facts.clone();
            older.as_object_mut().unwrap().remove(flag).unwrap();
            let error = serde_json::from_value::<PullRequestFacts>(older)
                .expect_err("a missing flag is never read as false");
            assert!(error.to_string().contains(flag), "{error}");
        }
    }

    #[test]
    fn a_target_round_trips_through_its_durable_json() {
        for target in [trunk(), pr()] {
            let bytes = serde_json::to_vec(&target).unwrap();
            assert_eq!(
                serde_json::from_slice::<ExecutionTarget>(&bytes).unwrap(),
                target
            );
        }
        let unknown = serde_json::json!({
            "spec": {"kind": "trunk"}, "head": "unborn", "branch": "main", "extra": 1
        });
        assert!(serde_json::from_value::<ExecutionTarget>(unknown).is_err());
    }

    #[test]
    fn a_lowered_refusal_is_recognised_by_its_code_and_nothing_else_is() {
        let refusal = TargetRefusal::new(TARGET_TRUNK_RENAMED, "froze `main`, now `release`");
        let lowered = crate::KataError::from(refusal.clone());
        assert_eq!(
            TargetRefusal::lowered_in(&lowered, TARGET_TRUNK_RENAMED),
            Some(refusal)
        );
        for other in [
            crate::KataError::Validation(format!("promote failed: {TARGET_TRUNK_RENAMED}: x")),
            crate::KataError::Validation(format!("{TARGET_TRUNK_RENAMED} without a colon")),
            crate::KataError::Validation(format!("{TARGET_TRUNK_RENAMED}:x")),
            crate::KataError::Validation(format!("{TARGET_NOT_LANDABLE}: x")),
            crate::KataError::Internal(format!("{TARGET_TRUNK_RENAMED}: x")),
        ] {
            assert_eq!(
                TargetRefusal::lowered_in(&other, TARGET_TRUNK_RENAMED),
                None,
                "{other:?}"
            );
        }
    }

    #[test]
    fn the_summary_names_the_spec_head_and_compare() {
        assert_eq!(
            trunk().summary(),
            format!("target=trunk head={A} compare={B}")
        );
        assert_eq!(
            pr().summary(),
            format!("target=pr:7 head={A} compare=main@{B}")
        );
    }
}
