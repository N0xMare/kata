//! The forge boundary: open a pull request for a pushed candidate
//! branch, and READ a pull request a run is asked to target.
//!
//! The operator knows the forge by name (GitHub, via the `gh` CLI), so per
//! kata's architecture rule it is a **trait** ([`Forge`]) with a **thin** impl
//! (`kata-vcs`'s `GhCliForge`) that shells the `gh` binary the operator already
//! authenticates (`gh auth login`) — kata pulls in no forge SDK / API-client
//! dependency tree.
//!
//! ## SINK, never a source
//!
//! A [`Forge`] is a validated-candidate SINK: `forge_export` calls it AFTER the
//! candidate has landed, and a PR-open failure fails only that terminal effect
//! stage — it can never un-validate the candidate, mutate trunk, or feed a
//! completion/validation signal back into the workflow. That property is
//! structural (the effect envelope carries no validation report) and enforced
//! at the stage boundary; a forge only has to fail CLOSED and TYPED.
//!
//! ## The pull-request read is a SOURCE, and untrusted
//!
//! [`Forge::resolve_pull_request`] and [`Forge::repository_url`] feed admission
//! (a `pr:<N>` target is resolved before acceptance). What they return is the
//! forge's — and, for a pull request's refs, title and body, its author's —
//! text, unvalidated: the caller validates every field before composing any of
//! it into a git argument. A failed read is a typed [`TargetRefusal`]
//! ([`TARGET_FORGE_UNAVAILABLE`], [`TARGET_PR_NOT_FOUND`]), never a guess.
//!
//! ## The in-process double
//!
//! [`RecordingForge`] is the in-process double for workflow-level tests: it
//! records every [`PullRequestSpec`] and returns a canned
//! [`PullRequestReceipt`].
//!
//! [`TARGET_PR_NOT_FOUND`]: kata_types::target::TARGET_PR_NOT_FOUND

use std::sync::Mutex;
use std::time::Duration;

use kata_types::KataResult;
use kata_types::target::{TARGET_FORGE_UNAVAILABLE, TargetRefusal};

/// Network publication gets a separate budget; an expired push has unknown outcome.
pub const FORGE_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

/// A pull request as the forge reported it: UNVALIDATED. Every string is the
/// forge's text, and `head_ref_name`, `title` and `body` are the pull-request
/// author's; the caller validates each before using it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgePullRequest {
    pub number: u64,
    pub url: String,
    pub head_ref_oid: String,
    pub head_ref_name: String,
    pub base_ref_name: String,
    pub is_cross_repository: bool,
    pub title: String,
    pub body: String,
}

/// The pull-request a [`Forge`] is asked to open for a pushed candidate branch.
///
/// `repository` is the forge repository the branch was pushed to; `head` is
/// the already-pushed branch (kata owns `kata/<exec>`); `base` is the target
/// branch the PR merges into. `title`/`body` are literal strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullRequestSpec {
    /// The forge repository, `HOST/OWNER/REPO`, the pull request opens in —
    /// the push remote's (`ExecutionWorkspaceProvider::forge_export_repository`).
    pub repository: String,
    /// PR title.
    pub title: String,
    /// PR body/description.
    pub body: String,
    /// Base branch the PR targets (e.g. `main`).
    pub base: String,
    /// Head branch the PR is opened from — already pushed to the remote
    /// (`kata/<exec>`).
    pub head: String,
}

/// The receipt returned once a forge has opened a PR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullRequestReceipt {
    /// The PR web URL (`https://github.com/owner/repo/pull/123`).
    pub url: String,
    /// The PR number parsed off the URL when present.
    pub number: Option<u64>,
}

impl PullRequestReceipt {
    /// Build a receipt from a forge-reported URL, parsing the trailing
    /// `/pull/<n>` (or `/pulls/<n>`, or `/-/merge_requests/<n>`) number when
    /// one is present. A URL with no recognizable number still yields a
    /// receipt (the URL is the load-bearing field).
    #[must_use]
    pub fn from_url(url: impl Into<String>) -> Self {
        let url = url.into();
        let number = url
            .rsplit('/')
            .next()
            .and_then(|segment| segment.trim().parse::<u64>().ok());
        Self { url, number }
    }
}

/// What the marker observer ([`Forge::find_marked_pull_request`]) read: an
/// ANSWER. A read the forge did not answer is the method's error instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarkedPullRequest {
    /// A pull request on the head carries the marker, in some state.
    Found(PullRequestReceipt),
    /// The forge listed every pull request on the head, and none carries it.
    Absent,
    /// The forge answered, but more than the read can hold — its listing
    /// reached the read's bound, or its stdout the cap on a forge read (its
    /// stderr is no answer, however long) — so a
    /// marked pull request past it cannot be ruled out: a state that answers
    /// neither way, which asking again does not change. The text says which
    /// bound.
    BeyondBound(String),
}

/// The forge boundary: open a pull request for a pushed candidate branch.
///
/// Operator-facing (the operator knows GitHub/`gh` by name), so it is a trait;
/// the concrete `GhCliForge` (`kata-vcs`) is a thin `gh` shell.
pub trait Forge: Send + Sync {
    /// CREATE a pull request in `req.repository` for `req.head` targeting
    /// `req.base`: the one wire effect, and nothing else — it reads nothing
    /// first. Returns the PR
    /// receipt, or a typed [`KataError`](kata_types::KataError) on any failure
    /// (never panics).
    ///
    /// The export asks [`Self::find_open_pr`] BEFORE the pull request's intent
    /// and adopts an open one it finds, so a create is only ever sent under an
    /// intent. Whether a crashed export already opened ITS pull request, closed
    /// since or not, is [`Self::find_marked_pull_request`]'s question, which
    /// the export asks before it creates one again.
    fn create_pull_request(&self, req: &PullRequestSpec) -> KataResult<PullRequestReceipt>;

    /// CONFIRM the forge addresses `repository` (`HOST/OWNER/REPO`): a
    /// read-only ask the export makes before the push's intent, so a
    /// repository every later call of the export would fail on refuses the
    /// export before anything is pushed. `Ok` only when the forge answers a
    /// repository whose `OWNER/REPO` is `repository`'s (ASCII case ignored).
    ///
    /// # Errors
    ///
    /// A typed [`KataError`](kata_types::KataError) when the forge does not
    /// answer (a host it cannot reach — an SSH host alias, which the forge
    /// client does not translate — no login for the host, no such
    /// repository), answers outside its contract, or answers another
    /// repository (one renamed since the remote's URL was written).
    fn confirm_repository(&self, repository: &str) -> KataResult<()>;

    /// The OPEN pull request from `head` into `base` in `repository`
    /// (`HOST/OWNER/REPO`), if the forge already has one — the read the
    /// export performs before the pull request's intent. `None` when none exists; an open pull request from `head` into
    /// another base, or from a branch named `head` in another repository (a
    /// fork's), is not this export's and answers `None` too. A typed
    /// [`KataError`](kata_types::KataError) when the forge cannot answer, or
    /// answers a listing too long to rule this export's out. A
    /// crashed export's recovery reads [`Self::find_marked_pull_request`]
    /// instead, which sees a closed one too.
    ///
    /// # Errors
    ///
    /// Same vocabulary as [`Self::create_pull_request`]'s spawn/exit mapping.
    fn find_open_pr(
        &self,
        repository: &str,
        head: &str,
        base: &str,
    ) -> KataResult<Option<PullRequestReceipt>>;

    /// The pull request of `repository` (`HOST/OWNER/REPO`) whose head is
    /// `head` in that repository (never a fork's branch of that name) and
    /// whose body carries `marker`,
    /// in ANY state — open, closed or merged: the observer of a pull request
    /// kata opened under an intent whose id the marker spells.
    ///
    /// # Errors
    ///
    /// A typed [`KataError`](kata_types::KataError) when the forge does not
    /// answer the read. An answer too large to rule a marked pull request out
    /// is no error: it is [`MarkedPullRequest::BeyondBound`].
    fn find_marked_pull_request(
        &self,
        repository: &str,
        head: &str,
        marker: &str,
    ) -> KataResult<MarkedPullRequest>;

    /// READ pull request `number` of the repository the forge serves, within
    /// `bound`. Unvalidated (see [`ForgePullRequest`]).
    ///
    /// # Errors
    ///
    /// [`TARGET_PR_NOT_FOUND`](kata_types::target::TARGET_PR_NOT_FOUND) when the
    /// forge reports no such pull request;
    /// [`TARGET_FORGE_UNAVAILABLE`] for every other failure to answer.
    fn resolve_pull_request(
        &self,
        number: u64,
        bound: Duration,
    ) -> Result<ForgePullRequest, TargetRefusal>;

    /// READ the web URL of the repository the forge serves (the one
    /// [`Self::resolve_pull_request`] reads from), within `bound`.
    ///
    /// # Errors
    ///
    /// [`TARGET_FORGE_UNAVAILABLE`] for every failure to answer.
    fn repository_url(&self, bound: Duration) -> Result<String, TargetRefusal>;
}

/// In-process [`Forge`] test double for workflow-level tests.
///
/// Records every [`PullRequestSpec`] it is asked to open (so a test can assert
/// the head/base/title the effect built) and returns a canned
/// [`PullRequestReceipt`]. Every [`Forge::create_pull_request`] records and
/// succeeds, it confirms every repository ([`Forge::confirm_repository`]), and
/// its [`Forge::find_open_pr`] answers `None`;
/// [`Forge::find_marked_pull_request`] answers the canned receipt exactly when a
/// recorded call in that repository on that head carries the marker in its
/// body. It reads no pull request: both reads refuse
/// [`TARGET_FORGE_UNAVAILABLE`].
///
/// Shipped in the library (not `#[cfg(test)]`) because it is exercised from
/// other crates' integration tests, where a `#[cfg(test)]`
/// double would be invisible.
pub struct RecordingForge {
    calls: Mutex<Vec<PullRequestSpec>>,
    receipt: PullRequestReceipt,
}

impl RecordingForge {
    /// A recording double that succeeds, returning `receipt` for every call.
    #[must_use]
    pub fn succeeding(receipt: PullRequestReceipt) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            receipt,
        }
    }

    /// A recording double that succeeds, returning a receipt built from `url`.
    #[must_use]
    pub fn succeeding_with_url(url: impl Into<String>) -> Self {
        Self::succeeding(PullRequestReceipt::from_url(url))
    }

    /// Every spec this double was asked to open, in call order.
    #[must_use]
    pub fn calls(&self) -> Vec<PullRequestSpec> {
        self.calls.lock().expect("recording forge mutex").clone()
    }

    /// How many times [`Forge::create_pull_request`] was invoked.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.lock().expect("recording forge mutex").len()
    }
}

impl Forge for RecordingForge {
    fn create_pull_request(&self, req: &PullRequestSpec) -> KataResult<PullRequestReceipt> {
        self.calls
            .lock()
            .expect("recording forge mutex")
            .push(req.clone());
        Ok(self.receipt.clone())
    }

    fn confirm_repository(&self, _repository: &str) -> KataResult<()> {
        Ok(())
    }

    fn find_open_pr(
        &self,
        _repository: &str,
        _head: &str,
        _base: &str,
    ) -> KataResult<Option<PullRequestReceipt>> {
        Ok(None)
    }

    fn find_marked_pull_request(
        &self,
        repository: &str,
        head: &str,
        marker: &str,
    ) -> KataResult<MarkedPullRequest> {
        let calls = self.calls.lock().expect("recording forge mutex");
        Ok(
            if calls.iter().any(|spec| {
                spec.repository == repository && spec.head == head && spec.body.contains(marker)
            }) {
                MarkedPullRequest::Found(self.receipt.clone())
            } else {
                MarkedPullRequest::Absent
            },
        )
    }

    fn resolve_pull_request(
        &self,
        number: u64,
        _bound: Duration,
    ) -> Result<ForgePullRequest, TargetRefusal> {
        Err(TargetRefusal::new(
            TARGET_FORGE_UNAVAILABLE,
            format!("the recording forge reads no pull request (#{number})"),
        ))
    }

    fn repository_url(&self, _bound: Duration) -> Result<String, TargetRefusal> {
        Err(TargetRefusal::new(
            TARGET_FORGE_UNAVAILABLE,
            "the recording forge serves no repository",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_parses_pull_number_off_github_url() {
        let receipt = PullRequestReceipt::from_url("https://github.com/o/r/pull/4217");
        assert_eq!(receipt.number, Some(4217));
        assert_eq!(receipt.url, "https://github.com/o/r/pull/4217");
    }

    #[test]
    fn receipt_without_trailing_number_still_carries_url() {
        let receipt = PullRequestReceipt::from_url("https://example.test/pr/new");
        assert_eq!(receipt.number, None);
        assert_eq!(receipt.url, "https://example.test/pr/new");
    }

    #[test]
    fn recording_forge_records_and_returns_canned_receipt() {
        let forge = RecordingForge::succeeding_with_url("https://github.com/o/r/pull/1");
        let spec = PullRequestSpec {
            repository: "forge.test/o/r".into(),
            title: "t".into(),
            body: "b".into(),
            base: "main".into(),
            head: "kata/x".into(),
        };
        let receipt = forge
            .create_pull_request(&spec)
            .expect("recording forge ok");
        assert_eq!(receipt.number, Some(1));
        assert_eq!(forge.call_count(), 1);
        assert_eq!(forge.calls()[0], spec);
        assert_eq!(
            forge
                .find_marked_pull_request("forge.test/o/r", "kata/x", "b")
                .unwrap(),
            MarkedPullRequest::Found(receipt),
            "a recorded body carrying the marker is found"
        );
        assert_eq!(
            forge
                .find_marked_pull_request("forge.test/o/r", "kata/x", "nope")
                .unwrap(),
            MarkedPullRequest::Absent
        );
        assert_eq!(
            forge
                .find_marked_pull_request("forge.test/o/r", "kata/y", "b")
                .unwrap(),
            MarkedPullRequest::Absent
        );
        assert_eq!(
            forge
                .find_marked_pull_request("forge.test/o/other", "kata/x", "b")
                .unwrap(),
            MarkedPullRequest::Absent,
            "a pull request in another repository is not found"
        );
    }
}
