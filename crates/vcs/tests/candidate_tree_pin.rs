//! The candidate identity fence, driven through the PRODUCTION jj promote path
//! against a real colocated repository and asserted on the **git** side.
//!
//! North-star clause 4: candidate → validation evidence → approval → landing is
//! one loop. Nothing in the graph forbids a stage between the validation stamp
//! and the in-graph `workspace_effect op="promote"`, and two shipped packs put
//! one there. `ExecutionWorkspaceProvider::promote_workspace` therefore takes
//! the tree identity validation approved and refuses to land anything else.
//!
//! Everything here reads the outcome out of git — `git rev-parse
//! refs/heads/<trunk>`, `git cat-file`, the worktree on disk — never out of
//! kata's own records. A fence that refuses while trunk still moves, or that
//! refuses and destroys the work it refused to land, would be green against
//! kata's return value alone.
//!
//! Companion suite: `crates/types/tests/candidate_tree_pin_refusals.rs` pins
//! the refused SET on the pure predicate.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_types::execution::CandidateTreePin;
use kata_vcs::{JjBackend, VcsBackend};
use ulid::Ulid;

fn git_stdout(repo: &Path, args: &[&str]) -> String {
    let out = kata_test_utils::git::hermetic_git_in(repo)
        .args(args)
        .output()
        .expect("git must be available");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Trunk as GIT sees it — the side an operator, a CI system and every git tool
/// read. A jj bookmark nobody but jj can see has landed nothing.
fn git_trunk(repo: &Path) -> String {
    git_stdout(repo, &["rev-parse", "refs/heads/main"])
}

struct Fixture {
    _tmp: tempfile::TempDir,
    repo: std::path::PathBuf,
    provider: Arc<JjBackend>,
    key: ExecutionWorkspaceKey,
    candidate: std::path::PathBuf,
    /// git trunk before anything promoted.
    trunk_before: String,
}

impl Fixture {
    /// The tree id of the LIVE candidate — on a clean candidate, the value a
    /// validation stamp records (`validation_candidate_binding_for_recorded`'s
    /// `tree_id`, the recorded `@` tree).
    fn live_tree_id(&self) -> String {
        let agent = kata_types::AgentId(self.key.execution_id);
        <JjBackend as VcsBackend>::workspace_status(self.provider.as_ref(), &agent)
            .expect("candidate status")
            .head
            .tree_id
    }

    fn promote(&self, pin: &CandidateTreePin) -> kata_types::KataResult<()> {
        ExecutionWorkspaceProvider::promote_workspace(self.provider.as_ref(), &self.key, pin, None)
            .map(|_| ())
    }
}

/// An ADOPTED colocated repo with a live execution workspace carrying an agent's
/// uncommitted edit — the state the runner hands a terminal `promote` stage.
fn candidate_with_agent_edit() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("project");
    fs::create_dir_all(&repo).expect("repo dir");
    kata_test_utils::git::init_git_repo_at(&repo);
    // A gitignore the candidate can write under without changing tracked
    // content — the flagship pack's `validate` writes `kata-out/check.log` into
    // the very tree it is judging.
    fs::write(repo.join(".gitignore"), "kata-out/\n").expect("gitignore");
    kata_test_utils::git::run_git(&repo, &["add", ".gitignore"]);
    kata_test_utils::git::run_git(&repo, &["commit", "-q", "-m", "ignore kata-out"]);
    let trunk_before = git_trunk(&repo);

    let provider = Arc::new(JjBackend::open(&repo).expect("adopt colocated git repo"));
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle =
        kata_vcs::test_support::create_trunk_workspace(provider.as_ref(), &key).expect("candidate");
    fs::write(handle.path.join("tally.py"), "def tally():\n    return 1\n").expect("agent edit");

    Fixture {
        _tmp: tmp,
        repo,
        provider,
        key,
        candidate: handle.path,
        trunk_before,
    }
}

/// ADMITS: the tree validation stamped is the tree that settles, so trunk moves.
///
/// The control for every refusal below — without it a fence that refused
/// EVERYTHING would pass all of them.
#[test]
fn a_candidate_untouched_since_the_validation_stamp_lands() {
    let fx = candidate_with_agent_edit();
    let stamped = fx.live_tree_id();

    fx.promote(&CandidateTreePin::Pinned(stamped.clone()))
        .expect("an unmodified candidate must land");

    let trunk_after = git_trunk(&fx.repo);
    assert_ne!(
        trunk_after, fx.trunk_before,
        "git trunk must have advanced past {}",
        fx.trunk_before
    );
    assert_eq!(
        git_stdout(&fx.repo, &["rev-parse", &format!("{trunk_after}^{{tree}}")]),
        stamped,
        "the tree git now holds at trunk must be the tree the pin approved"
    );
    assert_eq!(
        git_stdout(&fx.repo, &["show", &format!("{trunk_after}:tally.py")]),
        "def tally():\n    return 1",
        "the agent's edit must be readable at trunk through git"
    );
}

/// REFUSES: a stage edited tracked content after the validation stamp.
///
/// This is the whole point. The refusal must name BOTH tree ids (an operator
/// cannot act on "something changed"), must leave git trunk exactly where it
/// was, and must leave the candidate's work on disk — a fence that destroyed
/// the work it refused to land would be worse than no fence.
#[test]
fn a_candidate_edited_after_the_stamp_is_refused_with_both_trees_named() {
    let fx = candidate_with_agent_edit();
    let stamped = fx.live_tree_id();

    // The post-validation mutation: an autofix, a formatter, a version stamp.
    fs::write(
        fx.candidate.join("tally.py"),
        "def tally():\n    return 2  # snuck in after validation\n",
    )
    .expect("post-stamp edit");
    let observed = fx.live_tree_id();
    assert_ne!(stamped, observed, "the edit must rotate the tree id");

    let err = fx
        .promote(&CandidateTreePin::Pinned(stamped.clone()))
        .expect_err("a candidate edited after the stamp must NOT land");
    let message = err.to_string();
    assert!(
        message.contains("candidate_tree_mismatch"),
        "the refusal must name its criterion; got: {message}"
    );
    assert!(
        message.contains(&stamped) && message.contains(&observed),
        "the refusal must name BOTH the approved tree {stamped} and the observed tree \
         {observed}; got: {message}"
    );

    assert_eq!(
        git_trunk(&fx.repo),
        fx.trunk_before,
        "git trunk must not have moved"
    );
    assert!(
        fx.candidate.join("tally.py").exists(),
        "the refusal must happen BEFORE teardown — the candidate's work has to survive it"
    );
    assert_eq!(
        fs::read_to_string(fx.candidate.join("tally.py")).expect("read candidate"),
        "def tally():\n    return 2  # snuck in after validation\n",
        "the preserved work must be the post-edit content, unmodified by the refusal"
    );
}

/// ADMITS: a GITIGNORED write after the stamp.
///
/// Load-bearing, not a nicety: gold-loop's `validate` stage writes
/// `kata-out/check.log` INTO the tree it is judging, so a fence that keyed on
/// "did any file appear" would refuse the flagship pack on every run.
#[test]
fn a_gitignored_write_after_the_stamp_still_lands() {
    let fx = candidate_with_agent_edit();
    let stamped = fx.live_tree_id();

    fs::create_dir_all(fx.candidate.join("kata-out")).expect("mkdir kata-out");
    fs::write(fx.candidate.join("kata-out/check.log"), "all green\n").expect("ignored write");
    assert_eq!(
        fx.live_tree_id(),
        stamped,
        "a gitignored write must not rotate the tree id"
    );

    fx.promote(&CandidateTreePin::Pinned(stamped))
        .expect("a gitignored write must not block the land");
    assert_ne!(
        git_trunk(&fx.repo),
        fx.trunk_before,
        "git trunk must have advanced"
    );
}

/// REFUSES WITHOUT COMPARING: a `+`-joined (conflicted) tree id on either side.
///
/// A jj conflicted tree encodes as its sides joined by `+`. String-comparing two
/// such values would let a conflicted candidate through whenever the two happen
/// to be equal — and a conflicted candidate exports `.jjconflict-*` sidecars and
/// one arbitrary side of every conflicted file to git. The refusal must fire on
/// the CONFLICT, not on a mismatch, so an operator is told the real problem.
#[test]
fn a_conflicted_tree_is_refused_without_being_compared() {
    // A `+`-joined APPROVED value is the reachable half today (a candidate
    // forked from a conflicted trunk stamps one). The observed half is covered
    // by the same loop in `crates/types/tests/candidate_tree_pin_refusals.rs`,
    // which drives the predicate directly rather than needing a jj repository
    // that can be forced into a conflicted working copy.
    for (label, pin) in [
        (
            "approved side conflicted",
            CandidateTreePin::Pinned("aaaa+bbbb".to_string()),
        ),
        (
            // A `+`-joined value that would COMPARE EQUAL to a `+`-joined
            // observed value. The fence must refuse before it can compare.
            "conflicted value that equality would admit",
            CandidateTreePin::Pinned("cccc+dddd+eeee".to_string()),
        ),
    ] {
        let fx = candidate_with_agent_edit();
        let err = fx.promote(&pin).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("candidate_tree_conflicted"),
            "{label}: the refusal must name the CONFLICT, not a mismatch; got: {message}"
        );
        assert_eq!(
            git_trunk(&fx.repo),
            fx.trunk_before,
            "{label}: git trunk must not have moved"
        );
        assert!(
            fx.candidate.join("tally.py").exists(),
            "{label}: the candidate's work must survive the refusal"
        );
    }
}

/// REFUSES: a criterion bound this candidate but recorded no tree identity.
///
/// The upgrade case (evidence stamped before the field existed) and the
/// mint-failed case. "The tree that was judged is unknown" cannot be shown equal
/// to anything, so it fails CLOSED — and says which criterion, so an operator
/// knows what to re-run.
#[test]
fn an_unstamped_criterion_refuses_and_names_itself() {
    let fx = candidate_with_agent_edit();

    let err = fx
        .promote(&CandidateTreePin::Unstamped("tests-pass".to_string()))
        .expect_err("a criterion with no tree identity must not authorize a land");
    let message = err.to_string();
    assert!(
        message.contains("candidate_tree_unstamped") && message.contains("tests-pass"),
        "the refusal must name the criterion; got: {message}"
    );
    assert_eq!(
        git_trunk(&fx.repo),
        fx.trunk_before,
        "git trunk must not have moved"
    );
    assert!(
        fx.candidate.join("tally.py").exists(),
        "the candidate's work must survive the refusal"
    );
}

/// ADMITS: an execution with no validation criteria at all.
///
/// The fence is a mechanical IDENTITY check, not the promote gate. "A promote
/// must have validation criteria" is a separate rule with its own
/// prerequisites; refusing it here would silently change what every
/// criteria-less shipped pack does.
#[test]
fn an_unpinned_promote_is_admitted() {
    let fx = candidate_with_agent_edit();
    fx.promote(&CandidateTreePin::Unpinned)
        .expect("a promote with no validation binding is the gate's question, not the fence's");
    assert_ne!(git_trunk(&fx.repo), fx.trunk_before);
}

/// The stamp value and the fence value are the SAME value: settling the
/// candidate into a commit does not rotate its tree id.
///
/// This is what makes "read it live at validation, compare it after settle at
/// promote" a valid comparison rather than a coincidence. If a settle rotated
/// the tree id, the fence would refuse every honest promote — and the fixture
/// above would not catch it, because it also settles.
#[test]
fn settling_the_candidate_does_not_rotate_its_tree_id() {
    let fx = candidate_with_agent_edit();
    let live = fx.live_tree_id();

    // A park settles the candidate through the same settle a promote runs,
    // without the fence, and publishes the settled commit on its ref.
    let parked =
        ExecutionWorkspaceProvider::park_workspace(fx.provider.as_ref(), &fx.key, Some("settle"))
            .expect("park");

    assert_eq!(
        git_stdout(
            &fx.repo,
            &["rev-parse", &format!("{}^{{tree}}", parked.commit_sha)]
        ),
        live,
        "settling must not rotate the candidate tree id: the settled commit's GIT tree must \
         be the live tree id — the jj MergedTree root id and the git tree sha are one value \
         space on a colocated repository"
    );
}

/// The jj `@` pass-through cannot be mistaken for the candidate: the fence reads
/// the SETTLED status, and an agent id derived from the key resolves the same
/// workspace the provider settles.
///
/// Guards the one substitution that would make every test above pass while the
/// fence measured the wrong thing — comparing against the base tree rather than
/// the candidate's.
#[test]
fn the_fence_compares_the_candidate_tree_not_the_base_tree() {
    let fx = candidate_with_agent_edit();
    let base_tree = git_stdout(
        &fx.repo,
        &[
            "rev-parse",
            &format!("{}^{{tree}}", fx.trunk_before.as_str()),
        ],
    );
    assert_ne!(
        fx.live_tree_id(),
        base_tree,
        "fixture precondition: the candidate must differ from the base"
    );

    let err = fx
        .promote(&CandidateTreePin::Pinned(base_tree.clone()))
        .expect_err("pinning the BASE tree must refuse a candidate that carries work");
    assert!(
        err.to_string().contains("candidate_tree_mismatch"),
        "got: {err}"
    );
    assert_eq!(git_trunk(&fx.repo), fx.trunk_before);
}
