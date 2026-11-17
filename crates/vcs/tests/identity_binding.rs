//! kata commits as the OPERATOR, refuses when the host has no answer, and
//! records WHO on the way past.
//!
//! # What each proof is about, and why there are three of them
//!
//! ONE refusal does not discharge the defect: a configured identity must show a
//! non-placeholder `%an <%ae>` on the git side, **and** a REFUSAL must fire on
//! the `forge_export` path and not at commit time alone, or the empty identity
//! still leaves the host by that route.
//!
//! So: the INHERITANCE proof lives next door in `host_binding_known_red.rs`
//! (`jj_authored_commit_carries_the_repositorys_operator_identity`), and this
//! file carries the two refusals plus the receipt.
//!
//! # How these stay HOST-INDEPENDENT
//!
//! A test that needs "this host has no git identity" cannot get there by
//! removing config: `HostBindings::without_identity` clears the repo-LOCAL layer
//! only, and it says so in its own doc — the operator's global identity is still
//! visible to a process kata spawns. Mutating the process environment would work
//! under nextest's process-per-test model and is still the wrong tool: it makes
//! the proof depend on a runner property rather than on kata.
//!
//! Instead the fixture DECLARES an identity kata itself refuses — the agent
//! sandbox identity (`kata_types::commit_identity::SANDBOX_AGENT_*`). Repo-local
//! config outranks global, so `git var` answers it on every host, and
//! `kata_vcs::identity::resolve_commit_identity` refuses it on every host. The
//! arm under test is reached by DECLARATION rather than by absence, and the
//! host-independent baseline (`GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
//! just test-crate kata-vcs` passes) stays true.

use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_test_utils::host_repo::HostBindings;
use kata_types::commit_identity::{SANDBOX_AGENT_EMAIL, SANDBOX_AGENT_NAME};
use kata_vcs::{JjBackend, VcsBackend};
use ulid::Ulid;

/// ADMISSION: a host whose identity kata will not commit under is refused at
/// `create_workspace` — before a stage is dispatched and before a token is spent.
///
/// This is the half a commit-time refusal cannot cover, and the reason it is
/// here rather than at the commit: by the time a commit exists the run has
/// already been paid for.
#[test]
fn create_workspace_refuses_a_host_identity_kata_will_not_commit_under() {
    let repo = HostBindings::new()
        .with_identity(SANDBOX_AGENT_NAME, SANDBOX_AGENT_EMAIL)
        .init_git_repo();
    // NON-VACUOUS: the repository really does declare it, so the refusal below
    // is about kata rather than about an empty fixture.
    assert_eq!(
        repo.local_config("user.email").as_deref(),
        Some(SANDBOX_AGENT_EMAIL)
    );

    let backend = JjBackend::open(repo.path()).expect("adopt the fixture repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let err = kata_vcs::test_support::create_trunk_workspace(&backend, &key)
        .expect_err("admission must refuse an identity kata itself mints");

    let message = err.to_string();
    assert!(
        message.contains("kata has no identity to commit as"),
        "admission must say WHAT it refused: {message}"
    );
    assert!(
        message.contains("AGENT SANDBOX identity"),
        "admission must say WHY: {message}"
    );
    assert!(
        message.contains("git config user.email"),
        "a refusal without a remedy is a dead end: {message}"
    );
}

/// ADMISSION is not a blanket refusal: a real operator identity admits.
///
/// The control for the test above. Without it, a `create_workspace` that refused
/// EVERYTHING would satisfy it.
#[test]
fn control_create_workspace_admits_an_operator_identity() {
    let repo = HostBindings::new()
        .with_identity("Ada Lovelace", "ada@example.invalid")
        .init_git_repo();
    let backend = JjBackend::open(repo.path()).expect("adopt the fixture repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    kata_vcs::test_support::create_trunk_workspace(&backend, &key)
        .expect("an operator identity must admit");
}

/// THE EXPORT PATH.
///
/// MEASURED: `jj git push` refuses a commit with no author (*"Won't push commit
/// … since it has no author and/or committer set"*), but that refusal lives in
/// jj-**CLI**, and `JjBackend::push_forge_branch_expecting` shells `git push` at the
/// colocated root — so it never runs, and without kata's own refusal an
/// authorless commit reaches a real remote at `GIT_PUSH_EXIT=0`.
///
/// The candidate is built through `VcsBackend` rather than through the execution
/// provider on purpose: that is the seam admission does NOT guard, so this
/// proves the export refusal stands on its own rather than inheriting
/// admission's. It also models the real hazard — a commit that already exists,
/// authored by something other than this code path.
///
/// No remote is needed: the refusal is asked BEFORE the branch is written, let
/// alone before the push, so nothing leaves the machine even when it passes.
#[test]
fn forge_export_refuses_to_push_a_commit_kata_itself_authored() {
    let repo = HostBindings::new()
        .with_identity(SANDBOX_AGENT_NAME, SANDBOX_AGENT_EMAIL)
        .init_git_repo();
    let backend = JjBackend::open(repo.path()).expect("adopt the fixture repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());

    // Build the candidate through the ENGINE trait, which admission does not
    // guard, so the commit exists carrying the identity the export must refuse.
    let agent = kata_types::AgentId(key.execution_id);
    let handle = VcsBackend::create_workspace(&backend, &agent).expect("engine workspace");
    std::fs::write(handle.workspace_path.join("agent-output.txt"), "work\n").expect("agent writes");
    VcsBackend::commit(&backend, &agent, "candidate").expect("engine commit");
    // Export the live `@` — the empty child the engine commit checked out on
    // top of "candidate", authored with the same sandbox identity — because the
    // effect fences any other commit as a divergence before it reaches the
    // identity refusal under test.
    let live_wc = ExecutionWorkspaceProvider::workspace_effect_candidate_commit(&backend, &key)
        .expect("the candidate reads")
        .expect("a live workspace's @ reads");

    let err = ExecutionWorkspaceProvider::write_workspace_effect_forge_ref(
        &backend,
        &key,
        &format!("kata/{}", key.execution_id),
        &live_wc,
        &live_wc,
        "forge-export-identity-refusal",
    )
    .expect_err("the export path must refuse this commit");

    let message = err.to_string();
    assert!(
        message.contains("forge_export: refusing to publish commit"),
        "the export refusal must name itself and the commit: {message}"
    );
    assert!(
        message.contains("Nothing was published"),
        "a SINK's refusal must say the remote was not touched: {message}"
    );
    // The push never ran: there is no `origin` on this fixture at all, so a
    // refusal that fell through to `git push` would have failed with a network
    // error naming the missing remote instead.
    assert!(
        !message.contains("git push"),
        "the refusal must fire BEFORE the push, not as its failure: {message}"
    );
}

/// THE RECEIPT: `ExecutionWorkspaceIdentity` records WHO committed, and it
/// survives a PARK, which is a publish point with its own refusal call site.
///
/// Beside `workspace_commit_sha`, `base_commit_sha`, `target_commit_sha`, refs
/// and a backend name it carries the AUTHOR, so kata can answer *who committed
/// this* from its own durable records — the first question an operator auditing
/// a landed commit asks. It is a receipt rather than a projection: the value
/// stamped here is the value the publish refusal READ on the way past.
#[test]
fn a_parked_candidates_identity_records_who_committed_it() {
    let repo = HostBindings::new()
        .with_identity("Ada Lovelace", "ada@example.invalid")
        .init_git_repo();
    let backend = JjBackend::open(repo.path()).expect("adopt the fixture repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle =
        kata_vcs::test_support::create_trunk_workspace(&backend, &key).expect("create workspace");
    std::fs::write(handle.path.join("agent-output.txt"), "work\n").expect("agent writes");

    let parked = ExecutionWorkspaceProvider::park_workspace(&backend, &key, Some("smoke"))
        .expect("park workspace");
    assert_eq!(
        parked.identity.expect("park identity").author.as_deref(),
        Some("Ada Lovelace <ada@example.invalid>"),
    );
}
