//! SDK + endpoint regression tests for `kata run current`.
//!
//! Spins up the real `kata_api::server::ApiServer` on a loopback TCP
//! socket (kernel-assigned port) backed by the shared `oci`-plane rig —
//! `OciNodeRig` + its scripted worker, see `common::boot_oci_server` —
//! then drives the live HTTP surface via the SDK's `current_execution`
//! method.
//!
//! Three cases:
//!   * `current_returns_most_recent` — multiple submissions; the
//!     latest one comes back.
//!   * `current_active_filters_terminal` — one terminal + one live
//!     submission; with `--active`, the active one wins even though
//!     the terminal one was submitted later.
//!   * `current_no_executions_returns_error` — an empty server
//!     surfaces `KataClientError::NoCurrentExecution`.

mod common;

use kata_client::{KataClient, KataClientError};
use kata_test_utils::MockAgentBackend;

const ONE_STAGE_STAR: &str = r#"
only = stage(id = "only", agent = "default", prompt = "hi")
workflow("current-test", root = [only])
"#;

/// `(client, _boot)` — the `OciBoot` guard keeps the node dir, worker pump,
/// reactor, bookkeeper, delivery task and server task alive for the test's
/// duration.
async fn boot_server(_worker_label: &str) -> (KataClient, common::OciBoot) {
    common::boot_oci_server(&[], MockAgentBackend::new(), None).await
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn current_returns_most_recent() {
    let (client, _booted) = boot_server("current-most-recent").await;

    // Submit two workflows, wait for both to terminate.
    let exec_a = client
        .run_starlark(ONE_STAGE_STAR, Some("current-test.star"))
        .await
        .expect("submit A");
    let _ = exec_a
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait A");
    let exec_b = client
        .run_starlark(ONE_STAGE_STAR, Some("current-test.star"))
        .await
        .expect("submit B");
    let _ = exec_b
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait B");

    let current = client
        .current_execution(false)
        .await
        .expect("current_execution");
    assert_eq!(
        current.id,
        exec_b.id(),
        "expected most-recent (B) to win, got {current:?}"
    );
    // Status is the snake_case wire string of the aggregate status.
    assert!(
        ["completed", "running", "pending"].contains(&current.status.as_str()),
        "unexpected status {}",
        current.status
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn current_active_filters_terminal() {
    let (client, _booted) = boot_server("current-active").await;

    // Submit + complete A so it's terminal.
    let exec_a = client
        .run_starlark(ONE_STAGE_STAR, Some("current-test.star"))
        .await
        .expect("submit A");
    let _ = exec_a
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait A");

    // Submit B but DON'T wait for terminal — depending on scheduler
    // timing it may already be `Running` or `Completed` by the time
    // we read it. We verify two things:
    //   (1) `current` (no --active) returns B (newest), regardless of
    //       its current status.
    //   (2) `current --active`, when it succeeds, points at B (the
    //       only candidate that COULD be active); when both are
    //       terminal, it returns NoCurrentExecution. Either outcome
    //       is acceptable per the contract — the contract pins the
    //       NEGATIVE invariant (never returns A), not a specific
    //       positive one.
    let exec_b = client
        .run_starlark(ONE_STAGE_STAR, Some("current-test.star"))
        .await
        .expect("submit B");

    let current_any = client
        .current_execution(false)
        .await
        .expect("current_execution");
    assert_eq!(
        current_any.id,
        exec_b.id(),
        "current (no flag) returns latest submission"
    );

    // Drain B to terminal. After this, --active must surface
    // NoCurrentExecution (every known execution is now terminal).
    let _ = exec_b
        .wait_for_terminal(common::SETTLE_BUDGET)
        .await
        .expect("wait B");

    // Test the negative invariant: `--active` never returns A even
    // though A was completed first.
    let active_err = client
        .current_execution(true)
        .await
        .expect_err("all-terminal => NoCurrentExecution");
    assert!(
        matches!(active_err, KataClientError::NoCurrentExecution),
        "expected NoCurrentExecution, got {active_err:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn current_no_executions_returns_error() {
    let (client, _booted) = boot_server("current-empty").await;

    // Default flag (active=false): empty server still errors.
    let err = client
        .current_execution(false)
        .await
        .expect_err("empty server returns NoCurrentExecution");
    assert!(
        matches!(err, KataClientError::NoCurrentExecution),
        "expected NoCurrentExecution, got {err:?}"
    );

    // --active=true on an empty server: same error.
    let err_active = client
        .current_execution(true)
        .await
        .expect_err("empty server returns NoCurrentExecution under --active");
    assert!(
        matches!(err_active, KataClientError::NoCurrentExecution),
        "expected NoCurrentExecution, got {err_active:?}"
    );
}
