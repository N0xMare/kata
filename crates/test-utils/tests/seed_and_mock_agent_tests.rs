//! Unit tests for `kata-test-utils` and `kata-test-seeded`.
//!
//! These exercise the pieces that *don't* need `kata-core`: this crate's mock
//! agent queue semantics and fixture builders, and `kata-test-seeded`'s seed
//! capture (a dev-dependency here, so its own crate carries no test binary).
//!
//! The deterministic runner helpers are exercised by
//! `seed_env_roundtrip_and_run_seeded_wiring`, which drives a trivial body
//! through `run_seeded` and asserts its output.

use std::env;

use kata_test_seeded::{Seed, run_seeded};
use kata_test_utils::{MockAgentBackend, MockResponse, fixtures};

// ─── Seed tests ────────────────────────────────────────────────────────

#[test]
fn seed_random_produces_distinct_values() {
    // Two back-to-back calls should return different values. This is a
    // loose but effective check that `Seed::random` isn't returning a
    // constant.
    let a = Seed::random();
    let b = Seed::random();
    assert_ne!(a, b, "Seed::random returned two equal values in a row");
}

// `Seed::from_env` / `run_seeded` and the unset-variant test both touch
// process-global env state, so they're combined into one sequential test
// to avoid racing with each other (or with any parallel test-binary that
// nextest might spawn). Running them in one `#[test]` also lets us assert
// the ordering of state transitions explicitly.
//
// NOTE: `std::env::set_var` / `remove_var` became `unsafe` in Rust 2024.
// We localize the `unsafe` blocks to a single helper scope.
#[test]
#[allow(unsafe_code)]
fn seed_env_roundtrip_and_run_seeded_wiring() {
    let prior = env::var("KATA_TEST_SEED").ok();

    // 1. When unset, Seed::from_env returns None.
    // SAFETY: This test does not spawn other threads; we mutate env
    // state in a single-threaded context and restore it at the end.
    unsafe { env::remove_var("KATA_TEST_SEED") };
    assert!(Seed::from_env().is_none());

    // 2. When set to a parseable u64, Seed::from_env returns Some with
    //    that value.
    unsafe { env::set_var("KATA_TEST_SEED", "424242") };
    let captured = Seed::from_env().expect("env var set above");
    assert_eq!(captured.0, 424_242);

    // 3. `run_seeded` drives a trivial async body to completion and
    //    returns its output. The seed is logged to stderr as a side
    //    effect; we don't assert on that here.
    let out: u32 = run_seeded("kata_test_utils_smoke", |_ctx| async move { 7 });
    assert_eq!(out, 7);

    // 4. Garbage values parse to None.
    unsafe { env::set_var("KATA_TEST_SEED", "not-a-number") };
    assert!(Seed::from_env().is_none());

    // Restore prior env state.
    match prior {
        Some(v) => unsafe { env::set_var("KATA_TEST_SEED", v) },
        None => unsafe { env::remove_var("KATA_TEST_SEED") },
    }
}

// ─── MockAgentBackend tests ────────────────────────────────────────────

#[test]
fn mock_agent_pop_returns_fifo_then_default() {
    let mock = MockAgentBackend::with_responses(vec![
        MockResponse::Text("first".into()),
        MockResponse::Text("second".into()),
    ]);

    match mock.pop() {
        MockResponse::Text(s) => assert_eq!(s, "first"),
        other => panic!("expected first text response, got {other:?}"),
    }
    match mock.pop() {
        MockResponse::Text(s) => assert_eq!(s, "second"),
        other => panic!("expected second text response, got {other:?}"),
    }
    // Queue is now empty — next pop falls back to `Default`.
    match mock.pop() {
        MockResponse::Default => {}
        other => panic!("expected Default fallback, got {other:?}"),
    }
}

#[test]
fn mock_agent_push_appends_to_tail() {
    let mock = MockAgentBackend::new();
    assert!(mock.is_empty());
    assert_eq!(mock.len(), 0);

    mock.push(MockResponse::Text("a".into()));
    mock.push(MockResponse::Json(serde_json::json!({"k": "v"})));

    assert_eq!(mock.len(), 2);
    assert!(!mock.is_empty());

    // Pop both and confirm order.
    match mock.pop() {
        MockResponse::Text(s) => assert_eq!(s, "a"),
        other => panic!("expected 'a', got {other:?}"),
    }
    match mock.pop() {
        MockResponse::Json(v) => assert_eq!(v, serde_json::json!({"k": "v"})),
        other => panic!("expected json response, got {other:?}"),
    }
    assert!(mock.is_empty());
}

// ─── Fixture stability tests ───────────────────────────────────────────

#[test]
fn tempdir_helper_creates_a_real_directory() {
    let td = fixtures::tempdir();
    assert!(td.path().exists());
    assert!(td.path().is_dir());
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "seed_and_mock_agent_tests/workflow_helpers_tests.rs"]
mod workflow_helpers_tests;
