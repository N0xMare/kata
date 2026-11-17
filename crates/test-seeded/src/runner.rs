//! Deterministic test runner helpers.
//!
//! Wraps `commonware_runtime::deterministic::Runner` in a seed-driven
//! entrypoint. Tests call
//! `run_seeded("my_test", |ctx| async move { ... })` and the helper handles
//! seed capture, logging, and repro-command printing on panic.
//!
//! `run_seeded` consumes the runner to drive a single async root future to
//! completion, then returns its output. Panics inside the body propagate out
//! after the repro banner is printed.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use commonware_runtime::Runner as _;
use commonware_runtime::Supervisor as _;
use commonware_runtime::deterministic;

/// Run an async body under `deterministic::Runner` with the given seed and
/// context label. Returns the body's output.
///
/// The label is attached to the runtime context via
/// `commonware_runtime::Supervisor::child` so that per-subsystem metrics
/// and traces carry the test name as their root scope, the same
/// `ctx.child("test_name")` pattern subsystems use further down the tree.
/// `child` takes a `&'static str`, so the label is one too.
///
/// The low-level primitive under `run_seeded`, which captures the seed from
/// `KATA_TEST_SEED` and prints a repro command on panic.
fn run_deterministic<F, Fut, O>(label: &'static str, seed: u64, f: F) -> O
where
    F: FnOnce(deterministic::Context) -> Fut,
    Fut: Future<Output = O>,
{
    let cfg = deterministic::Config::default().with_seed(seed);
    let runner = deterministic::Runner::new(cfg);

    runner.start(move |ctx| {
        // Root context label — subsystems re-label further down the tree.
        let ctx = ctx.child(label);
        f(ctx)
    })
}

/// Run an async body with a seed read from `KATA_TEST_SEED` (or a fresh
/// pseudo-random seed if unset), logging the seed to stderr and printing a
/// reproduction command on panic.
///
/// Reproduction command format:
///
/// ```text
/// KATA_TEST_SEED=<seed> cargo nextest run <name>
/// ```
///
/// The `name` parameter is used both as the context label passed to
/// `run_deterministic` and as the test name in the repro banner — keep it
/// aligned with the enclosing `#[test]` function name.
pub fn run_seeded<F, Fut, O>(name: &'static str, f: F) -> O
where
    F: FnOnce(deterministic::Context) -> Fut,
    Fut: Future<Output = O>,
{
    let seed = crate::seed::Seed::from_env()
        .unwrap_or_else(crate::seed::Seed::random)
        .0;

    eprintln!("[{name}] seed={seed}");

    // We use `catch_unwind` here so that the repro banner prints *before*
    // the panic propagates up and cargo-nextest prints its own failure
    // summary. `AssertUnwindSafe` is acceptable because the closure takes
    // ownership of everything it touches; nothing observable escapes.
    let result = catch_unwind(AssertUnwindSafe(|| run_deterministic(name, seed, f)));

    match result {
        Ok(out) => out,
        Err(panic) => {
            eprintln!();
            eprintln!("=== TEST FAILED ===");
            eprintln!("Reproduce: KATA_TEST_SEED={seed} cargo nextest run {name}");
            eprintln!("===================");
            eprintln!();
            resume_unwind(panic);
        }
    }
}
