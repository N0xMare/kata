//! `kata-program` — kata's authoring toolchain.
//!
//! A workflow written in Starlark compiles here into the content-hashed checked
//! program kata admits and runs: the native Starlark DSL and its evaluation, the
//! loader and the workflow library, the parser and its validation, the checked
//! execution program and its lowering, the program hash, static analysis
//! (preflight, policy, the template and capsule-rule checks), the schema
//! catalog, the schedule a pack declares, the review-loop helpers, and the
//! fixture harness behind `kata workflows test`. Programmatic API-owned
//! requests use the `Api` source format and enter through dedicated checked-IR
//! compilers rather than a second workflow language.
//!
//! It depends on `kata-types` alone: nothing here reaches a store, a transport,
//! a VCS backend or a worker. `kata-workflow` is the runtime that executes what
//! this crate checks.

// The crate is `unsafe`-free except for the `dsl` module, where starlark's
// `#[derive(ProvidesStaticType)]` expands to an `unsafe impl` for the
// contract-DSL custom value types. That single module opts in via a
// `#![allow(unsafe_code)]`; the rest of the crate stays `forbid`-equivalent
// through this crate-level `deny`, matching the per-module opt-in pattern
// used by `bin/kata`.
#![deny(unsafe_code)]

/// The capsule rules the CHECK and capsule assembly share — a stage's class, the
/// budget defaults a capsule records, an agent block's credential, and a
/// capsule's network — so the prediction and the mint cannot drift.
pub mod capsule_rules;
pub mod dag;
mod dsl;
/// Machine-readable catalog of the native Starlark workflow DSL surface:
/// every registered builtin's signature plus the contract/verdict
/// grammar, reflected from the typed builtin families so an author can target a
/// schema instead of reverse-engineering the DSL from examples.
pub use dsl::catalog as dsl_catalog;
pub mod execution_program;
pub mod invocation_plan;
pub mod library;
pub mod loops;
pub mod orchestrator;
mod parser;
pub mod policy;
pub mod preflight;
/// The schedule a pack declares — `schedule(..)` lowers to a validated
/// [`schedule::ScheduleSpec`], its cron or interval trigger checked at authoring
/// time.
pub mod schedule;
mod shell_position;
mod starlark_eval;
pub mod target_namespace;
pub mod template;
/// A fixture-driven behavioral test harness — feed a workflow recorded
/// stage outputs and assert its routing (branch / loop / skip) + rendered
/// prompts deterministically, with no live models. Also the deterministic eval
/// substrate the golden fixture corpus reuses.
pub mod test_harness;

/// `"a", "b", "c"`: a closed set's labels as a refusal names them, read off the
/// authority that parses them so the message cannot drift from the set.
pub(crate) fn quoted_labels<'a>(labels: impl IntoIterator<Item = &'a str>) -> String {
    labels
        .into_iter()
        .map(|label| format!("{label:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}
