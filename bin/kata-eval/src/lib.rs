//! kata proof harness — the golden coding-task eval tier.
//!
//! This crate is kata's benchmark harness: kata running real coding tasks is the
//! proof. It carries two tiers that share ONE cap-enforcement + report-rendering
//! core:
//!
//! * The **deterministic tier** (`just eval`, rides `just gate`) exercises the
//!   whole pipeline with a ZERO-SPEND [`MockSolver`]: it materializes each
//!   golden task's seeded fixture, applies a canned-but-valid solution for the
//!   tasks configured to solve (and leaves the rest failing), then runs the
//!   task's DETERMINISTIC validator and renders a report. No models, no cost.
//!   The regression suite proves the validators DISCRIMINATE (a wrong/absent
//!   solution FAILS) and the cap logic TRIPS on fake costs.
//!
//! * The **live tier** (`just eval-live`, cost-capped, run by hand because it spends
//!   model budget) drives the SAME golden set through a real model backend on an
//!   installed main, one task at a time, and accounts every task's METERED
//!   `cost_micro_usd` against a hard per-run cap (default $20). The cap decision
//!   and the report rendering are the same [`budget`] + [`report`] code the
//!   deterministic tier tests, so the enforcement is kata-side metering, not vibes.
//!
//! The golden tasks live under the committed `test/eval/` root (see
//! [`task::tasks_root`]). Each task is a tiny seeded repo fixture + a task
//! prompt + a deterministic pass/fail validator + a kata `workflow.star` (agent
//! stage + shell validator stage) — the eval IS kata running.
//!
//! ## Honesty rail
//!
//! A validator that PASSES on the unmodified fixture is a broken task (it would
//! score a free pass for a model that did nothing). The meta-check
//! `every_validator_fails_on_the_pristine_fixture` (in `tests/deterministic_tier.rs`,
//! through [`validator::run_validator_on_pristine_fixture`]) runs every task's
//! validator against its untouched fixture and REQUIRES a failure; it rides the
//! deterministic `just eval` tier so no free-pass task can enter the corpus.

pub mod budget;
pub mod report;
pub mod runner;
pub mod solver;
pub mod task;
pub mod validator;

pub use budget::{Budget, CapDecision, DEFAULT_CAP_MICRO_USD, micro_usd_from_usd, usd_from_micro};
pub use report::{EvalReport, ReportTotals, TaskResult};
pub use runner::{RunConfig, run_eval, write_report};
pub use solver::{MockSolver, SolveOutcome, Solver};
pub use task::{GoldenTask, MockSpec, MockStrategy, load_tasks, tasks_root};
pub use validator::{ValidatorOutcome, run_validator};
