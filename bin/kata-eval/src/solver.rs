//! The solver abstraction: how a task's workspace gets "solved".
//!
//! The runner prepares a workspace (a fresh copy of the task's fixture) and asks
//! a [`Solver`] to solve it, returning a metered [`SolveOutcome`]. The validator
//! then runs against the mutated workspace.
//!
//! * [`MockSolver`] is the ZERO-SPEND stand-in for the deterministic tier: for a
//!   [`MockStrategy::Solve`] task it copies the canned `solution/` into the
//!   workspace (validator should pass); for a [`MockStrategy::Noop`] task it does
//!   nothing (validator fails honestly). It reports a configured FAKE cost so the
//!   cap logic can be exercised without spending a cent.
//!
//! The LIVE solver is not a [`Solver`] impl in this crate: `just eval-live`
//! drives each task's real `workflow.star` on an installed main (the proven
//! boot→submit→wait→show bash pattern) and reads the METERED `cost_micro_usd`
//! from the ledger. That path reuses this crate's [`crate::budget`] cap logic and
//! [`crate::report`] rendering, keeping enforcement kata-side.

use std::path::Path;

use crate::task::{GoldenTask, MockStrategy};
use crate::validator::copy_dir_recursive;

/// The metered result of solving a task.
#[derive(Debug, Clone, Default)]
pub struct SolveOutcome {
    /// Metered spend for this solve, in micro-USD.
    pub cost_micro_usd: u64,
    /// Prompt/input tokens (0 for the mock).
    pub tokens_in: u64,
    /// Completion/output tokens (0 for the mock).
    pub tokens_out: u64,
    /// Wall-clock milliseconds the solve took.
    pub wall_ms: u64,
    /// A short human note (e.g. "applied canned solution").
    pub note: String,
}

/// Something that can "solve" a task's workspace.
pub trait Solver {
    /// A stable backend label for the report (`mock`, `claude_code`, …).
    fn label(&self) -> &'static str;

    /// Mutate `workspace` (already seeded with the task's fixture) to attempt the
    /// task, returning the metered outcome.
    ///
    /// # Errors
    /// Implementation-defined (filesystem, subprocess, …).
    fn solve(&self, task: &GoldenTask, workspace: &Path) -> anyhow::Result<SolveOutcome>;
}

/// Zero-spend mock solver for the deterministic tier.
#[derive(Debug, Clone)]
pub struct MockSolver {
    /// The FAKE per-task cost this mock reports for the cap accounting.
    pub cost_per_task_micro_usd: u64,
}

impl MockSolver {
    /// A mock reporting `cost_per_task_micro_usd` for every solved task.
    #[must_use]
    pub fn new(cost_per_task_micro_usd: u64) -> Self {
        Self {
            cost_per_task_micro_usd,
        }
    }
}

impl Solver for MockSolver {
    fn label(&self) -> &'static str {
        "mock"
    }

    fn solve(&self, task: &GoldenTask, workspace: &Path) -> anyhow::Result<SolveOutcome> {
        let note = match task.mock.strategy {
            MockStrategy::Solve => {
                let solution = task.solution_dir();
                anyhow::ensure!(
                    solution.is_dir(),
                    "task {} is mock=solve but has no solution/ dir at {}",
                    task.id,
                    solution.display()
                );
                copy_dir_recursive(&solution, workspace).map_err(|e| {
                    anyhow::anyhow!("applying solution {}: {e}", solution.display())
                })?;
                "applied canned solution".to_string()
            }
            MockStrategy::Noop => "left fixture unmodified (honest fail)".to_string(),
        };
        Ok(SolveOutcome {
            cost_micro_usd: self.cost_per_task_micro_usd,
            tokens_in: 0,
            tokens_out: 0,
            wall_ms: 0,
            note,
        })
    }
}
