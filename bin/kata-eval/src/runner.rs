//! The eval runner: golden set × solver → report, under a hard cap.
//!
//! This is the shared, fully-tested pipeline the ZERO-SPEND deterministic tier
//! exercises with a [`MockSolver`]. For each task, in order: enforce the cap
//! guard, materialize a fresh workspace from the fixture, ask the solver to
//! solve it, charge the metered cost, run the deterministic validator, and
//! record the line. The run aborts cleanly the moment the cap guard would be
//! crossed — no task starts that could push cumulative spend past the cap.

use std::path::Path;
use std::time::Instant;

use crate::budget::{Budget, CapDecision};
use crate::report::{EvalReport, TaskResult};
use crate::solver::Solver;
use crate::task::GoldenTask;
use crate::validator::{copy_dir_recursive, run_validator, tool_available};

/// Runner configuration.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Hard run cap, micro-USD.
    pub cap_micro_usd: u64,
    /// Model id recorded in the report.
    pub model: String,
    /// Backend label recorded in the report (usually the solver's label).
    pub backend: String,
    /// Report date (`YYYY-MM-DD`).
    pub date: String,
}

/// Drive the golden `tasks` through `solver` under `cfg`, returning the report.
///
/// # Errors
/// Returns an error only on an unrecoverable setup failure (temp workspace or
/// fixture copy). A solver or validator failure is recorded as a task result,
/// not an error — a failing eval is still a valid report.
pub fn run_eval(
    tasks: &[GoldenTask],
    solver: &dyn Solver,
    cfg: &RunConfig,
) -> anyhow::Result<EvalReport> {
    let mut budget = Budget::new(cfg.cap_micro_usd);
    let mut results: Vec<TaskResult> = Vec::new();
    let mut aborted = false;
    let mut abort_reason: Option<String> = None;

    for task in tasks {
        // A task whose `required_tool` is absent is skipped cleanly rather than
        // left for the validator to fail-to-run and be miscounted.
        if !tool_available(&task.required_tool) {
            results.push(skipped_result(
                task,
                format!("required tool `{}` not on PATH", task.required_tool),
            ));
            continue;
        }

        if let CapDecision::Abort { reason } = budget.can_afford(task.max_cost_micro_usd) {
            aborted = true;
            abort_reason = Some(reason);
            break;
        }

        let workspace = tempfile::tempdir()
            .map_err(|e| anyhow::anyhow!("creating workspace for {}: {e}", task.id))?;
        copy_dir_recursive(&task.fixture_dir(), workspace.path())
            .map_err(|e| anyhow::anyhow!("seeding fixture for {}: {e}", task.id))?;

        let start = Instant::now();
        let solve = solver.solve(task, workspace.path())?;
        let measured_wall = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let wall_ms = if solve.wall_ms > 0 {
            solve.wall_ms
        } else {
            measured_wall
        };

        budget.charge(solve.cost_micro_usd);

        let validation = run_validator(&task.validator_path(), workspace.path())?;

        results.push(TaskResult {
            id: task.id.clone(),
            title: task.title.clone(),
            passed: validation.passed,
            skipped: false,
            validator_exit_code: validation.exit_code,
            wall_ms,
            tokens_in: solve.tokens_in,
            tokens_out: solve.tokens_out,
            cost_micro_usd: solve.cost_micro_usd,
            note: solve.note,
            detail: validation.output,
        });

        if let CapDecision::Abort { reason } = budget.over_cap() {
            aborted = true;
            abort_reason = Some(reason);
            break;
        }
    }

    Ok(EvalReport::new(
        cfg.date.clone(),
        cfg.model.clone(),
        cfg.backend.clone(),
        cfg.cap_micro_usd,
        tasks.len(),
        results,
        aborted,
        abort_reason,
    ))
}

fn skipped_result(task: &GoldenTask, note: String) -> TaskResult {
    TaskResult {
        id: task.id.clone(),
        title: task.title.clone(),
        passed: false,
        skipped: true,
        validator_exit_code: 0,
        wall_ms: 0,
        tokens_in: 0,
        tokens_out: 0,
        cost_micro_usd: 0,
        note,
        detail: String::new(),
    }
}

/// Write a report to `out_dir` as `<date>-<model>.md` and `<date>-<model>.json`,
/// returning the two written paths. The model id is slugified for the filename.
///
/// # Errors
/// Propagates directory-create, serialization, and write failures.
pub fn write_report(
    report: &EvalReport,
    out_dir: &Path,
) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| anyhow::anyhow!("creating report dir {}: {e}", out_dir.display()))?;
    let slug = slugify(&report.model);
    let md_path = out_dir.join(format!("{}-{}.md", report.date, slug));
    let json_path = out_dir.join(format!("{}-{}.json", report.date, slug));
    std::fs::write(&md_path, report.to_markdown())
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", md_path.display()))?;
    std::fs::write(&json_path, report.to_json()?)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", json_path.display()))?;
    Ok((md_path, json_path))
}

/// Lowercase, replacing any non-alphanumeric run with a single `-`.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}
