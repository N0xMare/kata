//! `kata-eval` — the proof-harness CLI.
//!
//! Subcommands:
//!
//! * `cap-check`  — pure cap decision used by the `just eval-live` bash runner
//!   before each live task: exit 0 to proceed, exit 3 to abort. Enforcement is
//!   the SAME [`kata_eval::Budget`] the deterministic tier tests.
//! * `report`     — render a committed Markdown+JSON report from a results JSON
//!   array (the live bash runner assembles per-task rows from the metered
//!   ledger via `kata run show` / `run output`).
//! * `task-list`  — emit the golden set as JSON for the live bash loop.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};

use kata_eval::budget::{Budget, CapDecision, micro_usd_from_usd};
use kata_eval::report::EvalReport;
use kata_eval::runner::write_report;
use kata_eval::task::load_tasks;

#[derive(Debug, Parser)]
#[command(
    name = "kata-eval",
    about = "kata proof-harness: golden coding-task eval tier"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Cap decision for the live bash runner: exit 0 (proceed) or 3 (abort).
    CapCheck {
        /// Run cap in USD.
        #[arg(long, default_value_t = 20.0)]
        cap_usd: f64,
        /// Cumulative metered spend so far, micro-USD.
        #[arg(long, default_value_t = 0)]
        spent_micro: u64,
        /// The next task's declared upper-bound cost, micro-USD.
        #[arg(long)]
        task_cap_micro: u64,
    },
    /// Render a committed report from a results JSON array.
    Report {
        /// Path to a JSON array of task results.
        #[arg(long)]
        results_json: PathBuf,
        /// Model id.
        #[arg(long)]
        model: String,
        /// Backend label.
        #[arg(long, default_value = "live")]
        backend: String,
        /// Run cap in USD.
        #[arg(long, default_value_t = 20.0)]
        cap_usd: f64,
        /// Total golden-task count (defaults to the number of result rows).
        #[arg(long)]
        tasks_total: Option<usize>,
        /// Mark the run as aborted (cap guard tripped).
        #[arg(long)]
        aborted: bool,
        /// Human abort reason.
        #[arg(long)]
        abort_reason: Option<String>,
        /// Directory to write the report into.
        #[arg(long)]
        out: PathBuf,
    },
    /// Emit the golden set as a JSON array (for the live bash loop).
    TaskList {
        /// Golden-tasks root (`test/eval/tasks`).
        #[arg(long)]
        tasks_dir: PathBuf,
    },
}

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::CapCheck {
            cap_usd,
            spent_micro,
            task_cap_micro,
        } => cap_check(cap_usd, spent_micro, task_cap_micro),
        Cmd::Report {
            results_json,
            model,
            backend,
            cap_usd,
            tasks_total,
            aborted,
            abort_reason,
            out,
        } => report(
            &results_json,
            &model,
            &backend,
            cap_usd,
            tasks_total,
            aborted,
            abort_reason,
            &out,
        ),
        Cmd::TaskList { tasks_dir } => task_list(&tasks_dir),
    }
}

// Returns `Result<()>` for uniform dispatch with the other subcommand handlers,
// even though the abort arm diverges via `process::exit`.
#[allow(clippy::unnecessary_wraps)]
fn cap_check(cap_usd: f64, spent_micro: u64, task_cap_micro: u64) -> anyhow::Result<()> {
    let budget = Budget::with_spent(micro_usd_from_usd(cap_usd), spent_micro);
    match budget.can_afford(task_cap_micro) {
        CapDecision::Proceed => {
            println!("proceed");
            Ok(())
        }
        CapDecision::Abort { reason } => {
            eprintln!("abort: {reason}");
            std::process::exit(3);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn report(
    results_json: &std::path::Path,
    model: &str,
    backend: &str,
    cap_usd: f64,
    tasks_total: Option<usize>,
    aborted: bool,
    abort_reason: Option<String>,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(results_json)
        .with_context(|| format!("reading {}", results_json.display()))?;
    let results: Vec<kata_eval::report::TaskResult> = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", results_json.display()))?;
    let total = tasks_total.unwrap_or(results.len());
    let report = EvalReport::new(
        today(),
        model.to_string(),
        backend.to_string(),
        micro_usd_from_usd(cap_usd),
        total,
        results,
        aborted,
        abort_reason,
    );
    let (md, json) = write_report(&report, out)?;
    print!("{}", report.to_markdown());
    eprintln!("wrote {} and {}", md.display(), json.display());
    Ok(())
}

fn task_list(tasks_dir: &std::path::Path) -> anyhow::Result<()> {
    let tasks = load_tasks(tasks_dir)?;
    let rows: Vec<serde_json::Value> = tasks
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "title": t.title,
                "required_tool": t.required_tool,
                "max_cost_micro_usd": t.max_cost_micro_usd,
                "prompt": t.prompt,
                "dir": t.dir,
                "workflow": t.workflow_path(),
                "validate": t.validator_path(),
                "fixture": t.fixture_dir(),
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&rows)?);
    Ok(())
}
