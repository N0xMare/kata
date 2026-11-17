//! The eval report — the publishable numbers table.
//!
//! Two committed renderings share one struct: a machine-readable JSON
//! (`target/eval/reports/<date>-<model>.json`) and a human Markdown table
//! (`target/eval/reports/<date>-<model>.md`). Per task: pass/fail, wall time, tokens,
//! metered cost; plus run totals and the cap outcome.

use serde::{Deserialize, Serialize};

use crate::budget::usd_from_micro;

/// Schema version of the emitted JSON report (bump on a breaking shape change).
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// One task's line in the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    /// Task id.
    pub id: String,
    /// One-line title.
    pub title: String,
    /// True when the task's validator passed.
    pub passed: bool,
    /// True when the task was skipped (e.g. required tool absent). A skipped
    /// task counts toward neither pass nor fail.
    pub skipped: bool,
    /// Validator process exit code (`0` on pass).
    pub validator_exit_code: i32,
    /// Wall-clock milliseconds for the solve step.
    pub wall_ms: u64,
    /// Prompt/input tokens.
    pub tokens_in: u64,
    /// Completion/output tokens.
    pub tokens_out: u64,
    /// Metered cost for this task, micro-USD.
    pub cost_micro_usd: u64,
    /// Short solver note.
    pub note: String,
    /// Truncated validator output (failure tail).
    pub detail: String,
}

/// Run-level totals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportTotals {
    /// Tasks in the golden set.
    pub tasks_total: usize,
    /// Tasks actually run (not skipped, not cut off by the cap abort).
    pub tasks_run: usize,
    /// Tasks whose validator passed.
    pub tasks_passed: usize,
    /// Tasks whose validator failed.
    pub tasks_failed: usize,
    /// Tasks skipped.
    pub tasks_skipped: usize,
    /// Sum of metered cost, micro-USD.
    pub total_cost_micro_usd: u64,
    /// Sum of solve wall time, ms.
    pub total_wall_ms: u64,
    /// Sum of input tokens.
    pub total_tokens_in: u64,
    /// Sum of output tokens.
    pub total_tokens_out: u64,
}

/// A complete eval report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    /// JSON schema version.
    pub schema_version: u32,
    /// Discriminator for evidence tooling.
    pub kind: &'static str,
    /// ISO date the run started (`YYYY-MM-DD`).
    pub date: String,
    /// Model identifier driving the solve stage (`mock` for the deterministic
    /// tier).
    pub model: String,
    /// Backend label (`mock` for the deterministic tier, `live` by default).
    pub backend: String,
    /// The hard run cap, micro-USD.
    pub cap_micro_usd: u64,
    /// Cumulative metered spend, micro-USD.
    pub spent_micro_usd: u64,
    /// True when the run aborted before completing every task (cap guard tripped
    /// or a task errored fatally).
    pub aborted: bool,
    /// Human reason the run aborted, if it did.
    pub abort_reason: Option<String>,
    /// Per-task results, in run order.
    pub results: Vec<TaskResult>,
    /// Run totals.
    pub totals: ReportTotals,
}

impl EvalReport {
    /// Assemble a report from its parts, computing totals.
    #[must_use]
    pub fn new(
        date: String,
        model: String,
        backend: String,
        cap_micro_usd: u64,
        tasks_total: usize,
        results: Vec<TaskResult>,
        aborted: bool,
        abort_reason: Option<String>,
    ) -> Self {
        let mut totals = ReportTotals {
            tasks_total,
            ..ReportTotals::default()
        };
        for r in &results {
            if r.skipped {
                totals.tasks_skipped += 1;
                continue;
            }
            totals.tasks_run += 1;
            if r.passed {
                totals.tasks_passed += 1;
            } else {
                totals.tasks_failed += 1;
            }
            totals.total_cost_micro_usd =
                totals.total_cost_micro_usd.saturating_add(r.cost_micro_usd);
            totals.total_wall_ms = totals.total_wall_ms.saturating_add(r.wall_ms);
            totals.total_tokens_in = totals.total_tokens_in.saturating_add(r.tokens_in);
            totals.total_tokens_out = totals.total_tokens_out.saturating_add(r.tokens_out);
        }
        let spent_micro_usd = totals.total_cost_micro_usd;
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            kind: "kata_eval_report",
            date,
            model,
            backend,
            cap_micro_usd,
            spent_micro_usd,
            aborted,
            abort_reason,
            results,
            totals,
        }
    }

    /// Pretty JSON rendering.
    ///
    /// # Errors
    /// Propagates serialization failure (not expected for this plain struct).
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Human Markdown rendering — the publishable numbers table.
    // `wall_ms as f64` is a display-only precision loss (milliseconds → seconds
    // to two decimals); exact integer fidelity is not needed for a report line.
    #[allow(clippy::cast_precision_loss)]
    #[must_use]
    pub fn to_markdown(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::new();
        let _ = writeln!(out, "# kata eval report — {}\n", self.date);
        let _ = writeln!(out, "- **Model:** `{}`", self.model);
        let _ = writeln!(out, "- **Backend:** `{}`", self.backend);
        let _ = writeln!(
            out,
            "- **Run cap:** {} ({} µUSD)",
            usd_from_micro(self.cap_micro_usd),
            self.cap_micro_usd
        );
        let _ = writeln!(
            out,
            "- **Metered spend:** {} ({} µUSD)",
            usd_from_micro(self.spent_micro_usd),
            self.spent_micro_usd
        );
        let t = &self.totals;
        let _ = writeln!(
            out,
            "- **Score:** {}/{} passed ({} run, {} skipped)",
            t.tasks_passed, t.tasks_total, t.tasks_run, t.tasks_skipped
        );
        if self.aborted {
            let _ = writeln!(
                out,
                "- **ABORTED:** {}",
                self.abort_reason.as_deref().unwrap_or("cap guard tripped")
            );
        }
        out.push('\n');

        out.push_str("| Task | Result | Wall (s) | Tokens (in/out) | Cost | Note |\n");
        out.push_str("|---|---|---:|---:|---:|---|\n");
        for r in &self.results {
            let result = if r.skipped {
                "skipped"
            } else if r.passed {
                "PASS"
            } else {
                "FAIL"
            };
            let _ = writeln!(
                out,
                "| `{}` | {} | {:.2} | {}/{} | {} | {} |",
                r.id,
                result,
                r.wall_ms as f64 / 1000.0,
                r.tokens_in,
                r.tokens_out,
                usd_from_micro(r.cost_micro_usd),
                r.note.replace('|', "\\|"),
            );
        }
        out.push('\n');
        let _ = writeln!(
            out,
            "**Totals:** {} passed / {} failed / {} skipped of {} tasks · {} · {:.2}s wall · {}/{} tokens",
            t.tasks_passed,
            t.tasks_failed,
            t.tasks_skipped,
            t.tasks_total,
            usd_from_micro(t.total_cost_micro_usd),
            t.total_wall_ms as f64 / 1000.0,
            t.total_tokens_in,
            t.total_tokens_out,
        );
        out
    }
}
