//! `kata usage` — a normalized provider spend report.
//!
//! SPEND, for every backend: aggregate kata-side metered cost from the node's
//! own ledger/execution records — per backend and per model: run count, tokens
//! in/out, and `cost_micro_usd` totals over a `--since` window (default 7d).
//! This is kata's own truth, fed by the metering that lands per-stage
//! `token_usage.cost_micro_usd` in each completed assignment's output. The grand
//! total is the sum of each execution's OWN accepted cost
//! (`running_cost_micro_usd` less the `Invoke` child spend it carries, since the
//! child is listed too); per-backend rows attribute what the execution's
//! invocation graph lets us join, and any remainder (failed / still-running
//! executions whose per-stage outputs aren't surfaced) is shown as an explicit
//! `(unattributed)` figure so the report never under- or over-states total spend.
//!
//! The report reads kata's ledger and nothing else: it runs no vendor CLI and
//! reads no vendor's login or rate-limit answer. kata keeps no per-vendor usage
//! integration, so a provider's plan or remaining quota is the vendor's own
//! tool's to report.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use kata_client::ExecutionRecord;
use kata_types::time::now_ms;
use serde::Serialize;

use super::{block_on, client, operator_client_error};
use crate::cli::output::{self, OutputFormat};

/// Dispatch `kata usage`.
pub(crate) fn run_usage_cmd(api_url: &str, since_arg: &str, format: OutputFormat) -> Result<()> {
    let now_ms = now_ms();
    let (since_ms, since_label) = parse_since(since_arg, now_ms)?;

    let records = block_on(async move {
        client(api_url)?
            .list()
            .await
            .map_err(|e| operator_client_error(api_url, e, "kata usage"))
    })?;

    let report = build_report(&records, since_ms, since_label, now_ms);

    match format {
        OutputFormat::Json => {
            // `--format json`: the usage report, bare. It is no operation's
            // response (`observe` returns an `ObserveResponse`), so it carries
            // no `op` tag.
            output::emit_record(&report)?;
        }
        OutputFormat::Human => print!("{}", render_human(&report)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SPEND aggregation (pure — golden-tested over seeded records)
// ---------------------------------------------------------------------------

/// The normalized usage report emitted by `kata usage`.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct UsageReport {
    summary_kind: &'static str,
    /// Window start as epoch-ms; `0` means "all time" (`--since all`).
    since_ms: u64,
    /// The literal `--since` label echoed back (`7d`, `24h`, `all`, …).
    since_label: String,
    /// When this report was generated (epoch-ms).
    generated_at_ms: u64,
    /// Number of in-window executions folded into the spend figures.
    execution_count: usize,
    /// Authoritative total spend across the window: each in-window execution's
    /// OWN accepted cost (`ExecutionRecord::own_cost_micro_usd` — its running cost
    /// less what it carries for `Invoke` children, which are records of the same
    /// list), so every accepted cost is counted once. Micro-USD; divide by
    /// 1_000_000 for USD.
    total_cost_micro_usd: u64,
    /// Portion of `total_cost_micro_usd` attributed to a concrete backend row.
    attributed_cost_micro_usd: u64,
    /// `total - attributed`: spend from executions whose per-stage outputs
    /// aren't surfaced (failed / still-running) — shown so totals stay honest.
    unattributed_cost_micro_usd: u64,
    /// Per-backend / per-model spend, backend then model sorted.
    backends: Vec<BackendSpend>,
}

/// One backend's spend, broken down per model.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct BackendSpend {
    backend: String,
    run_count: u64,
    tokens_in: u64,
    tokens_out: u64,
    cache_read: u64,
    cache_write: u64,
    cost_micro_usd: u64,
    models: Vec<ModelSpend>,
}

/// One (backend, model) spend row.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct ModelSpend {
    /// `None` when the stage carried no `model_hint` (backend default).
    model: Option<String>,
    run_count: u64,
    tokens_in: u64,
    tokens_out: u64,
    cache_read: u64,
    cache_write: u64,
    cost_micro_usd: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Acc {
    run_count: u64,
    tokens_in: u64,
    tokens_out: u64,
    cache_read: u64,
    cache_write: u64,
    cost_micro_usd: u64,
}

impl Acc {
    fn add(&mut self, other: &Acc) {
        self.run_count += other.run_count;
        self.tokens_in += other.tokens_in;
        self.tokens_out += other.tokens_out;
        self.cache_read += other.cache_read;
        self.cache_write += other.cache_write;
        self.cost_micro_usd += other.cost_micro_usd;
    }
}

/// Fold the node's execution records into a normalized spend report.
///
/// Pure over its inputs — the golden regression seeds `records` directly.
fn build_report(
    records: &[ExecutionRecord],
    since_ms: u64,
    since_label: String,
    now_ms: u64,
) -> UsageReport {
    // backend -> model -> accumulator.
    let mut per: BTreeMap<String, BTreeMap<Option<String>, Acc>> = BTreeMap::new();
    let mut total_cost: u64 = 0;
    let mut attributed: u64 = 0;
    let mut execution_count: usize = 0;

    for rec in records {
        if rec.submitted_at_ms < since_ms {
            continue;
        }
        execution_count += 1;
        // OWN cost, not running cost: an `Invoke` parent's running cost carries its
        // child's spend, and the child is a record of this list too.
        total_cost += rec.own_cost_micro_usd();

        // stage_name -> (backend label, model hint), from the invocation graph.
        // The stage output JSON carries token_usage but NOT which backend/model
        // produced it; the graph is the only join key we have.
        let mut stage_meta: BTreeMap<&str, (Option<String>, Option<String>)> = BTreeMap::new();
        if let Some(graph) = &rec.agent_invocation_graph {
            for node in &graph.nodes {
                stage_meta
                    .entry(node.stage_name.as_str())
                    .or_insert_with(|| {
                        (
                            node.agent_label.as_ref().map(ToString::to_string),
                            node.model_hint.as_ref().map(ToString::to_string),
                        )
                    });
            }
        }

        let Some(outputs) = &rec.outputs else {
            continue;
        };
        for (stage, out) in outputs {
            let Some(tu) = out.get("token_usage") else {
                continue;
            };
            let cost = json_u64(tu, "cost_micro_usd");
            let one = Acc {
                run_count: 1,
                tokens_in: json_u64(tu, "input"),
                tokens_out: json_u64(tu, "output"),
                cache_read: json_u64(tu, "cache_read"),
                cache_write: json_u64(tu, "cache_write"),
                cost_micro_usd: cost,
            };
            let (backend, model) = stage_meta
                .get(stage.as_str())
                .cloned()
                .unwrap_or((None, None));
            let backend = backend.unwrap_or_else(|| "unknown".to_string());
            per.entry(backend)
                .or_default()
                .entry(model)
                .or_default()
                .add(&one);
            attributed += cost;
        }
    }

    let backends = per
        .into_iter()
        .map(|(backend, models)| {
            let mut total = Acc::default();
            let model_rows: Vec<ModelSpend> = models
                .into_iter()
                .map(|(model, acc)| {
                    total.add(&acc);
                    ModelSpend {
                        model,
                        run_count: acc.run_count,
                        tokens_in: acc.tokens_in,
                        tokens_out: acc.tokens_out,
                        cache_read: acc.cache_read,
                        cache_write: acc.cache_write,
                        cost_micro_usd: acc.cost_micro_usd,
                    }
                })
                .collect();
            BackendSpend {
                backend,
                run_count: total.run_count,
                tokens_in: total.tokens_in,
                tokens_out: total.tokens_out,
                cache_read: total.cache_read,
                cache_write: total.cache_write,
                cost_micro_usd: total.cost_micro_usd,
                models: model_rows,
            }
        })
        .collect();

    UsageReport {
        summary_kind: "usage_report",
        since_ms,
        since_label,
        generated_at_ms: now_ms,
        execution_count,
        total_cost_micro_usd: total_cost,
        attributed_cost_micro_usd: attributed,
        unattributed_cost_micro_usd: total_cost.saturating_sub(attributed),
        backends,
    }
}

fn json_u64(value: &serde_json::Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// `--since` window parsing
// ---------------------------------------------------------------------------

/// Parse a `--since` argument into `(window_start_epoch_ms, echoed_label)`.
///
/// Accepts `all` / `0` (no window → `0`) or a suffixed duration (`Nd` / `Nh`
/// / `Nm` / `Ns`). Returns a usage error for anything else.
fn parse_since(arg: &str, now_ms: u64) -> Result<(u64, String)> {
    let trimmed = arg.trim();
    if trimmed.eq_ignore_ascii_case("all") || trimmed == "0" {
        return Ok((0, trimmed.to_string()));
    }
    let dur = parse_duration(trimmed)?;
    let window_ms = u64::try_from(dur.as_millis()).unwrap_or(u64::MAX);
    Ok((now_ms.saturating_sub(window_ms), trimmed.to_string()))
}

fn parse_duration(arg: &str) -> Result<Duration> {
    let (num, unit) = arg.split_at(
        arg.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| bad_since(arg))?,
    );
    let n: u64 = num.parse().map_err(|_| bad_since(arg))?;
    // `checked_mul` so an absurd N (e.g. `999999999999999d`) is a clean usage
    // error rather than a debug-build panic / release wraparound to a bogus
    // (tiny) window that would silently mis-scope the report.
    let secs = match unit {
        "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3_600),
        "d" => n.checked_mul(86_400),
        "w" => n.checked_mul(604_800),
        _ => return Err(bad_since(arg)),
    }
    .ok_or_else(|| bad_since(arg))?;
    Ok(Duration::from_secs(secs))
}

fn bad_since(arg: &str) -> anyhow::Error {
    // Usage-class error → exit 2 via the op-contract mapping.
    kata_op_contract::OpError::usage(format!(
        "invalid --since '{arg}': expected `all` or a duration like `7d`, `24h`, `30m`, `90s`"
    ))
    .into()
}

// ---------------------------------------------------------------------------
// Human rendering
// ---------------------------------------------------------------------------

/// Render micro-USD as `$D.DDDD` (4 decimal places) using integer math — no
/// float cast, deterministic half-up rounding at the 0.0001-USD (100-micro)
/// place.
fn micro_to_usd(micro: u64) -> String {
    // Round to the nearest 100 micro (= 0.0001 USD), then split into whole
    // dollars and the four-decimal fraction.
    let ten_thousandths = (micro + 50) / 100;
    format!(
        "${}.{:04}",
        ten_thousandths / 10_000,
        ten_thousandths % 10_000
    )
}

fn render_human(report: &UsageReport) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let window = if report.since_ms == 0 {
        "all time".to_string()
    } else {
        format!("last {}", report.since_label)
    };
    let _ = writeln!(s, "kata usage — spend ({window})");
    let _ = writeln!(s);

    if report.execution_count == 0 {
        let _ = writeln!(s, "  no metered runs in this window.");
    } else {
        let _ = writeln!(
            s,
            "  {:<16} {:<26} {:>6} {:>11} {:>11} {:>10}",
            "BACKEND", "MODEL", "RUNS", "TOK_IN", "TOK_OUT", "COST"
        );
        for backend in &report.backends {
            for model in &backend.models {
                let _ = writeln!(
                    s,
                    "  {:<16} {:<26} {:>6} {:>11} {:>11} {:>10}",
                    backend.backend,
                    model.model.as_deref().unwrap_or("(default)"),
                    model.run_count,
                    model.tokens_in,
                    model.tokens_out,
                    micro_to_usd(model.cost_micro_usd),
                );
            }
        }
        if report.unattributed_cost_micro_usd > 0 {
            let _ = writeln!(
                s,
                "  {:<16} {:<26} {:>6} {:>11} {:>11} {:>10}",
                "(unattributed)",
                "—",
                "—",
                "—",
                "—",
                micro_to_usd(report.unattributed_cost_micro_usd),
            );
        }
        let _ = writeln!(
            s,
            "  {:<16} {:<26} {:>6} {:>11} {:>11} {:>10}",
            "TOTAL",
            format!("{} execution(s)", report.execution_count),
            "",
            "",
            "",
            micro_to_usd(report.total_cost_micro_usd),
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(json: serde_json::Value) -> ExecutionRecord {
        serde_json::from_value(json).expect("valid ExecutionRecord fixture")
    }

    /// A completed execution with two agent stages on two backends/models.
    fn seeded_two_backend_records() -> Vec<ExecutionRecord> {
        const EXEC: &str = "01HQFRY1NN4ET5NH70AW3BE216";
        const N1: &str = "01HXYCXQTC6MZGRMBD6PXN66HW";
        const N2: &str = "01HTAJ2PNNGHS1NE16S0S629WF";
        vec![record(json!({
            "id": EXEC,
            "workflow_name": "demo",
            "status": "completed",
            "submitted_at_ms": 10_000u64,
            "started_at_ms": 10_100u64,
            "finished_at_ms": 20_000u64,
            "worker_id": "w1",
            "outputs": {
                "plan": {
                    "content": "…",
                    "token_usage": {
                        "input": 1000, "output": 200,
                        "cache_read": 50, "cache_write": 10,
                        "cost_micro_usd": 69646
                    }
                },
                "build": {
                    "content": "…",
                    "token_usage": {
                        "input": 8637, "output": 9,
                        "cost_micro_usd": 10844
                    }
                }
            },
            "error": null,
            "running_cost_micro_usd": 80490u64,
            "agent_invocation_graph": {
                "execution_id": EXEC,
                "nodes": [
                    {
                        "id": N1, "assignment_id": N1, "execution_id": EXEC,
                        "stage_name": "plan", "kind": "worker", "role": "worker",
                        "agent_label": "claude_code", "model_hint": "claude-sonnet-4-5",
                        "status": "completed", "created_at_ms": 10_100u64
                    },
                    {
                        "id": N2, "assignment_id": N2, "execution_id": EXEC,
                        "stage_name": "build", "kind": "worker", "role": "worker",
                        "agent_label": "opencode", "model_hint": "xai/grok-4.20-0309-non-reasoning",
                        "status": "completed", "created_at_ms": 10_200u64
                    }
                ],
                "roots": [N1],
                "orphaned": []
            }
        }))]
    }

    #[test]
    fn golden_two_backend_spend_aggregation() {
        let records = seeded_two_backend_records();
        let report = build_report(&records, 0, "all".to_string(), 99_999);

        assert_eq!(report.execution_count, 1);
        assert_eq!(report.total_cost_micro_usd, 80_490);
        assert_eq!(report.attributed_cost_micro_usd, 80_490);
        assert_eq!(report.unattributed_cost_micro_usd, 0);
        assert_eq!(report.backends.len(), 2, "≥2 backends rendered");

        let claude = &report.backends[0];
        assert_eq!(claude.backend, "claude_code");
        assert_eq!(claude.run_count, 1);
        assert_eq!(claude.tokens_in, 1000);
        assert_eq!(claude.tokens_out, 200);
        assert_eq!(claude.cache_read, 50);
        assert_eq!(claude.cost_micro_usd, 69_646);
        assert_eq!(claude.models[0].model.as_deref(), Some("claude-sonnet-4-5"));

        let opencode = &report.backends[1];
        assert_eq!(opencode.backend, "opencode");
        assert_eq!(opencode.cost_micro_usd, 10_844);
        assert_eq!(opencode.tokens_in, 8637);
    }

    /// An `Invoke` child's spend is counted ONCE. The parent's record
    /// carries the child's 1234 in `running_cost_micro_usd` (its per-execution view:
    /// the child's spend is what the parent spent) and names it in
    /// `child_cost_micro_usd`; the child's own record carries the same 1234 as the
    /// stage it accepted. The shapes are the executor's own
    /// (`an_invoke_parent_running_cost_carries_its_childs_metered_cost` reads them
    /// off a real parent/child pair against raw SQL).
    ///
    /// **Watched red:** summing `running_cost_micro_usd` reported 2468 for one stage
    /// billed 1234, with 1234 of it "unattributed".
    #[test]
    fn an_invoke_childs_spend_is_counted_once_across_parent_and_child() {
        const PARENT: &str = "01HQFRY1NN4ET5NH70AW3BE217";
        const CHILD: &str = "01HQFRY1NN4ET5NH70AW3BE218";
        let records = vec![
            record(json!({
                "id": PARENT,
                "workflow_name": "parent",
                "status": "completed",
                "submitted_at_ms": 10_000u64,
                "started_at_ms": 10_100u64,
                "finished_at_ms": 20_000u64,
                "worker_id": "pending",
                "outputs": {
                    "run_child": {
                        "child_execution_id": CHILD,
                        "child_invocation_summary": {
                            "token_usage": {"cost_micro_usd": 1234}
                        }
                    }
                },
                "error": null,
                "running_cost_micro_usd": 1234u64,
                "child_cost_micro_usd": 1234u64,
            })),
            record(json!({
                "id": CHILD,
                "workflow_name": "child",
                "status": "completed",
                "submitted_at_ms": 10_200u64,
                "started_at_ms": 10_300u64,
                "finished_at_ms": 19_000u64,
                "worker_id": "w1",
                "outputs": {
                    "leaf": {"token_usage": {"input": 10, "output": 2, "cost_micro_usd": 1234}}
                },
                "error": null,
                "running_cost_micro_usd": 1234u64,
            })),
        ];
        let report = build_report(&records, 0, "all".to_string(), 99_999);
        assert_eq!(report.execution_count, 2);
        assert_eq!(
            report.total_cost_micro_usd, 1234,
            "one stage billed 1234 across a parent and its Invoke child"
        );
        assert_eq!(report.attributed_cost_micro_usd, 1234);
        assert_eq!(report.unattributed_cost_micro_usd, 0);
    }

    #[test]
    fn since_window_excludes_older_executions() {
        let records = seeded_two_backend_records(); // submitted_at_ms = 10_000
        // Window start after the execution → excluded.
        let report = build_report(&records, 50_000, "1h".to_string(), 99_999);
        assert_eq!(report.execution_count, 0);
        assert_eq!(report.total_cost_micro_usd, 0);
        assert!(report.backends.is_empty());
    }

    #[test]
    fn failed_execution_cost_is_unattributed_not_lost() {
        // A failed execution: running_cost set, but `outputs` is None (the
        // aggregator only surfaces outputs for completed executions). Total
        // must still reflect the spend, as an explicit unattributed remainder.
        let records = vec![record(json!({
            "id": "01HMZC9S93BWP8H85CXFRJJNWB",
            "workflow_name": "demo",
            "status": "failed",
            "submitted_at_ms": 10_000u64,
            "started_at_ms": 10_100u64,
            "finished_at_ms": 20_000u64,
            "worker_id": "w1",
            "outputs": null,
            "error": "stage build failed",
            "running_cost_micro_usd": 4242u64
        }))];
        let report = build_report(&records, 0, "all".to_string(), 99_999);
        assert_eq!(report.execution_count, 1);
        assert_eq!(report.total_cost_micro_usd, 4242);
        assert_eq!(report.attributed_cost_micro_usd, 0);
        assert_eq!(report.unattributed_cost_micro_usd, 4242);
        assert!(report.backends.is_empty());
    }

    #[test]
    fn no_data_renders_gracefully() {
        let report = build_report(&[], 0, "all".to_string(), 99_999);
        let text = render_human(&report);
        assert!(text.contains("no metered runs"), "text: {text}");
    }

    #[test]
    fn human_render_shows_backends_and_total() {
        let report = build_report(&seeded_two_backend_records(), 0, "all".to_string(), 99_999);
        let text = render_human(&report);
        assert!(text.contains("claude_code"));
        assert!(text.contains("opencode"));
        assert!(text.contains("TOTAL"));
        assert!(text.contains("$0.0805"), "total USD rendered; text: {text}");
    }

    #[test]
    fn parse_since_variants() {
        let now = 1_000_000_000;
        assert_eq!(parse_since("all", now).unwrap(), (0, "all".to_string()));
        assert_eq!(parse_since("0", now).unwrap(), (0, "0".to_string()));
        let (start, label) = parse_since("7d", now).unwrap();
        assert_eq!(label, "7d");
        assert_eq!(start, now - 7 * 86_400 * 1000);
        let (start, _) = parse_since("30m", now).unwrap();
        assert_eq!(start, now - 30 * 60 * 1000);
        let (start, _) = parse_since("2h", now).unwrap();
        assert_eq!(start, now - 2 * 3600 * 1000);
        assert!(parse_since("banana", now).is_err());
        assert!(parse_since("7x", now).is_err());
        assert!(parse_since("d", now).is_err());
    }

    #[test]
    fn parse_since_absurd_value_is_usage_error_not_overflow() {
        // Regression: `n * 86_400` overflowed u64 (debug panic / release
        // wraparound to a tiny window). Must be a clean usage error instead.
        let now = 1_000_000_000;
        assert!(parse_since("999999999999999d", now).is_err());
        assert!(parse_since("18446744073709551615w", now).is_err());
        assert!(parse_since("99999999999999999999d", now).is_err()); // > u64 even before mul
    }

    #[test]
    fn report_serializes_with_expected_shape() {
        let report = build_report(&seeded_two_backend_records(), 0, "all".to_string(), 1);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["summary_kind"], "usage_report");
        assert_eq!(value["total_cost_micro_usd"], 80_490);
        assert_eq!(value["backends"][0]["backend"], "claude_code");
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "attributed_cost_micro_usd",
                "backends",
                "execution_count",
                "generated_at_ms",
                "since_label",
                "since_ms",
                "summary_kind",
                "total_cost_micro_usd",
                "unattributed_cost_micro_usd",
            ],
            "the report is spend only: no vendor limits section"
        );
    }
}
