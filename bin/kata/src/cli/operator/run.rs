//! `kata run <workflow>` submission, the `kata run <op>` switchboard,
//! and `kata steer` external-input commands.

use std::path::{Path, PathBuf};
use std::time::Duration;

use std::fmt::Write as _;

use anyhow::{Context, Result, bail};
use kata_client::operator_projection::{
    external_input_rows, filter_external_input_rows, filter_human_request_rows, human_request_rows,
};
use kata_client::types::{ExecutionExternalInputAppendRequest, ExecutionHumanRequestAnswerRequest};
use kata_client::{Execution, ExecutionRecord, KataClient};
use kata_op_contract::OpError;
use serde::Serialize;

use crate::cli::output::OutputFormat;
use crate::cli::{RunCmd, SteerCmd, looks_like_path};

use super::fmt::{format_cost_micro_usd, format_duration_ms, format_ms_utc};
use super::watch::watch_execution;
use super::{block_on, client, emit, emit_list, exit_for_terminal_status, serde_json_label};

/// Parse `--param name=value` entries + an optional `--params-file` JSON
/// object into the invocation-param map the operator submit sends.
///
/// Each `--param` value is split on the FIRST `=`; the value is parsed as JSON
/// when it parses (`3`, `true`, `"x"`, `[1,2]`), otherwise taken as a bare
/// string. `--params-file` is a JSON object merged UNDER `--param` (an explicit
/// `--param` overrides the same key from the file). The workflow's declared
/// `workflow(params=..)` contract does the real typing at admission; this only
/// assembles the `{name: value}` object.
pub(crate) fn parse_cli_params(
    param: &[String],
    params_file: Option<&Path>,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let mut map = serde_json::Map::new();
    if let Some(path) = params_file {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading --params-file {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("--params-file {} is not valid JSON", path.display()))?;
        let obj = value.as_object().ok_or_else(|| {
            anyhow::anyhow!(
                "--params-file {} must be a JSON object of {{name: value}}",
                path.display()
            )
        })?;
        for (k, v) in obj {
            map.insert(k.clone(), v.clone());
        }
    }
    for entry in param {
        let (name, raw) = entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--param must be NAME=VALUE; got {entry:?}"))?;
        // Parse the value as JSON when it parses, else treat it as a bare string.
        let value = serde_json::from_str::<serde_json::Value>(raw)
            .unwrap_or_else(|_| serde_json::Value::String(raw.to_owned()));
        map.insert(name.to_owned(), value);
    }
    Ok(map)
}

/// Submit `kata run <workflow> --submit|--watch|--wait` through the API node.
pub(crate) fn run_workflow_cmd(
    api_url: &str,
    workflow: String,
    params: serde_json::Map<String, serde_json::Value>,
    target: Option<kata_types::target::TargetSpec>,
    watch: bool,
    wait: bool,
    include_outputs: bool,
    timeout_secs: u64,
    poll_ms: u64,
) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        submit_and_observe_workflow(
            &client,
            &workflow,
            &[],
            &params,
            target.as_ref(),
            watch,
            wait,
            include_outputs,
            timeout_secs,
            poll_ms,
        )
        .await
    })
}
/// Dispatch `kata run <operator-subcommand>`.
pub(crate) fn run_run_cmd(api_url: &str, cmd: RunCmd, format: OutputFormat) -> Result<()> {
    // Validate the discharge arguments before anything touches the network.
    // Built here rather than inside the match arm because `client(api_url)` runs
    // first inside the async block and FAILS on an undiscoverable installed main.
    // `--operator` / `--assertion` are clap-required so their ABSENCE is caught
    // before this, but a blank or whitespace-only value is not, and an operator
    // who passed `--operator ""` must not be told the node is unreachable.
    let discharge_stop_arguments = match &cmd {
        RunCmd::DischargeStop {
            execution_id,
            attempt_id,
            lease_epoch,
            operator,
            assertion,
        } => Some(discharge_stop_op_arguments(
            execution_id,
            attempt_id,
            *lease_epoch,
            operator,
            assertion,
        )?),
        _ => None,
    };
    block_on(async move {
        let client = client(api_url)?;
        match cmd {
            RunCmd::List {
                limit,
                status,
                json,
            } => {
                let records = client.list_filtered(limit, status.as_deref()).await?;
                // The default is a terse one-row-per-execution table.
                // The full verbose records (one JSON object per line) are
                // behind `--json` and the global `--format json`. The
                // selection is a pure, unit-tested helper so the dispatch branch
                // cannot silently invert (terse leaking to `--json`, or a JSON
                // request falling through to the table).
                if run_list_emits_full_records(json, format) {
                    emit_list(records)
                } else {
                    print!("{}", render_run_list_table(&records)?);
                    Ok(())
                }
            }
            RunCmd::Show { execution_id } => emit(&client.observe(&execution_id).await?),
            RunCmd::Output {
                execution_id,
                stage,
            } => {
                if let Some(stage) = stage {
                    emit(&client.get_stage_output(&execution_id, &stage).await?)
                } else {
                    let record = client.observe(&execution_id).await?;
                    emit(&ExecutionOutputs {
                        execution_id,
                        outputs: record.outputs,
                    })
                }
            }
            RunCmd::Current { active } => emit(&client.current_execution(active).await?),
            RunCmd::Wait {
                execution_id,
                timeout_secs,
                poll_ms,
            } => {
                let exec = Execution::from_id(client, execution_id);
                let record = exec
                    .wait_for_terminal_with(
                        Duration::from_secs(timeout_secs),
                        Duration::from_millis(poll_ms),
                    )
                    .await?;
                emit(&record)?;
                exit_for_terminal_status(&record)
            }
            RunCmd::Approve {
                execution_id,
                assignment_id,
            } => {
                client.approve(&execution_id, &assignment_id).await?;
                emit(&ActionAck {
                    ok: true,
                    action: "approve",
                })
            }
            RunCmd::Reject {
                execution_id,
                assignment_id,
                reason,
            } => {
                client
                    .reject(&execution_id, &assignment_id, &reason)
                    .await?;
                emit(&ActionAck {
                    ok: true,
                    action: "reject",
                })
            }
            RunCmd::Cancel {
                execution_id,
                reason,
            } => {
                let reason = reason.unwrap_or_else(|| "operator-initiated cancel".to_string());
                let outcome = client.cancel(&execution_id, &reason).await?;
                emit(&CancelAck {
                    ok: true,
                    action: "cancel",
                    assignments_asked_to_stop: outcome.assignments_asked_to_stop,
                    main_side_settled: outcome.main_side_settled,
                    child_executions_cancelled: outcome.child_executions_cancelled,
                })
            }
            RunCmd::Promote { execution_id } => {
                client.promote(&execution_id).await?;
                emit(&ActionAck {
                    ok: true,
                    action: "promote",
                })
            }
            RunCmd::ForgeReconcile { execution_id } => {
                let exports = client.forge_reconcile(&execution_id).await?;
                emit(&ForgeReconcileReport {
                    execution_id,
                    exports,
                })
            }
            RunCmd::Park {
                execution_id,
                ref_name,
            } => {
                let parked = client.park(&execution_id, ref_name.as_deref()).await?;
                emit(&parked)
            }
            // Rides the unified `POST /ops/{operation}` route rather than a
            // bespoke REST path, so this CLI arm and a direct REST caller reach
            // ONE dispatch. MCP is not a reader: `Operation::DischargeStop` is
            // `ApiScope::Approve` — it clears a safety latch on the caller's own
            // word, with no probe to check it against — and the `kata mcp`
            // surface is OPERATE-only, so it is neither advertised nor callable
            // there.
            //
            // A success envelope is emitted verbatim: `data.discharged == false` means
            // an identical assertion had already been recorded, which is an honest
            // answer rather than a failure, and `data.outstanding_stops_remaining` is
            // the number the operator actually came for. A refusal (`ok: false`, which
            // the route answers with a 200) is returned as the contract's error, so the
            // process exits with its code (`exit_code_for_error`), never 0.
            RunCmd::DischargeStop { .. } => {
                let arguments = discharge_stop_arguments
                    .expect("the DischargeStop arm's arguments are built before the client");
                let answer = client.invoke_op("discharge_stop", &arguments).await?;
                if let Some(refusal) = discharge_stop_refusal(&answer)? {
                    return Err(kata_client::KataClientError::OperationRefused {
                        operation: kata_op_contract::Operation::DischargeStop,
                        error: refusal,
                    }
                    .into());
                }
                emit(&answer)
            }
        }
    })
}

/// The contract error a `discharge_stop` answer carries, when it is a refusal.
///
/// The route answers `ok: false` with a `200`, so the transport reports success; an
/// answer that is neither exactly a success nor exactly a refusal is malformed.
fn discharge_stop_refusal(answer: &serde_json::Value) -> Result<Option<OpError>> {
    match (answer.get("ok"), answer.get("error")) {
        (Some(serde_json::Value::Bool(true)), None) => Ok(None),
        (Some(serde_json::Value::Bool(false)), Some(error)) => Ok(Some(
            serde_json::from_value(error.clone())
                .context("the discharge_stop refusal carries no contract error")?,
        )),
        _ => bail!("the discharge_stop answer is neither a success nor a refusal"),
    }
}

/// What `kata run forge-reconcile` prints: each pending export as the reconcile
/// left it.
#[derive(Serialize)]
struct ForgeReconcileReport {
    execution_id: String,
    exports: Vec<kata_client::ReconciledForgeExport>,
}

/// Build the `discharge_stop` operation's request JSON, refusing an assertion
/// nobody can be held to.
///
/// Clap makes both fields mandatory, so this catches the shapes clap cannot: a
/// blank or whitespace-only value, and a negative lease epoch. The server-side
/// binding and `StopDischarge::from_provenance` each refuse the same thing
/// independently — this is a better message delivered sooner, not the guard.
pub(super) fn discharge_stop_op_arguments(
    execution_id: &str,
    attempt_id: &str,
    lease_epoch: i64,
    operator: &str,
    assertion: &str,
) -> Result<serde_json::Value> {
    let operator = operator.trim();
    let assertion = assertion.trim();
    if operator.is_empty() {
        anyhow::bail!(
            "`kata run discharge-stop` requires a non-empty `--operator <who>`: the discharge is \
             admissible ONLY because it is attributed. Without a name the durable record cannot \
             distinguish your judgement from the worker's own acknowledgement, which is the whole \
             reason discharging is allowed for a stop no worker will answer."
        );
    }
    if assertion.is_empty() {
        anyhow::bail!(
            "`kata run discharge-stop` requires a non-empty `--assertion <what you established>`: \
             a durable record saying only that an operator did this tells the next reader nothing \
             about what was checked, and this stop was refusing a destructive workspace reclaim."
        );
    }
    if lease_epoch < 0 {
        anyhow::bail!(
            "`--lease-epoch` must be non-negative; copy it from the `lease_epoch` field of the \
             `evidence.worker_stops` row you are discharging."
        );
    }
    Ok(serde_json::json!({
        "execution_id": execution_id.trim(),
        "attempt_id": attempt_id.trim(),
        "lease_epoch": lease_epoch,
        "operator": operator,
        "assertion": assertion,
    }))
}

/// Dispatch `kata steer ...`.
pub(crate) fn run_steer_cmd(api_url: &str, cmd: SteerCmd) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        match cmd {
            SteerCmd::HumanRequests {
                execution_id,
                status,
                answered,
                unanswered,
            } => emit_list(filter_human_request_rows(
                human_request_rows(client.list().await?),
                execution_id.as_deref(),
                status.as_deref(),
                answered,
                unanswered,
            )),
            SteerCmd::AnswerHumanRequest {
                execution_id,
                request_id,
                answer_summary,
                steering_id,
            } => {
                let body = ExecutionHumanRequestAnswerRequest {
                    request_id,
                    answer_summary,
                    answered_by_steering_id: steering_id,
                };
                emit(&client.answer_human_request(execution_id, &body).await?)
            }
            SteerCmd::ExternalInputs {
                execution_id,
                channel,
            } => emit_list(filter_external_input_rows(
                external_input_rows(client.list().await?),
                execution_id.as_deref(),
                channel.as_deref(),
            )),
            SteerCmd::AppendExternalInput {
                execution_id,
                channel,
                text,
                input_id,
                source,
                target_stage,
                payload_json,
            } => {
                let payload = payload_json
                    .as_deref()
                    .map(|raw| {
                        serde_json::from_str::<serde_json::Value>(raw)
                            .with_context(|| format!("parsing --payload-json `{raw}`"))
                    })
                    .transpose()?;
                let body = ExecutionExternalInputAppendRequest {
                    channel,
                    text,
                    input_id,
                    source,
                    target_stage,
                    payload,
                };
                emit(&client.append_external_input(execution_id, &body).await?)
            }
        }
    })
}
async fn submit_workflow_with_initial_inputs(
    client: &KataClient,
    target: &str,
    initial_inputs: &[ExecutionExternalInputAppendRequest],
    params: &serde_json::Map<String, serde_json::Value>,
    run_target: Option<&kata_types::target::TargetSpec>,
) -> Result<Execution> {
    let run_target = run_target.map(ToString::to_string);
    match submit_target(target)? {
        SubmitTarget::LibraryRef(name) => Ok(client
            .run_with_params(&name, initial_inputs, params, run_target.as_deref())
            .await?),
        SubmitTarget::StarlarkPath(path) => {
            let text = read_workflow_starlark(&path)?;
            let filename = path.to_string_lossy();
            Ok(client
                .run_starlark_with_params(
                    &text,
                    Some(&filename),
                    initial_inputs,
                    params,
                    run_target.as_deref(),
                )
                .await?)
        }
    }
}
pub(super) async fn submit_and_observe_workflow(
    client: &KataClient,
    workflow: &str,
    initial_inputs: &[ExecutionExternalInputAppendRequest],
    params: &serde_json::Map<String, serde_json::Value>,
    run_target: Option<&kata_types::target::TargetSpec>,
    watch: bool,
    wait: bool,
    include_outputs: bool,
    timeout_secs: u64,
    poll_ms: u64,
) -> Result<()> {
    if include_outputs && !watch {
        bail!("--include-outputs is only supported with --watch");
    }

    let submitted =
        submit_workflow_with_initial_inputs(client, workflow, initial_inputs, params, run_target)
            .await?;
    notice_uncommitted_edits(client, submitted.id()).await;
    if watch {
        emit(&SubmitSummary {
            id: submitted.id().to_string(),
            status: "pending",
        })?;
        // `None`, not `Duration::from_secs(timeout_secs)`: `--timeout-secs`
        // documents itself as "Maximum seconds for `--wait`" and defaults to
        // 60, so feeding it to the streaming face would silently cut every
        // `--watch` of a workflow longer than a minute — a regression dressed
        // as a bound. `kata watch --timeout-secs` is the bounded streaming face
        // for scripts; the transport-level bounds apply to both regardless.
        return watch_execution(client, submitted.id(), include_outputs, None).await;
    }
    if wait {
        let record = submitted
            .wait_for_terminal_with(
                Duration::from_secs(timeout_secs),
                Duration::from_millis(poll_ms),
            )
            .await?;
        emit(&record)?;
        return exit_for_terminal_status(&record);
    }
    emit(&SubmitSummary {
        id: submitted.id().to_string(),
        status: "pending",
    })
}
/// The one notice a submission over a dirty checkout owes: an isolated run forks
/// the COMMITTED target its admission froze, so uncommitted edits are
/// structurally not part of it. Printed to stderr — never refused, never on
/// stdout — when the current directory's git checkout has uncommitted TRACKED
/// changes ([`dirty_checkout`]) and the submitted execution froze a target.
/// Best effort: a failed read prints nothing.
async fn notice_uncommitted_edits(client: &KataClient, id: &str) {
    let Some(checkout) = std::env::current_dir()
        .ok()
        .and_then(|dir| dirty_checkout(&dir))
    else {
        return;
    };
    if let Ok(record) = client.observe(id).await
        && let Some(target) = record.target
    {
        eprintln!("{}", uncommitted_edits_notice(&checkout, &target));
    }
}

/// The notice text for `checkout` under the frozen `target`.
pub(super) fn uncommitted_edits_notice(
    checkout: &Path,
    target: &kata_types::target::ExecutionTarget,
) -> String {
    format!(
        "notice: uncommitted edits in {} are not part of this run; it forks the committed {}",
        checkout.display(),
        target.summary()
    )
}

/// The top level of the git checkout containing `dir` when that checkout has
/// uncommitted TRACKED changes — `git status --porcelain --untracked-files=no`
/// answers non-empty, git's own judgement read through the host's git — and
/// `None` when it is clean, when `dir` is in no checkout, or when git cannot
/// answer. Read with `--no-optional-locks`: a notice never writes the checkout's
/// index (a `git status` that may take `index.lock` writes back a racy index it
/// refreshed, beside the operator's own git). The checkout's configuration is
/// the operator's answer and is inherited, save its `core.fsmonitor` command: a
/// hook `git status` would run (measured, git 2.56), switched off.
pub(super) fn dirty_checkout(dir: &Path) -> Option<PathBuf> {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("--no-optional-locks")
            .args(["-c", "core.fsmonitor=false"])
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    let changed = git(&["status", "--porcelain", "--untracked-files=no"])?;
    if changed.is_empty() {
        return None;
    }
    git(&["rev-parse", "--show-toplevel"]).map(PathBuf::from)
}

/// Classify a workflow argument: a `.star` file, or a library ref.
///
/// Shared by `kata run <target> --submit|--watch|--wait`, `kata factory run
/// <target>` and the attached `kata mcp`'s `check`/`run` tools, so a workflow
/// argument is one thing on every face that takes it. A file that is not `.star`
/// is refused `usage`, in wording that names no one operation, and the refusal
/// names only the recourse that exists — renaming it — because a workflow runs
/// only on a running main; an argument spelled as a path that names no file is
/// `not_found`, the class `kata check` gives it. An existing file in the working
/// directory is the file, never a library name it shadows.
pub(crate) fn submit_target(target: &str) -> Result<SubmitTarget, OpError> {
    let candidate = Path::new(target);
    if candidate.is_file() {
        let extension = candidate
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase);
        if extension.as_deref() == Some("star") {
            return Ok(SubmitTarget::StarlarkPath(candidate.to_path_buf()));
        }
        return Err(OpError::usage(format!(
            "workflow {} names a file that is not Starlark (`.star`): a workflow argument \
             is a library name or a `.star` path. Rename it to `.star` if it is Starlark.",
            candidate.display()
        )));
    }

    if looks_like_path(target) {
        return Err(OpError::not_found(format!(
            "workflow path {} could not be read as a file",
            candidate.display()
        )));
    }

    Ok(SubmitTarget::LibraryRef(target.to_string()))
}
#[derive(Debug, Serialize)]
struct SubmitSummary {
    id: String,
    status: &'static str,
}
#[derive(Debug)]
pub(crate) enum SubmitTarget {
    LibraryRef(String),
    StarlarkPath(PathBuf),
}
pub(crate) fn read_workflow_starlark(path: &Path) -> Result<String, OpError> {
    std::fs::read_to_string(path).map_err(|error| {
        OpError::usage(format!(
            "reading workflow Starlark from {}: {error}",
            path.display()
        ))
    })
}
#[derive(Debug, Serialize)]
struct ExecutionOutputs {
    execution_id: String,
    outputs: Option<std::collections::BTreeMap<String, serde_json::Value>>,
}

/// `kata run list` output selection. The per-command `--json` and the
/// global `--format json` BOTH select the full verbose NDJSON records; only
/// the bare command renders the terse table.
///
/// Note the deliberate divergence from other `--format json` sites: run list
/// emits raw NDJSON here rather than one JSON document, because its
/// consumers (`json_lines` in the product smokes, `just api-executions`) parse
/// that stream.
pub(super) fn run_list_emits_full_records(json: bool, format: OutputFormat) -> bool {
    json || format.is_json()
}

/// The terse `kata run list` table: one row per execution with the
/// operator-relevant columns (id, name, status, submitted, duration, cost),
/// newest submission first. Pure over the record slice so the shape is
/// golden-testable. The full verbose records are behind `--json`.
pub(super) fn render_run_list_table(records: &[ExecutionRecord]) -> Result<String> {
    let mut rows: Vec<RunListRow> = records
        .iter()
        .map(RunListRow::from_record)
        .collect::<Result<_>>()?;
    // Newest first (by submission), with a stable id tiebreak for equal
    // timestamps so the table order is deterministic for the golden test.
    rows.sort_by(|a, b| {
        b.submitted_at_ms
            .cmp(&a.submitted_at_ms)
            .then_with(|| b.id.cmp(&a.id))
    });

    let mut out = String::new();
    if rows.is_empty() {
        let _ = writeln!(out, "no executions");
        return Ok(out);
    }

    const HEADERS: [&str; 6] = ["ID", "NAME", "STATUS", "SUBMITTED", "DURATION", "COST"];
    let mut widths: [usize; 6] = HEADERS.map(str::len);
    for row in &rows {
        for (i, cell) in row.cells().into_iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    write_run_list_row(&mut out, &HEADERS, &widths);
    for row in &rows {
        write_run_list_row(&mut out, &row.cells(), &widths);
    }
    Ok(out)
}

struct RunListRow {
    id: String,
    name: String,
    status: String,
    submitted: String,
    submitted_at_ms: u64,
    duration: String,
    cost: String,
}

impl RunListRow {
    fn from_record(record: &ExecutionRecord) -> Result<Self> {
        let duration = match (record.started_at_ms, record.finished_at_ms) {
            (Some(start), Some(finish)) => format_duration_ms(finish.saturating_sub(start)),
            _ => "-".to_string(),
        };
        Ok(Self {
            id: record.id.clone(),
            name: record.workflow_name.clone(),
            status: serde_json_label(&record.status)?,
            submitted: format_ms_utc(record.submitted_at_ms),
            submitted_at_ms: record.submitted_at_ms,
            duration,
            cost: format_cost_micro_usd(record.running_cost_micro_usd),
        })
    }

    fn cells(&self) -> [&str; 6] {
        [
            &self.id,
            &self.name,
            &self.status,
            &self.submitted,
            &self.duration,
            &self.cost,
        ]
    }
}

fn write_run_list_row(out: &mut String, cells: &[&str; 6], widths: &[usize; 6]) {
    // Two-space column gutter; the last column is not padded (no trailing
    // whitespace on the line).
    for (i, cell) in cells.iter().enumerate() {
        if i + 1 == cells.len() {
            let _ = write!(out, "{cell}");
        } else {
            let _ = write!(out, "{cell:<width$}  ", width = widths[i]);
        }
    }
    out.push('\n');
}
#[derive(Debug, Serialize)]
struct ActionAck {
    ok: bool,
    action: &'static str,
}
/// What `kata run cancel` reports.
///
/// `assignments_asked_to_stop` is a count of ASKS and its name says so: the
/// number an operator sees is how many stop frames a transport accepted, and
/// nothing about whether any work ended (a name like `assignments_terminated`
/// would misreport it). `kata run show <id>` carries the answer to that, as
/// `evidence.worker_stops[].awaiting_worker_acknowledgement`.
///
/// **There is no `run observe` subcommand** — `RunCmd` has no such variant —
/// so nothing here or in its recourse text may name one.
#[derive(Debug, Serialize)]
struct CancelAck {
    ok: bool,
    action: &'static str,
    assignments_asked_to_stop: usize,
    main_side_settled: usize,
    child_executions_cancelled: usize,
}

#[cfg(test)]
mod tests {
    use super::parse_cli_params;
    use serde_json::json;

    /// The CLI face — `--param name=value` parses the value as JSON when
    /// it parses, else as a bare string; the assembled `{name: value}` object is
    /// what the operator submit sends (the workflow contract types it at admission).
    #[test]
    fn parse_cli_params_parses_json_or_falls_back_to_string() {
        let params = parse_cli_params(
            &[
                "target=main".to_owned(),
                "count=7".to_owned(),
                "mode=fast".to_owned(),
                "flag=true".to_owned(),
                "quoted=\"hello\"".to_owned(),
            ],
            None,
        )
        .expect("parses");
        assert_eq!(params["target"], json!("main"), "bare string fallback");
        assert_eq!(params["count"], json!(7), "JSON integer");
        assert_eq!(params["mode"], json!("fast"));
        assert_eq!(params["flag"], json!(true), "JSON bool");
        assert_eq!(params["quoted"], json!("hello"), "explicit JSON string");
    }

    #[test]
    fn parse_cli_params_rejects_a_missing_equals() {
        let err = parse_cli_params(&["no-equals".to_owned()], None).unwrap_err();
        assert!(err.to_string().contains("NAME=VALUE"), "{err}");
    }

    /// `submit_target`'s two refusals carry the classes, and so the exit codes,
    /// the CHANGELOG promises `kata run` and `kata factory run`: a path naming
    /// no file is `not_found` (exit 3), a file that is not `.star` is `usage`
    /// (exit 2). The exit code is read through `exit_code_for_error`, the
    /// mapping `main` applies, on the `anyhow` error the callers propagate.
    #[test]
    fn a_missing_path_is_not_found_and_a_non_starlark_file_is_usage() {
        use kata_op_contract::OpErrorCode;

        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("absent.star");
        let not_starlark = dir.path().join("wf.toml");
        std::fs::write(&not_starlark, "# not starlark\n").expect("write");

        for (target, code, exit) in [
            (&missing, OpErrorCode::NotFound, 3),
            (&not_starlark, OpErrorCode::Usage, 2),
        ] {
            let target = target.to_str().expect("utf-8 path");
            let error = super::submit_target(target).expect_err("refused");
            assert_eq!(error.code, code, "{target}: {error}");
            assert_eq!(
                crate::cli::exit_code_for_error(&anyhow::Error::from(error)),
                exit,
                "{target}"
            );
        }
    }

    /// The refusal must not hand the operator an invocation that is itself refused.
    ///
    /// A workflow runs only on a running main, so the
    /// one recourse is the one the refusal names: a `.star` file or a library ref.
    /// Both callers — `kata run --submit|--watch|--wait` and `kata factory run` —
    /// get the same sentence.
    #[test]
    fn the_non_starlark_refusal_names_no_invocation_that_is_itself_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("wf.toml");
        std::fs::write(&target, "# not starlark\n").expect("write");
        let target = target.to_str().expect("utf-8 path").to_owned();

        let err = super::submit_target(&target)
            .expect_err("a non-`.star` file is not an API-backed submit target");
        let message = err.to_string();
        assert!(
            message.contains(&target) && message.contains("Rename it to `.star`"),
            "the refusal names the file and the recourse that exists; got:\n{message}"
        );
        for refused in ["--scratch", "--config"] {
            assert!(
                !message.contains(refused),
                "the refusal must not recommend `{refused}`; got:\n{message}"
            );
        }
    }
}
