//! `kata diff <execution> <stage>` — one stage's INPUT vs OUTPUT delta.
//!
//! INPUT is the parsed outputs of upstream stages the stage consumed (per the
//! evidence chain: `ExecutionRecord.outputs` ordered by the invocation graph's
//! finish times) plus any stage-scoped external inputs. OUTPUT is the stage's
//! completed envelope (content / parsed / exit_code / cost) from
//! `GET /executions/{id}/stages/{stage}/output`. When the stage carried a
//! workspace effect, the files-touched set from the output-closure
//! evidence is summarized alongside.

use std::fmt::Write as _;

use anyhow::Result;
use kata_client::types::ExecutionStatus;
use kata_client::{ExecutionRecord, KataClient, KataClientError};
use serde::Serialize;

use crate::cli::output::{self, OutputFormat};

use super::fmt::format_cost_micro_usd;
use super::{block_on, client};

/// Cap on how much stage `content` text is inlined into the delta before it is
/// truncated. The parsed/structured half is shown in full — that is the delta
/// that matters — but raw prose content is previewed.
const CONTENT_PREVIEW_CHARS: usize = 600;

/// Dispatch `kata diff <execution> <stage>`.
pub(crate) fn run_diff_cmd(
    api_url: &str,
    execution_id: String,
    stage: String,
    format: OutputFormat,
) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        let record = client.observe(&execution_id).await?;
        let output_result = fetch_stage_output(&client, &execution_id, &stage).await?;
        let packet = build_diff(&record, &stage, output_result);
        match format {
            OutputFormat::Json => output::emit_record(&packet),
            OutputFormat::Human => {
                print!("{}", render_diff_text(&packet));
                Ok(())
            }
        }
    })
}

/// Fetch the stage output envelope. A missing/incomplete stage is NOT a hard
/// error — the diff still renders its INPUT half and narrows the OUTPUT half —
/// so those two typed variants become `Ok(Err(reason))`. Every other transport
/// error propagates.
async fn fetch_stage_output(
    client: &KataClient,
    execution_id: &str,
    stage: &str,
) -> Result<Result<serde_json::Value, String>> {
    match client.get_stage_output(execution_id, stage).await {
        Ok(value) => Ok(Ok(value)),
        Err(KataClientError::NotFound) => Ok(Err(format!(
            "stage {stage:?} not found in execution {execution_id} (unknown stage name)"
        ))),
        Err(KataClientError::StageNotComplete) => Ok(Err(format!(
            "stage {stage:?} has not yet completed; its output envelope is not available"
        ))),
        Err(other) => Err(other.into()),
    }
}

#[derive(Debug, Serialize)]
pub(super) struct DiffPacket {
    summary_kind: &'static str,
    execution_id: String,
    stage: String,
    pub(super) input: DiffInput,
    pub(super) output: DiffOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) workspace_effect: Option<WorkspaceEffect>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) narrowings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct DiffInput {
    upstream_stage_count: usize,
    pub(super) upstream: Vec<UpstreamInput>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) external_inputs: Vec<StageExternalInput>,
}

#[derive(Debug, Serialize)]
pub(super) struct UpstreamInput {
    pub(super) stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    finished_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) parsed: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_preview: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct StageExternalInput {
    input_id: String,
    channel: String,
    text: String,
}

#[derive(Debug, Serialize)]
pub(super) struct DiffOutput {
    pub(super) available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unavailable_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) parsed: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) exit_code: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) cost_micro_usd: Option<u64>,
    /// The QUALITY of `cost_micro_usd`, or `None` for an envelope that carries
    /// no quality at all.
    ///
    /// Without this, an ABSENT `cost_micro_usd` (the shape an unmeterable stage
    /// now produces) reads on this surface exactly like a free stage — the same
    /// ambiguity on a different projection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) cost_quality: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub(super) struct WorkspaceEffect {
    pub(super) files_touched: Vec<String>,
    pub(super) conforming: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    undeclared: Vec<String>,
}

/// Fold the record + fetched stage output into a diff packet.
pub(super) fn build_diff(
    record: &ExecutionRecord,
    stage: &str,
    output_result: Result<serde_json::Value, String>,
) -> DiffPacket {
    let mut narrowings: Vec<String> = Vec::new();

    // --- INPUT: upstream parsed outputs consumed before this stage started ---
    let target_start = stage_start_ms(record, stage);
    let finished_by_stage = stage_finish_times(record);
    let has_graph = record
        .agent_invocation_graph
        .as_ref()
        .is_some_and(|g| !g.nodes.is_empty());

    let mut upstream: Vec<UpstreamInput> = Vec::new();
    if let Some(outputs) = record.outputs.as_ref() {
        for (name, value) in outputs {
            if name == stage {
                continue;
            }
            let finished = finished_by_stage.get(name).copied();
            // Keep a stage only if it demonstrably completed before the target
            // started. When we cannot order (no timing for either side) we keep
            // it and lean on the narrowing below rather than hide evidence.
            let ordered_before = match (finished, target_start) {
                (Some(f), Some(t)) => f <= t,
                _ => true,
            };
            if !ordered_before {
                continue;
            }
            upstream.push(UpstreamInput {
                stage: name.clone(),
                finished_at_ms: finished,
                parsed: value.get("parsed").cloned(),
                content_preview: value
                    .get("content")
                    .and_then(|c| c.as_str())
                    .map(preview_content),
            });
        }
    }
    upstream.sort_by(|a, b| {
        a.finished_at_ms
            .cmp(&b.finished_at_ms)
            .then_with(|| a.stage.cmp(&b.stage))
    });

    if has_graph && target_start.is_none() {
        narrowings.push(format!(
            "stage {stage:?} has no recorded start time; upstream inputs are ordered by finish \
             time but the before/after cut relative to {stage:?} could not be applied."
        ));
    } else if !has_graph {
        narrowings.push(
            "no invocation-graph timing on this execution; showing every recorded prior stage \
             output as available input (ordering approximate)."
                .to_string(),
        );
    }
    narrowings.push(
        "consumed inputs are the parsed outputs of upstream stages per the evidence chain; \
         precise per-template dependency edges are not on the operator read plane."
            .to_string(),
    );

    let external_inputs: Vec<StageExternalInput> = record
        .evidence
        .external_inputs
        .iter()
        .filter(|input| input.target_stage.as_deref() == Some(stage))
        .map(|input| StageExternalInput {
            input_id: input.id.clone(),
            channel: input.channel.clone(),
            text: input.text.clone(),
        })
        .collect();

    let input = DiffInput {
        upstream_stage_count: upstream.len(),
        upstream,
        external_inputs,
    };

    // --- OUTPUT: the stage's completed envelope --------------------------------
    let output = match output_result {
        Ok(value) => DiffOutput {
            available: true,
            unavailable_reason: None,
            content_preview: value
                .get("content")
                .and_then(|c| c.as_str())
                .map(preview_content),
            parsed: value.get("parsed").cloned(),
            exit_code: extract_exit_code(&value),
            cost_micro_usd: value
                .get("token_usage")
                .and_then(|t| t.get("cost_micro_usd"))
                .and_then(serde_json::Value::as_u64),
            cost_quality: value
                .get("token_usage")
                .and_then(|t| t.get("cost"))
                .and_then(|c| {
                    serde_json::from_value::<kata_types::metering::MeteredCost>(c.clone()).ok()
                })
                .map(|c| c.quality().label()),
        },
        Err(reason) => {
            let out = DiffOutput {
                available: false,
                unavailable_reason: Some(reason.clone()),
                content_preview: None,
                parsed: None,
                exit_code: None,
                cost_micro_usd: None,
                cost_quality: None,
            };
            narrowings.push(format!("output half unavailable: {reason}"));
            out
        }
    };

    // --- WORKSPACE EFFECT: files-touched from the output-closure evidence ------
    let workspace_effect = record
        .evidence
        .output_closures
        .iter()
        .find(|closure| closure.stage_name == stage)
        .map(|closure| {
            narrowings.push(
                "the workspace-effect tree root is an effect-plane internal not surfaced on \
                 the operator read record; the files-touched set below is the \
                 output-closure observation."
                    .to_string(),
            );
            WorkspaceEffect {
                files_touched: closure
                    .observed_outputs
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                conforming: closure.is_conforming(),
                undeclared: closure.undeclared.iter().map(ToString::to_string).collect(),
            }
        });

    // The aggregate `outputs` map is only populated on a successful terminal
    // run. When it is absent/empty the INPUT half looks bare — say why instead
    // of implying the stage consumed nothing. Failed and still-running/pending
    // executions each get a status-specific narrowing.
    let outputs_absent = record
        .outputs
        .as_ref()
        .is_none_or(std::collections::BTreeMap::is_empty);
    if outputs_absent {
        match record.status {
            ExecutionStatus::Failed => narrowings.push(
                "execution failed and exposes no aggregate stage outputs; upstream INPUT evidence \
                 is limited to what survived on the record."
                    .to_string(),
            ),
            ExecutionStatus::Cancelled => narrowings.push(
                "execution was cancelled and exposes no aggregate stage outputs; upstream INPUT \
                 evidence is limited to what survived on the record."
                    .to_string(),
            ),
            ExecutionStatus::Pending | ExecutionStatus::Running => narrowings.push(
                "execution is not yet terminal; the aggregate stage-outputs map is only surfaced \
                 on success, so upstream INPUT evidence is limited mid-run (an empty INPUT here \
                 means the map is not yet available, not that the stage consumed nothing)."
                    .to_string(),
            ),
            ExecutionStatus::Completed => {}
        }
    }

    DiffPacket {
        summary_kind: "operator_stage_diff",
        execution_id: record.id.clone(),
        stage: stage.to_string(),
        input,
        output,
        workspace_effect,
        narrowings,
    }
}

/// The target stage's start wall-time (prefer `started_at_ms`, fall back to
/// `dispatched_at_ms`) from the invocation graph, taking the latest matching
/// node so a retried stage cuts at its final attempt.
fn stage_start_ms(record: &ExecutionRecord, stage: &str) -> Option<u64> {
    let graph = record.agent_invocation_graph.as_ref()?;
    graph
        .nodes
        .iter()
        .filter(|n| n.stage_name.as_str() == stage)
        .filter_map(|n| n.started_at_ms.or(n.dispatched_at_ms))
        .max()
}

/// Map every stage name to its latest recorded finish wall-time.
fn stage_finish_times(record: &ExecutionRecord) -> std::collections::BTreeMap<String, u64> {
    let mut map = std::collections::BTreeMap::new();
    if let Some(graph) = record.agent_invocation_graph.as_ref() {
        for node in &graph.nodes {
            if let Some(finished) = node.finished_at_ms {
                let entry = map.entry(node.stage_name.to_string()).or_insert(finished);
                if finished > *entry {
                    *entry = finished;
                }
            }
        }
    }
    map
}

/// Pull the process exit code out of a stage result.
///
/// The one engine-owned position is the envelope root, where the main's
/// `capsule_result` envelope (`kata_core::operational::capsule_result_output`)
/// carries the capsule's exit code. An `exit_code` inside `parsed` is the
/// author's own field, not a value the engine measured, and is never read.
fn extract_exit_code(value: &serde_json::Value) -> Option<i64> {
    value.get("exit_code").and_then(serde_json::Value::as_i64)
}

/// Truncate long prose content to a bounded preview, annotating how many
/// characters were elided so the reader knows the output was clipped.
fn preview_content(content: &str) -> String {
    let char_count = content.chars().count();
    if char_count <= CONTENT_PREVIEW_CHARS {
        return content.to_string();
    }
    let head: String = content.chars().take(CONTENT_PREVIEW_CHARS).collect();
    format!(
        "{head}… (+{} more chars)",
        char_count - CONTENT_PREVIEW_CHARS
    )
}

/// Render a diff packet as an operator-readable INPUT → OUTPUT delta.
pub(super) fn render_diff_text(packet: &DiffPacket) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Kata diff: {}  stage={}",
        packet.execution_id, packet.stage
    );

    let _ = writeln!(out, "INPUT (consumed):");
    if packet.input.upstream.is_empty() && packet.input.external_inputs.is_empty() {
        let _ = writeln!(out, "  (no upstream stage outputs or stage-scoped inputs)");
    }
    for upstream in &packet.input.upstream {
        let _ = writeln!(out, "  <- {}", upstream.stage);
        if let Some(parsed) = &upstream.parsed {
            let _ = writeln!(out, "     parsed: {}", compact_json(parsed));
        } else if let Some(content) = &upstream.content_preview {
            let _ = writeln!(out, "     content: {}", indent_block(content, "     "));
        } else {
            let _ = writeln!(out, "     (no parsed/content fields)");
        }
    }
    for input in &packet.input.external_inputs {
        let _ = writeln!(
            out,
            "  <- external[{}] channel={}: {}",
            input.input_id, input.channel, input.text
        );
    }

    let _ = writeln!(out, "OUTPUT (produced):");
    if packet.output.available {
        if let Some(code) = packet.output.exit_code {
            let _ = writeln!(out, "  exit_code: {code}");
        }
        if let Some(parsed) = &packet.output.parsed {
            let _ = writeln!(out, "  parsed: {}", compact_json(parsed));
        }
        if let Some(content) = &packet.output.content_preview {
            let _ = writeln!(out, "  content: {}", indent_block(content, "  "));
        }
        if packet.output.parsed.is_none() && packet.output.content_preview.is_none() {
            let _ = writeln!(out, "  (empty output envelope)");
        }
        if let Some(cost) = packet.output.cost_micro_usd {
            let _ = writeln!(out, "  cost: {}", format_cost_micro_usd(cost));
        }
    } else {
        let reason = packet
            .output
            .unavailable_reason
            .as_deref()
            .unwrap_or("unavailable");
        let _ = writeln!(out, "  (unavailable) {reason}");
    }

    if let Some(effect) = &packet.workspace_effect {
        let _ = writeln!(
            out,
            "WORKSPACE EFFECT: {} file(s) touched, conforming={}",
            effect.files_touched.len(),
            effect.conforming
        );
        for file in &effect.files_touched {
            let _ = writeln!(out, "  ~ {file}");
        }
        for file in &effect.undeclared {
            let _ = writeln!(out, "  ! undeclared: {file}");
        }
    }

    if !packet.narrowings.is_empty() {
        let _ = writeln!(out, "narrowings:");
        for narrowing in &packet.narrowings {
            let _ = writeln!(out, "- {narrowing}");
        }
    }
    out
}

/// One-line JSON for a parsed value, bounded so a huge blob does not blow up
/// the terminal. Falls back to a length note when the compact form is large.
fn compact_json(value: &serde_json::Value) -> String {
    let rendered = value.to_string();
    if rendered.chars().count() <= CONTENT_PREVIEW_CHARS {
        rendered
    } else {
        let head: String = rendered.chars().take(CONTENT_PREVIEW_CHARS).collect();
        format!(
            "{head}… (+{} more chars)",
            rendered.chars().count() - CONTENT_PREVIEW_CHARS
        )
    }
}

/// Indent every line after the first by `pad` so a multi-line preview stays
/// visually attached to its label.
fn indent_block(content: &str, pad: &str) -> String {
    content.replace('\n', &format!("\n{pad}  "))
}
