//! `kata timeline <execution>` — a chronological, human-readable timeline
//! of one execution, reconstructed from the execution read record the API
//! already exposes (`GET /executions/{id}`).
//!
//! No new server plane: the execution record already carries the submission
//! and terminal wall-times plus the per-invocation timing on its
//! [`AgentInvocationGraph`] (`dispatched_at_ms` / `started_at_ms` /
//! `finished_at_ms`). This module folds those into a single sorted event
//! stream: submitted → running → per-stage dispatch/start/finish (with
//! durations) → parks → terminal.
//!
//! ## Sourcing scope
//!
//! The timeline is built from the invocation-graph timing on the read record,
//! NOT from a replay of the durable ledger event stream (`GET /events?
//! execution_id=&since=0`). The graph carries per-stage dispatch/start/finish
//! wall-times, but not a timestamped line per retry attempt or per
//! approval-gate park/answer — those transitions live on the ledger event
//! stream (SSE) and the live approvals plane. Folding them in as first-class
//! timestamped lines would mean draining an unbounded SSE firehose to head from
//! a one-shot CLI (no bounded historical-read endpoint exists today), so it is
//! deliberately out of scope here. What the record cannot show — a run with no
//! invocation metadata, or advisory human requests whose approval wall-times
//! live elsewhere — is surfaced as an explicit narrowing rather than silently
//! omitted. Enriching the timeline from the events replay is not a shipped
//! guarantee.

use std::fmt::Write as _;

use anyhow::Result;
use kata_client::ExecutionRecord;
use serde::Serialize;

use crate::cli::output::{self, OutputFormat};

use super::fmt::{format_delta_ms, format_duration_ms, format_ms_utc};
use super::{block_on, client, resolve_execution_id, serde_json_label};

/// Dispatch `kata timeline <execution>`.
pub(crate) fn run_timeline_cmd(
    api_url: &str,
    execution_id: Option<String>,
    current: bool,
    active: bool,
    format: OutputFormat,
) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        let execution_id =
            resolve_execution_id(&client, api_url, execution_id, current, active).await?;
        let record = client.observe(&execution_id).await?;
        let packet = build_timeline(&record)?;
        match format {
            OutputFormat::Json => output::emit_record(&packet),
            OutputFormat::Human => {
                print!("{}", render_timeline_text(&packet));
                Ok(())
            }
        }
    })
}

/// One line of the reconstructed timeline.
#[derive(Debug, Clone, Serialize)]
pub(super) struct TimelineEvent {
    /// Wall-clock millisecond timestamp of the event.
    pub(super) at_ms: u64,
    /// Delta from the previous event in the sorted stream (ms; first is 0).
    pub(super) delta_ms: i64,
    /// Event kind tag (`submitted` / `running` / `dispatch` / `start` /
    /// `finish` / `park` / `terminal`).
    pub(super) kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) detail: Option<String>,
}

/// Structured timeline packet — the `--format json` document and the
/// input to the text renderer.
#[derive(Debug, Serialize)]
pub(super) struct TimelinePacket {
    summary_kind: &'static str,
    execution_id: String,
    workflow_name: String,
    status: String,
    submitted_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finished_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) total_duration_ms: Option<u64>,
    event_count: usize,
    pub(super) events: Vec<TimelineEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) narrowings: Vec<String>,
}

/// A staged timeline event carrying its sort keys: `(at_ms, kind_order,
/// insertion_index, event)`.
type StagedEvent = (u64, u8, usize, TimelineEvent);

/// Append a staged event, capturing the current length as the stable
/// insertion-order tiebreak.
fn stage_push(
    staged: &mut Vec<StagedEvent>,
    at_ms: u64,
    kind: &'static str,
    stage: Option<String>,
    detail: Option<String>,
) {
    let idx = staged.len();
    staged.push((
        at_ms,
        kind_order(kind),
        idx,
        TimelineEvent {
            at_ms,
            delta_ms: 0,
            kind,
            stage,
            detail,
        },
    ));
}

/// Ordering hint used only to break ties between events that share a
/// millisecond timestamp, so the stream is deterministic. Chronology (the
/// millisecond stamp) always wins; this just fixes same-instant order.
fn kind_order(kind: &str) -> u8 {
    match kind {
        "submitted" => 0,
        "running" => 1,
        "dispatch" => 2,
        "start" => 3,
        "finish" => 4,
        "park" => 5,
        "terminal" => 6,
        _ => 7,
    }
}

/// Fold an execution record into a chronological timeline packet.
pub(super) fn build_timeline(record: &ExecutionRecord) -> Result<TimelinePacket> {
    let status = serde_json_label(&record.status)?;
    // (at_ms, kind_order, insertion_index, event) — insertion_index preserves
    // the source node iteration order as a final, stable tiebreak under the
    // sort.
    let mut staged: Vec<StagedEvent> = Vec::new();
    stage_push(&mut staged, record.submitted_at_ms, "submitted", None, None);
    if let Some(started) = record.started_at_ms {
        stage_push(&mut staged, started, "running", None, None);
    }

    let mut narrowings: Vec<String> = Vec::new();

    match record.agent_invocation_graph.as_ref() {
        Some(graph) if !graph.nodes.is_empty() => {
            for node in &graph.nodes {
                let stage = node.stage_name.to_string();
                let role = node.role.to_string();
                let kind = serde_json_label(&node.kind)?;
                if let Some(dispatched) = node.dispatched_at_ms {
                    stage_push(
                        &mut staged,
                        dispatched,
                        "dispatch",
                        Some(stage.clone()),
                        Some(format!("role={role} kind={kind}")),
                    );
                }
                if let Some(started) = node.started_at_ms {
                    stage_push(&mut staged, started, "start", Some(stage.clone()), None);
                }
                if let Some(finished) = node.finished_at_ms {
                    let node_status = serde_json_label(&node.status)?;
                    let mut detail = format!("status={node_status}");
                    if let Some(started) = node.started_at_ms {
                        let _ = write!(
                            detail,
                            " dur={}",
                            format_duration_ms(finished.saturating_sub(started))
                        );
                    }
                    stage_push(
                        &mut staged,
                        finished,
                        "finish",
                        Some(stage.clone()),
                        Some(detail),
                    );
                }
            }
        }
        _ => {
            narrowings.push(
                "no per-stage invocation metadata on this execution (cache hit or a \
                 pre-metadata run); stage-level dispatch/start/finish events are omitted."
                    .to_string(),
            );
        }
    }

    // Park is a terminal-time side effect; anchor it at the terminal wall-time
    // when known so it sorts just before the terminal line.
    if let Some(parked) = record.evidence.parked_candidate.as_ref() {
        let at = record.finished_at_ms.unwrap_or(record.submitted_at_ms);
        let source = if record.evidence.auto_parked {
            "auto"
        } else {
            "operator"
        };
        stage_push(
            &mut staged,
            at,
            "park",
            None,
            Some(format!("ref={} ({source})", parked.parked_ref)),
        );
    }

    if let Some(finished) = record.finished_at_ms {
        let mut detail = format!("status={status}");
        let _ = write!(
            detail,
            " total={}",
            format_duration_ms(finished.saturating_sub(record.submitted_at_ms))
        );
        stage_push(&mut staged, finished, "terminal", None, Some(detail));
    }

    // Approval-gate lifecycle (park-for-approval, approve/reject wall-times)
    // lives on the live approvals plane, not the execution read record; note it
    // only when this run actually carried advisory human-request evidence.
    if !record.evidence.human_requests.is_empty() {
        narrowings.push(format!(
            "{} advisory human-request(s) recorded; approval-gate park/answer wall-times are on \
             the live approvals plane (`kata approvals`), not the execution read record.",
            record.evidence.human_requests.len()
        ));
    }

    staged.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
    });

    let mut events: Vec<TimelineEvent> = Vec::with_capacity(staged.len());
    let mut prev: Option<u64> = None;
    for (at_ms, _, _, mut event) in staged {
        // Events are sorted ascending, so the gap is a non-negative u64 that
        // fits i64 for ms timestamps; saturate defensively rather than wrap.
        event.delta_ms = prev.map_or(0, |p| {
            i64::try_from(at_ms.saturating_sub(p)).unwrap_or(i64::MAX)
        });
        prev = Some(at_ms);
        events.push(event);
    }

    let total_duration_ms = record
        .finished_at_ms
        .map(|f| f.saturating_sub(record.submitted_at_ms));

    Ok(TimelinePacket {
        summary_kind: "operator_timeline",
        execution_id: record.id.clone(),
        workflow_name: record.workflow_name.clone(),
        status,
        submitted_at_ms: record.submitted_at_ms,
        started_at_ms: record.started_at_ms,
        finished_at_ms: record.finished_at_ms,
        total_duration_ms,
        event_count: events.len(),
        events,
        narrowings,
    })
}

/// Render a timeline packet as one line per event with an absolute UTC
/// timestamp and a delta from the previous event.
pub(super) fn render_timeline_text(packet: &TimelinePacket) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Kata timeline: {}  workflow={}  status={}",
        packet.execution_id, packet.workflow_name, packet.status
    );
    // Column widths kept fixed for a clean scan: delta (10) then timestamp.
    for event in &packet.events {
        let delta = format_delta_ms(event.delta_ms);
        let stage = event
            .stage
            .as_deref()
            .map(|s| format!("stage={s}"))
            .unwrap_or_default();
        let detail = event.detail.as_deref().unwrap_or_default();
        let tail = [stage.as_str(), detail]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join("  ");
        let mut line = format!(
            "{delta:<10}  {}  {:<9}",
            format_ms_utc(event.at_ms),
            event.kind,
        );
        if !tail.is_empty() {
            let _ = write!(line, "  {tail}");
        }
        // Trim so events without a tail carry no trailing whitespace.
        let _ = writeln!(out, "{}", line.trim_end());
    }
    if !packet.narrowings.is_empty() {
        let _ = writeln!(out, "narrowings:");
        for narrowing in &packet.narrowings {
            let _ = writeln!(out, "- {narrowing}");
        }
    }
    out
}
