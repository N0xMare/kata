//! Worker-attribution projection concern.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use futures::StreamExt as _;
use serde::Serialize;

use crate::error::KataClientError;
use crate::types::ExecutionRecord;
use crate::{EventFrame, KataClient, LedgerEvent};

#[derive(Clone, Debug, Serialize)]
pub struct WorkerAttribution {
    pub(super) stage_name: String,
    pub(super) assignment_id: String,
    pub(super) status: String,
    pub(super) worker_id: String,
}

#[derive(Default)]
pub struct WorkerAttributionProjection {
    by_assignment: BTreeMap<(String, String), WorkerAttribution>,
}

impl WorkerAttributionProjection {
    pub fn from_attribution(attribution: Vec<WorkerAttribution>) -> Self {
        let mut projection = Self::default();
        for item in attribution {
            projection
                .by_assignment
                .insert((item.stage_name.clone(), item.assignment_id.clone()), item);
        }
        projection
    }

    pub fn record_event(&mut self, event: &LedgerEvent) {
        if event.stage_name.as_str().starts_with("__") {
            return;
        }
        if let Some(worker_id) = event.new_status.worker_id() {
            self.by_assignment.insert(
                (
                    event.stage_name.to_string(),
                    event.assignment_id.to_string(),
                ),
                WorkerAttribution {
                    stage_name: event.stage_name.to_string(),
                    assignment_id: event.assignment_id.to_string(),
                    status: event.new_status.tag().to_string(),
                    worker_id: worker_id.to_string(),
                },
            );
        }
    }

    fn covers_assignments(&self, assignment_ids: &BTreeSet<String>) -> bool {
        !assignment_ids.is_empty()
            && assignment_ids.iter().all(|assignment_id| {
                self.by_assignment
                    .values()
                    .any(|item| &item.assignment_id == assignment_id && item.is_terminal())
            })
    }

    pub fn to_vec(&self) -> Vec<WorkerAttribution> {
        self.by_assignment.values().cloned().collect()
    }
}

impl WorkerAttribution {
    /// The tags are `AssignmentStatus::tag()`'s, read off the ledger EVENT — so
    /// `cancelled` reaches here verbatim, unlike the invocation-status projection
    /// one module over which collapses it onto `failed`. Omitting it would leave
    /// `covers_assignments` waiting out its whole drain budget for an execution an
    /// operator stopped.
    fn is_terminal(&self) -> bool {
        matches!(
            self.status.as_str(),
            "completed" | "failed" | "cancelled" | "orphaned"
        )
    }
}

pub async fn collect_worker_attribution(
    client: &KataClient,
    execution_id: &str,
    record: &ExecutionRecord,
) -> Result<Vec<WorkerAttribution>, KataClientError> {
    const MAX_DRAIN: Duration = Duration::from_millis(500);

    // REACHABLE, and correct: no dispatched node means no ledger event can carry a
    // worker for this record, so there is nothing to drain for. Three shapes reach
    // it — a record with no graph (no readable checked program), a graph of only
    // main-resolved nodes (an `Invoke`-only parent, a fully reused run; the api
    // test `the_node_wide_spend_counts_an_invoke_childs_cost_once` witnesses the
    // first), and an execution read before its first dispatch, whose later
    // attributions `kata watch` takes from its live stream rather than from this
    // snapshot.
    let expected_assignments = expected_worker_assignment_ids(record);
    if expected_assignments.is_empty() {
        return Ok(Vec::new());
    }

    let Ok(mut stream) = client
        .subscribe_event_frames(Some(execution_id), Some(0))
        .await
    else {
        return Ok(Vec::new());
    };
    let deadline = tokio::time::Instant::now() + MAX_DRAIN;
    let mut projection = WorkerAttributionProjection::default();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(Ok(EventFrame::Ledger(event)))) => {
                projection.record_event(&event);
                if projection.covers_assignments(&expected_assignments) {
                    break;
                }
            }
            Ok(Some(Ok(EventFrame::Progress(_) | EventFrame::ProgressLagged))) => {}
            Ok(Some(Err(_)) | None) | Err(_) => break,
        }
    }
    Ok(projection.to_vec())
}

/// The attempts a worker attribution can arrive for: the graph's DISPATCHED
/// nodes. A main-resolved attempt (an `Invoke`, a join, a reused stage) is never
/// placed, so no ledger event will carry a worker for it, and waiting for one
/// would hold [`collect_worker_attribution`] for its whole drain.
pub(super) fn expected_worker_assignment_ids(record: &ExecutionRecord) -> BTreeSet<String> {
    record
        .agent_invocation_graph
        .as_ref()
        .map(|graph| {
            graph
                .nodes
                .iter()
                .filter(|node| node.dispatched_at_ms.is_some())
                .map(|node| node.assignment_id.to_string())
                .collect()
        })
        .unwrap_or_default()
}
