//! Execution-evidence routing for the broadcast/delivery plane.
//!
//! This file carries the operational-plane evidence surface, the status mapping and
//! the pure graph builder the execution record's DERIVED invocation graph runs
//! through.

use std::collections::BTreeSet;

use super::{
    AgentInvocationGraph, AgentInvocationGraphNode, AgentInvocationRecord, AgentInvocationStatus,
    ExecutionEvidence, ExecutionEvidenceClaimOutcome, ExecutionEvidenceRecord, InFlightLedger,
    KataError, KataResult, Ulid, now_ms,
};

impl InFlightLedger {
    pub fn bind_operational(
        &self,
        operational: &std::sync::Arc<crate::operational::OperationalDb>,
    ) -> KataResult<()> {
        if let Some(bound) = self.operational.get() {
            if std::sync::Arc::ptr_eq(bound, operational) {
                return Ok(());
            }
            return Err(KataError::Validation(
                "ledger: the operational plane execution evidence is durable on is already \
                 bound to a different database; re-binding would split one execution's \
                 observations across two files with no record of which holds what"
                    .to_string(),
            ));
        }
        for record in operational.load_all_execution_evidence()? {
            self.evidence_rows.insert(record.id, record);
        }
        // `set` cannot fail here for a different value: the only other writer is this
        // method, and the `get` above already handled a prior bind. A racing identical
        // bind loses the `set` and is correct anyway.
        let _ = self.operational.set(std::sync::Arc::clone(operational));
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn arm_evidence_fault(&self, fault: super::EvidenceFault) {
        *self.evidence_fault.lock() = Some(fault);
    }

    /// TEST-ONLY: the armed [`super::EvidenceFault`], if any, decides the append.
    #[cfg(any(test, feature = "test-support"))]
    fn guard_evidence(
        &self,
        claim_key: Option<&str>,
        record: &ExecutionEvidenceRecord,
    ) -> KataResult<()> {
        match self.evidence_fault.lock().clone() {
            Some(fault) => fault(claim_key, record),
            None => Ok(()),
        }
    }

    pub(super) fn operational_plane(
        &self,
    ) -> Option<&std::sync::Arc<crate::operational::OperationalDb>> {
        self.operational.get()
    }

    pub(super) fn take_scratch_evidence_claim(
        &self,
        execution_id: Ulid,
        claim_key: &str,
    ) -> ExecutionEvidenceClaimOutcome {
        use dashmap::mapref::entry::Entry;
        match self
            .scratch_evidence_claims
            .entry((execution_id, claim_key.to_string()))
        {
            Entry::Occupied(_) => ExecutionEvidenceClaimOutcome::AlreadyClaimed,
            Entry::Vacant(slot) => {
                slot.insert(());
                ExecutionEvidenceClaimOutcome::Claimed
            }
        }
    }

    pub fn append_execution_evidence(
        &self,
        execution_id: Ulid,
        evidence: ExecutionEvidence,
    ) -> KataResult<Option<ExecutionEvidenceRecord>> {
        if evidence.is_empty() {
            return Ok(None);
        }
        let record = ExecutionEvidenceRecord {
            id: Ulid::new(),
            execution_id,
            created_at_ms: now_ms(),
            evidence,
        };
        #[cfg(any(test, feature = "test-support"))]
        self.guard_evidence(None, &record)?;
        if let Some(operational) = self.operational_plane() {
            operational.append_execution_evidence(&record)?;
        }
        self.evidence_rows.insert(record.id, record.clone());
        Ok(Some(record))
    }

    pub fn append_execution_evidence_claimed(
        &self,
        execution_id: Ulid,
        claim_key: &str,
        evidence: ExecutionEvidence,
    ) -> KataResult<Option<ExecutionEvidenceRecord>> {
        let claim_key = claim_key.trim();
        if claim_key.is_empty() {
            return Err(KataError::Validation(
                "execution evidence claim key cannot be empty".to_string(),
            ));
        }
        if evidence.is_empty() {
            return Ok(None);
        }
        let record = ExecutionEvidenceRecord {
            id: Ulid::new(),
            execution_id,
            created_at_ms: now_ms(),
            evidence,
        };
        // UNBOUND IS IN-RAM ONLY, and the CLAIM has to be too. Routing the claim to a
        // durable table while the row stayed in RAM (or the reverse) would give the
        // dedupe boundary and the observation two different lifetimes, which is how a
        // claim ends up reporting `AlreadyClaimed` forever for a row nobody can read.
        // The pairing lives in the one place that knows whether a durable plane is
        // bound.
        #[cfg(any(test, feature = "test-support"))]
        self.guard_evidence(Some(claim_key), &record)?;
        let outcome = match self.operational_plane() {
            Some(operational) => {
                operational.append_execution_evidence_claimed(claim_key, &record)?
            }
            None => self.take_scratch_evidence_claim(execution_id, claim_key),
        };
        match outcome {
            ExecutionEvidenceClaimOutcome::Claimed => {
                self.evidence_rows.insert(record.id, record.clone());
                Ok(Some(record))
            }
            ExecutionEvidenceClaimOutcome::AlreadyClaimed => Ok(None),
        }
    }

    pub fn execution_evidence_records(&self, execution_id: Ulid) -> Vec<ExecutionEvidenceRecord> {
        let mut rows = self
            .evidence_rows
            .iter()
            .filter(|entry| entry.value().execution_id == execution_id)
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        rows.sort_by_key(|record| (record.created_at_ms, record.id));
        rows
    }
}

/// The invocation graph's projection of an
/// [`AssignmentStatus`](kata_types::ledger::AssignmentStatus) (an execution
/// record's `agent_invocation_graph`, which REST `GET /executions/{id}` serves
/// and `kata timeline` and `kata diff` read) — kept here,
/// one spelling, so the writer and every fold apply the same mapping.
/// Terminality is the only property a reader asks of it: `Cancelled` collapses
/// onto `Failed`, and the authoritative discriminator stays
/// `AssignmentStatus::is_cancelled` on the attempt's own terminal.
pub fn invocation_status_for(status_tag: &str) -> AgentInvocationStatus {
    match status_tag {
        "stalled" => AgentInvocationStatus::Stalled,
        "awaiting_approval" => AgentInvocationStatus::AwaitingApproval,
        "awaiting_child_completion" | "dispatched" => AgentInvocationStatus::Dispatched,
        "running" => AgentInvocationStatus::Running,
        "completed" => AgentInvocationStatus::Completed,
        "failed" | "cancelled" => AgentInvocationStatus::Failed,
        "orphaned" => AgentInvocationStatus::Orphaned,
        _ => AgentInvocationStatus::Pending,
    }
}

/// Build a deterministic graph projection from invocation records — the pure
/// helper behind the API execution view, keyed directly on the records rather
/// than on a deleted assignment-row shape.
///
/// `records` yields `(record, latest_progress, output)`: the progress and output
/// come from the caller's read of the assignment's current outcome because the
/// record itself carries neither.
pub fn agent_invocation_graph_from_records<'a>(
    execution_id: Ulid,
    records: impl Iterator<
        Item = (
            &'a AgentInvocationRecord,
            Option<&'a kata_types::ledger::ProgressEvent>,
            Option<&'a serde_json::Value>,
        ),
    >,
) -> AgentInvocationGraph {
    let mut nodes: Vec<AgentInvocationGraphNode> = records
        .filter(|(record, _, _)| record.execution_id == execution_id)
        .map(
            |(record, latest_progress, output)| AgentInvocationGraphNode {
                id: record.id,
                parent_id: record.parent_id,
                assignment_id: record.assignment_id,
                execution_id: record.execution_id,
                stage_name: record.stage_name.clone(),
                kind: record.kind,
                role: record.role.clone(),
                agent_label: record.agent_label.clone(),
                effect_kind: record.effect_kind,
                topology_kind: record.topology_kind.clone(),
                model_hint: record.model_hint.clone(),
                timeout_ms: record.timeout_ms,
                progress_visibility: record.progress_visibility,
                owned_paths: record.owned_paths.clone(),
                sync_with_assignment: record.sync_with_assignment,
                status: record.status.clone(),
                created_at_ms: record.created_at_ms,
                dispatched_at_ms: record.dispatched_at_ms,
                started_at_ms: record.started_at_ms,
                finished_at_ms: record.finished_at_ms,
                child_ids: Vec::new(),
                latest_progress: latest_progress.cloned(),
                output: if record.sync_with_assignment {
                    output.cloned()
                } else {
                    None
                },
            },
        )
        .collect();
    nodes.sort_by(|a, b| {
        a.stage_name
            .cmp(&b.stage_name)
            .then(a.created_at_ms.cmp(&b.created_at_ms))
            .then(a.role.cmp(&b.role))
            .then(a.id.cmp(&b.id))
    });
    let known_ids: BTreeSet<Ulid> = nodes.iter().map(|node| node.id).collect();
    let mut child_ids: std::collections::BTreeMap<Ulid, Vec<Ulid>> =
        std::collections::BTreeMap::new();
    let mut roots = Vec::new();
    let mut orphaned = Vec::new();
    for node in &nodes {
        match node.parent_id {
            None => roots.push(node.id),
            Some(parent) if known_ids.contains(&parent) => {
                child_ids.entry(parent).or_default().push(node.id);
            }
            Some(_) => orphaned.push(node.id),
        }
    }
    for node in &mut nodes {
        node.child_ids = child_ids.remove(&node.id).unwrap_or_default();
        node.child_ids.sort();
    }
    roots.sort();
    orphaned.sort();
    AgentInvocationGraph {
        execution_id,
        nodes,
        roots,
        orphaned,
    }
}
