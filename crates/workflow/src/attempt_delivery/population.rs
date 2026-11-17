//! Whole admitted work reconstructed from one captured authority prefix.
//!
//! Lifecycle meanings belong to `envelope_for`; this reader retains the
//! record-only metadata that the runner's narrow fold discards. The fold
//! produces [`PopulationState`] — one row per admitted work unit — straight
//! off the chain: capsule attempts and workerless stage admissions fold
//! through the same delivery envelope. A MAIN-RESOLVED attempt is excluded by
//! name: it is not a work unit any consumer of this population can act on.

use std::collections::BTreeMap;

use kata_core::operational::chain::{ChainScope, TransitionFrame};
use kata_core::operational::{
    UNDISPATCHED_STAGE_ADMITTED_KIND, UNDISPATCHED_STAGE_RECORD_KIND,
    UNDISPATCHED_STAGE_SETTLED_KIND, UndispatchedStageAppend, UndispatchedStageRecord,
};
use kata_types::error::{KataError, KataResult};
use kata_types::ledger::AssignmentStatus;
use kata_types::metering::TerminalCharge;
use smol_str::SmolStr;
use ulid::Ulid;

use super::{
    AttemptDeliveryMapper, FrameDelivery, StageScopeFacts, envelope_for, foldable_frame,
    undispatched_stage_status,
};

/// One admitted assignment's reconstructed state — the fold's own row.
///
/// It carries no work unit, no dispatch directive and no contract. What it carries is what the
/// chain's frames durably state: lifecycle, timing anchors and the record-only appends.
#[derive(Debug)]
pub(crate) struct PopulationState {
    /// The assignment identity — the attempt's `attempts.attempt_id`, or the
    /// undispatched admission's assignment id.
    pub(crate) assignment_id: Ulid,
    /// The display stage name — the canonical `attempts.stage_id`, which is the
    /// only name either surviving arm carries.
    pub(crate) stage_name: SmolStr,
    /// The canonical stage id the frame attributes to.
    pub(crate) stage_id: Option<String>,
    /// The lifecycle status the last lifecycle frame established.
    pub(crate) status: AssignmentStatus,
    /// The durable output a terminal carries.
    pub(crate) output: Option<serde_json::Value>,
    /// The charge a terminal non-completion made.
    pub(crate) terminal_charge: Option<TerminalCharge>,
    /// The dispatch instant the latest delivery snapshot recorded.
    pub(crate) dispatched_at_ms: Option<u64>,
    /// The run-start instant the latest delivery snapshot recorded.
    pub(crate) started_at_ms: Option<u64>,
    /// The terminal instant the latest lifecycle frame recorded.
    pub(crate) finished_at_ms: Option<u64>,
    /// The approval-park anchor the latest lifecycle frame recorded.
    pub(crate) awaiting_approval_at_ms: Option<u64>,
    /// The checkpoint safe point the latest record established.
    pub(crate) last_checkpoint: Option<u64>,
}

impl AttemptDeliveryMapper {
    fn assignment_population_frames(&self, execution_id: Ulid) -> KataResult<Vec<TransitionFrame>> {
        if self.db.execution_lifecycle(execution_id)?.is_none() {
            return Err(KataError::Storage(format!(
                "assignment population: execution {execution_id} has no admission"
            )));
        }
        let head = self.db.execution_transition_head(execution_id)?;
        let mut frames = Vec::new();
        let mut from_seq = 1;
        loop {
            let page = self
                .db
                .read_transitions_for_execution(execution_id, from_seq, 1000)?;
            frames.extend(
                page.frames
                    .into_iter()
                    .take_while(|frame| frame.seq <= head),
            );
            if page.reached_tail || page.next_from_seq > head {
                break;
            }
            from_seq = page.next_from_seq;
        }
        if frames.last().map(|frame| frame.seq) != Some(head) {
            return Err(KataError::Storage(format!(
                "assignment population: execution {execution_id} lost captured authority head {head}"
            )));
        }
        frames
            .iter()
            .map(|frame| self.db.resolve_transition_output(frame))
            .collect()
    }

    pub(super) fn chain_states_after_capture(
        &self,
        execution_id: Ulid,
        after_capture: impl FnOnce(),
    ) -> KataResult<Vec<super::ChainAssignmentState>> {
        let frames = self.assignment_population_frames(execution_id)?;
        after_capture();
        let mut lifecycle = BTreeMap::new();
        let mut admitted = BTreeMap::new();
        for frame in &frames {
            let id = match envelope_for(frame)? {
                FrameDelivery::Delivery(delivered) => {
                    foldable_frame(&delivered)?.event.assignment_id
                }
                _ => continue,
            };
            admitted.entry(id).or_insert(frame.seq);
            lifecycle.insert(id, frame.seq);
        }
        let mut population = Vec::new();
        for state in fold_population(execution_id, frames)? {
            let settled_seq = lifecycle
                .remove(&state.assignment_id)
                .ok_or_else(|| KataError::Storage("assignment has no lifecycle frame".into()))?;
            population.push(super::ChainAssignmentState {
                assignment_id: state.assignment_id,
                execution_id,
                stage_name: state.stage_name,
                status: state.status.clone(),
                output: state.output.clone(),
                terminal_charge: state.terminal_charge.clone(),
                outcome: super::FoldOutcome::from_status(
                    &state.status,
                    state.output.as_ref(),
                    state.terminal_charge.clone(),
                ),
                settled_seq,
                finished_at_ms: state
                    .finished_at_ms
                    .map(i64::try_from)
                    .transpose()
                    .map_err(|error| KataError::Storage(error.to_string()))?,
                started_at_ms: state
                    .started_at_ms
                    .map(i64::try_from)
                    .transpose()
                    .map_err(|error| KataError::Storage(error.to_string()))?,
            });
        }
        population.sort_by_key(|state| admitted[&state.assignment_id]);
        Ok(population)
    }
}

struct StagePopulation {
    assignment_id: Ulid,
    stage_name: SmolStr,
    stage_id: Option<String>,
    latest: TransitionFrame,
    records: Vec<UndispatchedStageAppend>,
}

fn population_error(frame: &TransitionFrame, detail: impl std::fmt::Display) -> KataError {
    KataError::Storage(format!(
        "assignment population for {} at {}: {detail}",
        frame.execution_id, frame.seq
    ))
}

fn decode_payload<T: serde::de::DeserializeOwned>(frame: &TransitionFrame) -> KataResult<T> {
    serde_json::from_slice(&frame.payload_json).map_err(|error| population_error(frame, error))
}

/// Whether `frame` is one of a MAIN-RESOLVED attempt's three kinds — see the
/// Attempt arm of [`fold_population`].
fn is_main_attempt_frame(frame: &TransitionFrame) -> bool {
    [
        kata_core::operational::MAIN_ATTEMPT_CLAIMED_KIND,
        kata_core::operational::MAIN_ATTEMPT_PARKED_KIND,
        kata_core::operational::MAIN_ATTEMPT_RESOLVED_KIND,
    ]
    .contains(&frame.kind.as_str())
}

fn fold_population(
    execution_id: Ulid,
    frames: Vec<TransitionFrame>,
) -> KataResult<Vec<PopulationState>> {
    let mut attempts: BTreeMap<Ulid, PopulationState> = BTreeMap::new();
    let mut stages: BTreeMap<Ulid, StagePopulation> = BTreeMap::new();
    let mut main_attempts: std::collections::BTreeSet<Ulid> = std::collections::BTreeSet::new();
    let mut previous_seq = 0;
    for frame in frames {
        if frame.execution_id != execution_id || frame.seq <= previous_seq {
            return Err(population_error(
                &frame,
                "foreign or unordered authority frame",
            ));
        }
        previous_seq = frame.seq;
        // Validate lifecycle semantics through the same mapper used by replay.
        let mapped = envelope_for(&frame)?;
        match frame.scope {
            ChainScope::Execution => {}
            ChainScope::Stage => match frame.kind.as_str() {
                UNDISPATCHED_STAGE_ADMITTED_KIND => {
                    let facts: StageScopeFacts = decode_payload(&frame)?;
                    if attempts.contains_key(&facts.assignment_id)
                        || stages.contains_key(&facts.assignment_id)
                    {
                        return Err(population_error(&frame, "conflicting stage admission"));
                    }
                    stages.insert(
                        facts.assignment_id,
                        StagePopulation {
                            assignment_id: facts.assignment_id,
                            stage_name: facts.stage_name.clone(),
                            stage_id: frame.stage_id.clone(),
                            latest: frame,
                            records: Vec::new(),
                        },
                    );
                }
                UNDISPATCHED_STAGE_SETTLED_KIND => {
                    let facts: StageScopeFacts = decode_payload(&frame)?;
                    let held = stages.get_mut(&facts.assignment_id).ok_or_else(|| {
                        population_error(&frame, "stage lifecycle has no preceding admission")
                    })?;
                    if held.stage_id != frame.stage_id || held.stage_name != facts.stage_name {
                        return Err(population_error(
                            &frame,
                            "stage lifecycle attribution disagrees",
                        ));
                    }
                    held.latest = frame;
                }
                UNDISPATCHED_STAGE_RECORD_KIND => {
                    let payload: kata_core::operational::UndispatchedStageRecordPayload =
                        decode_payload(&frame)?;
                    let held = stages.get_mut(&payload.assignment_id).ok_or_else(|| {
                        population_error(&frame, "stage metadata has no preceding admission")
                    })?;
                    if held.stage_id != frame.stage_id {
                        return Err(population_error(
                            &frame,
                            "stage metadata attribution disagrees",
                        ));
                    }
                    held.records.push(UndispatchedStageAppend {
                        assignment_id: payload.assignment_id,
                        seq: frame.seq,
                        record: payload.record,
                    });
                }
                _ => return Err(population_error(&frame, "unknown stage record kind")),
            },
            ChainScope::Attempt => {
                // A MAIN-RESOLVED attempt is EXCLUDED BY NAME, every frame of it:
                // this population answers "what work units did the execution
                // admit" and a main attempt is work the MAIN resolved — no
                // consumer of `execution_assignment_states` can act on it, and
                // refusing it instead would take the whole execution's
                // population down permanently, since terminal frames are read
                // too. Its LIFECYCLE frames carry the three main kinds; the
                // executor latch also admits RECORD-ONLY appends on one
                // (`outcome_amended` for a reused stage's `parsed` fold, the
                // gate family's `approval_decided`), which carry no main kind —
                // so the attempt is remembered at its claim and every later
                // frame of it skipped.
                if is_main_attempt_frame(&frame) {
                    if let Some(id) = frame.attempt_id {
                        main_attempts.insert(id);
                    }
                    continue;
                }
                if frame
                    .attempt_id
                    .is_some_and(|id| main_attempts.contains(&id))
                {
                    continue;
                }
                let id = frame.attempt_id.ok_or_else(|| {
                    population_error(&frame, "attempt frame has no assignment identity")
                })?;
                if let FrameDelivery::Delivery(delivered) = mapped {
                    let folded = foldable_frame(&delivered)?;
                    let payload: serde_json::Value = decode_payload(&frame)?;
                    let snapshot: kata_core::operational::AttemptDeliverySnapshot =
                        serde_json::from_value(payload.get("delivery").cloned().ok_or_else(
                            || population_error(&frame, "missing delivery snapshot"),
                        )?)
                        .map_err(|error| population_error(&frame, error))?;
                    let mut state = if let Some(state) = attempts.remove(&id) {
                        if frame.kind == "claimed" {
                            return Err(population_error(&frame, "duplicate attempt admission"));
                        }
                        state
                    } else {
                        if frame.kind != "claimed" && frame.kind != "dispatched" {
                            return Err(population_error(
                                &frame,
                                "attempt lifecycle has no preceding admission",
                            ));
                        }
                        PopulationState {
                            assignment_id: id,
                            stage_name: folded.event.stage_name.clone(),
                            stage_id: frame.stage_id.clone(),
                            status: folded.event.new_status.clone(),
                            output: None,
                            awaiting_approval_at_ms: None,
                            dispatched_at_ms: None,
                            started_at_ms: None,
                            finished_at_ms: None,
                            last_checkpoint: None,
                            terminal_charge: None,
                        }
                    };
                    if state.stage_name != folded.event.stage_name
                        || frame.stage_id != state.stage_id
                    {
                        return Err(population_error(
                            &frame,
                            "attempt lifecycle attribution disagrees",
                        ));
                    }
                    state.status = folded.event.new_status;
                    state.output = folded.event.output;
                    // The charge a terminal non-completion made, riding
                    // the event beside `output` exactly as a completion's does.
                    state.terminal_charge = folded.event.terminal_charge;
                    state.started_at_ms = timestamp(&frame, snapshot.started_at_ms)?;
                    state.finished_at_ms = timestamp(&frame, snapshot.finished_at_ms)?;
                    state.dispatched_at_ms = timestamp(&frame, snapshot.dispatched_at_ms)?;
                    state.awaiting_approval_at_ms =
                        timestamp(&frame, snapshot.awaiting_approval_at_ms)?;
                    state.last_checkpoint = timestamp(&frame, snapshot.last_checkpoint)?;
                    attempts.insert(id, state);
                } else {
                    let state = attempts.get_mut(&id).ok_or_else(|| {
                        population_error(&frame, "attempt metadata has no preceding admission")
                    })?;
                    if frame.stage_id != state.stage_id {
                        return Err(population_error(
                            &frame,
                            "attempt metadata attribution disagrees",
                        ));
                    }
                    apply_attempt_record(state, &frame)?;
                }
            }
        }
    }
    let mut population: Vec<_> = attempts.into_values().collect();
    for held in stages.into_values() {
        let facts: StageScopeFacts = decode_payload(&held.latest)?;
        let status = undispatched_stage_status(&held.latest.resulting_state, &facts)
            .map_err(|error| population_error(&held.latest, error))?;
        population.push(stage_state_from_facts(
            held.assignment_id,
            held.stage_name,
            facts,
            status,
            held.latest.seq,
            held.records,
        ));
    }
    population.sort_by(|a, b| {
        a.stage_name
            .cmp(&b.stage_name)
            .then(a.assignment_id.cmp(&b.assignment_id))
    });
    Ok(population)
}

/// The undispatched-stage class's fold result — stage name and identity off the
/// admission payload, never off a work-unit blob (none is carried).
fn stage_state_from_facts(
    assignment_id: Ulid,
    stage_name: SmolStr,
    facts: StageScopeFacts,
    status: AssignmentStatus,
    lifecycle_seq: i64,
    records: Vec<UndispatchedStageAppend>,
) -> PopulationState {
    let _ = lifecycle_seq;
    let mut state = PopulationState {
        assignment_id,
        stage_name,
        stage_id: None,
        status,
        output: facts.output.clone(),
        terminal_charge: facts.terminal_charge.clone(),
        dispatched_at_ms: None,
        started_at_ms: None,
        finished_at_ms: facts.timing.finished_at_ms,
        awaiting_approval_at_ms: facts.timing.awaiting_approval_at_ms,
        last_checkpoint: None,
    };
    for append in records {
        match append.record {
            UndispatchedStageRecord::OutcomeAmended(output) => {
                state.output = Some(output);
            }
        }
    }
    state
}

fn timestamp(frame: &TransitionFrame, value: Option<i64>) -> KataResult<Option<u64>> {
    value
        .map(u64::try_from)
        .transpose()
        .map_err(|error| population_error(frame, error))
}

fn apply_attempt_record(state: &mut PopulationState, frame: &TransitionFrame) -> KataResult<()> {
    match frame.kind.as_str() {
        "attempt_stalled" => {
            // A validated observation is deliverable but never a lifecycle change.
            let mapped = super::map_stalled_delivery_frame(frame)
                .map_err(|error| population_error(frame, error))?;
            let event: kata_types::ledger::LedgerLogEvent =
                serde_json::from_value(mapped.event.payload)
                    .map_err(|error| population_error(frame, error))?;
            let event = event.as_ledger_event().ok_or_else(|| {
                population_error(frame, "stall observation has no ledger envelope")
            })?;
            if event.stage_name != state.stage_name {
                return Err(population_error(frame, "stall stage name disagrees"));
            }
        }
        "attempt_safe_point" => {
            #[derive(serde::Deserialize)]
            struct SafePoint {
                last_checkpoint: i64,
            }
            let payload: SafePoint = decode_payload(frame)?;
            let checkpoint = timestamp(frame, Some(payload.last_checkpoint))?;
            state.last_checkpoint = state.last_checkpoint.max(checkpoint);
        }
        kind if kind == AttemptRecordKind::OutcomeAmended.as_str() => {
            if !state.status.is_terminal() {
                return Err(population_error(
                    frame,
                    "outcome amendment precedes terminal settlement",
                ));
            }
            state.output = Some(decode_payload(frame)?);
        }
        // A gate-decision record changes no folded field, and its writer (the
        // shared `approval_decision_key` latch) already refused a malformed
        // payload before the chain kept it.
        "approval_decided" => {}
        kind => {
            return Err(population_error(
                frame,
                format!("unknown attempt record kind {kind:?}"),
            ));
        }
    }
    Ok(())
}

use kata_core::operational::AttemptRecordKind;

#[cfg(test)]
mod tests {
    use super::*;

    fn admitted() -> PopulationState {
        PopulationState {
            assignment_id: Ulid::new(),
            stage_name: SmolStr::new("only"),
            stage_id: Some("only".to_owned()),
            status: AssignmentStatus::Pending,
            output: None,
            terminal_charge: None,
            dispatched_at_ms: None,
            started_at_ms: None,
            finished_at_ms: None,
            awaiting_approval_at_ms: None,
            last_checkpoint: None,
        }
    }

    /// A stored record-only attempt row whose kind no writer produces is refused
    /// by the fold's generic arm, naming the row and its kind, rather than folded
    /// as a no-op.
    #[test]
    fn a_record_kind_no_writer_produces_is_refused_by_the_fold() {
        for kind in [
            "assignment_amended",
            "attempt_reclaimed",
            "placement_audit_recorded",
            "generation_advanced",
        ] {
            let frame = TransitionFrame {
                seq: 7,
                execution_id: Ulid::new(),
                scope: ChainScope::Attempt,
                stage_id: Some("only".to_owned()),
                attempt_ordinal: Some(0),
                attempt_id: Some(Ulid::new()),
                kind: kind.to_owned(),
                resulting_state: kind.to_owned(),
                folds_projection: false,
                payload_json: b"{}".to_vec(),
                recorded_at_ms: 0,
            };
            let Err(error) = apply_attempt_record(&mut admitted(), &frame) else {
                panic!("{kind}: a record kind no writer produces must be refused");
            };
            let message = error.to_string();
            assert!(
                message.contains(" at 7: unknown attempt record kind") && message.contains(kind),
                "{kind}: the generic refusal must name the row and its kind: {message}"
            );
        }
    }
}
