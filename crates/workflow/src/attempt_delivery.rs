//! The TRANSITION MAPPING: what a committed authority transition means — to an
//! SSE client, to the runner's fold, or to neither.
//!
//! # Two audiences, one rule
//!
//! Attempt and undispatched-stage lifecycle frames both produce delivery envelopes
//! consumed by the same pure fold. Workerless completion is represented explicitly.
//! Metadata appends produce no second lifecycle event: the deciding reader
//! overlays them on the recorded state. `DeliveryService` uses this same mapping
//! for the installed global producer.
//!
//! # Where this lives, and why it is a CHOICE rather than a constraint
//!
//! [`DeliveryProjector`](kata_core::operational::delivery::DeliveryProjector) owns
//! sequence allocation, cursor durability, and crash-safe catch-up, and its own doc
//! declines the mapping on the grounds that decoding attempt facts "in `kata-core`
//! would re-couple the planes". That justification **does not hold as a
//! dependency fact**:
//!
//! - `LedgerEvent`, `LedgerEventV1`, and `LedgerLogEvent` live in `kata-types`,
//!   which `kata-core` depends on and already decodes (`ledger/replay.rs`).
//! - The at-rest arms are the capsule frame and the at-rest-only `main` tag,
//!   classified structurally by `attempt_payload::frame_arm`: no type in this
//!   crate spells their shape.
//!
//! The boundary is deliberate either way, and it needs a justification that
//! survives the dependency facts moving:
//!
//! 1. **`kata-core` owns adjudicated facts, not their delivery meaning.** Attempt
//!    writers capture a typed postimage inside the deciding transaction and read
//!    the stage's display name off the row's canonical `stage_id`. This module
//!    interprets those immutable facts as workflow statuses and delivery envelopes.
//! 2. **This is where the admission chokepoint lives too.** Program-body
//!    re-derivation is in `kata-workflow` for exactly this reason:
//!    `OperationalDb::fire_schedule` inserts pinned bytes and "cannot see the
//!    typed program". Same shape, same resolution — put the mapping where the
//!    workflow semantics belong.
//! 3. **The delivery plane must stay REBUILDABLE.** Delivery/read planes are
//!    derived. Mapping here is a pure function of the retained frame;
//!    rebuilding never reads the mutable attempt postimage.
//!
//! Recorded rather than asserted, because "the crate cannot see the types" would
//! have been a constraint and this is a design decision with costs.
//!
//! # Invariant
//!
//! TWO SEQUENCE SPACES. [`TransitionFrame::seq`] is AUTHORITY ordering and is
//! carried into [`DeliveryFrame::source_seq`] as a projection cursor ONLY. The
//! delivery sequence a client resumes from is allocated by the projector, out of
//! its own space. Nothing here reads one and serves the other.
//!
//! # Enforcement — fail closed, never invent
//!
//! A state the delivery mapping cannot express — a main-resolved attempt's
//! non-terminal state, or a spelling outside the wire vocabulary — has NO
//! `AssignmentStatus` variant. (`cancelled` is a WRITTEN state with a real
//! envelope: the reactor's seam stamps it for a worker terminal under a standing
//! operator stop.) Several more states name a variant
//! whose required fields are not durable anywhere on this plane. Every such frame
//! is a TYPED REFUSAL naming the exact missing fact, never a fabricated envelope —
//! because a fabricated `Failed { reason: "unknown" }` is a wire fact the chain
//! does not carry, which is the forgery class one plane down from the admission
//! chokepoint.
//!
//! That is deliberately more useful than a lenient mapping: it makes the durable
//! facts still owed visible as compile-and-run failures, at the exact
//! transition that lacks them, instead of as silently wrong dashboards.

use std::sync::Arc;

use kata_core::operational::chain::{
    CURRENT_FORMAT_REFUSAL_RECOURSE, ChainScope, REFUSE_TO_RESUME_PREFIX, TransitionFrame,
};
use kata_core::operational::delivery::DeliveryFrame;
use kata_core::operational::{
    OperationalDb, UNDISPATCHED_STAGE_ADMITTED_KIND, UNDISPATCHED_STAGE_RECORD_KIND,
    UNDISPATCHED_STAGE_SETTLED_KIND,
};

use kata_types::error::{KataError, KataResult};
use kata_types::event::Event;
use kata_types::ledger::{AssignmentStatus, LedgerEvent, LedgerEventV1, LedgerLogEvent};
use smol_str::SmolStr;
use ulid::Ulid;

mod population;

/// What one chain frame MEANS: to the wire, to the fold, or to neither.
///
/// # Invariant
///
/// Every lifecycle transition the fold reads — an attempt's and an
/// undispatched stage's alike — maps onto a delivery envelope, so no stage is
/// folded and kept off the wire. A safe point ([`FrameDelivery::Checkpoint`])
/// is the one frame the fold reads with no envelope: it advances recovery and
/// states no lifecycle edge.
///
/// # Invariant
///
/// "NO ENVELOPE BY DESIGN" AND "CANNOT BUILD AN ENVELOPE" ARE DIFFERENT OUTCOMES
/// AND ARE NOT COLLAPSED. An execution-scope lifecycle transition and a
/// record-only effect append were never `LedgerEvent`s — omitting them is correct
/// and silent. A `failed` transition with no durable reason is a hole in the
/// chain, and it REFUSES. Merging the two would let every future hole hide behind
/// the legitimate omissions.
#[derive(Clone, Debug)]
pub enum FrameDelivery {
    /// The frame maps onto exactly one delivery envelope, which also folds.
    Delivery(Box<DeliveryFrame>),
    /// A durable safe point; it advances recovery without a lifecycle event.
    Checkpoint {
        /// Authority ordering of the safe-point record.
        source_seq: i64,
        /// Assignment whose checkpoint advanced.
        assignment_id: Ulid,
        /// Adjudicated monotone checkpoint.
        last_checkpoint: u64,
    },
    /// The frame is correctly absent from both planes.
    NotADeliveryEvent {
        /// Why, in one phrase, for the audit trail.
        because: &'static str,
    },
}

/// What one durable frame tells the FOLD, with every attribution the orchestrator
/// does not read left out.
///
/// # Invariant
///
/// ONE FOLD VOCABULARY, ONE PRODUCER. An attempt-scope frame and a stage-scope
/// frame (a stage satisfied without dispatch) both map onto a delivery envelope,
/// and [`FoldOutcome::from_status`] decodes either into the SAME body, the
/// runner's private `fold_frame`, behind `WorkflowRunner::apply_event`. The
/// alternative — a second handler that re-implements the routing for the
/// undispatched class — would have to re-derive the `#branch-skip`,
/// `#escalate-gate`, child-invocation and review-loop rules, and two
/// implementations of one routing rule can disagree — a data-loss defect.
///
/// # Why it is not simply [`AssignmentStatus`]
///
/// The fold consumes completion, failure and park decisions, independently of
/// delivery attribution. `AssignmentStatus` represents workerless completion,
/// but global stage-scope delivery is a separate concern. Keeping this
/// outcome projection preserves the shared fold without claiming stage-scope
/// delivery.
#[derive(Clone, Debug, PartialEq)]
pub enum FoldOutcome {
    /// Terminal success. `None` is a completion with NO durable output, which the
    /// fold refuses — carried rather than collapsed so the refusal stays the
    /// reader's, naming the assignment.
    Completed {
        /// The durable output the terminal carries.
        output: Option<serde_json::Value>,
    },
    /// Terminal failure.
    Failed {
        /// The operator-facing reason.
        reason: String,
        /// The charge the failed stage made, off the frame's
        /// `terminal_charge`: the stage's own `token_usage` or the
        /// `child_invocation_summary` of a child execution it invoked. A
        /// DISPATCHED attempt's frame that recorded none is read as an
        /// unknown charge (`TerminalCharge::as_read`), so `None` here means a
        /// terminal that owes none — nothing it ran could bill.
        terminal_charge: Option<kata_types::metering::TerminalCharge>,
    },
    /// Terminal cancellation — an operator asked this attempt to stop and the
    /// main holds a standing `attempt_stop_requests` row for it.
    ///
    /// Its own arm rather than a `Failed` the fold cannot tell apart, because the
    /// execution's DURABLE TERMINAL OUTCOME is decided from this vocabulary: a
    /// cancel folded as `Failed` is what made
    /// `require_terminal_lifecycle_for_parking` take its evidence-free arm.
    Cancelled {
        /// The operator-facing reason.
        reason: String,
        /// A cancelled stage is charged on the same rule as a failed one.
        terminal_charge: Option<kata_types::metering::TerminalCharge>,
    },
    /// Terminal abandonment.
    Orphaned {
        /// The operator-facing reason.
        reason: String,
        /// An orphan is the class whose definition IS unknowable
        /// outcome, so the writer records the charge the same derivation
        /// states and the fold reads it here.
        terminal_charge: Option<kata_types::metering::TerminalCharge>,
    },
    /// Placed on a worker. The only arm that reads a placement, and it is
    /// unreachable for a stage that was never dispatched.
    Dispatched {
        /// The worker the attempt was placed on.
        worker_id: SmolStr,
    },
    /// Parked on a child execution.
    AwaitingChildCompletion {
        /// The child the parent waits on.
        child_execution_id: Ulid,
    },
    /// Parked for an operator decision.
    AwaitingApproval {
        /// The operator-facing reason.
        reason: String,
    },
    /// Still in flight. `Pending`, `Running` and `Stalled`
    /// collapse here because the orchestrator tracks none of them — the eventual
    /// terminal drives its transition. Collapsing them in the TYPE is what keeps
    /// the fold from acquiring a rule for a state it deliberately ignores.
    InFlight,
}

impl FoldOutcome {
    /// Whether this outcome is TERMINAL.
    ///
    /// # One spelling, on the vocabulary rather than on each carrier
    ///
    /// The same four `AssignmentStatus::is_terminal` names. It lives HERE, on
    /// the vocabulary, so [`ChainAssignmentState::is_terminal`] and the
    /// dispatcher's pre-image readers (`Dispatcher::settled_attempt_pre_image`)
    /// ask one classification: a `matches!` per carrier would be two places for
    /// "finished" to drift apart.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            FoldOutcome::Completed { .. }
                | FoldOutcome::Failed { .. }
                | FoldOutcome::Cancelled { .. }
                | FoldOutcome::Orphaned { .. }
        )
    }

    /// The wire status a frame recorded, projected onto what the fold reads.
    ///
    /// TOTAL over [`AssignmentStatus`] with no wildcard arm, so a new wire status
    /// is a compile error here rather than a silently ignored frame.
    ///
    /// `terminal_charge` is a REQUIRED argument rather than read off the
    /// status: it lives on the frame/row beside the status — exactly as
    /// `output` does — so a caller that has it cannot drop it by passing a
    /// status alone, and a caller that does not states `None` explicitly.
    #[must_use]
    pub fn from_status(
        status: &AssignmentStatus,
        output: Option<&serde_json::Value>,
        terminal_charge: Option<kata_types::metering::TerminalCharge>,
    ) -> Self {
        match status {
            AssignmentStatus::Completed { .. } => FoldOutcome::Completed {
                output: output.cloned(),
            },
            AssignmentStatus::Failed { reason, .. } => FoldOutcome::Failed {
                reason: reason.clone(),
                terminal_charge,
            },
            AssignmentStatus::Cancelled { reason, .. } => FoldOutcome::Cancelled {
                reason: reason.clone(),
                terminal_charge,
            },
            AssignmentStatus::Orphaned { reason, .. } => FoldOutcome::Orphaned {
                reason: reason.clone(),
                terminal_charge,
            },
            AssignmentStatus::Dispatched { worker_id } => FoldOutcome::Dispatched {
                worker_id: worker_id.clone(),
            },
            AssignmentStatus::AwaitingChildCompletion {
                child_execution_id, ..
            } => FoldOutcome::AwaitingChildCompletion {
                child_execution_id: *child_execution_id,
            },
            AssignmentStatus::AwaitingApproval { reason, .. } => FoldOutcome::AwaitingApproval {
                reason: reason.clone(),
            },
            AssignmentStatus::Pending
            | AssignmentStatus::Running { .. }
            | AssignmentStatus::Stalled { .. } => FoldOutcome::InFlight,
        }
    }

    /// The charge this outcome carried, if it is a failure-class terminal
    /// that states one.
    ///
    /// One accessor for every reader that would otherwise open-code the
    /// three-way destructure: `Completed` has no `terminal_charge` (its cost
    /// rides `output`), and the in-flight arms have none to carry.
    #[must_use]
    pub fn terminal_charge(&self) -> Option<&kata_types::metering::TerminalCharge> {
        match self {
            FoldOutcome::Failed {
                terminal_charge, ..
            }
            | FoldOutcome::Cancelled {
                terminal_charge, ..
            }
            | FoldOutcome::Orphaned {
                terminal_charge, ..
            } => terminal_charge.as_ref(),
            _ => None,
        }
    }

    /// A greppable tag, for traces only. `InFlight` reports `in_flight` because it
    /// covers four wire statuses and naming one of them would be a guess.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            FoldOutcome::Completed { .. } => "completed",
            FoldOutcome::Failed { .. } => "failed",
            FoldOutcome::Cancelled { .. } => "cancelled",
            FoldOutcome::Orphaned { .. } => "orphaned",
            FoldOutcome::Dispatched { .. } => "dispatched",
            FoldOutcome::AwaitingChildCompletion { .. } => "awaiting_child_completion",
            FoldOutcome::AwaitingApproval { .. } => "awaiting_approval",
            FoldOutcome::InFlight => "in_flight",
        }
    }
}

/// Why a chain frame cannot be turned into a delivery envelope.
///
/// Distinguishable by `match`, so a caller routes on the class rather than
/// string-matching a `Display`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UndeliverableTransitionCause {
    /// The state names no [`AssignmentStatus`] variant at all. The wire type has
    /// no way to express it, so an envelope would have to misreport it as
    /// something else.
    NoWireStatusForState {
        /// The attempt-lifecycle state found on the chain.
        state: String,
    },
    /// The variant exists but one of its REQUIRED fields is not durable anywhere
    /// on this plane for this frame.
    MissingDurableFact {
        /// The state whose variant was being built.
        state: String,
        /// The field that has no durable source.
        field: &'static str,
        /// Where it would have had to come from.
        expected_from: &'static str,
    },
    /// An attempt-scope frame carries no attempt identity, so its facts cannot be
    /// resolved. The schema CHECK is an implication rather than an iff (an
    /// attempt-scope transition need not bind an `attempts` row), which is why this
    /// refuses rather than fabricating an identity.
    UnattributedAttemptFrame,
    /// The transition payload did not decode as the canonical frame the inbox
    /// seam writes.
    MalformedFramePayload {
        /// The decode error.
        detail: String,
    },
    /// A STAGE-SCOPE frame carries a `kind` this reader has no rule for.
    ///
    /// The stage-scope vocabulary is CLOSED (see
    /// [`UNDISPATCHED_STAGE_ADMITTED_KIND`]), so an unrecognised kind means a
    /// writer was added and this reader was not updated. It fails CLOSED rather
    /// than defaulting either way, because both defaults are wrong for a fold:
    /// treating it as nothing drops a fact the deciding reader is TOTAL over, and
    /// treating it as an undispatched-stage record folds a payload that may state
    /// something else entirely.
    UnknownStageScopeKind {
        /// The kind the stage-scope frame carries.
        kind: String,
    },
    /// A STAGE-SCOPE settlement names a state a stage that was never dispatched
    /// cannot be in.
    ///
    /// `dispatched`, `running` and `resumed` all assert a placement, and this class
    /// is defined by never having reached a worker. A frame that states one is the
    /// chain contradicting its own admission, so it refuses rather than being folded
    /// as one of the states it might have meant.
    StageStateOutsideUndispatchedClass {
        /// The state the stage-scope frame recorded.
        state: String,
    },
    /// The payload's own `kind` disagrees with the state the transition recorded.
    ///
    /// These are two INDEPENDENTLY supplied statements of one fact: the reactor
    /// passes `resulting_state` as its own argument and canonicalizes `kind` into
    /// the frame bytes separately. A disagreement means one of them is wrong, and
    /// delivering either would publish a status the other plane contradicts.
    FrameKindContradictsState {
        /// The state the transition recorded.
        state: String,
        /// The kind the durable payload carries.
        kind: String,
    },
}

impl UndeliverableTransitionCause {
    /// A stable, greppable class tag.
    #[must_use]
    pub fn class(&self) -> &'static str {
        match self {
            UndeliverableTransitionCause::NoWireStatusForState { .. } => "no-wire-status",
            UndeliverableTransitionCause::MissingDurableFact { .. } => "missing-durable-fact",
            UndeliverableTransitionCause::UnattributedAttemptFrame => "unattributed-attempt-frame",
            UndeliverableTransitionCause::MalformedFramePayload { .. } => "malformed-frame-payload",
            UndeliverableTransitionCause::UnknownStageScopeKind { .. } => {
                "unknown-stage-scope-kind"
            }
            UndeliverableTransitionCause::StageStateOutsideUndispatchedClass { .. } => {
                "stage-state-outside-undispatched-class"
            }
            UndeliverableTransitionCause::FrameKindContradictsState { .. } => {
                "frame-kind-contradicts-state"
            }
        }
    }
}

impl std::fmt::Display for UndeliverableTransitionCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UndeliverableTransitionCause::NoWireStatusForState { state } => write!(
                f,
                "attempt state `{state}` has no AssignmentStatus variant, so no \
                 envelope can express it (it is forward vocabulary that nothing \
                 writes; reporting it as a different status would misinform every \
                 subscriber)"
            ),
            UndeliverableTransitionCause::MissingDurableFact {
                state,
                field,
                expected_from,
            } => write!(
                f,
                "building the `{state}` envelope needs `{field}`, which is not \
                 durable here — it would have come from {expected_from}. \
                 Synthesizing it would put a wire fact on the delivery plane that \
                 the authority chain does not carry"
            ),
            UndeliverableTransitionCause::UnattributedAttemptFrame => write!(
                f,
                "an attempt-scope transition carries no attempt identity, so its \
                 facts cannot be resolved; the identity cannot be invented"
            ),
            UndeliverableTransitionCause::MalformedFramePayload { detail } => {
                write!(f, "the transition payload did not decode ({detail})")
            }
            UndeliverableTransitionCause::UnknownStageScopeKind { kind } => write!(
                f,
                "a stage-scope transition carries kind `{kind}`, which this reader \
                 has no rule for; the stage-scope vocabulary is closed and a new \
                 member has to state whether it folds (add it to `envelope_for`'s \
                 stage arm) rather than be guessed at"
            ),
            UndeliverableTransitionCause::StageStateOutsideUndispatchedClass { state } => write!(
                f,
                "a stage admitted as UNDISPATCHABLE recorded state `{state}`, which \
                 asserts a placement; the admission and the settlement contradict \
                 each other and neither can be folded"
            ),
            UndeliverableTransitionCause::FrameKindContradictsState { state, kind } => write!(
                f,
                "the transition recorded state `{state}` but its durable payload \
                 says the frame kind was `{kind}`; these are two independently \
                 supplied statements of one fact and they disagree, so neither can \
                 be published"
            ),
        }
    }
}

/// A named, typed refusal to deliver ONE execution's transition, carrying the same
/// operator-facing shape as the chain reader's refusal.
///
/// # Invariant
///
/// ONE DIAGNOSTIC SHAPE ACROSS BOTH LAYERS. The prefix and the recourse sentence
/// come from `kata-core` constants, not from a copy, so the two cannot drift into
/// naming different remedies for the same operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndeliverableTransition {
    /// The execution that cannot be delivered.
    pub execution_id: Ulid,
    /// The authority sequence of the offending transition.
    pub seq: i64,
    /// What is missing.
    pub cause: UndeliverableTransitionCause,
}

impl std::fmt::Display for UndeliverableTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{REFUSE_TO_RESUME_PREFIX} {} at transition seq {}: its delivery \
             envelope is unreconstructable [{}] — {}. {CURRENT_FORMAT_REFUSAL_RECOURSE}",
            self.execution_id,
            self.seq,
            self.cause.class(),
            self.cause
        )
    }
}

impl std::error::Error for UndeliverableTransition {}

impl From<UndeliverableTransition> for KataError {
    fn from(refusal: UndeliverableTransition) -> Self {
        // Storage, whose severity is FATAL — the same classification the chain
        // reader's refusal takes, and for the same reason: retrying reads the
        // identical bytes and the node must not resume the execution.
        KataError::Storage(refusal.to_string())
    }
}

/// Immutable event payload carried by every advancing attempt transition.
/// Optional event-specific fields are checked by the status decoder; all snapshot
/// fields, including explicit nulls, are required by the current durable format.
#[derive(Debug, serde::Deserialize)]
struct DurableFrameFacts {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default, deserialize_with = "present_output")]
    output: Option<serde_json::Value>,
    #[serde(default)]
    reason: Option<String>,
    /// The charge a terminal non-completion made, written by the fused
    /// failure adjudication and by `main_resolved`/`main_side` terminal
    /// writers. Absent on a frame that never carried it, which the fold reads
    /// as "nothing charged", never as unmetered.
    #[serde(default)]
    terminal_charge: Option<kata_types::metering::TerminalCharge>,
    delivery: kata_core::operational::AttemptDeliverySnapshot,
}

impl DurableFrameFacts {
    fn decode(payload: &[u8]) -> Result<Self, UndeliverableTransitionCause> {
        serde_json::from_slice(payload).map_err(|error| {
            UndeliverableTransitionCause::MalformedFramePayload {
                detail: error.to_string(),
            }
        })
    }
}

/// The completion writer retains its authenticated input verbatim, with the
/// delivery snapshot added by the same transaction. Validate that input against
/// the immutable frame before interpreting its distinct kind as completion.
fn validate_typed_completion(
    frame: &TransitionFrame,
    snapshot: &kata_core::operational::AttemptDeliverySnapshot,
) -> Result<(), UndeliverableTransitionCause> {
    let malformed = |detail: String| UndeliverableTransitionCause::MalformedFramePayload {
        detail: format!("worker_completion: {detail}"),
    };
    let mut object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&frame.payload_json)
            .map_err(|error| malformed(error.to_string()))?;
    object.remove("kind");
    object.remove("delivery");
    let input: kata_core::operational::WorkerCompletionInput =
        serde_json::from_value(serde_json::Value::Object(object))
            .map_err(|error| malformed(error.to_string()))?;
    if input.execution_id != frame.execution_id
        || Some(input.attempt_id) != frame.attempt_id
        || Some(input.attempt_ordinal) != frame.attempt_ordinal
        || input.lease_epoch < 0
        || input.worker_id.trim().is_empty()
        || input.worker_id.len() > 1024
        || snapshot.worker_id.as_deref() != Some(input.worker_id.as_str())
    {
        return Err(malformed(
            "input identity disagrees with retained transition or placement".into(),
        ));
    }
    Ok(())
}

/// Every durable fact ONE stage-scope transition payload states about itself.
///
/// # Invariant
///
/// A NARROW DECODE OF `undispatched_stage_payload`, not a second copy of it. The
/// producer is `kata-core`'s sole stage-scope payload writer and this is the sole
/// reader; the two agree by EXECUTION — the parity test drives the real writers and
/// folds what comes back — rather than by the field names matching.
///
/// `assignment_id` and `stage_name` are REQUIRED because this class has no
/// `attempts` row to read them off: that absence is what makes it this class. A
/// payload missing either is a malformed frame, not a sparse one.
#[derive(Debug, serde::Deserialize)]
struct StageScopeFacts {
    assignment_id: Ulid,
    stage_name: SmolStr,
    timing: StageScopeTiming,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    child_execution_id: Option<Ulid>,
    #[serde(default, deserialize_with = "present_output")]
    output: Option<serde_json::Value>,
    /// The charge a failed/cancelled stage-scope settlement recorded —
    /// a subworkflow parent's partial `child_invocation_summary` on the child
    /// that ended it.
    #[serde(default)]
    terminal_charge: Option<kata_types::metering::TerminalCharge>,
}

/// Anchors captured from the adjudicated stage transition, never reconstructed
/// from a later row or from the operational transaction's wall-clock timestamp.
#[derive(Debug, serde::Deserialize)]
struct StageScopeTiming {
    #[serde(deserialize_with = "required_nullable")]
    finished_at_ms: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    awaiting_approval_at_ms: Option<u64>,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize>::deserialize(deserializer)
}

// An absent output and a completed JSON null are distinct durable facts.
fn present_output<'de, D>(deserializer: D) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <serde_json::Value as serde::Deserialize>::deserialize(deserializer).map(Some)
}

/// The committed [`AssignmentStatus`] ONE stage-scope transition established.
///
/// # Preserve the complete status before projecting a fold outcome
///
/// They read the same payload and answer different questions, and the difference is
/// a stated obligation rather than a convenience. [`FoldOutcome`] deliberately
/// PROJECTS THE PLACEMENT AWAY — its own doc says so, because the fold reads no
/// placement in any arm this class can reach — and it collapses `pending`,
/// `running` and `stalled` into one `InFlight` arm for the same reason. A PRE-IMAGE
/// cannot project anything away: it is the wire type the caller's mutation is
/// applied to, so a lossy answer would silently change what the mutation produced.
///
/// Routing this through [`FoldOutcome`] would hand back `InFlight` where the
/// un-park gate needs to tell `pending` from a park. Completion is representable
/// without a worker, matching this class's admission rather than inventing one.
///
/// # What it refuses, and why each refusal is a real property
///
/// * `dispatched`, `running`, `stalled` and `resumed` each assert a placement, which
///   CONTRADICTS the admission — the same refusal
///   [`UndeliverableTransitionCause::StageStateOutsideUndispatchedClass`] already
///   makes for a state outside the class.
fn undispatched_stage_status(
    state: &str,
    facts: &StageScopeFacts,
) -> Result<AssignmentStatus, UndeliverableTransitionCause> {
    let missing = |field: &'static str, expected_from: &'static str| {
        UndeliverableTransitionCause::MissingDurableFact {
            state: state.to_string(),
            field,
            expected_from,
        }
    };
    let reason = || {
        facts.reason.clone().ok_or_else(|| {
            missing(
                "reason",
                "the stage-scope transition payload, which carries the reason the \
                 committed status held",
            )
        })
    };
    Ok(match state {
        "pending" => AssignmentStatus::Pending,
        "awaiting_approval" => AssignmentStatus::AwaitingApproval {
            // ALWAYS `None` on this plane, and the wire type says so at its own
            // field: "workers are selected at dispatch time, not pre-gated". So this
            // is the value the fact HAS, not a default standing in for one.
            worker_id: None,
            reason: reason()?,
        },
        "awaiting_child_completion" => AssignmentStatus::AwaitingChildCompletion {
            child_execution_id: facts.child_execution_id.ok_or_else(|| {
                missing(
                    "child_execution_id",
                    "the stage-scope transition payload's child binding",
                )
            })?,
            reason: reason()?,
        },
        "failed" => AssignmentStatus::Failed {
            // This class never reached a worker, so there is no placement to
            // attribute the failure to — the ABSENCE the wire type already
            // documents as its own edge case ("the failure happened before any
            // worker was assigned").
            worker_id: None,
            reason: reason()?,
        },
        // The `failed` arm's placement rule, verbatim: this class never reached a
        // worker, so the absence is the fact rather than a missing one. See
        // refusing here would fail closed at execution granularity.
        "cancelled" => AssignmentStatus::Cancelled {
            worker_id: None,
            reason: reason()?,
        },
        "orphaned" => AssignmentStatus::Orphaned {
            prev_worker: None,
            reason: reason()?,
        },
        "completed" => AssignmentStatus::Completed { worker_id: None },
        other => {
            return Err(
                UndeliverableTransitionCause::StageStateOutsideUndispatchedClass {
                    state: other.to_string(),
                },
            );
        }
    })
}

/// Map ONE STAGE-SCOPE frame.
///
/// # Invariant
///
/// THE KIND IS ENUMERATED, NEVER DEFAULTED. Undispatched admission
/// and settlement produce envelopes; metadata appends are decoded but do not
/// publish a second lifecycle event. Every other kind is a typed refusal.
/// Attribution is established by the transactional writer; this pure mapper
/// validates payload shape, not its relationship to another admission frame.
fn stage_scope_delivery(
    frame: &TransitionFrame,
) -> Result<FrameDelivery, UndeliverableTransitionCause> {
    match frame.kind.as_str() {
        UNDISPATCHED_STAGE_RECORD_KIND => {
            serde_json::from_slice::<kata_core::operational::UndispatchedStageRecordPayload>(
                &frame.payload_json,
            )
            .map_err(
                |error| UndeliverableTransitionCause::MalformedFramePayload {
                    detail: error.to_string(),
                },
            )?;
            Ok(FrameDelivery::NotADeliveryEvent {
                because: "stage metadata amendments do not publish a second lifecycle event",
            })
        }
        UNDISPATCHED_STAGE_ADMITTED_KIND | UNDISPATCHED_STAGE_SETTLED_KIND => {
            let facts: StageScopeFacts =
                serde_json::from_slice(&frame.payload_json).map_err(|error| {
                    UndeliverableTransitionCause::MalformedFramePayload {
                        detail: error.to_string(),
                    }
                })?;
            let status = undispatched_stage_status(frame.resulting_state.as_str(), &facts)?;
            let event = LedgerEventV1 {
                execution_id: frame.execution_id,
                assignment_id: facts.assignment_id,
                stage_name: facts.stage_name,
                new_status: status,
                output: facts.output,
                started_at_ms: None,
                last_checkpoint: None,
                // The stage-scope payload's `terminal_charge`, on a
                // failed/cancelled subworkflow parent.
                terminal_charge: facts.terminal_charge,
            };
            delivery_envelope(frame, event)
        }
        other => Err(UndeliverableTransitionCause::UnknownStageScopeKind {
            kind: other.to_string(),
        }),
    }
}

/// Map a record-only stall observation without feeding it to the lifecycle fold.
pub fn map_stalled_delivery_frame(
    frame: &TransitionFrame,
) -> Result<DeliveryFrame, UndeliverableTransition> {
    let refuse = |detail: String| UndeliverableTransition {
        execution_id: frame.execution_id,
        seq: frame.seq,
        cause: UndeliverableTransitionCause::MalformedFramePayload { detail },
    };
    if frame.scope != ChainScope::Attempt
        || frame.folds_projection
        || frame.kind != "attempt_stalled"
        || frame.resulting_state != "attempt_stalled"
    {
        return Err(refuse(
            "not a record-only attempt_stalled observation".into(),
        ));
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Observation {
        delivery: kata_core::operational::AttemptDeliverySnapshot,
        last_heartbeat_at_ms: u64,
        stalled_for_secs: u64,
    }
    let observation: Observation =
        serde_json::from_slice(&frame.payload_json).map_err(|error| refuse(error.to_string()))?;
    let snapshot = observation.delivery;
    for value in [
        snapshot.dispatched_at_ms,
        snapshot.started_at_ms,
        snapshot.finished_at_ms,
        snapshot.awaiting_approval_at_ms,
        snapshot.last_checkpoint,
    ]
    .into_iter()
    .flatten()
    {
        u64::try_from(value).map_err(|error| refuse(error.to_string()))?;
    }
    let event = LedgerEventV1 {
        execution_id: frame.execution_id,
        assignment_id: frame
            .attempt_id
            .ok_or_else(|| refuse("missing stalled attempt id".into()))?,
        stage_name: SmolStr::new(snapshot.stage_name),
        new_status: AssignmentStatus::Stalled {
            worker_id: SmolStr::new(
                snapshot
                    .worker_id
                    .ok_or_else(|| refuse("missing stalled worker".into()))?,
            ),
            last_heartbeat_at_ms: observation.last_heartbeat_at_ms,
            stalled_for_secs: observation.stalled_for_secs,
        },
        output: None,
        started_at_ms: snapshot
            .started_at_ms
            .map(u64::try_from)
            .transpose()
            .map_err(|error| refuse(error.to_string()))?,
        last_checkpoint: None,
        terminal_charge: None,
    };
    match delivery_envelope(frame, event).map_err(|cause| UndeliverableTransition {
        execution_id: frame.execution_id,
        seq: frame.seq,
        cause,
    })? {
        FrameDelivery::Delivery(frame) => Ok(*frame),
        _ => Err(refuse("stall envelope was not a delivery frame".into())),
    }
}

fn delivery_envelope(
    frame: &TransitionFrame,
    event: LedgerEventV1,
) -> Result<FrameDelivery, UndeliverableTransitionCause> {
    let timestamp =
        chrono::DateTime::from_timestamp_millis(frame.recorded_at_ms).ok_or_else(|| {
            UndeliverableTransitionCause::MalformedFramePayload {
                detail: "transition timestamp is out of range".to_owned(),
            }
        })?;
    let payload = serde_json::to_value(LedgerLogEvent::V1(Box::new(event))).map_err(|error| {
        UndeliverableTransitionCause::MalformedFramePayload {
            detail: error.to_string(),
        }
    })?;
    Ok(FrameDelivery::Delivery(Box::new(DeliveryFrame {
        source_seq: frame.seq,
        execution_id: frame.execution_id,
        event: Event {
            timestamp,
            payload,
            sequence: 0,
        },
    })))
}

/// Map ONE chain frame onto the delivery plane.
///
/// # Invariant
///
/// PURE. The retained frame carries every event fact. No current-row lookup,
/// wall-clock read or random identifier participates in a historical rebuild.
///
/// # Failure
///
/// A state with no wire variant, or a variant with a field the chain does not
/// carry, is a typed refusal. It is never an approximated envelope.
pub fn envelope_for(frame: &TransitionFrame) -> Result<FrameDelivery, UndeliverableTransition> {
    let refuse = |cause| UndeliverableTransition {
        execution_id: frame.execution_id,
        seq: frame.seq,
        cause,
    };
    match frame.scope {
        ChainScope::Stage => return stage_scope_delivery(frame).map_err(refuse),
        ChainScope::Execution => {
            return Ok(FrameDelivery::NotADeliveryEvent {
                because: "execution lifecycle has no assignment-keyed delivery envelope",
            });
        }
        ChainScope::Attempt => {}
    }
    if !frame.folds_projection {
        if frame.kind == "attempt_safe_point" {
            #[derive(serde::Deserialize)]
            struct SafePoint {
                last_checkpoint: i64,
            }
            let payload: SafePoint =
                serde_json::from_slice(&frame.payload_json).map_err(|error| {
                    refuse(UndeliverableTransitionCause::MalformedFramePayload {
                        detail: error.to_string(),
                    })
                })?;
            return Ok(FrameDelivery::Checkpoint {
                source_seq: frame.seq,
                assignment_id: frame.attempt_id.ok_or_else(|| {
                    refuse(UndeliverableTransitionCause::UnattributedAttemptFrame)
                })?,
                last_checkpoint: u64::try_from(payload.last_checkpoint).map_err(|error| {
                    refuse(UndeliverableTransitionCause::MalformedFramePayload {
                        detail: error.to_string(),
                    })
                })?,
            });
        }
        return Ok(FrameDelivery::NotADeliveryEvent {
            because: "record-only attempt metadata does not publish another lifecycle event",
        });
    }
    let attempt_id = frame
        .attempt_id
        .ok_or_else(|| refuse(UndeliverableTransitionCause::UnattributedAttemptFrame))?;
    let payload = DurableFrameFacts::decode(&frame.payload_json).map_err(refuse)?;
    let snapshot = &payload.delivery;
    let state = frame.resulting_state.as_str();
    // A MAIN-RESOLVED attempt (schema 24), named by its transition KIND — the executor
    // latch in `record_transition` makes the three main kinds exactly the frames of main
    // attempts. Its CLAIM is an ordinary `pending` admission and maps below; its PARK is
    // a chain fact with no wire event (nothing was sent, no worker holds it); its
    // RESOLUTION maps like any terminal, with NO worker — `Completed { worker_id: None }`
    // is the wire's own shape for work no worker ran. Refusing any of them here would
    // abort `map_page` for the whole execution at its first main frame.
    let main_resolved = match frame.kind.as_str() {
        kata_core::operational::MAIN_ATTEMPT_PARKED_KIND => {
            return Ok(FrameDelivery::NotADeliveryEvent {
                because: "a main-resolved attempt's park is a chain fact: nothing was sent and \
                          no worker holds it",
            });
        }
        kata_core::operational::MAIN_ATTEMPT_RESOLVED_KIND => {
            if !matches!(state, "completed" | "failed" | "cancelled") {
                return Err(refuse(UndeliverableTransitionCause::NoWireStatusForState {
                    state: state.to_owned(),
                }));
            }
            true
        }
        _ => false,
    };
    if let Some(kind) = payload.kind.as_deref() {
        if kind == "worker_completion" && state == "completed" && frame.kind == "event_accepted" {
            validate_typed_completion(frame, snapshot).map_err(refuse)?;
        } else if kind != state {
            return Err(refuse(
                UndeliverableTransitionCause::FrameKindContradictsState {
                    state: state.to_owned(),
                    kind: kind.to_owned(),
                },
            ));
        }
    }
    let missing = |field, expected_from| {
        refuse(UndeliverableTransitionCause::MissingDurableFact {
            state: state.to_owned(),
            field,
            expected_from,
        })
    };
    let invalid =
        |detail: String| refuse(UndeliverableTransitionCause::MalformedFramePayload { detail });
    let instant = |name: &str, value: Option<i64>| {
        value
            .map(|value| {
                u64::try_from(value)
                    .map_err(|_| invalid(format!("delivery.{name} is negative: {value}")))
            })
            .transpose()
    };
    // Reject corrupt values even when this lifecycle variant does not consume them.
    instant("dispatched_at_ms", snapshot.dispatched_at_ms)?;
    instant("finished_at_ms", snapshot.finished_at_ms)?;
    instant("awaiting_approval_at_ms", snapshot.awaiting_approval_at_ms)?;
    let started_at_ms = instant("started_at_ms", snapshot.started_at_ms)?;
    let last_checkpoint = instant("last_checkpoint", snapshot.last_checkpoint)?;
    let placement = || snapshot.worker_id.as_deref().map(SmolStr::new);
    let worker = || {
        placement().ok_or_else(|| {
            missing(
                "worker_id",
                "the immutable delivery snapshot's addressed worker",
            )
        })
    };
    let reason = || {
        payload
            .reason
            .clone()
            .ok_or_else(|| missing("reason", "the transition's captured state-specific reason"))
    };
    let new_status = match state {
        "pending" => AssignmentStatus::Pending,
        "dispatched" => AssignmentStatus::Dispatched {
            worker_id: worker()?,
        },
        "running" => AssignmentStatus::Running {
            worker_id: worker()?,
        },
        "completed" => AssignmentStatus::Completed {
            worker_id: if main_resolved { None } else { Some(worker()?) },
        },
        "failed" => AssignmentStatus::Failed {
            worker_id: placement(),
            reason: reason()?,
        },
        "cancelled" => AssignmentStatus::Cancelled {
            worker_id: placement(),
            reason: reason()?,
        },
        "orphaned" => AssignmentStatus::Orphaned {
            prev_worker: placement(),
            reason: reason()?,
        },
        "awaiting_approval" => AssignmentStatus::AwaitingApproval {
            worker_id: placement(),
            reason: reason()?,
        },
        "awaiting_child_completion" => AssignmentStatus::AwaitingChildCompletion {
            child_execution_id: snapshot.child_execution_id.ok_or_else(|| {
                missing(
                    "child_execution_id",
                    "the immutable delivery snapshot's child binding",
                )
            })?,
            reason: reason()?,
        },
        "stalled" => {
            return Err(missing(
                "last_heartbeat_at_ms",
                "a separately captured non-lifecycle heartbeat observation",
            ));
        }
        other => {
            return Err(refuse(UndeliverableTransitionCause::NoWireStatusForState {
                state: other.to_owned(),
            }));
        }
    };
    delivery_envelope(
        frame,
        LedgerEventV1 {
            execution_id: frame.execution_id,
            assignment_id: attempt_id,
            stage_name: SmolStr::new(&snapshot.stage_name),
            new_status,
            output: payload.output,
            started_at_ms,
            last_checkpoint,
            // The charge the fused failure adjudication or a main-side
            // terminal writer recorded on this frame — read through the ONE
            // rule: a DISPATCHED attempt's failure-class terminal that recorded
            // none is charged as unknown, never 0 (`TerminalCharge::as_read`).
            terminal_charge: if kata_core::operational::CHARGE_BEARING_ATTEMPT_STATES
                .contains(&state)
            {
                kata_types::metering::TerminalCharge::as_read(
                    payload.terminal_charge.clone(),
                    !main_resolved && snapshot.dispatched_at_ms.is_some(),
                )
            } else {
                payload.terminal_charge.clone()
            },
        },
    )
    .map_err(refuse)
}

/// One mapped frame of a page, in authority order.
///
/// # Invariant
///
/// ONE SEQUENCE. The fold applies frames in STRICT authority order, and a
/// safe point interleaves with the lifecycle envelopes of the same execution,
/// so the page keeps both classes in one ordered list rather than two a caller
/// would have to merge.
#[derive(Clone, Debug)]
pub enum MappedFrame {
    /// An envelope the delivery projector publishes, which the fold also consumes.
    Delivery(DeliveryFrame),
    /// A safe-point update, never a synthesized lifecycle or SSE event.
    Checkpoint {
        /// Authority ordering of the safe-point record.
        source_seq: i64,
        /// Assignment whose checkpoint advanced.
        assignment_id: Ulid,
        /// Adjudicated monotone checkpoint.
        last_checkpoint: u64,
    },
}

impl MappedFrame {
    /// The authority sequence this mapped frame came from.
    #[must_use]
    pub fn source_seq(&self) -> i64 {
        match self {
            MappedFrame::Delivery(frame) => frame.source_seq,
            MappedFrame::Checkpoint { source_seq, .. } => *source_seq,
        }
    }
}

/// ONE delivery envelope decoded back onto exactly what the RUNNER'S FOLD reads.
///
/// # Invariant
///
/// `WorkflowRunner::fold_to_head` touches four things per durable frame — the
/// flat wire event, the instant the chain recorded it, the start anchor, and the
/// checkpoint safe-point — one struct carries all four. Handing the fold a bare [`LedgerEvent`] and leaving it to
/// re-open the versioned envelope for the other two would put a second decoder of
/// one payload in the runner — an ambiguous second reader, a data-loss class.
///
/// The sequence is deliberately absent: on this plane it is
/// [`DeliveryFrame::source_seq`], which the caller already holds and which the
/// page's own cursor advances. Carrying it twice would be two watermarks to
/// disagree.
#[derive(Clone, Debug)]
pub struct FoldableFrame {
    /// The flat wire event `WorkflowRunner::apply_event` folds.
    pub event: LedgerEvent,
    /// The instant (ms since epoch) the chain RECORDED this frame — the instant a
    /// workflow `time_bound` measures a charged frame at, so a resumed fold
    /// measures it exactly as the live fold did, whatever the clock reads then.
    pub recorded_at_ms: u64,
    /// The execution start anchor this frame LEFT.
    pub started_at_ms: Option<u64>,
    /// The worker's durable safe point as of this frame.
    pub last_checkpoint: Option<u64>,
}

/// Decode ONE mapped delivery envelope for the fold.
///
/// # Failure
///
/// FAILS CLOSED ON A SCHEMA THIS BUILD CANNOT READ, and that is the opposite of
/// the in-memory ledger's polarity ON PURPOSE. `InFlightLedger`'s replay decode
/// SKIPS an unknown-schema frame, because it must tolerate a log written by a
/// newer binary. This envelope was minted by [`envelope_for`] microseconds
/// earlier, in this process, from this build's own types — so an undecodable one
/// is not forward-compatibility, it is a contradiction inside one binary, and
/// skipping it would silently drop a lifecycle transition from the plane that
/// DECIDES whether a stage re-runs.
pub fn foldable_frame(frame: &DeliveryFrame) -> KataResult<FoldableFrame> {
    let envelope: LedgerLogEvent =
        serde_json::from_value(frame.event.payload.clone()).map_err(|error| {
            KataError::Storage(format!(
                "runner: the delivery envelope this build minted for execution {} at \
                 transition seq {} did not decode back ({error}); a frame the mapper \
                 produced and the fold cannot read is a contradiction inside one binary, \
                 not a forward-compatible log",
                frame.execution_id, frame.source_seq
            ))
        })?;
    let LedgerLogEvent::V1(v1) = &envelope else {
        return Err(KataError::Storage(format!(
            "runner: the delivery envelope for execution {} at transition seq {} carries \
             schema version {}, which this build does not fold; skipping it would drop a \
             lifecycle transition from the deciding plane",
            frame.execution_id,
            frame.source_seq,
            envelope.schema_version()
        )));
    };
    let recorded_at_ms = u64::try_from(frame.event.timestamp.timestamp_millis()).map_err(|_| {
        KataError::Storage(format!(
            "runner: the delivery envelope for execution {} at transition seq {} was recorded \
             at {}, before the epoch, so no time bound can measure it",
            frame.execution_id, frame.source_seq, frame.event.timestamp
        ))
    })?;
    Ok(FoldableFrame {
        event: LedgerEvent::from(v1.as_ref()),
        recorded_at_ms,
        started_at_ms: v1.started_at_ms,
        last_checkpoint: v1.last_checkpoint,
    })
}

/// One page of the authority chain, mapped onto what each plane consumes.
#[derive(Clone, Debug)]
pub struct MappedDeliveryPage {
    /// Every frame that carries meaning, in AUTHORITY ORDER — see [`MappedFrame`]
    /// for why this is one ordered sequence rather than a list per plane.
    pub mapped: Vec<MappedFrame>,
    /// The chain cursor to resume from — carried straight through from the chain
    /// reader, so a frame that produced no envelope is still consumed exactly once.
    pub next_from_seq: i64,
    /// Whether the chain page reached the execution's durable tail.
    pub reached_tail: bool,
}

/// The state ONE ASSIGNMENT of an execution has REACHED on the authority chain,
/// in the ROW shape.
///
/// # Why the PREDICATE reader could not serve this
///
/// [`ChainStageState`](kata_core::operational::ChainStageState) is the chain's
/// answer for the runner's fold-path PREDICATES — "has this halt row been recorded", "is this bound
/// already spent" — and it carries a bare state string and nothing else. Eight kata-api authority
/// reads need the same scan and a different shape: they read the completion's OUTPUT, they
/// discriminate a cancellation on the failure's REASON PREFIX, and they order competing
/// completions. A state string answers none of those, so a stage-scope fold could not move them
/// however the predicates went.
///
/// # Invariant
///
/// ONE DECODER, AND IT IS [`envelope_for`]'s. Every field below is folded from
/// what the MAPPER produced for the same frames the runner's `fold_to_head`
/// consumes — never re-decoded from `payload_json` a second way. Two
/// implementations of one payload rule is a data-loss class: if this reader and
/// the mapper could disagree about
/// what a transition says, the disagreement IS the defect. They cannot, because
/// there is one `match` and both call it.
///
/// # Invariant
///
/// NOTHING HERE IS SYNTHESIZED. [`FoldOutcome`] is the mapper's own two-producer
/// vocabulary, and its arms carry exactly the facts the chain durably holds: the
/// reason rides [`MainSideTransition::reason`](kata_core::operational::MainSideTransition)
/// into the payload, the output rides beside it, and a state whose required fact
/// is missing is a TYPED REFUSAL from `envelope_for` rather than a fabricated
/// row. A caller therefore never has to tell an invented value from a durable
/// one, because no invented value can reach it.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainAssignmentState {
    pub assignment_id: Ulid,
    pub execution_id: Ulid,
    pub stage_name: SmolStr,
    /// The lifecycle status the last lifecycle frame established — the api's
    /// record layer matches on its variants directly.
    pub status: AssignmentStatus,
    /// The durable output a terminal carries.
    pub output: Option<serde_json::Value>,
    /// The charge a failure-class terminal carried.
    pub terminal_charge: Option<kata_types::metering::TerminalCharge>,
    /// Latest lifecycle status and output, including later output amendments.
    pub outcome: FoldOutcome,
    /// Sequence of the latest lifecycle frame, excluding metadata-only appends.
    pub settled_seq: i64,
    /// Captured terminal timestamp; workerless completions may also carry it.
    pub finished_at_ms: Option<i64>,
    /// Captured worker start timestamp, absent when no worker started.
    pub started_at_ms: Option<i64>,
}

impl ChainAssignmentState {
    /// Whether the assignment's chain folds to a COMPLETION.
    ///
    /// Spelled once, because six of the eight moved call sites filter on exactly
    /// this and a `matches!` per site is six places for the classification to
    /// drift — the shape [`ChainStageState::is`](kata_core::operational::ChainStageState::is)
    /// exists for one scope down.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self.outcome, FoldOutcome::Completed { .. })
    }

    /// Whether the assignment is parked at an APPROVAL GATE.
    #[must_use]
    pub fn is_awaiting_approval(&self) -> bool {
        matches!(self.outcome, FoldOutcome::AwaitingApproval { .. })
    }

    /// Whether the assignment's chain folds to an OPERATOR CANCELLATION.
    ///
    /// A lifecycle read, not a prose match on the reason prefix `"cancelled:"`:
    /// the standing-stop branch rewrites the worker's reason before the terminal
    /// is written, so a prefix match would report every honoured cancel as
    /// `Failed` and skip the stop-ack parking gate. Spelled here beside
    /// [`Self::is_completed`] for the reason that one gives: one classification,
    /// one place.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self.outcome, FoldOutcome::Cancelled { .. })
    }

    /// Whether the assignment's chain folds to a TERMINAL state.
    ///
    /// Delegates to [`FoldOutcome::is_terminal`], the one classification of
    /// "finished", so this carrier holds no list of its own.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.outcome.is_terminal()
    }

    /// The durable output the COMPLETION carries.
    ///
    /// Structurally `Some` only for [`FoldOutcome::Completed`] — no other arm of
    /// the fold vocabulary has an output, because no other durable state carries
    /// one ([`MainSideTransition::from_status`](kata_core::operational::MainSideTransition::from_status)
    /// filters the payload copy to terminals, and the wire type only ever
    /// populated it for a completion). `None` is therefore "this assignment did
    /// not complete, or completed with no durable output"; a caller that must
    /// tell those apart pairs this with [`Self::is_completed`], which is what
    /// every moved call site does.
    #[must_use]
    pub fn output(&self) -> Option<&serde_json::Value> {
        match &self.outcome {
            FoldOutcome::Completed { output } => output.as_ref(),
            _ => None,
        }
    }

    /// The operator-facing reason a FAILURE carries, and only a failure's.
    ///
    /// Deliberately NOT widened to `Cancelled` / `Orphaned` / `AwaitingApproval`,
    /// which also carry reasons. It has ONE prefix-discriminating consumer:
    /// `agent run timed out` decides a `TimedOut` verdict (a cancellation is
    /// [`Self::is_cancelled`], a lifecycle read). Widening this method is
    /// what would silently move the surviving decision — the ambiguous-name
    /// class, arriving as a behaviour change rather than a compile error. A
    /// `Cancelled` fold answers `None` here BY CONSTRUCTION, which is what keeps
    /// the timeout reader from inheriting an operator stop.
    #[must_use]
    pub fn failure_reason(&self) -> Option<&str> {
        match &self.outcome {
            FoldOutcome::Failed { reason, .. } => Some(reason.as_str()),
            _ => None,
        }
    }

    /// The operator-facing message a TERMINAL FAILURE states.
    ///
    /// The chain-plane twin of `kata_api`'s `failure_message`, kept
    /// byte-identical (`stage {name} failed: {reason}`) because it is surfaced as
    /// `ExecutionRecord::error` and as an agent run's `error`, both of which
    /// operators read through REST `GET /executions/{id}` and the CLI.
    #[must_use]
    pub fn failure_message(&self) -> Option<String> {
        match &self.outcome {
            FoldOutcome::Failed { reason, .. } => {
                Some(format!("stage {} failed: {reason}", self.stage_name))
            }
            // A cancel states its own verb rather than inheriting `failed`: an
            // operator stop reaches `ExecutionRecord::error` as
            // `stage {name} cancelled: {reason}`, never as a "failed" about a run
            // the operator ended on purpose.
            FoldOutcome::Cancelled { reason, .. } => {
                Some(format!("stage {} cancelled: {reason}", self.stage_name))
            }
            FoldOutcome::Orphaned { reason, .. } => {
                Some(format!("stage {} orphaned: {reason}", self.stage_name))
            }
            _ => None,
        }
    }
}

/// Reads the authority chain through the operational chain reader and emits the
/// envelopes the delivery plane publishes.
///
/// # Invariant
///
/// A READER AND A MAPPER, NEVER A WRITER. This type does not touch
/// `ledger_events.db`; it produces [`DeliveryFrame`]s for
/// [`DeliveryProjector::project`](kata_core::operational::delivery::DeliveryProjector::project),
/// which owns allocation, the cursor, and the transaction. Splitting it this way
/// is what keeps the delivery plane rebuildable from the retained chain.
pub struct AttemptDeliveryMapper {
    db: Arc<OperationalDb>,
}

impl std::fmt::Debug for AttemptDeliveryMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttemptDeliveryMapper")
            .finish_non_exhaustive()
    }
}

impl AttemptDeliveryMapper {
    /// Adopt `db` as the authority plane.
    #[must_use]
    pub fn new(db: Arc<OperationalDb>) -> Self {
        Self { db }
    }

    /// Reconstruct each assignment's latest lifecycle, timing and metadata from
    /// one captured authority prefix, in admission order. Mutable attempt rows
    /// and the in-memory ledger projection do not participate. Unreadable authority refuses
    /// the whole population; later appends are deferred to the next read.
    pub fn execution_assignment_states(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<ChainAssignmentState>> {
        self.execution_assignment_states_after_fold(execution_id, || {})
    }

    pub(crate) fn execution_assignment_states_after_fold(
        &self,
        execution_id: Ulid,
        after_fold: impl FnOnce(),
    ) -> KataResult<Vec<ChainAssignmentState>> {
        self.chain_states_after_capture(execution_id, after_fold)
    }

    /// Map one page of `execution_id`'s chain, starting at `from_seq`.
    ///
    /// # Failure
    ///
    /// FAIL CLOSED AT EXECUTION GRANULARITY, ON A GENUINELY UNMAPPABLE FRAME. A
    /// single transition this mapper cannot express aborts the whole page with a
    /// typed refusal naming the execution, the sequence, and the missing fact. It
    /// does not emit the frames before it and drop the rest: a partially delivered
    /// execution is a client that believes it has the whole story, and a partially
    /// folded one is a runner that redoes finished work.
    ///
    /// # What is NOT a failure
    ///
    /// A frame with no WIRE envelope. A two-outcome shape would make that the same
    /// answer as "carries nothing", so a safe point would be skipped and lost —
    /// silently, because the refusal never fires. The outcomes are kept apart: a
    /// [`FrameDelivery::Checkpoint`] is KEPT, in authority order, a
    /// [`FrameDelivery::NotADeliveryEvent`] is skipped, and only a
    /// [`UndeliverableTransition`] aborts the page.
    pub fn map_page(
        &self,
        execution_id: Ulid,
        from_seq: i64,
        limit: usize,
    ) -> KataResult<MappedDeliveryPage> {
        let page = self
            .db
            .read_transitions_for_execution(execution_id, from_seq, limit)?;
        let mut mapped = Vec::with_capacity(page.frames.len());
        for frame in &page.frames {
            let frame = self.db.resolve_transition_output(frame)?;
            absorb(envelope_for(&frame)?, &mut mapped);
        }
        Ok(MappedDeliveryPage {
            mapped,
            next_from_seq: page.next_from_seq,
            reached_tail: page.reached_tail,
        })
    }
}

/// Place ONE adjudicated frame into the page.
///
/// A total `match`, so every outcome states what it means here: a safe point is
/// KEPT as [`MappedFrame::Checkpoint`], and only a frame correctly absent from
/// both planes is skipped.
fn absorb(delivery: FrameDelivery, mapped: &mut Vec<MappedFrame>) {
    match delivery {
        FrameDelivery::Delivery(envelope) => mapped.push(MappedFrame::Delivery(*envelope)),
        FrameDelivery::Checkpoint {
            source_seq,
            assignment_id,
            last_checkpoint,
        } => {
            mapped.push(MappedFrame::Checkpoint {
                source_seq,
                assignment_id,
                last_checkpoint,
            });
        }
        FrameDelivery::NotADeliveryEvent { .. } => {}
    }
}
