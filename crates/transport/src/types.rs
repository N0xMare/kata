//! Transport-layer types.
//!
//! The wire vocabulary between a main and a worker: the capsule dispatch
//! frame, the worker's reports (checkpoints, terminals, progress, recovery),
//! and the control frames a main commands with.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use ulid::Ulid;

use kata_types::effect::{DeliveryFailureProvenance, ProviderFailureClass};
use kata_types::error::KataResult;
use kata_types::execution_contract::{CapsuleId, OccurrenceId};
use kata_types::primitives::ObjectId;
use kata_types::sandbox::SharedFilesystemPresumption;

/// The version of the attempt fencing contract this build speaks.
///
/// Carried on [`AttemptFence::protocol_version`] so the main can tell a sender
/// that speaks the contract from one that does not. `0` is not a version: it is
/// what [`AttemptFence::protocol_version`]'s `#[serde(default)]` produces for a
/// frame that carries no fence, and the ingress fence refuses it by
/// name rather than letting it decode into an unfenced transition.
pub const ATTEMPT_PROTOCOL_VERSION: u16 = 1;

/// WHO, and under WHICH generation of the attempt.
///
/// The same three coordinates now travel in BOTH directions and mean the mirror
/// of each other. On a [`WorkerMessage`] they say who is REPORTING; on a
/// [`WorkerControl`] they say who is being COMMANDED. One durable column
/// (`attempts.lease_epoch`) backs both, which is what lets the two sides compare
/// them at all — see [`Self::echoing_capsule`] and [`Self::commanding`] for why only one
/// side is allowed to mint.
///
/// # The defect this type exists to make unwritable
///
/// The attempt-terminal inbox seam already refuses a DUPLICATE frame
/// (`EventAcceptance::IdempotentAck` in `kata-core`, which sits BELOW this crate, so
/// it is named rather than linked). Two adversaries it structurally cannot
/// refuse, because nothing on the frame names them, are:
///
/// * **wrong-worker** — a frame reporting on an attempt that is durably placed
///   on a DIFFERENT worker. `attempts.worker_id` records the placement and the
///   frame named no sender, so the two were never compared.
/// * **stale generation** — a frame from generation N arriving after the attempt
///   has advanced to N+1. `crates/core/src/operational/inbox.rs` named this
///   exactly, BEFORE this struct existed: *"a STALE frame from generation N
///   redelivered after the attempt has advanced to N+1 is keyed to N+1.
///   Distinguishing it requires a frame ordinal on the wire; it cannot be closed
///   main-side."* (That doc is updated in place; the quote is kept here as the
///   statement of the defect, not as a live claim.)
///
/// The OUTBOUND half of that fence is the dispatch writer, which files each
/// command under the attempt's current `lease_epoch`; refusing an INBOUND frame
/// needs a wire field, and this struct is that field. Both halves read the same
/// durable column; only the direction differs.
///
/// # Why the sender is carried even though the connection identifies it
///
/// A reactor reads one worker's transport, so it already knows which worker sent
/// a frame. Carrying the claim anyway buys two distinct checks against two
/// distinct adversaries, and neither subsumes the other:
///
/// * frame sender vs CONNECTION identity catches a worker reporting under
///   another worker's name — a lie, which only a certified identity can refuse;
/// * frame sender vs DURABLE PLACEMENT catches an honest worker reporting on an
///   attempt that is not its own — a routing or recovery fault, where nobody
///   lied.
///
/// # Compatibility
///
/// Every field is `#[serde(default)]` so a frame without a fence DECODES rather
/// than erroring, and is then refused by name at the ingress fence. A decode error
/// would surface as transport death for the whole connection; a typed refusal
/// names the attempt and the reason and leaves the transport up.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptFence {
    /// The fencing contract this frame's sender speaks.
    ///
    /// `0` means the sender carries no fencing facts at all; it is refused
    /// rather than trusted. See [`ATTEMPT_PROTOCOL_VERSION`].
    #[serde(default)]
    pub protocol_version: u16,
    /// The attempt generation this frame reports on, echoed from
    /// [`CapsuleAssignment::lease_epoch`].
    ///
    /// NOT defaulted to a sentinel: `0` is a legitimate epoch (a claim lands at
    /// `lease_epoch` 0 and its dispatch bumps it), so an absent epoch is
    /// indistinguishable from a first-generation one by value. That is precisely
    /// why [`Self::protocol_version`] carries the "did the sender speak at all"
    /// question instead of overloading this field.
    #[serde(default)]
    pub lease_epoch: i64,
    /// The worker this frame CLAIMS to come from, echoed from
    /// [`CapsuleAssignment::placed_on`].
    #[serde(default)]
    pub worker_id: SmolStr,
}

impl AttemptFence {
    /// ECHO the generation and placement the main stamped on a
    /// [`CapsuleAssignment`], copied, never minted. A worker that could choose its own
    /// epoch could not be fenced by one. The one spelling every capsule frame a worker
    /// sends carries — its start checkpoint, its completion, and every refusal.
    #[must_use]
    pub fn echoing_capsule(capsule: &CapsuleAssignment) -> Self {
        Self {
            protocol_version: ATTEMPT_PROTOCOL_VERSION,
            lease_epoch: capsule.lease_epoch,
            worker_id: capsule.placed_on.clone(),
        }
    }

    /// Build the fence the MAIN mints to command a worker.
    ///
    /// The sibling above says "the worker never mints these coordinates", and
    /// that stays true in its own direction. The main is a different case: it is
    /// the ALLOCATOR of `attempts.lease_epoch` (bumped inside the dispatch
    /// transaction), so it does not echo a fence — it states the generation it
    /// has decided to act on, read from the durable row at that instant. That is
    /// deliberately NOT "whatever epoch some frame I am holding happens to say":
    /// the worker obeys a command only at the epoch its dispatch was fenced at,
    /// and the row is where that epoch is recorded.
    ///
    /// Two constructors rather than one, so the two mint sites keep their two
    /// separate justifications where a reader will meet them.
    #[must_use]
    pub fn commanding(lease_epoch: i64, worker_id: SmolStr) -> Self {
        Self {
            protocol_version: ATTEMPT_PROTOCOL_VERSION,
            lease_epoch,
            worker_id,
        }
    }
}

/// Control frames flowing from the main side TO a worker.
///
/// # Why this is a separate sum from the dispatch frame
///
/// The main→worker direction carries a dispatch frame; a stop is not a
/// dispatch and must not be expressible as one.
///
/// # Every frame is FENCED
///
/// [`Self::Stop`] carries an [`AttemptFence`] for the same reason every inbound
/// attempt-scoped frame does, in the opposite direction: one assignment id spans
/// generations, so an unfenced stop is a cross-generation kill of whichever
/// attempt happens to be running now. The worker compares the fence against the
/// assignment it holds and ignores a stale one — a refusal to act, not an error,
/// because a stop for a generation that already ended is satisfied by definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum WorkerControl {
    Enrollment(crate::enrollment::EnrollmentControl),
    /// Recovery is scoped to a configured effect domain, not an attempt lease.
    Recovery(kata_types::recovery::RecoveryCommand),
    /// Stop the named attempt if this worker still holds that generation of it.
    Stop {
        /// The attempt being stopped.
        assignment_id: Ulid,
        /// The generation and worker this stop is for. See the type's doc.
        #[serde(default)]
        fence: AttemptFence,
        /// The operator's stated reason, carried for the record an operator reads.
        #[serde(default)]
        reason: String,
    },
}

impl WorkerControl {
    /// Attempt-scoped commands return their fence. Recovery instead carries
    /// its mandatory full domain and artifact/request/generation correlation.
    #[must_use]
    pub const fn fenced_attempt(&self) -> Option<(Ulid, &AttemptFence)> {
        match self {
            Self::Stop {
                assignment_id,
                fence,
                ..
            } => Some((*assignment_id, fence)),
            Self::Recovery(_) | Self::Enrollment(_) => None,
        }
    }
}

/// The trace context a frame carries for propagation —
/// `traceparent`/`tracestate` as one value because they are one carrier:
/// `opentelemetry_sdk::propagation::TraceContextPropagator`'s injector writes
/// both or neither.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceContext {
    /// The `traceparent` header value, verbatim. Empty means "no context".
    pub traceparent: String,
    /// The `tracestate` companion value, verbatim.
    pub trace_state: String,
}

impl TraceContext {
    /// Whether there is any context to propagate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.traceparent.is_empty() && self.trace_state.is_empty()
    }
}

/// HOW a worker gets the capsule's bytes: its identity, the CAS object holding
/// its canonical serialization, and that object's length.
///
/// [`CapsuleId`] is `blake3` over the capsule's FIELDS, not over its
/// serialization, so it is not a CAS address: nothing can be read from it.
/// `object` is the address and `size_bytes` is the bound a verified read needs
/// BEFORE it allocates. The three are checked against each other on the worker
/// side (`kata_worker::capsule_frame::resolve`), which is what makes a frame
/// naming one capsule and another capsule's bytes a refusal rather than a
/// substitution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleRef {
    /// The capsule's identity, folding every field of it.
    pub id: CapsuleId,
    /// The CAS object holding the capsule's canonical serialization.
    pub object: ObjectId,
    /// That object's canonical byte length.
    pub size_bytes: u64,
}

/// A dispatch that hands a worker a CAPSULE REFERENCE and nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleAssignment {
    /// The attempt this dispatch discharges — `attempts.attempt_id`.
    pub attempt_id: Ulid,
    /// The execution the attempt belongs to.
    pub execution_id: Ulid,
    /// The logical occurrence the attempt is a generation of. Compared against the
    /// referenced capsule's own occurrence by the worker's resolver; see the type
    /// docs for why the apparent duplication is the mechanism.
    pub occurrence_id: OccurrenceId,
    /// Where the capsule's bytes are, and how long they are.
    pub capsule: CapsuleRef,
    /// The attempt generation this dispatch belongs to — `attempts.lease_epoch`.
    /// Stamped on the outgoing clone, never carried at rest. `0` is the legitimate
    /// first generation of every attempt, so an absent epoch is never defaulted —
    /// see [`AttemptFence::protocol_version`].
    pub lease_epoch: i64,
    /// The worker this dispatch was PLACED on, stamped by
    /// `WorkerPoolSupervisor`'s send boundary at the one seam that knows it.
    ///
    /// # Why the capsule arm carries it too
    ///
    /// The worker ECHOES it on every event it reports
    /// ([`AttemptFence::worker_id`]), which is what lets the main compare a report's
    /// claimed sender against `attempts.worker_id`. A capsule worker that named
    /// ITSELF instead would be fine for a completion — `capsule_execution` uses its
    /// own enrolled id there, which is strictly stronger — but a frame REFUSED at
    /// the admission door has no execution context to ask, and a refusal the main
    /// cannot attribute to a worker and a generation is one it must either trust
    /// blindly or drop. One fence mechanism across both arms, rather than two.
    ///
    /// Empty means "not stamped": that is the at-rest value, because a placement is
    /// a PER-DISPATCH fact, chosen after the claim wrote the at-rest blob.
    #[serde(default)]
    pub placed_on: SmolStr,
    /// The durable dispatch command this delivery discharges —
    /// `attempt_commands.command_id`. `None` at rest and on a delivery that names no
    /// durable command.
    pub command_id: Option<Ulid>,
    /// Durable enrollment of the receiving membrane, stamped at the physical send
    /// boundary. `None` at rest.
    pub effect_domain: Option<kata_types::identity::WorkerEffectDomain>,
    /// Epoch milliseconds by which the worker must begin. `None` when the node
    /// configures no start deadline.
    pub start_deadline_ms: Option<u64>,
    /// The stage's authored `progress_visibility` — how much of a running
    /// capsule's output and session events may stream to the main as
    /// `WorkerMessage::CapsuleProgress` frames.
    ///
    /// Carried on the FRAME and never in the capsule: visibility is a
    /// per-stage authored fact, and one capsule can serve two stages that
    /// authored different visibility — folding it into the capsule's hashed
    /// body would bind the knob to the wrong identity twice over (a reuse
    /// whose stage authors `full` must not stream under a capsule hashed
    /// when its first author wrote `off`). `Off` emits nothing.
    ///
    /// REQUIRED, like every non-`Option` field on this struct: the capsule
    /// arm carries no serde tolerance (see [`DispatchFrame`]'s type docs), so
    /// an older sender's frame fails at the decode instead of being read as
    /// `Off` — a silently-downgraded authored visibility would be exactly
    /// the "authored knob silently ignored" defect the field exists to close.
    pub progress_visibility: kata_types::workflow::ProgressVisibility,
    /// The trace context to continue under. Empty when the dispatcher is not inside
    /// an exporting span.
    pub trace: TraceContext,
}

impl CapsuleAssignment {
    /// Every place this frame names a path that only the MAIN's filesystem
    /// resolves. ALWAYS EMPTY, and the exhaustive destructure below is why that is a
    /// mechanism rather than a claim.
    ///
    /// # This is the inventory's whole point
    ///
    /// The capsule frame's answer is empty, and
    /// the only way to keep it empty as the type grows is to make a path-shaped
    /// field fail to compile here — which binding every field by name, with no `..`
    /// rest pattern, does (`error[E0027]: pattern does not mention field`).
    ///
    /// The reach is stated exactly: it is
    /// NOT transitive into [`CapsuleRef`] (three content identities and a length,
    /// none path-shaped) and not into the referenced capsule's bytes, whose
    /// `GuestPath`s are GUEST paths refused at construction from being anything
    /// else.
    #[must_use]
    pub fn shared_filesystem_presumptions(&self) -> Vec<SharedFilesystemPresumption<'_>> {
        let Self {
            // ULIDs and content identities.
            attempt_id: _,
            execution_id: _,
            occurrence_id: _,
            // Content identity, CAS address, length. See the reach note.
            capsule: _,
            // Counters and durable keys.
            lease_epoch: _,
            // A worker id, never a path.
            placed_on: _,
            command_id: _,
            effect_domain: _,
            start_deadline_ms: _,
            // An authored enum, never a path.
            progress_visibility: _,
            // Opaque W3C header values, never paths.
            trace: _,
        } = self;
        Vec::new()
    }
}

/// WHICH dispatch shape one attempt's work unit is.
///
/// One arm remains: the [`CapsuleAssignment`], a reference to an immutable
/// capsule plus the per-dispatch facts the main stamps at delivery
/// (`lease_epoch`, `command_id`, `start_deadline_ms`).
///
/// The enum stays because its serde arm tag (`{"capsule": {…}}`) is the
/// durable/wire shape and `Dispatcher::frame_for_dispatch` reads the stamped
/// fields through the arm. A deleted second arm would tempt nobody to add it
/// back: the enum was the seam that let two engines share one wire, and there
/// is one engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchFrame {
    /// A reference to an immutable capsule, plus the per-dispatch facts. Boxed —
    /// the payload is ~300 bytes and a second arm does not exist to balance it
    /// against; the `Box` is kept so a future arm lands without a churn pass.
    Capsule(Box<CapsuleAssignment>),
}

impl DispatchFrame {
    /// The attempt this frame's work belongs to.
    ///
    /// `CapsuleAssignment::attempt_id` IS the attempt id on the authority chain
    /// (the claim writes it as `attempts.attempt_id`).
    #[must_use]
    pub fn attempt_id(&self) -> Ulid {
        match self {
            Self::Capsule(capsule) => capsule.attempt_id,
        }
    }

    /// The generation this frame was stamped for.
    #[must_use]
    pub fn lease_epoch(&self) -> i64 {
        match self {
            Self::Capsule(capsule) => capsule.lease_epoch,
        }
    }

    /// The durable dispatch command this frame discharges, if it names one.
    #[must_use]
    pub fn command_id(&self) -> Option<Ulid> {
        match self {
            Self::Capsule(capsule) => capsule.command_id,
        }
    }

    /// The instant by which the worker must begin, if the node set one.
    #[must_use]
    pub fn start_deadline_ms(&self) -> Option<u64> {
        match self {
            Self::Capsule(capsule) => capsule.start_deadline_ms,
        }
    }

    /// STAMP the three PER-DISPATCH facts onto this (outgoing) frame.
    ///
    /// # Invariant
    ///
    /// The delivery clone and the durable blob differ, deliberately and in
    /// exactly these fields: the claim writes the blob before the dispatch
    /// allocates the epoch, the command and the deadline, so a value baked in
    /// at construction would be one the row never held.
    /// `Dispatcher::frame_for_dispatch` reads all three off the durable row at
    /// delivery and calls this; nothing else may.
    pub fn stamp_for_dispatch(
        &mut self,
        lease_epoch: i64,
        command_id: Option<Ulid>,
        start_deadline_ms: Option<u64>,
    ) {
        match self {
            Self::Capsule(capsule) => {
                capsule.lease_epoch = lease_epoch;
                capsule.command_id = command_id;
                capsule.start_deadline_ms = start_deadline_ms;
            }
        }
    }

    /// THE DISK DOOR: this frame's DURABLE projection.
    ///
    /// The `Capsule` arm borrows, and it is entitled to: the arm has no field a
    /// secret value can inhabit —
    /// [`CapsuleAssignment::shared_filesystem_presumptions`]'s destructure is
    /// the same guard applied to the same field list — and the capsule's own
    /// `secret_tokens` never leave the main, because the capsule commits to a
    /// PERMISSIONS HASH rather than to the directive.
    #[must_use]
    pub fn durable_record(&self) -> Cow<'_, Self> {
        match self {
            Self::Capsule(_) => Cow::Borrowed(self),
        }
    }

    /// Every place this frame names a path only the MAIN's filesystem resolves.
    ///
    /// Empty by construction for the one arm; `just`'s capsule gate —
    /// "`shared_filesystem_presumptions()` is empty for every production
    /// frame" — is a statement about this function.
    #[must_use]
    pub fn shared_filesystem_presumptions(&self) -> Vec<SharedFilesystemPresumption<'_>> {
        match self {
            Self::Capsule(capsule) => capsule.shared_filesystem_presumptions(),
        }
    }

    /// The dispatch arm this frame carries, as its recorded label.
    ///
    /// The one derivation of "arm ↔ label" in the workspace — the label a
    /// caller records in its own evidence rather than matching the arm itself.
    #[must_use]
    pub const fn arm_label(&self) -> &'static str {
        match self {
            Self::Capsule(_) => "capsule",
        }
    }
}

/// A [`DispatchFrame`] that has passed its main-side authority check.
///
/// The one remaining arm — `Capsule` — has NOTHING to check here, and that is
/// a property of the type rather than an omission: a [`CapsuleAssignment`]
/// cannot express a host path, an environment map or a secret
/// ([`CapsuleAssignment::shared_filesystem_presumptions`] is total, empty, and
/// guarded by an exhaustive destructure), so there is no hydration to verify
/// and no credential to scrub. What a capsule frame IS checked against is the
/// bytes it names, and those bytes are not on the main's side of the frame:
/// that is `kata_worker::capsule_frame`'s resolver's five refusals, at the
/// door that reads them.
///
/// The wrapper stays because the send boundary demands a witness — it is how
/// `WorkerTransport::dispatch` knows a frame was admitted, not merely
/// constructed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedDispatchFrame {
    frame: DispatchFrame,
}

impl CheckedDispatchFrame {
    /// Wrap `frame` for checked dispatch.
    pub fn new(frame: DispatchFrame) -> KataResult<Self> {
        Ok(Self { frame })
    }

    /// Borrow the validated frame.
    #[must_use]
    pub fn frame(&self) -> &DispatchFrame {
        &self.frame
    }

    /// Consume the wrapper and recover the wire frame for transport.
    #[must_use]
    pub fn into_inner(self) -> DispatchFrame {
        self.frame
    }

    /// The attempt this frame's work belongs to.
    #[must_use]
    pub fn attempt_id(&self) -> Ulid {
        self.frame.attempt_id()
    }

    /// The dispatch arm this frame carries, as its recorded label.
    #[must_use]
    pub const fn arm_label(&self) -> &'static str {
        self.frame.arm_label()
    }
}

/// A durable checkpoint emitted during stage execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageCheckpoint {
    /// The assignment this checkpoint belongs to.
    pub assignment_id: Ulid,
    /// Human-readable stage name.
    pub stage_name: SmolStr,
    /// Checkpoint payload (opaque JSON).
    pub output: serde_json::Value,
    /// Monotonic sequence number within the assignment.
    pub sequence: u64,
    /// Who is reporting, under which generation. See [`AttemptFence`].
    ///
    /// A checkpoint is authority-mutating: sequence 0 promotes the attempt to
    /// `running` and sets `started_at_ms`, the anchor BOTH deadline sweeps read,
    /// and every checkpoint advances the durable `attempts.last_checkpoint` safe
    /// point. So it is fenced on exactly the same terms as a terminal frame — an
    /// unfenced checkpoint from a superseded generation would re-anchor a live
    /// attempt's deadline.
    #[serde(default)]
    pub fence: AttemptFence,
}

/// The stage name a CAPSULE attempt's checkpoints carry. A capsule frame names no stage —
/// its identity is the capsule — so the worker reports this fixed label.
pub const CAPSULE_CHECKPOINT_STAGE_NAME: &str = "capsule";

impl StageCheckpoint {
    /// The START checkpoint — sequence 0, `{"event": "started"}` — a worker sends
    /// immediately before it runs an attempt. The main folds sequence 0 as `running` with
    /// `started_at_ms`, the anchor its deadline sweeps measure from, so this is the one
    /// spelling of that frame for every sender.
    #[must_use]
    pub fn started(assignment_id: Ulid, stage_name: SmolStr, fence: AttemptFence) -> Self {
        Self {
            assignment_id,
            stage_name,
            output: serde_json::json!({ "event": "started" }),
            sequence: 0,
            fence,
        }
    }

    /// [`Self::started`] for a CAPSULE attempt, fenced by [`AttemptFence::echoing_capsule`].
    #[must_use]
    pub fn capsule_started(capsule: &CapsuleAssignment) -> Self {
        Self::started(
            capsule.attempt_id,
            SmolStr::new(CAPSULE_CHECKPOINT_STAGE_NAME),
            AttemptFence::echoing_capsule(capsule),
        )
    }
}

/// Messages flowing from workers back to the main side.
///
/// `CompletedCapsule`'s payload (three artifact references, a fence, a
/// provenance) pushed the variant spread past `clippy::large_enum_variant` —
/// the same recourse `crate::local_socket::Envelope` takes for the same
/// arithmetic: one frame exists between a `send` and a `recv`, so boxing would
/// pay a heap allocation per message to save stack the message already
/// occupies.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum WorkerMessage {
    EnrollmentProbe(crate::enrollment::EnrollmentProbe),
    EnrollmentProof {
        proof: [u8; 32],
    },
    Recovery(kata_types::recovery::RecoveryReply),
    /// Intermediate checkpoint during stage execution.
    Checkpoint(StageCheckpoint),
    /// A CAPSULE attempt completed, and the RESULT is a published tree artifact.
    ///
    /// The only terminal-success frame. It carries no result bytes inline: the
    /// result is an [`ArtifactRef`], a content ADDRESS whose bytes are already
    /// fsync-durable in the shared content store and whose adoption is a verified
    /// read, a bound check against the capsule's own `result_bytes`/`result_entries`,
    /// and an `artifacts` row owned by the execution.
    ///
    /// It is also how the main knows which BOUND to hold the result to: the bound
    /// lives in the capsule, the capsule is named by the occurrence's row, and only
    /// a frame that reports on a capsule attempt has one.
    ///
    /// # The `/work` DIFF
    ///
    /// `work_delta` is the companion to `result`: where `result` is the
    /// `/out` tree republished whole, this is the capsule's mutation of its `/work`
    /// input as a [`kata_types::tree_delta::TreeDelta`] artifact — a sorted
    /// `path → {write | delete}` list named against the ONE base the capsule
    /// mapped. `None` means the capsule carried no `/work` mapping — NOT that the
    /// mapping was unchanged: a mapped `/work` the stage left untouched reports
    /// `Some` of an EMPTY delta, because "no delta" and "no `/work`" are different
    /// facts and the adopting side holds them apart.
    ///
    /// The reference names the delta's canonical bytes in the shared content
    /// store; the base it applies to is INSIDE those bytes
    /// (`TreeDelta::base`), so the wire needs no second field for it.
    ///
    /// [`ArtifactRef`]: kata_types::execution_contract::ArtifactRef
    CompletedCapsule {
        /// The attempt this reports on — `attempts.attempt_id`. Named `attempt_id`
        /// and not `assignment_id` because a capsule dispatch has no assignment:
        /// [`DispatchFrame::attempt_id`] is the one question both arms answer, and
        /// this is that value.
        attempt_id: Ulid,
        /// Who is reporting, under which generation. See [`AttemptFence`].
        ///
        /// NOT `#[serde(default)]`: an absent fence
        /// here would be this build filling in a first-generation epoch on a
        /// sender's behalf — the same guess [`Self::Failed`]'s `verdict` field
        /// refuses to make.
        fence: AttemptFence,
        /// The published `/out` TREE. An [`ArtifactRef`] and not a bespoke triple:
        /// it already carries the object address, the length and the privacy
        /// classification, and its own `Deserialize` RECOMPUTES the artifact id from
        /// that body — so a frame naming an id that is not its own content's is
        /// refused by the type rather than by a reader that might forget.
        ///
        /// [`ArtifactRef`]: kata_types::execution_contract::ArtifactRef
        result: kata_types::execution_contract::ArtifactRef,
        /// The published `/work` DELTA, or `None` when the capsule mapped no
        /// `/work` — see the variant docs. `Option` on the wire too: `None` is
        /// the report a `/work`-less capsule makes.
        work_delta: Option<kata_types::execution_contract::ArtifactRef>,
        /// The container's exit code as the provider reported it, or `None` when the
        /// provider killed the container itself.
        exit_code: Option<i32>,
        /// The container's stdout, as its PROVIDER spooled it: an [`ArtifactRef`]
        /// naming the CAS blob the worker published the spool file as — bounded
        /// combined with stderr at the capsule's `output_bytes`, which the provider
        /// protocol's `CaptureSpec::limit_bytes` carries.
        ///
        /// [`ArtifactRef`]: kata_types::execution_contract::ArtifactRef
        stdout: kata_types::execution_contract::ArtifactRef,
        /// The container's stderr, a CAS blob as `stdout` is.
        stderr: kata_types::execution_contract::ArtifactRef,
        /// The two spools together passed the combined bound and the provider KILLED
        /// the stage for it; the main fails the stage when it did.
        capture_exceeded: bool,
        /// The AGENT turn's report — `Some` exactly when the capsule's process
        /// was a `CapsuleProcess::Agent` turn that completed: the response
        /// artifact, the metered usage, the adapter and the model. `None` for
        /// a `Command` capsule.
        agent: Option<kata_types::agent::AgentTurnReport>,
        /// WHERE the fact was established. Only the two wire-assertable arms decode
        /// (`ExecutionProvenance`'s hand-written `Deserialize` refuses the rest), so
        /// a sender can narrow its own claim and never widen it.
        provenance: kata_types::execution_provenance::ExecutionProvenance,
        /// Every refusal the attempt's egress proxy recorded while the stage ran —
        /// each CONNECT the guest made that did not become a tunnel. Empty for an
        /// `Offline` capsule, which has no proxy. A list rather than an `Option`:
        /// there is no "the proxy's record is missing" state — the completion
        /// reports what the attempt's proxy saw, or there was no proxy.
        ///
        /// Worker-bounded: the proxy caps its recorded refusals
        /// (`kata_worker::egress_proxy::REFUSAL_RECORD_LIMIT`), so a guest that
        /// hammers CONNECT cannot grow this frame without limit.
        egress_refusals: Vec<kata_types::egress_refusal::EgressRefusalReport>,
    },
    /// Stage execution failed.
    Failed {
        assignment_id: Ulid,
        reason: String,
        /// Who is reporting, under which generation. See [`AttemptFence`].
        #[serde(default)]
        fence: AttemptFence,
        /// THE VERDICT THE WORKER COMPUTED, on the wire.
        ///
        /// A worker can tell its failure exits apart where the main cannot: a
        /// returned error (a definite negative answer), a backend-internal
        /// deadline, and its own outer deadline. The verdict travels so the
        /// main's failure-retry decision acts on the worker's classification rather
        /// than on [`DeliveryFailureProvenance::Unclassified`]. A main-side prose
        /// classifier is refused: the outer deadline has a stable prefix, the
        /// backend-internal one carries the backend's own text, so a substring
        /// match catches one and silently misses the other.
        ///
        /// # REQUIRED ON THE WIRE — no `#[serde(default)]`
        ///
        /// An absent field is not a sender saying anything; a default would be
        /// this build filling one in. And the obvious value to fill in —
        /// [`DeliveryFailureProvenance::Unclassified`] — is a value a sender that
        /// cannot classify must be able to send, so the guess would be
        /// byte-indistinguishable from a report on the one field that decides
        /// whether the attempt may be re-run.
        ///
        /// ## Is the refused population REACHABLE? Measured, not assumed
        ///
        /// A frame that omits `verdict` cannot come from this tree: every sender is
        /// a Rust struct literal the compiler forces to name the field, nothing
        /// carries `skip_serializing_if`, and no durable store anywhere in the
        /// workspace holds a [`WorkerMessage`] — it exists between a `send` and a
        /// `recv` and nowhere else. A sender with no fence at all is refused one
        /// layer up: it omits [`AttemptFence::protocol_version`], which the
        /// ingress fence refuses by name as `UnfencedSender` before any arm reads
        /// a verdict. So a default could only ever serve a sender CLAIMING
        /// protocol version 1 while omitting a version-1 field, and no build may
        /// guess a retry-polarity value on that sender's behalf.
        ///
        /// ## What it costs, stated rather than discovered
        ///
        /// [`AttemptFence`]'s own defaults stay, and its stated reason —
        /// *"a decode error would surface as transport death for the whole
        /// connection; a typed refusal names the attempt and the reason and leaves
        /// the transport up"* — does NOT transfer here, because it is an argument
        /// about unfenced frames and those are refused at the fence either way.
        /// The real cost is that such a frame dies at the DECODE rather than at
        /// the fence: one connection drops instead of one frame being named.
        /// That is the correct trade for a sender that contradicts the version it
        /// claims. No durable row holds this type, so there is no generation to
        /// migrate and no cache to cold.
        verdict: DeliveryFailureProvenance,
        /// The usage the stage's billable work measured before it failed,
        /// in the SAME shape a completion's `token_usage` object carries
        /// (`kata_types::metering::StageUsage`).
        ///
        /// `Some` means the worker's classifier can already say what kind of
        /// billable call ran before the failure — including the
        /// `MeteredCost::Unavailable` shape a call leaves when its outcome is
        /// unknowable — and carries whatever the backend reported. `None`
        /// means NO billable provider call was made: a shell or
        /// `workspace_effect` stage, or a failure the verdict proves preceded
        /// any call. The main charges `None` as an authoritative `0` — the
        /// distinction matters, so the field is REQUIRED rather than
        /// defaulted: a sender that cannot state it is not a sender the main
        /// may guess for (the same trade `verdict` documents above, and for
        /// the same absent-population reason there is no compat default).
        usage: Option<kata_types::metering::StageUsage>,
        /// The class of the model provider's failure, when the attempt is an agent
        /// turn its provider failed and the worker settled it PROVEN NOT PERFORMED
        /// (`kata_worker::agent_turn`); `None` for every other failure. The main
        /// records it beside the verdict, and the stage's retry chain re-runs a
        /// [`ProviderFailureClass::Transient`] attempt on its agent and never runs
        /// the agent of a [`ProviderFailureClass::Refused`] one again.
        provider_failure: Option<ProviderFailureClass>,
    },
    /// Keep-alive signal carrying telemetry. A unit-shaped
    /// `{"kind":"heartbeat"}` frame does not decode.
    Heartbeat(HeartbeatPayload),
    /// Mid-attempt progress for a CAPSULE attempt.
    ///
    /// A capsule attempt is not a ledger entry, so its frame resolves through
    /// the operational plane's `attempts` row rather than an assignment
    /// identity — `attempt_id` names that row. It also carries `dropped`, the
    /// count the capsule emitter's per-attempt bounds are obliged to report.
    ///
    /// Privacy shaping is at emission: a stage whose `progress_visibility` is
    /// `off` produces no frame at all, and every vendor-influenced string on
    /// one that does is scrubbed against the attempt's lifted credentials on
    /// the worker before the wire.
    CapsuleProgress {
        /// The attempt this reports on — `attempts.attempt_id`, named
        /// `attempt_id` for the same reason [`Self::CompletedCapsule`]'s is.
        attempt_id: Ulid,
        /// Cumulative source bytes the attempt's emitter has observed —
        /// spool bytes for a `Command` capsule, session-event bytes for an
        /// `Agent` one — strictly non-decreasing per attempt. Counts the
        /// SOURCE, not the preview.
        byte_offset: u64,
        /// The shaped preview: `summary` carries the event kind and
        /// tool/method names or a head-of-delta, `full` the bounded text. Empty
        /// when a `summary`-mode frame elects byte counts only.
        preview: String,
        /// Observations the attempt's progress bounds dropped, cumulative —
        /// a queue-full refusal or a spent byte budget; the rate window's
        /// coalescing is NOT a drop (it is how the bound is honoured).
        /// Relayed into `ProgressEvent::dropped` on the main.
        dropped: u64,
        /// Who is reporting, under which generation. See
        /// [`AttemptFence`]. REQUIRED rather than defaulted, like
        /// [`Self::CompletedCapsule`]'s: an absent fence is a sender claiming a
        /// generation it never was.
        fence: AttemptFence,
    },
}

impl WorkerMessage {
    /// The attempt this message reports on, paired with the fence it carries — or
    /// `None` for enrollment, recovery, and heartbeat session messages.
    /// that reports on no attempt and therefore fences nothing.
    ///
    /// # Why ONE accessor rather than an id one and a fence one
    ///
    /// The ingress fence needs both, and every attempt-scoped variant carries
    /// both. Two accessors returning two `Option`s would let a caller pair an
    /// attempt id with a `None` fence and decide what to do about it — a decision
    /// that must not exist, because "this frame names an attempt but carries no
    /// fence" is not a state any variant can be in. Returning the pair makes the
    /// session/attempt split the ONLY axis a caller can branch on.
    #[must_use]
    pub const fn fenced_attempt(&self) -> Option<(Ulid, &AttemptFence)> {
        match self {
            Self::Checkpoint(cp) => Some((cp.assignment_id, &cp.fence)),
            Self::Failed {
                assignment_id,
                fence,
                ..
            } => Some((*assignment_id, fence)),
            Self::CompletedCapsule {
                attempt_id, fence, ..
            }
            | Self::CapsuleProgress {
                attempt_id, fence, ..
            } => Some((*attempt_id, fence)),
            Self::Heartbeat(_)
            | Self::Recovery(_)
            | Self::EnrollmentProbe(_)
            | Self::EnrollmentProof { .. } => None,
        }
    }
}

/// Worker telemetry payload.
///
/// `Default` returns all-zero values; producers that don't sample
/// (e.g., test fixtures) can use it. Every field is required on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    /// Number of assignments currently in-flight on this worker.
    /// A worker processes sequentially → 0 or 1.
    pub active_stages: u32,
    /// CPU utilization in `[0.0, 1.0]`. NaN / pre-first-sample → `0.0`.
    pub cpu_utilization: f32,
    /// Resident set size in bytes. Linux-only;
    /// non-Linux platforms report `0`.
    pub memory_bytes: u64,
    /// Monotonic nanoseconds since worker process start.
    pub monotonic_nanos: u64,
}

/// Arbitrary-driven conformance draws for the LIVE worker <-> main wire
/// types.
///
/// This is the fuzz gate's type-level adversarial-input site, and it draws the
/// types that ARE on the live wire. The worker <-> main frame is the `local_socket` `Envelope` =
/// `{ Assignment(DispatchFrame) | Message(WorkerMessage) }`, serialized
/// with `serde_json::to_vec` (see `local_socket`) — so these
/// are the types a hostile or buggy peer can put on the wire.
///
/// Machinery: the `commonware_conformance::conformance_tests!` harness, plus `commonware_codec::conformance::generate_value`
/// for the arbitrary draw (identical seed→value semantics as `CodecConformance`).
/// The one difference is the encoder: the live wire is `serde_json`, not
/// `commonware-codec`, so [`SerdeConformance`] commits the serde bytes instead
/// of a codec `encode()`. Adding dead `commonware-codec` impls to these serde
/// types purely to reuse `CodecConformance` would be inert surface — exactly the
/// advertised-but-unconsumed shape this harness exists to avoid — so the marker wraps the
/// wire's actual codec.
///
/// Non-vacuous: each case draws an adversarial value, encodes it to the live
/// wire bytes, decodes them back, and asserts the round-trip is the identity
/// (panicking — i.e. failing the gate — on any serde asymmetry). The committed
/// bytes feed the stable-hash corpus in `conformance.toml`, so a silent wire
/// format change is also caught.
#[cfg(test)]
mod conformance {
    use core::marker::PhantomData;

    use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
    use commonware_codec::conformance::generate_value;
    use commonware_conformance::Conformance;
    use serde::Serialize;
    use serde::de::DeserializeOwned;

    use super::*;

    /// Deterministic sample budget per type. Bounded generators keep each
    /// draw's byte appetite small, so the harness stays in the low
    /// milliseconds and rides `just test-conformance`.
    const CASES: usize = 512;
    /// Cap on generated collection lengths (Vecs, JSON arrays/objects).
    const MAX_LEN: usize = 4;
    /// Cap on generated string byte lengths.
    const MAX_STR: usize = 24;
    /// Max nesting depth of a generated `serde_json::Value`.
    const MAX_JSON_DEPTH: u8 = 2;

    /// Bounded ASCII string — keeps draws deterministic, byte-cheap, and
    /// guaranteed to round-trip through JSON.
    fn bounded_string(u: &mut Unstructured<'_>) -> ArbitraryResult<String> {
        let len = u.int_in_range(0..=MAX_STR)?;
        let mut out = String::with_capacity(len);
        for byte in u.bytes(len)? {
            out.push(char::from(b'a' + (byte % 26)));
        }
        Ok(out)
    }

    fn smol(u: &mut Unstructured<'_>) -> ArbitraryResult<SmolStr> {
        Ok(SmolStr::new(bounded_string(u)?))
    }

    fn ulid(u: &mut Unstructured<'_>) -> ArbitraryResult<Ulid> {
        Ok(Ulid::from_parts(u64::arbitrary(u)?, u128::arbitrary(u)?))
    }

    /// A small refusal list — the proxy's own cap is far above this bound; the
    /// draw only has to cover the `[]`/`non-empty`/`kinded` shapes, not the cap.
    fn egress_refusal_reports(
        u: &mut Unstructured<'_>,
    ) -> ArbitraryResult<Vec<kata_types::egress_refusal::EgressRefusalReport>> {
        use kata_types::egress_refusal::{EgressRefusalKind, EgressRefusalReport};
        let kinds = [
            EgressRefusalKind::MethodNotConnect,
            EgressRefusalKind::RequestLineTooLong,
            EgressRefusalKind::MalformedRequestLine,
            EgressRefusalKind::HeaderBlockTooLarge,
            EgressRefusalKind::FoldedHeader,
            EgressRefusalKind::MalformedAuthority,
            EgressRefusalKind::HostNotAllowed,
            EgressRefusalKind::PortNotAllowed,
            EgressRefusalKind::UpstreamUnreachable,
            EgressRefusalKind::EgressAddressRefused,
            EgressRefusalKind::ConcurrencyCap,
            EgressRefusalKind::PendingCap,
            EgressRefusalKind::RequestTimeout,
            EgressRefusalKind::MalformedHeaderLine,
            EgressRefusalKind::ConnectionByteBudget,
            EgressRefusalKind::TotalByteBudget,
            EgressRefusalKind::IdleTimeout,
        ];
        let len = u.int_in_range(0..=MAX_LEN)?;
        let mut out = Vec::with_capacity(len);
        for seq in 0..len {
            out.push(EgressRefusalReport {
                attempt_id: ulid(u)?,
                seq: seq as u64,
                authority: bounded_string(u)?,
                kind: *u.choose(&kinds)?,
                port: u16::arbitrary(u)?,
                status: Option::<u16>::arbitrary(u)?,
                detail: bounded_string(u)?,
            });
        }
        Ok(out)
    }

    /// Bounded JSON value using only exactly-round-trippable scalars
    /// (`null` / `bool` / `i64` / bounded string) plus small arrays/objects.
    fn json_value(u: &mut Unstructured<'_>, depth: u8) -> ArbitraryResult<serde_json::Value> {
        let ceiling = if depth == 0 { 3u8 } else { 5u8 };
        Ok(match u.int_in_range(0..=ceiling)? {
            0 => serde_json::Value::Null,
            1 => serde_json::Value::Bool(bool::arbitrary(u)?),
            2 => serde_json::Value::from(i64::from(i32::arbitrary(u)?)),
            3 => serde_json::Value::String(bounded_string(u)?),
            4 => {
                let len = u.int_in_range(0..=MAX_LEN)?;
                let mut arr = Vec::with_capacity(len);
                for _ in 0..len {
                    arr.push(json_value(u, depth - 1)?);
                }
                serde_json::Value::Array(arr)
            }
            _ => {
                let len = u.int_in_range(0..=MAX_LEN)?;
                let mut map = serde_json::Map::new();
                for _ in 0..len {
                    map.insert(bounded_string(u)?, json_value(u, depth - 1)?);
                }
                serde_json::Value::Object(map)
            }
        })
    }

    fn artifact_ref(
        u: &mut Unstructured<'_>,
    ) -> ArbitraryResult<kata_types::execution_contract::ArtifactRef> {
        Ok(kata_types::execution_contract::ArtifactRef::new(
            kata_types::primitives::FixedBytes(<[u8; 32]>::arbitrary(u)?),
            u64::arbitrary(u)?,
            if bool::arbitrary(u)? {
                kata_types::execution_contract::ArtifactPrivacy::Public
            } else {
                kata_types::execution_contract::ArtifactPrivacy::Private
            },
        ))
    }

    /// Draw a fence across the whole adversarial range, INCLUDING the
    /// `protocol_version: 0` an unfenced sender produces and the
    /// negative `lease_epoch` no honest allocator emits. Both are values a
    /// hostile peer can put on the wire, so both must round-trip rather than
    /// panic; refusing them is the ingress fence's job, not the codec's.
    fn attempt_fence(u: &mut Unstructured<'_>) -> ArbitraryResult<AttemptFence> {
        Ok(AttemptFence {
            protocol_version: u16::arbitrary(u)?,
            lease_epoch: i64::arbitrary(u)?,
            worker_id: smol(u)?,
        })
    }

    /// A control frame draws the SAME adversarial fence as an inbound one. The
    /// direction is reversed but the codec's obligation is not: a hostile peer
    /// can put any bytes on this wire too, and refusing a stale or unversioned
    /// fence is the worker's check, never the decoder's.
    impl<'a> Arbitrary<'a> for WorkerControl {
        fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
            use kata_types::recovery::RecoveryCommand;
            Ok(match u.int_in_range(0..=6u8)? {
                0 => Self::Stop {
                    assignment_id: ulid(u)?,
                    fence: attempt_fence(u)?,
                    reason: bounded_string(u)?,
                },
                1 => Self::Enrollment(crate::enrollment::EnrollmentControl::Challenge(
                    crate::enrollment::EnrollmentChallenge {
                        version: u32::arbitrary(u)?,
                        worker_nonce: <[u8; 32]>::arbitrary(u)?,
                        main_nonce: <[u8; 32]>::arbitrary(u)?,
                        source_main: bounded_string(u)?,
                        proof: <[u8; 32]>::arbitrary(u)?,
                    },
                )),
                2 => Self::Enrollment(crate::enrollment::EnrollmentControl::Bound {
                    domain: recovery_domain(u)?,
                    heartbeat_interval_ms: u64::arbitrary(u)?,
                    proof: <[u8; 32]>::arbitrary(u)?,
                }),
                3 => Self::Recovery(RecoveryCommand::Begin {
                    request: recovery_request(u)?,
                    hold_ms: u64::arbitrary(u)?,
                    max_bytes: u64::arbitrary(u)?,
                }),
                4 => Self::Recovery(RecoveryCommand::Read {
                    request: recovery_request(u)?,
                    generation_id: ulid(u)?,
                    offset: u64::arbitrary(u)?,
                    max_bytes: u32::arbitrary(u)?,
                }),
                5 => Self::Recovery(RecoveryCommand::Renew {
                    request: recovery_request(u)?,
                    generation_id: ulid(u)?,
                    hold_ms: u64::arbitrary(u)?,
                }),
                _ => Self::Recovery(RecoveryCommand::Release {
                    request: recovery_request(u)?,
                    generation_id: ulid(u)?,
                }),
            })
        }
    }

    fn recovery_domain(
        u: &mut Unstructured<'_>,
    ) -> ArbitraryResult<kata_types::identity::WorkerEffectDomain> {
        Ok(kata_types::identity::WorkerEffectDomain {
            source_main: bounded_string(u)?,
            membrane: kata_types::identity::WorkerMembraneId(ulid(u)?),
            enrollment: ulid(u)?,
        })
    }

    fn recovery_request(
        u: &mut Unstructured<'_>,
    ) -> ArbitraryResult<kata_types::recovery::RecoveryRequest> {
        Ok(kata_types::recovery::RecoveryRequest {
            artifact_id: ulid(u)?,
            request_nonce: ulid(u)?,
            domain: recovery_domain(u)?,
        })
    }

    fn recovery_reply(
        u: &mut Unstructured<'_>,
    ) -> ArbitraryResult<kata_types::recovery::RecoveryReply> {
        use kata_types::recovery::{RecoveryRefusal, RecoveryReply, WorkerRecoveryReceipt};
        Ok(match u.int_in_range(0..=4u8)? {
            0 => RecoveryReply::Ready {
                receipt: WorkerRecoveryReceipt {
                    artifact_id: ulid(u)?,
                    request_nonce: ulid(u)?,
                    domain: recovery_domain(u)?,
                    generation_id: ulid(u)?,
                    schema_version: u32::arbitrary(u)?,
                    database_digest: bounded_string(u)?,
                    database_byte_len: u64::arbitrary(u)?,
                },
            },
            1 => RecoveryReply::Chunk {
                request: recovery_request(u)?,
                generation_id: ulid(u)?,
                offset: u64::arbitrary(u)?,
                bytes: (0..u.int_in_range(0..=MAX_LEN)?)
                    .map(|_| u8::arbitrary(u))
                    .collect::<ArbitraryResult<_>>()?,
            },
            2 => RecoveryReply::Renewed {
                request: recovery_request(u)?,
                generation_id: ulid(u)?,
            },
            3 => RecoveryReply::Released {
                request: recovery_request(u)?,
                generation_id: ulid(u)?,
            },
            _ => RecoveryReply::Refused {
                request: recovery_request(u)?,
                reason: *u.choose(&[
                    RecoveryRefusal::Unbound,
                    RecoveryRefusal::WrongDomain,
                    RecoveryRefusal::Busy,
                    RecoveryRefusal::InvalidBounds,
                    RecoveryRefusal::StaleGeneration,
                    RecoveryRefusal::Expired,
                    RecoveryRefusal::InvalidOffset,
                    RecoveryRefusal::CaptureFailed,
                ])?,
            },
        })
    }

    fn delivery_failure_provenance(
        u: &mut Unstructured<'_>,
    ) -> ArbitraryResult<DeliveryFailureProvenance> {
        Ok(match u.int_in_range(0..=2u8)? {
            0 => DeliveryFailureProvenance::ProvenNotPerformed,
            1 => DeliveryFailureProvenance::ProvenAmbiguous,
            _ => DeliveryFailureProvenance::Unclassified,
        })
    }

    impl<'a> Arbitrary<'a> for StageCheckpoint {
        fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
            Ok(Self {
                assignment_id: ulid(u)?,
                stage_name: smol(u)?,
                output: json_value(u, MAX_JSON_DEPTH)?,
                sequence: u64::arbitrary(u)?,
                fence: attempt_fence(u)?,
            })
        }
    }

    impl<'a> Arbitrary<'a> for HeartbeatPayload {
        fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
            Ok(Self {
                active_stages: u32::arbitrary(u)?,
                // Finite [0.0, 1.0] (the field's documented domain) so the
                // f32 survives a JSON round-trip; NaN/Inf would serialize to
                // `null` and break the identity assertion. `f32::from(u16)` is
                // lossless (no precision-loss cast).
                cpu_utilization: f32::from(u.int_in_range(0..=1000u16)?) / 1000.0,
                memory_bytes: u64::arbitrary(u)?,
                monotonic_nanos: u64::arbitrary(u)?,
            })
        }
    }

    impl<'a> Arbitrary<'a> for WorkerMessage {
        fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
            Ok(match u.int_in_range(0..=8u8)? {
                0 => Self::EnrollmentProbe(crate::enrollment::EnrollmentProbe {
                    version: 1,
                    worker_nonce: <[u8; 32]>::arbitrary(u)?,
                    membrane: kata_types::identity::WorkerMembraneId(ulid(u)?),
                    executor_term: kata_types::primitives::ContentHash::new(<[u8; 32]>::arbitrary(
                        u,
                    )?),
                    worker_info: json_value(u, MAX_JSON_DEPTH)?,
                }),
                1 => Self::Checkpoint(StageCheckpoint::arbitrary(u)?),
                2 => Self::Failed {
                    assignment_id: ulid(u)?,
                    reason: bounded_string(u)?,
                    fence: attempt_fence(u)?,
                    verdict: delivery_failure_provenance(u)?,
                    usage: if bool::arbitrary(u)? {
                        None
                    } else {
                        Some(kata_types::metering::StageUsage::unmetered(
                            bounded_string(u)?,
                            bounded_string(u)?,
                        ))
                    },
                    provider_failure: match u.int_in_range(0..=2u8)? {
                        0 => None,
                        1 => Some(ProviderFailureClass::Refused),
                        _ => Some(ProviderFailureClass::Transient),
                    },
                },
                3 => Self::Heartbeat(HeartbeatPayload::arbitrary(u)?),
                4 => Self::EnrollmentProof {
                    proof: <[u8; 32]>::arbitrary(u)?,
                },
                5 => Self::CompletedCapsule {
                    attempt_id: ulid(u)?,
                    fence: attempt_fence(u)?,
                    result: artifact_ref(u)?,
                    work_delta: if bool::arbitrary(u)? {
                        Some(artifact_ref(u)?)
                    } else {
                        None
                    },
                    exit_code: Option::<i32>::arbitrary(u)?,
                    stdout: artifact_ref(u)?,
                    stderr: artifact_ref(u)?,
                    capture_exceeded: bool::arbitrary(u)?,
                    agent: if bool::arbitrary(u)? {
                        Some(kata_types::agent::AgentTurnReport {
                            response: artifact_ref(u)?,
                            usage: if bool::arbitrary(u)? {
                                Some(kata_types::metering::StageUsage::unmetered(
                                    bounded_string(u)?,
                                    bounded_string(u)?,
                                ))
                            } else {
                                None
                            },
                            adapter: kata_types::agent::AdapterKind::NanocodeOpenai,
                            model_reported: if bool::arbitrary(u)? {
                                Some(smol_str::SmolStr::new(bounded_string(u)?))
                            } else {
                                None
                            },
                            session_evidence: if bool::arbitrary(u)? {
                                Some(artifact_ref(u)?)
                            } else {
                                None
                            },
                            stop_reason: if bool::arbitrary(u)? {
                                Some(smol_str::SmolStr::new(bounded_string(u)?))
                            } else {
                                None
                            },
                        })
                    } else {
                        None
                    },
                    provenance:
                        kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                            bounded_string(u)?,
                        ),
                    egress_refusals: egress_refusal_reports(u)?,
                },
                6 => Self::CapsuleProgress {
                    attempt_id: ulid(u)?,
                    byte_offset: u64::arbitrary(u)?,
                    preview: bounded_string(u)?,
                    dropped: u64::arbitrary(u)?,
                    fence: attempt_fence(u)?,
                },
                _ => Self::Recovery(recovery_reply(u)?),
            })
        }
    }

    /// Conformance marker over the LIVE serde_json wire codec. Mirrors
    /// `commonware_codec::conformance::CodecConformance`, but commits the
    /// bytes the wire actually produces (`serde_json`) and additionally
    /// asserts a decode round-trip identity so a real malformed-but-typed
    /// value is drawn, encoded, decoded, and validated — never panicking.
    struct SerdeConformance<T>(PhantomData<T>);

    /// The `Some`/`None` split on `CompletedCapsule::work_delta` is not
    /// interchangeable — `None` is "no `/work` mapping" and `Some` of an empty
    /// delta is "mapped and unchanged" — so the corpus must draw both or a
    /// regression in one arm's encoding is invisible to the pinned hash.
    #[test]
    fn wire_corpus_covers_both_work_delta_arms() {
        let (mapped, unmapped) = (0..CASES as u64)
            .map(generate_value)
            .filter_map(|message| match message {
                WorkerMessage::CompletedCapsule { work_delta, .. } => Some(work_delta),
                _ => None,
            })
            .fold((0usize, 0usize), |(some, none), delta| {
                if delta.is_some() {
                    (some + 1, none)
                } else {
                    (some, none + 1)
                }
            });
        assert!(mapped > 0, "the corpus must draw `Some` work deltas");
        assert!(unmapped > 0, "the corpus must draw `None` work deltas");
    }

    #[test]
    fn wire_corpus_covers_every_enrollment_and_recovery_arm() {
        use kata_types::recovery::{RecoveryCommand, RecoveryReply};
        let controls: std::collections::BTreeSet<_> = (0..CASES as u64)
            .map(|seed| match generate_value::<WorkerControl>(seed) {
                WorkerControl::Stop { .. } => "stop",
                WorkerControl::Enrollment(crate::enrollment::EnrollmentControl::Challenge(_)) => {
                    "challenge"
                }
                WorkerControl::Enrollment(crate::enrollment::EnrollmentControl::Bound {
                    ..
                }) => "bound",
                WorkerControl::Recovery(RecoveryCommand::Begin { .. }) => "begin",
                WorkerControl::Recovery(RecoveryCommand::Read { .. }) => "read",
                WorkerControl::Recovery(RecoveryCommand::Renew { .. }) => "renew",
                WorkerControl::Recovery(RecoveryCommand::Release { .. }) => "release",
            })
            .collect();
        assert_eq!(
            controls,
            [
                "stop",
                "challenge",
                "bound",
                "begin",
                "read",
                "renew",
                "release"
            ]
            .into_iter()
            .collect()
        );
        let messages: std::collections::BTreeSet<_> = (0..CASES as u64)
            .map(|seed| match generate_value::<WorkerMessage>(seed) {
                WorkerMessage::EnrollmentProbe(_) => "probe",
                WorkerMessage::EnrollmentProof { .. } => "proof",
                WorkerMessage::Checkpoint(_) => "checkpoint",
                WorkerMessage::CompletedCapsule { .. } => "completed_capsule",
                WorkerMessage::Failed { .. } => "failed",
                WorkerMessage::Heartbeat(_) => "heartbeat",
                WorkerMessage::CapsuleProgress { .. } => "capsule_progress",
                WorkerMessage::Recovery(RecoveryReply::Ready { .. }) => "ready",
                WorkerMessage::Recovery(RecoveryReply::Chunk { .. }) => "chunk",
                WorkerMessage::Recovery(RecoveryReply::Renewed { .. }) => "renewed",
                WorkerMessage::Recovery(RecoveryReply::Released { .. }) => "released",
                WorkerMessage::Recovery(RecoveryReply::Refused { .. }) => "refused",
            })
            .collect();
        assert_eq!(
            messages,
            [
                "probe",
                "proof",
                "checkpoint",
                "completed_capsule",
                "failed",
                "heartbeat",
                "capsule_progress",
                "ready",
                "chunk",
                "renewed",
                "released",
                "refused"
            ]
            .into_iter()
            .collect()
        );
    }

    impl<T> Conformance for SerdeConformance<T>
    where
        T: for<'a> Arbitrary<'a> + Serialize + DeserializeOwned + PartialEq + core::fmt::Debug,
        T: Send + Sync,
    {
        async fn commit(seed: u64) -> Vec<u8> {
            let value: T = generate_value(seed);
            let bytes = serde_json::to_vec(&value).expect("live wire serialize must not fail");
            let decoded: T =
                serde_json::from_slice(&bytes).expect("live wire round-trip decode must not fail");
            assert_eq!(
                decoded, value,
                "serde_json round-trip must be the identity for the live wire type"
            );
            bytes
        }
    }

    commonware_conformance::conformance_tests! {
        SerdeConformance<WorkerControl> => CASES,
        SerdeConformance<WorkerMessage> => CASES,
    }
}
