//! One agent TURN's outcome vocabulary, the ISSUANCE WATERMARK
//! that decides which word applies, and the mapping onto the effect plane.
//!
//! # The sentence this module implements
//!
//! ADR-0001 "Agent execution": *"Protocol disconnect after possible model or
//! tool issuance remains ambiguous; usage unknown is not recorded as zero."*
//!
//! Both halves are structural here, not documentary:
//!
//! * [`TurnOutcome::Completed`] carries `usage: Option<TokenUsage>`, and `None`
//!   means [`MeteredCost::Unavailable`](kata_types::metering::MeteredCost::Unavailable)
//!   — never `TokenUsage::default()`. `TokenUsage` HAS a `Default`, its own doc
//!   says why folding a garbled usage event into it is the defect, and
//!   [`MeteredCost`](kata_types::metering::MeteredCost) exists precisely so a
//!   zero-because-unmeasured cannot masquerade as a zero-because-free. An
//!   adapter that cannot parse usage therefore reports `None` and the pricing
//!   classifier says `Unavailable`; substituting `TokenUsage::default()` here
//!   would launder an absence into a measurement one layer below every policy
//!   that could still tell the difference.
//! * "after possible … issuance" is a question about ORDER, and order is what
//!   [`IssuanceWatermark`] records. EOF before the watermark is
//!   [`TurnOutcome::Cancelled`] or [`TurnOutcome::Refused`] — nothing was
//!   issued, so nothing is unknown (`Cancelled` also covers a
//!   harness-CONFIRMED stop after the watermark, which carries its own usage;
//!   see the variant, and [`CleanupReport::harness_acknowledged_cancel`] for
//!   which of the two a `Cancelled` was); EOF after it is
//!   [`TurnOutcome::Ambiguous`], which the worker's turn driver
//!   (`kata_worker::agent_turn`) settles as PROVEN AMBIGUOUS: an attempt the main
//!   never re-runs automatically. A turn the model PROVIDER failed with a typed
//!   answer is not a protocol that went away: it is
//!   [`TurnOutcome::ProviderFailed`], which the worker settles PROVEN NOT
//!   PERFORMED unless a tool call ran in a capsule that could reach the network.
//!
//! # Why the watermark is a TOKEN and not a `bool` someone remembers to set
//!
//! The ordering requirement is "mark BEFORE acting on the first issuance-capable
//! frame". A `bool` set by convention gets set after the act by the first author
//! in a hurry, and the resulting record says a crash issued nothing when it may
//! have issued everything. So the act is made unreachable without the mark:
//! [`observe_frame`] takes `&mut IssuanceWatermark`, marks it, and returns a
//! [`Marked`] token; [`act_on_marked_frame`] requires that token, and `Marked` has
//! a private field, no public constructor and no `Clone`, so the only way to
//! obtain one is to have already marked the watermark.
//!
//! What that buys, stated narrowly: within this vocabulary, an act cannot be
//! written before its mark. It is NOT a proof that every future frame handler
//! routes through [`observe_frame`] — a handler that acts on an issuance-capable
//! frame without asking for a token is still writable, and what catches that is
//! review plus the per-adapter qualification rows. The type makes the
//! wrong ORDER unwritable; it does not make the call site mandatory.

use async_trait::async_trait;
use kata_types::agent::{Prompt, SessionEvidenceEvent};
use kata_types::cache::TokenUsage;
use kata_types::effect::ProviderFailureClass;

use crate::resource_bounds::TeardownOutcome;
use smol_str::SmolStr;

/// A session's protocol-level name, as the harness knows it.
///
/// A `SmolStr` because every admitted protocol names sessions with an opaque
/// string it chose and kata must echo it back byte-for-byte rather than
/// re-encode it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SessionId(SmolStr);

impl SessionId {
    /// Adopt a harness-issued session name.
    #[must_use]
    pub fn new(id: impl Into<SmolStr>) -> Self {
        Self(id.into())
    }

    /// The name as the harness spelled it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a turn MAY have issued by the time the protocol went away.
///
/// The frame class that crossed the watermark, recorded as evidence rather than
/// as a rendered sentence: an operator resolving an `ambiguous` attempt needs to
/// know whether the harness had reached a tool call (an effect may be out in the
/// world) or only model tokens (spend may have happened, no external effect).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MayHaveIssued {
    /// Model tokens were being produced — spend may have occurred; no external
    /// effect was reached through kata.
    ModelTokens,
    /// A tool call was being acted on — an external effect may be out.
    ToolCall,
    /// A permission request was being acted on: the harness was authorized to do
    /// something whose completion kata cannot observe.
    PermissionGrant,
}

/// A frame class that MAY carry issuance, as seen on the wire.
///
/// Exactly the three classes ADR-0001's sentence names ("model or tool
/// issuance", plus the permission grant that authorizes one). A frame that
/// cannot issue anything — a protocol handshake, a log notification, a heartbeat
/// — is deliberately not representable here: passing one would set the watermark
/// and turn every later disconnect into an ambiguity nobody can drain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IssuanceFrame {
    /// A model-output / token frame.
    ModelToken,
    /// A tool-call frame.
    ToolCall,
    /// A permission-request frame.
    PermissionRequest,
}

impl IssuanceFrame {
    /// What acting on this frame may have issued.
    #[must_use]
    pub const fn may_have_issued(self) -> MayHaveIssued {
        match self {
            Self::ModelToken => MayHaveIssued::ModelTokens,
            Self::ToolCall => MayHaveIssued::ToolCall,
            Self::PermissionRequest => MayHaveIssued::PermissionGrant,
        }
    }
}

/// Proof that the watermark was set BEFORE the frame was acted on.
///
/// Zero-sized by intent and unconstructible outside this module: the private
/// field has no `pub` constructor, no `Default`, and no `From`. It is not
/// `Clone`, so it cannot be kept from an earlier frame and reused for a later
/// one — each act needs its own mark.
#[derive(Debug)]
pub struct Marked {
    frame: IssuanceFrame,
}

impl Marked {
    /// The frame this mark was taken for.
    #[must_use]
    pub const fn frame(&self) -> IssuanceFrame {
        self.frame
    }
}

/// The per-session record of whether issuance MAY have started.
///
/// Monotonic: it records the FIRST crossing and never retreats, because "may
/// have issued" cannot become false once true. A later, heavier frame does not
/// overwrite a lighter earlier one — the honest evidence is the point at which
/// the session stopped being provably clean.
// Deliberately NOT `Copy` and NOT `Default`. `Copy` would let a handler mark a
// COPY of the watermark — the mark would be lost and the session would classify a
// later EOF as clean — and the whole mechanism turns on the `&mut` reaching the one
// watermark the session owns. `Default` is omitted because `clean()` says what an
// unmarked watermark MEANS, and a session should have to name that claim.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IssuanceWatermark {
    crossed: Option<MayHaveIssued>,
}

impl IssuanceWatermark {
    /// A session that has issued nothing yet.
    #[must_use]
    pub const fn clean() -> Self {
        Self { crossed: None }
    }

    /// What may have been issued, if the watermark has been crossed.
    #[must_use]
    pub const fn crossed(&self) -> Option<MayHaveIssued> {
        self.crossed
    }

    /// Whether the session is still PROVABLY clean.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.crossed.is_none()
    }

    /// The outcome for a protocol EOF (or deadline) at this point in the
    /// session.
    ///
    /// Before the watermark: [`TurnOutcome::Cancelled`] — the turn stopped and
    /// nothing was issued, so there is nothing to latch, and its `usage` is
    /// `None` because a turn that issued nothing reported nothing. After it:
    /// [`TurnOutcome::Ambiguous`], carrying what may have gone out and the
    /// evidence an operator resolves the ambiguous attempt against.
    ///
    /// # Two things this function does NOT do
    ///
    /// * It never returns [`TurnOutcome::Refused`]. A refusal is an ADAPTER's
    ///   decision (a required capability the protocol lacks, a scope it cannot
    ///   serve); an EOF is not one, so that arm is unreachable from here even
    ///   though it shares the pre-watermark "nothing issued" property.
    /// * On the clean path it DISCARDS `evidence`. Deliberate rather than an
    ///   oversight: a clean stop needs no forensics, and a `Cancelled` arm carrying
    ///   an explanation invites a reader to treat the explanation as a reason the
    ///   turn is suspect. If a pre-watermark EOF ever needs its observation kept,
    ///   the place for it is the session's own log line, not this value.
    #[must_use]
    pub fn eof_outcome(&self, evidence: impl Into<String>) -> TurnOutcome {
        match self.crossed {
            None => TurnOutcome::Cancelled { usage: None },
            Some(issued) => TurnOutcome::Ambiguous {
                issued,
                evidence: evidence.into(),
            },
        }
    }
}

/// Mark the watermark for `frame` and return the token that authorizes acting on
/// it.
///
/// This is the ONLY producer of [`Marked`], and it sets the watermark before it
/// returns — so a caller holding a token is a caller whose watermark is already
/// durable in memory for the EOF classifier to read.
pub fn observe_frame(watermark: &mut IssuanceWatermark, frame: IssuanceFrame) -> Marked {
    if watermark.crossed.is_none() {
        watermark.crossed = Some(frame.may_have_issued());
    }
    Marked { frame }
}

/// Act on a frame whose watermark has been set.
///
/// Takes the token by reference and returns the frame class the caller may now
/// act on. The body is trivial on purpose: the value of this function is its
/// SIGNATURE, which is unsatisfiable without a prior [`observe_frame`].
#[must_use]
pub fn act_on_marked_frame(marked: &Marked) -> IssuanceFrame {
    marked.frame()
}

/// How one agent TURN ended.
///
/// Five arms, and the interesting property is which are NOT collapsed:
/// [`Self::Cancelled`] / [`Self::Refused`] are STOPS NOTHING UNKNOWN RIDES ON —
/// the harness acknowledged the stop, the turn stopped before it issued
/// anything, or the adapter declined before starting —
/// [`Self::ProviderFailed`] is a failure the model provider decided and the
/// harness classified, and [`Self::Ambiguous`] is
/// may-have-issued-and-nobody-can-say. A vocabulary that folded them (a
/// single `Failed { reason }`) is exactly the collapse
/// `kata_types::effect::DeliveryFailureProvenance` was built to undo one layer
/// out, and re-introducing it here would mean the main could only ever be told
/// `Unclassified`.
#[derive(Clone, Debug)]
pub enum TurnOutcome {
    /// The harness completed the turn and the response was read in full.
    Completed {
        /// The turn's textual response.
        response: String,
        /// Token usage, when the harness reported it in a form the adapter could
        /// parse.
        ///
        /// `None` means UNKNOWN and must reach
        /// [`MeteredCost::Unavailable`](kata_types::metering::MeteredCost::Unavailable).
        /// It must NOT be replaced by `TokenUsage::default()`: that value is
        /// indistinguishable from a real zero-token turn, and a hard
        /// `cost_bound` evaluated against it treats an unmeasured frontier call
        /// as free.
        usage: Option<TokenUsage>,
        /// The model the provider reported for this turn — the model the
        /// embedded harness's model calls reported. `None` when the provider
        /// states none: the requested model is the
        /// capsule's identity, and a field that claims the harness's account
        /// must never borrow it.
        model: Option<SmolStr>,
        /// The response hit the adapter's per-accumulator bound
        /// ([`AttemptScope::budgets`](crate::adapter::scope::AttemptScope::budgets)`().output_bytes`)
        /// and bytes were dropped — LATCHED, so a `final_text` that replaces a
        /// flooded `streamed` cannot un-say the drop. The worker folds it into
        /// `capture_exceeded`, which fails the stage PERFORMED BUT FAILED the
        /// same way the shell arm's killed capture does.
        response_exceeded: bool,
        /// Why the model stopped — the provider's own word for the end of its
        /// turn, or `None` when it states none. `None` means "the
        /// provider said nothing", never "the adapter did not look" — a reader
        /// of the capsule envelope's `stop_reason` learns the same fact.
        stop_reason: Option<SmolStr>,
    },
    /// The turn STOPPED, and nothing about what it issued is unknown.
    ///
    /// # What this arm claims, and what it does not
    ///
    /// At least one of two things, and the arm does not say which:
    ///
    /// * **kata asked the harness to stop, and the harness CONFIRMED it
    ///   stopped** — at any point of the watermark. The confirmation is what
    ///   separates this from [`Self::Ambiguous`]; spend may well have occurred
    ///   before it, which is why the arm carries usage.
    /// * **the turn stopped before the watermark was crossed** — nothing was
    ///   issued, whoever stopped it and whether or not anyone confirmed
    ///   ([`IssuanceWatermark::eof_outcome`]'s clean answer).
    ///
    /// Which of the two a `Cancelled` was is
    /// [`CleanupReport::harness_acknowledged_cancel`]'s to say, and a reader
    /// that words the stop as CONFIRMED reads it there, never off this arm.
    ///
    /// What it excludes, and this is the load-bearing half: once the watermark
    /// is crossed, a harness that went away without confirming, and a harness
    /// that announced a stop kata never asked for. Neither is a confirmed
    /// cancel, both are [`Self::Ambiguous`], and an adapter that reported
    /// either here would be claiming a confirmation nobody gave.
    Cancelled {
        /// Token usage for the part of the turn that ran, when the harness
        /// reported it in a form the adapter could parse.
        ///
        /// `None` means UNKNOWN and must reach
        /// [`MeteredCost::Unavailable`](kata_types::metering::MeteredCost::Unavailable),
        /// for exactly the reason [`Self::Completed::usage`] states: a cancelled
        /// turn that burned 40k tokens before it stopped is not a free turn, and
        /// `TokenUsage::default()` here would price it as one.
        usage: Option<TokenUsage>,
    },
    /// The adapter refused to run the turn, before the watermark: NO model
    /// call was issued, which is what makes it also provably nothing-issued.
    Refused {
        /// Why the turn was refused.
        reason: String,
    },
    /// The turn's MODEL PROVIDER failed it, and the harness's own typed error
    /// says how: the provider refused a model request
    /// ([`ProviderFailureClass::Refused`]), or failed one transiently past the
    /// harness's own retries ([`ProviderFailureClass::Transient`]).
    ///
    /// # What this arm claims, and what it does not
    ///
    /// It is a KNOWN failure, not a lost protocol: the model requests went out
    /// (the watermark is crossed) and the provider's answer to the last one is
    /// the reason. It does NOT claim that nothing the turn did reached beyond
    /// its capsule: `tool_called` says whether a tool call left the harness for
    /// the capsule during the turn, and the worker decides from it and the
    /// capsule's network whether the attempt is PROVEN NOT PERFORMED (an
    /// offline capsule, whose effects are capsule-local and unpublished, or a
    /// turn that ran no tool) or PROVEN AMBIGUOUS (a capsule that could reach
    /// the network, after a tool call).
    ProviderFailed {
        /// Who decided the failure, and whether a fresh attempt could succeed.
        class: ProviderFailureClass,
        /// The provider's own account of the failure — its error type and
        /// message where it stated them, else the harness's error — scrubbed of
        /// every lifted value and bounded.
        reason: String,
        /// What the turn is charged.
        charge: FailedTurnCharge,
        /// Whether any tool call left the harness for the capsule during the
        /// turn (a `ToolCall` mark), whatever the watermark's first crossing was.
        tool_called: bool,
    },
    /// The protocol went away AFTER the watermark. The turn may have issued
    /// model spend, a tool call, or a permission grant, and kata cannot tell.
    Ambiguous {
        /// What may have gone out.
        issued: MayHaveIssued,
        /// The observation an operator resolves the ambiguous attempt against —
        /// which frame was in flight, what the last wire event was. Prose for a human; the
        /// machine-readable fact is [`Self::Ambiguous::issued`].
        evidence: String,
    },
}

impl TurnOutcome {
    /// Stable lowercase label for logs and metrics.
    #[must_use]
    pub const fn as_label(&self) -> &'static str {
        match self {
            Self::Completed { .. } => "completed",
            Self::Cancelled { .. } => "cancelled",
            Self::Refused { .. } => "refused",
            Self::ProviderFailed { .. } => "provider_failed",
            Self::Ambiguous { .. } => "ambiguous",
        }
    }
}

/// What a turn its model provider failed ([`TurnOutcome::ProviderFailed`]) is
/// charged — the three answers a failure can give, so an unknown charge can never
/// be read as a zero, nor a zero as unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailedTurnCharge {
    /// The provider billed nothing: it refused the turn's one model request with
    /// an error response, no model call completed before it, and the harness
    /// retried no attempt. Recorded as the authoritative `0`.
    Nothing,
    /// The usage the turn's completed model calls reported, summed — what kata
    /// metered. The failed request adds nothing kata measured: a refusal billed
    /// nothing, and a transient failure that cut a stream short may have billed
    /// output kata never saw, the same residual a confirmed cancel's usage so far
    /// carries.
    Metered(TokenUsage),
    /// No completed call reported usage, and the failure may have billed: an
    /// UNKNOWN charge, recorded as `Unavailable`, never as zero.
    Unknown,
}

/// What a session's teardown established, in the vocabulary the resource
/// bounds already ship.
///
/// A wrapper rather than a bare [`TeardownOutcome`] so a session can add what is
/// specific to an agent teardown — whether the harness acknowledged the cancel
/// before the process went down, and what a turn end `close` itself ran found —
/// without the teardown vocabulary itself growing an agent-shaped arm.
/// `TeardownOutcome::Ambiguous` is NOT a success and this type does not offer a
/// predicate that says otherwise; `is_confirmed` delegates. In-process only: it
/// is never serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupReport {
    teardown: TeardownOutcome,
    harness_acknowledged_cancel: bool,
    turn_end: Vec<SessionEvidenceEvent>,
}

impl CleanupReport {
    /// Record a teardown.
    #[must_use]
    pub const fn new(teardown: TeardownOutcome, harness_acknowledged_cancel: bool) -> Self {
        Self {
            teardown,
            harness_acknowledged_cancel,
            turn_end: Vec::new(),
        }
    }

    /// The same report, carrying `records`: what the turn end `close` ran
    /// itself recorded and the caller had not drained with the session's
    /// evidence.
    #[must_use]
    pub fn with_turn_end(mut self, records: Vec<SessionEvidenceEvent>) -> Self {
        self.turn_end = records;
        self
    }

    /// The turn-end records `close` found still undrained once it had run the
    /// turn end itself, in the evidence's own vocabulary: the embedded harness's
    /// `TurnEnd` and `CodeModeWorkersLive` from a turn end `close` re-ran after
    /// the caller dropped `prompt`'s future and drained the evidence. Empty for
    /// every session whose `close` runs no turn end, and whenever `prompt`
    /// itself ended the turn: its records are in the evidence.
    #[must_use]
    pub fn turn_end(&self) -> &[SessionEvidenceEvent] {
        &self.turn_end
    }

    /// What the teardown observed.
    #[must_use]
    pub const fn teardown(&self) -> &TeardownOutcome {
        &self.teardown
    }

    /// Whether the harness acknowledged a cancel on the protocol before the
    /// process went away: the one record of whether a
    /// [`TurnOutcome::Cancelled`] was a CONFIRMED stop or a stop before the
    /// watermark nobody confirmed. Never on its own a claim that the process is
    /// GONE — that claim is [`TeardownOutcome::Confirmed`]'s and it names its
    /// probe.
    #[must_use]
    pub const fn harness_acknowledged_cancel(&self) -> bool {
        self.harness_acknowledged_cancel
    }

    /// Whether the process subtree's absence was OBSERVED.
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        self.teardown.is_confirmed()
    }
}

/// Cooperative cancellation for one in-flight turn.
///
/// Deliberately not `tokio_util::sync::CancellationToken`: this carries no
/// tree/child semantics and no drop-cancels behaviour, and the crate does not
/// otherwise depend on `tokio-util`. A cancel here is a REQUEST — what it
/// achieved is [`CleanupReport`]'s to say.
#[derive(Clone, Debug, Default)]
pub struct CancelToken {
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CancelToken {
    /// A token that has not been fired.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. Idempotent.
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// ONE live agent session, owned by ONE attempt.
///
/// `close` takes `self: Box<Self>` so closing consumes the session: a session
/// that has reported a [`CleanupReport`] cannot be prompted again.
#[async_trait]
pub trait AgentSession: Send {
    /// This session's protocol-level identity, derived from
    /// [`AttemptScope::session_seed`](crate::adapter::scope::AttemptScope::session_seed).
    fn session_id(&self) -> &SessionId;

    /// Run one turn.
    ///
    /// Never returns an `Err`: every way a turn can end is a [`TurnOutcome`]
    /// arm, because an `Err` at this seam is exactly the collapse that loses the
    /// clean/ambiguous distinction the outcome vocabulary exists to keep.
    async fn prompt(&mut self, prompt: &Prompt, cancel: &CancelToken) -> TurnOutcome;

    /// What this session may already have issued, read off its own
    /// [`IssuanceWatermark`].
    ///
    /// `None` means no issuance-capable frame was ever acted on — the
    /// mark-before-act discipline makes that a PROVABLE clean state, not a
    /// hope. The caller is the worker's deadline race: once the prompt
    /// future is dropped its `&mut` borrow is released, and this read is
    /// what classifies a stop the harness never confirmed — `None` is the
    /// pre-issuance stop, `Some(class)` is `Ambiguous` at exactly the class
    /// crossed, never wider.
    fn issuance(&self) -> Option<MayHaveIssued>;

    /// Drain the session's observed-event record — every refused request,
    /// model call and tool result it collected since `open` — for the worker to publish into the turn's durable
    /// evidence artifact.
    ///
    /// `close` consumes the session and this record with it; a caller that
    /// wants the record durable calls this FIRST. An empty record is an
    /// honest answer ("the harness asked for nothing") — it is not `None`,
    /// because `None` would be indistinguishable from "nobody looked".
    fn take_evidence(&mut self) -> kata_types::agent::SessionEvidence;

    /// How long this session's [`Self::prompt`] may take to hand back the
    /// outcome of a turn it can still answer, once its [`CancelToken`] fires:
    /// the grace the worker's deadline race waits before it stops waiting and
    /// classifies the turn off [`Self::issuance`] instead. `None` takes the
    /// worker's own grace, the codebase's five-second answer to "how long to
    /// wait for a counterparty to confirm a stop".
    ///
    /// A session whose `prompt` runs bounded steps of its own AFTER a stop
    /// (the embedded harness ends its turn inside `prompt`: it kills the
    /// capsule's processes and shuts its agent down before it answers) states
    /// their sum, so a stop it confirmed, and the usage that came with it, are
    /// not lost to the race. The worker never waits less than its own grace.
    fn stop_grace(&self) -> Option<std::time::Duration> {
        None
    }

    /// Close the session and report what the teardown established.
    ///
    /// # This must not hang, and the deadline is the IMPLEMENTOR's
    ///
    /// There is no budget parameter, and that is a decision rather than an
    /// omission: the caller has already handed over the process and cannot
    /// signal it, so a deadline it passed here would be a number it could not
    /// enforce. The implementor therefore owns both the deadline and the
    /// escalation, and owes the caller a [`CleanupReport`] in bounded time.
    ///
    /// Concretely: a process that catches `SIGTERM` to flush its session file is
    /// ordinary, not broken, so an implementation that waits on `Terminate`
    /// alone waits as long as that process likes — inside a teardown whose whole
    /// job is to end. An implementation must escalate to
    /// [`Signal::Kill`](crate::adapter::Signal::Kill) after a grace period it
    /// states, and it should let a caller with a real wall budget name that
    /// period.
    ///
    /// What it must NOT do is report [`TeardownOutcome::Confirmed`] on a
    /// deadline: a grace period expiring is kata declining to wait, not kata
    /// observing an absence. Either the escalated wait returns and the absence
    /// is real, or the report is `Ambiguous` with the reason it could not look.
    ///
    /// [`TeardownOutcome::Confirmed`]: crate::resource_bounds::TeardownOutcome::Confirmed
    async fn close(self: Box<Self>) -> CleanupReport;
}
