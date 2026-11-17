//! The ATTEMPT SCOPE an adapter is handed, and the reason it cannot
//! name a host fact.
//!
//! ADR-0001 trust boundary 3: the main→worker boundary carries *"identities,
//! guest paths, budgets, permissions, and artifact/environment references — not
//! main-host paths"*. Trust boundary 4 continues it inward: what reaches the
//! runtime and the agent is *"only the capsule's mounts and capabilities"*.
//!
//! [`AttemptScope`] is the inward face of those two sentences. Every path it can
//! carry is a [`GuestPath`], which by its own constructor is absolute,
//! normalized, control-byte-free and under one of
//! the guest roots `kata_types::execution_contract` fixes (`/work`, `/out`,
//! `/tmp`, `/nix/store`) — so
//! `/home/alice/.codex` is not a value of this type, and an adapter that wanted
//! to reach one would have to construct a path type this module does not import.
//! That is enforced twice: by the field types here, and by the source-derived
//! check in `crates/agent/tests/adapter_contract.rs` that no `std::path` type
//! appears anywhere under `adapter/`.

use kata_types::execution_contract::{CapsuleBudgets, CapsuleId, GuestMapping, GuestPath};
use kata_types::primitives::ContentHash;
use kata_types::redaction::LiftedSecrets;
use std::sync::Arc;
use ulid::Ulid;

/// The deterministic basis for a session's identity.
///
/// A resumed attempt must be able to re-derive the SAME session name it used
/// before, without asking the vendor and without minting a fresh id — so the
/// seed is a content hash the worker computes from facts that survive a restart
/// (the capsule identity and the attempt id), never a random value and never a
/// clock read. What an adapter does with it is protocol-specific; what it may
/// NOT do is invent its own seed, which is why the field is private and there is
/// no `Default`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SessionSeed(ContentHash);

impl SessionSeed {
    /// Wrap a seed the worker derived.
    #[must_use]
    pub const fn new(hash: ContentHash) -> Self {
        Self(hash)
    }

    /// The seed bytes' hash.
    #[must_use]
    pub const fn hash(&self) -> ContentHash {
        self.0
    }
}

/// One adapter-observed session fact, offered to the attempt's progress
/// emitter as it happens rather than at evidence drain.
///
/// Evidence ([`SessionEvidence`](kata_types::agent::SessionEvidence), the bounded per-adapter event
/// records drained into the turn report) is the DURABLE observation channel —
/// it settles with the attempt and is read back by every later generation.
/// Progress is the EPHEMERAL one: it exists so an operator watching a running
/// capsule sees movement, it travels `WorkerMessage::CapsuleProgress`, and a
/// worker restart loses it without losing anything. [`SessionObservation`] is
/// the shape that ephemeral channel accepts.
///
/// Every string on one is bounded-and-scrubbed vocabulary: `kind` is a kata
/// constant naming the observation (the event fold's tag, the refused
/// request's class), and `text` is the observation's principal value — the
/// delta text for a streamed chunk, the tool call id, the method name —
/// scrubbed against the attempt's [`LiftedSecrets`] by the SAME funnel that
/// scrubs the evidence record — a stream's chunks as ONE text
/// (`kata_types::redaction::RollingScrub`), so a value split across chunks is
/// replaced whole; a chunk may carry text an earlier delta held back, and a
/// delta that releases nothing makes no chunk. The emitter further bounds
/// `text` to its own preview budget before anything crosses the wire; an
/// adapter never learns what that budget is.
pub struct SessionObservation {
    /// A kata-named tag for what happened — e.g. `"agent_message_chunk"`,
    /// `"tool_call"`, `"request_refused"`. `&'static str` deliberately: the
    /// emitter stringifies it into a preview without a lookup table, and a
    /// vendor-controlled string in this slot would be a privacy defect the
    /// type itself can rule out.
    pub kind: &'static str,
    /// The observation's principal text, when it has one — already scrubbed.
    /// `None` for a fact that is only its kind (a usage update's numbers are
    /// evidence detail, not progress text).
    pub text: Option<String>,
    /// Whether the emitter's rate window may coalesce it. The adapter decides,
    /// because only the adapter knows which of its vendor's frames are a
    /// stream and which are the turn's lifecycle.
    pub class: ObservationClass,
}

/// How the progress emitter may treat one [`SessionObservation`] inside its
/// rate window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationClass {
    /// A streamed preview — a model-text delta, a vendor's streaming-delta
    /// notification, a cumulative usage tick — that the next `Stream`
    /// observation of the SAME `kind` supersedes. Inside one window the
    /// emitter sends only the latest of each stream kind; the superseded ones
    /// are coalesced away, which is not a drop.
    ///
    /// A vendor method an adapter does not name is a `Stream`: an unknown
    /// method cannot be relied on as a lifecycle fact, and a flood of them
    /// must not spend the budget a lifecycle frame needs.
    Stream,
    /// A lifecycle fact — a model call's start, end or failure, a tool call
    /// or result, a turn boundary, a refusal. Never coalesced and never held
    /// for a window: the emitter sends it at once, after whatever stream
    /// frames it holds, so the wire keeps the order things happened in.
    Milestone,
}

/// What a session reports progress TO.
///
/// The worker owns the implementation: it is the same transport the terminal
/// `WorkerMessage` leaves on, wrapped in the emitter that rate-limits,
/// byte-bounds, counts drops and shapes the preview by the stage's authored
/// `progress_visibility`. The adapter knows none of that — `observe` returns
/// nothing, because a dropped progress frame is the emitter's fact to count,
/// never the session's to retry.
///
/// Object-safe so the scope can carry `Arc<dyn SessionProgressSink>`: one
/// sink per attempt, shared by the session and every helper the session
/// spawns.
pub trait SessionProgressSink: Send + Sync + std::fmt::Debug {
    /// Offer one observation. Never blocks a turn outcome; an emitter that
    /// cannot accept the frame counts the drop instead.
    fn observe(&self, observation: SessionObservation);
}

/// Everything ONE attempt gives ONE agent session.
///
/// Fields are private with accessors rather than `pub`, for one reason worth
/// stating: a `pub` struct invites a later field, and the field a later author
/// reaches for is the one this type exists to exclude (a host working directory,
/// a home to grant). Adding one here has to go through this module's doc.
#[derive(Clone, Debug)]
pub struct AttemptScope {
    attempt_id: Ulid,
    session_seed: SessionSeed,
    mappings: Vec<GuestMapping>,
    budgets: CapsuleBudgets,
    capsule: CapsuleId,
    secrets: LiftedSecrets,
    /// The attempt's progress sink, or `None` when the stage authored
    /// `progress_visibility = "off"` — in which case the adapter still calls
    /// `observe` nowhere because there is nothing to call it on, which is the
    /// authored semantic exactly.
    progress: Option<Arc<dyn SessionProgressSink>>,
}

impl AttemptScope {
    /// Build the scope for one attempt.
    ///
    /// `secrets` is the attempt's lifted credential set, carried for
    /// REDACTION ONLY: every vendor-influenced string an adapter puts on a
    /// kata surface goes through [`LiftedSecrets::bound`],
    /// [`LiftedSecrets::bound_field`] or [`LiftedSecrets::cut`]. It is never
    /// rendered, never sent to the vendor, and `Debug` on the set reports a
    /// count — the values themselves are the one thing this scope must never
    /// show.
    #[must_use]
    pub fn new(
        attempt_id: Ulid,
        session_seed: SessionSeed,
        mappings: Vec<GuestMapping>,
        budgets: CapsuleBudgets,
        capsule: CapsuleId,
        secrets: LiftedSecrets,
    ) -> Self {
        Self {
            attempt_id,
            session_seed,
            mappings,
            budgets,
            capsule,
            secrets,
            progress: None,
        }
    }

    /// Give the scope the attempt's progress sink. Consuming, like
    /// `with_close_budget` on the sessions: visibility is decided where the
    /// frame is authorized and is not a knob a later hand may turn.
    ///
    /// The WORKER decides whether the arc exists — a stage authoring
    /// `progress_visibility = "off"` hands `None` down, and `observe` is
    /// simply never reachable. An adapter given a sink reports every
    /// observation through it; shaping, rate and byte bounds live on the
    /// emitter side, where the authored policy is visible.
    #[must_use]
    pub fn with_progress(mut self, progress: Arc<dyn SessionProgressSink>) -> Self {
        self.progress = Some(progress);
        self
    }

    /// The attempt this session belongs to: the same `Ulid` the operational
    /// plane settles, so an ambiguity a session reports lands on the right
    /// attempt without a translation step.
    #[must_use]
    pub const fn attempt_id(&self) -> Ulid {
        self.attempt_id
    }

    /// The deterministic session-identity basis.
    #[must_use]
    pub const fn session_seed(&self) -> SessionSeed {
        self.session_seed
    }

    /// The capsule's guest mappings, in capsule order.
    #[must_use]
    pub fn mappings(&self) -> &[GuestMapping] {
        &self.mappings
    }

    /// The guest paths this session may name, in capsule order. The ONLY path
    /// vocabulary an adapter has.
    pub fn guest_paths(&self) -> impl Iterator<Item = &GuestPath> {
        self.mappings.iter().map(|mapping| &mapping.guest_path)
    }

    /// The capsule's budgets — wall time, captured output, memory, processes.
    #[must_use]
    pub const fn budgets(&self) -> CapsuleBudgets {
        self.budgets
    }

    /// The attempt's lifted credential values, for redaction only — never
    /// rendered, never sent.
    #[must_use]
    pub fn secrets(&self) -> &LiftedSecrets {
        &self.secrets
    }

    /// The capsule this attempt executes.
    #[must_use]
    pub const fn capsule(&self) -> CapsuleId {
        self.capsule
    }

    /// The attempt's progress sink, or `None` when the stage authored
    /// `progress_visibility = "off"`. Adapters report through
    /// [`SessionProgressSink::observe`] at the same points they fold evidence —
    /// the sink is how an observation becomes ephemeral signal rather than a
    /// record.
    #[must_use]
    pub fn progress(&self) -> Option<&Arc<dyn SessionProgressSink>> {
        self.progress.as_ref()
    }
}
