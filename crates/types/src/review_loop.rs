//! Review loop configuration — workflow-level worker/reviewer iteration.
//!
//! A [`ReviewLoop`] pairs a worker stage with a reviewer stage and iterates
//! up to `max_iterations` times until the reviewer produces an `approve`
//! verdict. When the iteration budget exhausts, [`OnMaxAction`] determines
//! the outcome.
//!
//! The shared helpers live in `kata_program::loops`; the drive is
//! `kata_workflow::runner::expansion`.

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::bound::Bound;
use crate::workflow::StageId;

/// Error returned by [`LoopVerdictConfig::new`] when the supplied verdict
/// vocabulary is malformed. Surfaced as a clean DSL/loader error rather
/// than panicking — the three tag-sets must be disjoint and non-empty and
/// the verdict field must be non-empty.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LoopVerdictConfigError {
    /// `verdict_field` was empty.
    #[error("loop gate verdict field must be a non-empty string")]
    EmptyField,
    /// One of the three tag-sets (`approve`/`refine`/`block`) was empty.
    #[error("loop gate verdict \"{role}\" tag-set must list at least one tag")]
    EmptyTagSet {
        /// The action role whose tag-set was empty.
        role: &'static str,
    },
    /// A tag appeared in more than one of the three sets (ambiguous routing).
    #[error(
        "loop gate verdict tag \"{tag}\" appears in both the \"{first}\" and \
         \"{second}\" sets; each tag must map to exactly one action"
    )]
    OverlappingTag {
        /// The duplicated tag.
        tag: SmolStr,
        /// The first action role the tag was found in.
        first: &'static str,
        /// The second action role the tag was found in.
        second: &'static str,
    },
}

/// Configurable verdict vocabulary for a review loop's gate.
///
/// Generalizes the loop gate's verdict read so the verdict FIELD NAME and
/// the TAG→ACTION mapping are author-configurable, unlocking custom
/// vocabularies (e.g. a factory controller's `{advance|park|promote}`) on
/// the existing review-loop runtime. The runtime reads
/// `parsed[verdict_field]` — a bare enum string OR an externally-tagged
/// `variant` object `{"<tag>": payload}` (the tag is the single key, same
/// discriminant read as `branch`) — then maps the tag:
///
/// * tag ∈ `approve` ⇒ loop resolves Approved (terminal);
/// * tag ∈ `refine`  ⇒ next worker iteration runs with feedback;
/// * tag ∈ `block`   ⇒ loop resolves Blocked (terminal);
/// * any other tag   ⇒ loop Aborted.
///
/// A review loop that omits `gate_verdict` uses [`Self::default_verdict`]
/// (field `"verdict"`, `approve=["approve"]`, `refine=["refine"]`,
/// `block=["block"]`) — byte-identical IR (the optional field is skipped
/// from serialization when `None`) and behaviorally identical to the
/// pre-slice hardcoded read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopVerdictConfig {
    /// The field on the reviewer's `parsed` envelope that carries the
    /// verdict. Non-empty. Default vocabulary uses `"verdict"`.
    pub verdict_field: SmolStr,
    /// Tags that resolve the loop as Approved (terminal). Non-empty,
    /// disjoint from `refine`/`block`.
    pub approve: Vec<SmolStr>,
    /// Tags that trigger the next worker iteration (refine). Non-empty,
    /// disjoint from `approve`/`block`.
    pub refine: Vec<SmolStr>,
    /// Tags that resolve the loop as Blocked (terminal). Non-empty,
    /// disjoint from `approve`/`refine`.
    pub block: Vec<SmolStr>,
}

/// The action a matched verdict tag routes to. Returned by
/// [`LoopVerdictConfig::classify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopVerdictAction {
    /// Tag is in the `approve` set.
    Approve,
    /// Tag is in the `refine` set.
    Refine,
    /// Tag is in the `block` set.
    Block,
}

/// Error returned by the `TryFrom<&str>` impls on [`ControllerDecision`] and
/// [`ControllerApplicationAction`] when the wire tag falls outside the closed
/// vocabulary. A typed error rather than a bare `()` so callers can render the
/// offending tag in their own diagnostic.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown controller tag \"{tag}\"")]
pub struct UnknownControllerTag {
    /// The tag that matched no known vocabulary entry.
    pub tag: String,
}

/// The canonical controller decision vocabulary: the
/// eight tags a factory controller — or any custom reviewer gating a review
/// loop on the same discriminant — can emit. This is the ONE Rust vocabulary
/// the executor's controller-application routing speaks, so the wire tag is
/// validated ONCE (at the parse boundary) and every downstream
/// dispatch is an exhaustive `match` the compiler keeps honest.
///
/// Parsed from the wire tag with [`TryFrom<&str>`]; rendered back with
/// [`Self::as_str`] (round-trips exactly). [`Self::application_action`] is the
/// TOTAL projection onto the server-side workspace side effect the tag applies
/// ([`ControllerApplicationAction`]), or `None` for the two tags (`stop` /
/// `ask_human`) that resolve the loop WITHOUT a server-side apply action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum ControllerDecision {
    /// Progress is valid; run another bounded wave (refine).
    Continue,
    /// Bounded defects found; fix them in the next wave (refine).
    Repair,
    /// Next work exceeds one wave; split it (refine).
    Split,
    /// The wave is too broad; narrow it (refine).
    ReduceScope,
    /// Validation is sufficient; integrate the candidate (approve).
    Promote,
    /// Validation is sufficient; no next autonomous action (approve).
    Stop,
    /// Preserve candidate state for later inspection (block).
    Park,
    /// Explicit human/product judgment is required (block).
    AskHuman,
}

impl ControllerDecision {
    /// The canonical wire tag for this decision. Inverse of
    /// [`TryFrom<&str>`]. Delegates to the derived `strum::IntoStaticStr` so the
    /// tag mapping is defined once.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    /// TOTAL projection onto the server-side apply action, or `None` when the
    /// decision resolves the loop with NO workspace side effect. `park` → Park,
    /// `promote` → Promote, the four refine tags → Advance, and `stop` /
    /// `ask_human` → `None`. Deliberately NOT a bijection: several decisions
    /// collapse to Advance and two have no action — which is why
    /// [`ControllerApplicationAction`] is a distinct, smaller vocabulary.
    #[must_use]
    pub fn application_action(self) -> Option<ControllerApplicationAction> {
        match self {
            Self::Park => Some(ControllerApplicationAction::Park),
            Self::Promote => Some(ControllerApplicationAction::Promote),
            Self::Continue | Self::Repair | Self::Split | Self::ReduceScope => {
                Some(ControllerApplicationAction::Advance)
            }
            Self::Stop | Self::AskHuman => None,
        }
    }
}

// NOTE: NOT derived via `strum::EnumString`. That derive emits both
// `FromStr` and its own `TryFrom<&str>`, each yielding `strum::ParseError` — it
// cannot produce the bespoke [`UnknownControllerTag`] error (which carries the
// offending tag for the caller). So the parse side stays hand-written; only the
// `as_str` side above is derived (`strum::IntoStaticStr`).
impl TryFrom<&str> for ControllerDecision {
    type Error = UnknownControllerTag;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "continue" => Ok(Self::Continue),
            "repair" => Ok(Self::Repair),
            "split" => Ok(Self::Split),
            "reduce_scope" => Ok(Self::ReduceScope),
            "promote" => Ok(Self::Promote),
            "stop" => Ok(Self::Stop),
            "park" => Ok(Self::Park),
            "ask_human" => Ok(Self::AskHuman),
            other => Err(UnknownControllerTag {
                tag: other.to_string(),
            }),
        }
    }
}

/// The server-side workspace apply action a [`ControllerDecision`] routes to —
/// a DISTINCT, smaller vocabulary than the eight decision tags (kept separate
/// on purpose: several decisions collapse to `Advance`, and `stop`/`ask_human`
/// have none). `PromoteThenAdvance` is a COMPOUND apply (promote the validated
/// candidate, then advance a follow-on wave) with no 1:1 decision tag: the
/// runtime constructs it for a `continue` decision, so `TryFrom<&str>` accepts
/// it but no [`ControllerDecision::application_action`] ever yields it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum ControllerApplicationAction {
    /// Park the candidate workspace at a durable ref without integrating it.
    Park,
    /// Integrate (fast-forward the trusted base onto) the candidate workspace.
    Promote,
    /// Advance a follow-on wave without touching the workspace.
    Advance,
    /// Promote the candidate AND advance a follow-on wave (compound apply).
    PromoteThenAdvance,
}

impl ControllerApplicationAction {
    /// The canonical wire tag for this apply action. Inverse of
    /// [`TryFrom<&str>`]. Delegates to the derived `strum::IntoStaticStr` so the
    /// tag mapping is defined once.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

// NOTE: see the `ControllerDecision` `TryFrom` note — the parse
// side stays hand-written to preserve the tag-carrying [`UnknownControllerTag`]
// error; only `as_str` is derived (`strum::IntoStaticStr`).
impl TryFrom<&str> for ControllerApplicationAction {
    type Error = UnknownControllerTag;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "park" => Ok(Self::Park),
            "promote" => Ok(Self::Promote),
            "advance" => Ok(Self::Advance),
            "promote_then_advance" => Ok(Self::PromoteThenAdvance),
            other => Err(UnknownControllerTag {
                tag: other.to_string(),
            }),
        }
    }
}

impl LoopVerdictConfig {
    /// Construct + validate a verdict config. Returns
    /// [`LoopVerdictConfigError`] if the field is empty, any tag-set is
    /// empty, or the three tag-sets are not pairwise disjoint.
    pub fn new(
        verdict_field: impl Into<SmolStr>,
        approve: Vec<SmolStr>,
        refine: Vec<SmolStr>,
        block: Vec<SmolStr>,
    ) -> Result<Self, LoopVerdictConfigError> {
        let config = Self {
            verdict_field: verdict_field.into(),
            approve,
            refine,
            block,
        };
        config.validate()?;
        Ok(config)
    }

    /// Re-check the construction invariants (non-empty field, non-empty +
    /// pairwise-disjoint tag-sets). [`Self::new`] runs this; it is exposed so
    /// the load-time checked-IR validator can re-validate any config that may
    /// have bypassed `new` (e.g. a `gate_verdict` deserialized from a pack),
    /// rejecting a malformed config at the checked boundary rather than letting
    /// an overlapping tag silently mis-route at runtime.
    ///
    /// # Errors
    ///
    /// [`LoopVerdictConfigError`] if the field is empty, any tag-set is empty,
    /// or the three tag-sets are not pairwise disjoint.
    pub fn validate(&self) -> Result<(), LoopVerdictConfigError> {
        if self.verdict_field.is_empty() {
            return Err(LoopVerdictConfigError::EmptyField);
        }
        for (role, set) in [
            ("approve", &self.approve),
            ("refine", &self.refine),
            ("block", &self.block),
        ] {
            if set.is_empty() {
                return Err(LoopVerdictConfigError::EmptyTagSet { role });
            }
        }
        // Pairwise disjointness. Linear scans are fine — tag-sets are tiny.
        for (a_role, a_set, b_role, b_set) in [
            ("approve", &self.approve, "refine", &self.refine),
            ("approve", &self.approve, "block", &self.block),
            ("refine", &self.refine, "block", &self.block),
        ] {
            if let Some(dup) = a_set.iter().find(|t| b_set.contains(t)) {
                return Err(LoopVerdictConfigError::OverlappingTag {
                    tag: dup.clone(),
                    first: a_role,
                    second: b_role,
                });
            }
        }
        Ok(())
    }

    /// The default verdict vocabulary, behaviorally identical to the
    /// pre-slice hardcoded read: field `"verdict"`, `approve=["approve"]`,
    /// `refine=["refine"]`, `block=["block"]`. Constructed infallibly.
    #[must_use]
    pub fn default_verdict() -> Self {
        Self {
            verdict_field: SmolStr::new("verdict"),
            approve: vec![SmolStr::new("approve")],
            refine: vec![SmolStr::new("refine")],
            block: vec![SmolStr::new("block")],
        }
    }

    /// Map a verdict tag to its action, or `None` if the tag is in none of
    /// the three sets (the runtime treats an unmatched tag as an abort).
    #[must_use]
    pub fn classify(&self, tag: &str) -> Option<LoopVerdictAction> {
        if self.approve.iter().any(|t| t == tag) {
            Some(LoopVerdictAction::Approve)
        } else if self.refine.iter().any(|t| t == tag) {
            Some(LoopVerdictAction::Refine)
        } else if self.block.iter().any(|t| t == tag) {
            Some(LoopVerdictAction::Block)
        } else {
            None
        }
    }
}

/// Action taken when a review loop exhausts its iteration budget without
/// reaching an `approve` verdict.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnMaxAction {
    /// Pause the worker stage on an approval gate so an operator can
    /// inspect the latest output + feedback and decide manually.
    Escalate,
    /// Accept the last worker output as if the reviewer had approved.
    /// The reviewer stage is marked Completed with its final verdict.
    Accept,
    /// Fail the worker stage with the reviewer's last feedback as the
    /// reason. The reviewer stage is marked Completed (its output is
    /// still useful for audit).
    #[default]
    Fail,
}

impl OnMaxAction {
    /// The closed set of exhaustion actions, in a stable order. The single
    /// source of truth for the DSL catalog's `on_exhaustion` domain and
    /// [`ReviewLoop::parse_on_max`]'s accepted spellings.
    #[must_use]
    pub const fn variants() -> &'static [Self] {
        &[Self::Escalate, Self::Accept, Self::Fail]
    }

    /// The canonical `snake_case` spelling — the SAME token
    /// [`ReviewLoop::parse_on_max`] accepts and serde emits.
    #[must_use]
    pub const fn as_tag(&self) -> &'static str {
        match self {
            Self::Escalate => "escalate",
            Self::Accept => "accept",
            Self::Fail => "fail",
        }
    }
}

/// Configuration for a worker/reviewer review loop.
///
/// Review loops are workflow-scoped: an author declares them at the top
/// level of the workflow definition, pointing at two already-defined
/// stages. The reviewer stage must list the worker stage in its
/// `depends_on` so the DAG orders them correctly for the first
/// iteration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewLoop {
    /// Stage name that produces the work under review.
    pub worker_stage: SmolStr,
    /// Stage name that evaluates the worker's output. Must return a
    /// structured envelope with a `verdict` field in
    /// `{"approve", "refine", "block"}` and an optional `feedback`
    /// string.
    pub reviewer_stage: SmolStr,
    /// Upper bound on the number of worker/reviewer iterations. Must
    /// be >= 1. Iteration 0 is the first pass; if
    /// `max_iterations == 1`, no retry is possible and a `refine`
    /// verdict triggers `on_max` immediately.
    pub max_iterations: u32,
    /// Action to take when the loop exhausts its iteration budget
    /// without reaching `approve`.
    pub on_max: OnMaxAction,
    /// Loop-scope composable
    /// walk-away [`Bound`]s, lowered from a native `loop(bounds=[..])`
    /// declaration. Each entry is a kind-tagged guard (a wall-clock `Time` or a
    /// `Cost` ceiling) scoped to *this* loop; the list carries at most one bound
    /// per kind and is stored in canonical order (`Time` before `Cost`) so
    /// author order never changes the definition hash. The iteration ceiling is
    /// already [`Self::max_iterations`] (the iteration-bound special case), so v1
    /// loop bounds accept only `Time` and
    /// `Cost`. Empty for every loop that omits `bounds=` — an empty list is
    /// skipped from serialization and the definition hash entirely, so a loop
    /// without bounds hashes as if the field did not exist.
    ///
    /// The review-loop runner enforces these as cumulative walk-aways across
    /// iterations. It folds usage/time before further dispatch, routes a trip
    /// through `on_max`, and reconstructs the cumulative state across resume.
    /// See [`crate::bound`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bounds: Vec<Bound>,
    /// An OPTIONAL custom verdict
    /// vocabulary for the gate. `None` ⇒ the default vocabulary
    /// ([`LoopVerdictConfig::default_verdict`]: field `"verdict"`,
    /// `approve=["approve"]`, `refine=["refine"]`, `block=["block"]`), which
    /// is BYTE-IDENTICAL (the field is skipped from serialization + the
    /// definition hash when `None`). `Some` GATES a custom vocabulary (custom
    /// field name + tag→action sets) on the same review-loop runtime,
    /// supporting both a bare enum string and an externally-tagged `variant`
    /// verdict (same discriminant read as `branch`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_verdict: Option<LoopVerdictConfig>,
    /// The loop's body as an ORDERED sub-DAG of
    /// stage ids (entry … exit), re-run in full each iteration. This is the
    /// "general body-subgraph" extension of the single-stage `loop()`: instead
    /// of one worker stage, the body is a multi-stage subgraph that iterates as
    /// a unit.
    ///
    /// * **Empty** ⇒ single-stage body: the body IS [`Self::worker_stage`].
    ///   The field is skipped from serialization and the definition hash when
    ///   empty.
    /// * **Non-empty** ⇒ multi-stage body: the ordered members of the body
    ///   sub-DAG. The LAST element is the body's EXIT stage and equals
    ///   [`Self::worker_stage`] (the stage whose output is "the worker output"
    ///   the gate reads + that the gate `depends_on`). Per iteration, the
    ///   runner re-dispatches the entire ordered list with per-stage `#iter-N`
    ///   synthetic naming, then fires the gate once the exit stage completes.
    ///
    /// The list is stored in dependency order (each member, except the entry,
    /// depends on its predecessor — guaranteed by the `sequence()` lowering)
    /// and validated at the checked boundary by [`Self::validate_body`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_stages: Vec<StageId>,
    /// The continue-as-new valve: the loop-scope CONTEXT-BUDGET
    /// rollover knob. A long-running (effectively unbounded) loop keeps its
    /// per-iteration prompt and its live working set from GROWING with the
    /// iteration / rollover count by performing a *distilled restart* — a
    /// "continue as new" — every this-many iterations: the per-iteration
    /// transcript context resets to a bounded distilled summary while durable
    /// memory + the monotonic iteration counter carry forward.
    ///
    /// The precise guarantee is *context does not grow with iteration count*,
    /// not *every prompt is hard-capped*. Between boundaries the prompt still
    /// carries the single latest worker output / reviewer feedback (one
    /// completion envelope, inherently response-bounded — it never accumulates);
    /// only AT a generation boundary is `previous_output` hard-replaced by the
    /// bounded summary. So a single large worker output can ride an
    /// intra-window iteration, but no transcript ever compounds across the
    /// window/rollover — the audit gap (an ever-growing carried context) is what
    /// this closes.
    ///
    /// `None` ⇒ the RUNTIME default ([`DEFAULT_ROLLOVER_AFTER_ITERATIONS`]) is
    /// applied. Enforcement is therefore ON BY DEFAULT: an author who declares
    /// no budget still gets rollover, so an unbounded loop can never accumulate
    /// an ever-growing carried context (the audit gap this closes). The field
    /// is `Option` so a loop that declares no window carries nothing in its
    /// CHECKED IR (skipped from serialization + the definition hash); the
    /// default is resolved at runtime via
    /// [`Self::effective_rollover_after_iterations`], never baked into the IR.
    ///
    /// `Some(n)` (n ≥ 1) sets a custom window. `Some(0)` is rejected at the
    /// checked boundary ([`Self::validate_rollover`]) — there is deliberately NO
    /// "disable rollover" value, because a no-budget unbounded loop is the exact
    /// audit gap this valve exists to close.
    ///
    /// # Where the boundary lands (design)
    ///
    /// The rollover is an IN-PLACE iteration-window reset, NOT a new chained
    /// execution. The absolute `iteration` counter is NEVER reset (every
    /// iteration keeps a unique `#iter-N` ledger row, so the evidence chain
    /// stays honest and monotonic); the rollover *generation* is the pure
    /// function `iteration / effective_rollover_after_iterations`, so it is
    /// re-derived on crash-resume from the ledger-restored counter with ZERO new
    /// durable markers — the maximally REPLAY-SAFE choice. What RESETS is only
    /// the per-iteration transcript context handed to the next worker prompt:
    /// at a generation boundary the runner presents a bounded distilled summary
    /// (feedback digest + carried durable-memory ref) in place of the raw prior
    /// output. See `kata_program::loops::rollover_context_for`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollover_after_iterations: Option<u32>,
}

/// The runtime default rollover window for a loop that declares no
/// explicit `rollover_after_iterations`. Generous — a normal review loop
/// resolves in a handful of iterations and never reaches it — but finite, so an
/// unbounded/long-horizon loop (a factory controller, a `continue`-heavy gate)
/// always performs a distilled restart before its per-iteration context or live
/// working set can grow without bound.
pub const DEFAULT_ROLLOVER_AFTER_ITERATIONS: u32 = 200;

impl ReviewLoop {
    /// The EFFECTIVE rollover window — the author's explicit
    /// `rollover_after_iterations` if set, otherwise
    /// [`DEFAULT_ROLLOVER_AFTER_ITERATIONS`]. Always ≥ 1 (the checked boundary
    /// rejects `Some(0)`), so callers may divide by it without a zero guard.
    #[must_use]
    pub fn effective_rollover_after_iterations(&self) -> u32 {
        self.rollover_after_iterations
            .unwrap_or(DEFAULT_ROLLOVER_AFTER_ITERATIONS)
    }

    /// Re-check the rollover-knob invariant (a set value must be ≥ 1) at
    /// the checked boundary. Exposed so the load-time checked-IR validator can
    /// reject a `rollover_after_iterations = 0` deserialized from a pack —
    /// there is no "disable" value, since a no-budget unbounded loop is the
    /// audit gap the valve closes.
    ///
    /// # Errors
    ///
    /// [`RolloverConfigError`] when `rollover_after_iterations == Some(0)`.
    pub fn validate_rollover(&self) -> Result<(), RolloverConfigError> {
        if self.rollover_after_iterations == Some(0) {
            return Err(RolloverConfigError::Zero);
        }
        Ok(())
    }
}

/// Error returned by [`ReviewLoop::validate_rollover`] when the context-budget
/// rollover knob is malformed. Surfaced as a clean checked-IR loader / DSL
/// error rather than a silent mis-configuration.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RolloverConfigError {
    /// `rollover_after_iterations` was `Some(0)`; the window must be ≥ 1 (there
    /// is no "disable" value — the default is always on).
    #[error(
        "loop rollover_after_iterations must be >= 1 (a long-running loop always \
         needs a context-budget window; omit the argument to use the default)"
    )]
    Zero,
}

impl ReviewLoop {
    /// Parse an `on_exhaustion` spelling (the native `loop(on_exhaustion=..)`
    /// kwarg) into [`OnMaxAction`]. Unknown values return `None` so the caller
    /// can surface a descriptive `KataError::Validation`. Kept in lockstep with
    /// [`OnMaxAction::as_tag`] by the DSL decode-roundtrip drift guard.
    #[must_use]
    pub fn parse_on_max(s: &str) -> Option<OnMaxAction> {
        match s {
            "escalate" => Some(OnMaxAction::Escalate),
            "accept" => Some(OnMaxAction::Accept),
            "fail" => Some(OnMaxAction::Fail),
            _ => None,
        }
    }

    /// The effective gate verdict config: the loop's explicit
    /// `gate_verdict` if set, otherwise the byte-identical default
    /// vocabulary. The runtime resolves the verdict read through this so a
    /// no-config loop behaves exactly like the pre-slice hardcoded path.
    #[must_use]
    pub fn effective_gate_verdict(&self) -> std::borrow::Cow<'_, LoopVerdictConfig> {
        match &self.gate_verdict {
            Some(cfg) => std::borrow::Cow::Borrowed(cfg),
            None => std::borrow::Cow::Owned(LoopVerdictConfig::default_verdict()),
        }
    }

    /// True when this loop has a multi-stage body sub-DAG. A single-stage body leaves `body_stages`
    /// empty and the loop's body is just [`Self::worker_stage`].
    #[must_use]
    pub fn is_multi_stage_body(&self) -> bool {
        !self.body_stages.is_empty()
    }

    /// The body's ordered member list, including the single-stage case. For a
    /// single-stage body (`body_stages` empty) this is the one-element list
    /// `[worker_stage]`; for a multi-stage body it is `body_stages` verbatim
    /// (entry … exit). The runner iterates this list in order each iteration.
    #[must_use]
    pub fn effective_body_stages(&self) -> Vec<StageId> {
        if self.body_stages.is_empty() {
            vec![StageId(self.worker_stage.clone())]
        } else {
            self.body_stages.clone()
        }
    }

    /// Validate the body-subgraph invariants for this loop at the checked
    /// boundary. A single-stage body (empty `body_stages`) is always valid —
    /// the pre-slice path. A multi-stage body must:
    ///
    /// * be non-empty (an empty multi-stage body never reaches here — empty
    ///   means single-stage — but the check is defensive);
    /// * have its LAST element equal [`Self::worker_stage`] (the exit stage is
    ///   the worker the gate reads);
    /// * NOT include [`Self::reviewer_stage`] (the gate is not a body member);
    /// * contain no duplicate stage ids.
    ///
    /// Dependency-chain consistency (each member depending on its predecessor)
    /// is established by the `sequence()` lowering and re-checked against the
    /// stage graph by the workflow-level `validate_review_loops`; this method
    /// validates only the body-list shape, which is graph-independent.
    ///
    /// # Errors
    ///
    /// [`BodySubgraphError`] when any invariant above is violated.
    pub fn validate_body(&self) -> Result<(), BodySubgraphError> {
        if self.body_stages.is_empty() {
            return Ok(());
        }
        let exit = self.body_stages.last().expect("non-empty checked above");
        if exit.0 != self.worker_stage {
            return Err(BodySubgraphError::ExitMismatch {
                exit: exit.0.clone(),
                worker_stage: self.worker_stage.clone(),
            });
        }
        for (idx, stage) in self.body_stages.iter().enumerate() {
            if stage.0 == self.reviewer_stage {
                return Err(BodySubgraphError::GateInBody {
                    gate: self.reviewer_stage.clone(),
                });
            }
            if self.body_stages[..idx].iter().any(|prev| prev == stage) {
                return Err(BodySubgraphError::DuplicateBodyStage {
                    stage: stage.0.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Error returned by [`ReviewLoop::validate_body`] when a multi-stage loop
/// body sub-DAG violates a shape invariant. Surfaced as a clean checked-IR
/// loader error rather than letting a malformed body mis-dispatch at runtime.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BodySubgraphError {
    /// The body's last (exit) stage is not the loop's `worker_stage`.
    #[error(
        "loop body exit stage \"{exit}\" must equal the loop worker_stage \
         \"{worker_stage}\" (the body's output stage is the worker the gate reads)"
    )]
    ExitMismatch {
        /// The body's actual last element.
        exit: SmolStr,
        /// The loop's `worker_stage`.
        worker_stage: SmolStr,
    },
    /// The gate (`reviewer_stage`) appears as a body member.
    #[error("loop gate stage \"{gate}\" must not be a member of the loop body")]
    GateInBody {
        /// The gate stage id found in the body.
        gate: SmolStr,
    },
    /// A stage id appears more than once in the body list.
    #[error("loop body stage \"{stage}\" appears more than once in the body sub-DAG")]
    DuplicateBodyStage {
        /// The duplicated stage id.
        stage: SmolStr,
    },
}
