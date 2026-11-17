//! The named **Effect** type: a kata stage is ONE coarse Effect.
//!
//! # The Determinism Boundary
//!
//! > Orchestration is pure; every non-determinism + side-effect is a named,
//! > idempotency-keyed Effect whose result is recorded so replay returns it.
//!
//! This module is the thesis's home, as text. Its checkable form is the checked execution class
//! ([`crate::execution_class`]): a `determinism` axis whose `Deterministic` value means all
//! semantic inputs are identified and live inputs are excluded (it permits recomputation and only
//! conditionally permits content caching), a `Nondeterministic` value that is never
//! content-cacheable (a committed result always replays), and a content-cache key that folds every
//! certified ambient-input identity.
//!
//! **The clause NUMBERS are stable and MUST NOT be renumbered**: **clause 4's
//! number ships inside an operator-visible refusal message** — see the map
//! below — so renaming it is a BEHAVIOUR change, not a comment edit. Do not
//! invent a second numbering either.
//!
//! # The five clauses, and where each is enforced
//!
//! - **Clause 1** (orchestration is pure) — the ONLY clause with a live,
//!   machine-checked definition, and it is in code, not prose:
//!   `edge_condition_routes_purely` / `verify_program` in
//!   `crates/program/src/execution_program/verify.rs`, which raises the
//!   diagnostic code `clause1_orchestration_impurity`.
//! - **Clause 2** (side-effects are idempotency-keyed Effects) — no single
//!   enforcement point. The checked class covers the pieces under its external
//!   issuance axis (`DurableActivity`) and the `ReconcileRequired` pre-commit
//!   recovery policy. THIS module is the naming/observability layer.
//! - **Clause 3** (replay returns recorded Effect results) — accepted-result
//!   replay is not a policy choice: a committed result always replays.
//! - **Clause 4** (determinism classification picks the identity strategy) —
//!   content-cache eligibility is derived, never authored. Enforced by the
//!   cache guards in `compile_execution_program_with_options`
//!   (`crates/program/src/execution_program/compile.rs`), whose refusal text
//!   EMITS the literal string "clause 4" and is asserted by
//!   `crates/workflow/tests/execution_program_tests.rs`. That number is
//!   therefore a shipped operator-visible contract, not merely a comment.
//! - **Clause 5** (the Contract is the membrane) — the runner's coerce-retry
//!   (`EffectCoerceRetryPolicy`, `crates/workflow/src/runner/effect.rs`).
//!
//! # Scope
//!
//! A kata workflow *stage* IS one coarse Effect; fine-grained per-tool-call
//! Effects are deferred.
//!
//! This module NAMES that boundary so it is observable in the ledger:
//! [`EffectKind`] classifies WHAT kind of side-effect a stage performs (derived
//! from its resolved agent label / executor).
//!
//! It is purely additive metadata. The Effect's *correctness* (at-least-once +
//! idempotency + result-recording) is owned elsewhere and unchanged: the
//! runner's coerce-retry (`crates/workflow/src/runner/effect.rs`), the
//! per-attempt settlement and crash-resume, and the workspace provider's
//! lookup-first reconciliation. Naming the Effect here makes the
//! boundary observable without touching any of that machinery — and without
//! affecting any pack `program_hash` / `contract_hash` (this type lives only on
//! runtime ledger state, never on the compiled program).

use serde::{Deserialize, Serialize};

use crate::agent::BackendType;
use crate::workflow::WORKSPACE_EFFECT_AGENT_LABEL;

/// The class of side-effect a single stage performs.
///
/// A kata stage is ONE coarse Effect. The kind is
/// classified from the stage's resolved agent label / executor — it is NOT
/// authored directly; it is derived and recorded so the Effect boundary is
/// named + observable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, strum::IntoStaticStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum EffectKind {
    /// An opaque model turn — a stage routed to the embedded harness under any
    /// agent label but the deterministic ones. Non-deterministic. Per-tool-call idempotency is
    /// architecturally impossible for an opaque subprocess backend; the
    /// achievable path is a tool-mediation protocol (deferred).
    /// The whole stage-Effect is made replay-safe by recording its output in
    /// the durable ledger (so completed stages are never re-invoked).
    ModelCall,
    /// A deterministic `sh -c <cmd>` executor ([`BackendType::Shell`]). As for
    /// [`Self::ModelCall`], a completed stage is never re-invoked because its output is
    /// recorded in the durable ledger. Nothing memoizes a shell result to replay in place of
    /// running the command: a crash between running it and recording its result is settled
    /// at the attempt level — the attempt's terminal verdict
    /// ([`DeliveryFailureProvenance`]) is recorded, and one that may have performed the
    /// command is never re-run automatically.
    Shell,
    /// A recorded, replay-safe candidate-workspace mutation (park / promote /
    /// commit) via the `ExecutionWorkspaceProvider`
    /// ([`BackendType::WorkspaceEffect`]). Main-local and already
    /// idempotent via lookup-first reconciliation against execution-scoped
    /// refs — the correctness floor without any extra store.
    WorkspaceEffect,
    /// Reserved: a typed memory-plane write. No executor produces this kind
    /// today; it is named here for the typed memory-state-plane boundary so
    /// the Effect taxonomy is complete and forward-declared.
    Memory,
}

impl EffectKind {
    /// Classify a stage's Effect kind from its resolved agent label.
    ///
    /// Kept in lockstep with [`crate::agent::is_deterministic_agent_label`]:
    /// `workspace_effect` → [`Self::WorkspaceEffect`], `shell` →
    /// [`Self::Shell`], every other (or absent) label is an LLM/agent backend
    /// → [`Self::ModelCall`]. ([`Self::Memory`] is never produced by label
    /// classification today — see its doc.)
    ///
    /// ENFORCEMENT BOUNDARY (EffectKind classification): this is the LABEL-based
    /// classifier, for sites that hold only a resolved agent label and NO checked
    /// execution stage (the core ledger invocation record). Where a checked stage
    /// IS in hand, the authoritative classification derives from the seven-axis
    /// class (computation + issuance), which is strictly more informed than the
    /// label. This label form is kept as the sound boundary fallback and MUST
    /// track `is_deterministic_agent_label`; a new deterministic executor label
    /// classifies into BOTH deliberately.
    #[must_use]
    pub fn from_agent_label(label: Option<&str>) -> Self {
        match label {
            Some(l) if l == WORKSPACE_EFFECT_AGENT_LABEL => Self::WorkspaceEffect,
            Some(l) if l == BackendType::Shell.label() => Self::Shell,
            _ => Self::ModelCall,
        }
    }

    /// Stable snake_case label matching the serde representation
    /// (`model_call` / `shell` / `workspace_effect` / `memory`). Delegates to
    /// the derived `strum::IntoStaticStr` so the mapping is defined once.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    /// True if this Effect is deterministic (non-LLM): replay-stable output.
    /// Mirrors [`BackendType::is_deterministic`] over the *Effect* taxonomy.
    #[must_use]
    pub const fn is_deterministic(self) -> bool {
        matches!(self, Self::Shell | Self::WorkspaceEffect)
    }
}

/// WHAT THE MAIN CAN PROVE about a delivery that came back reporting failure.
///
/// The worker classifies its own failure exits where it can tell them apart and
/// reports the classification on `WorkerMessage::Failed`'s `verdict` field, so the
/// verdict does not die in the worker process:
/// `kata_worker::capsule_execution::execute_capsule_frame` reports a refusal before
/// the driver was asked for anything as an observation that nothing ran, and a
/// refusal after a container may have run as ambiguous. A main-side prose
/// classifier is refused: failure text is free-form, so a substring match would
/// catch one spelling of a failure class and silently miss another.
///
/// The main records the verdict on the attempt's terminal transition, and the
/// stage's failure-retry decision reads it from there
/// (`OperationalDb::attempt_terminal_verdict`): a [`Self::ProvenAmbiguous`] or
/// [`Self::Unclassified`] attempt is never re-run automatically, because the
/// effect it may have performed would be performed again. That is attempt-level
/// settlement. The only per-effect records are a `forge_export`'s push and pull
/// request intents (`forge_intents`), whose observer decides an intent a crash left
/// without a receipt (ADR 0002 as ADR 0003's stage E1 implements it); per-effect
/// permits for every other effect are proposed in ADR 0002.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, strum::EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryFailureProvenance {
    /// The main holds POSITIVE PROOF from the executing party that the effect did
    /// not happen: the delivery returned a definite negative answer.
    ///
    /// The only verdict that is an OBSERVATION that nothing ran rather than an
    /// inference, and so the only one under which redoing the work cannot perform
    /// an effect twice.
    ProvenNotPerformed,
    /// The main holds POSITIVE PROOF that the executing party stopped waiting
    /// without an answer — a deadline expiry, a cancel, a dropped call.
    ///
    /// The effect may have landed, so the attempt is never re-run automatically;
    /// the run fails and an operator decides. A timeout is ambiguous, carried as a
    /// value.
    ProvenAmbiguous,
    /// The effect WENT OUT and the stage failed anyway.
    ///
    /// Neither [`Self::ProvenNotPerformed`] (it WAS performed) nor
    /// [`Self::ProvenAmbiguous`] (nothing is unknown). The producing arm is the
    /// main's capsule settlement of a process that ran, exited, and whose
    /// completion fails the stage (`kata_workflow`'s `capsule_settlement`).
    PerformedButFailed,
    /// The report cannot be classified from anything the main durably holds.
    ///
    /// NOT a synonym for [`Self::ProvenNotPerformed`], in meaning or in what the
    /// main does with it: no information is not a negative observation, so it is
    /// treated as ambiguous.
    ///
    /// # Why the variant exists
    ///
    /// A reporter that cannot classify its own failure must be able to say so
    /// without LYING: a store it could not read (and reading it is the only way
    /// to learn whether a PRIOR attempt already issued this effect), or an error
    /// that escaped its drive without classifying itself. Such a report is not
    /// [`Self::ProvenNotPerformed`] (no observation), not
    /// [`Self::ProvenAmbiguous`] (nobody gave up waiting), and not
    /// [`Self::PerformedButFailed`] (nothing is known to have gone out). The
    /// worker's production failure paths in this build all send a classified
    /// verdict; the main decodes this one and never re-runs the attempt on it.
    /// `Unclassified` describes a live party that could not classify; it is never
    /// a serde fallback.
    Unclassified,
}

impl DeliveryFailureProvenance {
    /// Whether this provenance is an OBSERVATION that the effect did not happen.
    ///
    /// True for [`Self::ProvenNotPerformed`] alone. Deliberately not `!= Unclassified`:
    /// [`Self::ProvenAmbiguous`] is also classified, and also not a negative
    /// observation, so a predicate written as an inequality would treat a
    /// timeout's ambiguity as proof that nothing ran.
    #[must_use]
    pub const fn proves_the_effect_did_not_happen(self) -> bool {
        matches!(self, Self::ProvenNotPerformed)
    }

    // There is NO verdict for a frame that omits one. A frame whose provenance
    // nobody recorded must be read as POSSIBLY-PERFORMED, never as provably-not,
    // and the invariant lives at the DECODE: `WorkerMessage::Failed::verdict` in
    // `kata_transport::types` has no `#[serde(default)]`, so a `Failed` frame
    // that omits the field is refused by serde NAMING it rather than decoded into
    // a value this crate then has to interpret. No verdict is ever recorded
    // for a frame that stated none — `Unclassified` means only what a sender
    // SAID, which is what makes the record's line between an observed give-up
    // (`ProvenAmbiguous`) and an absent report a real distinction.
    //
    // Do not add a fallback constructor or a serde default: they are two spellings
    // of the same guess about a frame nothing produces.

    /// A stable label for logs and refusal messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProvenNotPerformed => "proven_not_performed",
            Self::ProvenAmbiguous => "proven_ambiguous",
            Self::PerformedButFailed => "performed_but_failed",
            Self::Unclassified => "unclassified",
        }
    }

    /// EVERY variant, DERIVED — for census surfaces that must not silently skip a
    /// verdict added after they were written.
    ///
    /// A hand-typed list is the failure this avoids: it keeps compiling when a
    /// variant is added, so a partition test written over it passes over a smaller
    /// set than the enum has. `strum::EnumIter` regenerates from the definition, so
    /// the census is total by construction — the same device, for the same reason,
    /// as [`crate::sandbox::ExecBackend::all`].
    pub fn every() -> impl Iterator<Item = Self> {
        <Self as strum::IntoEnumIterator>::iter()
    }
}

/// What an agent turn's MODEL PROVIDER answered when it failed the turn, as the
/// harness's own typed error classifies it — the one failure a worker can tell
/// apart by WHO decided it, not by when the protocol went away.
///
/// Orthogonal to [`DeliveryFailureProvenance`]: the verdict says whether re-running
/// the attempt is SAFE; this says whether re-running it unchanged could SUCCEED. The
/// worker states it only beside a [`DeliveryFailureProvenance::ProvenNotPerformed`]
/// verdict (`kata_worker::agent_turn`), and a plain stage's retry chain reads it off
/// each failed seat's terminal transition (`OperationalDb::occurrence_provider_failure`):
/// a [`Self::Transient`] attempt is re-run on the same agent a fixed number of times,
/// and the agent of a [`Self::Refused`] one is never run again on that chain.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, strum::EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    /// The provider answered a model request with an HTTP 4xx error response the
    /// harness does not retry (an invalid request, a credit or billing refusal, an
    /// authentication or permission refusal, an unknown model, a request too large):
    /// that request produced no output, and the same request from the same agent is
    /// refused again.
    Refused,
    /// The provider failed a model request in a way the harness classes as transient
    /// (an overload, a rate limit, a server error, a timeout, a dropped stream), and
    /// the turn ended on it once the harness's own retries were spent: a fresh
    /// attempt may succeed.
    Transient,
}

impl ProviderFailureClass {
    /// A stable label for logs, refusal messages and the durable record.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Transient => "transient",
        }
    }
}

/// HOW a durable assertion was obtained: a machine proof, or a human's word.
///
/// The one spelling of that question in the tree. Its consumer today is the
/// worker-stop discharge (`crate::execution::StopDischarge`), which admits only
/// [`Self::OperatorAsserted`]: nothing in kata can prove a worker process exited.
/// An operator assertion is admissible only because it is LABELLED — recorded as
/// though a probe had proved it, it would be a verification satisfiable by
/// observing nothing.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "provenance")]
pub enum ObservationProvenance {
    /// A PROBE queried the provider and the answer is a proof.
    Probed {
        /// The probe that answered, by name.
        probe: String,
        /// The effect kind the probe observed.
        kind: EffectKind,
    },
    /// A HUMAN asserts they checked outside kata. NOT a proof: kata has no way to
    /// verify the claim, and the record says so by carrying this variant rather
    /// than [`Self::Probed`].
    OperatorAsserted {
        /// Who asserted it. Required — an unattributed assertion is
        /// indistinguishable from a probe result to everyone reading the record
        /// later, which is the whole failure this variant exists to prevent.
        operator: String,
    },
}

impl ObservationProvenance {
    /// Whether this provenance is a machine PROOF rather than a human assertion.
    #[must_use]
    pub const fn is_a_proof(&self) -> bool {
        matches!(self, Self::Probed { .. })
    }

    /// A stable label for logs and operator output.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Probed { .. } => "probed",
            Self::OperatorAsserted { .. } => "operator_asserted",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_effect_kind_from_agent_label() {
        assert_eq!(
            EffectKind::from_agent_label(Some("workspace_effect")),
            EffectKind::WorkspaceEffect
        );
        assert_eq!(
            EffectKind::from_agent_label(Some("shell")),
            EffectKind::Shell
        );
        // The model backend label and any agent alias classify as a ModelCall.
        for llm in ["default", "planner", "reviewer"] {
            assert_eq!(
                EffectKind::from_agent_label(Some(llm)),
                EffectKind::ModelCall,
                "label {llm} must classify as ModelCall"
            );
        }
        // An absent / unknown label defaults to ModelCall (the LLM path).
        assert_eq!(EffectKind::from_agent_label(None), EffectKind::ModelCall);
        assert_eq!(
            EffectKind::from_agent_label(Some("totally_unknown")),
            EffectKind::ModelCall
        );
    }

    #[test]
    fn classification_tracks_backend_label_constants() {
        // Lockstep with the BackendType labels rather than hard-coded strings.
        assert_eq!(
            EffectKind::from_agent_label(Some(BackendType::Shell.label())),
            EffectKind::Shell
        );
        assert_eq!(
            EffectKind::from_agent_label(Some(BackendType::WorkspaceEffect.label())),
            EffectKind::WorkspaceEffect
        );
        assert_eq!(
            EffectKind::from_agent_label(Some(BackendType::Harness.label())),
            EffectKind::ModelCall
        );
    }

    #[test]
    fn deterministic_kinds_match_backend_taxonomy() {
        assert!(EffectKind::Shell.is_deterministic());
        assert!(EffectKind::WorkspaceEffect.is_deterministic());
        assert!(!EffectKind::ModelCall.is_deterministic());
        assert!(!EffectKind::Memory.is_deterministic());
    }

    #[test]
    fn effect_kind_serde_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&EffectKind::WorkspaceEffect).unwrap(),
            "\"workspace_effect\""
        );
        assert_eq!(
            serde_json::to_string(&EffectKind::ModelCall).unwrap(),
            "\"model_call\""
        );
        assert_eq!(
            serde_json::from_str::<EffectKind>("\"shell\"").unwrap(),
            EffectKind::Shell
        );
    }

    /// The not-performed PROOF predicate is true for exactly one verdict and is
    /// not the complement of `Unclassified`: an inequality-shaped spelling of it
    /// admits a verdict that must not pass.
    #[test]
    fn the_proof_predicates_are_mutually_exclusive_and_never_complements() {
        use DeliveryFailureProvenance as P;

        let proven: Vec<_> = P::every()
            .filter(|p| p.proves_the_effect_did_not_happen())
            .collect();
        assert_eq!(proven, vec![P::ProvenNotPerformed]);
        // The one variant that answers NOTHING, which is exactly its content.
        assert!(!P::Unclassified.proves_the_effect_did_not_happen());

        // COUNTERFACTUAL: `!= Unclassified` is the tempting spelling for "we know
        // something", and it is true for all three proven variants — so a redo
        // gated on it would redo a give-up AND a performed effect.
        for provenance in P::every().filter(|p| *p != P::Unclassified) {
            assert_ne!(provenance, P::Unclassified);
        }
        assert!(!P::ProvenAmbiguous.proves_the_effect_did_not_happen());
        assert!(!P::PerformedButFailed.proves_the_effect_did_not_happen());
    }

    /// The wire spelling of every verdict round-trips, and the NEW one is not an
    /// alias of an existing one.
    ///
    /// `PerformedButFailed` rides on `WorkerMessage::Failed`, so a serde spelling
    /// that collided with another variant would be a silent mis-classification at
    /// the one seam that decides whether an attempt may be re-run.
    #[test]
    fn every_verdict_round_trips_on_the_wire_under_a_distinct_tag() {
        let mut tags = std::collections::BTreeSet::new();
        for provenance in DeliveryFailureProvenance::every() {
            let json = serde_json::to_string(&provenance).expect("the verdict serializes");
            assert_eq!(
                json,
                format!("\"{}\"", provenance.as_str()),
                "`as_str` is the label operators and logs read; it must not drift from the wire tag"
            );
            assert!(
                tags.insert(json.clone()),
                "two verdicts share the wire tag {json} — a decode would silently pick one"
            );
            let back: DeliveryFailureProvenance =
                serde_json::from_str(&json).expect("the verdict decodes");
            assert_eq!(back, provenance);
        }
        assert_eq!(tags.len(), 4);
        assert!(tags.contains("\"performed_but_failed\""));
    }

    /// The main's failure-retry decision reads a provider failure's class off the
    /// durable terminal as the string `as_str` names, so the label IS the wire tag.
    #[test]
    fn every_provider_failure_class_round_trips_under_its_label() {
        use strum::IntoEnumIterator as _;
        for class in ProviderFailureClass::iter() {
            let json = serde_json::to_string(&class).expect("the class serializes");
            assert_eq!(json, format!("\"{}\"", class.as_str()));
            let back: ProviderFailureClass = serde_json::from_str(&json).expect("it decodes");
            assert_eq!(back, class);
        }
    }
}
