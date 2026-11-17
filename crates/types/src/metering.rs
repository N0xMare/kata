//! The QUALITY of a cost figure, carried alongside the figure.
//!
//! # The collapse this type exists to prevent
//!
//! kata reports one number per stage, `token_usage.cost_micro_usd`, and three
//! very different facts can arrive at it:
//!
//! 1. the provider stated this exact charge (Claude Code's `total_cost_usd`),
//! 2. kata multiplied token counts by a price table it ships, or
//! 3. kata had neither, and the number was `0`.
//!
//! Collapsed into one number, the three are indistinguishable by the time
//! anything downstream sees them: case 3 — a backend that reported no cost AND
//! no token usage — would produce `0`, which every consumer
//! (`ExecutionRecord::running_cost_micro_usd`, the `BudgetTracker` accumulator,
//! the `cost_bound` walk-away) reads as *free*.
//!
//! The consequence is sharper than a wrong dashboard number. A hard cost policy
//! — `cost_bound(..)` or `cost_budget("halt", ..)` — is kata's promise that an
//! unattended run will not spend past a ceiling. That promise is evaluated
//! against a running total. A stage that contributes a silent `0` because
//! nothing could be measured makes the total a LOWER BOUND while the policy
//! treats it as a measurement, so the ceiling can be blown through without the
//! guard ever firing. **A hard cost policy cannot fail closed on unenforceable
//! metering if the fact that a figure was unenforceable no longer exists in the
//! value being evaluated.**
//!
//! # Metering reaches every terminal, not just completions
//!
//! The readers reach in two directions, on one vocabulary:
//!
//! * **Child invocations carry their metering.** `child_invocation_summary`
//!   carries `metering` — a [`MeteringSummary`] over the child's stages plus
//!   each stage's own nested summary absorbed recursively (a grandchild's
//!   unmeterable call surfaces as `"<child stage>/<stage>"`). It is written on
//!   every route a child's terminal resolves its parent on: the `oci` `Invoke`
//!   completion AND its fail/cancel arms, each over every call the child
//!   billed (a child that ended still charged its whole spend) — and on the
//!   settlement a PARENT's own terminal makes of an `Invoke` still waiting,
//!   over every call the child billed so far (a lower bound: the child may
//!   still finish a stage it started).
//! * **Failed, cancelled and orphaned stages are charged.** The
//!   [`TerminalCharge`] a terminal transition carries — `token_usage` (what a
//!   failed call's usage measured, `Unavailable` when it cannot be stated,
//!   authoritative `0` when no billable call provably ran) and a partial
//!   `child_invocation_summary` — is folded into `running_cost_micro_usd`,
//!   `metering`, resume reconstruction, and the SAME halt evaluation a
//!   completion gets: metering fail-closed and the ceiling walk-aways.
//!
//! And the bound in the other direction: **no cost policy, and
//! `cost_budget("warn", ..)`, never halt** — not on an unmeterable stage, not
//! on a charge that cannot be measured. Every fact is recorded best-effort
//! and the run continues.
//!
//! # The trichotomy
//!
//! [`MeteredCost`] is that fact, kept attached to the number:
//!
//! * [`MeteredCost::Authoritative`] — the charge is known exactly. Either the
//!   provider stated it, or there was no billable provider at all (a `shell` /
//!   `workspace_effect` stage genuinely costs $0 of model spend, and kata knows
//!   that rather than merely failing to find out).
//! * [`MeteredCost::Estimated`] — kata derived the figure from token counts and
//!   a rate. Enforceable, but it is not what you will be billed, and
//!   [`EstimateBasis`] says which rate and how stale it is.
//! * [`MeteredCost::Unavailable`] — kata cannot say what this call cost. It is
//!   emphatically NOT `0`.
//!
//! # What this type deliberately does NOT offer
//!
//! There is no `Default`, no `From<MeteredCost> for u64`, and no accessor that
//! yields a bare `u64`. The only ways out are
//! [`MeteredCost::chargeable_micro_usd`] (an `Option`, for summing and display)
//! and [`MeteredCost::charge_under`] (a three-way [`CostCharge`] whose
//! `FailClosed` arm a policy site cannot ignore without writing the word). The
//! collapse the module exists to prevent is therefore not merely discouraged;
//! `some_response.cost.unwrap_or(estimate)` does not compile, because neither
//! [`ProviderCost`] nor `MeteredCost` has an `unwrap_or`.

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

/// The three-way quality of a cost figure, as one word.
///
/// The single spelling shared by [`MeteredCost::quality`] (per stage) and
/// [`MeteringSummary::quality`] (per execution), so an operator reading the
/// record and an operator reading a log line are reading the same vocabulary.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeteringQuality {
    /// The charge is known exactly.
    Authoritative,
    /// kata derived the charge from token counts and a rate it ships.
    Estimated,
    /// kata cannot say what this cost. Ordered LAST so
    /// [`MeteringSummary::quality`] can take the worst case with `max`.
    Unavailable,
}

impl MeteringQuality {
    /// Operator-facing label — the same token serde emits.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
            Self::Estimated => "estimated",
            Self::Unavailable => "unavailable",
        }
    }
}

/// What the PROVIDER said one agent call cost — the only cost claim a backend
/// is entitled to make.
///
/// A backend adapter parses a CLI's or an API's response. It has no price
/// table, so it can report an authoritative charge or nothing; deciding what an
/// unstated charge *means* belongs to the executor (see `kata_worker::pricing`),
/// which knows the backend type, the effective model, and the token counts.
///
/// Not an `Option<u64>`: that shape invites `.unwrap_or(estimate)` at the
/// boundary, which destroys the quality distinction. `ProviderCost` has no
/// `unwrap_or`, no `Into<u64>`, and its `Default` is [`Self::Unstated`] — the
/// honest reading of an absent field, and one that yields no number.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderCost {
    /// The provider stated this exact charge for the call, in micro-USD.
    Reported {
        /// The stated charge (USD × 1_000_000).
        micro_usd: u64,
    },
    /// The provider stated nothing usable — the field was absent, malformed, or
    /// (for a subscription-billed run) a `0` that contradicts the work done.
    ///
    /// This is NOT a claim that the call was free.
    #[default]
    Unstated,
}

impl ProviderCost {
    /// The stated charge, if the provider stated one.
    ///
    /// Deliberately the ONLY accessor: it is an `Option`, so a caller that
    /// wants a number has to say what an absent one means.
    #[must_use]
    pub const fn reported_micro_usd(self) -> Option<u64> {
        match self {
            Self::Reported { micro_usd } => Some(micro_usd),
            Self::Unstated => None,
        }
    }
}

/// Which rate produced an [`MeteredCost::Estimated`] figure, and how stale it
/// is.
///
/// An estimate is only as trustworthy as the rate behind it, and the three
/// sources differ in ways an operator must be able to act on: a shipped table
/// row has a *date*, an operator override is the operator's own responsibility,
/// and the unknown-model floor is not a measurement at all.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(tag = "rate_source", rename_all = "snake_case")]
pub enum EstimateBasis {
    /// A row from the price table kata ships.
    PriceTable {
        /// The `YYYY-MM` the shipped list prices were captured. A bound
        /// evaluated against months-old prices trips early or late, and this is
        /// the only field that lets an operator tell which.
        rates_as_of: SmolStr,
    },
    /// An operator `[[pricing.models]]` row from `kata.toml`. kata cannot date
    /// these — their freshness is the operator's to own.
    OperatorOverride,
    /// No rate row existed for this `(backend, model)`, so the conservative
    /// frontier floor was substituted. The figure is an UPPER BOUND, not a
    /// measurement, and can be high by an order of magnitude against a cheap
    /// model.
    UnknownModelFloor {
        /// The model that has no rate — the exact string an operator puts in a
        /// `[[pricing.models]]` row to replace this estimate with a real rate.
        /// Empty when the stage named no model at all.
        model: SmolStr,
    },
}

/// The cost of ONE agent call, carrying how well it is known.
///
/// Constructed by `kata_worker::pricing::meter_call`, which is the single
/// classifier: keeping the three arms in one total function is what makes the
/// trichotomy exhaustive rather than a convention each backend re-implements.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "quality", rename_all = "snake_case")]
pub enum MeteredCost {
    /// The charge is known exactly — the provider stated it, or the stage made
    /// no billable provider call (`shell`, `workspace_effect`), for which `0`
    /// is a fact rather than a failure to measure.
    Authoritative {
        /// The exact charge (USD × 1_000_000).
        micro_usd: u64,
    },
    /// kata priced the call from its token counts. Real, and safe to enforce
    /// against, but not what the provider will bill.
    Estimated {
        /// The derived charge (USD × 1_000_000).
        micro_usd: u64,
        /// Which rate produced it, and how stale that rate is.
        basis: EstimateBasis,
    },
    /// kata cannot say what this call cost: the provider stated no charge AND
    /// reported no token usage to price. **Not zero** — the whole reason this
    /// variant exists is that `0` and "unknown" had been the same value.
    Unavailable {
        /// The backend whose call could not be priced.
        backend: SmolStr,
        /// The effective model, or empty when the stage named none.
        model: SmolStr,
    },
}

impl MeteredCost {
    /// This cost's quality, as one word.
    #[must_use]
    pub const fn quality(&self) -> MeteringQuality {
        match self {
            Self::Authoritative { .. } => MeteringQuality::Authoritative,
            Self::Estimated { .. } => MeteringQuality::Estimated,
            Self::Unavailable { .. } => MeteringQuality::Unavailable,
        }
    }

    /// The figure, when one exists — for SUMMING and DISPLAY.
    ///
    /// `None` for [`Self::Unavailable`], and the `Option` is the point: a total
    /// built by skipping `None`s is a sum of *known* costs (honest, and a lower
    /// bound), whereas one built by substituting `0` is a sum that claims to be
    /// complete. Policy sites must use [`Self::charge_under`] instead — see its
    /// docs for why an `Option` is not enough there.
    #[must_use]
    pub const fn chargeable_micro_usd(&self) -> Option<u64> {
        match self {
            Self::Authoritative { micro_usd } | Self::Estimated { micro_usd, .. } => {
                Some(*micro_usd)
            }
            Self::Unavailable { .. } => None,
        }
    }

    /// Resolve this cost for a scope evaluating a cost POLICY under
    /// `enforcement`.
    ///
    /// [`Self::chargeable_micro_usd`] is not sufficient at a policy site
    /// because `Option<u64>` still admits `.unwrap_or(0)`, and `0` is precisely
    /// the substitution that makes a hard bound unenforceable while looking
    /// enforced. The returned [`CostCharge`] has no numeric arm for the
    /// unmeterable case at all: a caller reaches the halt decision by matching
    /// [`CostCharge::FailClosed`], or it does not compile.
    #[must_use]
    pub fn charge_under(&self, enforcement: CostEnforcement) -> CostCharge {
        match self {
            Self::Authoritative { micro_usd } | Self::Estimated { micro_usd, .. } => {
                CostCharge::Add(*micro_usd)
            }
            Self::Unavailable { backend, model } => {
                let backend = backend.clone();
                let model = model.clone();
                match enforcement {
                    CostEnforcement::Hard => CostCharge::FailClosed { backend, model },
                    CostEnforcement::Advisory => CostCharge::RecordUnmetered { backend, model },
                }
            }
        }
    }
}

/// Whether the scope evaluating a cost carries a HARD policy — one kata has
/// promised to enforce.
///
/// "Hard" is `cost_bound(..)` (an unconditional walk-away) or
/// `cost_budget("halt", ..)`. `cost_budget("warn", ..)` and no policy at all
/// are [`Self::Advisory`]: they make no promise, so there is nothing to fail
/// closed on.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CostEnforcement {
    /// A `cost_bound` or a `Halt`-mode cost budget applies to this scope.
    Hard,
    /// No policy, or a `Warn`-mode budget: cost is observed, not promised.
    Advisory,
}

impl CostEnforcement {
    /// Classify a scope from whether a hard guard applies to it.
    #[must_use]
    pub const fn from_hard(hard: bool) -> Self {
        if hard { Self::Hard } else { Self::Advisory }
    }
}

/// The outcome of resolving a [`MeteredCost`] at a policy site.
///
/// Three arms because there are three genuinely different obligations, and
/// collapsing any two of them re-creates the defect: `Add(0)` for an unmetered
/// call is the original bug, and treating every unmetered call as fatal would
/// halt every `shell`-only workflow that never made a promise in the first
/// place.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CostCharge {
    /// Fold this into the running total.
    Add(u64),
    /// The call is UNMETERABLE and a hard policy is in force. The promise
    /// cannot be kept, so the caller must stop rather than continue spending
    /// against a ceiling it can no longer measure.
    FailClosed {
        /// The backend whose call could not be priced.
        backend: SmolStr,
        /// The effective model, or empty when the stage named none.
        model: SmolStr,
    },
    /// The call is UNMETERABLE and no hard policy is in force. Nothing is
    /// added, the fact is recorded on the operator surface, and the run
    /// continues — there was no ceiling to blow through.
    RecordUnmetered {
        /// The backend whose call could not be priced.
        backend: SmolStr,
        /// The effective model, or empty when the stage named none.
        model: SmolStr,
    },
}

/// One stage whose cost kata could not measure — named so the operator surface
/// carries a recourse, not just a count.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UnmeteredStage {
    /// The stage that produced an unmeterable cost.
    pub stage: String,
    /// The backend it ran on.
    pub backend: String,
    /// The effective model, or empty when the stage named none.
    pub model: String,
}

/// The QUALITY of an execution's
/// [`running_cost_micro_usd`](crate::execution::ExecutionRecord::running_cost_micro_usd),
/// projected onto the record an operator actually reads.
///
/// # Why this is on the record and not only in a log line
///
/// Tests that assert only the dispatcher's own assignment rows cannot catch a
/// wrong operator-facing projection, so the quality must be ON the projection.
/// A WARN log and a `kata_pricing_unknown_model_fallback_total` counter for the
/// unknown-model floor do not stop an estimated charge from being
/// indistinguishable from an authoritative one at every surface a person or a
/// policy reads.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct MeteringSummary {
    /// Completed stages whose charge the provider stated exactly, plus stages
    /// that made no billable provider call.
    #[serde(default)]
    pub authoritative_stages: u32,
    /// Completed stages kata PRICED from token counts. Their cost is included
    /// in `running_cost_micro_usd` and is not what you will be billed.
    #[serde(default)]
    pub estimated_stages: u32,
    /// Completed stages kata could NOT price. They contribute NOTHING to
    /// `running_cost_micro_usd`, which is therefore a LOWER BOUND whenever this
    /// is non-zero.
    #[serde(default)]
    pub unmetered_stages: u32,
    /// How much of `running_cost_micro_usd` is estimated rather than billed.
    #[serde(default)]
    pub estimated_micro_usd: u64,
    /// The unmetered stages by name, with the `(backend, model)` pair each
    /// ran on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmetered: Vec<UnmeteredStage>,
    /// The tokens the folded stages RECORDED, every class counted
    /// ([`StageUsage::recorded_tokens`]) — a LOWER BOUND whenever
    /// [`Self::tokens_unknown`] is non-empty. The figure a `token_bound` is
    /// enforced against, and what a parent's token fold charges for a child.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub tokens: u64,
    /// The stages whose token count is UNKNOWN (a usage stating no count), by
    /// name, with the `(backend, model)` pair each ran on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens_unknown: Vec<UnmeteredStage>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl MeteringSummary {
    /// Fold one stage's cost into the summary.
    #[allow(clippy::missing_panics_doc)]
    pub fn fold(&mut self, stage: &str, cost: &MeteredCost) {
        match cost {
            MeteredCost::Authoritative { .. } => {
                self.authoritative_stages = self.authoritative_stages.saturating_add(1);
            }
            MeteredCost::Estimated { micro_usd, .. } => {
                self.estimated_stages = self.estimated_stages.saturating_add(1);
                self.estimated_micro_usd = self.estimated_micro_usd.saturating_add(*micro_usd);
            }
            MeteredCost::Unavailable { backend, model } => {
                self.unmetered_stages = self.unmetered_stages.saturating_add(1);
                self.unmetered.push(UnmeteredStage {
                    stage: stage.to_owned(),
                    backend: backend.to_string(),
                    model: model.to_string(),
                });
            }
        }
    }

    /// Fold one stage's whole recorded usage: its cost ([`Self::fold`]) and its
    /// tokens — the known count, or the stage named as token-unknown.
    pub fn fold_usage(&mut self, stage: &str, usage: &StageUsage) {
        self.fold(stage, &usage.cost);
        if let Some(tokens) = usage.recorded_tokens() {
            self.tokens = self.tokens.saturating_add(tokens);
        } else {
            let (backend, model) = usage.cost_pair();
            self.tokens_unknown.push(UnmeteredStage {
                stage: stage.to_owned(),
                backend: backend.to_owned(),
                model: model.to_owned(),
            });
        }
    }

    /// Fold ANOTHER execution's metering summary into this one — the
    /// `child_invocation_summary.metering` an `Invoke` stage carries for its
    /// child, or a child stage's own nested summary.
    ///
    /// `prefix` is the child stage path: every unmetered stage name in `other`
    /// is re-recorded as `"<prefix>/<stage>"`, so a record or a halt reason
    /// still names where the unmeasurable call happened rather than losing it
    /// inside a generic count.
    #[allow(clippy::missing_panics_doc)]
    pub fn absorb(&mut self, prefix: &str, other: &MeteringSummary) {
        self.authoritative_stages = self
            .authoritative_stages
            .saturating_add(other.authoritative_stages);
        self.estimated_stages = self.estimated_stages.saturating_add(other.estimated_stages);
        self.unmetered_stages = self.unmetered_stages.saturating_add(other.unmetered_stages);
        self.estimated_micro_usd = self
            .estimated_micro_usd
            .saturating_add(other.estimated_micro_usd);
        self.unmetered
            .extend(other.unmetered.iter().map(|u| UnmeteredStage {
                stage: format!("{prefix}/{}", u.stage),
                backend: u.backend.clone(),
                model: u.model.clone(),
            }));
        self.tokens = self.tokens.saturating_add(other.tokens);
        self.tokens_unknown
            .extend(other.tokens_unknown.iter().map(|u| UnmeteredStage {
                stage: format!("{prefix}/{}", u.stage),
                backend: u.backend.clone(),
                model: u.model.clone(),
            }));
    }

    /// The execution's metering quality: the WORST any stage reported.
    ///
    /// One unmeterable stage makes the whole total unmeterable, which is why
    /// this is a max and not an average — an operator asking "can I trust this
    /// number" is asking about the weakest link.
    ///
    /// An execution with no completed stages at all reads
    /// [`MeteringQuality::Authoritative`]: it has spent nothing, and `0` is a
    /// fact about it.
    #[must_use]
    pub fn quality(&self) -> MeteringQuality {
        if self.unmetered_stages > 0 {
            MeteringQuality::Unavailable
        } else if self.estimated_stages > 0 {
            MeteringQuality::Estimated
        } else {
            MeteringQuality::Authoritative
        }
    }

    /// `true` when nothing has been folded — used to keep the field off the
    /// wire for executions that recorded no completions, so their golden bodies
    /// carry no metering object.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.authoritative_stages == 0 && self.estimated_stages == 0 && self.unmetered_stages == 0
    }

    /// Operator-facing warning lines for
    /// [`ExecutionRecord::warnings`](crate::execution::ExecutionRecord::warnings)
    /// — ONE per distinct `(backend, model)`, not one per stage.
    ///
    /// Grouped because the RECOURSE is per-`(backend, model)`: every stage of
    /// one pair has the same one, so a 200-stage workflow on one unpriced model
    /// needs one line, not 200 near-identical ones repeating the same fix. Each line still names every affected stage, and
    /// [`Self::unmetered`] carries the per-stage rows for anything that wants
    /// them structured.
    ///
    /// Prefixed `unmetered_cost:` to sit beside the `walk_away_halt:` lines in
    /// the same field, and each line NAMES the recourse rather than
    /// merely reporting the problem — a warning an operator cannot act on is a
    /// report.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        // BTreeMap so the lines are deterministically ordered: `warnings` is
        // compared in tests and read by operators, and a set-iteration order
        // would make an identical run produce a different record.
        let mut by_pair: std::collections::BTreeMap<(&str, &str), Vec<&str>> =
            std::collections::BTreeMap::new();
        for u in &self.unmetered {
            by_pair
                .entry((u.backend.as_str(), u.model.as_str()))
                .or_default()
                .push(u.stage.as_str());
        }
        by_pair
            .into_iter()
            .map(|((backend, model), stages)| {
                let model = if model.is_empty() { "<none>" } else { model };
                let stage_list = stages
                    .iter()
                    .map(|s| format!("`{s}`"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "unmetered_cost: {} stage(s) [{stage_list}] ran on backend `{backend}` \
                     (model `{model}`), whose cost kata could not price, so their cost is \
                     UNKNOWN and contributes NOTHING to running_cost_micro_usd — that total is \
                     a lower bound, not a measurement. Recourse: {}.",
                    stages.len(),
                    unpriced_recourse(backend),
                )
            })
            .collect()
    }
}

/// The recourse for a stage kata could not price on `backend`.
///
/// kata meters a stage `Unavailable` for an adapter with no billing backend,
/// under a `subscription` credential, or when its call reported no token usage
/// (`kata_worker::pricing::meter_call` and `meter_agent_turn`). A
/// `[[pricing.models]]` row prices none of the three — its `backend` is a
/// [`BillingBackend`](crate::agent::BillingBackend), which no adapter label decodes
/// as — so the recourse never names one. An adapter label with no billing
/// backend gets the adapters kata prices; any other backend gets the
/// credential and the usage.
fn unpriced_recourse(backend: &str) -> String {
    use crate::agent::AdapterKind;
    if AdapterKind::from_label(backend).is_some_and(|kind| kind.billing_backend().is_none()) {
        let priced = AdapterKind::ALL
            .into_iter()
            .filter(|kind| kind.billing_backend().is_some())
            .map(|kind| format!("`{}`", kind.as_label()))
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "kata has no price for adapter `{backend}` under any credential, and no \
             `[[pricing.models]]` row can give it one; run the stage on an adapter kata \
             prices ({priced}) under an `api_key` credential"
        );
    }
    format!(
        "a stage on `{backend}` is unpriced when its credential is `subscription` (flat-rate \
         spend has no per-token price) or when its call reported no usage; run it under an \
         `api_key` credential on a backend that reports usage"
    )
}

/// The reason string a run halted on unenforceable metering records, and the
/// prefix an operator greps for.
///
/// Mirrors `bound_exceeded:` / `budget_exceeded:` — the two reason prefixes
/// already surfaced on `ExecutionRecord::error` — so the three
/// walk-away causes read as one vocabulary.
pub const METERING_UNAVAILABLE_REASON_PREFIX: &str = "metering_unavailable";

/// Compose the operator-facing halt reason for a fail-closed metering halt.
///
/// Free function rather than a `Display` impl because BOTH the runner (writing
/// the durable synthetic row) and any later projection must produce the exact
/// same sentence; a second hand-spelled copy is the drift `kata_types::bound`'s
/// marker constants were pulled down here to prevent.
#[must_use]
pub fn metering_unavailable_reason(stage: &str, backend: &str, model: &str) -> String {
    let model = if model.is_empty() { "<none>" } else { model };
    format!(
        "{METERING_UNAVAILABLE_REASON_PREFIX}: stage {stage:?} on backend `{backend}` (model \
         `{model}`) has a cost kata could not price, and this run carries a HARD cost policy. \
         kata cannot keep a spend ceiling it cannot measure, so the run halted rather than \
         continue unbounded. Recourse: {}, or replace the hard cost policy with \
         `cost_budget(\"warn\", ..)`.",
        unpriced_recourse(backend),
    )
}

/// The reason prefix a run halted on an UNKNOWN token count under a
/// `token_bound` records — the token twin of
/// [`METERING_UNAVAILABLE_REASON_PREFIX`].
pub const TOKEN_METERING_UNAVAILABLE_REASON_PREFIX: &str = "token_metering_unavailable";

/// Compose the operator-facing halt reason for a fail-closed token halt: the
/// stage path whose token count is unknown, under a `token_bound`.
#[must_use]
pub fn token_metering_unavailable_reason(stage: &str, backend: &str, model: &str) -> String {
    let backend = if backend.is_empty() {
        "<unknown>"
    } else {
        backend
    };
    let model = if model.is_empty() { "<none>" } else { model };
    format!(
        "{TOKEN_METERING_UNAVAILABLE_REASON_PREFIX}: stage {stage:?} on backend `{backend}` (model \
         `{model}`) recorded no token count, and this run carries a `token_bound`. kata cannot \
         keep a token ceiling it cannot count, so the run halted rather than continue \
         unbounded. Recourse: run the stage on an adapter that reports every token class, or \
         drop the `token_bound` and bound the run with a `time_bound`."
    )
}

/// Extract a stage record's KNOWN cost in micro-USD — the
/// SAME two fields every cost reader sums, on BOTH terminal shapes: a
/// completion envelope's `token_usage.cost_micro_usd` plus any
/// `child_invocation_summary.token_usage.cost_micro_usd`, and — because
/// [`TerminalCharge::envelope`] re-serializes the charge as exactly that flat
/// object — the identical read on a failed/cancelled/orphaned terminal's
/// charge. `WorkflowRunner::check_halts_for_stage` and
/// `check_halts_for_terminal_charge`, the per-loop bound, the operational
/// plane's `Invoke` child fold and `resume_authority`'s loop reconstruction
/// all call this one function, so workflow-scope, per-loop, failed-stage and
/// child-invocation cost accounting are guaranteed to agree
/// (saturating-added). A record missing either field — a non-LLM stage, a
/// terminal with no carried charge, an `Unavailable` cost — contributes 0, which is a sum of
/// KNOWN costs and never a claim that the spend was zero.
///
/// `cost_micro_usd` is ABSENT (rather than `0`) on a stage whose
/// cost the worker could not determine, so this returns a sum of KNOWN costs.
/// The quality of that sum is `envelope_cost_quality` (`kata_program::loops`)'s answer, and a hard
/// cost policy must consult it — a total that silently omits an unmeasurable
/// stage is a lower bound, and enforcing a ceiling against a lower bound is the
/// unenforceable case metering fail-closed exists to catch.
#[must_use]
pub fn envelope_cost_micro_usd(envelope: &serde_json::Value) -> u64 {
    let direct = envelope
        .get("token_usage")
        .and_then(|tu| tu.get("cost_micro_usd"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    direct.saturating_add(envelope_child_cost_micro_usd(envelope))
}

/// The CHILD half of [`envelope_cost_micro_usd`]: the
/// `child_invocation_summary.token_usage.cost_micro_usd` an `Invoke` stage's
/// envelope carries — spend the child execution accepted on its OWN chain, which
/// the parent charges as well. A sum ACROSS executions subtracts it, or it counts
/// every child's spend twice (`ExecutionRecord::own_cost_micro_usd`).
#[must_use]
pub fn envelope_child_cost_micro_usd(envelope: &serde_json::Value) -> u64 {
    envelope
        .get("child_invocation_summary")
        .and_then(|summary| summary.get("token_usage"))
        .and_then(|tu| tu.get("cost_micro_usd"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

/// The `token_usage` object a stage's terminal record carries — the SAME
/// shape a completion envelope's `token_usage` field uses, shared by the
/// completion path and `WorkerMessage::Failed`'s `usage` so a failure and a
/// success state the identical facts.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageUsage {
    /// Tokens the backend reported consuming on input.
    #[serde(default)]
    pub input: u64,
    /// Tokens the backend reported producing.
    #[serde(default)]
    pub output: u64,
    /// Cached input tokens the backend reported.
    #[serde(default)]
    pub cache_read: u64,
    /// Tokens written to cache.
    #[serde(default)]
    pub cache_write: u64,
    /// Estimated saving of cached input tokens (micro-USD).
    #[serde(default)]
    pub cache_savings_micro_usd: u64,
    /// What the call's measured cost is — the metering trichotomy in one
    /// value, never a bare number that could smuggle "unknown" through as `0`.
    pub cost: MeteredCost,
    /// The chargeable micro-USD figure, where `cost` carries one. `None` on
    /// `Unavailable`, so no reader can sum an unknown into a total. Derived
    /// from `cost` by the constructors, never independently set, so the two
    /// fields cannot disagree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_micro_usd: Option<u64>,
}

/// How the credentials a billable provider call ran under were issued — the
/// credential-mode metering rule.
///
/// The mode decides whether a token-derived estimate is honest. On an
/// `ApiKey` call an operator pays the provider's published list rate, so
/// kata's price-table estimate is a real bound. On a `Subscription` call the
/// flat-rate plan has no per-token price, so a per-token estimate would be a
/// fabricated precision — real spend, but not one a price table can bound —
/// and [`MeteredCost::Unavailable`] is the honest answer.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    /// An API key the operator pays per token — the estimate is honest.
    ApiKey,
    /// A subscription credential (a lifted OAuth or session token) whose
    /// plan is flat-rate — real spend with no per-token price kata can
    /// bound, so the cost is [`MeteredCost::Unavailable`], never Estimated.
    Subscription,
}

impl CredentialMode {
    /// The node's `[agents.<label>] credential.mode` spelling.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::Subscription => "subscription",
        }
    }

    /// Parse the node's `[agents.<label>] credential.mode` value. `None` for
    /// anything not in the two-mode vocabulary — the caller names the refusal.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "api_key" => Some(Self::ApiKey),
            "subscription" => Some(Self::Subscription),
            _ => None,
        }
    }
}

impl StageUsage {
    /// The usage of a completed call whose token counts the backend reported.
    ///
    /// `cost_micro_usd` is derived from `cost` here so the value and its
    /// flat sum field can never be written inconsistently.
    #[must_use]
    pub fn metered(
        usage: &crate::cache::TokenUsage,
        cost: MeteredCost,
        cache_savings_micro_usd: u64,
    ) -> Self {
        Self {
            input: usage.input,
            output: usage.output,
            cache_read: usage.cache_read,
            cache_write: usage.cache_write,
            cache_savings_micro_usd,
            cost_micro_usd: cost.chargeable_micro_usd(),
            cost,
        }
    }

    /// The usage of a stage that failed AFTER a billable provider call whose
    /// cost is now unknowable — the timeout, the lost connection, the verdict
    /// that cannot prove non-performance. Zero counters (nothing measured
    /// survives to report) and an [`MeteredCost::Unavailable`] cost naming the
    /// backend and model the call went to, so a hard policy fails closed
    /// naming that pair.
    #[must_use]
    pub fn unmetered(backend: impl Into<SmolStr>, model: impl Into<SmolStr>) -> Self {
        Self::metered(
            &crate::cache::TokenUsage::default(),
            MeteredCost::Unavailable {
                backend: backend.into(),
                model: model.into(),
            },
            0,
        )
    }

    /// The usage of a stage that provably made NO billable provider call —
    /// a shell or `workspace_effect` stage, or a failure the verdict
    /// provably-pre-call refused. `0` is a fact here, not a placeholder.
    #[must_use]
    pub fn unbilled() -> Self {
        Self::metered(
            &crate::cache::TokenUsage::default(),
            MeteredCost::Authoritative { micro_usd: 0 },
            0,
        )
    }

    /// The tokens this usage RECORDS — every class kata counts, summed:
    /// `input + output + cache_read + cache_write`. The adapters normalize
    /// them to disjoint counts (`input` excludes the cached prefix and the
    /// cache writes; reasoning rides inside `output`), so the sum is the
    /// vendor's own total of tokens processed. Counting only `input + output`
    /// would let a cache-heavy agent turn, whose prefix is mostly cached,
    /// under-count by most of its tokens.
    ///
    /// `None` — UNKNOWN — when every counter is zero and the cost is anything
    /// but the authoritative `0` of a call that billed nothing: that is the
    /// [`Self::unmetered`] shape a lost or unreported turn records, never a
    /// measured zero. [`Self::unbilled`] (a shell or effect stage) is `Some(0)`.
    #[must_use]
    pub fn recorded_tokens(&self) -> Option<u64> {
        let sum = self
            .input
            .saturating_add(self.output)
            .saturating_add(self.cache_read)
            .saturating_add(self.cache_write);
        if sum == 0 && self.cost != (MeteredCost::Authoritative { micro_usd: 0 }) {
            return None;
        }
        Some(sum)
    }

    /// The `(backend, model)` this usage's cost names — the pair an
    /// `Unavailable` cost carries, empty for a known one.
    #[must_use]
    pub fn cost_pair(&self) -> (&str, &str) {
        match &self.cost {
            MeteredCost::Unavailable { backend, model } => (backend.as_str(), model.as_str()),
            MeteredCost::Authoritative { .. } | MeteredCost::Estimated { .. } => ("", ""),
        }
    }
}

/// The tokens ONE stage record states, off the envelope shape every cost
/// reader takes — a completion's output or [`TerminalCharge::envelope`]: its
/// own `token_usage` and an invoked child's `child_invocation_summary.metering`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct EnvelopeTokens {
    /// The tokens the record states — its own plus its child's known count.
    pub known: u64,
    /// The FIRST stage whose count it cannot state — this stage's own, or a
    /// child's re-rooted as `"<stage>/<child stage>"` — or `None`.
    pub unknown: Option<UnmeteredStage>,
}

/// Read [`EnvelopeTokens`] off one stage record — the token twin of
/// [`envelope_cost_micro_usd`], shared by the workflow-scope fold (completion
/// and terminal charge) and the per-loop fold.
///
/// * `token_usage` absent or `null` — a shell stage's completion, a
///   main-resolved stage — states `0`: no billable call ran.
/// * `token_usage` present: [`StageUsage::recorded_tokens`], or this stage
///   named as unknown — also when the object does not decode as a
///   [`StageUsage`], which states no count it can be held to.
/// * `child_invocation_summary.metering`: the child's `tokens` add, and its
///   first `tokens_unknown` stage is the unknown, re-rooted. A summary with no
///   `metering` key states nothing — the carve-out every cost reader applies.
#[must_use]
pub fn envelope_tokens(stage: &str, envelope: &serde_json::Value) -> EnvelopeTokens {
    let mut read = EnvelopeTokens::default();
    match envelope.get("token_usage") {
        None | Some(serde_json::Value::Null) => {}
        Some(raw) => {
            let unknown = |backend: &str, model: &str| UnmeteredStage {
                stage: stage.to_owned(),
                backend: backend.to_owned(),
                model: model.to_owned(),
            };
            match serde_json::from_value::<StageUsage>(raw.clone()) {
                Ok(usage) => {
                    if let Some(tokens) = usage.recorded_tokens() {
                        read.known = tokens;
                    } else {
                        let (backend, model) = usage.cost_pair();
                        read.unknown = Some(unknown(backend, model));
                    }
                }
                Err(_) => read.unknown = Some(unknown("", "")),
            }
        }
    }
    if let Some(child) = envelope
        .get("child_invocation_summary")
        .and_then(|summary| summary.get("metering"))
        .and_then(|metering| serde_json::from_value::<MeteringSummary>(metering.clone()).ok())
    {
        read.known = read.known.saturating_add(child.tokens);
        if read.unknown.is_none()
            && let Some(first) = child.tokens_unknown.first()
        {
            read.unknown = Some(UnmeteredStage {
                stage: format!("{stage}/{}", first.stage),
                backend: first.backend.clone(),
                model: first.model.clone(),
            });
        }
    }
    read
}

/// The usage ONE agent turn is charged: the metered [`StageUsage`] the worker
/// reported, or — when the vendor reported nothing parseable, or no report
/// reached the main at all — [`StageUsage::unmetered`] naming the adapter and
/// the model, because a turn that was issued is never a free one.
///
/// The one rule both readers of a turn's report apply: the accepted completion
/// (`capsule_result_output`'s `token_usage`) and a capsule attempt the main
/// settles failed (`Dispatcher::settle_capsule_attempt`'s `terminal_charge`).
#[must_use]
pub fn agent_turn_usage(reported: Option<&StageUsage>, adapter: &str, model: &str) -> StageUsage {
    reported.map_or_else(
        || StageUsage::unmetered(adapter, model),
        std::clone::Clone::clone,
    )
}

/// The usage ONE capsule attempt is charged when no report of its turn states
/// one — the worker refusing an attempt at or past its container, and the main
/// settling one it lost sight of (`Dispatcher::settlement_charge`). A `Command`
/// capsule makes no billable call: the authoritative `0`
/// ([`StageUsage::unbilled`]). An `Agent` turn may have been issued:
/// [`StageUsage::unmetered`] naming its adapter and its DECLARED model (no
/// report says which model answered), never a zero. One rule for both sides, so
/// a lost attempt is charged the same whichever of them records its terminal.
#[must_use]
pub fn unreported_capsule_usage(process: &crate::execution_contract::CapsuleProcess) -> StageUsage {
    match process {
        crate::execution_contract::CapsuleProcess::Command { .. } => StageUsage::unbilled(),
        crate::execution_contract::CapsuleProcess::Agent(turn) => StageUsage::unmetered(
            turn.adapter.as_label(),
            turn.model.as_ref().map_or("", SmolStr::as_str),
        ),
    }
}

/// What a failed, cancelled or orphaned terminal transition's `terminal_charge`
/// object carries: the same two keys a completed stage's envelope puts at its
/// top level — the stage's own `token_usage` (what its billable work measured,
/// or the authoritative `0` of a call that never billed) and the
/// `child_invocation_summary` of a child execution it invoked.
///
/// Serialized as the flat object `{"token_usage": …, "child_invocation_
/// summary": …}` so [`TerminalCharge::envelope`] is the identity the shared
/// cost readers already take.
///
/// # Which terminals owe one
///
/// A failure-class terminal of an attempt that was DISPATCHED to a worker —
/// one whose dispatch frame may have reached a worker, so whose process may
/// have run and whose agent turn may have been issued — always carries a
/// charge: the writer refuses one without it, or with an empty one
/// (`terminal_charge_required`,
/// `kata_core`'s main-side writer; the worker-failure acceptance always writes
/// one). Its `token_usage` is the turn's reported usage, the `Unavailable`
/// shape when the turn's usage is unknown, or the authoritative `0` of a
/// process that provably made no billable call (a `Command` capsule, a frame
/// that provably never reached a worker). A terminal of an attempt that was
/// never dispatched (a claim settled before its dispatch, a rejected approval
/// gate, a main-resolved attempt) owes none: nothing it ran could bill. Every
/// reader reads a dispatched attempt's absent charge through
/// [`Self::as_read`], as unknown — never as `0`.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalCharge {
    /// The stage's own metered usage — `None` on a terminal that owes no
    /// charge for its own work (see the type's doc), or one that carries
    /// only an invoked child's summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_usage: Option<StageUsage>,
    /// The child's spend summary, on a terminal whose stage invoked a child
    /// execution (a subworkflow stage's `Invoke`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_invocation_summary: Option<ChildInvocationSummary>,
}

impl TerminalCharge {
    /// The charge of a terminal whose stage's own work measured `usage`.
    #[must_use]
    pub fn of_usage(usage: StageUsage) -> Self {
        Self {
            token_usage: Some(usage),
            child_invocation_summary: None,
        }
    }

    /// The ONE reading of a failure-class terminal's recorded charge.
    ///
    /// `dispatched` is whether the attempt's dispatch was recorded — a frame
    /// that may have reached a worker. A dispatched attempt's terminal that
    /// recorded NO charge, or an empty one ([`Self::is_empty`], which states no
    /// fact), is read as UNKNOWN: [`StageUsage::unmetered`] with no backend or
    /// model to name, which every cost reader folds as an unmetered stage and
    /// a hard cost policy fails closed on. It is never read as `0` — the work
    /// may have run and spent. A never-dispatched attempt's absent or empty
    /// charge reads as absent: nothing it ran could bill.
    #[must_use]
    pub fn as_read(recorded: Option<Self>, dispatched: bool) -> Option<Self> {
        match recorded {
            Some(charge) if !charge.is_empty() => Some(charge),
            _ if dispatched => Some(Self::of_usage(StageUsage::unmetered("", ""))),
            _ => None,
        }
    }

    /// `true` when it states no charge facts at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.token_usage.is_none() && self.child_invocation_summary.is_none()
    }

    /// The envelope-shaped value [`envelope_cost_micro_usd`],
    /// `envelope_cost_quality` and the runner's halt check all read.
    #[must_use]
    pub fn envelope(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// The `child_invocation_summary` an `Invoke` stage's terminal envelope or a
/// failed/cancelled parent's `terminal_charge` carries: the child's KNOWN
/// spend plus the metering quality of that figure.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildInvocationSummary {
    /// The child's KNOWN metered spend — the field
    /// `envelope_cost_micro_usd` reads as `token_usage.cost_micro_usd`.
    pub token_usage: ChildInvocationUsage,
    /// The metering quality of the figure. A record without it is read as
    /// absent, which readers skip rather than fail closed on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metering: Option<MeteringSummary>,
}

/// The `token_usage` object inside a [`ChildInvocationSummary`] — a bare
/// known-sum, not a per-call breakdown.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildInvocationUsage {
    /// The summed KNOWN cost of every call the child billed — each attempt's
    /// completion, a structured-output retry's included, and each failure-class
    /// terminal charge. On a completed child it can exceed the cost of the
    /// accepted outputs the envelope's `outputs` map carries.
    pub cost_micro_usd: u64,
}

/// The `child_invocation_summary` an `Invoke` stage's terminal envelope
/// carries: the KNOWN spend of the child's metered work under
/// `token_usage.cost_micro_usd`, and its metering QUALITY under `metering` —
/// one shape, written by every route that resolves a parent on a terminal
/// child (the `oci` completion and fail/cancel resolutions) and by a parent's
/// own terminal settling an `Invoke` still waiting (over what the child billed
/// so far), so the parent's own halt check, budget fold and record read it
/// identically.
///
/// `stages` is the child's charge records — one envelope per attempt it billed, a
/// completion's output or a failure-class terminal's charge, so a stage retried
/// under one name appears once per call. The known sum
/// is [`envelope_cost_micro_usd`] per stage — a stage's own cost PLUS the
/// known spend of any child IT invoked. The metering summary folds each
/// stage's `token_usage.cost` directly and absorbs each stage's own nested
/// `child_invocation_summary.metering` through [`MeteringSummary::absorb`], so
/// an unmeasurable call a GRANDCHILD made reaches the grandparent as
/// `"<child stage>/<grandchild stage>"` rather than being dropped. A stage
/// with no `cost` object at all folds nothing — the
/// same absence-means-absent carve-out `envelope_cost_quality` documents.
#[must_use]
pub fn child_invocation_summary<'a, I>(stages: I) -> ChildInvocationSummary
where
    I: IntoIterator<Item = (&'a str, &'a serde_json::Value)>,
{
    let mut known = 0u64;
    let mut metering = MeteringSummary::default();
    for (stage, envelope) in stages {
        known = known.saturating_add(envelope_cost_micro_usd(envelope));
        if let Some(usage) = envelope
            .get("token_usage")
            .and_then(|tu| serde_json::from_value::<StageUsage>(tu.clone()).ok())
        {
            metering.fold_usage(stage, &usage);
        } else if let Some(cost) = envelope
            .get("token_usage")
            .and_then(|tu| tu.get("cost"))
            .and_then(|c| serde_json::from_value::<MeteredCost>(c.clone()).ok())
        {
            metering.fold(stage, &cost);
        }
        if let Some(nested) = envelope
            .get("child_invocation_summary")
            .and_then(|summary| summary.get("metering"))
            .and_then(|m| serde_json::from_value::<MeteringSummary>(m.clone()).ok())
        {
            metering.absorb(stage, &nested);
        }
    }
    ChildInvocationSummary {
        token_usage: ChildInvocationUsage {
            cost_micro_usd: known,
        },
        metering: Some(metering),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn floor_estimate(micro: u64, model: &str) -> MeteredCost {
        MeteredCost::Estimated {
            micro_usd: micro,
            basis: EstimateBasis::UnknownModelFloor {
                model: SmolStr::new(model),
            },
        }
    }

    fn unavailable(backend: &str, model: &str) -> MeteredCost {
        MeteredCost::Unavailable {
            backend: SmolStr::new(backend),
            model: SmolStr::new(model),
        }
    }

    /// The defect in one assertion: an unmeterable call and a genuinely-free
    /// call must not be the same value, though both would naively be `0`.
    #[test]
    fn unknown_and_free_are_distinct_values() {
        let free = MeteredCost::Authoritative { micro_usd: 0 };
        let unknown = unavailable("codex", "gpt-5.3-codex-spark");
        assert_ne!(free, unknown);
        assert_eq!(free.chargeable_micro_usd(), Some(0));
        assert_eq!(
            unknown.chargeable_micro_usd(),
            None,
            "an unmeterable cost must not present itself as a number at all"
        );
        assert_eq!(free.quality(), MeteringQuality::Authoritative);
        assert_eq!(unknown.quality(), MeteringQuality::Unavailable);
    }

    /// The fail-closed rule: the SAME unmeterable cost is fatal under a hard
    /// policy and merely recorded without one. Both directions are asserted
    /// because a design that halts unconditionally would break every
    /// `shell`-only workflow, and one that never halts is the original defect.
    #[test]
    fn unmeterable_fails_closed_only_under_a_hard_policy() {
        let cost = unavailable("codex", "m");
        assert_eq!(
            cost.charge_under(CostEnforcement::Hard),
            CostCharge::FailClosed {
                backend: SmolStr::new("codex"),
                model: SmolStr::new("m"),
            }
        );
        assert_eq!(
            cost.charge_under(CostEnforcement::Advisory),
            CostCharge::RecordUnmetered {
                backend: SmolStr::new("codex"),
                model: SmolStr::new("m"),
            }
        );
    }

    /// An estimate is enforceable — it must NOT fail closed. The unknown-model
    /// floor over-estimates, so a bound evaluated against it trips at-or-before
    /// the true spend; halting on it would make every unpriced model unusable
    /// under a cost bound, which is a named recourse nobody could invoke.
    #[test]
    fn an_estimate_charges_normally_even_under_a_hard_policy() {
        let cost = floor_estimate(261_239, "gpt-5.3-codex-spark");
        assert_eq!(
            cost.charge_under(CostEnforcement::Hard),
            CostCharge::Add(261_239)
        );
    }

    /// The summary takes the WORST stage, and one unmeterable stage makes the
    /// whole running total a lower bound.
    #[test]
    fn summary_quality_is_the_worst_stage() {
        let mut s = MeteringSummary::default();
        assert_eq!(s.quality(), MeteringQuality::Authoritative);
        assert!(s.is_empty());

        s.fold("a", &MeteredCost::Authoritative { micro_usd: 10 });
        assert_eq!(s.quality(), MeteringQuality::Authoritative);
        assert!(!s.is_empty());

        s.fold("b", &floor_estimate(500, "m"));
        assert_eq!(s.quality(), MeteringQuality::Estimated);
        assert_eq!(s.estimated_micro_usd, 500);

        s.fold("c", &unavailable("codex", ""));
        assert_eq!(s.quality(), MeteringQuality::Unavailable);
        assert_eq!(s.authoritative_stages, 1);
        assert_eq!(s.estimated_stages, 1);
        assert_eq!(s.unmetered_stages, 1);
    }

    /// The warning names the affected stages AND the `(backend, model)` pair,
    /// because a count an operator cannot act on is a report, not a recourse.
    #[test]
    fn unmetered_warning_names_an_invocable_recourse() {
        let mut s = MeteringSummary::default();
        s.fold("draft", &unavailable("codex", "gpt-5.3-codex-spark"));
        let warnings = s.warnings();
        assert_eq!(warnings.len(), 1);
        let w = &warnings[0];
        assert!(w.starts_with("unmetered_cost: 1 stage(s) [`draft`]"), "{w}");
        assert!(w.contains("gpt-5.3-codex-spark"), "{w}");
        assert!(w.contains("`api_key` credential"), "{w}");
        assert!(w.contains("lower bound"), "{w}");
        // A stage that named no model still renders readably rather than
        // printing an empty pair of backticks an operator cannot copy.
        let mut s2 = MeteringSummary::default();
        s2.fold("x", &unavailable("codex", ""));
        assert!(s2.warnings()[0].contains("<none>"), "{:?}", s2.warnings());
    }

    /// Warnings are grouped by `(backend, model)`, NOT emitted per stage.
    ///
    /// Every stage of one pair has the same recourse, so a 200-stage workflow
    /// on one unpriced model has ONE fix — repeating the same 350-character
    /// recourse 200 times buries it. Two distinct pairs still get two lines,
    /// because they are two different fixes.
    #[test]
    fn warnings_group_by_backend_and_model_not_by_stage() {
        let mut s = MeteringSummary::default();
        s.fold("a", &unavailable("codex", "m1"));
        s.fold("b", &unavailable("codex", "m1"));
        s.fold("c", &unavailable("codex", "m1"));
        let warnings = s.warnings();
        assert_eq!(warnings.len(), 1, "one pair, one recourse: {warnings:?}");
        assert!(
            warnings[0].starts_with("unmetered_cost: 3 stage(s) [`a`, `b`, `c`]"),
            "the one line must still name every affected stage; got {}",
            warnings[0]
        );
        // The per-stage rows are still there for anything that wants structure.
        assert_eq!(s.unmetered.len(), 3);

        // A second, genuinely different pair is a second recourse.
        s.fold("d", &unavailable("open_code", "m2"));
        let warnings = s.warnings();
        assert_eq!(warnings.len(), 2, "two pairs, two recourses: {warnings:?}");
        // Deterministically ordered — an identical run must produce an identical
        // record, and a hash-set iteration order would not.
        assert!(warnings[0].contains("`codex`"), "{warnings:?}");
        assert!(warnings[1].contains("`open_code`"), "{warnings:?}");
    }

    /// The halt reason names the recourse and both escape hatches. It is the
    /// text an unattended operator wakes up to.
    #[test]
    fn halt_reason_names_both_recourses() {
        let r = metering_unavailable_reason("draft", "codex", "gpt-5.3-codex-spark");
        assert!(
            r.starts_with("metering_unavailable: stage \"draft\""),
            "{r}"
        );
        assert!(r.contains("`api_key` credential"), "{r}");
        assert!(r.contains("cost_budget(\"warn\""), "{r}");
        assert!(r.contains("HARD cost policy"), "{r}");
    }

    /// **No unmetered line sends the operator to a recourse that does not
    /// exist, nor says something of the stage that may be false.** A stage
    /// meters `Unavailable` for an adapter with no billing backend, under a
    /// `subscription` credential, or when it reported no token usage; a
    /// `[[pricing.models]]` row prices none of the three, so neither the
    /// warning nor the halt reason tells the operator to add one, and neither
    /// says the stage reported no token usage (an unpriced adapter's turn and a
    /// subscription turn keep their tokens).
    ///
    /// For an unpriced adapter the witness that no row can name it is the
    /// config's own `[[pricing.models]]` decoder, which refuses the adapter's
    /// label as a row's `backend`; the line names the adapters kata prices
    /// instead.
    #[test]
    fn an_unmetered_line_names_only_a_recourse_the_operator_can_take() {
        let row = |backend: &str| {
            toml::from_str::<crate::config::PriceOverride>(&format!(
                "backend = \"{backend}\"\nmodel = \"m\"\n\
                 input_rate_per_mtok = 1.0\noutput_rate_per_mtok = 1.0\n\
                 cache_read_multiplier = 0.1\ncache_write_multiplier = 1.0\n"
            ))
        };
        assert!(
            row("anthropic").is_ok(),
            "the decoder admits a priced backend"
        );
        let unpriced: Vec<_> = crate::agent::AdapterKind::ALL
            .into_iter()
            .filter(|kind| kind.billing_backend().is_none())
            .collect();
        assert!(
            unpriced.contains(&crate::agent::AdapterKind::NanocodeOpenai),
            "{unpriced:?}"
        );
        for kind in unpriced {
            let backend = kind.as_label();
            assert!(
                row(backend).is_err(),
                "a `[[pricing.models]]` row cannot name `{backend}`"
            );
            let mut s = MeteringSummary::default();
            s.fold("draft", &unavailable(backend, "gpt-5.4-mini"));
            let lines = [
                s.warnings().remove(0),
                metering_unavailable_reason("draft", backend, "gpt-5.4-mini"),
            ];
            for line in lines {
                assert!(!line.contains("add a `[[pricing.models]]`"), "{line}");
                assert!(!line.contains("token usage"), "{line}");
                assert!(line.contains(&format!("adapter `{backend}`")), "{line}");
                assert!(line.contains("`nanocode_anthropic`"), "{line}");
            }
        }
        let mut s = MeteringSummary::default();
        s.fold("draft", &unavailable("anthropic", "claude-sonnet-5-5"));
        for line in [
            s.warnings().remove(0),
            metering_unavailable_reason("draft", "anthropic", "claude-sonnet-5-5"),
        ] {
            assert!(!line.contains("add a `[[pricing.models]]`"), "{line}");
            assert!(!line.contains("reported neither"), "{line}");
            assert!(line.contains("`subscription`"), "{line}");
        }
    }

    /// **A dispatched attempt's absent charge is UNKNOWN, never 0.** The
    /// reading rule every cost reader shares: a recorded charge is read as
    /// recorded; a dispatched attempt that recorded none is `Unavailable` (so
    /// it folds as an unmetered stage and a hard policy fails closed on it);
    /// a never-dispatched one's absence stays absent.
    ///
    /// **Would red if:** the absence on a dispatched attempt were skipped
    /// (`None`) or read as the authoritative `0` of `StageUsage::unbilled`, or an
    /// empty `{}` charge on one were read as recorded (every reader sums it to `0`).
    #[test]
    fn a_dispatched_attempt_without_a_charge_reads_as_unknown() {
        let read = TerminalCharge::as_read(None, true).expect("a dispatched attempt is charged");
        let usage = read.token_usage.clone().expect("its own usage is stated");
        assert_eq!(usage.cost.quality(), MeteringQuality::Unavailable);
        assert_eq!(usage.cost_micro_usd, None, "no number for an unknown cost");
        assert_eq!(
            usage.cost.charge_under(CostEnforcement::Hard),
            CostCharge::FailClosed {
                backend: SmolStr::new(""),
                model: SmolStr::new(""),
            }
        );
        let mut summary = MeteringSummary::default();
        summary.fold("implement", &usage.cost);
        assert_eq!(summary.unmetered_stages, 1);
        assert_eq!(envelope_cost_micro_usd(&read.envelope()), 0);

        assert_eq!(TerminalCharge::as_read(None, false), None);
        let recorded = TerminalCharge::of_usage(StageUsage::unbilled());
        assert_eq!(
            TerminalCharge::as_read(Some(recorded.clone()), true),
            Some(recorded)
        );

        // An EMPTY charge states no fact: a dispatched attempt's reads as the same
        // unknown, never as the `0` every reader would sum `{}` to.
        assert_eq!(
            TerminalCharge::as_read(Some(TerminalCharge::default()), true),
            Some(read),
            "an empty charge on a dispatched attempt is unknown"
        );
        assert_eq!(
            TerminalCharge::as_read(Some(TerminalCharge::default()), false),
            None
        );
    }

    /// An agent turn with no reported usage is charged `Unavailable` naming
    /// the adapter and the model; a reported usage is charged verbatim.
    #[test]
    fn an_agent_turn_without_reported_usage_is_unavailable_naming_its_pair() {
        let unknown = agent_turn_usage(None, "nanocode_openai", "gpt-6-luna");
        assert_eq!(
            unknown.cost,
            unavailable("nanocode_openai", "gpt-6-luna"),
            "{unknown:?}"
        );
        let reported = StageUsage::metered(
            &crate::cache::TokenUsage {
                input: 500,
                output: 40,
                cache_read: 0,
                cache_write: 0,
            },
            MeteredCost::Authoritative { micro_usd: 7 },
            0,
        );
        assert_eq!(
            agent_turn_usage(Some(&reported), "nanocode_openai", "m"),
            reported
        );
    }

    /// **The token count a usage records: every class, summed; UNKNOWN only for
    /// the counter-less shape of an unmeasured call.** A measured turn counts
    /// `input + output + cache_read + cache_write`; an unbilled stage records a
    /// known `0`; the `unmetered` shape (a lost or unreported turn) and a priced
    /// cost with no counters state no count.
    ///
    /// **Would red if:** a class were left out of the sum (a cache-heavy turn
    /// under-counts), or a counter-less unmeasured call read as a known `0`.
    #[test]
    fn a_usage_records_every_token_class_or_states_none() {
        let usage = |input, output, cache_read, cache_write, cost| {
            StageUsage::metered(
                &crate::cache::TokenUsage {
                    input,
                    output,
                    cache_read,
                    cache_write,
                },
                cost,
                0,
            )
        };
        let priced = MeteredCost::Authoritative { micro_usd: 9 };
        assert_eq!(
            usage(100, 20, 3_000, 400, priced.clone()).recorded_tokens(),
            Some(3_520)
        );
        assert_eq!(
            usage(1, 2, 0, 0, unavailable("nanocode_openai", "m")).recorded_tokens(),
            Some(3),
            "a turn whose COST is unknown still records its tokens"
        );
        assert_eq!(StageUsage::unbilled().recorded_tokens(), Some(0));
        assert_eq!(StageUsage::unmetered("codex", "m").recorded_tokens(), None);
        assert_eq!(usage(0, 0, 0, 0, priced).recorded_tokens(), None);
    }

    /// The envelope reader every token fold shares: a shell completion (`null`
    /// usage) states `0`, an agent turn its recorded classes, an unmetered turn
    /// names itself unknown, and an invoked child's summary adds its tokens and
    /// re-roots its first unknown stage under the invoking stage.
    #[test]
    fn envelope_tokens_reads_own_usage_and_a_childs_summary() {
        assert_eq!(
            envelope_tokens("sh", &serde_json::json!({"token_usage": null})),
            EnvelopeTokens::default()
        );
        let turn = StageUsage::metered(
            &crate::cache::TokenUsage {
                input: 10,
                output: 5,
                cache_read: 100,
                cache_write: 7,
            },
            unavailable("nanocode_openai", "gpt-6-luna"),
            0,
        );
        let read = envelope_tokens(
            "draft",
            &serde_json::json!({"token_usage": serde_json::to_value(&turn).unwrap()}),
        );
        assert_eq!(read.known, 122);
        assert_eq!(read.unknown, None);

        let lost = TerminalCharge::of_usage(StageUsage::unmetered("nanocode_openai", "m"));
        let read = envelope_tokens("draft", &lost.envelope());
        assert_eq!(read.known, 0);
        assert_eq!(
            read.unknown,
            Some(UnmeteredStage {
                stage: "draft".to_owned(),
                backend: "nanocode_openai".to_owned(),
                model: "m".to_owned(),
            })
        );

        let mut child = MeteringSummary::default();
        child.fold_usage("a", &turn);
        child.fold_usage("b", &StageUsage::unmetered("nanocode_openai", "m2"));
        assert_eq!(child.tokens, 122);
        let parent = serde_json::json!({
            "token_usage": null,
            "child_invocation_summary": {
                "token_usage": {"cost_micro_usd": 0},
                "metering": serde_json::to_value(&child).unwrap(),
            },
        });
        let read = envelope_tokens("sub", &parent);
        assert_eq!(read.known, 122);
        assert_eq!(read.unknown.map(|u| u.stage), Some("sub/b".to_owned()));
    }

    /// `ProviderCost`'s default is "the provider said nothing", never "free".
    /// An absent cost decodes to "the provider said nothing", which must not
    /// silently claim a zero charge.
    #[test]
    fn provider_cost_defaults_to_unstated_not_zero() {
        assert_eq!(ProviderCost::default(), ProviderCost::Unstated);
        assert_eq!(ProviderCost::default().reported_micro_usd(), None);
        assert_eq!(
            ProviderCost::Reported { micro_usd: 7 }.reported_micro_usd(),
            Some(7)
        );
    }

    /// The envelope shapes are a WIRE FORMAT: the worker writes them into the
    /// stage-completion JSON that the runner's policy read and the API's record
    /// projection both parse, and those rows outlive the process. A silent
    /// rename un-meters every execution already holding one.
    #[test]
    fn metered_cost_wire_shape_is_pinned() {
        let authoritative =
            serde_json::to_string(&MeteredCost::Authoritative { micro_usd: 55_400 })
                .expect("serialize");
        assert_eq!(
            authoritative,
            r#"{"quality":"authoritative","micro_usd":55400}"#
        );

        let estimated = serde_json::to_string(&MeteredCost::Estimated {
            micro_usd: 261_239,
            basis: EstimateBasis::UnknownModelFloor {
                model: SmolStr::new("gpt-5.3-codex-spark"),
            },
        })
        .expect("serialize");
        assert_eq!(
            estimated,
            r#"{"quality":"estimated","micro_usd":261239,"basis":{"rate_source":"unknown_model_floor","model":"gpt-5.3-codex-spark"}}"#
        );

        let table = serde_json::to_string(&EstimateBasis::PriceTable {
            rates_as_of: SmolStr::new("2026-04"),
        })
        .expect("serialize");
        assert_eq!(
            table,
            r#"{"rate_source":"price_table","rates_as_of":"2026-04"}"#
        );

        let unavailable_json =
            serde_json::to_string(&unavailable("codex", "m")).expect("serialize");
        assert_eq!(
            unavailable_json,
            r#"{"quality":"unavailable","backend":"codex","model":"m"}"#
        );

        // Round-trip: the runner and the record projection both DECODE these.
        for cost in [
            MeteredCost::Authoritative { micro_usd: 1 },
            floor_estimate(2, "m"),
            MeteredCost::Estimated {
                micro_usd: 3,
                basis: EstimateBasis::PriceTable {
                    rates_as_of: SmolStr::new("2026-04"),
                },
            },
            MeteredCost::Estimated {
                micro_usd: 4,
                basis: EstimateBasis::OperatorOverride,
            },
            unavailable("codex", ""),
        ] {
            let s = serde_json::to_string(&cost).expect("serialize");
            let back: MeteredCost = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back, cost, "round-trip must be lossless for {s}");
        }
    }

    /// An empty summary serializes without the `unmetered` array so a clean
    /// run's record body does not grow a field that says nothing.
    #[test]
    fn empty_summary_omits_the_unmetered_array() {
        let s = MeteringSummary::default();
        let json = serde_json::to_string(&s).expect("serialize");
        assert_eq!(
            json,
            r#"{"authoritative_stages":0,"estimated_stages":0,"unmetered_stages":0,"estimated_micro_usd":0}"#
        );
        let back: MeteringSummary = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, s);
        // A record body with no metering object at all.
        let absent: MeteringSummary = serde_json::from_str("{}").expect("deserialize absent");
        assert_eq!(absent, MeteringSummary::default());
    }
}
