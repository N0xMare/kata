//! Composable walk-away [`Bound`] abstraction.
//!
//! A `Bound` is a single, kind-tagged walk-away guard an author attaches to a workflow: a
//! wall-clock ceiling, a cost ceiling or a token ceiling (an iteration ceiling or a metric
//! threshold would be further kinds). Every bound is OPT-IN: a workflow that authors none has
//! no limit but the per-stage wall timeouts. Bounds are *composable*: a scope carries a small list of them, at most one per
//! kind, and the runner walks away when the first one trips.
//!
//! # Enforcement state per kind
//!
//! The native DSL constructors (`time_bound(..)` / `cost_bound(..)` / `token_bound(..)`) and
//! `workflow(bounds=[..])` lower a `Vec<Bound>` onto the checked
//! [`crate::workflow::WorkflowDefinition`] and surface it on the
//! `ExecutionProgram`. Every kind is ENFORCED:
//!
//! - **[`Bound::Cost`] — ENFORCED.** A workflow-scope cost
//!   bound is a hard walk-away halt: the runner folds each stage's cost into the
//!   same running-cost accumulator the cost-`BudgetPolicy` watches, and the
//!   moment the accumulated spend exceeds the bound the run halts (the tripping
//!   stage stays `Completed`, a synthetic `<stage>#bound-halt-cost` Failed row is
//!   recorded, downstream stages are skipped, and the halt is counted on
//!   `kata_workflow_bound_exceeded_total` and logged — mirroring the cost-budget
//!   Halt machinery). The trip is deterministic and durable, so resume/replay
//!   reconstructs the halted state.
//! - **[`Bound::Time`] — ENFORCED.** A workflow-scope time
//!   bound is a *total-lifetime* wall-clock walk-away anchored to the execution's
//!   ORIGINAL start (set on the first stage dispatch; restored on resume as the
//!   minimum recorded assignment start so resume never resets the clock). It is
//!   evaluated at *stage-terminal granularity*, at the instant the authority
//!   chain RECORDED each charged terminal — never the clock the fold runs under —
//!   and if total elapsed since the original start exceeds the bound the run
//!   halts identically to a cost bound (tripping stage stays `Completed`, a
//!   synthetic `<stage>#bound-halt-time` Failed row is recorded, downstream
//!   stages are skipped, and the halt is counted with `bound_kind="time"`).
//!   Because the instant is the frame's own, a resumed fold re-measures every
//!   frame exactly as the live fold did: it never trips the bound at a terminal
//!   the live run recorded inside it, and the durable row keeps the halted state.
//!   A `Time` bound does NOT interrupt a single in-flight stage mid-run — that is
//!   what per-stage `timeout_ms` is for; it stops scheduling after the next
//!   terminal once total elapsed exceeds the bound.
//! - **[`Bound::Tokens`] — ENFORCED.** A token ceiling over the tokens the run's
//!   stages RECORDED: every class kata records — `input + output + cache_read +
//!   cache_write` ([`crate::metering::StageUsage::recorded_tokens`]) — which the
//!   adapters normalize to disjoint counts, so the sum is the vendor's own total
//!   of tokens processed (reasoning rides inside `output`). It is folded exactly
//!   where the cost is — each stage's completion, each failed, cancelled or
//!   orphaned terminal's charge, and an invoked child's summary — and trips like
//!   the cost bound, at stage-terminal granularity, when the cumulative total
//!   EXCEEDS the limit (`<stage>#bound-halt-tokens`). A stage whose tokens are
//!   UNKNOWN under a token bound fails the run closed (`token_metering_unavailable`,
//!   a `#metering-halt` row). Every adapter reports every token class its
//!   vendor bills, so the count a bound is held over is the vendor's whole
//!   count.
//!
//! # Forward compatibility
//!
//! The [`Bound`] enum is `kind`-tagged (externally tagged via
//! `#[serde(tag = "kind", content = "data")]`, the same convention as
//! [`crate::workflow::EdgeCondition`] and
//! [`crate::review_loop::OnMaxAction`]), so the `Iterations` and `Metric`
//! kinds can be added later as new variants without changing the serialized
//! shape of the existing `Time` / `Cost` variants — old packs stay
//! byte-identical.
//!
//! # Cost unit
//!
//! [`Bound::Cost`] reuses the exact micro-USD integer unit
//! [`crate::budget::BudgetPolicy`] already models cost in
//! (`limit_micro_usd: u64`). Operator-facing DSL takes USD (`f64`) for
//! ergonomics and converts to micro-USD at construction so all in-IR math
//! stays integer-only, matching the micro-USD unit every metered cost uses.

use serde::{Deserialize, Serialize};

/// USD → micro-USD conversion factor (1 USD = 1_000_000 micro-USD), matching
/// the `BudgetPolicy::limit_micro_usd` convention.
pub const MICRO_USD_PER_USD: u64 = 1_000_000;

/// A single composable walk-away guard.
///
/// `kind`-tagged so future kinds (`Iterations`, `Metric`) add as new variants
/// without disturbing the serialized shape of existing ones. v1 carries two
/// kinds: a wall-clock ceiling ([`Self::Time`]), a cost ceiling
/// ([`Self::Cost`], in micro-USD — the same unit
/// [`crate::budget::BudgetPolicy`] uses) and a token ceiling ([`Self::Tokens`]).
///
/// Construct via [`Bound::time`] / [`Bound::cost_usd`] / [`Bound::tokens`] (or
/// the native DSL `time_bound(..)` / `cost_bound(..)` / `token_bound(..)`),
/// which enforce the value invariants (`ms > 0`, `micro_usd > 0`, `tokens > 0`).
/// Assemble a per-scope list with [`validate_bounds`], which enforces
/// at-most-one-bound-per-kind.
///
/// # Enforcement state
///
/// Every kind is ENFORCED as a walk-away halt: [`Self::Cost`] (accumulated-cost
/// ceiling), [`Self::Tokens`] (accumulated recorded-token ceiling) and
/// [`Self::Time`] (total-lifetime wall-clock ceiling), each at stage-terminal
/// granularity. See the [module docs](crate::bound) for the per-kind detail.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Bound {
    /// Wall-clock ceiling in milliseconds. `ms > 0`.
    Time {
        /// Milliseconds of wall-clock budget. Always `> 0` for a constructed
        /// bound.
        ms: u64,
    },
    /// Cost ceiling in micro-USD (`1 USD == 1_000_000` micro-USD), the same
    /// integer unit [`crate::budget::BudgetPolicy::limit_micro_usd`] uses.
    /// `micro_usd > 0`.
    Cost {
        /// Micro-USD of cost budget. Always `> 0` for a constructed bound.
        micro_usd: u64,
    },
    /// Token ceiling: the cumulative tokens the scope's stages recorded, every
    /// class counted ([`crate::metering::StageUsage::recorded_tokens`]).
    /// `tokens > 0`.
    Tokens {
        /// Tokens of budget. Always `> 0` for a constructed bound.
        tokens: u64,
    },
}

/// Stable per-kind discriminant used to enforce at-most-one-bound-per-kind in a
/// bounds list. Distinct from the serde tag so the uniqueness check never
/// depends on serialization.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BoundKind {
    /// [`Bound::Time`].
    Time,
    /// [`Bound::Cost`].
    Cost,
    /// [`Bound::Tokens`].
    Tokens,
}

impl BoundKind {
    /// Operator-facing label for diagnostics (`"time"` / `"cost"` / `"tokens"`)
    /// — the suffix of the synthetic `<stage>#bound-halt-<kind>` row.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Time => "time",
            Self::Cost => "cost",
            Self::Tokens => "tokens",
        }
    }

    /// The unit a bound of this kind's limit and observation are counted in.
    #[must_use]
    pub fn unit(self) -> &'static str {
        match self {
            Self::Time => "ms",
            Self::Cost => "micro-USD",
            Self::Tokens => "tokens",
        }
    }
}

/// Infix of the synthetic ledger row a tripped workflow-scope [`Bound`] records:
/// `"<stage>#bound-halt-<kind>"`, `kind` being [`BoundKind::label`].
pub const BOUND_HALT_MARKER_INFIX: &str = "#bound-halt-";

/// Suffix of the synthetic ledger row a crossed cost-`Halt`
/// [`crate::budget::BudgetPolicy`] records: `"<stage>#budget-halt"`.
pub const BUDGET_HALT_MARKER_SUFFIX: &str = "#budget-halt";

/// Suffix of the synthetic ledger row a FAIL-CLOSED metering halt records:
/// `"<stage>#metering-halt"`.
///
/// The third walk-away cause, and it is a walk-away for the same reason the
/// other two are: a hard cost policy is a promise about spend, and kata stops
/// when it can no longer keep one. The difference is only WHY — `#bound-halt-*`
/// and `#budget-halt` fire when a ceiling is EXCEEDED, this fires when the
/// ceiling becomes UNKNOWABLE because a stage reported no measurable cost.
///
/// Carrying it in the marker family rather than inventing a parallel mechanism
/// is deliberate: [`is_walkaway_halt_row`] is what makes a halted run report
/// `status: failed` with a reason and a warning instead of `completed`/exit 0,
/// and that surface is already proven. A separate mechanism would have to
/// re-earn it.
pub const METERING_HALT_MARKER_SUFFIX: &str = "#metering-halt";

/// `true` if `stage_name` is one of the three synthetic rows that record a
/// WALK-AWAY — the unattended-safety guarantee's whole durable surface.
///
/// # Why this predicate exists
///
/// A walk-away is the ONLY terminal an execution can reach that no DAG stage
/// records. Its writer — `WorkflowRunner::persist_walkaway_halt`, once per
/// execution — mints the row under a name the workflow never declared,
/// precisely so it cannot collide with a real stage. A terminal-outcome scan
/// that enumerated only the DAG's topological order would structurally miss the
/// one row that writer produces.
///
/// The consequence is not cosmetic: the run would latch the operational
/// lifecycle `Completed`, the record's status would follow the lifecycle and
/// erase the `Failed` that `aggregate_status` derives from this very row, and a
/// run that walked away from a `time_bound` would report `"status":"completed"`,
/// `"error":null`, `"warnings":[]` and exit code 0 — the exact answer an
/// unattended operator must never be given.
///
/// # Why it lives in `kata-types` and not next to the writers
///
/// FIVE sites depend on these names agreeing, and they span two crates:
/// `kata-workflow`'s writer and its once-per-execution idempotence read, the
/// fold's walk-away latch, its terminal-outcome read, and `kata-api`'s
/// `walkaway_halt_warnings` record projection. Another site hand-spelling the
/// same literals is the exact drift a shared const exists to prevent.
/// `kata-types` is the lowest crate all of them already depend on, so it is the
/// only home where "one spelling" is enforceable rather than merely intended.
#[must_use]
pub fn is_walkaway_halt_row(stage_name: &str) -> bool {
    stage_name.contains(BOUND_HALT_MARKER_INFIX)
        || stage_name.ends_with(BUDGET_HALT_MARKER_SUFFIX)
        || stage_name.ends_with(METERING_HALT_MARKER_SUFFIX)
}

/// Error constructing or assembling [`Bound`]s.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum BoundError {
    /// A `Time` bound was constructed with `ms == 0`.
    #[error("time bound requires ms > 0")]
    NonPositiveTime,
    /// A `Cost` bound was constructed with a non-positive USD / micro-USD
    /// value.
    #[error("cost bound requires a positive USD value")]
    NonPositiveCost,
    /// A `Cost` bound's USD value is so large its micro-USD conversion would
    /// not fit a `u64` (it would otherwise silently saturate to `u64::MAX`).
    #[error("cost bound USD value is too large to represent")]
    CostOutOfRange,
    /// A `Tokens` bound was constructed with `tokens == 0`.
    #[error("token bound requires tokens > 0")]
    NonPositiveTokens,
    /// A bounds list declared two bounds of the same kind.
    #[error(
        "duplicate {} bound: at most one bound per kind is allowed in a bounds list",
        .0.label()
    )]
    DuplicateKind(BoundKind),
}

impl Bound {
    /// Construct a [`Bound::Time`], rejecting `ms == 0`.
    ///
    /// # Errors
    ///
    /// [`BoundError::NonPositiveTime`] when `ms == 0`.
    pub fn time(ms: u64) -> Result<Self, BoundError> {
        if ms == 0 {
            return Err(BoundError::NonPositiveTime);
        }
        Ok(Self::Time { ms })
    }

    /// Construct a [`Bound::Cost`] from an already-computed micro-USD value,
    /// rejecting `micro_usd == 0`.
    ///
    /// # Errors
    ///
    /// [`BoundError::NonPositiveCost`] when `micro_usd == 0`.
    pub fn cost_micro_usd(micro_usd: u64) -> Result<Self, BoundError> {
        if micro_usd == 0 {
            return Err(BoundError::NonPositiveCost);
        }
        Ok(Self::Cost { micro_usd })
    }

    /// Construct a [`Bound::Cost`] from a USD `f64`, converting to the
    /// micro-USD integer unit [`crate::budget::BudgetPolicy`] uses.
    ///
    /// The USD value must be finite and strictly positive; the converted
    /// micro-USD value must also be `> 0` (so a sub-micro-USD value like
    /// `0.0000001` is rejected — it would truncate to zero budget).
    ///
    /// # Errors
    ///
    /// [`BoundError::NonPositiveCost`] when `usd` is non-finite, `<= 0`, or
    /// converts to `0` micro-USD; [`BoundError::CostOutOfRange`] when `usd` is
    /// so large its micro-USD conversion would overflow `u64`.
    pub fn cost_usd(usd: f64) -> Result<Self, BoundError> {
        if !usd.is_finite() || usd <= 0.0 {
            return Err(BoundError::NonPositiveCost);
        }
        // Round to the nearest micro-USD. This matches
        // `crate::parser::normalize_budget_policy`'s `limit_usd →
        // limit_micro_usd` conversion exactly (both round-to-nearest), so a
        // `cost_bound(x)` and a `cost_budget(.., x)` written with the same USD
        // literal record the identical micro-USD ceiling. `MICRO_USD_PER_USD`
        // (1_000_000) and `u64::MAX` are both used only as f64 magnitude
        // bounds here, so the precision loss in those casts is harmless.
        #[allow(clippy::cast_precision_loss)]
        let scaled = usd * MICRO_USD_PER_USD as f64;
        #[allow(clippy::cast_precision_loss)]
        let overflow_ceiling = u64::MAX as f64;
        // Reject absurd values (`> ~$1.8e13`) that would otherwise saturate the
        // `as u64` cast to `u64::MAX` and silently collapse distinct intents.
        if !scaled.is_finite() || scaled >= overflow_ceiling {
            return Err(BoundError::CostOutOfRange);
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micro_usd = scaled.round() as u64;
        Self::cost_micro_usd(micro_usd)
    }

    /// Construct a [`Bound::Tokens`], rejecting `tokens == 0`.
    ///
    /// # Errors
    ///
    /// [`BoundError::NonPositiveTokens`] when `tokens == 0`.
    pub fn tokens(tokens: u64) -> Result<Self, BoundError> {
        if tokens == 0 {
            return Err(BoundError::NonPositiveTokens);
        }
        Ok(Self::Tokens { tokens })
    }

    /// The per-kind discriminant of this bound.
    #[must_use]
    pub fn kind(&self) -> BoundKind {
        match self {
            Self::Time { .. } => BoundKind::Time,
            Self::Cost { .. } => BoundKind::Cost,
            Self::Tokens { .. } => BoundKind::Tokens,
        }
    }

    /// The bound's limit, in its kind's [`BoundKind::unit`].
    #[must_use]
    pub fn limit(&self) -> u64 {
        match *self {
            Self::Time { ms } => ms,
            Self::Cost { micro_usd } => micro_usd,
            Self::Tokens { tokens } => tokens,
        }
    }
}

/// Validate an author-ordered list of [`Bound`]s for a single scope.
///
/// Enforces the per-kind-uniqueness invariant (a list with two bounds of one
/// kind is a construction error) and returns a *canonically-ordered*
/// `Vec<Bound>` — sorted by kind (`Time`, then `Cost`, then `Tokens`) — so
/// author order never changes the definition hash. Each individual
/// bound is assumed already value-validated by its constructor; this function
/// only checks list-level invariants.
///
/// # Errors
///
/// [`BoundError::DuplicateKind`] when two bounds share a kind.
pub fn validate_bounds(bounds: Vec<Bound>) -> Result<Vec<Bound>, BoundError> {
    let mut seen: Vec<BoundKind> = Vec::with_capacity(bounds.len());
    for bound in &bounds {
        let kind = bound.kind();
        if seen.contains(&kind) {
            return Err(BoundError::DuplicateKind(kind));
        }
        seen.push(kind);
    }
    Ok(canonical_order(bounds))
}

/// Sort a bounds list into the canonical hash order: `Time`, `Cost`, `Tokens`.
///
/// Used by [`validate_bounds`] and by the definition hash so author order has
/// no effect on identity. Within a kind there is at most one bound (enforced
/// by [`validate_bounds`]), so this total order is unambiguous.
fn canonical_order(mut bounds: Vec<Bound>) -> Vec<Bound> {
    bounds.sort_by_key(|b| match b.kind() {
        BoundKind::Time => 0u8,
        BoundKind::Cost => 1u8,
        BoundKind::Tokens => 2u8,
    });
    bounds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_constructor_rejects_zero() {
        assert_eq!(Bound::time(0), Err(BoundError::NonPositiveTime));
        assert_eq!(Bound::time(1), Ok(Bound::Time { ms: 1 }));
    }

    #[test]
    fn cost_micro_usd_constructor_rejects_zero() {
        assert_eq!(Bound::cost_micro_usd(0), Err(BoundError::NonPositiveCost));
        assert_eq!(Bound::cost_micro_usd(1), Ok(Bound::Cost { micro_usd: 1 }));
    }

    #[test]
    fn cost_usd_converts_to_micro_usd() {
        // 1.5 USD == 1_500_000 micro-USD.
        assert_eq!(
            Bound::cost_usd(1.5),
            Ok(Bound::Cost {
                micro_usd: 1_500_000
            })
        );
        // 5.0 USD == 5_000_000 micro-USD.
        assert_eq!(
            Bound::cost_usd(5.0),
            Ok(Bound::Cost {
                micro_usd: 5_000_000
            })
        );
    }

    #[test]
    fn cost_usd_rounds_to_nearest_micro_usd() {
        // Round-to-nearest (not truncation): the f64 closest to 1.005 scales to
        // ~1_005_000, which must round up rather than floor to 1_004_999.
        assert_eq!(
            Bound::cost_usd(1.005),
            Ok(Bound::Cost {
                micro_usd: 1_005_000
            })
        );
    }

    #[test]
    fn cost_usd_rejects_out_of_range() {
        // ~$1.8e13 is the u64 micro-USD ceiling; beyond it the cast would
        // saturate to u64::MAX, so it is rejected rather than silently clamped.
        assert_eq!(Bound::cost_usd(1e14), Err(BoundError::CostOutOfRange));
        assert_eq!(Bound::cost_usd(1e15), Err(BoundError::CostOutOfRange));
    }

    #[test]
    fn cost_usd_rejects_non_positive_and_non_finite() {
        assert_eq!(Bound::cost_usd(0.0), Err(BoundError::NonPositiveCost));
        assert_eq!(Bound::cost_usd(-1.0), Err(BoundError::NonPositiveCost));
        assert_eq!(Bound::cost_usd(f64::NAN), Err(BoundError::NonPositiveCost));
        assert_eq!(
            Bound::cost_usd(f64::INFINITY),
            Err(BoundError::NonPositiveCost)
        );
        // Sub-micro-USD truncates to zero budget and is rejected.
        assert_eq!(
            Bound::cost_usd(0.000_000_1),
            Err(BoundError::NonPositiveCost)
        );
    }

    #[test]
    fn kind_discriminants() {
        assert_eq!(Bound::Time { ms: 1 }.kind(), BoundKind::Time);
        assert_eq!(Bound::Cost { micro_usd: 1 }.kind(), BoundKind::Cost);
        assert_eq!(Bound::Tokens { tokens: 1 }.kind(), BoundKind::Tokens);
    }

    #[test]
    fn tokens_constructor_rejects_zero() {
        assert_eq!(Bound::tokens(0), Err(BoundError::NonPositiveTokens));
        assert_eq!(Bound::tokens(1), Ok(Bound::Tokens { tokens: 1 }));
        assert_eq!(Bound::tokens(50_000).map(|b| b.limit()), Ok(50_000));
    }

    #[test]
    fn validate_bounds_rejects_duplicate_tokens() {
        let err = validate_bounds(vec![
            Bound::Tokens { tokens: 1 },
            Bound::Tokens { tokens: 2 },
        ])
        .unwrap_err();
        assert_eq!(err, BoundError::DuplicateKind(BoundKind::Tokens));
    }

    /// The token bound is a WIRE FORMAT on the checked program and the loop policy
    /// hash: `{"kind":"tokens","data":{"tokens":N}}`, sorted after cost.
    #[test]
    fn token_bound_serde_is_kind_tagged_and_sorts_last() {
        let bound = Bound::Tokens { tokens: 50_000 };
        let s = serde_json::to_string(&bound).unwrap();
        assert_eq!(s, r#"{"kind":"tokens","data":{"tokens":50000}}"#);
        assert_eq!(serde_json::from_str::<Bound>(&s).unwrap(), bound);
        assert_eq!(
            validate_bounds(vec![
                Bound::Tokens { tokens: 9 },
                Bound::Cost { micro_usd: 5 },
                Bound::Time { ms: 1 },
            ])
            .unwrap(),
            vec![
                Bound::Time { ms: 1 },
                Bound::Cost { micro_usd: 5 },
                Bound::Tokens { tokens: 9 },
            ]
        );
    }

    #[test]
    fn validate_bounds_rejects_duplicate_time() {
        let err = validate_bounds(vec![Bound::Time { ms: 1 }, Bound::Time { ms: 2 }]).unwrap_err();
        assert_eq!(err, BoundError::DuplicateKind(BoundKind::Time));
    }

    #[test]
    fn validate_bounds_rejects_duplicate_cost() {
        let err = validate_bounds(vec![
            Bound::Cost { micro_usd: 1 },
            Bound::Cost { micro_usd: 2 },
        ])
        .unwrap_err();
        assert_eq!(err, BoundError::DuplicateKind(BoundKind::Cost));
    }

    #[test]
    fn validate_bounds_canonicalizes_order() {
        // Author order Cost-then-Time canonicalizes to Time-then-Cost.
        let canonical = validate_bounds(vec![
            Bound::Cost {
                micro_usd: 5_000_000,
            },
            Bound::Time { ms: 1_000 },
        ])
        .unwrap();
        assert_eq!(
            canonical,
            vec![
                Bound::Time { ms: 1_000 },
                Bound::Cost {
                    micro_usd: 5_000_000
                },
            ]
        );
    }

    #[test]
    fn validate_bounds_accepts_empty_and_single() {
        assert_eq!(validate_bounds(vec![]), Ok(vec![]));
        assert_eq!(
            validate_bounds(vec![Bound::Time { ms: 1 }]),
            Ok(vec![Bound::Time { ms: 1 }])
        );
    }

    #[test]
    fn time_bound_serde_is_kind_tagged() {
        let bound = Bound::Time { ms: 1_500 };
        let s = serde_json::to_string(&bound).unwrap();
        assert_eq!(s, r#"{"kind":"time","data":{"ms":1500}}"#);
        let back: Bound = serde_json::from_str(&s).unwrap();
        assert_eq!(back, bound);
    }

    #[test]
    fn cost_bound_serde_is_kind_tagged() {
        let bound = Bound::Cost {
            micro_usd: 1_500_000,
        };
        let s = serde_json::to_string(&bound).unwrap();
        assert_eq!(s, r#"{"kind":"cost","data":{"micro_usd":1500000}}"#);
        let back: Bound = serde_json::from_str(&s).unwrap();
        assert_eq!(back, bound);
    }

    /// The marker literals are pinned because they are a WIRE
    /// FORMAT, not an implementation detail: they name durable ledger rows that
    /// outlive the process, so a resumed or upgraded node reads rows a previous
    /// binary wrote. Changing either string silently un-halts every execution
    /// already holding a halt row — the walk-away would report clean on restart.
    /// Renaming must therefore be a deliberate act that breaks this test, not a
    /// refactor that passes.
    #[test]
    fn walkaway_halt_markers_are_pinned() {
        assert_eq!(BOUND_HALT_MARKER_INFIX, "#bound-halt-");
        assert_eq!(BUDGET_HALT_MARKER_SUFFIX, "#budget-halt");
        assert_eq!(METERING_HALT_MARKER_SUFFIX, "#metering-halt");
        // The names the two writers actually compose, for every bound kind.
        for kind in [BoundKind::Time, BoundKind::Cost, BoundKind::Tokens] {
            let row = format!("work{BOUND_HALT_MARKER_INFIX}{}", kind.label());
            assert!(
                is_walkaway_halt_row(&row),
                "the composed bound-halt row must be recognized: {row}"
            );
        }
        assert!(is_walkaway_halt_row(&format!(
            "work{BUDGET_HALT_MARKER_SUFFIX}"
        )));
        // The fail-closed metering halt is the THIRD walk-away cause and must reach
        // the same terminal surface: a run that stopped because it could no
        // longer measure spend must not report `completed`/exit 0 either.
        assert!(is_walkaway_halt_row(&format!(
            "work{METERING_HALT_MARKER_SUFFIX}"
        )));
    }

    /// The predicate must not fire on names a workflow author can actually
    /// declare. `#` is the reserved synthetic sentinel, so a declared stage can
    /// never collide — but a false positive here would report a CLEAN run as a
    /// walk-away, which is the opposite lie from a missed halt and just as bad
    /// for an unattended operator.
    #[test]
    fn walkaway_predicate_ignores_declared_stage_names() {
        for name in [
            "work",
            "bound-halt-time",  // no `#` sentinel
            "budget-halt",      // no `#` sentinel
            "metering-halt",    // no `#` sentinel
            "work#branch-skip", // a different synthetic class
            "__workflow__",     // the workflow-level failure sentinel
            "halt",
            "",
        ] {
            assert!(
                !is_walkaway_halt_row(name),
                "must not classify {name:?} as a walk-away halt row"
            );
        }
    }
}
