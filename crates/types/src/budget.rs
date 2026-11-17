//! Cost-budget enforcement policy types.
//!
//! Three modes — `Unlimited` (default; no enforcement), `Warn`
//! (emit metric + event on crossing), `Halt` (fail offending stage,
//! cascade skip-dependents) — with a single `limit_micro_usd` knob
//! shared by Warn and Halt. Default is `Unlimited` so workflows that
//! never set a `cost_budget` field decode unchanged.
//!
//! Operator-facing Starlark uses `limit_usd: f64` for ergonomics; lowering
//! converts to `limit_micro_usd: u64` so all in-runtime math
//! stays integer-only (the micro-USD unit every metered cost uses).

use serde::{Deserialize, Serialize};

/// Three-mode cost-budget enforcement policy.
///
/// Default is [`Self::Unlimited`] so missing `cost_budget` fields in
/// workflow configs decode without breakage (`#[serde(default)]` in the
/// owning struct).
///
/// `Warn` and `Halt` carry the same shape (a single `limit_micro_usd`)
/// — the only behavioral difference is whether the runner stops the
/// workflow (`Halt`) or just emits observability (`Warn`) when the
/// running cost crosses the limit.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum BudgetPolicy {
    /// No enforcement, no tracking overhead. Default when no
    /// `cost_budget` field is declared by the workflow.
    #[default]
    Unlimited,
    /// Emit the `kata_workflow_budget_exceeded_total{mode="warn"}`
    /// counter when running spend crosses `limit_micro_usd`. Workflow
    /// continues.
    /// Debounced once per scope per crossing.
    Warn { limit_micro_usd: u64 },
    /// Fail the offending stage with a structured `budget_exceeded`
    /// reason and cascade skip across dependents per the
    /// `orchestrator::skip_dependents` contract.
    Halt { limit_micro_usd: u64 },
}

impl BudgetPolicy {
    /// `Some(limit)` for [`Self::Warn`] / [`Self::Halt`]; `None` for
    /// [`Self::Unlimited`].
    #[must_use]
    pub fn limit_micro_usd(&self) -> Option<u64> {
        match self {
            Self::Unlimited => None,
            Self::Warn { limit_micro_usd } | Self::Halt { limit_micro_usd } => {
                Some(*limit_micro_usd)
            }
        }
    }

    /// `true` if the policy is the [`Self::Halt`] variant.
    #[must_use]
    pub fn is_halt(&self) -> bool {
        matches!(self, Self::Halt { .. })
    }

    /// The [`BudgetMode`] this policy is authored with.
    #[must_use]
    pub fn mode(&self) -> BudgetMode {
        match self {
            Self::Unlimited => BudgetMode::Unlimited,
            Self::Warn { .. } => BudgetMode::Warn,
            Self::Halt { .. } => BudgetMode::Halt,
        }
    }

    /// Mode label for metrics / event payloads. `"warn"`, `"halt"`,
    /// or `"unlimited"`.
    #[must_use]
    pub fn mode_label(&self) -> &'static str {
        self.mode().label()
    }
}

/// A [`BudgetPolicy`]'s `mode` without its ceiling: the closed set
/// `cost_budget(mode=)` and a `cost_budget={"mode": ..}` dict parse through
/// [`Self::from_label`], and the DSL catalog's `cost_budget_mode` domain.
#[derive(
    Clone, Copy, PartialEq, Eq, Debug, strum::IntoStaticStr, strum::EnumString, strum::VariantArray,
)]
#[strum(serialize_all = "snake_case")]
pub enum BudgetMode {
    Unlimited,
    Warn,
    Halt,
}

impl BudgetMode {
    /// The mode's spelling — the serde `mode` tag of [`BudgetPolicy`].
    #[must_use]
    pub fn label(self) -> &'static str {
        self.into()
    }

    /// The mode whose [`Self::label`] is exactly `label` (no trimming, no case
    /// folding), or `None`.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        label.parse().ok()
    }

    /// `true` for the modes that carry a ceiling (`warn`, `halt`).
    #[must_use]
    pub fn is_bounded(self) -> bool {
        !matches!(self, Self::Unlimited)
    }

    /// The policy this mode names with ceiling `limit_micro_usd`, which
    /// [`Self::Unlimited`] ignores.
    #[must_use]
    pub fn with_limit(self, limit_micro_usd: u64) -> BudgetPolicy {
        match self {
            Self::Unlimited => BudgetPolicy::Unlimited,
            Self::Warn => BudgetPolicy::Warn { limit_micro_usd },
            Self::Halt => BudgetPolicy::Halt { limit_micro_usd },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_unlimited() {
        assert_eq!(BudgetPolicy::default(), BudgetPolicy::Unlimited);
    }

    #[test]
    fn limit_accessor() {
        assert_eq!(BudgetPolicy::Unlimited.limit_micro_usd(), None);
        assert_eq!(
            BudgetPolicy::Warn {
                limit_micro_usd: 5_000_000
            }
            .limit_micro_usd(),
            Some(5_000_000)
        );
        assert_eq!(
            BudgetPolicy::Halt {
                limit_micro_usd: 1_000_000
            }
            .limit_micro_usd(),
            Some(1_000_000)
        );
    }

    #[test]
    fn variant_predicates() {
        assert!(!BudgetPolicy::Unlimited.is_halt());
        assert!(BudgetPolicy::Halt { limit_micro_usd: 1 }.is_halt());
        assert!(!BudgetPolicy::Warn { limit_micro_usd: 1 }.is_halt());
    }

    #[test]
    fn mode_labels() {
        assert_eq!(BudgetPolicy::Unlimited.mode_label(), "unlimited");
        assert_eq!(
            BudgetPolicy::Warn {
                limit_micro_usd: 1_000_000
            }
            .mode_label(),
            "warn"
        );
        assert_eq!(
            BudgetPolicy::Halt {
                limit_micro_usd: 1_000_000
            }
            .mode_label(),
            "halt"
        );
    }

    /// Every [`BudgetMode`]'s label is the serde `mode` tag of the policy it
    /// names — read off the serializer, not off the label — and parses back to
    /// that mode, which the policy reports. The modes come from the derived
    /// `VARIANTS`, so a new mode is covered without editing this list.
    #[test]
    fn budget_mode_labels_are_the_serde_mode_tags() {
        use strum::VariantArray;
        for mode in BudgetMode::VARIANTS {
            let policy = mode.with_limit(1);
            let tag = serde_json::to_value(policy).expect("serializes")["mode"]
                .as_str()
                .expect("a mode tag")
                .to_owned();
            assert_eq!(tag, mode.label());
            assert_eq!(BudgetMode::from_label(&tag), Some(*mode));
            assert_eq!(policy.mode(), *mode);
        }
        assert_eq!(BudgetMode::from_label("Warn"), None);
        assert_eq!(BudgetMode::from_label(" warn"), None);
    }

    #[test]
    fn unlimited_serde_roundtrip() {
        let s = serde_json::to_string(&BudgetPolicy::Unlimited).unwrap();
        // Internally-tagged enum: `{"mode":"unlimited"}`.
        assert_eq!(s, r#"{"mode":"unlimited"}"#);
        let back: BudgetPolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(back, BudgetPolicy::Unlimited);
    }

    #[test]
    fn halt_serde_roundtrip() {
        let original = BudgetPolicy::Halt {
            limit_micro_usd: 5_000_000,
        };
        let s = serde_json::to_string(&original).unwrap();
        let back: BudgetPolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn warn_serde_roundtrip() {
        let original = BudgetPolicy::Warn {
            limit_micro_usd: 250_000,
        };
        let s = serde_json::to_string(&original).unwrap();
        let back: BudgetPolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(back, original);
    }
}
