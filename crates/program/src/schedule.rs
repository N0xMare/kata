//! The schedule a pack DECLARES: `schedule(id=..,submit=..,every_ms=..|cron=..)`
//! lowers to a [`ScheduleSpec`], validated at authoring time (fail-closed) so a
//! malformed cron expression or a zero interval is a load-time error, never a
//! sweep-time surprise. `kata_workflow::schedule` is the durable authority that
//! installs, pins and fires one.

use kata_types::error::{KataError, KataResult};
use serde::{Deserialize, Serialize};

mod cron;
pub use cron::CronSchedule;

/// How a schedule that came due while the engine was DOWN is handled on the
/// first sweep after boot. See the module docs for the semantics.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, strum::VariantArray,
)]
#[serde(rename_all = "snake_case")]
pub enum MissedPolicy {
    /// Coalesce every missed occurrence into a single catch-up run, then
    /// re-anchor. The default.
    #[default]
    FireOnceOnBoot,
    /// Drop the missed occurrence; re-anchor to the next future one.
    Skip,
}

impl MissedPolicy {
    /// Every policy (the derived `strum::VariantArray`): the DSL catalog's
    /// `schedule_on_missed` domain and the set [`Self::parse`] accepts.
    #[must_use]
    pub fn variants() -> &'static [Self] {
        <Self as strum::VariantArray>::VARIANTS
    }

    /// The DSL spelling — the SAME token serde emits.
    #[must_use]
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::FireOnceOnBoot => "fire_once_on_boot",
            Self::Skip => "skip",
        }
    }

    /// Parse the DSL string spelling (`"fire_once_on_boot"` / `"skip"`).
    pub fn parse(s: &str) -> Option<Self> {
        Self::variants()
            .iter()
            .copied()
            .find(|policy| policy.as_tag() == s)
    }
}

/// What makes a [`ScheduleSpec`] come due: a fixed interval or a cron
/// expression. Serialized durably into `schedules."trigger"`, so the variant tag is
/// stable — and the durable encoding is CANONICAL, because `install_schedule`
/// compares that column by string equality to decide converge-or-refuse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleTrigger {
    /// Fire every `every_ms` milliseconds.
    Interval { every_ms: u64 },
    /// Fire per a 5-field cron expression (`min hour dom month dow`, UTC).
    Cron { expr: String },
}

impl ScheduleTrigger {
    /// Validate + parse the trigger at authoring time so a malformed cron
    /// expression (or a zero interval) is a load-time error, never a
    /// sweep-time surprise (fail-closed).
    pub fn validate(&self) -> KataResult<()> {
        match self {
            ScheduleTrigger::Interval { every_ms } => {
                if *every_ms == 0 {
                    return Err(KataError::Validation(
                        "schedule() every_ms must be > 0".to_owned(),
                    ));
                }
                Ok(())
            }
            ScheduleTrigger::Cron { expr } => CronSchedule::parse(expr).map(|_| ()),
        }
    }

    /// The first firing instant STRICTLY after `after_ms`.
    ///
    /// For an interval this is `after_ms + every_ms`; for a cron expression it
    /// is the next matching minute (evaluated in UTC).
    pub fn next_after(&self, after_ms: u64) -> KataResult<u64> {
        match self {
            ScheduleTrigger::Interval { every_ms } => Ok(after_ms.saturating_add(*every_ms)),
            ScheduleTrigger::Cron { expr } => CronSchedule::parse(expr)?.next_after(after_ms),
        }
    }
}

/// A durable schedule declaration: submit workflow `submit_pack` when
/// `trigger` comes due, subject to `on_missed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleSpec {
    /// Stable schedule id (the durable key). Non-empty.
    pub id: String,
    /// The workflow pack to submit when the schedule fires.
    pub submit_pack: String,
    /// What makes the schedule come due.
    pub trigger: ScheduleTrigger,
    /// Missed-while-down policy.
    #[serde(default)]
    pub on_missed: MissedPolicy,
    /// Authored constant invocation params (`{name: value}`) supplied to the
    /// target pack, resolved + default-filled against the target program's declared
    /// param contract. Empty for a schedule that submits a param-less pack, and
    /// skipped from the durable JSON when empty.
    ///
    /// The resolved result is PINNED. These params are resolved once, at
    /// INSTALL, into the immutable invocation the durable row binds — and then
    /// re-validated over those PINNED BYTES on every fire, which is what
    /// `ParamProvenance::Schedule`'s "re-validated at fire time" means now. Because
    /// the input is fixed, that re-validation is a genuine fixed point: it can only
    /// confirm or REFUSE, never silently resolve to something different. Digest
    /// stability across fires and across restarts therefore holds BY CONSTRUCTION —
    /// every fire submits byte-identical invocation bytes.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub params: serde_json::Map<String, serde_json::Value>,
}

impl ScheduleSpec {
    /// Validate the whole spec at authoring time (fail-closed).
    pub fn validate(&self) -> KataResult<()> {
        if self.id.trim().is_empty() {
            return Err(KataError::Validation(
                "schedule() id must be non-empty".to_owned(),
            ));
        }
        if self.submit_pack.trim().is_empty() {
            return Err(KataError::Validation(
                "schedule() submit target must be non-empty".to_owned(),
            ));
        }
        self.trigger.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_trigger_next_after_is_strict() {
        let t = ScheduleTrigger::Interval { every_ms: 100 };
        assert_eq!(t.next_after(1_000).unwrap(), 1_100);
    }

    #[test]
    fn spec_validation_is_fail_closed() {
        let ok = ScheduleSpec {
            id: "s".into(),
            submit_pack: "p".into(),
            trigger: ScheduleTrigger::Interval { every_ms: 1 },
            on_missed: MissedPolicy::default(),
            params: serde_json::Map::new(),
        };
        assert!(ok.validate().is_ok());

        let bad_id = ScheduleSpec {
            id: "  ".into(),
            ..ok.clone()
        };
        assert!(bad_id.validate().is_err());

        let bad_interval = ScheduleSpec {
            trigger: ScheduleTrigger::Interval { every_ms: 0 },
            ..ok.clone()
        };
        assert!(bad_interval.validate().is_err());

        let bad_cron = ScheduleSpec {
            trigger: ScheduleTrigger::Cron {
                expr: "not a cron".into(),
            },
            ..ok
        };
        assert!(bad_cron.validate().is_err());
    }
}
