//! THE ATTEMPT-PLANE VOCABULARY, AS A TYPE.
//!
//! `attempt_projection.state` holds a TWELVE-spelling lifecycle vocabulary —
//! the attempt plane's answer to *"who holds this work and has it settled?"*,
//! typed here as [`AttemptLifecycle`] and read only through it.
//! [`AttemptCustody`] partitions the lifecycle by who holds the attempt.
//!
//! # The attempt-plane vocabulary is a type, not bare strings
//!
//! [`AttemptLifecycle`] is that type. A hand-maintained SQL `IN` list beside bare
//! `&str` at every call site is a drift nothing can notice. The CHECK list is
//! GENERATED from [`AttemptLifecycle::ALL`] — see `schema.rs` — so a member added
//! here reaches it, and a member the CHECK does not know is unwritable rather than
//! merely untested.

/// Every state `attempt_projection.state` may hold — the STAMPED attempt-lifecycle
/// vocabulary, as a type.
///
/// # Invariant
///
/// THIS TYPE IS THE VOCABULARY. The SQL `IN` list that enforces the column is
/// BUILT from [`Self::ALL`] via [`state_check_list`], so the type and the CHECK
/// cannot disagree — the drift class that costs nothing to introduce and everything
/// to find is unrepresentable rather than tested for.
///
/// # The two states with no wire status
///
/// Every member but two is an `AssignmentStatus::tag()` spelling.
/// `awaiting_timer` and `awaiting_input` are the exception: their writer is
/// `OperationalDb::claim_main_attempt`, not an `AssignmentStatus` arm, and they are
/// MAIN-ONLY — a worker attempt may not enter them. They have no wire status by
/// design: they are a main attempt's park, which the delivery mapping records as
/// no wire event, so they are named on the chain by their transition kind
/// (`main_parked`) and never refused by class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AttemptLifecycle {
    /// Admitted and durable; no executor holds it.
    Pending,
    /// Parked on an operator approval gate.
    AwaitingApproval,
    /// Parked on a child execution's completion.
    AwaitingChildCompletion,
    /// A MAIN-RESOLVED attempt waiting for its durable deadline
    /// (`attempts.wait_deadline_ms`) — a timer wait. Written only by
    /// `OperationalDb::claim_main_attempt`.
    AwaitingTimer,
    /// A MAIN-RESOLVED attempt waiting for a committed input fact (an operator
    /// answer), optionally bounded by `attempts.wait_deadline_ms`. Written only by
    /// `OperationalDb::claim_main_attempt`.
    AwaitingInput,
    /// A dispatch command was issued to a named worker.
    Dispatched,
    /// The worker announced it is running the assignment.
    Running,
    /// Held, past its liveness deadline, and not yet given up on.
    Stalled,
    /// Given up on: no executor holds it and no further delivery will be made.
    Orphaned,
    /// Finished with a durable output.
    Completed,
    /// Finished with a definite negative answer.
    Failed,
    /// Terminated by an operator, on a durable `attempt_stop_requests` row that
    /// stands against the attempt. Worker-failure adjudication records this
    /// atomically with the accepted input.
    Cancelled,
}

impl AttemptLifecycle {
    /// Every member, in the order the DDL lists them.
    ///
    /// The SOLE source of the column's `IN` list, of the custody partition's
    /// completeness proof, and of every sweep over the vocabulary.
    pub const ALL: &'static [Self] = &[
        Self::Pending,
        Self::AwaitingApproval,
        Self::AwaitingChildCompletion,
        Self::AwaitingTimer,
        Self::AwaitingInput,
        Self::Dispatched,
        Self::Running,
        Self::Stalled,
        Self::Orphaned,
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
    ];

    /// The exact spelling `attempt_projection.state` stores.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::AwaitingApproval => "awaiting_approval",
            Self::AwaitingChildCompletion => "awaiting_child_completion",
            Self::AwaitingTimer => "awaiting_timer",
            Self::AwaitingInput => "awaiting_input",
            Self::Dispatched => "dispatched",
            Self::Running => "running",
            Self::Stalled => "stalled",
            Self::Orphaned => "orphaned",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Decode one stored `attempt_projection.state`, or `None` for a spelling the
    /// CHECK does not admit.
    ///
    /// The EXACT inverse of [`Self::as_str`], written beside it: a reader with its
    /// own copy of the vocabulary is a reader that can drift into admitting a
    /// state no writer produces.
    #[must_use]
    pub fn from_state(state: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.as_str() == state)
    }

    /// WHO holds this attempt, and whether it has settled.
    ///
    /// # Invariant
    ///
    /// A TOTAL PARTITION of [`Self::ALL`]. Every member lands in exactly one arm,
    /// so a caller that matches on the custody answers for every state;
    /// `attempt_custody_partitions_the_whole_vocabulary`
    /// proves it by counting the partition back up to `ALL`.
    #[must_use]
    pub fn custody(self) -> AttemptCustody {
        match self {
            Self::Pending
            | Self::AwaitingApproval
            | Self::AwaitingChildCompletion
            | Self::AwaitingTimer
            | Self::AwaitingInput => AttemptCustody::Unheld,
            Self::Dispatched | Self::Running | Self::Stalled => AttemptCustody::Held,
            Self::Orphaned | Self::Completed | Self::Failed | Self::Cancelled => {
                AttemptCustody::Settled
            }
        }
    }

    /// Whether this is a MAIN-RESOLVED WAIT — a state only an `executor = 'main'`
    /// attempt enters, and that no worker path can resolve.
    #[must_use]
    pub fn is_main_resolved_wait(self) -> bool {
        matches!(self, Self::AwaitingTimer | Self::AwaitingInput)
    }
}

/// WHO holds an attempt, as a total partition of [`AttemptLifecycle`].
///
/// Custody says who holds the work, not whether an effect it performed escaped:
/// that is the settlement verdict's question (PROVEN NOT PERFORMED, PERFORMED BUT
/// FAILED, PROVEN AMBIGUOUS), recorded on the attempt's terminal transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttemptCustody {
    /// Durable, and NO executor holds it: admitted, or parked on an approval, a
    /// child, or a main-resolved wait.
    Unheld,
    /// An executor holds it under a lease.
    Held,
    /// No executor holds it and no further delivery will be made for this
    /// generation.
    Settled,
}

/// The `attempt_projection.state` CHECK's `IN` list, built from
/// [`AttemptLifecycle::ALL`].
///
/// # Invariant
///
/// THE VOCABULARY IS GENERATED, NEVER RESTATED. The DDL's CHECK interpolates this
/// rather than carrying a hand-written copy of the spellings, so a member added to
/// the type reaches the enforcement point and a member the CHECK does not know is
/// unwritable.
#[must_use]
pub fn state_check_list() -> String {
    AttemptLifecycle::ALL
        .iter()
        .map(|state| format!("'{}'", state.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The decode is the exact inverse of the encode, in both directions, and
    /// refuses a spelling outside the vocabulary.
    #[test]
    fn attempt_lifecycle_round_trips_and_refuses_an_undeclared_spelling() {
        for state in AttemptLifecycle::ALL {
            assert_eq!(
                AttemptLifecycle::from_state(state.as_str()),
                Some(*state),
                "{} must decode to itself",
                state.as_str()
            );
        }
        // COUNTERFACTUAL: the retired states nothing ever wrote do not decode.
        for outside in [
            "awaiting_retry",
            "resumed",
            "timed_out",
            "ambiguous",
            "",
            "Pending",
        ] {
            assert_eq!(
                AttemptLifecycle::from_state(outside),
                None,
                "{outside:?} is outside the stamped vocabulary and must not decode"
            );
        }
    }

    /// `custody` is a TOTAL PARTITION: every member lands in exactly one arm and
    /// the three arms sum back to the whole vocabulary. A caller matching on a
    /// partition with a gap would answer for some states and not others.
    #[test]
    fn attempt_custody_partitions_the_whole_vocabulary() {
        let mut counted = 0usize;
        for arm in [
            AttemptCustody::Unheld,
            AttemptCustody::Held,
            AttemptCustody::Settled,
        ] {
            counted += AttemptLifecycle::ALL
                .iter()
                .filter(|state| state.custody() == arm)
                .count();
        }
        assert_eq!(
            counted,
            AttemptLifecycle::ALL.len(),
            "every lifecycle state must land in exactly one custody arm"
        );
        assert_eq!(AttemptLifecycle::ALL.len(), 12);
    }

    /// The generated `IN` list is the vocabulary, quoted, in `ALL` order — the one
    /// thing three SQL enforcement sites interpolate.
    #[test]
    fn the_generated_check_list_is_the_vocabulary() {
        let list = state_check_list();
        for state in AttemptLifecycle::ALL {
            assert!(
                list.contains(&format!("'{}'", state.as_str())),
                "the generated CHECK list must contain {}",
                state.as_str()
            );
        }
        assert_eq!(
            list.matches('\'').count(),
            AttemptLifecycle::ALL.len() * 2,
            "one quoted literal per member and nothing else"
        );
    }
}
