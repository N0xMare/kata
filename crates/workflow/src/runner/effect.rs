//! The **Effect coerce-retry policy**.
//!
//! Validation-retry is NOT a control-flow `loop`: it is an Effect coerce-retry
//! policy ("re-invoke the model until its output satisfies its Contract
//! membrane, up to a budget, injecting the validation error as feedback"). The
//! `loop` builtin routes on a downstream agent-verdict Effect; this policy
//! governs a SINGLE Effect's at-least-once coerce-with-feedback re-invocation.
//! The decision is named and centralized here; the dispatcher still owns
//! the stateful queue/ledger-dedup orchestration, but consults this policy for
//! every coerce-retry decision so future Effect-interpreter work has one seam.
//!
//! This is a borrowing VIEW over the two `ExecutionStagePolicies` fields that
//! carry the policy (`validate_retries`, `validate_feedback_template`); it does
//! not change their serialized representation (so no `contract_hash` / TOML
//! churn), it only gives the coerce-retry behavior a name and one home.
//!
//! ## The Effect-invocation policy (the unifying view)
//!
//! Re-invoking a single stage-Effect at the orchestration boundary is governed
//! by THREE composable layers, each keyed off a different failure class, each
//! with its own budget, and (by construction) never double-firing with the
//! others on the same event. Naming them together here frames the "how an
//! Effect is invoked at-least-once until it succeeds or exhausts" policy that
//! — a documentation view, NOT a refactor: the
//! machinery of each layer stays where it lives.
//!
//! 1. **Coerce-retry** — re-invoke the Effect until its output satisfies its
//!    Contract membrane, injecting the validation error as feedback, up to
//!    `validate_retries`. Owned HERE ([`EffectCoerceRetryPolicy`]); the
//!    dispatcher consults this policy and owns the stateful queue/ledger-dedup.
//! 2. **Failure-retry** — a worker-REPORTED `Failed` re-runs at once: a
//!    transient model provider failure on the same agent a fixed number of
//!    times, on any plain stage; any other retryable failure on a stage that
//!    authors an agent fallback panel on the panel's next member the provider
//!    has not refused, until the panel is walked
//!    (`WorkflowRunner::capsule_failure_retry`, then the runner's
//!    `execute_failure_retries`).
//! 3. **Crash-settlement** — a worker *death* (transport/heartbeat) settles
//!    the in-flight capsule attempt PROVEN NOT PERFORMED or NOT PROVEN
//!    (`Dispatcher::handle_worker_death`), never re-dispatched.
//!
//! A fourth layer — the model backend's in-call HTTP-transient retry — lives
//! INSIDE a single `ModelCall` Effect invocation and is not part of this
//! orchestration-boundary view. The stateful validate-retry queue/drain stays
//! in the dispatcher (a deliberate deferred refinement, not reshaped here).

use kata_program::execution_program::ExecutionStagePolicies;

/// The validation coerce-retry policy resolved from a checked stage's policies.
pub(super) struct EffectCoerceRetryPolicy<'a> {
    /// Maximum number of coerce-retries after the initial attempt (attempt 0).
    budget: u32,
    /// Operator-supplied feedback template, or `None` to use the default.
    feedback_template: Option<&'a str>,
}

impl<'a> EffectCoerceRetryPolicy<'a> {
    /// Resolve the policy from a checked stage's policies.
    pub(super) fn from_policies(policies: &'a ExecutionStagePolicies) -> Self {
        Self {
            budget: policies.validate_retries,
            feedback_template: policies.validate_feedback_template.as_deref(),
        }
    }

    /// The coerce-retry budget (number of retries permitted after attempt 0).
    pub(super) fn budget(&self) -> u32 {
        self.budget
    }

    /// Whether this stage opts into runner-owned coerce-retry at all. When
    /// `false`, the worker's own fail-fast schema validation is authoritative
    /// (the runner does not pre-empt it with a main-side retry budget).
    #[cfg(test)]
    pub(super) fn is_enabled(&self) -> bool {
        self.budget > 0
    }

    /// Whether a stage that has already taken `current_attempt` coerce-retries
    /// is permitted another. Attempt 0 is the initial invocation; attempts
    /// `1..=budget` are the coerce-retries.
    pub(super) fn should_retry(&self, current_attempt: u32) -> bool {
        current_attempt < self.budget
    }

    /// Build the coerce-retry prompt: the stage's originally-rendered prompt
    /// with the validation `error` injected via the feedback template (the
    /// operator-supplied one, or [`kata_program::template::DEFAULT_VALIDATE_FEEDBACK_TEMPLATE`]).
    ///
    /// # Errors
    ///
    /// `rendered_prompt_over_bound` when the feedback carries the prompt past
    /// [`kata_program::template::MAX_RENDERED_PROMPT_BYTES`]: the original was bounded
    /// at its render, the appended text was not.
    pub(super) fn build_retry_prompt(
        &self,
        stage_name: &str,
        original_prompt: &str,
        error: &str,
    ) -> kata_types::error::KataResult<String> {
        let template = self
            .feedback_template
            .unwrap_or(kata_program::template::DEFAULT_VALIDATE_FEEDBACK_TEMPLATE);
        let prompt = kata_program::template::render_validate_feedback_prompt(
            original_prompt,
            template,
            error,
        );
        kata_program::template::refuse_rendered_over_bound(stage_name, &prompt, false)?;
        Ok(prompt)
    }
}

#[cfg(test)]
impl<'a> EffectCoerceRetryPolicy<'a> {
    /// Direct constructor for unit tests. `from_policies` (the production path)
    /// is a trivial field copy exercised by the dispatch integration tests and
    /// the live validation-retry e2e.
    fn for_test(budget: u32, feedback_template: Option<&'a str>) -> Self {
        Self {
            budget,
            feedback_template,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_enabled_tracks_budget() {
        assert!(!EffectCoerceRetryPolicy::for_test(0, None).is_enabled());
        assert!(EffectCoerceRetryPolicy::for_test(1, None).is_enabled());
    }

    #[test]
    fn should_retry_respects_budget_boundary() {
        let policy = EffectCoerceRetryPolicy::for_test(2, None);
        assert!(policy.should_retry(0), "initial attempt may retry");
        assert!(policy.should_retry(1), "first retry may retry again");
        assert!(
            !policy.should_retry(2),
            "budget exhausted at attempt == budget"
        );
        assert!(!policy.should_retry(3), "beyond budget never retries");
    }

    #[test]
    fn build_retry_prompt_uses_default_template_when_unset() {
        let prompt = EffectCoerceRetryPolicy::for_test(1, None)
            .build_retry_prompt("s", "do the thing", "expected object, got string")
            .expect("within the bound");
        assert!(
            prompt.starts_with("do the thing"),
            "original prompt preserved"
        );
        assert!(
            prompt.contains("expected object, got string"),
            "validation error injected: {prompt}"
        );
    }

    #[test]
    fn build_retry_prompt_honors_custom_template() {
        let prompt = EffectCoerceRetryPolicy::for_test(1, Some("\n\nFIX THIS: {{ error }}"))
            .build_retry_prompt("s", "original", "bad field x")
            .expect("within the bound");
        assert!(
            prompt.contains("FIX THIS: bad field x"),
            "custom template used: {prompt}"
        );
    }

    /// The retry prompt is bounded AFTER its feedback is appended: an original
    /// prompt one byte under the bound passes its own render's check, and the
    /// feedback carries it past, so the retry is refused naming the code.
    #[test]
    fn a_retry_prompt_past_the_prompt_bound_is_refused() {
        let bound = kata_program::template::MAX_RENDERED_PROMPT_BYTES;
        let original = "x".repeat(bound - 1);
        kata_program::template::refuse_rendered_over_bound("s", &original, false)
            .expect("the original prompt fits");
        let Err(err) = EffectCoerceRetryPolicy::for_test(1, None).build_retry_prompt(
            "s",
            &original,
            "expected object, got string",
        ) else {
            panic!("the feedback carries the retry prompt past the bound");
        };
        let err = err.to_string();
        assert!(err.contains("rendered_prompt_over_bound"), "{err}");
    }
}
