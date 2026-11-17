//! Review-loop shared helpers.
//!
//! The durable expansion drive (`kata_workflow::runner::expansion`) owns review-loop
//! execution: iteration membership, the `#iter-N` name contract, per-loop
//! bound accounting, rollover context, and the review template's `review.*`
//! packet. This module holds the one spelling of each shared piece — the
//! name parsers and composers every name-dependent read peels through, the
//! envelope cost/metering extracts, and the rollover/context builders the
//! drive passes to iteration N+1.
//!
//! The pieces the drive reads are public because the drive is the runtime's
//! (`kata-workflow`) and this module is the program's; the fixture harness
//! (`crate::test_harness`) reads the same ones.
//!
use kata_types::bound::Bound;
use kata_types::review_loop::ReviewLoop;
use smol_str::SmolStr;

pub(crate) const ROLLOVER_SUMMARY_MAX_BYTES: usize = 2048;

/// Continue-as-new: the bounded distilled-restart descriptor for a loop
/// iteration that belongs to rollover GENERATION ≥ 1.
///
/// A PURE FUNCTION of the loop's monotonic `iteration` counter, its config, and
/// its current `latest_feedback` — so it is re-derived on crash-resume straight
/// from the durably-folded loop view (`runner::expansion`) with NO new durable
/// marker (the
/// maximally replay-safe choice; see [`ReviewLoop::rollover_after_iterations`]).
/// Surfaced to the next worker prompt as `{{ review.rollover }}` so an
/// unbounded loop "continues as new" from a bounded summary + a durable-memory
/// reference instead of an ever-growing raw transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolloverContext {
    /// The rollover generation this iteration belongs to
    /// (`iteration / window`). ≥ 1 whenever this descriptor exists (generation 0
    /// has no rollover yet and yields `None`).
    pub generation: u32,
    /// Total iterations elapsed before this generation began
    /// (`generation * window`) — the loop-counter provenance the distilled
    /// restart preserves across the reset.
    pub iterations_elapsed: u32,
    /// Deterministic *logical* reference under which the rich distilled summary
    /// is written to the durable memory plane at the boundary (best-effort).
    /// Stable across resume because it is a pure function of `(worker_stage,
    /// generation)`.
    ///
    /// NOTE — this is NOT the durable object's raw `id`. To stay collision-free
    /// when one memory store is shared across executions (two runs both reach a
    /// gen-1 rollover for the same worker), the persisted object id is
    /// execution-prefixed (`{execution_id}:{memory_key}`), while this logical
    /// key is surfaced bare to the prompt as `{{ review.rollover.memory_key }}`
    /// so it stays execution-independent and resume-stable. The persisted object
    /// therefore resolves within the execution scope via its
    /// `provenance.source_id` (== this `memory_key`), not by a raw `store.get`
    /// of this string. See `WorkflowRunner::persist_rollover_memory`.
    pub memory_key: String,
    /// Bounded feedback digest carried forward (truncated to
    /// [`ROLLOVER_SUMMARY_MAX_BYTES`]).
    pub summary: String,
    /// True only on the FIRST iteration of the generation
    /// (`iteration % window == 0`) — the exact "continue as new" boundary where
    /// the runner distills + writes durable memory and the prompt's
    /// `previous_output` is replaced by the bounded summary. On the remaining
    /// intra-generation iterations the descriptor still rides (provenance) but
    /// `previous_output` is the ordinary latest output.
    pub at_boundary: bool,
}

/// Truncate a carried summary string to [`ROLLOVER_SUMMARY_MAX_BYTES`]
/// on a UTF-8 char boundary (never mid-codepoint), so the distilled restart's
/// prompt contribution is bounded regardless of the raw feedback size.
pub(crate) fn truncate_rollover_summary(s: &str) -> String {
    if s.len() <= ROLLOVER_SUMMARY_MAX_BYTES {
        return s.to_owned();
    }
    let mut end = ROLLOVER_SUMMARY_MAX_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_owned();
    out.push('…');
    out
}

/// The deterministic logical memory reference for a loop's rollover
/// summary at a given generation. Execution-relative (namespaced by the durable
/// write's `MemoryScope` + provenance.execution_id at the call site) so the
/// prompt-facing key is stable across resume.
pub(crate) fn rollover_memory_key(worker_stage: &str, generation: u32) -> String {
    format!("rollover:{worker_stage}:gen-{generation}")
}

/// The [`RolloverContext`] descriptor for `iteration` of `config`'s
/// loop, or `None` in generation 0. A pure function of `(config, iteration,
/// latest_feedback)` — freestanding so the durable expansion derive
/// (`runner::expansion`) renders it off its own durably-folded view.
pub fn rollover_context_for(
    config: &ReviewLoop,
    iteration: u32,
    latest_feedback: Option<&str>,
) -> Option<RolloverContext> {
    let window = config.effective_rollover_after_iterations();
    let generation = iteration / window;
    if generation == 0 {
        return None;
    }
    let summary =
        truncate_rollover_summary(latest_feedback.unwrap_or("(no reviewer feedback carried)"));
    Some(RolloverContext {
        generation,
        iterations_elapsed: generation * window,
        memory_key: rollover_memory_key(config.worker_stage.as_str(), generation),
        summary,
        at_boundary: iteration.is_multiple_of(window),
    })
}

/// The `review.*` template context for `iteration` — the one shape the
/// expansion's member render composes. Before the first rollover it carries
/// `iteration` / `previous_output` / `feedback` alone; from rollover generation ≥ 1 the
/// `rollover` descriptor rides along, and AT the boundary iteration (the
/// first of a fresh window) `previous_output` and `feedback` are REPLACED
/// by the bounded distilled summary so the per-iteration prompt never
/// carries the unbounded transcript across the restart.
pub fn render_review_context(
    iteration: u32,
    latest_worker_output: Option<&serde_json::Value>,
    latest_feedback: Option<&str>,
    rollover: Option<&RolloverContext>,
) -> serde_json::Value {
    let (previous_output, feedback) = match rollover {
        Some(ctx) if ctx.at_boundary => (
            serde_json::Value::String(ctx.summary.clone()),
            ctx.summary.clone(),
        ),
        _ => (
            latest_worker_output
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            latest_feedback.unwrap_or_default().to_owned(),
        ),
    };
    let mut obj = serde_json::json!({
        "iteration": iteration,
        "previous_output": previous_output,
        "feedback": feedback,
    });
    if let Some(ctx) = rollover {
        obj["rollover"] = serde_json::json!({
            "generation": ctx.generation,
            "iterations_elapsed": ctx.iterations_elapsed,
            "memory_key": ctx.memory_key,
            "summary": ctx.summary,
            "at_boundary": ctx.at_boundary,
        });
    }
    obj
}

/// What a loop's accepted members have spent so far — the per-loop bounds'
/// input, re-accumulated durably by the expansion derive (`runner::expansion`)
/// off EVERY charge record each accepted member's attempts made
/// (`OperationalDb::charge_records_under` over the member's coordinate): its
/// accepted completion, a structured-output retry's rejected completion, a
/// failed, cancelled or orphaned attempt's terminal charge, and — for a member
/// that is a static topology — each of its root's and children's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoopSpend {
    /// `envelope_cost_micro_usd` summed — a sum of KNOWN costs: a record whose
    /// cost is `Unavailable` adds nothing to it, and is named by
    /// [`Self::cost_unknown`] instead.
    pub(crate) micro_usd: u64,
    /// The first member stage a record of unknown cost was charged to, if any
    /// ([`envelope_unmetered_cost`]).
    pub(crate) cost_unknown: Option<String>,
    /// `kata_types::metering::envelope_tokens`' known count summed.
    pub(crate) tokens: u64,
    /// The first member stage whose token count is unknown, if any.
    pub(crate) tokens_unknown: Option<String>,
}

impl LoopSpend {
    /// Charge ONE charge record of member `stage` — a completion's output or a
    /// failure-class terminal's charge envelope — through the readers the
    /// workflow-scope fold uses: [`envelope_cost_micro_usd`] for the known
    /// cost and [`envelope_unmetered_cost`] for an unknown one,
    /// `kata_types::metering::envelope_tokens` for the tokens. Each unknown (an
    /// `Unavailable` usage, a dispatched attempt's charge-less terminal) is
    /// kept, never read as `0`.
    pub fn charge(&mut self, stage: &str, record: &serde_json::Value) {
        self.micro_usd = self
            .micro_usd
            .saturating_add(envelope_cost_micro_usd(record));
        if self.cost_unknown.is_none() {
            self.cost_unknown = envelope_unmetered_cost(stage, record).map(|_| stage.to_owned());
        }
        let tokens = kata_types::metering::envelope_tokens(stage, record);
        self.tokens = self.tokens.saturating_add(tokens.known);
        if self.tokens_unknown.is_none() {
            self.tokens_unknown = tokens.unknown.map(|unknown| unknown.stage);
        }
    }
}

/// The pure bound predicate — `None` or the FIRST bound's trip reason. The
/// durable expansion derive (`runner::expansion`) asks it of its
/// durably-accumulated `(spend, started_at_ms)`.
///
/// A loop `cost_bound` and `token_bound` each trip CLOSED on a member record
/// whose cost (tokens) is unknown, whatever the known total — the total is
/// then a lower bound, which a ceiling cannot be held to — exactly as the
/// workflow scope fails closed (`metering_unavailable`,
/// `token_metering_unavailable`); CHECK refuses an agent stage a loop
/// `cost_bound` covers whose spend kata cannot price.
pub fn loop_bounds_trip(
    bounds: &[Bound],
    spend: &LoopSpend,
    started_at_ms: Option<u64>,
    now_ms: u64,
) -> Option<String> {
    let running_micro_usd = spend.micro_usd;
    for bound in bounds {
        match *bound {
            Bound::Cost { micro_usd } => {
                if let Some(stage) = spend.cost_unknown.as_deref() {
                    return Some(format!(
                        "loop cost bound unenforceable: member {stage:?} recorded no measurable \
                         cost ({})",
                        kata_types::metering::METERING_UNAVAILABLE_REASON_PREFIX
                    ));
                }
                if running_micro_usd > micro_usd {
                    return Some(format!(
                        "loop cost bound exceeded: {running_micro_usd} > {micro_usd} micro-USD"
                    ));
                }
            }
            Bound::Tokens { tokens } => {
                // FAIL CLOSED: a member whose token count is unknown makes the
                // loop's total a lower bound, which a ceiling cannot be held to.
                if let Some(stage) = spend.tokens_unknown.as_deref() {
                    return Some(format!(
                        "loop token bound unenforceable: member {stage:?} recorded no token \
                         count ({})",
                        kata_types::metering::TOKEN_METERING_UNAVAILABLE_REASON_PREFIX
                    ));
                }
                if spend.tokens > tokens {
                    return Some(format!(
                        "loop token bound exceeded: {} > {tokens} tokens",
                        spend.tokens
                    ));
                }
            }
            Bound::Time { ms } => {
                if let Some(start) = started_at_ms {
                    let elapsed = now_ms.saturating_sub(start);
                    if elapsed > ms {
                        return Some(format!("loop time bound exceeded: {elapsed} > {ms} ms"));
                    }
                }
            }
        }
    }
    None
}

pub(crate) use kata_types::metering::envelope_cost_micro_usd;

/// The first stage whose cost ONE charge record — a completion's envelope or
/// a failure-class terminal's [`TerminalCharge::envelope`] — cannot state:
/// its own `token_usage.cost` when that is `Unavailable` (named `stage`), else
/// the first unmetered stage of an invoked child's
/// `child_invocation_summary.metering`, re-rooted `<stage>/<child stage>`.
/// `None` when every cost the record carries is known — a record with no
/// `cost` object (a shell or main-resolved stage) and a summary with no
/// `metering` key state nothing, the carve-out [`envelope_cost_quality`]
/// documents.
///
/// The ONE rule both scopes fail closed by: the workflow fold's
/// `check_metering_enforceable` under a hard cost policy and a loop
/// `cost_bound` ([`LoopSpend::charge`]).
///
/// [`TerminalCharge::envelope`]: kata_types::metering::TerminalCharge::envelope
pub fn envelope_unmetered_cost(
    stage: &str,
    envelope: &serde_json::Value,
) -> Option<kata_types::metering::UnmeteredStage> {
    if let Some(kata_types::metering::MeteredCost::Unavailable { backend, model }) =
        envelope_cost_quality(envelope)
    {
        return Some(kata_types::metering::UnmeteredStage {
            stage: stage.to_owned(),
            backend: backend.to_string(),
            model: model.to_string(),
        });
    }
    let metering = envelope
        .get("child_invocation_summary")
        .and_then(|summary| summary.get("metering"))?;
    let metering =
        serde_json::from_value::<kata_types::metering::MeteringSummary>(metering.clone()).ok()?;
    let first = metering.unmetered.first()?;
    Some(kata_types::metering::UnmeteredStage {
        stage: format!("{stage}/{}", first.stage),
        backend: first.backend.clone(),
        model: first.model.clone(),
    })
}

/// Extract a stage-completion envelope's METERING QUALITY: the
/// `token_usage.cost` object the worker's `build_completed_output` writes
/// alongside the flat `cost_micro_usd`.
///
/// `None` for an envelope that carries no `cost` object at all — a synthetic
/// assignment, or a stage whose output the worker never produced. Deliberately NOT
/// treated as unmeasurable: doing so would fail closed on rows that never carried a
/// cost, a false positive in the direction that costs an operator a working run.
/// Such a row's `cost_micro_usd` still sums.
///
/// Lives beside [`envelope_cost_micro_usd`] for the same reason that one does:
/// the per-loop and workflow-scope paths must read the same field the same way,
/// or the two accountings disagree about which stage was measurable.
pub(crate) fn envelope_cost_quality(
    envelope: &serde_json::Value,
) -> Option<kata_types::metering::MeteredCost> {
    envelope
        .get("token_usage")
        .and_then(|tu| tu.get("cost"))
        .and_then(|c| serde_json::from_value(c.clone()).ok())
}

/// Compose the ledger-visible stage name for iteration N of a loop
/// stage. Iteration 0 uses the base name unchanged (the first pass is
/// indistinguishable from a non-loop stage in the ledger); iterations
/// 1+ use the synthetic suffix `#iter-<N>`.
///
/// Dashboard grouping by base stage can recover the original name via
/// [`parse_iteration`] or [`base_stage_name`].
pub fn iteration_stage_name(base: &SmolStr, n: u32) -> SmolStr {
    if n == 0 {
        base.clone()
    } else {
        SmolStr::new(format!("{base}#iter-{n}"))
    }
}

/// Parse a stage name into `(base, iteration)` if it carries an
/// iteration suffix; returns `None` for unadorned names (which
/// represent iteration 0 by convention).
///
/// A loop stage's validation retry is named
/// `<base>#iter-<N>#validate-<M>` so the dispatching iteration N is
/// intrinsic to the synthetic name (the iteration-stable identity the
/// resync re-walk dedup latch keys on). This parser strips any OUTER
/// `#validate-<M>` suffix FIRST so it reports the inner iteration N for
/// both `<base>#iter-N` and `<base>#iter-N#validate-M`. The bare
/// non-loop retry `<base>#validate-M` (no `#iter-`) still parses to
/// `None` (iteration 0), as before.
pub(crate) fn parse_iteration(name: &str) -> Option<(&str, u32)> {
    let stripped = match parse_validate_retry(name) {
        Some((before, _)) => before,
        None => name,
    };
    let (base, tail) = stripped.rsplit_once("#iter-")?;
    tail.parse().ok().map(|n| (base, n))
}

/// Strip any synthetic suffix (`#iter-N`, `#validate-M`, or the
/// composite `#iter-N#validate-M`) to recover the TRUE base stage name
/// — the name present in the checked execution program. Returns the
/// input unchanged when no suffix is present, so callers can apply this
/// to every stage name regardless of whether it's a synthetic name.
///
/// A loop stage's validation retry is
/// `<base>#iter-N#validate-M`; this peels the OUTER `#validate-M` first
/// (so `parse_iteration` sees the inner `#iter-N`) and then the
/// `#iter-N`, yielding `<base>` for the program lookup. A bare non-loop
/// retry `<base>#validate-M` (no `#iter-`) peels to `<base>` too.
pub fn base_stage_name(name: &SmolStr) -> SmolStr {
    // Peel the outer validate-retry suffix first, if present.
    let without_validate = match parse_validate_retry(name.as_str()) {
        Some((before, _)) => before,
        None => name.as_str(),
    };
    // Then peel any iteration suffix on what remains.
    match parse_iteration(without_validate) {
        Some((base, _)) => SmolStr::new(base),
        None if without_validate.len() == name.len() => name.clone(),
        None => SmolStr::new(without_validate),
    }
}

/// Extract the iteration count from a stage name. Returns 0 for
/// unadorned names. `iteration_of("impl")` → 0, `iteration_of("impl#iter-3")` → 3.
///
/// A loop stage's validation retry is named `<base>#iter-N#validate-M`; the
/// trailing `#validate-M` is peeled first (see [`parse_iteration`]) so the
/// inner iteration `N` is reported, not `0`.
pub fn iteration_of(name: &SmolStr) -> u32 {
    parse_iteration(name.as_str()).map_or(0, |(_, n)| n)
}

/// Synthetic-stage name for a schema-validation retry attempt.
///
/// The original assignment uses iteration-0's bare base name (attempt
/// 0); validation-retry attempts use `<base>#validate-<attempt>`
/// (attempt ≥ 1) so the runner's `apply_event` can detect them and
/// route the validation pass + retry-or-fail-or-complete logic.
///
/// Iteration-stable identity: when the failing
/// stage is a LOOP stage at iteration `dispatch_iter` ≥ 1, the retry
/// name embeds that iteration as `<base>#iter-<N>#validate-<attempt>`.
/// Preserving N in the synthetic name is what gives a retry-completion
/// row a STABLE iteration identity: `iteration_of` recovers N regardless of
/// how far the loop has since advanced, so a re-walk of that row at ANY later
/// iteration attributes it to iteration N rather than over-advancing the
/// loop.
/// `dispatch_iter == 0` keeps the bare `<base>#validate-<attempt>` form
/// (non-loop stages and a loop's iteration-0 pass are indistinguishable
/// in the ledger, as before).
pub(crate) fn validate_retry_name(base: &SmolStr, dispatch_iter: u32, attempt: u32) -> SmolStr {
    debug_assert!(
        attempt >= 1,
        "attempt 0 uses the bare base name; validate_retry_name is for attempt≥1"
    );
    if dispatch_iter == 0 {
        SmolStr::new(format!("{base}#validate-{attempt}"))
    } else {
        SmolStr::new(format!("{base}#iter-{dispatch_iter}#validate-{attempt}"))
    }
}

/// Parse a stage name into `(base, attempt)` if it carries a
/// `#validate-N` suffix; returns `None` for unadorned names.
pub(crate) fn parse_validate_retry(name: &str) -> Option<(&str, u32)> {
    let (base, tail) = name.rsplit_once("#validate-")?;
    tail.parse().ok().map(|n| (base, n))
}

#[doc(hidden)]
pub mod testing {
    //! Test-only accessors for `loops` internals: these wrappers give
    //! `kata-workflow`'s `tests/orchestrator_tests/loops_tests.rs` integration test narrow
    //! string-/bool-typed probes, `parse_iteration` among them, which stays
    //! crate-private.
    use smol_str::SmolStr;

    /// Forwarding wrapper for `super::iteration_stage_name`.
    pub fn iteration_stage_name(base: &SmolStr, n: u32) -> SmolStr {
        super::iteration_stage_name(base, n)
    }

    /// Forwarding wrapper for `super::parse_iteration`.
    pub fn parse_iteration(name: &str) -> Option<(&str, u32)> {
        super::parse_iteration(name)
    }

    /// Forwarding wrapper for `super::base_stage_name`.
    pub fn base_stage_name(name: &SmolStr) -> SmolStr {
        super::base_stage_name(name)
    }

    /// Forwarding wrapper for `super::iteration_of`.
    pub fn iteration_of(name: &SmolStr) -> u32 {
        super::iteration_of(name)
    }
}

#[cfg(test)]
mod bound_tests {
    use kata_types::bound::Bound;

    use super::{LoopSpend, loop_bounds_trip};

    /// The loop token bound, pure: strictly-greater over the recorded total, and
    /// CLOSED on an uncounted member whatever the total — the other kinds untouched.
    #[test]
    fn a_loop_token_bound_trips_past_its_limit_and_closed_on_an_uncounted_member() {
        let bounds = [Bound::Tokens { tokens: 100 }];
        let spend = |tokens, unknown: Option<&str>| LoopSpend {
            tokens,
            tokens_unknown: unknown.map(str::to_owned),
            ..LoopSpend::default()
        };
        assert_eq!(loop_bounds_trip(&bounds, &spend(100, None), None, 0), None);
        assert_eq!(
            loop_bounds_trip(&bounds, &spend(101, None), None, 0).as_deref(),
            Some("loop token bound exceeded: 101 > 100 tokens")
        );
        assert!(
            loop_bounds_trip(&bounds, &spend(0, Some("w")), None, 0).is_some_and(
                |trip| trip.starts_with("loop token bound unenforceable: member \"w\"")
            ),
        );
        assert_eq!(
            loop_bounds_trip(
                &[Bound::Cost { micro_usd: 5 }],
                &spend(0, Some("w")),
                None,
                0
            ),
            None,
            "an uncounted member trips only a TOKEN bound"
        );
    }

    /// `LoopSpend::charge` reads a record the way the workflow-scope fold does: a
    /// completion's usage adds its cost and every token class; a failure-class
    /// terminal's `Unavailable` charge adds no number and marks the tokens UNKNOWN,
    /// naming the member; a shell completion (no `token_usage`) adds a known `0`.
    #[test]
    fn a_member_record_charges_its_known_spend_and_marks_an_unknown_one() {
        use kata_types::metering::{MeteredCost, StageUsage, TerminalCharge};
        let mut spend = LoopSpend::default();
        spend.charge("sh", &serde_json::json!({"content": "ok"}));
        assert_eq!(
            spend,
            LoopSpend::default(),
            "a shell completion is a known 0"
        );
        let usage = StageUsage::metered(
            &kata_types::cache::TokenUsage {
                input: 50,
                output: 20,
                cache_read: 40,
                cache_write: 0,
            },
            MeteredCost::Authoritative { micro_usd: 600 },
            0,
        );
        spend.charge("w", &TerminalCharge::of_usage(usage).envelope());
        assert_eq!((spend.micro_usd, spend.tokens), (600, 110));
        assert_eq!(spend.tokens_unknown, None);
        assert_eq!(spend.cost_unknown, None);
        let lost = TerminalCharge::of_usage(StageUsage::unmetered("nanocode_openai", "m"));
        spend.charge("g", &lost.envelope());
        assert_eq!(
            (spend.micro_usd, spend.tokens),
            (600, 110),
            "an unknown adds no number"
        );
        assert_eq!(spend.tokens_unknown.as_deref(), Some("g"));
        assert_eq!(
            spend.cost_unknown.as_deref(),
            Some("g"),
            "an Unavailable cost is kept as unknown, never read as a known 0"
        );
    }

    /// **A loop `cost_bound` trips CLOSED on a member of unknown cost**, whatever the
    /// known total — and only a cost bound: a known-cost member over the limit trips it
    /// as before, an unknown-cost member under no cost bound trips nothing.
    ///
    /// **Would red if:** the loop cost bound compared only the sum of known costs (the
    /// unknown member's `None` leaves a 0 total under the limit).
    #[test]
    fn a_loop_cost_bound_trips_closed_on_a_member_of_unknown_cost() {
        let cost = [Bound::Cost { micro_usd: 500 }];
        let spend = |micro_usd, unknown: Option<&str>| LoopSpend {
            micro_usd,
            cost_unknown: unknown.map(str::to_owned),
            ..LoopSpend::default()
        };
        assert_eq!(loop_bounds_trip(&cost, &spend(500, None), None, 0), None);
        assert_eq!(
            loop_bounds_trip(&cost, &spend(501, None), None, 0).as_deref(),
            Some("loop cost bound exceeded: 501 > 500 micro-USD")
        );
        assert_eq!(
            loop_bounds_trip(&cost, &spend(0, Some("w")), None, 0).as_deref(),
            Some(
                "loop cost bound unenforceable: member \"w\" recorded no measurable cost \
                 (metering_unavailable)"
            )
        );
        assert_eq!(
            loop_bounds_trip(
                &[Bound::Tokens { tokens: 100 }],
                &spend(0, Some("w")),
                None,
                0
            ),
            None,
            "a member of unknown COST trips only a cost bound"
        );
    }
}
