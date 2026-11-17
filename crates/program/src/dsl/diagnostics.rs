//! Load-time DSL diagnostics — collect-all + kwarg "did you mean" suggestions.
//!
//! An agent author who mistypes a `stage()` / `workflow()` keyword should get
//! ONE round-trip to a working file, not error-whack-a-mole. Two mechanisms
//! deliver that:
//!
//! * **Suggestions.** `stage()` / `workflow()` each carry a `**kwargs` catch-all
//!   (see [`super::graph_globals`]). Any keyword the typed signature does not
//!   name lands there instead of aborting the call with starlark-rust's bare
//!   `Found \`x\` extra named parameter(s)`. This module turns each stray keyword
//!   into a nearest-known-keyword suggestion (a curated alias table for the
//!   common semantic slips — `model` → `model_hint`, `stages` → `root` — then an
//!   edit-distance / prefix fallback for typos) and appends the full accepted
//!   keyword menu.
//!
//! * **Collect-all.** Because the catch-all does NOT fail the call, evaluation
//!   continues past a bad `stage()` and reaches later `stage()` / `workflow()`
//!   calls, each recording its own diagnostics into a thread-local sink. The
//!   evaluator drains the sink after `eval_module` and fails the load with the
//!   FULL list rather than first-error-wins. A hard error (a syntax error, or a
//!   different runtime failure that stops evaluation) still bounds what can be
//!   collected — the evaluator surfaces whatever was gathered before the stop.
//!
//! The sink is a `thread_local!` for the same reason the graph builder is (see
//! [`super::builder`]): evaluation runs on a dedicated worker thread, one file
//! at a time. [`reset`] clears it before each evaluation; the load-isolation
//! guard snapshots/restores it around nested `load()`s.

use std::cell::RefCell;
use std::fmt::Write as _;

use starlark::collections::SmallMap;
use starlark::values::Value;

use kata_types::source::SourceSpan;

/// A collected diagnostic paired with its call-site [`SourceSpan`]
/// (the `pack.star:LINE:COL` origin of the offending `stage()` / `workflow()`
/// call), when the evaluator could resolve one. `span == None` renders with no
/// location prefix, so a diagnostic collected
/// without a resolvable call site degrades cleanly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SpannedDiagnostic {
    pub(crate) span: Option<SourceSpan>,
    pub(crate) diag: DslDiagnostic,
}

/// One collected load-time definition diagnostic from a `stage()` / `workflow()`
/// call. Recorded (never thrown) so [collect-all](self) can gather every
/// reachable slip in one pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DslDiagnostic {
    /// A keyword the builtin's typed signature does not name.
    UnknownKwarg {
        /// The builtin the stray keyword was passed to (`"stage"` / `"workflow"`).
        func: &'static str,
        /// The keyword the author wrote.
        key: String,
        /// The nearest accepted keyword, when one is close enough to suggest.
        suggestion: Option<&'static str>,
    },
    /// `workflow()`'s name was passed by keyword, or omitted — it is the first
    /// POSITIONAL argument.
    WorkflowName {
        /// `true` when the author wrote `workflow(name=..)` (name given as a
        /// keyword); `false` when the positional name was omitted entirely.
        given_as_kwarg: bool,
    },
    /// `workflow()` was called with no `root=` and no mis-named keyword standing
    /// in for it — the entry stage(s) were simply omitted.
    MissingRoot,
    /// `workflow()`'s name was supplied BOTH positionally and as a redundant
    /// `name=` keyword (`workflow("w", name="x")`). The catch-all would otherwise
    /// silently drop the keyword, so it is recorded here instead of being
    /// swallowed.
    DuplicateWorkflowName,
}

/// The accepted named keywords of `stage()`, sorted. Kept in lockstep with the
/// `#[starlark_module] fn stage` signature by
/// [`tests::stage_kwargs_match_signature`] (fail-closed against drift).
pub(crate) const STAGE_KWARGS: &[&str] = &[
    "agent",
    "allowed_tools",
    "approval",
    "approval_reason",
    "body",
    "cache_policy",
    "consumes",
    "cost_budget",
    "depends_on",
    "execution_requirements",
    "exit_policy",
    "id",
    "label",
    "model_hint",
    "op",
    "output_bytes",
    "outputs",
    "produces",
    "produces_files",
    "progress_visibility",
    "prompt",
    "reads",
    "required_capabilities",
    "run",
    "sandbox",
    "timeout_ms",
    "title",
    "topology",
    "validate_feedback_template",
    "validate_retries",
    "work_delta_bytes",
    "work_delta_entries",
];

/// The accepted named keywords of `workflow()`, sorted. Excludes the leading
/// `name`, which is positional. Kept in lockstep with the
/// `#[starlark_module] fn workflow` signature by
/// [`tests::workflow_kwargs_match_signature`] (fail-closed against drift).
pub(crate) const WORKFLOW_KWARGS: &[&str] = &[
    "bounds",
    "cost_budget",
    "description",
    "external_input_channels",
    "human_requests",
    "max_concurrency",
    "max_external_input_channels",
    "max_human_requests",
    "max_memory_selectors",
    "max_memory_writebacks",
    "memory_selectors",
    "memory_writebacks",
    "params",
    "root",
    "sandbox_profiles",
    "tags",
    "validation_criteria",
    "version",
    "workflow_pattern",
    "worktree_isolated",
];

/// Curated aliases for the common SEMANTIC slips whose correct keyword is not
/// lexically close (edit distance alone would miss them). Consulted before the
/// distance fallback. Covers observed authoring stumbles plus a few obvious
/// synonyms.
fn stage_alias(key: &str) -> Option<&'static str> {
    match key {
        "model" | "model_name" | "llm" => Some("model_hint"),
        "tools" => Some("allowed_tools"),
        "capabilities" | "caps" => Some("required_capabilities"),
        "deps" | "depends" | "after" | "needs" => Some("depends_on"),
        "command" | "cmd" | "shell" => Some("run"),
        "timeout" => Some("timeout_ms"),
        "execution_class" | "exec_class" | "class" | "requires" => Some("execution_requirements"),
        _ => None,
    }
}

/// Curated `workflow()` aliases — see [`stage_alias`].
fn workflow_alias(key: &str) -> Option<&'static str> {
    match key {
        "stages" | "nodes" | "steps" | "graph" | "entry" | "start" | "roots" => Some("root"),
        "desc" => Some("description"),
        _ => None,
    }
}

/// The nearest accepted keyword to `key`, or `None` when nothing is close.
///
/// Order: curated alias → prefix relationship → bounded edit distance. The
/// prefix rule catches a typed *prefix* of the real keyword (`model` →
/// `model_hint`), which a raw Levenshtein threshold rejects as too distant.
fn suggest(func: &str, key: &str, accepted: &'static [&'static str]) -> Option<&'static str> {
    let alias = match func {
        "stage" => stage_alias(key),
        "workflow" => workflow_alias(key),
        _ => None,
    };
    if let Some(alias) = alias {
        return Some(alias);
    }

    // Prefix relationship (either direction), min length 3 so a one/two-char
    // stub does not latch onto an unrelated keyword. Pick the shortest match for
    // determinism.
    if key.len() >= 3 {
        let prefix = accepted
            .iter()
            .filter(|cand| cand.starts_with(key) || key.starts_with(**cand))
            .min_by_key(|cand| (cand.len(), **cand));
        if let Some(cand) = prefix {
            return Some(cand);
        }
    }

    // Bounded edit distance. Threshold scales with the keyword length so short
    // keywords need a tighter match. Ties broken lexicographically.
    let threshold = (key.len() / 2).max(2);
    accepted
        .iter()
        .map(|cand| (levenshtein(key, cand), *cand))
        .filter(|(dist, _)| *dist <= threshold)
        .min_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)))
        .map(|(_, cand)| cand)
}

/// Classic O(m·n) Levenshtein edit distance over `char`s (keyword identifiers
/// are ASCII, but `char` iteration is correct regardless).
fn levenshtein(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut cur = vec![0usize; b_chars.len() + 1];
    for (i, ca) in a.chars().enumerate() {
        cur[0] = i + 1;
        for (j, &cb) in b_chars.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b_chars.len()]
}

thread_local! {
    /// Per-evaluation diagnostics sink. Cleared by [`reset`] before each
    /// evaluation and drained by [`take`] after it.
    static DIAGNOSTICS: RefCell<Vec<SpannedDiagnostic>> = const { RefCell::new(Vec::new()) };
}

/// Record one diagnostic into the per-evaluation sink, carrying its optional
/// call-site [`SourceSpan`].
pub(crate) fn record(span: Option<SourceSpan>, diag: DslDiagnostic) {
    DIAGNOSTICS.with(|cell| cell.borrow_mut().push(SpannedDiagnostic { span, diag }));
}

/// Clear the sink before an evaluation (mirrors
/// [`super::builder::reset_workflow_builder`]).
pub(crate) fn reset() {
    DIAGNOSTICS.with(|cell| cell.borrow_mut().clear());
}

/// Drain and return every diagnostic collected during an evaluation.
pub(crate) fn take() -> Vec<SpannedDiagnostic> {
    DIAGNOSTICS.with(|cell| std::mem::take(&mut *cell.borrow_mut()))
}

/// Snapshot-and-clear the sink for the duration of a nested `load()` evaluation
/// (mirrors [`super::builder::isolate_for_load`]). Returns the importer's
/// diagnostics so the guard can restore them, discarding anything the loaded
/// module recorded.
pub(crate) fn snapshot_and_clear() -> Vec<SpannedDiagnostic> {
    take()
}

/// Restore a [`snapshot_and_clear`] snapshot, dropping whatever accumulated
/// since.
pub(crate) fn restore(saved: Vec<SpannedDiagnostic>) {
    DIAGNOSTICS.with(|cell| *cell.borrow_mut() = saved);
}

/// Record a nearest-known suggestion for every keyword in `extra` that the
/// typed signature of `func` did not consume. Does NOT fail — evaluation
/// continues so [collect-all](self) reaches later calls. Keys are processed in
/// sorted order so the rendered report is deterministic regardless of the
/// author's keyword order in the source.
pub(crate) fn diagnose_unknown_kwargs(
    func: &'static str,
    accepted: &'static [&'static str],
    extra: &SmallMap<String, Value<'_>>,
    span: Option<SourceSpan>,
) {
    let mut keys: Vec<&String> = extra.keys().collect();
    keys.sort();
    for key in keys {
        record(
            span.clone(),
            DslDiagnostic::UnknownKwarg {
                func,
                key: key.clone(),
                suggestion: suggest(func, key, accepted),
            },
        );
    }
}

/// The sorted accepted-keyword menu for a builtin, or `None` if unknown.
fn accepted_for(func: &str) -> Option<&'static [&'static str]> {
    match func {
        "stage" => Some(STAGE_KWARGS),
        "workflow" => Some(WORKFLOW_KWARGS),
        _ => None,
    }
}

/// Render the collected diagnostics into one actionable report. Deterministic:
/// diagnostics render in record (source) order; the accepted-keyword menu is
/// appended once per builtin that produced an unknown-keyword diagnostic, in
/// `stage` → `workflow` order.
pub(crate) fn render_report(diags: &[SpannedDiagnostic]) -> String {
    let n = diags.len();
    let mut out = String::new();
    if n == 1 {
        out.push_str("kata workflow DSL: 1 definition error found — fix it, then re-check:\n");
    } else {
        writeln!(
            out,
            "kata workflow DSL: {n} definition errors found — fix all of them, then re-check:"
        )
        .expect("writing to String cannot fail");
    }

    for sd in diags {
        // The `pack.star:LINE:COL` origin prefix, when known. Empty
        // (no separator) when the call site could not be resolved, so a
        // span-less diagnostic renders with no location prefix.
        let loc = sd
            .span
            .as_ref()
            .map(|span| format!("{span}: "))
            .unwrap_or_default();
        match &sd.diag {
            DslDiagnostic::UnknownKwarg {
                func,
                key,
                suggestion,
            } => match suggestion {
                Some(sug) => writeln!(
                    out,
                    "  {loc}✗ {func}() got an unknown keyword `{key}`; did you mean `{sug}`?"
                )
                .expect("writing to String cannot fail"),
                None => writeln!(
                    out,
                    "  {loc}✗ {func}() got an unknown keyword `{key}` (no close match — see the accepted keywords below)"
                )
                .expect("writing to String cannot fail"),
            },
            DslDiagnostic::WorkflowName { given_as_kwarg } => {
                if *given_as_kwarg {
                    writeln!(
                        out,
                        "  {loc}✗ workflow()'s name is the first POSITIONAL argument, not a keyword — \
                         write workflow(\"my-workflow\", root=...)",
                    )
                    .expect("writing to String cannot fail");
                } else {
                    writeln!(
                        out,
                        "  {loc}✗ workflow() is missing its name — it is the first POSITIONAL argument — \
                         write workflow(\"my-workflow\", root=...)",
                    )
                    .expect("writing to String cannot fail");
                }
            }
            DslDiagnostic::MissingRoot => {
                writeln!(
                    out,
                    "  {loc}✗ workflow() is missing its required root= — name the entry stage(s), \
                     e.g. workflow(\"my-workflow\", root=last_stage)",
                )
                .expect("writing to String cannot fail");
            }
            DslDiagnostic::DuplicateWorkflowName => {
                writeln!(
                    out,
                    "  {loc}✗ workflow() got its name both positionally and as a `name=` keyword — \
                     drop the name= keyword; the first positional argument is the name",
                )
                .expect("writing to String cannot fail");
            }
        }
    }

    // Append the accepted-keyword menu for each builtin that produced an
    // unknown-keyword diagnostic, in a stable builtin order.
    for func in ["stage", "workflow"] {
        let had_unknown = diags
            .iter()
            .any(|d| matches!(&d.diag, DslDiagnostic::UnknownKwarg { func: f, .. } if *f == func));
        if had_unknown && let Some(accepted) = accepted_for(func) {
            writeln!(out, "accepted {func}() keywords: {}", accepted.join(", "))
                .expect("writing to String cannot fail");
            if func == "workflow" {
                out.push_str(
                    "  (plus the workflow name as the first positional argument: workflow(\"name\", root=...))\n",
                );
            }
        }
    }

    // Drop the trailing newline so callers control the surrounding framing.
    out.pop();
    out
}

#[cfg(test)]
#[path = "diagnostics_tests.rs"]
mod tests;
