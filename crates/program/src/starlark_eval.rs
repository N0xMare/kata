//! Starlark workflow evaluator.
//!
//! Evaluates `.star` files using `starlark-rust` and converts the result
//! into a typed `WorkflowDefinition`. The evaluator is sandboxed: no
//! filesystem access, no network, and no `load()` imports unless the
//! caller explicitly supplies whitelisted library roots.
//!
//! kata has a single Starlark frontend: the `.star` module must
//! construct its workflow with the native graph DSL — `stage(...)` builtins
//! plus a `workflow(...)` / `sequence(...)` / `loop(...)` call **at module
//! scope**. That call drains the thread-local graph builder into a typed
//! `WorkflowDefinition`, which is lowered DIRECTLY (no dict, no `to_json`
//! round-trip) through the shared `validate` + `from_parts` checked path and
//! returned as a `CheckedWorkflowDefinition` that compiles through the shared
//! `ExecutionProgram` path. A module that evaluates without ever calling
//! `workflow()`/`sequence()`/`loop()` at module scope produces no execution
//! program and is a hard error. Only the typed graph builder is recognized as
//! workflow output; a returned raw dictionary is not executable syntax.
//!
//! # DoS resource limit
//!
//! Workflow authors can accidentally (or maliciously) write Starlark that
//! blocks indefinitely or exhausts memory, e.g. `list(range(1_000_000_000))`
//! or a runaway `while` loop. To bound that, evaluation installs
//! starlark-rust's before-statement hook with a statement budget and wall-clock
//! guard, and also runs on a dedicated OS thread with an outer wall-clock
//! deadline of [`STARLARK_EVAL_BUDGET`]. The in-evaluator hook is the normal
//! cancellation path; the outer watchdog remains a last-resort guard around
//! native work that does not yield statements. The hook is ONE budget
//! ([`StarlarkEvalBudget`]) installed on the top-level evaluator and on the
//! evaluator of every module a `load()` evaluates, at any depth, so a loaded
//! helper spends the importer's statements and wall clock.
//!
//! # Cooperative cancel — no orphan-on-timeout
//!
//! Once a long-lived engine compiles many packs (inline authoring), a
//! timed-out eval must not leak its OS thread. The coordinating thread shares an
//! `AtomicBool` cancel flag with the in-evaluator before-statement hook: when the
//! outer deadline fires, the coordinator sets the flag and hands the worker's
//! `JoinHandle` to a bounded reaper thread that joins it, so the OS thread is
//! reclaimed instead of detached. The hook observes the flag at its next
//! statement — in the importing file or in any module it `load()`s — so any
//! eval that executes Starlark statements (the realistic runaway) is reaped
//! promptly. A single non-yielding native call remains
//! unreapable at starlark-rust 0.13 — the reaper stays blocked until that call
//! returns — but that is O(1) per stuck eval, not a per-compile leak as a
//! detach-on-timeout path would accumulate.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use kata_types::sandbox::{SandboxProfile, SandboxRef};
use kata_types::workflow::{
    WorkflowDefinition, WorkflowFrontendProvenance, WorkflowSourceFormat, workflow_source_hash,
};
use kata_types::{ContentHash, KataError, KataResult};
use starlark::codemap::FileSpanRef;
use starlark::environment::{GlobalsBuilder, Module};
use starlark::eval::{BeforeStmtFuncDyn, Evaluator};
use starlark::syntax::{AstModule, Dialect};

use crate::library::WhitelistedFileLoader;
use crate::parser::CheckedWorkflowDefinition;

/// Maximum wall-clock duration a single `.star` workflow file is allowed
/// to evaluate. See the module-level "DoS resource limit" section for
/// the rationale. Ten seconds is generous for legitimate workflows and
/// short enough to fail fast on runaway loops.
pub const STARLARK_EVAL_BUDGET: Duration = Duration::from_secs(10);
const STARLARK_EVAL_MAX_STATEMENTS: u64 = 200_000;

/// Distinct, stable sentinel embedded in the [`KataError::Internal`] returned
/// when the Starlark eval WORKER thread panics.
///
/// The frontend parse+eval (`AstModule::parse` + `Evaluator`) — the hostile-byte
/// attack surface the frontend fuzz guards — runs on the spawned worker thread. The
/// workspace compiles `panic = "unwind"`, so a genuine `panic!`/`unwrap` inside
/// starlark-rust or [`evaluate_starlark_inner`] would otherwise unwind ONLY the
/// worker, drop the mpsc sender, and surface as a generic
/// `RecvTimeoutError::Disconnected` → [`KataError::Internal`] — indistinguishable
/// from any other worker death and silently discardable. Catching the unwind
/// inside the worker and tagging the error with this sentinel turns a frontend
/// panic into a SURFACED, identifiable signal in BOTH production and the fuzz.
pub(crate) const STARLARK_WORKER_PANIC_SENTINEL: &str =
    "starlark eval worker panicked on the parse/eval frontend attack surface";

/// Bounds enforced on a single `.star` evaluation.
#[derive(Clone, Copy)]
struct StarlarkEvalBounds {
    /// Outer wall-clock deadline: when the coordinating thread stops waiting,
    /// cooperatively cancels the worker, and returns a timeout error.
    outer_deadline: Duration,
    /// In-evaluator wall-clock backstop, checked at each statement — a last-resort
    /// guard for native work that ignores the cooperative-cancel flag.
    inner_backstop: Duration,
    /// Per-evaluation statement budget.
    statement_budget: u64,
}

impl StarlarkEvalBounds {
    /// Production shape: a single `budget` serves as both the outer deadline and
    /// the inner backstop, with the default statement budget.
    fn uniform(budget: Duration) -> Self {
        Self {
            outer_deadline: budget,
            inner_backstop: budget,
            statement_budget: STARLARK_EVAL_MAX_STATEMENTS,
        }
    }
}

/// ONE evaluation's budget — the statement count, the in-evaluator wall-clock
/// backstop and the coordinator's cancel flag — shared by the top-level module's
/// evaluator and the evaluator of every module it `load()`s, at any depth
/// ([`WhitelistedFileLoader`] installs it on each). A loaded helper therefore
/// spends the importer's statements and observes its cancel: there is no
/// unbudgeted evaluator in an evaluation.
pub(crate) struct StarlarkEvalBudget {
    /// The top-level file, named in every refusal.
    filename: String,
    started: Instant,
    wall_budget: Duration,
    statement_budget: u64,
    statements_remaining: AtomicU64,
    /// Set by the coordinating thread when the outer deadline fires; observed
    /// at the next statement of ANY module of the evaluation, so a runaway is
    /// cancelled and reaped instead of orphaned.
    cancel: Arc<AtomicBool>,
}

impl StarlarkEvalBudget {
    fn new(filename: &str, bounds: StarlarkEvalBounds, cancel: Arc<AtomicBool>) -> Self {
        Self {
            filename: filename.to_owned(),
            started: Instant::now(),
            wall_budget: bounds.inner_backstop,
            statement_budget: bounds.statement_budget,
            statements_remaining: AtomicU64::new(bounds.statement_budget),
            cancel,
        }
    }

    /// Charge this budget for every statement `eval` executes.
    pub(crate) fn install<'a, 'e: 'a>(self: &Arc<Self>, eval: &mut Evaluator<'_, 'a, 'e>) {
        eval.before_stmt_for_dap(
            (Box::new(StarlarkEvalLimiter(Arc::clone(self))) as Box<dyn BeforeStmtFuncDyn<'a, 'e>>)
                .into(),
        );
    }

    fn charge_statement(&self) -> starlark::Result<()> {
        if self.cancel.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!(
                "Starlark evaluation of {} was cancelled after the coordinating timeout",
                self.filename
            )
            .into());
        }
        if self.started.elapsed() > self.wall_budget {
            return Err(anyhow::anyhow!(
                "Starlark evaluation of {} exceeded the {:?} budget",
                self.filename,
                self.wall_budget
            )
            .into());
        }
        if self
            .statements_remaining
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |r| r.checked_sub(1))
            .is_err()
        {
            return Err(anyhow::anyhow!(
                "Starlark evaluation of {} exceeded the {} statement budget",
                self.filename,
                self.statement_budget
            )
            .into());
        }
        Ok(())
    }

    /// A budget no test evaluation can reach, for cells that drive
    /// [`WhitelistedFileLoader`] directly rather than through an evaluation.
    #[cfg(test)]
    pub(crate) fn unreachable_for_tests() -> Arc<Self> {
        Arc::new(Self::new(
            "test",
            StarlarkEvalBounds::uniform(Duration::from_secs(3600)),
            Arc::new(AtomicBool::new(false)),
        ))
    }
}

struct StarlarkEvalLimiter(Arc<StarlarkEvalBudget>);

impl<'a, 'e: 'a> BeforeStmtFuncDyn<'a, 'e> for StarlarkEvalLimiter {
    fn call<'v>(
        &mut self,
        _span: FileSpanRef,
        _eval: &mut Evaluator<'v, 'a, 'e>,
    ) -> starlark::Result<()> {
        self.0.charge_statement()
    }
}

/// Evaluate a Starlark source string and extract a checked workflow definition.
///
/// Evaluation runs on a dedicated OS thread with a
/// [`STARLARK_EVAL_BUDGET`] wall-clock deadline. If the thread does not
/// report a result within the budget, this function returns
/// `KataError::Validation` describing the timeout.
///
/// On timeout the worker thread is cooperatively cancelled and reaped rather
/// than orphaned: the coordinator sets a shared cancel flag (observed by the
/// in-evaluator before-statement hook at its next statement) and hands the
/// `JoinHandle` to a bounded reaper that joins it. See the module-level
/// "Cooperative cancel" section. The starlark-rust 0.13 crate offers no
/// hook to interrupt a single non-yielding native call, so such a call keeps the
/// reaper blocked until it returns — bounded per stuck eval, not per compile.
pub(crate) fn evaluate_starlark_checked(
    source: &str,
    filename: &str,
) -> KataResult<CheckedWorkflowDefinition> {
    evaluate_starlark_checked_with(
        source,
        filename,
        StarlarkEvalBounds::uniform(STARLARK_EVAL_BUDGET),
        &[],
    )
}

/// Same as [`evaluate_starlark_checked`] but permits `load()` statements that
/// resolve against a caller-supplied list of canonical roots. Paths
/// outside the whitelist are rejected; see
/// [`WhitelistedFileLoader`](crate::library::WhitelistedFileLoader) for
/// the exact rules.
///
/// Used by [`crate::parser::from_file_with_library_checked`] when the caller has configured
/// a workflow library, so `.star` files shipped in the stdlib can
/// pull shared helpers from sibling files.
pub(crate) fn evaluate_starlark_with_loader_checked(
    source: &str,
    filename: &str,
    loader_roots: &[PathBuf],
) -> KataResult<CheckedWorkflowDefinition> {
    evaluate_starlark_checked_with(
        source,
        filename,
        StarlarkEvalBounds::uniform(STARLARK_EVAL_BUDGET),
        loader_roots,
    )
}

/// Internal entry point with caller-specified evaluation bounds. Runs the
/// evaluation on a dedicated OS thread and coordinates the outer deadline with a
/// cooperative-cancel + reaper so a timed-out eval is reclaimed, never orphaned.
/// Tests pin the bounds to small values to exercise the timeout path
/// without stalling the suite.
fn evaluate_starlark_checked_with(
    source: &str,
    filename: &str,
    bounds: StarlarkEvalBounds,
    loader_roots: &[PathBuf],
) -> KataResult<CheckedWorkflowDefinition> {
    // Move owned copies into the worker thread so the closure is 'static.
    let source_owned = source.to_owned();
    let filename_owned = filename.to_owned();
    let roots_owned: Vec<PathBuf> = loader_roots.to_vec();

    // Shared cancel flag: the coordinator sets it on the outer deadline; the
    // in-evaluator before-statement hook observes it and aborts.
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_worker = Arc::clone(&cancel);

    let (tx, rx) = mpsc::channel::<KataResult<CheckedWorkflowDefinition>>();

    // Give the thread a descriptive name so `thread_name` fields in panic
    // backtraces and ps output make the source obvious.
    let builder = thread::Builder::new().name(format!("starlark-eval:{filename}"));
    let handle: JoinHandle<()> = builder
        .spawn(move || {
            // Catch a panic on the Starlark parse+eval frontend (the hostile-byte
            // attack surface). `Evaluator` and the mpsc sender are not
            // `UnwindSafe`, so we assert unwind-safety: the caught unwind is
            // converted immediately into a value and nothing observed after the
            // unwind is reused across the boundary. Without this, a frontend panic
            // would drop `tx` and surface as an untyped channel `Disconnected` —
            // silently swallowed by the fuzz. With it, the panic becomes the
            // distinct [`STARLARK_WORKER_PANIC_SENTINEL`] error, surfaced in
            // production and asserted-against in the frontend fuzz. The worker still
            // returns from its closure and is joined/reaped normally, so this does
            // not reintroduce an orphan-on-timeout leak.
            let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                evaluate_starlark_inner(
                    &source_owned,
                    &filename_owned,
                    bounds,
                    &roots_owned,
                    &cancel_worker,
                )
            })) {
                Ok(result) => result,
                Err(payload) => Err(KataError::Internal(format!(
                    "{STARLARK_WORKER_PANIC_SENTINEL}: {filename_owned}: {}",
                    panic_payload_detail(&payload)
                ))),
            };
            // The receiver may have already timed out and dropped the rx
            // end; if so, we silently discard the result.
            let _ = tx.send(result);
        })
        .map_err(|e| {
            KataError::Internal(format!(
                "failed to spawn starlark worker thread for {filename}: {e}"
            ))
        })?;

    match rx.recv_timeout(bounds.outer_deadline) {
        // Worker reported on its own; join to reclaim its OS thread (it is already
        // returning from its closure, so this does not block).
        Ok(result) => {
            let _ = handle.join();
            result
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Cooperative cancel + reap: signal the in-evaluator hook to abort at
            // the next statement, then hand the JoinHandle to a bounded reaper so
            // the OS thread is reclaimed instead of detached/orphaned.
            cancel.store(true, Ordering::SeqCst);
            reap_worker(handle, filename);
            Err(KataError::Validation(format!(
                "Starlark evaluation of {filename} exceeded the {:?} budget; \
                 possible infinite loop or oversized computation",
                bounds.outer_deadline
            )))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // Worker panicked/exited before sending; join to observe + reclaim it.
            let _ = handle.join();
            Err(KataError::Internal(format!(
                "starlark worker thread for {filename} exited without sending a result"
            )))
        }
    }
}

/// Reap a timed-out worker on a bounded background reaper thread. The
/// cooperative-cancel flag has already been set, so a statement-yielding eval
/// stops at its next statement and the reaper's `join()` returns promptly. This
/// keeps the coordinating caller non-blocking while still reclaiming (not
/// detaching) the worker's OS thread.
fn reap_worker(handle: JoinHandle<()>, filename: &str) {
    let name = format!("starlark-reap:{filename}");
    // If the reaper spawn fails (resource pressure), `spawn` consumes and drops
    // the closure — and with it `handle` — detaching the worker. The cancel flag
    // was already set, so a statement-yielding worker still self-terminates at its
    // next statement: a best-effort fallback, not the normal path.
    let _ = thread::Builder::new().name(name).spawn(move || {
        let _ = handle.join();
    });
}

/// Extract a human-readable detail string from a caught panic payload. Rust panic
/// payloads are `&str` or `String` for `panic!`/`unwrap`/`assert!`; anything else
/// is opaque. Used only to enrich [`STARLARK_WORKER_PANIC_SENTINEL`] so a surfaced
/// frontend panic carries its message.
fn panic_payload_detail(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "opaque (non-string) panic payload".to_string()
    }
}

/// Test-only fault injection: a sentinel source string makes the WORKER-thread
/// parse/eval path panic, so the panic regression can prove a genuine frontend
/// panic is SURFACED (caught → [`STARLARK_WORKER_PANIC_SENTINEL`]) rather than
/// swallowed into a channel disconnect. Gated to test builds; in production this
/// is an inlined no-op and the sentinel const does not exist, so no production
/// caller can reach the injection.
#[cfg(test)]
pub(crate) const STARLARK_EVAL_PANIC_INJECT_SENTINEL: &str =
    "__KATA_TEST_PANIC_IN_STARLARK_WORKER__";

#[cfg(test)]
fn maybe_inject_worker_panic(source: &str) {
    // Deliberate fault injection: the sentinel source PANICS the worker so the
    // panic regression exercises the catch → surfaced-error path. (`assert!` on
    // the negated predicate is the clippy-preferred spelling of if-then-`panic!`.)
    assert!(
        !source.contains(STARLARK_EVAL_PANIC_INJECT_SENTINEL),
        "injected worker-thread frontend panic (test fault injection)"
    );
}

#[cfg(not(test))]
#[inline(always)]
fn maybe_inject_worker_panic(_source: &str) {}

/// Test shim for callers that want to pin a single wall-clock budget directly.
#[cfg(test)]
#[doc(hidden)]
fn evaluate_starlark_checked_with_budget_for_tests(
    source: &str,
    filename: &str,
    budget: Duration,
) -> KataResult<CheckedWorkflowDefinition> {
    evaluate_starlark_checked_with(source, filename, StarlarkEvalBounds::uniform(budget), &[])
}

/// Test shim exercising the cooperative-cancel/reaper path: a SHORT outer
/// deadline against a FAR inner backstop + large statement budget, so only the
/// cooperative cancel (fired at the outer deadline) can stop a statement-yielding
/// runaway. Lets a test assert the worker OS thread is reclaimed at the outer
/// deadline rather than lingering to the backstop.
#[cfg(test)]
#[doc(hidden)]
fn evaluate_starlark_reap_probe_for_tests(
    source: &str,
    filename: &str,
    outer_deadline: Duration,
    inner_backstop: Duration,
    statement_budget: u64,
    loader_roots: &[PathBuf],
) -> KataResult<CheckedWorkflowDefinition> {
    evaluate_starlark_checked_with(
        source,
        filename,
        StarlarkEvalBounds {
            outer_deadline,
            inner_backstop,
            statement_budget,
        },
        loader_roots,
    )
}

/// Core Starlark evaluation. Runs synchronously on the eval worker thread;
/// [`evaluate_starlark_checked_with`] is the time-bounded coordinator that
/// spawns, cancels and reaps it.
///
/// 1. Parses the source into an AST with `Dialect::Standard`.
/// 2. Evaluates the module under one [`StarlarkEvalBudget`] — installed on every
///    `load()`ed module's evaluator too — so the module-scope
///    `workflow()`/`sequence()`/`loop()` call drains the typed graph builder.
/// 3. Takes the drained `(WorkflowDefinition, extensions)` and checks it through
///    [`CheckedWorkflowDefinition::from_parts`] — no dict, no `to_json`.
fn evaluate_starlark_inner(
    source: &str,
    filename: &str,
    bounds: StarlarkEvalBounds,
    loader_roots: &[PathBuf],
    cancel: &Arc<AtomicBool>,
) -> KataResult<CheckedWorkflowDefinition> {
    // Test-only fault injection on the WORKER thread's frontend path. No-op in
    // production (see `maybe_inject_worker_panic`). This runs INSIDE the worker's
    // `catch_unwind`, so the injected panic exercises the exact
    // catch → sentinel-error surfacing the panic regression asserts.
    maybe_inject_worker_panic(source);

    // 1. Parse source into AST.
    let ast = AstModule::parse(filename, source.to_owned(), &Dialect::Standard)
        .map_err(|e| KataError::Validation(format!("Starlark parse error in {filename}: {e}")))?;

    // 2. Create sandboxed globals — standard library plus kata's native
    //    contract-DSL and graph-DSL builtins (`contract`/`field`/`enum`/
    //    `list_of`/`variant`, `stage`/`workflow`/`sequence`/`loop`,
    //    `cost_budget`, ...), no filesystem/network. These builtins
    //    are the single frontend: every pack assembles its workflow by calling
    //    them and draining a module-scope `workflow()`/`sequence()`/`loop()`.
    let globals = Arc::new(
        GlobalsBuilder::standard()
            .with(crate::dsl::kata_contract_globals)
            .with(crate::dsl::kata_graph_globals)
            .build(),
    );

    // Clear any workflow-graph state left over from a previous evaluation on
    // this (possibly reused) worker thread before `stage()`/`workflow()` can
    // register into it. See `crate::dsl::builder` for why the thread-local is
    // sound on the dedicated eval thread.
    crate::dsl::builder::reset_workflow_builder();
    // Clear the load-time diagnostics sink too, so a reused worker thread
    // never carries a prior evaluation's collected authoring diagnostics.
    crate::dsl::diagnostics::reset();

    // If the caller supplied load() roots, install a whitelisted file
    // loader. The loader rejects any path that escapes the roots after
    // canonicalization. When `loader_roots` is empty we intentionally
    // leave no loader installed so `load()` statements fail with the
    // default starlark error ("load not supported") — this preserves
    // the sandboxed behaviour for callers who don't opt in.
    //
    // The loader must outlive the `Evaluator` because `set_loader`
    // borrows it. We declare it *before* the evaluator so Rust's drop
    // order (reverse declaration order) works in our favour.
    let budget = Arc::new(StarlarkEvalBudget::new(
        filename,
        bounds,
        Arc::clone(cancel),
    ));
    let loader: Option<WhitelistedFileLoader> = if loader_roots.is_empty() {
        None
    } else {
        Some(WhitelistedFileLoader::new(
            loader_roots,
            Arc::clone(&globals),
            Arc::clone(&budget),
        ))
    };

    // 3. Evaluate the module.
    let module = Module::new();
    let mut eval = Evaluator::new(&module);
    budget.install(&mut eval);

    if let Some(loader_ref) = loader.as_ref() {
        eval.set_loader(loader_ref);
    }

    // Evaluating the module runs every top-level statement, including the
    // module-scope `workflow()` / `sequence()` / `loop()` call that drains the
    // thread-local graph builder. We don't inspect the module's return value:
    // kata's single frontend is the native graph DSL, so the assembled workflow
    // lives in the builder, not in a returned dict.
    let eval_result = eval.eval_module(ast, &globals);

    // Collect-all: drain every authoring diagnostic the `stage()` /
    // `workflow()` calls recorded (unknown keywords with "did you mean"
    // suggestions, mis-placed/omitted workflow name/root). These are recorded,
    // not thrown, so a single bad `stage()` does not stop the load at the first
    // error — evaluation reaches later calls and gathers ALL collectible
    // definition errors. When any were collected the load FAILS with the full
    // rendered report, ahead of any downstream "no execution program" / hard
    // error, because a mistyped keyword is the actionable root cause.
    let collected = crate::dsl::diagnostics::take();
    if !collected.is_empty() {
        let report = crate::dsl::diagnostics::render_report(&collected);
        return Err(KataError::Validation(match eval_result {
            Ok(_) => report,
            // A hard error (syntax further on, or a different runtime failure)
            // bounds what could be collected; surface the gathered report AND the
            // stopping error so nothing is silently dropped.
            Err(e) => {
                format!("{report}\n\n(evaluation then stopped before the workflow drained: {e})")
            }
        }));
    }

    eval_result
        .map_err(|e| KataError::Validation(format!("Starlark eval error in {filename}: {e}")))?;

    // Native graph-DSL path. The module-scope `workflow()` /
    // `sequence()` / `loop()` call drained the thread-local builder into a typed
    // `(WorkflowDefinition, extensions)` pair. Lower it DIRECTLY — no dict, no
    // `to_json` round-trip — through the shared `validate` + `from_parts` checked
    // path. If nothing drained the builder, the module never called
    // `workflow()`/`sequence()`/`loop()` at module scope: it produced no
    // execution program. A raw returned dictionary is an authoring error, not a
    // fallback.
    let Some((mut definition, extensions, pack_metadata)) =
        crate::dsl::builder::take_drained_workflow()?
    else {
        return Err(KataError::Validation(format!(
            "Starlark file {filename} produced no execution program: it evaluated \
             without calling workflow(), sequence(), or loop() at module scope. \
             kata has a single native frontend — assemble stages with stage(...) \
             and call workflow(...)/sequence(...)/loop(...) at module scope so the \
             graph builder drains into a workflow."
        )));
    };
    // `validate` + `validate_extensions` run ONCE, inside `from_parts` below —
    // the one chokepoint every construction path funnels through. Provenance
    // attaches first; on an invalid definition it is discarded with the refusal.
    let import_hashes = loader
        .as_ref()
        .map(WhitelistedFileLoader::import_hashes)
        .unwrap_or_default();
    attach_starlark_provenance(&mut definition, source, import_hashes)?;
    // Drain the durable schedules declared by module-scope `schedule(...)`
    // calls in this evaluation, so boot can install them through `ScheduleFace`
    // into `operational.db`'s schedule tables. Drained AFTER a successful
    // workflow drain so a pack's cron registrations ride alongside its workflow
    // definition. `load()`ed helper modules' schedules are isolated (see
    // `builder::isolate_for_load`).
    let schedules = crate::dsl::builder::take_registered_schedules();
    // Attach the drained pack-discovery metadata (description /
    // version / tags / params) so `WorkflowLibrary` / `kata workflows list`
    // can surface it without a second evaluation pass.
    CheckedWorkflowDefinition::from_parts(definition, extensions)
        .map(|checked| checked.with_pack_metadata(pack_metadata))
        .map(|checked| checked.with_schedules(schedules))
}

fn attach_starlark_provenance(
    definition: &mut WorkflowDefinition,
    source: &str,
    import_hashes: BTreeMap<String, ContentHash>,
) -> KataResult<()> {
    definition
        .attach_provenance(
            WorkflowFrontendProvenance {
                format: WorkflowSourceFormat::Starlark,
                source_hash: Some(workflow_source_hash(source.as_bytes())),
                import_hashes,
            },
            crate::parser::workflow_compiler_identity("starlark-rust:0.13"),
        )
        .map_err(|e| {
            KataError::Serialization(format!(
                "failed to hash normalized Starlark workflow definition: {e}"
            ))
        })
}

/// Convert a starlark-emitted JSON value into a [`StageTopology`].
///
/// The native `stage(topology=topology(..))` builtin
/// constructs a `topology` dict and hands its JSON here; this helper applies a
/// `serde_json::from_value` decode into the typed `StageTopology`. Kept as a
/// shared decoder so the `dsl::builder` lowering and any other JSON-shaped
/// topology source agree on one parse.
pub(crate) fn topology_from_json(
    value: &serde_json::Value,
) -> KataResult<kata_types::workflow::StageTopology> {
    serde_json::from_value(value.clone()).map_err(|e| {
        KataError::Validation(format!(
            "starlark: stage topology does not match expected shape: {e}"
        ))
    })
}

/// Convert a starlark-emitted JSON value into a [`SandboxRef`].
///
/// Accepts either a bare string (`"name"` → `SandboxRef::Named`) or
/// a dict/object (inline profile). Any other shape is a parse error.
///
/// This is the single shared lowering for a stage's `sandbox` reference. The
/// native `stage(sandbox=..)` builtin lowers through it from typed builder state
/// (`dsl::builder::lower_workflow`) into [`SandboxRef`].
///
/// # `sandbox = "host"` — the reserved spelling
///
/// The one string that is NOT a profile-map lookup. It lowers HERE, to an
/// inline [`SandboxProfile::host_unconfined`], so it never reaches the
/// `sandbox_profiles` map at all — and `decode_sandbox_profiles` refuses a map
/// entry under that name, so the word cannot be redefined to mean something
/// confined. One capability, one spelling: there is no boolean, no
/// `confined = False`, and no profile that grants host authority without
/// saying `host`.
pub(crate) fn sandbox_ref_from_json(value: &serde_json::Value) -> KataResult<SandboxRef> {
    match value {
        serde_json::Value::String(s) if s == kata_types::sandbox::HOST_SANDBOX_SPELLING => Ok(
            SandboxRef::Inline(Box::new(SandboxProfile::host_unconfined())),
        ),
        serde_json::Value::String(s) => Ok(SandboxRef::Named(s.clone())),
        serde_json::Value::Object(_) => {
            let profile = sandbox_profile_from_json(value)?;
            Ok(SandboxRef::Inline(Box::new(profile)))
        }
        other => Err(KataError::Validation(format!(
            "starlark: stage `sandbox` must be a string (named profile) or a dict \
             (inline profile); got {}",
            other
        ))),
    }
}

/// Convert a starlark-emitted JSON value into a [`SandboxProfile`].
///
/// Accepts the same string-shaped enums the shared `parser` normalizers
/// accept, by re-using those helpers via a `Raw*` round-trip through
/// `serde_json::from_value`.
///
/// This is the single shared lowering for a sandbox profile.
/// The native `sandbox_profile(..)` builtin lowers through it
/// (`dsl::builder::lower_workflow`, both for `workflow(sandbox_profiles=..)` and
/// inline `stage(sandbox=sandbox_profile(..))`). Starlark is kata's sole
/// workflow frontend, so this decoder is the one place a sandbox profile is
/// lowered.
pub(crate) fn sandbox_profile_from_json(value: &serde_json::Value) -> KataResult<SandboxProfile> {
    // A local raw shape that reads the JSON starlark's `.to_json()` emits, kept
    // self-contained (not shared as a public type) so the decoder owns its own
    // wire shape.
    #[derive(serde::Deserialize)]
    struct Raw {
        /// Omitted means `offline`, the confined default.
        #[serde(default)]
        net: Option<serde_json::Value>,
        /// What survived of `fs=`: the workspace VIEW,
        /// `"ro"` (default) / `"rw"` / `"scratch"`. `exec` has no slot at all:
        /// a profile is always the `oci` containment provider, and the one
        /// unconfined form is `stage(sandbox = "host")`.
        #[serde(default)]
        workspace: Option<String>,
        #[serde(default)]
        secrets: BTreeMap<String, String>,
        #[serde(default)]
        locked: bool,
        #[serde(default)]
        image: Option<RawImage>,
        /// Read as a raw `String` and parsed BELOW rather than decoded
        /// straight into a [`kata_types::sandbox::ToolchainRequirement`].
        ///
        /// The type's own `Deserialize` would reject a bad value with serde's
        /// message, attributed to "sandbox profile does not match expected
        /// shape" — which tells an author their profile is malformed without
        /// telling them that `toolchain = "/usr/local/rust"` was refused
        /// BECAUSE it is a path. Parsing here buys the refusal that names the
        /// mistake; the type still owns what is acceptable.
        #[serde(default)]
        toolchain: Option<String>,
        /// The ROOT FILESYSTEM requirement, read raw and parsed
        /// by the same helper as `toolchain` for the same reason.
        #[serde(default)]
        rootfs: Option<String>,
        /// Program names the node environment must provide.
        #[serde(default)]
        requires: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    struct RawImage {
        /// Optional so a memory-only image (`image = {"memory_mb": 2048}`)
        /// parses — the only shape `oci` admits (`per_stage_image_unsupported_under_oci`
        /// refuses `ref`/`cpus` at CHECK). Decodes to the empty string when absent.
        #[serde(rename = "ref", default)]
        reference: String,
        #[serde(default)]
        cpus: Option<u32>,
        #[serde(default)]
        memory_mb: Option<u32>,
    }

    let raw: Raw = serde_json::from_value(value.clone()).map_err(|e| {
        KataError::Validation(format!(
            "starlark: sandbox profile does not match expected shape: {e}"
        ))
    })?;

    // The authored surface has exactly one containment provider, and
    // `sandbox = "host"` is the opt-out (lowered elsewhere, to
    // `ExecBackend::Host`).
    let exec = kata_types::sandbox::ExecBackend::Oci;
    let fs = crate::parser::normalize_workspace(raw.workspace.as_deref())?;
    let net = match &raw.net {
        Some(net) => crate::parser::normalize_net_value(net)?,
        None => kata_types::sandbox::NetPolicy::Offline,
    };

    let mut secrets = BTreeMap::new();
    for (name, spec) in &raw.secrets {
        secrets.insert(name.clone(), crate::parser::normalize_secret_spec(spec)?);
    }

    let image = raw.image.map(|i| kata_types::sandbox::SandboxImage {
        reference: i.reference,
        cpus: i.cpus,
        memory_mb: i.memory_mb,
    });

    // `toolchain` and `rootfs` — the two REQUIREMENT doors. This is where "a pack must never
    // contain a host path" becomes a refusal an author reads.
    //
    // ONE parser for both kwargs, not two. The mistakes, the argument and the
    // accepted form are identical — `rootfs=` is `toolchain=`'s shape one layer
    // down — so a second copy of
    // this arm would be a second place for the two to drift apart, with the
    // author of whichever copy was not updated getting the weaker message. What
    // differs is the KWARG the message names, and that is a parameter.
    let requirement = |kwarg: &str, raw: Option<&str>| -> KataResult<Option<_>> {
        match raw.map(str::trim) {
            None | Some("") => Ok(None),
            Some(spec) => Ok(Some(
                kata_types::sandbox::ToolchainRequirement::parse(spec).ok_or_else(|| {
                    KataError::Validation(format!(
                        "starlark: sandbox_profile({kwarg} = {spec:?}) is not a {kwarg} \
                         requirement. A requirement is `{store}<64 lowercase hex>` and names \
                         CONTENT, never a filesystem path: a path resolves only on the host that \
                         authored the pack. (No stage may pin a {kwarg} on this build anyway — a \
                         capsule's tools are its node environment's; state what the stage needs \
                         with `requires`.)",
                        store = kata_types::sandbox::STORE_BASIS_PREFIX,
                    ))
                })?,
            )),
        }
    };
    let toolchain = requirement("toolchain", raw.toolchain.as_deref())?;
    let rootfs = requirement("rootfs", raw.rootfs.as_deref())?;
    // The PAIR is refused, and it is refused HERE. See [`refuse_root_and_toolchain_pair`] for the
    // refused set and for why load time is the earliest sound site.
    refuse_root_and_toolchain_pair(rootfs.as_ref(), toolchain.as_ref())?;
    // A requirement names a PROGRAM on the node environment's
    // PATH, never a path: a path resolves only on the box that wrote it.
    let mut requires: Vec<String> = Vec::with_capacity(raw.requires.len());
    for program in raw.requires {
        let program = program.trim().to_owned();
        if program.is_empty() || program.contains('/') || program.chars().any(char::is_whitespace) {
            return Err(KataError::Validation(format!(
                "starlark: sandbox_profile(requires = [..]) entry {program:?} is not a program \
                 name. Write the bare name the node environment's PATH provides (`\"cargo\"`, \
                 `\"just\"`) — never a path, which resolves only on the host that authored the \
                 pack"
            )));
        }
        if !requires.contains(&program) {
            requires.push(program);
        }
    }
    requires.sort();
    Ok(SandboxProfile {
        exec,
        fs,
        net,
        secrets,
        locked: raw.locked,
        image,
        toolchain,
        rootfs,
        requires,
    })
}

/// REFUSE a sandbox profile that declares BOTH a root filesystem and a toolchain.
///
/// **Refused: a single `sandbox_profile(..)` carrying a non-blank `rootfs=`
/// AND a non-blank `toolchain=`.** That is the whole set, and it is decided at
/// pack LOAD, where `kata workflows check` reports it against the author's own
/// source. An addressed root names the WHOLE userland by content, so a toolchain
/// beside it is either the same bytes named twice or a toolchain the root does
/// not contain.
///
/// Either kwarg ALONE is refused one step later, at CHECK, on this build
/// (`per_stage_toolchain_unsupported_under_oci`: a capsule's tools are its node
/// environment's); this door keeps the pair's sharper diagnosis.
fn refuse_root_and_toolchain_pair(
    rootfs: Option<&kata_types::sandbox::ToolchainRequirement>,
    toolchain: Option<&kata_types::sandbox::ToolchainRequirement>,
) -> KataResult<()> {
    let (Some(rootfs), Some(toolchain)) = (rootfs, toolchain) else {
        return Ok(());
    };
    Err(KataError::Validation(format!(
        "starlark: sandbox_profile(rootfs = \"{rootfs}\", toolchain = \"{toolchain}\") declares \
         BOTH a root filesystem and a toolchain. Refusing the pair. An addressed ROOT is a \
         SUPERSET of an addressed toolchain: `rootfs=` names the whole userland by content, and \
         a toolchain provisioned into that userland is already inside that digest — so this \
         stage is either naming the same bytes twice, or naming a toolchain the declared root \
         does not contain, and the second would make the run's recorded address describe bytes \
         the stage did not run. Neither kwarg is \
         accepted on this build anyway: a capsule's tools are its node environment's, so state \
         what the stage needs with `requires`."
    )))
}

#[cfg(test)]
#[path = "starlark_eval_tests.rs"]
mod tests;

/// Cooperative-cancel / no-orphan-on-timeout regression tests.
#[cfg(test)]
mod cancel_tests {
    use super::*;

    /// Count live OS threads in THIS process whose kernel `comm` name starts with
    /// `prefix`. Under nextest's process-per-test isolation there are no other
    /// `.star` evaluators running, so the eval-worker count is a precise, stable
    /// signal. (`/proc/self/task/<tid>/comm` is Linux-only; the CI/dev target is
    /// Linux — see `just` env.)
    fn count_threads_named(prefix: &str) -> usize {
        let mut count = 0;
        if let Ok(entries) = std::fs::read_dir("/proc/self/task") {
            for entry in entries.flatten() {
                if let Ok(name) = std::fs::read_to_string(entry.path().join("comm"))
                    && name.trim_end().starts_with(prefix)
                {
                    count += 1;
                }
            }
        }
        count
    }

    /// A timed-out eval must NOT leak its OS worker thread: the cooperative-cancel
    /// flag stops the statement-yielding runaway at the OUTER deadline (300ms) and
    /// the reaper joins it, so the worker is reclaimed rather than left running to
    /// the 30s inner backstop.
    ///
    /// Would red if the `JoinHandle` were dropped (detach) with no cancel flag:
    /// with a far backstop the worker keeps spinning long past the deadline and
    /// the reclamation poll below fails. Cancel + reaper reclaim the worker
    /// within milliseconds.
    #[test]
    fn timed_out_eval_reaps_its_worker_thread() {
        const WORKER_PREFIX: &str = "starlark-eval:";
        let baseline = count_threads_named(WORKER_PREFIX);

        // Statement-yielding infinite loop (range is lazy in starlark-rust, proven
        // by `evaluation_budget_kills_runaway_loop`). The inner backstop is 30s and
        // the statement budget is effectively unbounded, so ONLY the cooperative
        // cancel — fired at the 300ms outer deadline — can stop it.
        let source = r#"
def burn():
    x = 0
    for i in range(1000000000):
        x = x + 1
    return x

burned = burn()
s = stage(id = "s", prompt = str(burned), agent = "worker")
workflow("reap", root = s)
"#;

        let start = Instant::now();
        let result = evaluate_starlark_reap_probe_for_tests(
            source,
            "reap.star",
            Duration::from_millis(300),
            Duration::from_secs(30),
            u64::MAX,
            &[],
        );
        let elapsed = start.elapsed();

        assert!(result.is_err(), "runaway eval must return a timeout error");
        // The outer deadline (not the 30s backstop) must drive the return.
        assert!(
            elapsed < Duration::from_secs(5),
            "eval returned after {elapsed:?}; the outer deadline must fire promptly"
        );

        // Reclamation poll: cooperative cancel + reaper must join the worker so the
        // eval-worker thread count returns to baseline. Generous 30s budget per the
        // repo's state-poll convention; the realistic reclaim is sub-second.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let live = count_threads_named(WORKER_PREFIX);
            if live <= baseline {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "worker thread leaked on timeout: {live} eval workers still live \
                 (baseline {baseline}) — the timed-out eval was not reaped"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// A library root holding `spin.star`, whose MODULE SCOPE runs `body`.
    fn library_with_module_scope(body: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("library root");
        std::fs::write(root.path().join("spin.star"), body).expect("write spin.star");
        root
    }

    const IMPORTER: &str = r#"
load("spin.star", "spun")
s = stage(id = "s", prompt = str(spun), agent = "worker")
workflow("importer", root = s)
"#;

    /// The cooperative cancel reaches a `load()`ed module: a runaway at a
    /// helper's module scope stops at the outer deadline and its worker thread
    /// is reclaimed, exactly as a runaway in the importing file is.
    #[test]
    fn timed_out_load_reaps_its_worker_thread() {
        const WORKER_PREFIX: &str = "starlark-eval:";
        let baseline = count_threads_named(WORKER_PREFIX);
        let root = library_with_module_scope(
            r"
def burn():
    x = 0
    for i in range(1000000000):
        x = x + 1
    return x

spun = burn()
",
        );

        let start = Instant::now();
        let result = evaluate_starlark_reap_probe_for_tests(
            IMPORTER,
            "importer.star",
            Duration::from_millis(300),
            Duration::from_secs(30),
            u64::MAX,
            &[root.path().to_path_buf()],
        );
        assert!(result.is_err(), "runaway load must return a timeout error");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the outer deadline must fire promptly"
        );

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let live = count_threads_named(WORKER_PREFIX);
            if live <= baseline {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "worker thread leaked on timeout inside a load(): {live} eval workers \
                 still live (baseline {baseline}) — the loaded module ignored the cancel"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// The statement budget is ONE budget for the whole evaluation: statements a
    /// `load()`ed module executes are charged to the importer's count, so a
    /// helper cannot run past the budget the top-level file is held to.
    #[test]
    fn load_spends_the_importers_statement_budget() {
        let root = library_with_module_scope(
            r"
def burn():
    x = 0
    for i in range(5000):
        x = x + 1
    return x

spun = burn()
",
        );
        let err = evaluate_starlark_reap_probe_for_tests(
            IMPORTER,
            "importer.star",
            Duration::from_secs(30),
            Duration::from_secs(30),
            1_000,
            &[root.path().to_path_buf()],
        )
        .expect_err("a load() that executes 10k statements must exhaust a 1k budget");
        assert!(
            err.to_string().contains(
                "Starlark evaluation of importer.star exceeded the 1000 statement budget"
            ),
            "{err}"
        );
    }
}

/// Generative/adversarial conformance fuzz for the `.star` frontend
/// INLINE-COMPILE path (`compile_execution_program`), the untrusted surface
/// inline authoring exposes. A hostile/malformed `.star` must never panic, hang, or escape the
/// sandbox — it must always return a `Result`. The `conformance` module path
/// makes it ride `just test-conformance`.
#[cfg(test)]
mod conformance {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};

    /// Bounded per-input eval budget: small enough that a runaway can't stall the
    /// gate, large enough that a legitimately fast near-valid workflow finishes.
    const FUZZ_EVAL_BUDGET: Duration = Duration::from_millis(250);
    /// Deterministic sample count. Kept modest so the whole harness stays well
    /// under a second even if a few inputs reach the budget.
    const FUZZ_SAMPLES: u64 = 256;

    /// Deterministic splitmix64 step — same seed → same stream on every platform,
    /// so any failing sample is exactly reproducible.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn seed_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&splitmix64(&mut state).to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// Graph-DSL + minijinja token alphabet. Splicing these reaches far past the
    /// lexer into builtin dispatch, JSON normalization, validation, and — via the
    /// embedded template fragments — the load-time prompt-template check.
    const TOKENS: &[&str] = &[
        "workflow",
        "stage",
        "sequence",
        "loop",
        "def ",
        "return ",
        "contract",
        "field",
        "enum",
        "list_of",
        "variant",
        "prompt",
        "agent",
        "id",
        "root",
        "=",
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        ",",
        ":",
        "\n",
        "  ",
        "\"x\"",
        "\"worker\"",
        "0",
        "1",
        "True",
        "False",
        "None",
        // minijinja fragments so eval-valid stages carry adversarial templates.
        "{{",
        "}}",
        "{%",
        "%}",
        " for ",
        " in ",
        " endfor ",
        " if ",
        " endif ",
        "|",
        "stages.",
        ".parsed.",
        ".content",
        "no_such_filter",
        "review.iteration",
    ];

    /// Splice tokens under seed control, occasionally interleaving raw arbitrary
    /// text to perturb the grammar.
    fn token_soup(u: &mut Unstructured<'_>) -> String {
        let n = u.int_in_range(0u32..=64).unwrap_or(0);
        let mut s = String::new();
        for _ in 0..n {
            let pick = u.int_in_range(0usize..=TOKENS.len() + 2).unwrap_or(0);
            if let Some(tok) = TOKENS.get(pick) {
                s.push_str(tok);
            } else if let Ok(extra) = <&str>::arbitrary(u) {
                s.push_str(extra);
            }
        }
        s
    }

    /// Build a near-valid workflow whose stage prompt embeds an adversarial
    /// minijinja fragment, so eval reliably SUCCEEDS and the input reaches the
    /// inline-compile path (lower → output-ref check → template check).
    fn adversarial_template_workflow(u: &mut Unstructured<'_>) -> String {
        let n = u.int_in_range(0u32..=24).unwrap_or(0);
        let jinja: &[&str] = &[
            "{{",
            "}}",
            "{%",
            "%}",
            "for",
            "in",
            "endfor",
            "if",
            "endif",
            "|",
            "no_such_filter",
            "stages.a.parsed.x",
            "review.iteration",
            "workspace.query(",
            ")",
            " ",
            "x",
        ];
        let mut prompt = String::new();
        for _ in 0..n {
            let pick = u.int_in_range(0usize..=jinja.len() - 1).unwrap_or(0);
            prompt.push_str(jinja[pick]);
        }
        // `{prompt:?}` embeds the fragment as a safely-escaped Starlark string.
        format!(
            "s = stage(id = \"s\", prompt = {prompt:?}, agent = \"worker\")\nworkflow(\"w\", root = s)\n"
        )
    }

    /// A frontend eval that DIED on the worker thread — either a caught panic on
    /// the parse/eval attack surface (the distinct [`STARLARK_WORKER_PANIC_SENTINEL`])
    /// or a raw channel disconnect (the worker exited before sending). Neither is
    /// an acceptable outcome for adversarial input: the property under test is that
    /// a hostile `.star` always yields a STRUCTURED parse/eval/validation error or a
    /// compiled program — never a thread death the harness silently swallows.
    fn is_worker_death(err: &KataError) -> bool {
        let msg = err.to_string();
        msg.contains(STARLARK_WORKER_PANIC_SENTINEL)
            || msg.contains("exited without sending a result")
    }

    /// Drive one source string through the full inline-compile path with a bounded
    /// eval budget. The property is "always returns a Result, never panics/hangs,
    /// and never dies on the worker thread".
    fn drive_inline_compile(source: &str, filename: &str) {
        // Bounded eval so a runaway can't stall the gate; on success, drive the
        // rest of the inline-compile path (the fast, budget-free lowering + checks).
        match evaluate_starlark_checked_with_budget_for_tests(source, filename, FUZZ_EVAL_BUDGET) {
            Ok(checked) => {
                let _ = crate::execution_program::compile_execution_program(&checked);
            }
            Err(err) => {
                // Adversarial input may legitimately produce a STRUCTURED
                // parse/eval/validation error — that is fine, the property holds.
                // What it must NEVER produce is a WORKER-THREAD DEATH: a panic on
                // the parse/eval attack surface (now caught + tagged) or a raw
                // channel disconnect. The pre-hardening harness discarded ALL `Err`
                // via `if let Ok(..)`, so a real frontend panic — mapped to
                // `Disconnected` → `Internal` by the dropped sender — passed the
                // fuzz SILENTLY. This assertion closes that blind spot: a frontend
                // panic now fails the fuzz loudly.
                assert!(
                    !is_worker_death(&err),
                    "adversarial input drove the Starlark frontend to a WORKER-THREAD \
                     DEATH (a panic on the parse/eval attack surface, or a raw worker \
                     disconnect) rather than a structured error: {err}\nsource: {source:?}"
                );
            }
        }
    }

    #[test]
    fn starlark_inline_compile_adversarial_never_panics() {
        let mut completed = 0u64;
        for seed in 0..FUZZ_SAMPLES {
            // 1. Raw arbitrary UTF-8: exercises the lexer/parser error path.
            let raw_buf = seed_bytes(seed, 96);
            let mut u_raw = Unstructured::new(&raw_buf);
            let raw = String::arbitrary(&mut u_raw).unwrap_or_default();
            drive_inline_compile(&raw, "fuzz-inline-raw.star");

            // 2. Grammar-aware token soup: reaches builtin dispatch + normalization.
            let soup_buf = seed_bytes(seed ^ 0xA5A5_A5A5_A5A5_A5A5, 160);
            let mut u_soup = Unstructured::new(&soup_buf);
            let soup = token_soup(&mut u_soup);
            drive_inline_compile(&soup, "fuzz-inline-soup.star");

            // 3. Near-valid workflow with an adversarial prompt template: reliably
            //    reaches the lower + output-ref + template-check surface.
            let tpl_buf = seed_bytes(seed ^ 0x5A5A_5A5A_5A5A_5A5A, 96);
            let mut u_tpl = Unstructured::new(&tpl_buf);
            let tpl_src = adversarial_template_workflow(&mut u_tpl);
            drive_inline_compile(&tpl_src, "fuzz-inline-template.star");

            completed += 1;
        }
        // Reaching here without a panic/hang IS the property under test; the count
        // documents the fixed, deterministic sample budget (non-vacuous).
        assert_eq!(completed, FUZZ_SAMPLES);
    }

    /// Run `f` with the default panic hook silenced, then restore it. The panic
    /// regressions below INJECT a panic on purpose; suppressing the hook keeps the
    /// deliberately-provoked backtrace out of the test log. Scoped restore + Linux
    /// nextest's process-per-test isolation mean this never leaks into other tests.
    fn with_silenced_panic_hook<R>(f: impl FnOnce() -> R) -> R {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        std::panic::set_hook(prev);
        match out {
            Ok(r) => r,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    /// Panic-blind-spot regression — PRODUCTION SIGNAL half.
    ///
    /// A panic on the WORKER-thread parse/eval attack surface must be CAUGHT and
    /// surfaced as the distinct [`STARLARK_WORKER_PANIC_SENTINEL`] error — NOT the
    /// `RecvTimeoutError::Disconnected` → generic `Internal` mapping a dropped
    /// sender produces (`Internal("… exited without sending a result")`, an
    /// untyped death indistinguishable from any other). `catch_unwind` inside the
    /// worker converts the panic into the distinct sentinel error, asserted here.
    #[test]
    fn injected_worker_panic_surfaces_as_distinct_sentinel_not_disconnect() {
        let result = with_silenced_panic_hook(|| {
            evaluate_starlark_checked_with_budget_for_tests(
                STARLARK_EVAL_PANIC_INJECT_SENTINEL,
                "panic-inject.star",
                FUZZ_EVAL_BUDGET,
            )
        });

        let Err(err) = result else {
            panic!("an injected worker-thread frontend panic must NOT produce Ok");
        };
        let msg = err.to_string();
        assert!(
            msg.contains(STARLARK_WORKER_PANIC_SENTINEL),
            "a caught worker-thread panic must carry the distinct panic sentinel, got: {msg}"
        );
        assert!(
            !msg.contains("exited without sending a result"),
            "the panic must be caught IN the worker, not observed as a raw channel \
             disconnect: {msg}"
        );
        // And the harness classifier recognizes it as a worker death.
        assert!(
            is_worker_death(&err),
            "the surfaced panic must classify as a worker death so the fuzz fails on it: {msg}"
        );
    }

    /// Panic-blind-spot regression — HARNESS ASSERTION half.
    ///
    /// [`drive_inline_compile`] must FAIL LOUDLY (panic via its `assert!`) when the
    /// worker frontend panics, instead of swallowing the resulting `Err`: an
    /// `if let Ok(checked) = … { … }` harness would let this panic-derived `Err`
    /// fall through with NO assertion and the fuzz would pass BLIND. The
    /// `!is_worker_death` assertion fires, so the drive call panics and
    /// `catch_unwind` observes `Err` here.
    #[test]
    fn hardened_harness_fails_loudly_on_worker_frontend_panic() {
        let outcome = with_silenced_panic_hook(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drive_inline_compile(STARLARK_EVAL_PANIC_INJECT_SENTINEL, "panic-inject.star");
            }))
        });
        assert!(
            outcome.is_err(),
            "the hardened drive_inline_compile must FAIL LOUDLY on a worker-thread \
             frontend panic; discarding the Err via `if let Ok(..)` would let the \
             fuzz pass blind"
        );
    }
}
