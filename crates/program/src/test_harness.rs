//! A fixture-driven BEHAVIORAL workflow test harness.
//!
//! Feed a workflow RECORDED stage outputs (deterministic fixtures — no live
//! models) and ASSERT the routing (which branch / loop / skip decisions fire)
//! and the exact rendered prompts (minijinja output) for each stage. This is the
//! deterministic eval substrate the fixture corpus reuses as a golden corpus, so the
//! fixture format is shaped as a reusable, serde-friendly document.
//!
//! ## What the harness drives
//!
//! The harness is a DETERMINISTIC interpreter over the checked
//! [`ExecutionProgram`], built on the SAME primitives production uses so its
//! routing cannot drift from the runner:
//!
//! * **DAG readiness / skip** — [`crate::orchestrator::Orchestrator`]
//!   (`advance` / `complete_stage` / `skip_stage` / `skip_dependents`).
//! * **Rendered prompts** — [`crate::template::render_prompt`] /
//!   [`crate::template::render_prompt_with_review`], the exact functions the
//!   runner renders each stage's prompt through.
//! * **Branch routing** — [`crate::execution_program::select::select_decision`], the
//!   one route decision `WorkflowRunner::route_after_completion`'s `Select`
//!   resolution applies.
//! * **Review loops** — the loop's own
//!   [`LoopVerdictConfig::classify`](kata_types::review_loop::LoopVerdictConfig::classify)
//!   verdict read drives worker→reviewer iterations, with the `review.*` context
//!   built in the shape of `loops::render_review_context`.
//!
//! Because every DECISION reuses the production primitive, a fixture that passes
//! here asserts the real routing, not a re-implementation.
//!
//! ## Namespaces
//!
//! Prompt rendering covers the `stages.*` and `review.*` namespaces. A prompt
//! that references a runtime-only namespace the harness does not model
//! (`external_inputs.*` / `human_requests.*` / `memory.*` / `params.*` /
//! `workspace.*`)
//! surfaces a clear "harness does not model namespace" error rather than a
//! misleading render — fixtures target packs that flow data through stage
//! outputs and review context.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use kata_types::review_loop::{LoopVerdictAction, OnMaxAction, ReviewLoop};
use kata_types::workflow::StageId;
use kata_types::{KataError, KataResult};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::execution_program::{
    ExecutionProgram, ExecutionProgramStage, ExecutionPromptRendering,
    compile_starlark_execution_program,
};
use crate::loops::iteration_stage_name;
use crate::orchestrator::{Orchestrator, StageState};
use crate::template::{render_prompt, render_prompt_with_review};

/// Upper bound on driver ticks — a guard against a pathological fixture wedging
/// the interpreter. Far above any real workflow's stage×iteration product.
const MAX_TICKS: usize = 100_000;

// ---------------------------------------------------------------------------
// Fixture format
// ---------------------------------------------------------------------------

/// A behavioral test fixture: a workflow, a map of recorded stage outputs, and
/// the routing / rendered-prompt assertions to check after driving it.
///
/// The workflow is carried either inline (`workflow_starlark`) or by path
/// (`workflow_path`, resolved by the caller against a base directory). Recorded
/// outputs are keyed by the LEDGER-VISIBLE stage name: the base id for a normal
/// stage or a review loop's iteration 0, and `<base>#iter-<N>` for later loop
/// iterations.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WorkflowTestFixture {
    /// Optional human-readable fixture name (diagnostics only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Inline Starlark workflow source. Mutually exclusive with `workflow_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_starlark: Option<String>,
    /// Path to a `.star` workflow, resolved by the caller against a base dir.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_path: Option<String>,
    /// Diagnostic filename for inline-source parse errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_filename: Option<String>,
    /// Recorded stage-output envelopes, keyed by ledger-visible stage name.
    #[serde(default)]
    pub recorded_outputs: BTreeMap<String, serde_json::Value>,
    /// The assertions to check after driving the workflow.
    #[serde(default)]
    pub expect: FixtureExpectations,
}

/// The routing + rendered-prompt assertions a fixture checks. Every field is
/// optional and checked as a SUBSET: a fixture asserts only what it cares about.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FixtureExpectations {
    /// Stages expected to have RUN (completed), in any order.
    #[serde(default)]
    pub ran: Vec<String>,
    /// Stages expected to have been SKIPPED (e.g. a non-taken branch arm).
    #[serde(default)]
    pub skipped: Vec<String>,
    /// Expected EXACT rendered prompt per ledger-visible stage name (partial:
    /// only the listed stages are checked).
    #[serde(default)]
    pub rendered_prompts: BTreeMap<String, String>,
    /// Expected branch routing: condition-stage id → the arm tag taken.
    #[serde(default)]
    pub branch_taken: BTreeMap<String, String>,
    /// Expected iterations RUN per review loop, keyed by worker-stage id (a loop
    /// that runs iteration 0 then 1 has run 2 iterations).
    #[serde(default)]
    pub loop_iterations: BTreeMap<String, u32>,
    /// Expected terminal loop resolution per worker-stage id: one of
    /// `approved` / `blocked` / `max_exhausted` / `escalated`.
    #[serde(default)]
    pub loop_resolution: BTreeMap<String, String>,
}

impl WorkflowTestFixture {
    /// Load a fixture from a JSON document.
    ///
    /// # Errors
    /// A read or parse failure surfaces as [`KataError`].
    pub fn load_json(path: &Path) -> KataResult<Self> {
        let bytes = std::fs::read(path).map_err(|e| {
            KataError::Validation(format!("reading fixture {}: {e}", path.display()))
        })?;
        serde_json::from_slice(&bytes)
            .map_err(|e| KataError::Validation(format!("parsing fixture {}: {e}", path.display())))
    }

    /// Resolve the fixture's workflow source and a diagnostic filename. An inline
    /// `workflow_starlark` wins; otherwise `workflow_path` is read relative to
    /// `base_dir` (typically the fixture file's own directory).
    ///
    /// # Errors
    /// A missing source, or a `workflow_path` read failure, surfaces as
    /// [`KataError`].
    pub fn workflow_source(&self, base_dir: &Path) -> KataResult<(String, String)> {
        if let Some(source) = &self.workflow_starlark {
            let filename = self
                .workflow_filename
                .clone()
                .unwrap_or_else(|| "<inline>".to_string());
            return Ok((source.clone(), filename));
        }
        if let Some(rel) = &self.workflow_path {
            let path = base_dir.join(rel);
            let source = std::fs::read_to_string(&path).map_err(|e| {
                KataError::Validation(format!("reading workflow {}: {e}", path.display()))
            })?;
            let filename = path
                .file_name()
                .map_or_else(|| rel.clone(), |name| name.to_string_lossy().into_owned());
            return Ok((source, filename));
        }
        Err(KataError::Validation(
            "fixture declares neither `workflow_starlark` nor `workflow_path`".to_string(),
        ))
    }
}

/// Load, drive, and assert a fixture FILE, resolving its `workflow_path` against
/// the fixture file's own directory. This is the entry point the
/// `kata workflows test <fixture>` CLI and the golden-corpus test both use.
///
/// # Errors
/// A load / compile / structural driver error surfaces as [`KataError`];
/// assertion mismatches are collected into the returned outcome (not errors).
pub fn check_fixture_file(path: &Path, loader_roots: &[PathBuf]) -> KataResult<FixtureOutcome> {
    let fixture = WorkflowTestFixture::load_json(path)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let (source, filename) = fixture.workflow_source(base_dir)?;
    check_fixture_source(&source, &filename, &fixture, loader_roots)
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

/// The observations a driven fixture produces — what actually happened.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HarnessRun {
    /// Rendered prompt per ledger-visible stage name.
    pub rendered_prompts: BTreeMap<String, String>,
    /// Stages that ran (completed), in dispatch order.
    pub ran: Vec<String>,
    /// Stages that were skipped.
    pub skipped: Vec<String>,
    /// Branch routing that fired: condition-stage id → taken arm tag.
    pub branch_taken: BTreeMap<String, String>,
    /// Iterations run per review loop (worker-stage id → count).
    pub loop_iterations: BTreeMap<String, u32>,
    /// Terminal resolution per review loop (worker-stage id → label).
    pub loop_resolution: BTreeMap<String, String>,
    /// Set when the run wedged (a non-terminal stage with nothing ready), naming
    /// the stuck stages. `None` on a clean run.
    pub stuck: Option<String>,
}

/// The result of checking a fixture: the observations plus any assertion
/// failures. `passed()` is true iff `failures` is empty.
#[derive(Clone, Debug)]
pub struct FixtureOutcome {
    /// What the harness observed.
    pub run: HarnessRun,
    /// Human-readable assertion failures (empty ⇒ the fixture passed).
    pub failures: Vec<String>,
}

impl FixtureOutcome {
    /// Whether every asserted expectation held.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Compile a fixture's inline Starlark workflow source into a checked program.
///
/// # Errors
/// A compile / verifier failure surfaces as [`KataError`].
pub fn compile_fixture_source(
    source: &str,
    filename: &str,
    loader_roots: &[PathBuf],
) -> KataResult<ExecutionProgram> {
    compile_starlark_execution_program(source, filename, loader_roots)
}

/// Drive a compiled program with the fixture's recorded outputs, returning the
/// observed routing + rendered prompts.
///
/// # Errors
/// A structural fixture error (a ready stage with no recorded output, an
/// unmodeled prompt namespace, an unclassifiable loop verdict) surfaces as
/// [`KataError`].
pub fn run_program(
    program: &ExecutionProgram,
    recorded_outputs: &BTreeMap<String, serde_json::Value>,
) -> KataResult<HarnessRun> {
    let orchestrator = Orchestrator::from_execution_program(program)?;
    let mut driver = Driver {
        program,
        orchestrator,
        recorded: recorded_outputs,
        outputs: BTreeMap::new(),
        run: HarnessRun::default(),
    };
    driver.drive()?;
    driver.collect_skips();
    Ok(driver.run)
}

/// Compile + drive + assert a fixture from its inline source, returning a
/// [`FixtureOutcome`] (observations + assertion failures).
///
/// # Errors
/// A compile failure or a structural driver error surfaces as [`KataError`];
/// assertion mismatches are collected into the returned outcome (not errors).
pub fn check_fixture_source(
    source: &str,
    filename: &str,
    fixture: &WorkflowTestFixture,
    loader_roots: &[PathBuf],
) -> KataResult<FixtureOutcome> {
    let program = compile_fixture_source(source, filename, loader_roots)?;
    let run = run_program(&program, &fixture.recorded_outputs)?;
    let failures = assert_expectations(&run, &fixture.expect);
    Ok(FixtureOutcome { run, failures })
}

/// Compare an observed run against a fixture's expectations, returning a list of
/// human-readable failures (empty ⇒ all assertions held).
#[must_use]
pub fn assert_expectations(run: &HarnessRun, expect: &FixtureExpectations) -> Vec<String> {
    let mut failures = Vec::new();

    if let Some(stuck) = &run.stuck {
        failures.push(format!("run wedged before terminal: {stuck}"));
    }

    let ran: BTreeSet<&str> = run.ran.iter().map(String::as_str).collect();
    for stage in &expect.ran {
        if !ran.contains(stage.as_str()) {
            failures.push(format!(
                "expected stage \"{stage}\" to RUN, but it did not (ran: {})",
                join(&run.ran)
            ));
        }
    }
    let skipped: BTreeSet<&str> = run.skipped.iter().map(String::as_str).collect();
    for stage in &expect.skipped {
        if !skipped.contains(stage.as_str()) {
            failures.push(format!(
                "expected stage \"{stage}\" to be SKIPPED, but it was not (skipped: {})",
                join(&run.skipped)
            ));
        }
    }
    for (stage, expected) in &expect.rendered_prompts {
        match run.rendered_prompts.get(stage) {
            Some(actual) if actual == expected => {}
            Some(actual) => failures.push(format!(
                "rendered prompt mismatch for stage \"{stage}\":\n  expected: {expected:?}\n  actual:   {actual:?}" // kata-spacing: intentional
            )),
            None => failures.push(format!(
                "expected a rendered prompt for stage \"{stage}\", but it never rendered"
            )),
        }
    }
    for (cond, expected_tag) in &expect.branch_taken {
        match run.branch_taken.get(cond) {
            Some(actual) if actual == expected_tag => {}
            Some(actual) => failures.push(format!(
                "branch on \"{cond}\" took arm \"{actual}\", expected \"{expected_tag}\""
            )),
            None => failures.push(format!(
                "expected branch routing on condition stage \"{cond}\", but none fired"
            )),
        }
    }
    for (worker, expected) in &expect.loop_iterations {
        match run.loop_iterations.get(worker) {
            Some(actual) if actual == expected => {}
            other => failures.push(format!(
                "loop \"{worker}\" ran {:?} iteration(s), expected {expected}",
                other
            )),
        }
    }
    for (worker, expected) in &expect.loop_resolution {
        match run.loop_resolution.get(worker) {
            Some(actual) if actual == expected => {}
            other => failures.push(format!(
                "loop \"{worker}\" resolved {other:?}, expected \"{expected}\""
            )),
        }
    }
    failures
}

fn join(items: &[String]) -> String {
    if items.is_empty() {
        "<none>".to_string()
    } else {
        items.join(", ")
    }
}

// ---------------------------------------------------------------------------
// The deterministic driver
// ---------------------------------------------------------------------------

struct Driver<'a> {
    program: &'a ExecutionProgram,
    orchestrator: Orchestrator,
    recorded: &'a BTreeMap<String, serde_json::Value>,
    /// Accumulated stage outputs keyed by BASE stage id (the `stages.*` context
    /// each downstream render reads). A loop stage's entry is its final
    /// iteration's output, matching the runner's ledger base-name output.
    outputs: BTreeMap<SmolStr, serde_json::Value>,
    run: HarnessRun,
}

impl Driver<'_> {
    fn drive(&mut self) -> KataResult<()> {
        let reviewer_stages: BTreeSet<SmolStr> = self
            .program
            .review_loops
            .iter()
            .map(|loop_cfg| loop_cfg.reviewer_stage.clone())
            .collect();

        for _ in 0..MAX_TICKS {
            let mut ready = self.orchestrator.advance();
            if ready.is_empty() {
                if self.orchestrator.is_finished() {
                    return Ok(());
                }
                self.run.stuck = Some(self.describe_stuck());
                return Ok(());
            }
            // Deterministic dispatch order regardless of the DAG's ready-set order.
            ready.sort_unstable();
            for stage_name in ready {
                // A loop reviewer is driven as part of its worker's loop; if it
                // surfaces standalone it is already handled — skip defensively.
                if reviewer_stages.contains(&stage_name) {
                    continue;
                }
                if let Some(loop_cfg) = self.loop_for_worker(&stage_name) {
                    self.drive_review_loop(&loop_cfg)?;
                } else {
                    self.run_normal_stage(&stage_name)?;
                }
            }
        }
        Err(KataError::Internal(format!(
            "workflow test harness exceeded {MAX_TICKS} ticks — possible fixture cycle"
        )))
    }

    fn loop_for_worker(&self, stage_name: &SmolStr) -> Option<ReviewLoop> {
        self.program
            .review_loops
            .iter()
            .find(|loop_cfg| loop_cfg.worker_stage == *stage_name)
            .cloned()
    }

    /// Drive a single non-loop stage: render its prompt, complete it with its
    /// recorded output, and evaluate any branch route anchored on it.
    fn run_normal_stage(&mut self, stage_name: &SmolStr) -> KataResult<()> {
        let stage = self.stage_def(stage_name)?;
        let rendered = self.render(stage_name.as_str(), stage, None)?;
        self.run
            .rendered_prompts
            .insert(stage_name.to_string(), rendered);

        let output = self.recorded_output(stage_name.as_str())?;
        self.orchestrator
            .complete_stage(stage_name.as_str(), output.clone())?;
        self.outputs.insert(stage_name.clone(), output.clone());
        self.run.ran.push(stage_name.to_string());

        self.evaluate_branch(stage_name, &output)?;
        Ok(())
    }

    /// Drive a review loop from recorded per-iteration outputs, reusing the
    /// loop's own verdict config to classify each reviewer verdict — the SAME
    /// classification the durable expansion's gate applies (`runner::expansion`).
    fn drive_review_loop(&mut self, loop_cfg: &ReviewLoop) -> KataResult<()> {
        // The harness models the common single-stage-body loop (body == the
        // worker). A MULTI-stage body sub-DAG re-dispatches its intermediate
        // members each iteration — not yet modeled — so reject it explicitly
        // rather than silently under-driving the body chain.
        if !loop_cfg.body_stages.is_empty() {
            return Err(KataError::Validation(format!(
                "review loop \"{}\" has a multi-stage body ({} members), which the workflow test \
                 harness does not yet model — fixtures target single-stage-body loops",
                loop_cfg.worker_stage,
                loop_cfg.body_stages.len()
            )));
        }
        let worker = loop_cfg.worker_stage.clone();
        let reviewer = loop_cfg.reviewer_stage.clone();
        let gate = loop_cfg.effective_gate_verdict();
        let worker_def = self.stage_def(&worker)?.clone();
        let reviewer_def = self.stage_def(&reviewer)?.clone();

        let mut iteration: u32 = 0;
        let mut latest_worker_output = serde_json::Value::Null;
        let mut latest_feedback = String::new();
        let resolution: LoopOutcome;

        loop {
            // ── Worker iteration N ──────────────────────────────────────────
            let review_ctx = review_context(iteration, &latest_worker_output, &latest_feedback);
            let worker_ledger = iteration_stage_name(&worker, iteration);
            let rendered = self.render(worker_ledger.as_str(), &worker_def, Some(&review_ctx))?;
            self.run
                .rendered_prompts
                .insert(worker_ledger.to_string(), rendered);
            let worker_output = self.recorded_output(worker_ledger.as_str())?;
            latest_worker_output = worker_output.clone();
            // The worker's output is visible to the reviewer's `stages.<worker>`.
            self.outputs.insert(worker.clone(), worker_output);

            // ── Reviewer iteration N ────────────────────────────────────────
            let review_ctx = review_context(iteration, &latest_worker_output, &latest_feedback);
            let reviewer_ledger = iteration_stage_name(&reviewer, iteration);
            let rendered =
                self.render(reviewer_ledger.as_str(), &reviewer_def, Some(&review_ctx))?;
            self.run
                .rendered_prompts
                .insert(reviewer_ledger.to_string(), rendered);
            let reviewer_output = self.recorded_output(reviewer_ledger.as_str())?;
            self.outputs
                .insert(reviewer.clone(), reviewer_output.clone());

            // ── Classify the verdict (shared primitive) ─────────────────────
            let tag = crate::execution_program::select::verdict_tag(
                &reviewer_output,
                gate.verdict_field.as_str(),
            )
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "review loop \"{worker}\": reviewer output at iteration {iteration} carries no \
                     \"parsed.{}\" verdict tag",
                    gate.verdict_field
                ))
            })?;
            latest_feedback = reviewer_output
                .get("parsed")
                .and_then(|parsed| parsed.get("feedback"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();

            let action = gate.classify(&tag).ok_or_else(|| {
                KataError::Validation(format!(
                    "review loop \"{worker}\": reviewer emitted unknown verdict \"{tag}\" \
                     (approve={:?}, refine={:?}, block={:?})",
                    gate.approve, gate.refine, gate.block
                ))
            })?;

            match action {
                LoopVerdictAction::Approve => {
                    resolution = LoopOutcome::Approved;
                    break;
                }
                LoopVerdictAction::Block => {
                    resolution = LoopOutcome::Blocked;
                    break;
                }
                LoopVerdictAction::Refine => {
                    let next = iteration.saturating_add(1);
                    if next >= loop_cfg.max_iterations {
                        resolution = LoopOutcome::MaxExhausted(loop_cfg.on_max);
                        break;
                    }
                    iteration = next;
                }
            }
        }

        self.run
            .loop_iterations
            .insert(worker.to_string(), iteration + 1);
        self.run
            .loop_resolution
            .insert(worker.to_string(), resolution.label().to_string());

        self.finalize_loop_orchestrator(&worker, &reviewer, resolution)?;
        Ok(())
    }

    /// Reconcile the orchestrator's worker + reviewer states with the loop's
    /// terminal outcome, so the outer driver's readiness / skip accounting
    /// matches what the runner's loop resolution produces.
    fn finalize_loop_orchestrator(
        &mut self,
        worker: &SmolStr,
        reviewer: &SmolStr,
        resolution: LoopOutcome,
    ) -> KataResult<()> {
        // The reviewer stage is Pending (its worker dep just "completed" inside
        // the loop) until we promote it; promote then finalize.
        self.orchestrator.promote_to_ready(reviewer.as_str())?;
        let worker_output = self
            .outputs
            .get(worker)
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let reviewer_output = self
            .outputs
            .get(reviewer)
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        match resolution {
            // Both stages complete; downstream proceeds.
            LoopOutcome::Approved
            | LoopOutcome::MaxExhausted(OnMaxAction::Accept | OnMaxAction::Escalate) => {
                self.orchestrator
                    .complete_stage(worker.as_str(), worker_output)?;
                self.orchestrator
                    .complete_stage(reviewer.as_str(), reviewer_output)?;
                self.run.ran.push(worker.to_string());
                self.run.ran.push(reviewer.to_string());
            }
            // Worker fails; reviewer completes; the worker's dependents cascade
            // to Skipped (matching the runner's blocked and `on_max = "fail"`
            // resolutions).
            LoopOutcome::Blocked | LoopOutcome::MaxExhausted(OnMaxAction::Fail) => {
                self.orchestrator
                    .complete_stage(reviewer.as_str(), reviewer_output)?;
                self.orchestrator
                    .fail_stage(worker.as_str(), "review loop did not approve".to_string())?;
                self.orchestrator.skip_dependents(worker.as_str());
                self.run.ran.push(reviewer.to_string());
            }
        }
        Ok(())
    }

    /// Evaluate every branch route anchored on `completed_stage` through the one route
    /// decision ([`crate::execution_program::select::select_decision`]) and the
    /// orchestrator skip primitives the runner applies it with.
    fn evaluate_branch(
        &mut self,
        completed_stage: &SmolStr,
        envelope: &serde_json::Value,
    ) -> KataResult<()> {
        for route in &self.program.branch_routes {
            if route.condition_stage.0 != *completed_stage {
                continue;
            }
            let decision = crate::execution_program::select::select_decision(route, envelope)
                .map_err(|refusal| {
                    KataError::Validation(refusal.describe(&route.condition_stage))
                })?;
            self.run
                .branch_taken
                .insert(completed_stage.to_string(), decision.taken.to_string());
            for skipped in &decision.not_taken {
                // Best-effort skip (a raced-terminal target is fine to leave), then
                // cascade to the arm's subtree — the same pair the runner applies.
                let _ = self.orchestrator.skip_stage(
                    skipped.target.0.as_str(),
                    format!("branch not taken: {} != {}", skipped.arm, decision.taken),
                );
                self.orchestrator.skip_dependents(skipped.target.0.as_str());
            }
        }
        Ok(())
    }

    /// Render a stage's prompt exactly as the runner would: a `Literal` prompt is
    /// forwarded byte-for-byte; a `Template` prompt is rendered through minijinja
    /// with the accumulated `stages.*` outputs and the optional `review.*` context.
    fn render(
        &self,
        render_name: &str,
        stage: &ExecutionProgramStage,
        review_ctx: Option<&serde_json::Value>,
    ) -> KataResult<String> {
        if stage.op.prompt_rendering == ExecutionPromptRendering::Literal {
            return Ok(stage.op.prompt_template.clone());
        }
        Self::guard_modeled_namespaces(render_name, &stage.op.prompt_template)?;
        // The runner's `stages.*` is the stage's dependency closure only.
        let visible_outputs = self
            .program
            .outputs_in_dependency_closure(&stage.stage_id, &self.outputs);
        match review_ctx {
            Some(ctx) => render_prompt_with_review(
                render_name,
                &stage.op.prompt_template,
                &visible_outputs,
                Some(ctx),
            ),
            None => render_prompt(render_name, &stage.op.prompt_template, &visible_outputs),
        }
    }

    /// Fail loudly if a prompt references a runtime-only namespace the harness
    /// does not model, rather than letting the strict-undefined render produce a
    /// misleading error deep in minijinja.
    fn guard_modeled_namespaces(render_name: &str, template: &str) -> KataResult<()> {
        for namespace in [
            "external_inputs",
            "human_requests",
            "memory",
            "params",
            "workspace",
        ] {
            if !crate::execution_program::extract_head_references(template, namespace).is_empty() {
                return Err(KataError::Validation(format!(
                    "stage \"{render_name}\" prompt references the `{namespace}.*` namespace, which \
                     the workflow test harness does not model — fixtures target packs that flow \
                     data through stage outputs (`stages.*`) and review context (`review.*`)"
                )));
            }
        }
        Ok(())
    }

    fn stage_def(&self, stage_name: &SmolStr) -> KataResult<&ExecutionProgramStage> {
        self.program
            .stages
            .get(&StageId(stage_name.clone()))
            .ok_or_else(|| {
                KataError::Internal(format!("ready stage \"{stage_name}\" not found in program"))
            })
    }

    fn recorded_output(&self, ledger_name: &str) -> KataResult<serde_json::Value> {
        self.recorded.get(ledger_name).cloned().ok_or_else(|| {
            KataError::Validation(format!(
                "fixture is missing a recorded output for stage \"{ledger_name}\" (add it under \
                 `recorded_outputs`)"
            ))
        })
    }

    /// After the run, record every stage the orchestrator left Skipped.
    fn collect_skips(&mut self) {
        let mut skipped: Vec<String> = self
            .program
            .stages
            .keys()
            .filter(|stage_id| {
                matches!(
                    self.orchestrator.stage_state(stage_id.0.as_str()),
                    Some(StageState::Skipped { .. })
                )
            })
            .map(|stage_id| stage_id.0.to_string())
            .collect();
        skipped.sort();
        self.run.skipped = skipped;
    }

    fn describe_stuck(&self) -> String {
        let mut unfinished: Vec<String> = self
            .orchestrator
            .unfinished_stages()
            .into_iter()
            .map(|(name, tag)| format!("{name} ({tag})"))
            .collect();
        unfinished.sort();
        unfinished.join(", ")
    }
}

/// Terminal outcome of a driven review loop (a harness-local projection of the
/// runner's loop resolution).
#[derive(Clone, Copy, Debug)]
enum LoopOutcome {
    Approved,
    Blocked,
    MaxExhausted(OnMaxAction),
}

impl LoopOutcome {
    fn label(self) -> &'static str {
        match self {
            LoopOutcome::Approved => "approved",
            LoopOutcome::Blocked => "blocked",
            LoopOutcome::MaxExhausted(OnMaxAction::Escalate) => "escalated",
            LoopOutcome::MaxExhausted(_) => "max_exhausted",
        }
    }
}

/// Build the `review.*` template context for iteration N, identical in shape to
/// `loops::render_review_context` without a rollover:
/// `{iteration, previous_output, feedback}`.
fn review_context(
    iteration: u32,
    latest_worker_output: &serde_json::Value,
    latest_feedback: &str,
) -> serde_json::Value {
    serde_json::json!({
        "iteration": iteration,
        "previous_output": latest_worker_output.clone(),
        "feedback": latest_feedback,
    })
}

/// The `[agents.<label>]` block a scripted-worker rig declares for one label:
/// adapter `nanocode_openai` under kata's own login (`subscription` from
/// `kata_login`), no `argv` — the kind fixes the launch. The scripted worker
/// never runs it — the declaration is what the `oci` CHECK's agent doors and
/// the capsule assembly read.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn rig_agent_backend_config() -> kata_types::config::AgentBackendConfig {
    kata_types::config::AgentBackendConfig::Harness {
        model: None,
        reasoning_effort: None,
        adapter: Some("nanocode_openai".to_owned()),
        credential: Some(kata_types::config::AgentCredentialDecl {
            mode: "subscription".to_owned(),
            source: "kata_login".to_owned(),
        }),
        env: std::collections::BTreeMap::new(),
    }
}

/// Install the node-level `[agents.*]` map a scripted rig needs: one
/// [`rig_agent_backend_config`] block per NON-deterministic label in `labels`
/// (`shell`/`workspace_effect` are the deterministic classes — their stages
/// compile to `Command`/effect capsules that need no agent block). Process-
/// global like every `install_node_*` — install at rig build, the same place
/// `mark_node_installed` lands.
#[cfg(any(test, feature = "test-support"))]
pub fn install_rig_agents(labels: impl IntoIterator<Item = String>) {
    let agents = labels
        .into_iter()
        .filter(|label| !kata_types::agent::is_deterministic_agent_label(label))
        .map(|label| {
            let config = rig_agent_backend_config();
            (label, config)
        })
        .collect();
    kata_types::node_profile::install_node_agents(agents);
}

#[cfg(test)]
#[path = "test_harness_tests.rs"]
mod tests;
