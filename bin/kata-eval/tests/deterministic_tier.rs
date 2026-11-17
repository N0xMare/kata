//! The DETERMINISTIC eval tier (rides `just eval` and `just gate`).
//!
//! Zero-spend proofs over the committed golden set:
//!
//! * **honesty rail** — every validator FAILS on its untouched fixture (no
//!   free-pass task can enter the corpus);
//! * **mock pipeline** — the shared runner solves the golden set with the mock
//!   backend and the validators DISCRIMINATE (canned solution passes, no-op
//!   fails), and the report renders;
//! * **validator discrimination** — a planted WRONG answer fails the same
//!   validator a correct one passes (regression, RED evidence);
//! * **cap trip** — the cap guard aborts the run before cumulative declared
//!   cost can exceed the cap (regression, RED evidence).

use std::path::Path;

use kata_eval::budget::micro_usd_from_usd;
use kata_eval::runner::{RunConfig, run_eval};
use kata_eval::solver::{MockSolver, SolveOutcome, Solver};
use kata_eval::task::{GoldenTask, MockStrategy, load_tasks, tasks_root};
use kata_eval::validator::{
    copy_dir_recursive, run_validator, run_validator_on_pristine_fixture, tool_available,
};

fn golden_tasks() -> Vec<GoldenTask> {
    load_tasks(&tasks_root()).expect("golden tasks load")
}

/// Tasks whose validator interpreter is present on this host.
fn runnable(tasks: &[GoldenTask]) -> Vec<&GoldenTask> {
    tasks
        .iter()
        .filter(|t| tool_available(&t.required_tool))
        .collect()
}

// ---------------------------------------------------------------------------
// Corpus shape
// ---------------------------------------------------------------------------

/// The corpus is bounded at both ends ON PURPOSE. The floor keeps the published
/// score from resting on a handful of tasks; the ceiling keeps `eval-live` inside
/// its metered cap, since every task is a real metered model run.
///
/// The ceiling is 16 because single-file, single-edit, bug-is-described tasks
/// prove that the PIPELINE ran and almost nothing about capability, so the set also
/// carries tasks that each raise difficulty on another axis: `python-multifile` (the defect
/// spans two modules, so patching the first symptom still fails),
/// `python-diagnose` (the prompt does not name the bug, so the model must run the
/// suite and read the failure), `bash-quoting` (the failure appears only for a
/// hostile input the fixture does not contain), and `rust-trait` (implement to a
/// law, where the obvious answer passes one test and fails another).
#[test]
fn golden_set_is_6_to_16_real_tasks() {
    let tasks = golden_tasks();
    assert!(
        (6..=16).contains(&tasks.len()),
        "the golden set must carry 6–16 tasks, found {}",
        tasks.len()
    );
    // At least two tasks solve in the mock, and at least two fail honestly, so
    // the deterministic tier proves BOTH outcomes.
    let solve = tasks
        .iter()
        .filter(|t| t.mock.strategy == MockStrategy::Solve)
        .count();
    let noop = tasks
        .iter()
        .filter(|t| t.mock.strategy == MockStrategy::Noop)
        .count();
    assert!(solve >= 2, "need ≥2 mock=solve tasks, found {solve}");
    assert!(
        noop >= 2,
        "need ≥2 mock=noop honest-fail tasks, found {noop}"
    );
}

// ---------------------------------------------------------------------------
// Honesty rail — no free-pass tasks
// ---------------------------------------------------------------------------

/// Every task's validator must FAIL on its UNMODIFIED fixture. A validator that
/// passes on the pristine fixture would score a model that did nothing.
#[test]
fn every_validator_fails_on_the_pristine_fixture() {
    let tasks = golden_tasks();
    let mut ran = 0usize;
    for task in &tasks {
        if !tool_available(&task.required_tool) {
            eprintln!(
                "honesty: skipping {} (tool `{}` absent)",
                task.id, task.required_tool
            );
            continue;
        }
        let outcome =
            run_validator_on_pristine_fixture(&task.fixture_dir(), &task.validator_path())
                .unwrap_or_else(|e| panic!("running validator for {}: {e}", task.id));
        assert!(
            !outcome.passed,
            "FREE-PASS TASK: {} validator passed on the unmodified fixture (exit {}). A task whose \
             validator passes with no edits is broken.\noutput:\n{}",
            task.id, outcome.exit_code, outcome.output
        );
        ran += 1;
    }
    assert!(
        ran >= 5,
        "expected ≥5 tasks to run their validator on this host, ran {ran}"
    );
}

// ---------------------------------------------------------------------------
// Mock pipeline — the whole runner, zero spend
// ---------------------------------------------------------------------------

#[test]
fn mock_pipeline_discriminates_and_renders() {
    let tasks = golden_tasks();
    let cfg = RunConfig {
        cap_micro_usd: micro_usd_from_usd(20.0),
        model: "mock".into(),
        backend: "mock".into(),
        date: "2026-07-11".into(),
    };
    let solver = MockSolver::new(micro_usd_from_usd(0.5));
    let report = run_eval(&tasks, &solver, &cfg).expect("mock run");

    // Discrimination: for every task that actually RAN, a solved task passed and
    // a no-op task failed — the validator is not rubber-stamping.
    let by_id: std::collections::HashMap<_, _> = tasks.iter().map(|t| (t.id.clone(), t)).collect();
    let (mut passed, mut failed) = (0usize, 0usize);
    for r in &report.results {
        if r.skipped {
            continue;
        }
        let task = by_id[&r.id];
        match task.mock.strategy {
            MockStrategy::Solve => assert!(
                r.passed,
                "{}: mock applied the canned solution but the validator FAILED (exit {}):\n{}",
                r.id, r.validator_exit_code, r.detail
            ),
            MockStrategy::Noop => assert!(
                !r.passed,
                "{}: mock left the fixture unmodified but the validator PASSED — free pass",
                r.id
            ),
        }
        if r.passed {
            passed += 1;
        } else {
            failed += 1;
        }
    }
    assert!(passed >= 2, "expected ≥2 passing tasks, got {passed}");
    assert!(failed >= 2, "expected ≥2 honest failures, got {failed}");

    // The run did not abort under the generous cap.
    assert!(
        !report.aborted,
        "unexpected abort: {:?}",
        report.abort_reason
    );
    assert!(report.spent_micro_usd <= report.cap_micro_usd);

    // Report renders both faces.
    let md = report.to_markdown();
    assert!(md.contains("| Task | Result |"), "markdown table missing");
    assert!(md.contains("**Totals:**"), "markdown totals missing");
    let json = report.to_json().expect("json render");
    let round: serde_json::Value = serde_json::from_str(&json).expect("json parses");
    assert_eq!(round["kind"], "kata_eval_report");
    assert_eq!(
        usize::try_from(round["totals"]["tasks_passed"].as_u64().unwrap()).unwrap(),
        passed
    );
}

// ---------------------------------------------------------------------------
// Validator discrimination — planted wrong answer FAILS (regression, RED)
// ---------------------------------------------------------------------------

/// For a solve task: the canned solution PASSES its validator, and a planted
/// WRONG answer FAILS it. RED evidence: if the validator rubber-stamped (always
/// exit 0), the wrong-answer branch would pass and this test would fail.
#[test]
fn planted_wrong_answer_fails_the_validator() {
    let tasks = golden_tasks();
    let task = tasks
        .iter()
        .find(|t| t.id == "bash-add" && tool_available(&t.required_tool))
        .expect("bash-add is a runnable solve task");

    // Correct solution passes.
    let good = tempfile::tempdir().unwrap();
    copy_dir_recursive(&task.fixture_dir(), good.path()).unwrap();
    copy_dir_recursive(&task.solution_dir(), good.path()).unwrap();
    let good_outcome = run_validator(&task.validator_path(), good.path()).unwrap();
    assert!(
        good_outcome.passed,
        "canned solution should pass:\n{}",
        good_outcome.output
    );

    // Planted WRONG answer (returns a constant that is not the sum) fails.
    let bad = tempfile::tempdir().unwrap();
    copy_dir_recursive(&task.fixture_dir(), bad.path()).unwrap();
    std::fs::write(
        bad.path().join("lib.sh"),
        "#!/usr/bin/env bash\nadd() { echo 99; }\n",
    )
    .unwrap();
    let bad_outcome = run_validator(&task.validator_path(), bad.path()).unwrap();
    assert!(
        !bad_outcome.passed,
        "planted wrong answer must FAIL the validator, but it passed (validator not discriminating)"
    );
}

// ---------------------------------------------------------------------------
// Cap trip — the guard aborts before overspend (regression, RED)
// ---------------------------------------------------------------------------

/// A solver that reports a fixed FAKE cost, so the runner's cap accounting is
/// driven deterministically without touching a fixture-specific validator.
struct FixedCostSolver {
    cost: u64,
}
impl Solver for FixedCostSolver {
    fn label(&self) -> &'static str {
        "fixed-cost"
    }
    fn solve(&self, _task: &GoldenTask, _workspace: &Path) -> anyhow::Result<SolveOutcome> {
        Ok(SolveOutcome {
            cost_micro_usd: self.cost,
            note: "fixed cost".into(),
            ..SolveOutcome::default()
        })
    }
}

#[test]
fn cap_guard_aborts_before_cumulative_cost_exceeds_cap() {
    let tasks = golden_tasks();
    let runnable_tasks = runnable(&tasks);
    assert!(
        runnable_tasks.len() >= 5,
        "need ≥5 runnable tasks to demonstrate the cap trip"
    );

    // Cap = $3. Each task's declared per-task cap is ≥ $1.5, so the guard must
    // stop the run after at most a couple of tasks. The FAKE cost per task is
    // $1.0 so cumulative measured spend never exceeds the cap either.
    let cap = micro_usd_from_usd(3.0);
    let cfg = RunConfig {
        cap_micro_usd: cap,
        model: "fixed".into(),
        backend: "fixed".into(),
        date: "2026-07-11".into(),
    };
    let solver = FixedCostSolver {
        cost: micro_usd_from_usd(1.0),
    };
    let report = run_eval(&tasks, &solver, &cfg).expect("capped run");

    // The guard tripped: the run aborted, fewer tasks ran than the full set, and
    // measured spend stayed within the cap.
    assert!(
        report.aborted,
        "cap guard did NOT trip — spent {} of cap {}",
        report.spent_micro_usd, report.cap_micro_usd
    );
    assert!(
        report.totals.tasks_run < report.totals.tasks_total,
        "cap guard let every task run ({} of {})",
        report.totals.tasks_run,
        report.totals.tasks_total
    );
    assert!(
        report.spent_micro_usd <= cap,
        "OVERSPEND: metered spend {} exceeded the cap {}",
        report.spent_micro_usd,
        cap
    );
    assert!(report.abort_reason.is_some(), "abort must carry a reason");

    // RED counterfactual: an UNGUARDED runner would run every task and spend the
    // full sum, which exceeds the cap — that overspend is exactly what the guard
    // (removed → this test fails) prevents.
    let unguarded_spend = micro_usd_from_usd(1.0) * runnable_tasks.len() as u64;
    assert!(
        unguarded_spend > cap,
        "test is only meaningful when the unguarded total ({unguarded_spend}) exceeds the cap ({cap})"
    );
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "deterministic_tier/workflows_compile.rs"]
mod workflows_compile;
