//! Workflow-level `max_concurrency` throttle tests for the runner
//! (`crates/workflow/src/runner/`).
#![allow(clippy::large_futures)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kata_test_utils::MockResponse;
use kata_types::workflow::WorkflowDefinition;
use smol_str::SmolStr;
use tokio::sync::Barrier;
use tokio::time::Instant;
use ulid::Ulid;

mod common;
use common::make_definition;

// ---- `parallel`: workflow-level max_concurrency throttle ----
//
// No bound is read from the count the cap is enforced on
// (`WorkflowRunner::in_flight_stage_count`), and none from a sampler racing a
// stage's lifetime:
//
// * The UNTHROTTLED cell's frames share one `MockResponse::Rendezvous` barrier
//   with a party per stage, so the worker answers none of them until every
//   stage is inside it: the run completes only if the runner held them all in
//   flight at once. A runner that waited on one stage before dispatching the
//   next never fills the barrier, and the cell fails on `RUN_BUDGET`.
// * The CAPPED cells hold every frame in the worker on a rendezvous the cell is
//   the other party to, and release the frames one at a time, oldest first.
//   Before each release, once the runner has nothing more it can submit, they
//   read the durable chain's in-flight count through a second, read-only SQLite
//   handle. A held frame cannot complete, so the chain moves only by the
//   runner's own claims, and the count at that point is exact: a runner that
//   ignored the cap has claimed its excess stages by then however slowly it
//   ran, and one that never reached the cap shows fewer.

/// How long a run may take before the cell gives up on it. The unthrottled run
/// has taken 23 s under full L1 suite load.
const RUN_BUDGET: Duration = Duration::from_secs(45);

/// `n` independent (no-dependency) stages `s0..s{n-1}` under `max_concurrency`,
/// with their names.
fn independent_stages(n: usize, max_concurrency: Option<u32>) -> (WorkflowDefinition, Vec<String>) {
    let names: Vec<String> = (0..n).map(|i| format!("s{i}")).collect();
    let stages: Vec<(&str, &[&str])> = names
        .iter()
        .map(|name| (name.as_str(), &[] as &[&str]))
        .collect();
    let mut def = make_definition(&stages);
    def.max_concurrency = max_concurrency;
    (def, names)
}

/// A second, read-only SQLite handle on the rig's `operational.db` — the durable
/// chain read without the dispatcher whose count the cap is enforced on.
fn raw_chain(op_path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second, read-only handle on the rig's operational db")
}

/// One execution's authored stages as the durable chain holds them.
#[derive(Debug)]
struct ChainStages {
    /// Claimed and not yet terminal.
    in_flight: usize,
    /// The most that were ever in flight at once.
    peak: usize,
    /// Terminal.
    settled: usize,
}

/// Fold the attempt-scope LIFECYCLE transitions (`folds_projection = 1`) of
/// `execution` in sequence order: an attempt's first transition is its claim
/// and opens it, a terminal one
/// ([`kata_core::operational::ATTEMPT_TERMINAL_STATES`]) closes it. Only the
/// authored `stages` are counted, so a `/work` apply's `#apply/<stage>` attempt
/// — which takes no `max_concurrency` slot — is not.
fn chain_stages(chain: &rusqlite::Connection, execution: Ulid, stages: &[String]) -> ChainStages {
    let mut lifecycle = chain
        .prepare_cached(
            "SELECT attempt_id, stage_id, resulting_state FROM transitions \
              WHERE execution_id = ?1 AND scope = 'attempt' AND folds_projection = 1 \
              ORDER BY seq",
        )
        .expect("the lifecycle read prepares");
    let rows = lifecycle
        .query_map([execution.to_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .expect("the lifecycle read runs");
    let mut open = BTreeSet::new();
    let mut closed = BTreeSet::new();
    let mut peak = 0;
    for row in rows {
        let (attempt, stage_id, resulting_state) = row.expect("a lifecycle transition decodes");
        if !stages.contains(&stage_id) {
            continue;
        }
        if kata_core::operational::ATTEMPT_TERMINAL_STATES.contains(&resulting_state.as_str()) {
            open.remove(&attempt);
            closed.insert(attempt);
        } else {
            open.insert(attempt);
        }
        peak = peak.max(open.len());
    }
    ChainStages {
        in_flight: open.len(),
        peak,
        settled: closed.len(),
    }
}

/// What the runner's drive has begun, counted at its two test-support seams.
#[derive(Clone, Copy, Debug, Default)]
struct DriveProgress {
    /// Drive-pass iterations (`interleave_before_the_pass_fold`).
    passes: usize,
    /// Stage submissions (`interleave_before_a_stage_submit`).
    submits: usize,
    /// `passes` when the latest submission began.
    pass_of_last_submit: usize,
}

/// Count `execution`'s drive passes and stage submissions. The seams are
/// process globals; nextest runs each cell in its own process.
fn count_drive_progress(execution: Ulid) -> Arc<Mutex<DriveProgress>> {
    let progress = Arc::new(Mutex::new(DriveProgress::default()));
    kata_workflow::test_harness::interleave_before_the_pass_fold({
        let progress = Arc::clone(&progress);
        Arc::new(move |id| {
            if id == execution {
                progress.lock().unwrap().passes += 1;
            }
        })
    });
    kata_workflow::test_harness::interleave_before_a_stage_submit({
        let progress = Arc::clone(&progress);
        Arc::new(move |id, _stage| {
            if id == execution {
                let mut progress = progress.lock().unwrap();
                progress.submits += 1;
                progress.pass_of_last_submit = progress.passes;
            }
        })
    });
    progress
}

/// A capped run and what it left behind.
struct CappedRun {
    outputs: BTreeMap<SmolStr, serde_json::Value>,
    /// The chain's in-flight count just before each release, in release order.
    in_flight_before_each_release: Vec<usize>,
    /// The chain once the run has finished.
    chain: ChainStages,
}

/// Run `n` independent stages under `max_concurrency = Some(cap)` with every
/// frame held in the worker until this cell releases it, oldest first.
///
/// Before release `r` the cell waits until the `r` frames already released are
/// terminal on the chain, the runner has begun the `min(n, cap + r)` submissions
/// a runner honouring the cap can have begun by then, and the drive pass that
/// began the latest of them has iterated again. A pass submits its whole ready
/// set before it iterates, and no unreleased stage can complete, so at that
/// point the runner has claimed everything it will claim before the next
/// release — a breach included.
///
/// # Panics
///
/// When a wait outlasts [`RUN_BUDGET`], naming what the chain, the drive and the
/// worker had reached.
async fn run_capped_holding_every_frame(n: usize, cap: usize) -> CappedRun {
    let (def, stage_names) = independent_stages(n, Some(u32::try_from(cap).unwrap()));
    let stack = common::boot_stack();
    let holds: Vec<Arc<Barrier>> = (0..n).map(|_| Arc::new(Barrier::new(2))).collect();
    for hold in &holds {
        stack.mock.push(MockResponse::Rendezvous(Arc::clone(hold)));
    }
    let execution_id = Ulid::new();
    let progress = count_drive_progress(execution_id);
    let chain = raw_chain(stack.op_path());
    let runner = stack.runner(&def, execution_id).unwrap();
    let run = tokio::spawn(async move { runner.run().await });
    let deadline = Instant::now() + RUN_BUDGET;

    let mut in_flight_before_each_release = Vec::with_capacity(n);
    for (released, hold) in holds.iter().enumerate() {
        let submitted = n.min(cap + released);
        let in_flight = loop {
            let held = chain_stages(&chain, execution_id, &stage_names);
            let drive = *progress.lock().unwrap();
            if held.settled >= released
                && drive.submits >= submitted
                && drive.passes > drive.pass_of_last_submit
            {
                break held.in_flight;
            }
            assert!(
                Instant::now() < deadline,
                "before release {released}, the run did not settle within {RUN_BUDGET:?}: \
                 chain {held:?}, drive {drive:?}, {} frames received",
                stack.mock.calls()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        in_flight_before_each_release.push(in_flight);
        tokio::time::timeout_at(deadline, hold.wait())
            .await
            .unwrap_or_else(|_| panic!("frame {released} never reached the worker to be released"));
    }
    let outputs = tokio::time::timeout_at(deadline, run)
        .await
        .expect("the run finishes once every frame is released")
        .expect("run task panicked")
        .expect("workflow run failed");
    CappedRun {
        outputs,
        in_flight_before_each_release,
        chain: chain_stages(&chain, execution_id, &stage_names),
    }
}

/// max_concurrency = 2 with 5 independent ready stages: before every release
/// the chain holds exactly two stages in flight while two or more remain — the
/// runner reaches the cap and never passes it — and all 5 complete.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn max_concurrency_two_caps_in_flight_and_completes_all() {
    let run = run_capped_holding_every_frame(5, 2).await;
    assert_eq!(
        run.in_flight_before_each_release,
        [2, 2, 2, 2, 1],
        "max_concurrency=2: the stages the chain held in flight before each release"
    );
    assert!(
        run.chain.peak <= 2,
        "throttle max_concurrency=2 breached between releases: {:?}",
        run.chain
    );
    assert_eq!(run.outputs.len(), 5, "all five stages must complete");
    for i in 0..5 {
        // The capsule fold's adopted envelope — the reactor's `"stage"`
        // injection is not a capsule-arm stamp, so assert the recorded outcome
        // itself rather than a carrier field.
        assert_eq!(
            run.outputs[&SmolStr::new(format!("s{i}"))]["kind"],
            "capsule_result"
        );
    }
}

/// max_concurrency = 1 serializes: never more than one stage in flight, and the
/// whole workflow still completes.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn max_concurrency_one_serializes_and_completes() {
    let run = run_capped_holding_every_frame(4, 1).await;
    assert_eq!(
        run.in_flight_before_each_release,
        [1, 1, 1, 1],
        "max_concurrency=1: the stages the chain held in flight before each release"
    );
    assert_eq!(
        run.chain.peak, 1,
        "throttle max_concurrency=1 breached between releases: {:?}",
        run.chain
    );
    assert_eq!(run.outputs.len(), 4, "all four stages must complete");
}

/// max_concurrency = None (default): unthrottled — the runner holds EVERY
/// independent ready stage in flight at once. The four frames share one
/// four-party rendezvous, so no stage is answered until all four are inside the
/// worker: a runner that waited on a stage before dispatching the next never
/// completes. All stages complete.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn max_concurrency_none_is_unthrottled_baseline() {
    const STAGES: usize = 4;
    let (def, stage_names) = independent_stages(STAGES, None);
    let stack = common::boot_stack();
    let everyone = Arc::new(Barrier::new(STAGES));
    for _ in 0..STAGES {
        stack
            .mock
            .push(MockResponse::Rendezvous(Arc::clone(&everyone)));
    }
    let execution_id = Ulid::new();
    let runner = stack.runner(&def, execution_id).unwrap();
    let run = tokio::spawn(async move { runner.run().await });
    let Ok(joined) = tokio::time::timeout(RUN_BUDGET, run).await else {
        panic!(
            "the run did not finish within {RUN_BUDGET:?}: the worker received {} of \
             {STAGES} frames, and answers none until all {STAGES} are inside it",
            stack.mock.calls()
        );
    };
    let outputs = joined
        .expect("run task panicked")
        .expect("workflow run failed");
    assert_eq!(outputs.len(), STAGES, "all four stages must complete");
    // The fold is not blind to concurrency: where four stages were provably held
    // in flight together, it reads four.
    let chain = chain_stages(&raw_chain(stack.op_path()), execution_id, &stage_names);
    assert_eq!(
        chain.peak, STAGES,
        "the rendezvous proved four stages in flight together: {chain:?}"
    );
}

/// Named live-lock regression: two executions share ONE durable
/// authority chain. `fold_to_head` reads only THIS execution's rows, so its applied-watermark advances
/// over this execution's sequences alone. The replay drive's blocked-check
/// therefore compares against the PER-EXECUTION head (`execution_transition_head`),
/// not the global source head — a per-execution watermark could never reach the
/// global head while the log interleaves the other execution's rows, so a
/// global comparison would live-lock one runner. Both executions must fold only
/// their own rows AND terminate.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn replay_two_concurrent_executions_share_one_log_and_both_terminate() {
    // `oci`: one shared rig — ONE durable authority chain — across both
    // executions; the scripted worker answers each capsule frame.
    let stack = common::boot_stack();

    // Two multi-stage executions so each emits several rows that interleave in
    // the shared log.
    let exec_a = Ulid::new();
    let exec_b = Ulid::new();
    let def_a = make_definition(&[("a1", &[]), ("a2", &["a1"]), ("a3", &["a2"])]);
    let def_b = make_definition(&[("b1", &[]), ("b2", &["b1"]), ("b3", &["b2"])]);
    for _ in 0..6 {
        stack
            .mock
            .push(kata_test_utils::MockResponse::Text("done".into()));
    }
    let runner_a = stack.runner(&def_a, exec_a).unwrap();
    let runner_b = stack.runner(&def_b, exec_b).unwrap();

    let ha = tokio::spawn(async move { runner_a.run().await });
    let hb = tokio::spawn(async move { runner_b.run().await });
    let (ra, rb) = tokio::join!(ha, hb);

    let out_a = ra
        .unwrap()
        .expect("execution A must terminate (no live-lock)");
    let out_b = rb
        .unwrap()
        .expect("execution B must terminate (no live-lock)");
    assert!(out_a.contains_key("a3"), "A ran its full chain: {out_a:?}");
    assert!(out_b.contains_key("b3"), "B ran its full chain: {out_b:?}");

    // Both executions contributed rows to the ONE shared log: the global head is
    // the max of the two per-execution heads, and the smaller per-execution head
    // is strictly below the global head — precisely the interleaving that would
    // have live-locked the loser under a global-head blocked-check.
    let face = stack.dispatcher.execution_lifecycle();
    let head_a = face.db().execution_transition_head(exec_a).unwrap();
    let head_b = face.db().execution_transition_head(exec_b).unwrap();
    let global = face.db().read_transition_page(1, 1).unwrap().observed_head;
    assert!(head_a > 0 && head_b > 0, "both executions emitted rows");
    // `<=`, not `==`, and the difference matters.
    //
    // Three OTHER writers share this ledger and outlive the two runners: the
    // embedded worker, the `ResultReactor` (which holds its own `Arc` clone), and
    // the bookkeeper. Only the reactor is aborted, and `abort()` is not a join —
    // it requests cancellation and returns. So a row appended by any of them AFTER
    // both executions' last rows makes `global` legitimately exceed both per-exec
    // heads, and an `assert_eq!` would fail on a scheduling accident that load
    // makes likely (it passes in isolation and flakes at peak suite load).
    //
    // Equality was never the property. What this test is FOR is that both
    // executions contributed rows to ONE shared log and neither live-locked, and
    // that is carried entirely by the two assertions around this one: both heads
    // are non-zero, and the smaller is STRICTLY below the global head. Asserting
    // "and nothing else ever wrote after them" is an assertion about the test's own
    // background tasks, not about the runner.
    assert!(
        head_a.max(head_b) <= global,
        "per-execution heads must live inside the shared log (a={head_a} b={head_b} \
         global={global})"
    );
    assert!(
        head_a.min(head_b) < global,
        "at least one execution's head is strictly below the shared global head \
         (a={head_a} b={head_b} global={global})"
    );

    // Each per-execution read isolates its own rows: no A frame appears in B's
    // read and vice versa — the AUTHORITY CHAIN's per-execution read, the
    // durable plane the replay drive compares against.
    let a_rows = face
        .db()
        .read_transitions_for_execution(exec_a, 1, 10_000)
        .unwrap();
    assert!(
        a_rows.frames.iter().all(|f| f.execution_id == exec_a),
        "exec A read must contain only A's frames"
    );
    let b_rows = face
        .db()
        .read_transitions_for_execution(exec_b, 1, 10_000)
        .unwrap();
    assert!(
        b_rows.frames.iter().all(|f| f.execution_id == exec_b),
        "exec B read must contain only B's frames"
    );
}

/// A stage's `stages.*` is its dependency closure, never what happened to finish
/// first. `b` and `c` are siblings under `a`; under `max_concurrency = 1` the
/// runner completes `b` before it renders `c`, so `b`'s envelope is in the run's
/// outputs when `c` renders. `c` reads `b` inside a statement block, which the
/// load-time reference check does not see, so only the runtime closure decides:
/// the prompt the worker RECEIVED for `c` must say `b` was not visible.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_sibling_completion_is_not_in_the_render_context() {
    let program = common::compile_star(
        r#"
a = stage(id = "a", agent = "default", prompt = "emit")
b = stage(id = "b", agent = "default", depends_on = ["a"], prompt = "emit")
c = stage(
    id = "c",
    agent = "default",
    depends_on = ["a"],
    prompt = "{% if stages.b is defined %}sibling-visible{% else %}sibling-hidden{% endif %} {% if stages.a is defined %}ancestor-visible{% endif %}",
)
workflow("closure-render", root = [a], max_concurrency = 1)
"#,
        "closure-render.star",
    );
    let stack = common::boot_stack();
    stack.mock.push(MockResponse::Text("a-out".into()));
    stack.mock.push(MockResponse::Text("b-out".into()));
    stack.mock.push(MockResponse::Echo);
    let execution_id = Ulid::new();
    let runner = stack.runner_program(&program, execution_id);
    let outputs = tokio::time::timeout(RUN_BUDGET, runner.run())
        .await
        .expect("the run finishes")
        .expect("workflow run failed");
    assert!(
        outputs.contains_key("b") && outputs.contains_key("c"),
        "{outputs:?}"
    );
    let chain = raw_chain(stack.op_path());
    let order: Vec<String> = chain
        .prepare(
            "SELECT stage_id FROM transitions \
              WHERE execution_id = ?1 AND scope = 'attempt' AND folds_projection = 1 \
                AND resulting_state = 'completed' \
              ORDER BY seq",
        )
        .and_then(|mut stmt| {
            stmt.query_map([execution_id.to_bytes().as_slice()], |row| row.get(0))?
                .collect()
        })
        .expect("read the completion order off the raw chain");
    let b_at = order.iter().position(|s| s == "b");
    let c_at = order.iter().position(|s| s == "c");
    assert!(
        b_at < c_at && b_at.is_some(),
        "the cell needs b completed before c: {order:?}"
    );
    assert_eq!(
        stack.mock.delivered_prompt("c").as_deref(),
        Some("sibling-hidden ancestor-visible"),
        "the prompt delivered for c"
    );
}
