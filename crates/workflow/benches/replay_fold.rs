//! Criterion latency bench for the orchestrator
//! replay-fold hot path.
//!
//! On resume — and on every live advance — the runner reconstructs orchestrator
//! DAG state by folding recorded stage completions: it builds a fresh
//! [`Orchestrator`] from the compiled [`ExecutionProgram`], then repeatedly
//! `advance()`s (marking dependency-satisfied stages Ready) and `complete_stage()`s
//! (folding each recorded terminal output) until the DAG is finished. That
//! advance/complete loop is the pure twin of `WorkflowRunner::apply_event`'s
//! ledger fold — it is what a crash-recovery replay pays to rebuild in-RAM
//! execution state from the durable log. This bench measures that fold over a
//! realistic linear chain, with no ledger, worker, or network.
//!
//! Benched through the PUBLIC API only. The compiled program is built ONCE in
//! setup (Starlark compilation is not the hot path — the fold is), then each
//! iteration reconstructs the orchestrator and folds the whole chain to terminal.
//!
//! NOT part of `just gate`; run via `just bench-crate workflow`.
//! `just bench-check` guards it against regression.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_program::orchestrator::Orchestrator;

/// Build a compiled `ExecutionProgram` for a linear `n`-stage chain
/// (`s0 -> s1 -> ... -> s{n-1}`) via the public Starlark compile path. Each stage
/// declares a single boolean output and depends on its predecessor, so the fold
/// below walks the chain one ready stage at a time — the worst case for the
/// advance/complete loop (no parallel fan-out to amortize the ready-set scan).
fn linear_program(n: usize) -> ExecutionProgram {
    use std::fmt::Write as _;
    let mut src = String::new();
    for i in 0..n {
        if i == 0 {
            let _ = writeln!(
                src,
                "s{i} = stage(id = \"s{i}\", prompt = \"do {i}\", outputs = {{\"done\": \"bool\"}})"
            );
        } else {
            let prev = i - 1;
            let _ = writeln!(
                src,
                "s{i} = stage(id = \"s{i}\", prompt = \"do {i}\", depends_on = [s{prev}], \
                 outputs = {{\"done\": \"bool\"}})"
            );
        }
    }
    let _ = writeln!(src, "workflow(\"replay-fold-bench\", root = [s0])");
    compile_starlark_execution_program(&src, "replay_fold_bench.star", &[])
        .expect("linear chain compiles")
}

/// Reconstruct the orchestrator from `program` and fold every stage to
/// `Completed` by driving the advance/complete loop to a finished DAG. Returns
/// the number of stages folded (a black-box sink so the loop is not optimized out).
fn fold_to_completion(program: &ExecutionProgram) -> usize {
    let orch = Orchestrator::from_execution_program(program).expect("orchestrator builds");
    let mut folded = 0usize;
    loop {
        let ready = orch.advance();
        if ready.is_empty() {
            break;
        }
        for name in &ready {
            orch.complete_stage(name, serde_json::json!({ "done": true }))
                .expect("fold completion");
            folded += 1;
        }
    }
    folded
}

fn bench_replay_fold(c: &mut Criterion) {
    let mut group = c.benchmark_group("replay_fold");
    for &n in &[8usize, 32, 128] {
        let program = linear_program(n);
        // Sanity: the fold reaches every stage before we time it.
        assert_eq!(
            fold_to_completion(&program),
            n,
            "fold must reach all {n} stages"
        );
        group.bench_with_input(BenchmarkId::from_parameter(n), &program, |b, program| {
            b.iter(|| black_box(fold_to_completion(black_box(program))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_replay_fold);
criterion_main!(benches);
