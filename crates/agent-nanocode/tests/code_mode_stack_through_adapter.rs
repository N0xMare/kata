//! Code Mode's stack limit, and the thread stack the interpreter runs a cell
//! on, seen through the nanocode adapter and the engine.
//!
//! djs keeps a script's call stack in its heap: past its own slot limit
//! (`ExecOptions::max_stack`) it throws a catchable `RangeError: Maximum call
//! stack size exceeded`, and kata's interpreter process reports the stack
//! limit when that error ends a cell. What a cell's frames cannot reach, the
//! interpreter thread's native stack (`CodeModeLimits::thread_stack_bytes`),
//! still runs djs's own native recursions: its compiler on nested source, its
//! regular-expression parser, and whatever of its runtime recurses in Rust.
//! A thread stack those overflow ends the process the thread runs in by
//! Rust's stack-overflow abort: with kata's backend, the cell's interpreter
//! process, never the process that hosts the worker.
//!
//! The thread stack is the install's, process-wide and once-only, so the
//! cells under a shrunk thread stack run as CHILDREN: this binary re-execs
//! itself to run [`PROBE_CELL`] alone with `THREAD_STACK_ENV` naming the
//! child's thread stack, and the child's cells run in an interpreter process
//! of its own (this binary again: its `interpreter_entry!`).
//!
//! The witnesses do not share the adapter's code: the mock's log of the request
//! bodies it received (what the model was told), the kernel's account of this
//! process's interpreter processes, and the kernel's exit status of each child
//! with the line it prints.

mod code_mode_engine;
#[path = "fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;
#[path = "fixtures/openai_turn.rs"]
#[allow(dead_code)]
mod openai_turn;
#[path = "fixtures/quickjs_threads.rs"]
#[allow(dead_code)]
mod quickjs_threads;
#[path = "fixtures/toolhost_double.rs"]
#[allow(dead_code)]
mod toolhost_double;

use std::process::{Command, Output};
use std::time::Duration;

use kata_agent::adapter::TurnOutcome;
use kata_agent_nanocode::{CODE_MODE_LIMITS, install_code_mode_limits};
use kata_code_mode_host::{CodeModeLimits, Program, install};
use mock_provider::{
    Gate, MockProvider, Reply, call_output, call_outputs, code_reply, message_reply, usage,
};
use nanocode_code_mode_engine::EmbeddedHost;
use openai_turn::{bounded, open, openai, openai_prompt, turn};
use quickjs_threads::{interpreters, once_listed};
use toolhost_double::DoubleConfig;

// The Code Mode limits this binary installs run each cell in an interpreter
// process: this binary, re-executed.
kata_code_mode_host::interpreter_entry!();

/// Set only in a child this binary re-execs: the thread stack, in bytes, its
/// probe cell installs beside kata's other limits.
const THREAD_STACK_ENV: &str = "KATA_TEST_CODE_MODE_THREAD_STACK_BYTES";

/// The probe cell, by its libtest name, which a child runs alone.
const PROBE_CELL: &str = "the_deepest_recursions_under_a_childs_thread_stack";

/// Thread stacks are whole pages.
const PAGE: usize = 4096;

/// djs's own stack-limit error.
const STACK_ERROR: &str = "RangeError: Maximum call stack size exceeded";

/// The interpreter process's report of a stack hit.
const STACK_REPORT: &str = "Code Mode cell exceeded its interpreter stack limit";

/// A cell that waits 500 ms, recurses through `sort`'s comparator until djs's
/// stack limit throws (any other error ends the cell), then recurses through
/// `setTimeout`'s delay coercion until it throws again, and lets that error
/// end the cell.
const DIVE: &str = "await new Promise((resolve) => setTimeout(resolve, 500));\n\
     function sorting() { [2, 1].sort(() => { sorting(); return 0; }); }\n\
     try { sorting(); } catch (error) {\n\
       if (!`${error}`.includes(\"Maximum call stack size exceeded\")) throw error;\n\
     }\n\
     const deeper = { valueOf() { setTimeout(() => {}, deeper); return 0; } };\n\
     setTimeout(() => {}, deeper);";

/// A cell that waits a second, then runs both recursions counting their
/// levels, caught: the cell reports how deep each got and what stopped it.
const COUNTED_DIVE: &str = "await new Promise((resolve) => setTimeout(resolve, 1000));\n\
     let sorted = 0;\n\
     function sorting() { sorted += 1; [2, 1].sort(() => { sorting(); return 0; }); }\n\
     try { sorting(); } catch (error) { text(`sort depth ${sorted}: ${error}`); }\n\
     let delayed = 0;\n\
     const deeper = { valueOf() { delayed += 1; setTimeout(() => {}, deeper); return 0; } };\n\
     try { setTimeout(() => {}, deeper); } catch (error) {\n\
       text(`setTimeout depth ${delayed}: ${error}`);\n\
     }";

/// **A model-written cell that recurses through host calls until djs's stack
/// limit trips fails to the model, and the turn goes on.** Under kata's limits
/// the model's first cell recurses through `sort`'s comparator, catches the
/// stack error, then recurses through `setTimeout`'s delay coercion; the next
/// request hands the model that cell's failure naming djs's stack error, not
/// an interpreter's end. The model's second cell runs both recursions counted
/// and caught, in an interpreter process of its own (the kernel lists one
/// while the first cell waits, the model's second cell held until then, and
/// one while the second waits before it recurses), and both depths reach the
/// third request; the turn completes. Just before the first cell's error the
/// interpreter process reports the stack limit, which the model is handed as
/// an output of its own and the evidence records as one
/// `CodeModeLimit{stack}`; the second cell caught both its stack errors, so
/// nothing reports it.
///
/// **Would red if:** the interpreter did not report a stack hit
/// (`interpreter::forward`'s `notify(cell_id, STACK_REPORT)` removed), or the
/// adapter did not record its report (`CodeModeLimit{stack}`).
#[tokio::test]
async fn a_cell_recursing_through_host_calls_to_the_stack_limit_fails_to_the_model_and_the_turn_goes_on()
 {
    install_code_mode_limits();
    let first_listed = Gate::default();
    let mock = MockProvider::start(vec![
        code_reply("r1", DIVE, usage(1, 0, 1)),
        Reply::Gated(
            first_listed.clone(),
            Box::new(code_reply("r2", COUNTED_DIVE, usage(1, 0, 1))),
        ),
        message_reply("r3", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let prompt = openai_prompt("recurse");

    let (outcome, (diving, next_running)) = tokio::join!(turn(session.as_mut(), &prompt), async {
        // On the kernel's listing, not on a sleep: a host starts on its own
        // schedule, and only the held second cell could start another.
        let diving = bounded("the first cell's host", once_listed(1, interpreters)).await;
        first_listed.open();
        mock.wait_for_requests(2).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        (diving, interpreters())
    });

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        3,
        "one model call per response: {outcome:?}"
    );
    let failed = call_output(&requests[1], "call_r1").expect("the model was told the first cell");
    assert!(
        failed.contains("Script failed") && failed.contains(STACK_ERROR),
        "the first cell's output names djs's stack error: {failed}"
    );
    let counted = call_output(&requests[2], "call_r2").expect("the model was told the second cell");
    let sorted = depth(&counted, "sort");
    let delayed = depth(&counted, "setTimeout");
    assert!(
        sorted > 1
            && delayed > 1
            && counted.matches(STACK_ERROR).count() == 2
            && !counted.contains("Script failed"),
        "the cell after the stack hit ran and both recursions stopped at the stack limit: \
         {counted}"
    );
    eprintln!(
        "under memory_bytes {} and thread_stack_bytes {}: recursion through sort's comparator \
         {sorted} levels, through setTimeout's delay coercion {delayed} levels",
        CODE_MODE_LIMITS.memory_bytes, CODE_MODE_LIMITS.thread_stack_bytes
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a stack hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(
        diving.len(),
        1,
        "one interpreter while the first cell waits: {diving:?}"
    );
    assert_eq!(
        next_running.len(),
        1,
        "one interpreter while the second cell waits: {next_running:?}"
    );
    assert_eq!(
        call_outputs(&requests[1], "call_r1")
            .into_iter()
            .skip(1)
            .collect::<Vec<_>>(),
        [serde_json::json!(STACK_REPORT)],
        "the model is handed the interpreter's report of the stack limit"
    );
    let evidence = session.take_evidence();
    let recorded: Vec<_> = evidence
        .events
        .iter()
        .filter(|event| {
            matches!(
                event,
                kata_types::agent::SessionEvidenceEvent::CodeModeLimit { .. }
            )
        })
        .collect();
    assert_eq!(
        recorded,
        [&kata_types::agent::SessionEvidenceEvent::CodeModeLimit {
            which: "stack".into(),
        }],
        "the evidence records the first cell's stack hit once: {:?}",
        evidence.events
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// The depth the counted cell reports for the recursion named `label`.
fn depth(counted: &str, label: &str) -> u64 {
    counted
        .split_once(&format!("{label} depth "))
        .and_then(|(_, rest)| rest.split_once(':'))
        .and_then(|(depth, _)| depth.parse().ok())
        .unwrap_or_else(|| panic!("the second cell reports its {label} depth: {counted}"))
}

/// The deepest recursions a cell can write, one cell each, every one caught
/// so its cell completes and notifies how it ended: through `sort`'s
/// comparator and through `setTimeout`'s delay coercion (the two shapes that
/// call back into the script from a native step), plain recursion, djs's
/// compiler on the most deeply nested source of each of eight shapes it
/// accepts (`eval`, whose parser bounds its own depth: each cell bisects to
/// that bound), its regular-expression parser on the most deeply nested groups
/// it accepts (bisected the same way), `JSON.parse` and
/// `JSON.stringify` and `String` on a deeply nested array, a deep chain of
/// `Proxy` objects and of bound functions, and a collection walking a long
/// linked list.
const SHAPES: [(&str, &str); 12] = [
    (
        "sort",
        "let n = 0;\n\
         function s() { n += 1; [2, 1].sort(() => { s(); return 0; }); }\n\
         try { s(); notify(`sort ${n}`); } catch (e) { notify(`sort ${n} ${e}`); }",
    ),
    (
        "setTimeout",
        "let n = 0;\n\
         const d = { valueOf() { n += 1; setTimeout(() => {}, d); return 0; } };\n\
         try { setTimeout(() => {}, d); notify(`setTimeout ${n}`); } catch (e) { notify(`setTimeout ${n} ${e}`); }",
    ),
    (
        "plain",
        "let n = 0;\n\
         function f() { n += 1; f(); }\n\
         try { f(); notify(`plain ${n}`); } catch (e) { notify(`plain ${n} ${e}`); }",
    ),
    (
        "nested source",
        "const deepest = (accepts) => {\n\
           let lo = 0, hi = 100000;\n\
           while (lo < hi) { const mid = Math.ceil((lo + hi) / 2); if (accepts(mid)) lo = mid; else hi = mid - 1; }\n\
           return lo;\n\
         };\n\
         const out = [];\n\
         for (const [what, open, close] of [['array', '[', ']'], ['paren', '(', ')'], ['block', '{', '}'], ['arrow', '() => ', ''], ['unary', '- ', ''], ['template', '`${', '}`'], ['call', 'f(', ')'], ['object', '({a:', '})']]) {\n\
           const source = (d) => `const f = (x) => x;\\n${open.repeat(d)}1${close.repeat(d)};`;\n\
           const parses = (d) => { try { eval(source(d)); return true; } catch (e) { return false; } };\n\
           out.push(`${what} ${deepest(parses)}`);\n\
         }\n\
         notify(`nested source ${out.join(', ')}`);",
    ),
    (
        "regexp",
        "let lo = 0, hi = 100000;\n\
         while (lo < hi) {\n\
           const mid = Math.ceil((lo + hi) / 2);\n\
           let ok = false;\n\
           try { new RegExp('('.repeat(mid) + 'a' + ')'.repeat(mid)).test('a'); ok = true; } catch {}\n\
           if (ok) lo = mid; else hi = mid - 1;\n\
         }\n\
         notify(`regexp ${lo}`);",
    ),
    (
        "JSON.parse",
        "const out = [];\n\
         for (const d of [4999, 5000, 100000]) {\n\
           try { JSON.parse('['.repeat(d) + ']'.repeat(d)); out.push(`${d} ok`); }\n\
           catch (e) { out.push(`${d} ${e.name}`); }\n\
         }\n\
         notify(`JSON.parse ${out.join(', ')}`);",
    ),
    (
        "JSON.stringify",
        "let a = [];\n\
         for (let i = 0; i < 100000; i++) a = [a];\n\
         try { notify(`JSON.stringify ${JSON.stringify(a).length}`); } catch (e) { notify(`JSON.stringify ${e.name}`); }",
    ),
    (
        "String",
        "let a = [1];\n\
         for (let i = 0; i < 100000; i++) a = [a];\n\
         try { notify(`String ${String(a).length}`); } catch (e) { notify(`String ${e.name}`); }",
    ),
    (
        "Proxy",
        "let p = { x: 1 };\n\
         for (let i = 0; i < 100000; i++) p = new Proxy(p, {});\n\
         try { notify(`Proxy ${p.x}`); } catch (e) { notify(`Proxy ${e.name}`); }",
    ),
    (
        "bind",
        "let f = () => 1;\n\
         for (let i = 0; i < 100000; i++) f = f.bind(null);\n\
         try { notify(`bind ${f()}`); } catch (e) { notify(`bind ${e.name}`); }",
    ),
    (
        "prototype chain",
        "let o = { x: 1 };\n\
         for (let i = 0; i < 100000; i++) o = Object.create(o);\n\
         try { notify(`prototype chain ${o.x} ${o.y}`); } catch (e) { notify(`prototype chain ${e.name}`); }",
    ),
    (
        "collection",
        "let list = null;\n\
         for (let i = 0; i < 1000000; i++) list = { next: list };\n\
         let garbage = 0;\n\
         for (let i = 0; i < 200000; i++) garbage += [i, i].length;\n\
         notify(`collection ${garbage}`);",
    ),
];

/// **In a child: every shape of [`SHAPES`] under the child's thread stack.**
/// With `THREAD_STACK_ENV`, it installs kata's limits with that thread stack,
/// runs each shape as a cell of its own on one host, and prints one JSON line:
/// each shape's notification, or, for a shape whose cell failed, its error and
/// report, and every interpreter process the kernel listed. In the suite,
/// without `THREAD_STACK_ENV`, it does nothing.
#[tokio::test]
async fn the_deepest_recursions_under_a_childs_thread_stack() {
    let Ok(bytes) = std::env::var(THREAD_STACK_ENV) else {
        return;
    };
    install(
        CodeModeLimits {
            thread_stack_bytes: bytes.parse().expect("a child's thread stack in bytes"),
            ..CODE_MODE_LIMITS
        },
        Program::this_executable(),
    )
    .expect("the only limits this child installs");
    let mut host = EmbeddedHost::spawn().expect("a host");
    let mut shapes = serde_json::Map::new();
    let mut listed = std::collections::BTreeSet::new();
    for (id, (name, source)) in (1..).zip(SHAPES) {
        let cell = code_mode_engine::run(&mut host, id, source).await;
        listed.extend(interpreters());
        let outcome = match cell.error {
            None => serde_json::json!({ "notified": cell.notified }),
            Some(error) => serde_json::json!({ "error": error, "reported": cell.reported }),
        };
        shapes.insert(name.to_owned(), outcome);
    }
    host.terminate().await;
    println!(
        "\n{}",
        serde_json::json!({ "shapes": shapes, "interpreters": listed.len() })
    );
}

/// What a child running [`PROBE_CELL`] under a thread stack reported.
struct Probe {
    output: Output,
    /// Its printed line: `shapes` and `interpreters`.
    printed: serde_json::Value,
}

impl Probe {
    /// The shapes whose cell failed, with their reports.
    fn failed(&self) -> Vec<(String, serde_json::Value)> {
        self.printed["shapes"]
            .as_object()
            .map(|shapes| {
                shapes
                    .iter()
                    .filter(|(_, outcome)| outcome.get("error").is_some())
                    .map(|(name, outcome)| (name.clone(), outcome.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Runs [`PROBE_CELL`] alone in a child of this binary with
/// `thread_stack_bytes` as its interpreter's cell thread stack.
fn probe(thread_stack_bytes: usize) -> Probe {
    let output = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", PROBE_CELL, "--nocapture", "--test-threads=1"])
        .env(THREAD_STACK_ENV, thread_stack_bytes.to_string())
        .output()
        .expect("run the probe cell in a child");
    let printed = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| serde_json::from_str(line).ok())
        .unwrap_or(serde_json::Value::Null);
    Probe { output, printed }
}

/// Whether every shape completed under `thread_stack_bytes`, and the probe;
/// panics on any outcome but that or an interpreter ended by its cell
/// thread's stack overflow, with the child itself passing, so a search never
/// reads another failure as either.
fn survives(thread_stack_bytes: usize) -> (bool, Probe) {
    let probe = probe(thread_stack_bytes);
    assert!(
        probe.output.status.success() && probe.printed.is_object(),
        "a {thread_stack_bytes}-byte thread stack ended the child itself: {:?}\n{}",
        probe.output.status,
        String::from_utf8_lossy(&probe.output.stderr)
    );
    let failed = probe.failed();
    for (name, outcome) in &failed {
        assert!(
            ended_by_its_stack_overflow(outcome),
            "a {thread_stack_bytes}-byte thread stack failed shape {name} other than by its \
             interpreter's stack overflow: {outcome}"
        );
    }
    (failed.is_empty(), probe)
}

/// Candidates one round of the search tries at once, each in a child of its
/// own: a round narrows the range to one of `CANDIDATES + 1` parts, so the
/// search takes four rounds where a bisection takes eleven.
const CANDIDATES: usize = 8;

/// Whether a failed shape's `outcome` is its interpreter process ended by
/// Rust's stack-overflow abort on the cell thread: the supervisor's report of
/// the end, and the interpreter's standard error naming the thread.
fn ended_by_its_stack_overflow(outcome: &serde_json::Value) -> bool {
    let reported = outcome["reported"].as_str().unwrap_or_default();
    let error = outcome["error"].as_str().unwrap_or_default();
    reported.starts_with(kata_code_mode_host::ENDED_BY)
        && error.contains("thread 'code-mode-cell'")
        && error.contains("has overflowed its stack")
}

/// **A thread stack too small for a cell's recursions ends only its
/// interpreter process.** A child runs every shape under a 64 KiB cell thread
/// stack: the child (the process hosting the worker) exits 0 having printed
/// every shape's outcome, at least one shape's cell failed with the
/// supervisor's report of its interpreter's end by Rust's stack-overflow abort
/// on the cell thread, and the cells after it ran in a new interpreter
/// process.
///
/// **Would red if:** the cell thread's stack were not the install's
/// (`interpreter::serve`'s `stack_size(limits.thread_stack_bytes)` dropped: the
/// thread gets Rust's default 2 MiB, on which every shape completes), or a
/// cell ran in the process hosting the worker (the child dies by the abort).
#[test]
fn a_thread_stack_too_small_ends_only_the_interpreter() {
    let probe = probe(64 << 10);
    assert!(
        probe.output.status.success(),
        "the child ended {:?}:\n{}",
        probe.output.status,
        String::from_utf8_lossy(&probe.output.stderr)
    );
    let failed = probe.failed();
    eprintln!("under a 64 KiB thread stack: {}", probe.printed);
    assert!(!failed.is_empty(), "no shape overflowed: {}", probe.printed);
    for (name, outcome) in &failed {
        assert!(ended_by_its_stack_overflow(outcome), "{name}: {outcome}");
    }
    assert!(
        probe.printed["interpreters"].as_u64() > Some(1),
        "an interpreter ended and the next cell started another: {}",
        probe.printed
    );
}

/// **kata's thread stack is at least twice what the deepest recursions
/// need.** Children search, to the page, [`CANDIDATES`] at a time, the
/// smallest cell thread stack on
/// which every shape of [`SHAPES`] completes, between one that overflows and
/// kata's `thread_stack_bytes` (which must pass); kata's must be at least twice
/// it, so a change to `CODE_MODE_LIMITS` that eats the headroom, or a bump
/// that widens djs's native frames past half of it, is red here.
///
/// MEASURED on this host's test build (djs and the vendored engine at the dev
/// profile's opt-level 2 for dependencies): 372 KiB, with 368 KiB overflowing
/// in the regular-expression shape alone (211 nested groups, its parser's
/// bound); kata's 8 MiB is 22 times it. On kata's stack the compiler accepts
/// nesting 182 deep for arrays, parentheses and templates, 273 for arrows and
/// calls, 546 for blocks and unary operators, 91 for object literals; the
/// script recursions djs keeps in its heap stop on its stack error (`sort`'s
/// comparator after 20,971 levels, `setTimeout`'s coercion after 15,419, plain
/// recursion after 131,068) and complete on a 64 KiB stack as well, as do the
/// `Proxy` chain, the bound functions, the prototype chain and `JSON.parse`;
/// the compiler, the regular-expression parser, the nested `JSON.stringify` and
/// `String`, and the collection of the long list each overflow 64 KiB. It is a
/// bound for these shapes, not for every recursion a cell can write.
///
/// **Would red if:** `CODE_MODE_LIMITS.thread_stack_bytes` fell below twice the
/// need, or the interpreter's cell thread ignored it (`interpreter::serve`'s
/// `stack_size(limits.thread_stack_bytes)` dropped: no stack below Rust's
/// default overflows, and the search finds no overflowing stack to start
/// from).
#[test]
fn kata_thread_stack_is_twice_what_the_deepest_recursions_need() {
    let (passes_on_katas, on_katas) = survives(CODE_MODE_LIMITS.thread_stack_bytes);
    assert!(
        passes_on_katas,
        "every shape completes on kata's own thread stack: {}",
        on_katas.printed
    );
    let mut overflows = 64 << 10;
    let (passes_at_floor, mut just_short) = survives(overflows);
    assert!(
        !passes_at_floor,
        "a {overflows}-byte thread stack overflows"
    );
    let mut passes = CODE_MODE_LIMITS.thread_stack_bytes;
    while passes - overflows > PAGE {
        let step = (passes - overflows).div_ceil(CANDIDATES + 1).div_ceil(PAGE) * PAGE;
        let candidates: Vec<usize> = (1..=CANDIDATES)
            .map(|part| overflows + part * step)
            .filter(|candidate| *candidate < passes)
            .collect();
        let outcomes: Vec<(usize, bool, Probe)> = std::thread::scope(|scope| {
            let running: Vec<_> = candidates
                .iter()
                .map(|&candidate| {
                    scope.spawn(move || {
                        let (survived, probe) = survives(candidate);
                        (candidate, survived, probe)
                    })
                })
                .collect();
            running
                .into_iter()
                .map(|child| child.join().expect("a search child"))
                .collect()
        });
        for (candidate, survived, probe) in outcomes {
            if survived {
                passes = passes.min(candidate);
            } else if candidate > overflows {
                overflows = candidate;
                just_short = probe;
            }
        }
        assert!(
            overflows < passes,
            "a thread stack overflows above one that passes: {overflows} >= {passes}"
        );
    }
    let needed = passes;
    let set_by: Vec<String> = just_short
        .failed()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    eprintln!(
        "smallest cell thread stack every shape completes on: {} KiB ({} KiB overflows, in \
         {set_by:?}); kata's thread_stack_bytes {} KiB is {} times it, rounded down",
        needed / 1024,
        overflows / 1024,
        CODE_MODE_LIMITS.thread_stack_bytes / 1024,
        CODE_MODE_LIMITS.thread_stack_bytes / needed,
    );
    eprintln!("every shape on kata's thread stack: {}", on_katas.printed);
    assert!(
        CODE_MODE_LIMITS.thread_stack_bytes >= 2 * needed,
        "kata's {}-byte thread stack is less than twice the {needed} bytes the recursions need",
        CODE_MODE_LIMITS.thread_stack_bytes
    );
}
