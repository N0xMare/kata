//! **Every stage in the shipped corpus carries a positive wall-time bound in the
//! checked IR** — the authoring default, read back off the compiled program.
//!
//! The `timeout_ms` disposition is an AUTHORING default, not an
//! admission refusal and not a node default. It is applied in TWO places, both
//! in the frontend and neither at runtime: `parser::resolve_stage_timeout_ms`
//! for every stage-shaped builtin, and
//! `execution_program::compile_agent_run_execution_program` for the API-shaped
//! `/agents/run` surface. So `ExecutionStagePolicies::timeout_ms` is a `u64` and
//! "this stage has no wall-time bound" has no spelling in the IR at all.
//!
//! The type makes absence unrepresentable, which is the real guarantee. What a
//! type cannot say is that the SUBSTITUTION actually happens — a frontend that
//! filled `0` in, or a lowering that dropped the authored value on the floor and
//! wrote the default over it, would still typecheck. So this file reads the
//! compiled program for every shipped pack and asserts both halves:
//!
//! * every stage's `timeout_ms` is `> 0`; and
//! * every stage carries either [`DEFAULT_STAGE_TIMEOUT_MS`] or a value that
//!   appears as a `timeout_ms =` literal in THAT PACK or one of the sources it
//!   `load()`s, transitively — nowhere else in the corpus.
//!
//! # Why the literal set is scoped to the pack's own `load()` closure
//!
//! It was not, at first: it pooled every `.star` under `workflows/**`, and a
//! substitution that wrote `600_000` over a stage would have passed because some
//! unrelated pack declares `600_000`. A per-pack closure makes the assertion
//! about the pack under test. It is still a SUPERSET of what one stage could
//! declare (a library's own function default counts for every pack that loads
//! it), which is deliberate — the alternative is reimplementing Starlark
//! evaluation in a test, and the `> 0` arm plus the exact-default arm carry the
//! substitution claim.
//!
//! **Would red if:** the frontend stopped substituting (every undeclared stage
//! reads `0`, and the `> 0` arm names them), or the substitution overwrote a
//! declaration with a value the pack's own closure never mentions.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kata_program::execution_program::{ExecutionProgram, compile_execution_program_from_file};
use kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS;

/// `<repo>` — the crate lives at `<repo>/crates/workflow`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/crates/workflow")
        .to_path_buf()
}

/// Loader roots wide enough for any shipped pack's or rig's `load()` targets.
fn loader_roots() -> Vec<PathBuf> {
    let wf = repo_root().join("workflows");
    vec![
        wf.join("std"),
        wf.join("kata-factory"),
        wf.join("examples"),
        wf.join("smoke"),
    ]
}

fn collect_star(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_star(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "star") {
            out.push(path);
        }
    }
}

/// Every shipped pack under the product roots, and every `workflows/smoke` rig,
/// sorted.
fn shipped_packs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for sub in ["std", "kata-factory", "examples", "smoke"] {
        collect_star(&repo_root().join("workflows").join(sub), &mut out);
    }
    out.sort();
    out
}

/// Compile one pack with its own directory prepended to the loader roots.
fn compile(pack: &Path) -> Option<ExecutionProgram> {
    let mut roots = loader_roots();
    if let Some(dir) = pack.parent() {
        roots.insert(0, dir.to_path_buf());
    }
    // A shared Starlark LIBRARY (`workflows/std/kata/std.star`,
    // `workflows/kata-factory/kata/factory.star`) never calls `workflow()` at
    // module scope, so compiling it by path is a category error, not a pack
    // failure. Skipping on compile failure would weaken this suite into
    // vacuity, so the count assertion below is what keeps it honest.
    compile_execution_program_from_file(pack, &roots).ok()
}

/// The `timeout_ms = N` literals a pack's SOURCE declares, in source order.
///
/// Read out of the pack text rather than out of kata, because a suite that asked
/// the compiler what the compiler produced would agree with itself by
/// construction. This is deliberately a superset: a library's `timeout_ms = N`
/// default lands in whatever pack loads it, so the assertion below is that every
/// non-default value in the IR appears in this set — not that the two are equal.
fn declared_literals(source: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find("timeout_ms") {
        rest = &rest[at + "timeout_ms".len()..];
        let after = rest.trim_start();
        let Some(after) = after.strip_prefix('=') else {
            continue;
        };
        let digits: String = after
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '_')
            .collect();
        if let Ok(value) = digits.replace('_', "").parse::<u64>() {
            out.push(value);
        }
    }
    out
}

/// The pack's source plus every source it `load()`s, transitively.
///
/// `load("kata/std.star", ..)` resolves the way the evaluator resolves it: the
/// pack's own directory first, then the loader roots. An unresolvable target is
/// skipped rather than panicked on — it cannot exist for a pack that COMPILED,
/// and a panic here would turn a resolution quirk into a failure about timeouts.
fn load_closure(pack: &Path) -> Vec<String> {
    let mut roots = loader_roots();
    if let Some(dir) = pack.parent() {
        roots.insert(0, dir.to_path_buf());
    }
    let mut pending = vec![pack.to_path_buf()];
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut sources = Vec::new();
    while let Some(path) = pending.pop() {
        if !seen.insert(path.clone()) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for target in load_targets(&text) {
            for root in &roots {
                let candidate = root.join(&target);
                if candidate.is_file() {
                    pending.push(candidate);
                    break;
                }
            }
        }
        sources.push(text);
    }
    sources
}

/// The first string literal of every `load(..)` statement in `source`.
fn load_targets(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("load("))
        .filter_map(|rest| rest.trim_start().strip_prefix('"'))
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn every_shipped_stage_carries_a_positive_timeout_in_the_checked_ir() {
    let packs = shipped_packs();
    assert!(
        packs.len() > 40,
        "the shipped corpus must be walked, found only {} packs — the roots moved",
        packs.len()
    );

    let mut compiled = 0usize;
    let mut stages = 0usize;
    let mut defaulted = 0usize;
    let mut declared = 0usize;
    let mut unbounded: Vec<String> = Vec::new();
    let mut unexplained: Vec<String> = Vec::new();

    for pack in &packs {
        let Some(program) = compile(pack) else {
            continue;
        };
        compiled += 1;
        // THIS pack plus the sources it `load()`s, transitively — not the whole
        // corpus (see the module header for what that hid).
        let mut literals = Vec::new();
        for source in load_closure(pack) {
            literals.extend(declared_literals(&source));
        }

        for (stage_id, stage) in &program.stages {
            stages += 1;
            let timeout_ms = stage.policies.timeout_ms;
            if timeout_ms == 0 {
                unbounded.push(format!("{}::{}", pack.display(), stage_id.0));
                continue;
            }
            if timeout_ms == DEFAULT_STAGE_TIMEOUT_MS {
                defaulted += 1;
            } else {
                declared += 1;
                if !literals.contains(&timeout_ms) {
                    unexplained.push(format!(
                        "{}::{} carries timeout_ms={timeout_ms}, which no `timeout_ms =` literal \
                         in that pack or its `load()` closure declares",
                        pack.display(),
                        stage_id.0
                    ));
                }
            }
        }
    }

    assert!(
        unbounded.is_empty(),
        "every stage in the checked IR must carry a positive wall-time bound — the authoring \
         default is what makes an undeclared `timeout_ms=` impossible. {} stage(s) read 0:\n  {}",
        unbounded.len(),
        unbounded.join("\n  ")
    );
    assert!(
        unexplained.is_empty(),
        "a stage carrying neither DEFAULT_STAGE_TIMEOUT_MS nor a value its own source declares \
         means the frontend invented a bound:\n  {}",
        unexplained.join("\n  ")
    );
    assert!(
        stages > 40 && compiled > 40,
        "the corpus must have been read, not skipped: {compiled} pack(s), {stages} stage(s)"
    );
    assert!(
        defaulted > 0 && declared > 0,
        "this suite proves BOTH halves, so the corpus must hold both: {defaulted} defaulted and \
         {declared} declared stage(s)"
    );
    println!(
        "shipped corpus: {compiled} pack(s), {stages} stage(s) — {defaulted} at the \
         DEFAULT_STAGE_TIMEOUT_MS={DEFAULT_STAGE_TIMEOUT_MS} authoring default, {declared} \
         carrying an authored value"
    );
}

/// **`stage(timeout_ms = 0)` lowers to the default, and a NEGATIVE literal is
/// refused by name** — the two ends of the authoring surface's own spelling.
///
/// `0` is not a bound an author could mean; it is how the `stage()` builtin spells
/// "unset", and the shipped `workflows/std/kata/std.star` helpers
/// (`shell_json_stage`, `workspace_write_stage`) take `timeout_ms = 0` as their own
/// parameter default and forward it. So a rule that refused `0` would refuse the
/// library every shipped shell pack loads — which is why the earlier "zero is
/// refused" reading was wrong at the only surface that can produce it.
///
/// The sign is the one thing only `stage()` can see: by the time the flat field is
/// an `Option<u64>`, a negative literal has no representation, so the refusal has
/// to live in the builtin and this cell holds it there.
///
/// **Would red if:** `0` started refusing (arm one panics on the compile error), or
/// `0` started meaning a zero budget (arm one's `assert_eq` names the value), or the
/// negative refusal moved out of `stage()` and lost its wording (arm two).
#[test]
fn zero_takes_the_default_and_a_negative_timeout_is_refused_by_name() {
    // ONE pack name for both compiles. `authored_span.file` is the pack path, so
    // two different names would make the whole-stage comparison below fail on the
    // span instead of on the budget — and comparing a hand-picked subset of fields
    // would let a future field diverge unwatched.
    const SENTINEL_PACK: &str = "sentinel.star";
    let zero = kata_program::execution_program::compile_starlark_execution_program(
        "a = stage(id = \"a\", run = \":\", agent = \"shell\", timeout_ms = 0)\n\
         workflow(\"zero\", root = [a])\n",
        SENTINEL_PACK,
        &[],
    )
    .expect("timeout_ms = 0 is the DSL's spelling for `unset`, not an error");
    let stage = zero
        .stages
        .get(&kata_types::workflow::StageId(smol_str::SmolStr::new("a")))
        .expect("the stage compiled");
    assert_eq!(
        stage.policies.timeout_ms, DEFAULT_STAGE_TIMEOUT_MS,
        "an explicit `timeout_ms = 0` must resolve to exactly the authoring default, the same as \
         omitting the kwarg"
    );

    let omitted = kata_program::execution_program::compile_starlark_execution_program(
        "a = stage(id = \"a\", run = \":\", agent = \"shell\")\n\
         workflow(\"zero\", root = [a])\n",
        SENTINEL_PACK,
        &[],
    )
    .expect("the omitted spelling compiles");
    assert_eq!(
        omitted.stages, zero.stages,
        "`timeout_ms = 0` and an omitted `timeout_ms=` must be the SAME authoring statement, \
         byte-for-byte in the checked IR — if they diverge, one of them is inventing a bound"
    );

    let error = kata_program::execution_program::compile_starlark_execution_program(
        "a = stage(id = \"a\", run = \":\", agent = \"shell\", timeout_ms = -1)\n\
         workflow(\"negative\", root = [a])\n",
        SENTINEL_PACK,
        &[],
    )
    .expect_err("a negative wall clock is an authoring error");
    let message = error.to_string();
    assert!(
        message.contains("timeout_ms must not be negative"),
        "the refusal must name what it refuses and why: {message}"
    );
}
