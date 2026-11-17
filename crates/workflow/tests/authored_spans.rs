//! Every authored stage carries its `pack.star:LINE:COL`.
//!
//! # The oracle is the PACK BYTES, not the compiler
//!
//! A test that asked the compiler "which line did you record?" and compared it to
//! the compiler's own answer would pass on any line at all. So every assertion
//! here re-reads the `.star` file from disk and checks that the recorded line
//! really contains the builtin call the span claims minted the stage. The pack
//! text is authored by hand and never produced by the code under test, which is
//! what makes it an independent oracle.
//!
//! # Refused set, stated
//!
//! What these tests refuse:
//!
//! * a shipped-pack stage with NO span, or a span whose line does not contain the
//!   minting builtin's name (`stage(` / `sleep(` / `subworkflow(` / `parallel(` /
//!   `memory_snapshot(`);
//! * a span whose `file` is anything but a basename — a `/` anywhere in it would
//!   be a host path leaking into a content-hashed IR (locked authoring rule);
//! * a whitespace-only pack edit that moves ANY stage's `contract_hash`;
//! * a whitespace-only pack edit that does NOT move the serialized stage bytes
//!   (i.e. the span was never recorded there in the first place).
//!
//! What they do NOT claim: that the COLUMN is the column of the builtin name
//! (starlark's call span begins at the callee expression, which for a method-style
//! or parenthesized call need not be the bare name), and nothing about spans
//! inside a prompt template — a `{{ ref }}` maps to the stage's call site, which
//! is the coarse span compile threads, not a template source-map.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kata_program::execution_program::{
    ExecutionProgram, ExecutionProgramStage, compile_execution_program_from_file,
    compile_starlark_execution_program,
};
use kata_types::workflow::{StageId, SynthesizedStage};

/// Below this many compiled packs the corpus walk has stopped seeing the shipped
/// library (53 today) — the same floor `program_body_hash.rs` and
/// `typed_lowering_corpus.rs` use, so a broken walk reds instead of vacuously
/// passing.
const PACK_FLOOR: usize = 20;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workflow crate lives under <repo>/crates/workflow")
        .to_path_buf()
}

fn loader_roots() -> Vec<PathBuf> {
    let workflows = repo_root().join("workflows");
    vec![
        workflows.join("std"),
        workflows.join("examples"),
        workflows.join("kata-factory"),
        workflows.join("smoke"),
    ]
}

/// Root-level `.star` packs of `workflows/std`, `workflows/examples` and
/// `workflows/smoke`, sorted.
fn corpus_packs() -> Vec<PathBuf> {
    let workflows = repo_root().join("workflows");
    let mut packs = Vec::new();
    for dir in [
        workflows.join("std"),
        workflows.join("examples"),
        workflows.join("smoke"),
    ] {
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "star") {
                packs.push(path);
            }
        }
    }
    packs.sort();
    packs
}

fn compiled_corpus() -> Vec<(PathBuf, ExecutionProgram)> {
    let compiled: Vec<(PathBuf, ExecutionProgram)> = corpus_packs()
        .into_iter()
        .filter_map(|path| {
            compile_execution_program_from_file(&path, &loader_roots())
                .ok()
                .map(|program| (path, program))
        })
        .collect();
    assert!(
        compiled.len() >= PACK_FLOOR,
        "the corpus walk must see the shipped library: only {} packs compiled",
        compiled.len()
    );
    compiled
}

/// THE ORACLE SIDE: every `.star` file under `workflows/`, grouped by basename.
///
/// A span records only the basename (the whole point — no host path reaches the
/// IR), so resolving it back to bytes means walking the source tree ourselves.
///
/// Candidates are collected as a LIST per basename rather than collapsed to one
/// path, and ambiguity is refused at LOOKUP (see [`resolve_oracle`]) rather than
/// here: a duplicated basename somewhere else under `workflows/` — a second
/// `README.star`, a vendored copy — says nothing about whether the basenames these
/// tests actually reference are ambiguous, and failing the whole row on it would
/// be a refusal wider than its mechanism.
fn star_files_by_basename() -> BTreeMap<String, Vec<PathBuf>> {
    fn walk(dir: &Path, out: &mut BTreeMap<String, Vec<PathBuf>>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "star") {
                let name = path
                    .file_name()
                    .expect("a file has a name")
                    .to_string_lossy()
                    .into_owned();
                out.entry(name).or_default().push(path);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(&repo_root().join("workflows"), &mut out);
    for candidates in out.values_mut() {
        candidates.sort();
    }
    out
}

/// Resolve ONE referenced basename to the single `.star` file it names.
///
/// Refused set: the basename names no shipped `.star` file, or it names more than
/// one — only then is the ambiguity this test's problem, because only then can it
/// not read the bytes the span points at.
fn resolve_oracle<'a>(
    oracle: &'a BTreeMap<String, Vec<PathBuf>>,
    file: &str,
    context: &str,
) -> &'a Path {
    let candidates = oracle.get(file).map(Vec::as_slice).unwrap_or_default();
    match candidates {
        [only] => only,
        [] => panic!("{context}: span names {file:?}, which is not a shipped `.star` file"),
        many => panic!(
            "{context}: span names {file:?}, which is ambiguous — {} shipped files carry that basename ({}), so the recorded span cannot be resolved to bytes",
            many.len(),
            many.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Which builtin MINTED this stage, as the token its authoring line must contain.
fn minting_builtin(stage: &ExecutionProgramStage) -> &'static str {
    if stage.synthesized == Some(SynthesizedStage::ParallelJoin) {
        "parallel("
    } else if stage.durable_sleep.is_some() {
        "sleep("
    } else if stage.subworkflow.is_some() {
        "subworkflow("
    } else if stage.memory_snapshot.is_some() {
        "memory_snapshot("
    } else {
        "stage("
    }
}

/// Read the 1-based `line` out of `path`'s bytes.
fn source_line(path: &Path, line: u32) -> String {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("reading the oracle {}: {e}", path.display()));
    let index = usize::try_from(line).expect("a line number fits usize");
    assert!(index >= 1, "spans are 1-based; got line {line}");
    text.lines()
        .nth(index - 1)
        .unwrap_or_else(|| {
            panic!(
                "{} has fewer than {line} lines, so the recorded span points past the file",
                path.display()
            )
        })
        .to_owned()
}

/// Assert one stage's span against the pack bytes it claims to come from.
fn assert_span_matches_source(
    label: &str,
    stage_id: &StageId,
    stage: &ExecutionProgramStage,
    oracle: &BTreeMap<String, Vec<PathBuf>>,
) {
    let span = stage.authored_span.as_ref().unwrap_or_else(|| {
        panic!("{label}: stage {} carries no authored_span", stage_id.0);
    });
    assert!(
        !span.file.contains('/'),
        "{label}: stage {} span file {:?} is not a basename — a host path in a \
         content-hashed IR is refused by the locked authoring rule",
        stage_id.0,
        span.file
    );
    let source = resolve_oracle(
        oracle,
        &span.file,
        &format!("{label}: stage {}", stage_id.0),
    );
    let expected = minting_builtin(stage);
    let text = source_line(source, span.line);
    assert!(
        text.contains(expected),
        "{label}: stage {} claims {span}, but that line reads {text:?} — it does \
         not contain the minting builtin {expected:?}",
        stage_id.0
    );
}

/// (a) Every stage of every shipped pack carries a span whose line, READ FROM THE
/// PACK BYTES, contains the call that minted it, and whose file is a basename.
#[test]
fn every_shipped_stage_span_points_at_its_minting_call() {
    let oracle = star_files_by_basename();
    let mut checked = 0usize;
    for (path, program) in compiled_corpus() {
        let label = path.file_name().unwrap().to_string_lossy().into_owned();
        for (stage_id, stage) in &program.stages {
            if stage.synthesized.is_some() {
                // Covered by `synthesized_barrier_span_is_the_parallel_call`.
                continue;
            }
            assert_span_matches_source(&label, stage_id, stage, &oracle);
            checked += 1;
        }
    }
    assert!(
        checked >= PACK_FLOOR,
        "the shipped corpus must present authored stages to check; saw {checked}"
    );
}

/// (a, continued) `sleep()` and `subworkflow()` mint stages no shipped pack
/// carries, so their spans are proved against inline packs — same oracle shape
/// (the authored text), just held in this file.
#[test]
fn sleep_and_subworkflow_spans_point_at_their_own_builtin() {
    // Line 1 is blank, so the asserted lines below are not line 1 by accident. A
    // `sleep()` must sit BETWEEN stages (it cannot be a root), hence `up`/`down`.
    let source = concat!(
        "\n",
        "up = stage(id = \"up\", agent = \"shell\", run = \"echo up\")\n",
        "napped = sleep(for_ms = 1000, depends_on = [up])\n",
        "down = stage(id = \"down\", agent = \"shell\", run = \":\", depends_on = [napped])\n",
        "child = subworkflow(pack = \"downstream\", depends_on = [down])\n",
        "workflow(\"spans-inline\", root = child)\n",
    );
    // The child is bound at check, so the pack compiles through a library holding it.
    let library = tempfile::tempdir().expect("library tempdir");
    std::fs::write(
        library.path().join("downstream.star"),
        "only = stage(id = \"only\", agent = \"shell\", run = \":\")\n\
         workflow(\"downstream-wf\", root = only)\n",
    )
    .expect("write the child pack");
    let program = compile_starlark_execution_program(
        source,
        "spans_inline.star",
        &[library.path().to_path_buf()],
    )
    .expect("the inline sleep/subworkflow pack compiles");

    let lines: Vec<&str> = source.lines().collect();
    let mut seen_sleep = false;
    let mut seen_subworkflow = false;
    for (stage_id, stage) in &program.stages {
        let span = stage
            .authored_span
            .as_ref()
            .unwrap_or_else(|| panic!("stage {} carries no authored_span", stage_id.0));
        assert_eq!(span.file, "spans_inline.star");
        let text = lines[usize::try_from(span.line).unwrap() - 1];
        let expected = minting_builtin(stage);
        assert!(
            text.contains(expected),
            "stage {} claims {span}, but that line reads {text:?} (wanted {expected:?})",
            stage_id.0
        );
        seen_sleep |= expected == "sleep(";
        seen_subworkflow |= expected == "subworkflow(";
    }
    assert!(seen_sleep, "the inline pack must present a sleep() stage");
    assert!(
        seen_subworkflow,
        "the inline pack must present a subworkflow() stage"
    );
}

/// (b) The one stage no author wrote still has a truthful origin: the
/// `parallel()` CALL that minted it.
///
/// `synthesized` — not an absent span — is what says nobody authored it, so the
/// barrier is deliberately NOT span-less: an operator asking "where did
/// `__parallel_join_0` come from" gets the line they can act on.
#[test]
fn synthesized_barrier_span_is_the_parallel_call() {
    let oracle = star_files_by_basename();
    let mut barriers = 0usize;
    for (path, program) in compiled_corpus() {
        let label = path.file_name().unwrap().to_string_lossy().into_owned();
        for (stage_id, stage) in &program.stages {
            if stage.synthesized != Some(SynthesizedStage::ParallelJoin) {
                continue;
            }
            assert_span_matches_source(&label, stage_id, stage, &oracle);
            barriers += 1;
        }
    }
    assert!(
        barriers > 0,
        "the shipped corpus must contain at least one parallel() barrier to check"
    );
}

/// The bytes of a program's STAGES map alone — the span-bearing material, isolated
/// from `ExecutionProgram.source.source_hash`.
///
/// `program_hash` folds the source bytes as well, so it would move on ANY
/// whitespace edit whether or not a span was ever recorded; serializing the
/// stages alone is what makes the rotation below attributable to the span.
fn stage_bytes(program: &ExecutionProgram) -> Vec<u8> {
    serde_json::to_vec(&program.stages).expect("the checked stages serialize")
}

/// (c) A whitespace-only edit rotates the SERIALIZED STAGES (the span moved with
/// the line) and leaves EVERY `contract_hash` byte-identical (the span is not
/// contract).
///
/// This is the cache-correctness half of authored spans: re-indenting a pack must not
/// invalidate a single cached stage result.
///
/// WHY THE STAGE BYTES AND NOT `program_hash`: the whole-program hash also folds
/// `source.source_hash`, the hash of the exact pack bytes, so it moves on any
/// whitespace edit whether or not a span was ever recorded — asserting on it here
/// would pass with the span never threaded at all, which is the vacuity this row
/// exists to avoid. That `program_hash` rotates is a true COROLLARY of the stage
/// bytes moving, not evidence for it, and it is pinned where it belongs: the
/// golden `execution_program_tests::program_hash_is_stable_at_schema_11`.
#[test]
fn reindenting_moves_the_serialized_stages_and_no_contract_hash() {
    const TIGHT: &str = "\
a = stage(id = \"a\", agent = \"shell\", run = \"echo a\")
b = stage(id = \"b\", agent = \"shell\", run = \"echo b\", depends_on = [a])
workflow(\"reindent\", root = b)
";
    // WHITESPACE ONLY: three blank lines prepended and one between the stages,
    // built FROM `TIGHT` so the two cannot drift apart in anything but whitespace.
    let loose_source = format!("\n\n\n{}", TIGHT.replace("b = stage", "\nb = stage"));
    let loose_source = loose_source.as_str();
    assert_eq!(
        TIGHT.split_whitespace().collect::<Vec<_>>(),
        loose_source.split_whitespace().collect::<Vec<_>>(),
        "the two fixtures must differ in WHITESPACE ONLY"
    );

    let tight = compile_starlark_execution_program(TIGHT, "reindent.star", &[])
        .expect("the tight pack compiles");
    let loose = compile_starlark_execution_program(loose_source, "reindent.star", &[])
        .expect("the re-indented pack compiles");

    assert_eq!(
        tight.stages.keys().collect::<Vec<_>>(),
        loose.stages.keys().collect::<Vec<_>>(),
        "a whitespace edit must not change the stage set"
    );
    for (stage_id, tight_stage) in &tight.stages {
        let loose_stage = &loose.stages[stage_id];
        assert_eq!(
            tight_stage.contract_hash, loose_stage.contract_hash,
            "re-indenting rotated stage {}'s contract_hash — the authored span \
             leaked into the stage contract, so every cached result for an \
             untouched stage would be invalidated by a formatting change",
            stage_id.0
        );
        assert_ne!(
            tight_stage.authored_span, loose_stage.authored_span,
            "stage {} must record the line it actually sits on in each fixture",
            stage_id.0
        );
    }
    assert_ne!(
        stage_bytes(&tight),
        stage_bytes(&loose),
        "the authored span must be INSIDE the serialized stages (and so inside \
         program_hash); identical stage bytes across a line move mean it was \
         never recorded there"
    );
}

/// (d) No serialized program carries a `/` in any span's `file` — the whole-IR
/// form of the basename rule, checked over the SERIALIZED bytes rather than the
/// typed field, so a future span-bearing field is covered without being named.
#[test]
fn no_serialized_span_file_carries_a_path_separator() {
    /// Every `{file, line, column}` object anywhere in the tree — a span, whatever
    /// field it hangs off.
    fn collect_span_files(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                if map.len() == 3
                    && let Some(file) = map.get("file").and_then(serde_json::Value::as_str)
                    && map.contains_key("line")
                    && map.contains_key("column")
                {
                    out.push(file.to_owned());
                }
                for nested in map.values() {
                    collect_span_files(nested, out);
                }
            }
            serde_json::Value::Array(items) => {
                for nested in items {
                    collect_span_files(nested, out);
                }
            }
            _ => {}
        }
    }

    let mut total = 0usize;
    for (path, program) in compiled_corpus() {
        let json = serde_json::to_value(&program).expect("the checked program serializes");
        let mut files = Vec::new();
        collect_span_files(&json, &mut files);
        assert!(
            !files.is_empty(),
            "{} serialized no span at all",
            path.display()
        );
        for file in &files {
            assert!(
                !file.contains('/') && !file.contains('\\'),
                "{} serialized the span file {file:?}, which is a PATH — a \
                 content-hashed program may not name a machine's facts",
                path.display()
            );
        }
        total += files.len();
    }
    assert!(
        total >= PACK_FLOOR,
        "the corpus must serialize spans to check; saw {total}"
    );
}
