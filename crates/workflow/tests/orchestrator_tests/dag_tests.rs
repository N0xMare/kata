//! Tests for crates/program/src/dag.rs. Extracted from the inline #[cfg(test)] module.

use std::collections::HashSet;

use indexmap::IndexMap;
use kata_program::dag::WorkflowDag;
use smol_str::SmolStr;

fn deps(pairs: &[(&str, &[&str])]) -> IndexMap<SmolStr, Vec<SmolStr>> {
    let mut m = IndexMap::new();
    for (name, dep_list) in pairs {
        m.insert(
            SmolStr::new(name),
            dep_list.iter().map(SmolStr::new).collect(),
        );
    }
    m
}

#[test]
fn linear_dag_topo_sort() {
    // a -> b -> c
    let d = deps(&[("a", &[]), ("b", &["a"]), ("c", &["b"])]);
    let dag = WorkflowDag::build_from_deps(&d).unwrap();
    let order = dag.topological_order();
    assert_eq!(
        order,
        &[SmolStr::new("a"), SmolStr::new("b"), SmolStr::new("c")]
    );
}

#[test]
fn diamond_dag_topo_sort() {
    // a -> b, a -> c, b -> d, c -> d
    let d = deps(&[("a", &[]), ("b", &["a"]), ("c", &["a"]), ("d", &["b", "c"])]);
    let dag = WorkflowDag::build_from_deps(&d).unwrap();
    let order = dag.topological_order();
    // a must be first, d must be last, b and c in between.
    assert_eq!(order[0], "a");
    assert_eq!(order[3], "d");
    assert!(order.contains(&SmolStr::new("b")));
    assert!(order.contains(&SmolStr::new("c")));
}

#[test]
fn cycle_detected() {
    // a -> b -> a (cycle)
    let d = deps(&[("a", &["b"]), ("b", &["a"])]);
    let err = WorkflowDag::build_from_deps(&d).unwrap_err();
    assert!(err.to_string().contains("cycle"));
}

#[test]
fn self_cycle_detected() {
    // a -> a
    let d = deps(&[("a", &["a"])]);
    let err = WorkflowDag::build_from_deps(&d).unwrap_err();
    assert!(err.to_string().contains("cycle"));
}

#[test]
fn ready_stages_with_no_completions() {
    let d = deps(&[("a", &[]), ("b", &["a"]), ("c", &["a"])]);
    let dag = WorkflowDag::build_from_deps(&d).unwrap();
    let completed = HashSet::new();
    let ready = dag.ready_stages(&completed);
    assert_eq!(ready, vec![SmolStr::new("a")]);
}

#[test]
fn ready_stages_after_a_completed() {
    let d = deps(&[("a", &[]), ("b", &["a"]), ("c", &["a"])]);
    let dag = WorkflowDag::build_from_deps(&d).unwrap();
    let mut completed = HashSet::new();
    completed.insert(SmolStr::new("a"));
    let mut ready = dag.ready_stages(&completed);
    ready.sort();
    assert_eq!(ready, vec![SmolStr::new("b"), SmolStr::new("c")]);
}

#[test]
fn ready_stages_join() {
    // d depends on b and c; only ready when both complete.
    let d = deps(&[("a", &[]), ("b", &["a"]), ("c", &["a"]), ("d", &["b", "c"])]);
    let dag = WorkflowDag::build_from_deps(&d).unwrap();
    let mut completed = HashSet::new();
    completed.insert(SmolStr::new("a"));
    completed.insert(SmolStr::new("b"));
    // c not yet done, so d is not ready.
    let ready = dag.ready_stages(&completed);
    assert_eq!(ready, vec![SmolStr::new("c")]);

    completed.insert(SmolStr::new("c"));
    let ready = dag.ready_stages(&completed);
    assert_eq!(ready, vec![SmolStr::new("d")]);
}

#[test]
fn nonexistent_dependency_rejected() {
    let d = deps(&[("a", &["z"])]);
    let err = WorkflowDag::build_from_deps(&d).unwrap_err();
    assert!(err.to_string().contains("non-existent"));
}

#[test]
fn empty_dag() {
    let d = deps(&[]);
    let dag = WorkflowDag::build_from_deps(&d).unwrap();
    assert!(dag.is_empty());
    assert!(dag.topological_order().is_empty());
}

#[test]
fn single_stage() {
    let d = deps(&[("only", &[])]);
    let dag = WorkflowDag::build_from_deps(&d).unwrap();
    assert_eq!(dag.len(), 1);
    assert_eq!(dag.topological_order(), &[SmolStr::new("only")]);
}
