//! The deciding reader's fail-closed gate, driven through the runner's own fold.
//!
//! `fold_to_head` and `rehydrate_in_flight_from_ledger` both take their chain
//! through `Dispatcher::deciding_chain_reader`. In-crate because both are private
//! to the runner.

use std::collections::BTreeMap;
use std::sync::Arc;

use ulid::Ulid;

use crate::runner::WorkflowRunner;
use crate::test_harness::OciNodeRig;
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};

const REFUSAL: &str = "the operational nucleus does not hold";

fn program() -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(
        "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
         workflow(\"gate\", root = [only])\n",
        "gate.star",
        &[],
    )
    .expect("compiles under oci")
}

/// A runner over an execution the ATTACHED nucleus does not hold refuses to fold,
/// naming the execution, rather than reading the absence as an empty history.
///
/// An empty history is the opposite answer, not a lesser one: it reports never-run
/// for work this plane simply cannot see, and the drive loop would dispatch it
/// again. The plane is populated — it holds a DIFFERENT admitted execution, and
/// folds it — so "the plane is empty" cannot explain the refusal, and a gate that
/// refused everything fails the first half.
///
/// **Watched red:** with `deciding_chain_reader` returning the nucleus without
/// asking `attempt_chain_nucleus`, the unheld fold returns `Ok(())`.
#[tokio::test]
async fn the_fold_refuses_an_execution_the_attached_nucleus_does_not_hold() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    assert!(rig.dispatcher.execution_lifecycle_is_attached());
    let program = program();

    let held = rig.runner(&program, Ulid::new());
    let (mut applied, mut outputs) = (0, BTreeMap::new());
    held.fold_to_head(&mut applied, &mut outputs)
        .expect("the nucleus speaks for the execution it holds");
    held.rehydrate_in_flight_from_ledger()
        .expect("the nucleus speaks for the execution it holds");

    let unheld = Ulid::new();
    let runner = WorkflowRunner::new_from_program(program, Arc::clone(&rig.dispatcher), unheld)
        .expect("the runner builds");
    let (mut applied, mut outputs) = (0, BTreeMap::new());
    let fold = runner
        .fold_to_head(&mut applied, &mut outputs)
        .expect_err("an unheld execution must fail closed, not fold an empty history")
        .to_string();
    assert!(
        fold.contains(REFUSAL) && fold.contains(&unheld.to_string()),
        "{fold}"
    );
    let rehydrate = runner
        .rehydrate_in_flight_from_ledger()
        .expect_err("an unheld execution must fail closed, not rehydrate nothing")
        .to_string();
    assert!(
        rehydrate.contains(REFUSAL) && rehydrate.contains(&unheld.to_string()),
        "{rehydrate}"
    );
}
