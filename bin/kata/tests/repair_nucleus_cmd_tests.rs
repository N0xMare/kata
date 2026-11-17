//! CLI-layer coverage for `kata repair-nucleus`.
//!
//! Boot refuses on a three-way nucleus integrity mismatch and names "an
//! explicit projection rebuild" as the sanctioned repair. These tests pin that
//! the named action is REACHABLE (`OperationalDb::rebuild_projection`, through
//! this command) for the class it can repair, and that the classes it provably
//! cannot repair are reported as such with their real recourse instead of
//! being promised a repair that does nothing.

use std::path::{Path, PathBuf};

use kata::cli::testing::{
    initialize_clean_data_dir_for_test, run_repair_nucleus_cmd_with_lease_paths,
};
use kata_program::execution_program::compile_starlark_execution_program;
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use kata_workflow::execution_program_store::ExecutionLifecycleState;
use ulid::Ulid;

/// Run the CLI wrapper with per-test coordination paths, mirroring
/// `upgrade_cmd_tests`: production has one fixed per-owner authority path and
/// parallel integration tests must not contend for that global host resource.
fn run_repair_nucleus(
    data_dir: Option<PathBuf>,
    apply: bool,
    coordination: &Path,
) -> anyhow::Result<()> {
    // The lease parent is a SUBDIRECTORY the lease code creates 0700 itself; a
    // bare tempdir is 0700-checked and rejected. Mirrors `upgrade_cmd_tests`.
    let lease_parent = coordination.join("coordination");
    run_repair_nucleus_cmd_with_lease_paths(
        data_dir,
        None,
        apply,
        &lease_parent.join("lifecycle-operation.lock"),
        &lease_parent.join("discovery.lock"),
    )
}

struct Fixture {
    dir: tempfile::TempDir,
    coordination: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            dir: tempfile::tempdir().unwrap(),
            coordination: tempfile::tempdir().unwrap(),
        };
        initialize_clean_data_dir_for_test(fixture.dir.path()).unwrap();
        fixture
    }

    fn face(&self) -> ExecutionLifecycleFace {
        ExecutionLifecycleFace::open(self.dir.path().join("operational.db")).unwrap()
    }

    /// Admit a `running` execution through the typed API.
    fn seed_running(&self) -> Ulid {
        let execution_id = Ulid::new();
        let program = compile_starlark_execution_program(
            "one = stage(id = \"one\", prompt = \"ok\", agent = \"shell\")\nworkflow(\"repair\", root = one)\n",
            "repair.star",
            &[],
        )
        .unwrap();
        self.face()
            .put_current_program(execution_id, &program)
            .unwrap();
        execution_id
    }

    fn report(&self) -> anyhow::Result<()> {
        run_repair_nucleus(
            Some(self.dir.path().to_path_buf()),
            false,
            self.coordination.path(),
        )
    }

    fn apply(&self) -> anyhow::Result<()> {
        run_repair_nucleus(
            Some(self.dir.path().to_path_buf()),
            true,
            self.coordination.path(),
        )
    }
}

/// The REPAIRABLE class end to end: boot's named action exists, is reachable
/// from the CLI, and actually reconciles the nucleus.
#[test]
fn repair_nucleus_apply_rebuilds_a_projection_that_drifted_from_its_chain() {
    let fixture = Fixture::new();
    let execution_id = fixture.seed_running();
    {
        let face = fixture.face();
        face.db()
            .debug_corrupt_execution_projection(execution_id, "terminalizing")
            .unwrap();
        face.db()
            .verify_projection_integrity(execution_id)
            .expect_err("the drifted projection refuses");
    }

    fixture.report().expect("the report never mutates");
    {
        let face = fixture.face();
        face.db()
            .verify_projection_integrity(execution_id)
            .expect_err("...so the mismatch is still there after a report");
    }

    fixture.apply().expect("the repair succeeds");
    let face = fixture.face();
    face.db()
        .verify_projection_integrity(execution_id)
        .expect("the projection rebuild reconciled it");
    assert_eq!(
        face.db()
            .execution_projection(execution_id)
            .unwrap()
            .unwrap()
            .state,
        "running",
        "the repair rebuilt the projection FROM the chain, never the chain from the projection"
    );
}

/// The UNREPAIRABLE class: a drifted LIFECYCLE row. A projection rebuild
/// provably cannot fix it — it never writes `execution_lifecycle` — so `--apply`
/// must FAIL loudly and name the real recourse rather than reporting success
/// after a no-op.
#[test]
fn repair_nucleus_refuses_to_claim_it_repaired_a_drifted_lifecycle_row() {
    let fixture = Fixture::new();
    let execution_id = fixture.seed_running();
    fixture
        .face()
        .db()
        .debug_forge_lifecycle_terminal(execution_id, "completed")
        .unwrap();

    let error = fixture
        .apply()
        .expect_err("a lifecycle-vs-chain mismatch is not repairable in place");
    let message = format!("{error:#}");
    assert!(
        message.contains("not repairable by a projection rebuild"),
        "{message}"
    );
    assert!(
        message.contains("Preserve this directory offline")
            && message.contains("verified current-format backup"),
        "the refusal must name only current-format recourse: {message}"
    );

    // And the command left the nucleus exactly as it found it.
    let face = fixture.face();
    assert_eq!(
        face.lifecycle(execution_id).unwrap().unwrap().state,
        ExecutionLifecycleState::Completed
    );
    assert_eq!(
        face.db()
            .execution_projection(execution_id)
            .unwrap()
            .unwrap()
            .state,
        "running"
    );
}

/// A coherent data dir is a clean no-op in both modes.
#[test]
fn repair_nucleus_on_a_coherent_data_dir_is_a_no_op() {
    let fixture = Fixture::new();
    fixture.seed_running();
    fixture.report().unwrap();
    fixture.apply().unwrap();
}

/// A data dir with no nucleus at all is a clear refusal, not a panic or a
/// silently created empty database.
#[test]
fn repair_nucleus_refuses_a_data_dir_with_no_nucleus() {
    let fixture = Fixture::new();
    let identity_before =
        std::fs::read(fixture.dir.path().join("main-identity.json")).expect("clean identity");
    let lock_before = std::fs::read(fixture.dir.path().join("main.lock")).expect("clean lock");
    std::fs::remove_file(fixture.dir.path().join("operational.db"))
        .expect("remove the required nucleus to model store loss");
    let error = fixture.report().expect_err("no nucleus, nothing to repair");
    assert!(
        format!("{error:#}").contains("no operational nucleus at"),
        "{error:#}"
    );
    assert!(
        !fixture.dir.path().join("operational.db").exists(),
        "the refusal must not create the database it refused to find"
    );
    assert_eq!(
        std::fs::read(fixture.dir.path().join("main-identity.json")).unwrap(),
        identity_before,
        "repair refusal must preserve the established clean identity"
    );
    assert_eq!(
        std::fs::read(fixture.dir.path().join("main.lock")).unwrap(),
        lock_before,
        "missing-authority preflight must precede lock metadata mutation"
    );
}
