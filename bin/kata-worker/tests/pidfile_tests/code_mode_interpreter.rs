//! The shipped `kata-worker` runs as its own Code Mode interpreter process:
//! `main` dispatches to the interpreter first thing when it is started with
//! `kata_code_mode_host::INTERPRETER_ARGS`, which is how the daemon's
//! supervisor re-executes it for each Code Mode worker.

#[path = "../../../../crates/code-mode-host/tests/fixtures/shipped_interpreter.rs"]
mod shipped_interpreter;

/// **`kata-worker` started as an interpreter confines itself and runs a cell.**
///
/// **Would red if:** `main` did not dispatch first (clap would refuse the
/// arguments and the process would exit before its `Ready`).
#[test]
fn kata_worker_runs_a_cell_as_a_code_mode_interpreter() {
    shipped_interpreter::a_cell_runs_in(env!("CARGO_BIN_EXE_kata-worker"));
}
