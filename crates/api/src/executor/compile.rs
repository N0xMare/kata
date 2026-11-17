//! Inline Starlark execution-program compilation.

use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};

use super::ExecutorError;

/// Compile an inline Starlark workflow directly into checked execution IR.
pub fn compile_inline_starlark_execution_program(
    contents: &str,
    filename: &str,
    loader_roots: &[std::path::PathBuf],
) -> Result<ExecutionProgram, ExecutorError> {
    compile_starlark_execution_program(contents, filename, loader_roots)
        .map_err(|e| ExecutorError::InvalidDefinition(e.to_string()))
}
