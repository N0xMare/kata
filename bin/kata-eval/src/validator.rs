//! Deterministic validator invocation + fixture materialization.
//!
//! A task's `validate.sh` is THE single source of truth for its pass/fail
//! check. It is run with CWD set to a materialized WORKSPACE (a copy of the
//! task's `fixture/`, possibly mutated by a solver) and operates only on files
//! under that CWD. Exit 0 = pass; any non-zero = fail. The live tier's
//! `workflow.star` runs the SAME script from its shell validator stage.

use std::path::Path;
use std::process::Command;

/// The outcome of running a task's validator against a workspace.
#[derive(Debug, Clone)]
pub struct ValidatorOutcome {
    /// True when the validator exited 0.
    pub passed: bool,
    /// The validator's process exit code (or `-1` when it was killed by a
    /// signal / could not be inspected).
    pub exit_code: i32,
    /// Combined stdout+stderr, truncated for reporting.
    pub output: String,
}

/// Maximum captured validator output kept in a report (bytes).
const MAX_OUTPUT_BYTES: usize = 2_000;

/// Recursively copy `src` into `dst` (which is created if missing). Symlinks are
/// followed as their targets (fixtures are plain files). Executable bits are
/// preserved by `std::fs::copy`.
///
/// # Errors
/// Propagates any filesystem error.
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// True when `tool` resolves on `PATH` (via `command -v`). Used to skip a task
/// whose validator interpreter is absent, rather than false-fail.
#[must_use]
pub fn tool_available(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool} >/dev/null 2>&1"))
        .status()
        .is_ok_and(|s| s.success())
}

/// Run `validator` (`validate.sh`) with CWD = `workspace`, capturing its
/// combined output and exit code.
///
/// # Errors
/// Returns an error only if the validator process could not be spawned at all.
pub fn run_validator(validator: &Path, workspace: &Path) -> anyhow::Result<ValidatorOutcome> {
    // The validator script may live outside the workspace, and we run it with
    // CWD = workspace, so a relative validator path would not resolve. Absolutize
    // it against the current working directory first.
    let validator = std::path::absolute(validator).unwrap_or_else(|_| validator.to_path_buf());
    let output = Command::new("bash")
        .arg(&validator)
        .current_dir(workspace)
        .output()
        .map_err(|e| anyhow::anyhow!("spawning validator {}: {e}", validator.display()))?;

    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    if combined.len() > MAX_OUTPUT_BYTES {
        // Keep the TAIL — the failure reason is usually last.
        let start = combined.len() - MAX_OUTPUT_BYTES;
        combined = format!("…{}", &combined[start..]);
    }

    Ok(ValidatorOutcome {
        passed: output.status.success(),
        exit_code: output.status.code().unwrap_or(-1),
        output: combined,
    })
}

/// Materialize a task's PRISTINE fixture into a fresh temp workspace and run its
/// validator there. The honesty rail asserts this outcome is a FAILURE — a
/// validator that passes on the unmodified fixture is a broken (free-pass) task.
///
/// # Errors
/// Propagates fixture-copy or validator-spawn errors.
pub fn run_validator_on_pristine_fixture(
    fixture_dir: &Path,
    validator: &Path,
) -> anyhow::Result<ValidatorOutcome> {
    let workspace =
        tempfile::tempdir().map_err(|e| anyhow::anyhow!("creating temp workspace: {e}"))?;
    copy_dir_recursive(fixture_dir, workspace.path())
        .map_err(|e| anyhow::anyhow!("copying fixture {}: {e}", fixture_dir.display()))?;
    run_validator(validator, workspace.path())
}
