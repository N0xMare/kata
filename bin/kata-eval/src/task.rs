//! Golden-task model + loader.
//!
//! A golden task lives under `test/eval/tasks/<id>/`:
//!
//! ```text
//! test/eval/tasks/<id>/
//!   task.toml      # id, title, prompt, required_tool, max_cost_micro_usd, [mock]
//!   fixture/       # the seeded repo, in its FAILING starting state
//!   validate.sh    # deterministic pass/fail check; CWD = workspace; exit 0 = pass
//!   workflow.star  # the kata workflow: solve (agent) + validate (shell) stages
//!   solution/      # canned-but-valid solution files (used ONLY by the mock solver)
//! ```
//!
//! The fixture is isolated in its own `fixture/` subtree so the live model — which
//! only ever sees a materialized copy of `fixture/` (never `solution/` or
//! `task.toml`) — cannot cheat by reading the answer.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::budget::DEFAULT_CAP_MICRO_USD;

/// What the ZERO-SPEND mock solver does for a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MockStrategy {
    /// Apply the canned `solution/` into the workspace — the validator should
    /// then PASS. At least two tasks must use this so the deterministic tier
    /// proves a valid solution scores.
    Solve,
    /// Leave the fixture untouched — the validator FAILS honestly. Proves the
    /// harness does not free-pass a model that did nothing.
    Noop,
}

/// The `[mock]` block of `task.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockSpec {
    /// What the mock solver does (defaults to [`MockStrategy::Solve`]).
    #[serde(default = "default_strategy")]
    pub strategy: MockStrategy,
}

fn default_strategy() -> MockStrategy {
    MockStrategy::Solve
}

impl Default for MockSpec {
    fn default() -> Self {
        Self {
            strategy: default_strategy(),
        }
    }
}

/// The on-disk `task.toml` shape.
#[derive(Debug, Clone, Deserialize)]
struct TaskManifest {
    id: String,
    title: String,
    prompt: String,
    /// The single external tool the validator needs (`bash`, `python3`,
    /// `rustc`). Used to skip a task cleanly on a host that lacks the tool
    /// rather than false-fail the deterministic tier.
    required_tool: String,
    #[serde(default = "default_task_cap")]
    max_cost_micro_usd: u64,
    #[serde(default)]
    mock: MockSpec,
}

fn default_task_cap() -> u64 {
    // A conservative per-task upper bound if a manifest omits one.
    3_000_000
}

/// A loaded golden task.
#[derive(Debug, Clone)]
pub struct GoldenTask {
    /// Stable task id (also the directory name).
    pub id: String,
    /// One-line human title.
    pub title: String,
    /// The natural-language task prompt handed to the live model's solve stage.
    pub prompt: String,
    /// The external tool the validator requires.
    pub required_tool: String,
    /// Declared UPPER-BOUND spend for this task, in micro-USD. The cap guard
    /// uses this as the worst case before running.
    pub max_cost_micro_usd: u64,
    /// Mock-solver behavior for the deterministic tier.
    pub mock: MockSpec,
    /// Absolute path to the task directory (`test/eval/tasks/<id>`).
    pub dir: PathBuf,
}

impl GoldenTask {
    /// Path to the task's seeded fixture (the failing starting state).
    #[must_use]
    pub fn fixture_dir(&self) -> PathBuf {
        self.dir.join("fixture")
    }

    /// Path to the task's canned solution (mock-only).
    #[must_use]
    pub fn solution_dir(&self) -> PathBuf {
        self.dir.join("solution")
    }

    /// Path to the task's deterministic validator.
    #[must_use]
    pub fn validator_path(&self) -> PathBuf {
        self.dir.join("validate.sh")
    }

    /// Path to the task's kata workflow.
    #[must_use]
    pub fn workflow_path(&self) -> PathBuf {
        self.dir.join("workflow.star")
    }
}

/// The committed eval-input root (`<repo>/test/eval`), discovered at runtime from the
/// current directory or executable ancestors. Used by the deterministic tier;
/// the CLI takes an explicit `--tasks-dir`. No build-host path is embedded in
/// production artifacts.
#[must_use]
pub fn eval_root() -> PathBuf {
    std::env::current_dir()
        .ok()
        .into_iter()
        .chain(std::env::current_exe().ok())
        .flat_map(|path| path.ancestors().map(Path::to_path_buf).collect::<Vec<_>>())
        .find_map(|candidate| {
            let eval = candidate.join("test/eval");
            eval.join("tasks").is_dir().then_some(eval)
        })
        .unwrap_or_else(|| PathBuf::from("test/eval"))
}

/// The committed golden-tasks root (`<repo>/test/eval/tasks`).
#[must_use]
pub fn tasks_root() -> PathBuf {
    eval_root().join("tasks")
}

/// Load every golden task under `tasks_dir`, sorted by id. A task directory
/// without a `task.toml` is skipped; a malformed `task.toml` is an error.
///
/// # Errors
/// Returns an error if `tasks_dir` cannot be read, or if any `task.toml` is
/// present but malformed, or if a task is missing a required companion file
/// (`fixture/`, `validate.sh`, `workflow.star`).
pub fn load_tasks(tasks_dir: &Path) -> anyhow::Result<Vec<GoldenTask>> {
    // Absolutize the root so every derived task path (fixture/, validate.sh,
    // workflow.star) is absolute — the runner invokes the validator with CWD set
    // to a throwaway workspace, where a relative task path would not resolve.
    let tasks_dir = std::fs::canonicalize(tasks_dir)
        .map_err(|e| anyhow::anyhow!("resolving tasks dir {}: {e}", tasks_dir.display()))?;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&tasks_dir)
        .map_err(|e| anyhow::anyhow!("reading tasks dir {}: {e}", tasks_dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();

    let mut tasks = Vec::new();
    for dir in entries {
        let manifest_path = dir.join("task.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let raw = std::fs::read_to_string(&manifest_path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", manifest_path.display()))?;
        let manifest: TaskManifest = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", manifest_path.display()))?;

        if manifest.id != dir.file_name().and_then(|n| n.to_str()).unwrap_or_default() {
            anyhow::bail!(
                "task id {:?} does not match its directory name {}",
                manifest.id,
                dir.display()
            );
        }

        let task = GoldenTask {
            id: manifest.id,
            title: manifest.title,
            prompt: manifest.prompt,
            required_tool: manifest.required_tool,
            max_cost_micro_usd: manifest.max_cost_micro_usd,
            mock: manifest.mock,
            dir: dir.clone(),
        };

        for (label, path) in [
            ("fixture/", task.fixture_dir()),
            ("validate.sh", task.validator_path()),
            ("workflow.star", task.workflow_path()),
        ] {
            anyhow::ensure!(
                path.exists(),
                "task {} is missing its {label} ({})",
                task.id,
                path.display()
            );
        }
        anyhow::ensure!(
            task.max_cost_micro_usd > 0,
            "task {} must declare a positive max_cost_micro_usd",
            task.id
        );
        anyhow::ensure!(
            task.max_cost_micro_usd <= DEFAULT_CAP_MICRO_USD,
            "task {} declares a per-task cap {} above the default run cap {}",
            task.id,
            task.max_cost_micro_usd,
            DEFAULT_CAP_MICRO_USD
        );

        tasks.push(task);
    }
    Ok(tasks)
}
